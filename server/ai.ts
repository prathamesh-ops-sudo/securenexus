import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { SageMakerRuntimeClient, InvokeEndpointCommand } from "@aws-sdk/client-sagemaker-runtime";
import { db } from "./db";
import { entities } from "@shared/schema";
import { eq, inArray } from "drizzle-orm";
import { getEnrichmentForEntity } from "./threat-enrichment";
import { getCachedOsintIndicators } from "./osint-feeds";
import { config as appConfig } from "./config";
import { logger } from "./logger";
import { getAwsClientConfig } from "./aws-credentials";

const bedrockClient = new BedrockRuntimeClient(getAwsClientConfig());

const sagemakerClient = new SageMakerRuntimeClient(getAwsClientConfig());

type ModelBackend = "bedrock" | "sagemaker";

interface ModelConfig {
  backend: ModelBackend;
  modelId: string;
  sagemakerEndpoint?: string;
  maxTokens: number;
  temperature: number;
  topP: number;
}

const MODEL_CONFIG: ModelConfig = {
  backend: appConfig.ai.backend,
  modelId: appConfig.ai.modelId,
  sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
  maxTokens: appConfig.ai.maxTokens,
  temperature: appConfig.ai.temperature,
  topP: appConfig.ai.topP,
};

const TRIAGE_MODEL_CONFIG: ModelConfig = {
  backend: appConfig.ai.backend,
  modelId: appConfig.ai.triage.modelId,
  sagemakerEndpoint: appConfig.ai.triage.sagemakerEndpoint,
  maxTokens: appConfig.ai.triage.maxTokens,
  temperature: appConfig.ai.triage.temperature,
  topP: appConfig.ai.topP,
};

type InferenceTier = "triage" | "narrative" | "correlation";

interface InferenceMetrics {
  tier: InferenceTier;
  model: string;
  inputTokensEstimate: number;
  outputTokensEstimate: number;
  latencyMs: number;
  costEstimateUsd: number;
}

const inferenceLog: InferenceMetrics[] = [];

const CYBER_ENGINE_IDENTITY = `You are SecureNexus Cyber Analyst — a specialized cybersecurity instruct model purpose-built for Security Operations Center (SOC) analysis. You operate under strict analytical protocols derived from the following frameworks:

OPERATIONAL FRAMEWORKS:
- MITRE ATT&CK Enterprise Matrix v15 (14 Tactics, 201 Techniques, 424 Sub-techniques)
- NIST SP 800-61r2 Incident Response Lifecycle
- Lockheed Martin Cyber Kill Chain
- Diamond Model of Intrusion Analysis (Adversary, Infrastructure, Capability, Victim)
- OCSF (Open Cybersecurity Schema Framework)

ANALYSIS PROTOCOLS:
1. Evidence-Based Reasoning: Every assessment must cite observable indicators. Never speculate without labeling confidence levels.
2. Kill Chain Mapping: Map all findings to both MITRE ATT&CK and Cyber Kill Chain stages.
3. IOC Extraction: Extract all Indicators of Compromise (IPs, domains, file hashes, URLs, email addresses, registry keys, mutexes).
4. Confidence Scoring: Use calibrated confidence (0.0-1.0): >=0.9 confirmed, 0.7-0.89 high, 0.5-0.69 moderate, 0.3-0.49 low, <0.3 speculative.
5. False Positive Assessment: Always evaluate false positive probability with reasoning.
6. Severity Calibration: Map to CVSS-aligned severity (critical >=9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9, informational 0.0).

OUTPUT REQUIREMENTS:
- Respond ONLY with valid JSON matching the requested schema
- No markdown formatting, no explanatory text outside the JSON
- All timestamps in ISO 8601 format
- All MITRE references use official technique IDs (e.g., T1059.001)
- All IOCs extracted and categorized by type`;

async function invokeModel(systemPrompt: string, userMessage: string, maxTokens?: number): Promise<string> {
  if (MODEL_CONFIG.backend === "sagemaker") {
    return invokeSageMaker(systemPrompt, userMessage, maxTokens);
  }
  return invokeBedrock(systemPrompt, userMessage, maxTokens);
}

async function invokeBedrock(systemPrompt: string, userMessage: string, maxTokens?: number): Promise<string> {
  try {
    const command = new ConverseCommand({
      modelId: MODEL_CONFIG.modelId,
      messages: [
        {
          role: "user",
          content: [{ text: userMessage }],
        },
      ],
      system: [{ text: systemPrompt }],
      inferenceConfig: {
        maxTokens: maxTokens || MODEL_CONFIG.maxTokens,
        temperature: MODEL_CONFIG.temperature,
        topP: MODEL_CONFIG.topP,
      },
    });

    const response = await bedrockClient.send(command);
    const outputContent = response.output?.message?.content;
    if (!outputContent || outputContent.length === 0) {
      throw new Error("Empty response from model");
    }
    return outputContent[0].text || "";
  } catch (error: any) {
    if (error.name === "AccessDeniedException" || error.name === "UnrecognizedClientException") {
      throw new Error("AWS credentials are invalid or lack Bedrock access. Verify IAM role has bedrock:InvokeModel permission.");
    }
    if (error.name === "ResourceNotFoundException" || error.name === "ModelNotReadyException" || error.name === "ValidationException") {
      throw new Error(`Model ${MODEL_CONFIG.modelId} is not available in region ${appConfig.aws.region}. Enable it in the AWS Bedrock console under Model Access.`);
    }
    if (error.name === "ThrottlingException") {
      throw new Error("Rate limit exceeded on AWS Bedrock. Retry after a brief delay.");
    }
    logger.child("ai").error("Bedrock Converse error", { errorName: error.name, error: error.message });
    throw new Error(`AI analysis failed: ${error.message}`);
  }
}

async function invokeSageMaker(systemPrompt: string, userMessage: string, maxTokens?: number): Promise<string> {
  const endpoint = MODEL_CONFIG.sagemakerEndpoint;
  if (!endpoint) {
    throw new Error("SAGEMAKER_ENDPOINT environment variable is required when AI_BACKEND=sagemaker");
  }

  try {
    const payload = {
      inputs: `<s>[INST] ${systemPrompt}\n\n${userMessage} [/INST]`,
      parameters: {
        max_new_tokens: maxTokens || MODEL_CONFIG.maxTokens,
        temperature: MODEL_CONFIG.temperature,
        top_p: MODEL_CONFIG.topP,
        do_sample: true,
      },
    };

    const command = new InvokeEndpointCommand({
      EndpointName: endpoint,
      ContentType: "application/json",
      Accept: "application/json",
      Body: new TextEncoder().encode(JSON.stringify(payload)),
    });

    const response = await sagemakerClient.send(command);
    const result = JSON.parse(new TextDecoder().decode(response.Body as Uint8Array));

    if (Array.isArray(result) && result[0]?.generated_text) {
      return result[0].generated_text;
    }
    if (result.generated_text) {
      return result.generated_text;
    }
    if (typeof result === "string") {
      return result;
    }
    throw new Error("Unexpected SageMaker response format");
  } catch (error: any) {
    if (error.name === "ModelError") {
      throw new Error(`SageMaker model error on endpoint ${endpoint}: ${error.message}`);
    }
    if (error.name === "ValidationError") {
      throw new Error(`SageMaker endpoint ${endpoint} not found or not in service.`);
    }
    logger.child("ai").error("SageMaker invocation error", { errorName: error.name, error: error.message });
    throw new Error(`AI analysis failed (SageMaker): ${error.message}`);
  }
}

async function invokeBedrockWithConfig(systemPrompt: string, userMessage: string, config: ModelConfig, maxTokens?: number): Promise<string> {
  try {
    const command = new ConverseCommand({
      modelId: config.modelId,
      messages: [
        {
          role: "user",
          content: [{ text: userMessage }],
        },
      ],
      system: [{ text: systemPrompt }],
      inferenceConfig: {
        maxTokens: maxTokens || config.maxTokens,
        temperature: config.temperature,
        topP: config.topP,
      },
    });

    const response = await bedrockClient.send(command);
    const outputContent = response.output?.message?.content;
    if (!outputContent || outputContent.length === 0) {
      throw new Error("Empty response from model");
    }
    return outputContent[0].text || "";
  } catch (error: any) {
    if (error.name === "ValidationException" && error.message?.includes("system")) {
      const fallbackCommand = new ConverseCommand({
        modelId: config.modelId,
        messages: [
          {
            role: "user",
            content: [{ text: `${systemPrompt}\n\n${userMessage}` }],
          },
        ],
        inferenceConfig: {
          maxTokens: maxTokens || config.maxTokens,
          temperature: config.temperature,
          topP: config.topP,
        },
      });
      const fallbackResponse = await bedrockClient.send(fallbackCommand);
      const fallbackContent = fallbackResponse.output?.message?.content;
      if (!fallbackContent || fallbackContent.length === 0) {
        throw new Error("Empty response from model");
      }
      return fallbackContent[0].text || "";
    }
    if (error.name === "AccessDeniedException" || error.name === "UnrecognizedClientException") {
      throw new Error("AWS credentials are invalid or lack Bedrock access. Verify IAM role has bedrock:InvokeModel permission.");
    }
    if (error.name === "ResourceNotFoundException" || error.name === "ModelNotReadyException" || error.name === "ValidationException") {
      throw new Error(`Model ${config.modelId} is not available in region ${appConfig.aws.region}. Enable it in the AWS Bedrock console under Model Access.`);
    }
    if (error.name === "ThrottlingException") {
      throw new Error("Rate limit exceeded on AWS Bedrock. Retry after a brief delay.");
    }
    logger.child("ai").error("Bedrock Converse error", { errorName: error.name, error: error.message });
    throw new Error(`AI analysis failed: ${error.message}`);
  }
}

async function invokeSageMakerWithConfig(systemPrompt: string, userMessage: string, config: ModelConfig, maxTokens?: number): Promise<string> {
  const endpoint = config.sagemakerEndpoint;
  if (!endpoint) {
    throw new Error("SageMaker endpoint is required when AI_BACKEND=sagemaker");
  }

  try {
    const payload = {
      inputs: `<s>[INST] ${systemPrompt}\n\n${userMessage} [/INST]`,
      parameters: {
        max_new_tokens: maxTokens || config.maxTokens,
        temperature: config.temperature,
        top_p: config.topP,
        do_sample: true,
      },
    };

    const command = new InvokeEndpointCommand({
      EndpointName: endpoint,
      ContentType: "application/json",
      Accept: "application/json",
      Body: new TextEncoder().encode(JSON.stringify(payload)),
    });

    const response = await sagemakerClient.send(command);
    const result = JSON.parse(new TextDecoder().decode(response.Body as Uint8Array));

    if (Array.isArray(result) && result[0]?.generated_text) {
      return result[0].generated_text;
    }
    if (result.generated_text) {
      return result.generated_text;
    }
    if (typeof result === "string") {
      return result;
    }
    throw new Error("Unexpected SageMaker response format");
  } catch (error: any) {
    if (error.name === "ModelError") {
      throw new Error(`SageMaker model error on endpoint ${endpoint}: ${error.message}`);
    }
    if (error.name === "ValidationError") {
      throw new Error(`SageMaker endpoint ${endpoint} not found or not in service.`);
    }
    logger.child("ai").error("SageMaker invocation error", { errorName: error.name, error: error.message });
    throw new Error(`AI analysis failed (SageMaker): ${error.message}`);
  }
}

async function invokeModelWithTier(
  systemPrompt: string,
  userMessage: string,
  tier: InferenceTier,
  maxTokens?: number
): Promise<{ text: string; metrics: InferenceMetrics }> {
  const config = tier === "triage" ? TRIAGE_MODEL_CONFIG : MODEL_CONFIG;
  const start = Date.now();

  const text = config.backend === "sagemaker"
    ? await invokeSageMakerWithConfig(systemPrompt, userMessage, config, maxTokens)
    : await invokeBedrockWithConfig(systemPrompt, userMessage, config, maxTokens);

  const latencyMs = Date.now() - start;
  const inputTokensEstimate = Math.ceil((systemPrompt.length + userMessage.length) / 4);
  const outputTokensEstimate = Math.ceil(text.length / 4);

  const costPerInputToken = tier === "triage" ? 0.00000015 : 0.000004;
  const costPerOutputToken = tier === "triage" ? 0.0000002 : 0.000012;
  const costEstimateUsd = (inputTokensEstimate * costPerInputToken) + (outputTokensEstimate * costPerOutputToken);

  const metrics: InferenceMetrics = {
    tier,
    model: config.modelId,
    inputTokensEstimate,
    outputTokensEstimate,
    latencyMs,
    costEstimateUsd,
  };

  inferenceLog.push(metrics);
  if (inferenceLog.length > 1000) inferenceLog.splice(0, inferenceLog.length - 500);

  return { text, metrics };
}

export interface CorrelationResult {
  correlatedGroups: {
    groupName: string;
    alertIds: string[];
    confidence: number;
    reasoning: string;
    suggestedIncidentTitle: string;
    severity: string;
    mitreTactics: string[];
    mitreTechniques: string[];
    killChainPhases: string[];
    diamondModel: {
      adversary: string;
      infrastructure: string[];
      capability: string;
      victim: string[];
    };
  }[];
  uncorrelatedAlertIds: string[];
  overallAssessment: string;
  threatLandscape: string;
}

export interface NarrativeResult {
  narrative: string;
  citedAlertIds?: string[];
  summary: string;
  attackTimeline: { timestamp: string; description: string; alertId?: string; mitreTechnique?: string }[];
  attackerProfile: {
    ttps: string[];
    sophistication: string;
    likelyMotivation: string;
    estimatedOrigin: string;
    diamondModel: {
      adversary: string;
      infrastructure: string[];
      capability: string;
      victim: string[];
    };
  };
  killChainAnalysis: {
    phase: string;
    description: string;
    evidence: string[];
  }[];
  mitigationSteps: string[];
  iocs: { type: string; value: string; context: string }[];
  riskScore: number;
  nistPhase: string;
}

export interface TriageResult {
  severity: string;
  priority: number;
  category: string;
  recommendedAction: string;
  reasoning: string;
  mitreTactic: string;
  mitreTechnique: string;
  killChainPhase: string;
  falsePositiveLikelihood: number;
  falsePositiveReasoning: string;
  relatedIocs: { type: string; value: string }[];
  nistClassification: string;
  escalationRequired: boolean;
  containmentAdvice: string;
  threatIntelSources?: string[];
}

export interface ThreatIntelContext {
  enrichmentResults: Array<{
    ioc: string;
    iocType: string;
    provider: string;
    verdict: string;
    reputationScore: number;
    tags: string[];
  }>;
  osintMatches: Array<{
    ioc: string;
    iocType: string;
    feedName: string;
    threat: string;
    confidence: number;
    tags: string[];
  }>;
  summary: string;
}

export async function buildThreatIntelContext(alerts: any[]): Promise<ThreatIntelContext> {
  const result: ThreatIntelContext = {
    enrichmentResults: [],
    osintMatches: [],
    summary: "",
  };

  try {
    const iocSet = new Map<string, string>();
    for (const alert of alerts) {
      if (alert.sourceIp) iocSet.set(alert.sourceIp, "ip");
      if (alert.destIp) iocSet.set(alert.destIp, "ip");
      if (alert.domain) iocSet.set(alert.domain, "domain");
      if (alert.url) iocSet.set(alert.url, "url");
      if (alert.fileHash) iocSet.set(alert.fileHash, "file_hash");
    }

    if (iocSet.size === 0) {
      return result;
    }

    const iocValues = Array.from(iocSet.keys());

    try {
      const matchingEntities = await db
        .select()
        .from(entities)
        .where(inArray(entities.value, iocValues))
        .limit(100);

      for (const entity of matchingEntities) {
        const enrichment = getEnrichmentForEntity(entity.metadata as Record<string, any> | null);
        if (enrichment && enrichment.results.length > 0) {
          for (const er of enrichment.results) {
            result.enrichmentResults.push({
              ioc: er.entityValue,
              iocType: er.entityType,
              provider: er.provider,
              verdict: er.verdict,
              reputationScore: er.reputationScore,
              tags: er.tags,
            });
          }
        }
      }
    } catch (err) {
      logger.child("ai").warn("Failed to fetch entity enrichment for threat intel context", { error: String(err) });
    }

    try {
      const cachedIndicators = getCachedOsintIndicators();
      const iocLower = new Map<string, string>();
      const iocOriginal = new Map<string, string>();
      const iocSetEntries = Array.from(iocSet.entries());
      for (const [val, type] of iocSetEntries) {
        const lower = val.toLowerCase();
        iocLower.set(lower, type);
        iocOriginal.set(lower, val);
      }

      for (const indicator of cachedIndicators) {
        const indicatorVal = indicator.value.toLowerCase();

        if (iocLower.has(indicatorVal)) {
          result.osintMatches.push({
            ioc: iocOriginal.get(indicatorVal) || indicator.value,
            iocType: iocLower.get(indicatorVal)!,
            feedName: indicator.source,
            threat: indicator.threat,
            confidence: indicator.confidence,
            tags: indicator.tags,
          });
        }
      }
    } catch (err) {
      logger.child("ai").warn("Failed to check OSINT feeds for threat intel context", { error: String(err) });
    }

    result.enrichmentResults = result.enrichmentResults.slice(0, 20);
    result.osintMatches = result.osintMatches.slice(0, 20);

    const maliciousCount = result.enrichmentResults.filter(r => r.verdict === "malicious").length;
    const suspiciousCount = result.enrichmentResults.filter(r => r.verdict === "suspicious").length;
    const osintCount = result.osintMatches.length;

    const parts: string[] = [];
    if (maliciousCount > 0) parts.push(`${maliciousCount} IOC(s) flagged as malicious by enrichment providers`);
    if (suspiciousCount > 0) parts.push(`${suspiciousCount} IOC(s) flagged as suspicious`);
    if (osintCount > 0) parts.push(`${osintCount} IOC(s) matched in OSINT threat feeds`);

    if (parts.length > 0) {
      const confidence = maliciousCount > 0 || osintCount > 2 ? "High" : suspiciousCount > 0 || osintCount > 0 ? "Moderate" : "Low";
      result.summary = `${parts.join(", ")}. ${confidence} confidence of genuine threat activity.`;
    }
  } catch (err) {
    logger.child("ai").warn("Failed to build threat intel context", { error: String(err) });
  }

  return result;
}

export function formatThreatIntelForPrompt(ctx: ThreatIntelContext): string {
  if (ctx.enrichmentResults.length === 0 && ctx.osintMatches.length === 0) {
    return "";
  }

  const lines: string[] = [];
  lines.push("THREAT INTELLIGENCE CONTEXT:");
  lines.push("The following IOCs from this alert have been cross-referenced against threat intelligence feeds and enrichment providers.");
  lines.push("");

  if (ctx.enrichmentResults.length > 0) {
    lines.push("ENRICHMENT RESULTS (from AbuseIPDB, VirusTotal, OTX AlienVault):");
    for (const r of ctx.enrichmentResults) {
      const tagStr = r.tags.length > 0 ? ` [tags: ${r.tags.join(", ")}]` : "";
      lines.push(`- ${r.ioc} (${r.iocType}): ${r.verdict.toUpperCase()} (score: ${r.reputationScore.toFixed(2)}) via ${r.provider}${tagStr}`);
    }
    lines.push("");
  }

  if (ctx.osintMatches.length > 0) {
    lines.push("OSINT FEED MATCHES:");
    for (const m of ctx.osintMatches) {
      const tagStr = m.tags.length > 0 ? ` [tags: ${m.tags.join(", ")}]` : "";
      lines.push(`- ${m.ioc} (${m.iocType}): Matched in ${m.feedName} - threat: ${m.threat} (confidence: ${m.confidence})${tagStr}`);
    }
    lines.push("");
  }

  if (ctx.summary) {
    lines.push(`INTELLIGENCE SUMMARY: ${ctx.summary}`);
    lines.push("");
  }

  lines.push("Use this threat intelligence to inform your analysis. IOCs with high reputation scores or OSINT matches should increase your confidence that this is a genuine threat, not a false positive. Cross-reference these findings with the alert telemetry.");

  return lines.join("\n");
}

export async function correlateAlerts(alertsData: any[], threatIntelCtx?: ThreatIntelContext): Promise<CorrelationResult> {
  const systemPrompt = `${CYBER_ENGINE_IDENTITY}

CORRELATION SPECIALIZATION:
You are executing Phase 2 (Detection & Analysis) of the NIST IR lifecycle.
Apply the following correlation heuristics in order of priority:
1. TEMPORAL: Alerts within 15-minute windows from related sources
2. TOPOLOGICAL: Shared source/destination IPs, hostnames, or user accounts
3. BEHAVIORAL: Sequential MITRE ATT&CK technique chains (e.g., T1566→T1059→T1053→T1048)
4. INDICATOR: Shared IOCs (file hashes, domains, IPs, URLs)
5. CAMPAIGN: TTP patterns matching known threat actor profiles
6. THREAT_INTEL: Cross-reference IOCs against provided threat intelligence enrichment and OSINT feed data to strengthen correlation confidence

Map each correlated group to:
- Lockheed Martin Kill Chain phases (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives)
- Diamond Model quadrants (Adversary, Infrastructure, Capability, Victim)
- MITRE ATT&CK Enterprise tactics and techniques`;

  const userMessage = `Correlate these ${alertsData.length} security alerts. Identify attack chains, lateral movement patterns, and coordinated campaigns.

ALERT TELEMETRY:
${JSON.stringify(alertsData.map(a => ({
  id: a.id,
  title: a.title,
  source: a.source,
  category: a.category,
  severity: a.severity,
  sourceIp: a.sourceIp,
  destIp: a.destIp,
  sourcePort: a.sourcePort,
  destPort: a.destPort,
  protocol: a.protocol,
  hostname: a.hostname,
  userId: a.userId,
  mitreTactic: a.mitreTactic,
  mitreTechnique: a.mitreTechnique,
  detectedAt: a.detectedAt,
  description: a.description,
  domain: a.domain,
  fileHash: a.fileHash,
  url: a.url,
})), null, 2)}

Respond with this exact JSON structure:
{
  "correlatedGroups": [
    {
      "groupName": "descriptive attack chain name",
      "alertIds": ["id1", "id2"],
      "confidence": 0.85,
      "reasoning": "evidence-based explanation citing specific indicators",
      "suggestedIncidentTitle": "concise incident title",
      "severity": "critical|high|medium|low",
      "mitreTactics": ["Initial Access", "Execution"],
      "mitreTechniques": ["T1566.001", "T1059.001"],
      "killChainPhases": ["Delivery", "Exploitation"],
      "diamondModel": {
        "adversary": "threat actor profile or unknown",
        "infrastructure": ["malicious IPs/domains"],
        "capability": "attack capability description",
        "victim": ["affected hosts/users"]
      }
    }
  ],
  "uncorrelatedAlertIds": ["standalone alert ids"],
  "overallAssessment": "strategic threat assessment",
  "threatLandscape": "broader threat context and recommendations"
}`;

  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeModelWithTier(systemPrompt, finalUserMessage, "correlation", 4096);
  return JSON.parse(extractJson(text));
}

export async function generateIncidentNarrative(incident: any, alerts: any[], threatIntelCtx?: ThreatIntelContext): Promise<NarrativeResult> {
  const systemPrompt = `${CYBER_ENGINE_IDENTITY}

NARRATIVE SPECIALIZATION:
You are executing Phase 2-3 (Detection/Analysis → Containment) of the NIST IR lifecycle.
Generate an attacker-centric narrative that reconstructs the full intrusion timeline.
Apply the Lockheed Martin Cyber Kill Chain and Diamond Model to structure the narrative.

NARRATIVE REQUIREMENTS:
1. Reconstruct attacker actions in chronological order
2. Map each action to MITRE ATT&CK techniques
3. Identify the Kill Chain phase for each stage
4. Apply the Diamond Model to characterize the intrusion
5. Extract all IOCs with type classification (ip, domain, hash, url, email, registry, mutex)
6. Provide actionable containment and mitigation steps aligned with NIST SP 800-61r2
7. Assign a calibrated risk score (0-100) based on asset criticality, data sensitivity, and attack sophistication
8. CITATION REQUIREMENT: Every factual claim in the narrative MUST include an inline citation referencing the alert ID that provides the evidence. Use the format [Alert <alertId>] where alertId is the exact alert ID from the telemetry. For example: "Mimikatz credential dumping was detected on the domain controller [Alert abc123]."
9. Every paragraph in the narrative must cite at least one alert.
10. THREAT INTELLIGENCE: Incorporate provided threat intelligence enrichment and OSINT feed data into the narrative, citing which IOCs were confirmed malicious by external sources`;

  const userMessage = `Generate a comprehensive incident narrative for this security incident.

INCIDENT CONTEXT:
${JSON.stringify({
  title: incident.title,
  summary: incident.summary,
  severity: incident.severity,
  status: incident.status,
  mitreTactics: incident.mitreTactics,
  mitreTechniques: incident.mitreTechniques,
  affectedAssets: incident.affectedAssets,
  createdAt: incident.createdAt,
}, null, 2)}

ASSOCIATED ALERT TELEMETRY (${alerts.length} alerts):
${JSON.stringify(alerts.map(a => ({
  id: a.id,
  title: a.title,
  source: a.source,
  category: a.category,
  severity: a.severity,
  description: a.description,
  sourceIp: a.sourceIp,
  destIp: a.destIp,
  sourcePort: a.sourcePort,
  destPort: a.destPort,
  protocol: a.protocol,
  hostname: a.hostname,
  userId: a.userId,
  mitreTactic: a.mitreTactic,
  mitreTechnique: a.mitreTechnique,
  detectedAt: a.detectedAt,
  fileHash: a.fileHash,
  domain: a.domain,
  url: a.url,
})), null, 2)}

Respond with this exact JSON structure:
{
  "narrative": "detailed multi-paragraph attacker-centric narrative with inline [Alert <id>] citations for every claim. Every paragraph MUST reference at least one alert ID from the provided telemetry.",
  "citedAlertIds": ["list of all alert IDs explicitly cited in the narrative"],
  "summary": "one-line executive summary",
  "attackTimeline": [
    {"timestamp": "ISO 8601", "description": "action description", "alertId": "source alert", "mitreTechnique": "T1xxx.xxx"}
  ],
  "attackerProfile": {
    "ttps": ["TTP descriptions"],
    "sophistication": "nation-state|advanced-persistent|organized-crime|intermediate|opportunistic",
    "likelyMotivation": "financial|espionage|hacktivism|destruction|unknown",
    "estimatedOrigin": "geographic/organizational origin assessment",
    "diamondModel": {
      "adversary": "threat actor characterization",
      "infrastructure": ["C2 servers, domains, IPs used"],
      "capability": "tooling and technique sophistication",
      "victim": ["targeted assets, users, systems"]
    }
  },
  "killChainAnalysis": [
    {"phase": "Kill Chain phase", "description": "what occurred in this phase", "evidence": ["supporting indicators"]}
  ],
  "mitigationSteps": ["NIST-aligned containment and recovery steps"],
  "iocs": [{"type": "ip|domain|hash|url|email|registry|mutex", "value": "indicator value", "context": "where/how observed"}],
  "riskScore": 85,
  "nistPhase": "Detection|Analysis|Containment|Eradication|Recovery"
}`;

  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeModelWithTier(systemPrompt, finalUserMessage, "narrative", 6144);
  const parsed = JSON.parse(extractJson(text));
  if (!parsed.citedAlertIds || !Array.isArray(parsed.citedAlertIds) || parsed.citedAlertIds.length === 0) {
    const citationRegex = /\[Alert ([^\]]+)\]/g;
    const extracted: string[] = [];
    let m;
    while ((m = citationRegex.exec(parsed.narrative || "")) !== null) {
      if (!extracted.includes(m[1])) extracted.push(m[1]);
    }
    parsed.citedAlertIds = extracted;
  }
  return parsed;
}

export async function triageAlert(alertData: any, threatIntelCtx?: ThreatIntelContext): Promise<TriageResult> {
  const systemPrompt = `${CYBER_ENGINE_IDENTITY}

TRIAGE SPECIALIZATION:
You are executing real-time alert triage as a Tier 2 SOC Analyst.
Apply the following triage protocol:
1. CLASSIFY: Map to MITRE ATT&CK tactic/technique and Kill Chain phase
2. ASSESS: Evaluate severity using CVSS-aligned scoring and environmental context
3. DETERMINE: Calculate false positive probability with evidence-based reasoning
4. PRIORITIZE: Assign priority (1=immediate, 2=urgent, 3=normal, 4=low, 5=informational)
5. RECOMMEND: Provide specific, actionable next steps for the analyst
6. ESCALATE: Determine if escalation to Tier 3 or incident commander is needed
7. CONTAIN: Provide immediate containment advice if threat is active
8. INTEL-AUGMENTED: Cross-reference alert IOCs against provided threat intelligence enrichment and OSINT feed matches to validate threat classification

TRIAGE DECISION MATRIX:
- P1 (Immediate): Active data exfiltration, ransomware execution, confirmed APT, critical asset compromise
- P2 (Urgent): Lateral movement detected, privilege escalation, C2 beacon, credential theft
- P3 (Normal): Suspicious behavior, policy violation, reconnaissance activity
- P4 (Low): Informational alerts, failed attacks, known benign anomalies
- P5 (Informational): Audit events, configuration changes, system health`;

  const userMessage = `Triage this security alert with full analytical assessment.

ALERT TELEMETRY:
${JSON.stringify({
  title: alertData.title,
  source: alertData.source,
  severity: alertData.severity,
  category: alertData.category,
  description: alertData.description,
  sourceIp: alertData.sourceIp,
  destIp: alertData.destIp,
  sourcePort: alertData.sourcePort,
  destPort: alertData.destPort,
  protocol: alertData.protocol,
  hostname: alertData.hostname,
  userId: alertData.userId,
  fileHash: alertData.fileHash,
  url: alertData.url,
  domain: alertData.domain,
  rawData: alertData.rawData,
  normalizedData: alertData.normalizedData,
  detectedAt: alertData.detectedAt,
}, null, 2)}

Respond with this exact JSON structure:
{
  "severity": "critical|high|medium|low|informational",
  "priority": 1,
  "category": "MITRE-aligned category",
  "recommendedAction": "specific actionable next step for the analyst",
  "reasoning": "evidence-based triage reasoning citing specific indicators",
  "mitreTactic": "MITRE ATT&CK Tactic",
  "mitreTechnique": "T1xxx.xxx",
  "killChainPhase": "Kill Chain phase",
  "falsePositiveLikelihood": 0.15,
  "falsePositiveReasoning": "why this is or is not likely a false positive",
  "relatedIocs": [{"type": "ip|domain|hash|url", "value": "indicator value"}],
  "nistClassification": "NIST incident category",
  "escalationRequired": false,
  "containmentAdvice": "immediate containment steps if threat is active"
}`;

  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeModelWithTier(systemPrompt, finalUserMessage, "triage", 2048);
  return JSON.parse(extractJson(text));
}

export async function checkModelHealth(): Promise<{
  status: string;
  backend: string;
  model: string;
  region: string;
  latencyMs: number;
  error?: string;
}> {
  const start = Date.now();
  try {
    const testPrompt = "Respond with exactly: {\"status\":\"operational\"}";
    const result = await invokeModel("You are a health check responder. Respond only with the exact JSON requested.", testPrompt, 50);
    const latency = Date.now() - start;
    return {
      status: "healthy",
      backend: MODEL_CONFIG.backend,
      model: MODEL_CONFIG.modelId,
      region: appConfig.aws.region,
      latencyMs: latency,
    };
  } catch (error: any) {
    return {
      status: "unhealthy",
      backend: MODEL_CONFIG.backend,
      model: MODEL_CONFIG.modelId,
      region: appConfig.aws.region,
      latencyMs: Date.now() - start,
      error: error.message,
    };
  }
}

export function getModelConfig(): {
  backend: string;
  model: string;
  region: string;
  temperature: number;
  maxTokens: number;
} {
  return {
    backend: MODEL_CONFIG.backend,
    model: MODEL_CONFIG.modelId,
    region: appConfig.aws.region,
    temperature: MODEL_CONFIG.temperature,
    maxTokens: MODEL_CONFIG.maxTokens,
  };
}

export function getInferenceMetrics(): {
  recentOperations: InferenceMetrics[];
  totalCostUsd: number;
  operationsByTier: Record<string, { count: number; avgLatencyMs: number; totalCostUsd: number }>;
} {
  const totalCostUsd = inferenceLog.reduce((sum, m) => sum + m.costEstimateUsd, 0);
  const byTier: Record<string, { count: number; avgLatencyMs: number; totalCostUsd: number }> = {};
  for (const m of inferenceLog) {
    if (!byTier[m.tier]) byTier[m.tier] = { count: 0, avgLatencyMs: 0, totalCostUsd: 0 };
    byTier[m.tier].count++;
    byTier[m.tier].totalCostUsd += m.costEstimateUsd;
    byTier[m.tier].avgLatencyMs += m.latencyMs;
  }
  for (const tier of Object.keys(byTier)) {
    byTier[tier].avgLatencyMs = Math.round(byTier[tier].avgLatencyMs / byTier[tier].count);
  }
  return {
    recentOperations: inferenceLog.slice(-20),
    totalCostUsd: Math.round(totalCostUsd * 1000000) / 1000000,
    operationsByTier: byTier,
  };
}

function extractJson(text: string): string {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error("AI returned an unexpected response format. Please try again.");
  try {
    JSON.parse(jsonMatch[0]);
    return jsonMatch[0];
  } catch {
    const cleaned = jsonMatch[0]
      .replace(/,\s*}/g, "}")
      .replace(/,\s*]/g, "]")
      .replace(/[\x00-\x1F\x7F]/g, " ");
    try {
      JSON.parse(cleaned);
      return cleaned;
    } catch {
      throw new Error("AI response could not be parsed as valid JSON. Please try again.");
    }
  }
}
