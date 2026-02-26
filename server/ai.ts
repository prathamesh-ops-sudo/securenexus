import { db } from "./db";
import { entities } from "@shared/schema";
import { inArray } from "drizzle-orm";
import { getEnrichmentForEntity } from "./threat-enrichment";
import { getCachedOsintIndicators } from "./osint-feeds";
import { config as appConfig } from "./config";
import { logger } from "./logger";
import { invokeModel as gatewayInvoke, getCircuitBreakerStatus, getModelCacheStats, clearModelCache } from "./ai/model-gateway";
import type { ModelInvokeResult } from "./ai/model-gateway";
import { getPrompt, recordPromptInvocation, initializeDefaultPrompts, getPromptCatalogSummary, getAllPrompts, getPromptAuditLog, getPromptVersionHistory } from "./ai/prompt-registry";
import { getOrgUsageSummary, getAllOrgUsageSummaries, setOrgBudget } from "./ai/budget";

initializeDefaultPrompts();

const log = logger.child("ai");

type InferenceTier = "triage" | "narrative" | "correlation";

interface InferenceMetrics {
  tier: InferenceTier;
  model: string;
  inputTokensEstimate: number;
  outputTokensEstimate: number;
  latencyMs: number;
  costEstimateUsd: number;
  cached: boolean;
  promptId?: string;
  promptVersion?: number;
}

const inferenceLog: InferenceMetrics[] = [];

async function invokeWithPrompt(
  promptId: string,
  userMessage: string,
  tier: InferenceTier,
  orgId?: string,
  maxTokensOverride?: number,
): Promise<{ text: string; metrics: InferenceMetrics }> {
  const prompt = getPrompt(promptId);
  if (!prompt) {
    throw new Error(`Prompt "${promptId}" not found in registry`);
  }

  if (prompt.deprecated) {
    log.warn("Using deprecated prompt", { promptId, version: prompt.version, supersededBy: prompt.supersededBy });
  }

  const modelConfig = tier === "triage"
    ? {
        modelId: appConfig.ai.triage.modelId,
        sagemakerEndpoint: appConfig.ai.triage.sagemakerEndpoint,
        maxTokens: maxTokensOverride || appConfig.ai.triage.maxTokens,
        temperature: appConfig.ai.triage.temperature,
      }
    : {
        modelId: appConfig.ai.modelId,
        sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
        maxTokens: maxTokensOverride || appConfig.ai.maxTokens,
        temperature: appConfig.ai.temperature,
      };

  const result: ModelInvokeResult = await gatewayInvoke({
    modelId: modelConfig.modelId,
    backend: appConfig.ai.backend,
    systemPrompt: prompt.systemPrompt,
    userMessage,
    maxTokens: modelConfig.maxTokens,
    temperature: modelConfig.temperature,
    topP: appConfig.ai.topP,
    sagemakerEndpoint: modelConfig.sagemakerEndpoint,
    orgId,
    promptId: prompt.id,
    promptVersion: prompt.version,
    tier,
  });

  recordPromptInvocation(prompt.id, prompt.version, {
    tier,
    modelId: modelConfig.modelId,
    latencyMs: result.latencyMs,
    cached: result.cached,
    orgId,
  });

  const metrics: InferenceMetrics = {
    tier,
    model: result.modelId,
    inputTokensEstimate: result.inputTokensEstimate,
    outputTokensEstimate: result.outputTokensEstimate,
    latencyMs: result.latencyMs,
    costEstimateUsd: result.costEstimateUsd,
    cached: result.cached,
    promptId: prompt.id,
    promptVersion: prompt.version,
  };

  inferenceLog.push(metrics);
  if (inferenceLog.length > 1000) inferenceLog.splice(0, inferenceLog.length - 500);

  return { text: result.text, metrics };
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

    if (iocSet.size === 0) return result;

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
      log.warn("Failed to fetch entity enrichment for threat intel context", { error: String(err) });
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
      log.warn("Failed to check OSINT feeds for threat intel context", { error: String(err) });
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
    log.warn("Failed to build threat intel context", { error: String(err) });
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
  const userMessage = buildCorrelationUserMessage(alertsData);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("correlation", finalUserMessage, "correlation");
  return JSON.parse(extractJson(text));
}

function buildCorrelationUserMessage(alertsData: any[]): string {
  const telemetry = JSON.stringify(alertsData.map(a => ({
    id: a.id, title: a.title, source: a.source, category: a.category, severity: a.severity,
    sourceIp: a.sourceIp, destIp: a.destIp, sourcePort: a.sourcePort, destPort: a.destPort,
    protocol: a.protocol, hostname: a.hostname, userId: a.userId,
    mitreTactic: a.mitreTactic, mitreTechnique: a.mitreTechnique,
    detectedAt: a.detectedAt, description: a.description,
    domain: a.domain, fileHash: a.fileHash, url: a.url,
  })), null, 2);

  return `Correlate these ${alertsData.length} security alerts. Identify attack chains, lateral movement patterns, and coordinated campaigns.\n\nALERT TELEMETRY:\n${telemetry}\n\nRespond with this exact JSON structure:\n{\n  "correlatedGroups": [\n    {\n      "groupName": "descriptive attack chain name",\n      "alertIds": ["id1", "id2"],\n      "confidence": 0.85,\n      "reasoning": "evidence-based explanation citing specific indicators",\n      "suggestedIncidentTitle": "concise incident title",\n      "severity": "critical|high|medium|low",\n      "mitreTactics": ["Initial Access", "Execution"],\n      "mitreTechniques": ["T1566.001", "T1059.001"],\n      "killChainPhases": ["Delivery", "Exploitation"],\n      "diamondModel": {\n        "adversary": "threat actor profile or unknown",\n        "infrastructure": ["malicious IPs/domains"],\n        "capability": "attack capability description",\n        "victim": ["affected hosts/users"]\n      }\n    }\n  ],\n  "uncorrelatedAlertIds": ["standalone alert ids"],\n  "overallAssessment": "strategic threat assessment",\n  "threatLandscape": "broader threat context and recommendations"\n}`;
}

export async function generateIncidentNarrative(incident: any, alerts: any[], threatIntelCtx?: ThreatIntelContext): Promise<NarrativeResult> {
  const userMessage = buildNarrativeUserMessage(incident, alerts);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("narrative", finalUserMessage, "narrative", undefined, 6144);
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

function buildNarrativeUserMessage(incident: any, alerts: any[]): string {
  const incidentCtx = JSON.stringify({
    title: incident.title, summary: incident.summary, severity: incident.severity,
    status: incident.status, mitreTactics: incident.mitreTactics,
    mitreTechniques: incident.mitreTechniques, affectedAssets: incident.affectedAssets,
    createdAt: incident.createdAt,
  }, null, 2);

  const alertTelemetry = JSON.stringify(alerts.map(a => ({
    id: a.id, title: a.title, source: a.source, category: a.category, severity: a.severity,
    description: a.description, sourceIp: a.sourceIp, destIp: a.destIp,
    sourcePort: a.sourcePort, destPort: a.destPort, protocol: a.protocol,
    hostname: a.hostname, userId: a.userId, mitreTactic: a.mitreTactic,
    mitreTechnique: a.mitreTechnique, detectedAt: a.detectedAt,
    fileHash: a.fileHash, domain: a.domain, url: a.url,
  })), null, 2);

  return `Generate a comprehensive incident narrative for this security incident.\n\nINCIDENT CONTEXT:\n${incidentCtx}\n\nASSOCIATED ALERT TELEMETRY (${alerts.length} alerts):\n${alertTelemetry}\n\nRespond with this exact JSON structure:\n{\n  "narrative": "detailed multi-paragraph attacker-centric narrative with inline [Alert <id>] citations for every claim. Every paragraph MUST reference at least one alert ID from the provided telemetry.",\n  "citedAlertIds": ["list of all alert IDs explicitly cited in the narrative"],\n  "summary": "one-line executive summary",\n  "attackTimeline": [\n    {"timestamp": "ISO 8601", "description": "action description", "alertId": "source alert", "mitreTechnique": "T1xxx.xxx"}\n  ],\n  "attackerProfile": {\n    "ttps": ["TTP descriptions"],\n    "sophistication": "nation-state|advanced-persistent|organized-crime|intermediate|opportunistic",\n    "likelyMotivation": "financial|espionage|hacktivism|destruction|unknown",\n    "estimatedOrigin": "geographic/organizational origin assessment",\n    "diamondModel": {\n      "adversary": "threat actor characterization",\n      "infrastructure": ["C2 servers, domains, IPs used"],\n      "capability": "tooling and technique sophistication",\n      "victim": ["targeted assets, users, systems"]\n    }\n  },\n  "killChainAnalysis": [\n    {"phase": "Kill Chain phase", "description": "what occurred in this phase", "evidence": ["supporting indicators"]}\n  ],\n  "mitigationSteps": ["NIST-aligned containment and recovery steps"],\n  "iocs": [{"type": "ip|domain|hash|url|email|registry|mutex", "value": "indicator value", "context": "where/how observed"}],\n  "riskScore": 85,\n  "nistPhase": "Detection|Analysis|Containment|Eradication|Recovery"\n}`;
}

export async function triageAlert(alertData: any, threatIntelCtx?: ThreatIntelContext): Promise<TriageResult> {
  const userMessage = buildTriageUserMessage(alertData);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("triage", finalUserMessage, "triage");
  return JSON.parse(extractJson(text));
}

function buildTriageUserMessage(alertData: any): string {
  const telemetry = JSON.stringify({
    title: alertData.title, source: alertData.source, severity: alertData.severity,
    category: alertData.category, description: alertData.description,
    sourceIp: alertData.sourceIp, destIp: alertData.destIp,
    sourcePort: alertData.sourcePort, destPort: alertData.destPort,
    protocol: alertData.protocol, hostname: alertData.hostname, userId: alertData.userId,
    fileHash: alertData.fileHash, url: alertData.url, domain: alertData.domain,
    rawData: alertData.rawData, normalizedData: alertData.normalizedData,
    detectedAt: alertData.detectedAt,
  }, null, 2);

  return `Triage this security alert with full analytical assessment.\n\nALERT TELEMETRY:\n${telemetry}\n\nRespond with this exact JSON structure:\n{\n  "severity": "critical|high|medium|low|informational",\n  "priority": 1,\n  "category": "MITRE-aligned category",\n  "recommendedAction": "specific actionable next step for the analyst",\n  "reasoning": "evidence-based triage reasoning citing specific indicators",\n  "mitreTactic": "MITRE ATT&CK Tactic",\n  "mitreTechnique": "T1xxx.xxx",\n  "killChainPhase": "Kill Chain phase",\n  "falsePositiveLikelihood": 0.15,\n  "falsePositiveReasoning": "why this is or is not likely a false positive",\n  "relatedIocs": [{"type": "ip|domain|hash|url", "value": "indicator value"}],\n  "nistClassification": "NIST incident category",\n  "escalationRequired": false,\n  "containmentAdvice": "immediate containment steps if threat is active"\n}`;
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
    const prompt = getPrompt("health-check");
    if (!prompt) throw new Error("Health check prompt not found in registry");

    await gatewayInvoke({
      modelId: appConfig.ai.modelId,
      backend: appConfig.ai.backend,
      systemPrompt: prompt.systemPrompt,
      userMessage: prompt.userTemplate,
      maxTokens: prompt.maxTokens,
      temperature: prompt.temperature,
      topP: appConfig.ai.topP,
      sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
      skipCache: true,
    });

    return {
      status: "healthy",
      backend: appConfig.ai.backend,
      model: appConfig.ai.modelId,
      region: appConfig.aws.region,
      latencyMs: Date.now() - start,
    };
  } catch (error: unknown) {
    return {
      status: "unhealthy",
      backend: appConfig.ai.backend,
      model: appConfig.ai.modelId,
      region: appConfig.aws.region,
      latencyMs: Date.now() - start,
      error: (error as Error).message,
    };
  }
}

export function getModelConfig(): {
  backend: string;
  model: string;
  region: string;
  temperature: number;
  maxTokens: number;
  promptCount: number;
  cacheStats: { size: number; maxSize: number };
  circuitBreakers: Record<string, { failures: number; isOpen: boolean; resetAt: string | null }>;
} {
  return {
    backend: appConfig.ai.backend,
    model: appConfig.ai.modelId,
    region: appConfig.aws.region,
    temperature: appConfig.ai.temperature,
    maxTokens: appConfig.ai.maxTokens,
    promptCount: getAllPrompts().length,
    cacheStats: getModelCacheStats(),
    circuitBreakers: getCircuitBreakerStatus(),
  };
}

export function getInferenceMetrics(): {
  recentOperations: InferenceMetrics[];
  totalCostUsd: number;
  operationsByTier: Record<string, { count: number; avgLatencyMs: number; totalCostUsd: number; cachedCount: number }>;
} {
  const totalCostUsd = inferenceLog.reduce((sum, m) => sum + m.costEstimateUsd, 0);
  const byTier: Record<string, { count: number; avgLatencyMs: number; totalCostUsd: number; cachedCount: number }> = {};
  for (const m of inferenceLog) {
    if (!byTier[m.tier]) byTier[m.tier] = { count: 0, avgLatencyMs: 0, totalCostUsd: 0, cachedCount: 0 };
    byTier[m.tier].count++;
    byTier[m.tier].totalCostUsd += m.costEstimateUsd;
    byTier[m.tier].avgLatencyMs += m.latencyMs;
    if (m.cached) byTier[m.tier].cachedCount++;
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

export {
  getPromptCatalogSummary,
  getAllPrompts as getAllRegisteredPrompts,
  getPromptAuditLog,
  getPromptVersionHistory,
  getOrgUsageSummary as getAiOrgUsage,
  getAllOrgUsageSummaries as getAllAiOrgUsage,
  setOrgBudget as setAiOrgBudget,
  clearModelCache,
};

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
