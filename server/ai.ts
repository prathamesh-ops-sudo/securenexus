import { db } from "./db";
import { entities } from "@shared/schema";
import { inArray } from "drizzle-orm";
import { getEnrichmentForEntity } from "./threat-enrichment";
import { getCachedOsintIndicators } from "./osint-feeds";
import { config as appConfig } from "./config";
import { logger } from "./logger";
import {
  invokeModel as gatewayInvoke,
  getCircuitBreakerStatus,
  getModelCacheStats,
  clearModelCache,
} from "./ai/model-gateway";
import type { ModelInvokeResult } from "./ai/model-gateway";
import {
  getPrompt,
  recordPromptInvocation,
  initializeDefaultPrompts,
  getPromptCatalogSummary,
  getAllPrompts,
  getPromptAuditLog,
  getPromptVersionHistory,
} from "./ai/prompt-registry";
import { getOrgUsageSummary, getAllOrgUsageSummaries, setOrgBudget } from "./ai/budget";
import { registerEnhancedPrompts } from "./ai/enhanced-prompts";
import { buildRAGContext, formatRAGContextForPrompt, type RAGContext } from "./ai/vector-search";

initializeDefaultPrompts().catch((err) => log.error("Failed to initialize default prompts", { error: String(err) }));
registerEnhancedPrompts();

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
  const prompt = await getPrompt(promptId);
  if (!prompt) {
    throw new Error(`Prompt "${promptId}" not found in registry`);
  }

  if (prompt.deprecated) {
    log.warn("Using deprecated prompt", { promptId, version: prompt.version, supersededBy: prompt.supersededBy });
  }

  const modelConfig =
    tier === "triage"
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

  await recordPromptInvocation(prompt.id, prompt.version, {
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

// ─── Relevance Scoring ────────────────────────────────────────────────────────

interface ScoredEnrichmentResult {
  ioc: string;
  iocType: string;
  provider: string;
  verdict: string;
  reputationScore: number;
  tags: string[];
  /** Relevance score: malicious=3, suspicious=2, clean/unknown=1 */
  relevanceScore: number;
}

interface ScoredOsintMatch {
  ioc: string;
  iocType: string;
  feedName: string;
  threat: string;
  confidence: number;
  tags: string[];
  /** Relevance score based on confidence + threat type */
  relevanceScore: number;
}

function scoreEnrichmentResult(r: { verdict: string; reputationScore: number; tags: string[] }): number {
  let score = 1;
  if (r.verdict === "malicious") score = 3;
  else if (r.verdict === "suspicious") score = 2;
  // Boost for high reputation scores (scale 0-1)
  score += r.reputationScore >= 0.8 ? 1 : r.reputationScore >= 0.5 ? 0.5 : 0;
  // Boost for actionable tags
  const boostTags = ["c2", "botnet", "ransomware", "apt", "exploit", "phishing", "malware"];
  if (r.tags.some((t) => boostTags.includes(t.toLowerCase()))) score += 0.5;
  return score;
}

function scoreOsintMatch(m: { confidence: number; threat: string }): number {
  let score = 1;
  // Confidence-based scoring
  if (m.confidence >= 90) score = 3;
  else if (m.confidence >= 70) score = 2.5;
  else if (m.confidence >= 50) score = 2;
  // Boost for high-severity threat types
  const highThreat = ["apt", "ransomware", "c2", "exploit", "zero-day"];
  if (highThreat.some((t) => m.threat.toLowerCase().includes(t))) score += 0.5;
  return score;
}

/**
 * Rough token estimation: ~4 chars per token for English text.
 * Each enrichment line is roughly 80-150 chars = ~20-40 tokens.
 */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/** Default token budget for threat intel context (30% of a 4096-token window). */
const DEFAULT_TI_TOKEN_BUDGET = 1228;

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
  historicalContext?: RAGContext;
  /** Items that were summarized rather than included in full (low-relevance). */
  droppedSummary?: string;
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
      const matchingEntities = await db.select().from(entities).where(inArray(entities.value, iocValues)).limit(100);

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

    // ── Ranked context packing ──────────────────────────────────────────────
    // Score each item by relevance, sort descending, pack highest-score first
    // up to token budget, then summarize the rest instead of dropping them.

    const scoredEnrichment: ScoredEnrichmentResult[] = result.enrichmentResults.map((r) => ({
      ...r,
      relevanceScore: scoreEnrichmentResult(r),
    }));
    scoredEnrichment.sort((a, b) => b.relevanceScore - a.relevanceScore);

    const scoredOsint: ScoredOsintMatch[] = result.osintMatches.map((m) => ({
      ...m,
      relevanceScore: scoreOsintMatch(m),
    }));
    scoredOsint.sort((a, b) => b.relevanceScore - a.relevanceScore);

    // Pack into token budget — high-score items first
    const tokenBudget = DEFAULT_TI_TOKEN_BUDGET;
    let tokensUsed = 0;

    const packedEnrichment: typeof result.enrichmentResults = [];
    const droppedEnrichment: typeof result.enrichmentResults = [];

    for (const item of scoredEnrichment) {
      const line = `- ${item.ioc} (${item.iocType}): ${item.verdict.toUpperCase()} (score: ${item.reputationScore.toFixed(2)}) via ${item.provider}`;
      const lineTokens = estimateTokens(line);
      if (tokensUsed + lineTokens <= tokenBudget * 0.6) {
        // 60% of budget for enrichment
        packedEnrichment.push(item);
        tokensUsed += lineTokens;
      } else {
        droppedEnrichment.push(item);
      }
    }

    const packedOsint: typeof result.osintMatches = [];
    const droppedOsint: typeof result.osintMatches = [];
    let osintTokens = 0;

    for (const item of scoredOsint) {
      const line = `- ${item.ioc} (${item.iocType}): Matched in ${item.feedName} - threat: ${item.threat} (confidence: ${item.confidence})`;
      const lineTokens = estimateTokens(line);
      if (osintTokens + lineTokens <= tokenBudget * 0.4) {
        // 40% of budget for OSINT
        packedOsint.push(item);
        osintTokens += lineTokens;
      } else {
        droppedOsint.push(item);
      }
    }

    result.enrichmentResults = packedEnrichment;
    result.osintMatches = packedOsint;

    // Summarize dropped items instead of discarding them entirely
    if (droppedEnrichment.length > 0 || droppedOsint.length > 0) {
      const summaryParts: string[] = [];

      if (droppedEnrichment.length > 0) {
        const verdictCounts: Record<string, number> = {};
        const uniqueIocs = new Set<string>();
        for (const d of droppedEnrichment) {
          verdictCounts[d.verdict] = (verdictCounts[d.verdict] || 0) + 1;
          uniqueIocs.add(d.ioc);
        }
        const verdictStr = Object.entries(verdictCounts)
          .map(([v, c]) => `${c} ${v}`)
          .join(", ");
        summaryParts.push(
          `${droppedEnrichment.length} additional enrichment results (${uniqueIocs.size} unique IOCs: ${verdictStr}) were deprioritized due to lower relevance scores`,
        );
      }

      if (droppedOsint.length > 0) {
        const feeds = new Set(droppedOsint.map((d) => d.feedName));
        const avgConf = droppedOsint.reduce((sum, d) => sum + d.confidence, 0) / droppedOsint.length;
        summaryParts.push(
          `${droppedOsint.length} additional OSINT matches from ${feeds.size} feed(s) (avg confidence: ${avgConf.toFixed(0)}%) were deprioritized`,
        );
      }

      result.droppedSummary = summaryParts.join(". ") + ".";
      log.info("Ranked context packing applied", {
        enrichmentPacked: packedEnrichment.length,
        enrichmentDropped: droppedEnrichment.length,
        osintPacked: packedOsint.length,
        osintDropped: droppedOsint.length,
        tokensUsed: tokensUsed + osintTokens,
        tokenBudget,
      });
    }

    // Build RAG context from alert data
    try {
      const representativeAlert = alerts[0] || {};
      const ragCtx = await buildRAGContext(
        {
          title: representativeAlert.title,
          description: representativeAlert.description,
          mitreTactic: representativeAlert.mitreTactic,
          mitreTechnique: representativeAlert.mitreTechnique,
          sourceIp: representativeAlert.sourceIp,
          destIp: representativeAlert.destIp,
          hostname: representativeAlert.hostname,
          domain: representativeAlert.domain,
          fileHash: representativeAlert.fileHash,
          category: representativeAlert.category,
          severity: representativeAlert.severity,
        },
        representativeAlert.orgId,
      );
      result.historicalContext = ragCtx;
    } catch (ragErr) {
      log.warn("RAG context build failed (non-fatal)", { error: String(ragErr) });
    }

    const maliciousCount = result.enrichmentResults.filter((r) => r.verdict === "malicious").length;
    const suspiciousCount = result.enrichmentResults.filter((r) => r.verdict === "suspicious").length;
    const osintCount = result.osintMatches.length;

    const parts: string[] = [];
    if (maliciousCount > 0) parts.push(`${maliciousCount} IOC(s) flagged as malicious by enrichment providers`);
    if (suspiciousCount > 0) parts.push(`${suspiciousCount} IOC(s) flagged as suspicious`);
    if (osintCount > 0) parts.push(`${osintCount} IOC(s) matched in OSINT threat feeds`);

    if (parts.length > 0) {
      const confidence =
        maliciousCount > 0 || osintCount > 2 ? "High" : suspiciousCount > 0 || osintCount > 0 ? "Moderate" : "Low";
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
  lines.push(
    "The following IOCs from this alert have been cross-referenced against threat intelligence feeds and enrichment providers.",
  );
  lines.push("");

  if (ctx.enrichmentResults.length > 0) {
    lines.push("ENRICHMENT RESULTS (from AbuseIPDB, VirusTotal, OTX AlienVault):");
    for (const r of ctx.enrichmentResults) {
      const tagStr = r.tags.length > 0 ? ` [tags: ${r.tags.join(", ")}]` : "";
      lines.push(
        `- ${r.ioc} (${r.iocType}): ${r.verdict.toUpperCase()} (score: ${r.reputationScore.toFixed(2)}) via ${r.provider}${tagStr}`,
      );
    }
    lines.push("");
  }

  if (ctx.osintMatches.length > 0) {
    lines.push("OSINT FEED MATCHES:");
    for (const m of ctx.osintMatches) {
      const tagStr = m.tags.length > 0 ? ` [tags: ${m.tags.join(", ")}]` : "";
      lines.push(
        `- ${m.ioc} (${m.iocType}): Matched in ${m.feedName} - threat: ${m.threat} (confidence: ${m.confidence})${tagStr}`,
      );
    }
    lines.push("");
  }

  if (ctx.summary) {
    lines.push(`INTELLIGENCE SUMMARY: ${ctx.summary}`);
    lines.push("");
  }

  // Include summary of deprioritized (low-relevance) items so the LLM knows they exist
  if (ctx.droppedSummary) {
    lines.push(
      `ADDITIONAL LOW-PRIORITY CONTEXT (summarized): ${ctx.droppedSummary} These items had lower relevance scores but may still be worth noting for completeness.`,
    );
    lines.push("");
  }

  lines.push(
    "Use this threat intelligence to inform your analysis. IOCs with high reputation scores or OSINT matches should increase your confidence that this is a genuine threat, not a false positive. Cross-reference these findings with the alert telemetry. Items above are ranked by relevance — malicious verdicts and high-confidence OSINT matches appear first.",
  );

  // Append RAG context if available
  if (ctx.historicalContext) {
    const ragBlock = formatRAGContextForPrompt(ctx.historicalContext);
    if (ragBlock) {
      lines.push("");
      lines.push(ragBlock);
    }
  }

  return lines.join("\n");
}

export async function correlateAlerts(
  alertsData: any[],
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<CorrelationResult> {
  const userMessage = buildCorrelationUserMessage(alertsData);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("correlation", finalUserMessage, "correlation", orgId);
  return JSON.parse(extractJson(text));
}

function buildCorrelationUserMessage(alertsData: any[]): string {
  const telemetry = JSON.stringify(
    alertsData.map((a) => ({
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
    })),
    null,
    2,
  );

  return `Correlate these ${alertsData.length} security alerts. Identify attack chains, lateral movement patterns, and coordinated campaigns.\n\nALERT TELEMETRY:\n${telemetry}\n\nRespond with this exact JSON structure:\n{\n  "correlatedGroups": [\n    {\n      "groupName": "descriptive attack chain name",\n      "alertIds": ["id1", "id2"],\n      "confidence": 0.85,\n      "reasoning": "evidence-based explanation citing specific indicators",\n      "suggestedIncidentTitle": "concise incident title",\n      "severity": "critical|high|medium|low",\n      "mitreTactics": ["Initial Access", "Execution"],\n      "mitreTechniques": ["T1566.001", "T1059.001"],\n      "killChainPhases": ["Delivery", "Exploitation"],\n      "diamondModel": {\n        "adversary": "threat actor profile or unknown",\n        "infrastructure": ["malicious IPs/domains"],\n        "capability": "attack capability description",\n        "victim": ["affected hosts/users"]\n      }\n    }\n  ],\n  "uncorrelatedAlertIds": ["standalone alert ids"],\n  "overallAssessment": "strategic threat assessment",\n  "threatLandscape": "broader threat context and recommendations"\n}`;
}

export async function generateIncidentNarrative(
  incident: any,
  alerts: any[],
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<NarrativeResult> {
  const userMessage = buildNarrativeUserMessage(incident, alerts);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("narrative", finalUserMessage, "narrative", orgId, 6144);
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
  const incidentCtx = JSON.stringify(
    {
      title: incident.title,
      summary: incident.summary,
      severity: incident.severity,
      status: incident.status,
      mitreTactics: incident.mitreTactics,
      mitreTechniques: incident.mitreTechniques,
      affectedAssets: incident.affectedAssets,
      createdAt: incident.createdAt,
    },
    null,
    2,
  );

  const alertTelemetry = JSON.stringify(
    alerts.map((a) => ({
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
    })),
    null,
    2,
  );

  return `Generate a comprehensive incident narrative for this security incident.\n\nINCIDENT CONTEXT:\n${incidentCtx}\n\nASSOCIATED ALERT TELEMETRY (${alerts.length} alerts):\n${alertTelemetry}\n\nRespond with this exact JSON structure:\n{\n  "narrative": "detailed multi-paragraph attacker-centric narrative with inline [Alert <id>] citations for every claim. Every paragraph MUST reference at least one alert ID from the provided telemetry.",\n  "citedAlertIds": ["list of all alert IDs explicitly cited in the narrative"],\n  "summary": "one-line executive summary",\n  "attackTimeline": [\n    {"timestamp": "ISO 8601", "description": "action description", "alertId": "source alert", "mitreTechnique": "T1xxx.xxx"}\n  ],\n  "attackerProfile": {\n    "ttps": ["TTP descriptions"],\n    "sophistication": "nation-state|advanced-persistent|organized-crime|intermediate|opportunistic",\n    "likelyMotivation": "financial|espionage|hacktivism|destruction|unknown",\n    "estimatedOrigin": "geographic/organizational origin assessment",\n    "diamondModel": {\n      "adversary": "threat actor characterization",\n      "infrastructure": ["C2 servers, domains, IPs used"],\n      "capability": "tooling and technique sophistication",\n      "victim": ["targeted assets, users, systems"]\n    }\n  },\n  "killChainAnalysis": [\n    {"phase": "Kill Chain phase", "description": "what occurred in this phase", "evidence": ["supporting indicators"]}\n  ],\n  "mitigationSteps": ["NIST-aligned containment and recovery steps"],\n  "iocs": [{"type": "ip|domain|hash|url|email|registry|mutex", "value": "indicator value", "context": "where/how observed"}],\n  "riskScore": 85,\n  "nistPhase": "Detection|Analysis|Containment|Eradication|Recovery"\n}`;
}

export async function triageAlert(
  alertData: any,
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<TriageResult> {
  const userMessage = buildTriageUserMessage(alertData);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("triage", finalUserMessage, "triage", orgId);
  return JSON.parse(extractJson(text));
}

function buildTriageUserMessage(alertData: any): string {
  const telemetry = JSON.stringify(
    {
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
    },
    null,
    2,
  );

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
    const prompt = await getPrompt("health-check");
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

export async function getModelConfig(): Promise<{
  backend: string;
  model: string;
  region: string;
  temperature: number;
  maxTokens: number;
  promptCount: number;
  cacheStats: { size: number; maxSize: number };
  circuitBreakers: Record<string, { failures: number; isOpen: boolean; resetAt: string | null }>;
}> {
  const prompts = await getAllPrompts();
  return {
    backend: appConfig.ai.backend,
    model: appConfig.ai.modelId,
    region: appConfig.aws.region,
    temperature: appConfig.ai.temperature,
    maxTokens: appConfig.ai.maxTokens,
    promptCount: prompts.length,
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

// =============================
// ENHANCED AI CAPABILITIES
// =============================

export interface DeepInvestigationResult {
  executiveSummary: string;
  investigationConfidence: number;
  scopeAssessment: {
    compromisedAssets: Array<{
      type: string;
      name: string;
      confidence: number;
      evidence: string[];
    }>;
    dataImpact: {
      sensitiveDataAccessed: string[];
      exfiltrationConfirmed: boolean;
      estimatedDataVolume: string;
      confidence: number;
    };
    persistenceMechanisms: Array<{
      type: string;
      location: string;
      confidence: number;
    }>;
    totalAssetCount: number;
    criticalAssets: number;
  };
  attackGraph: {
    initialAccess: any;
    nodes: any[];
    edges: any[];
    currentPosition: string;
    objectivesAchieved: string[];
    objectivesInProgress: string[];
  };
  adversaryProfile: {
    sophisticationLevel: string;
    motivation: string;
    targetedOrOpportunistic: string;
    operationalTempo: string;
    ttps: string[];
    tooling: string[];
    infrastructureFingerprint: any;
    attributionConfidence: number;
    possibleThreatActors: string[];
    attributionEvidence: string[];
  };
  hypotheses: Array<{
    hypothesis: string;
    confidence: number;
    supportingEvidence: string[];
    contradictingEvidence: string[];
  }>;
  predictedNextMoves: Array<{
    move: string;
    probability: number;
    indicators: string[];
  }>;
  intelligenceGaps: string[];
  containmentPriority: Array<{
    action: string;
    targets: string[];
    urgency: string;
    rationale: string;
  }>;
  remediationRoadmap: {
    phase1_containment: string[];
    phase2_eradication: string[];
    phase3_recovery: string[];
    phase4_postIncident: string[];
  };
  estimatedDwellTime: string;
  attackTimeline: Array<{
    timestamp: string;
    stage: string;
    description: string;
    technique: string;
    evidence: string[];
    confidence: number;
  }>;
  iocs: Array<{
    type: string;
    value: string;
    context: string;
    pyramidOfPain: string;
    priority: string;
  }>;
  lessonsLearned: string[];
  confidenceStatement: string;
}

export interface ThreatHuntingResult {
  huntMissionId: string;
  hypotheses: Array<{
    id: string;
    hypothesis: string;
    rationale: string;
    priority: string;
    testingMethod: string;
    expectedIndicators: string[];
    confidence: number;
  }>;
  findings: Array<{
    hypothesisId: string;
    finding: string;
    severity: string;
    confidence: number;
    evidence: any[];
    iocs: Array<{ type: string; value: string }>;
    recommendedAction: string;
    escalate: boolean;
  }>;
  anomalies: Array<{
    type: string;
    description: string;
    severity: string;
    confidence: number;
    falsePositiveReason: string;
    huntRecommendation: string;
  }>;
  huntSummary: {
    hypothesesTested: number;
    threatsConfirmed: number;
    threatsLikelyButUnconfirmed: number;
    anomaliesRequiringInvestigation: number;
    cleanFindings: number;
  };
  nextHuntRecommendations: string[];
  toolingGaps: string[];
}

export interface BehavioralAnalysisResult {
  entityId: string;
  entityType: string;
  analysisTimeframe: string;
  behavioralScore: number;
  riskLevel: string;
  anomalies: Array<{
    anomalyType: string;
    description: string;
    severity: string;
    confidence: number;
    deviationMagnitude: string;
    evidence: any[];
    timeframe: string;
    peersComparison: string;
    threatIndicators: string[];
    possibleExplanations: Array<{
      explanation: string;
      likelihood: number;
    }>;
    recommendedAction: string;
  }>;
  behavioralBaseline: {
    typical_login_hours: string;
    typical_geo_locations: string[];
    typical_resources: string[];
    typical_data_volume: string;
    typical_authentication: string[];
  };
  deviationsFromBaseline: Array<{
    metric: string;
    baseline: string;
    observed: string;
    deviation: string;
  }>;
  riskFactors: Array<{
    factor: string;
    riskWeight: number;
  }>;
  recommendation: string;
  confidenceStatement: string;
}

export interface AttackPathPredictionResult {
  currentCompromiseState: {
    accessLevel: string;
    compromisedHosts: string[];
    compromisedAccounts: string[];
    establishedPersistence: string[];
    c2Channels: string[];
  };
  inferredObjectives: Array<{
    objective: string;
    confidence: number;
    reasoning: string;
  }>;
  predictedAttackPaths: Array<{
    pathId: string;
    objective: string;
    probability: number;
    steps: Array<{
      step: number;
      action: string;
      technique: string;
      purpose: string;
      difficulty: string;
      detectability: string;
      success_probability: number;
    }>;
    total_probability: number;
    estimated_time: string;
    indicators: string[];
  }>;
  defenseRecommendations: Array<{
    path: string;
    priority: number;
    defenses: Array<{
      control: string;
      effectiveness: number;
      cost: string;
    }>;
  }>;
  blindSpots: string[];
  worstCaseScenario: {
    scenario: string;
    probability: number;
    impact: string;
    time_to_scenario: string;
    prevention: string;
  };
}

/**
 * Conduct deep forensic investigation with advanced analysis
 */
export async function conductDeepInvestigation(
  incident: any,
  alerts: any[],
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<DeepInvestigationResult> {
  const incidentCtx = JSON.stringify(
    {
      title: incident.title,
      summary: incident.summary,
      severity: incident.severity,
      status: incident.status,
      mitreTactics: incident.mitreTactics,
      mitreTechniques: incident.mitreTechniques,
      affectedAssets: incident.affectedAssets,
      createdAt: incident.createdAt,
    },
    null,
    2,
  );

  const alertTelemetry = JSON.stringify(
    alerts.map((a) => ({
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
    })),
    null,
    2,
  );

  const threatIntelBlock = threatIntelCtx
    ? formatThreatIntelForPrompt(threatIntelCtx)
    : "No threat intelligence available for this incident.";

  const userMessage = `Conduct a deep forensic investigation of this incident.

INCIDENT CONTEXT:
${incidentCtx}

ALERT TELEMETRY (${alerts.length} alerts):
${alertTelemetry}

THREAT INTELLIGENCE:
${threatIntelBlock}`;

  try {
    const { text } = await invokeWithPrompt("deep-investigation", userMessage, "narrative", orgId, 8192);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("AI deep investigation unavailable, returning heuristic fallback", { error: String(error) });
    return buildHeuristicInvestigation(incident, alerts);
  }
}

/**
 * Conduct proactive threat hunting mission
 */
export async function conductThreatHunt(
  huntContext: string,
  telemetryData: any,
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<ThreatHuntingResult> {
  const threatIntelBlock = threatIntelCtx
    ? formatThreatIntelForPrompt(threatIntelCtx)
    : "No threat intelligence available.";

  const userMessage = `Conduct a threat hunting mission on this telemetry.

HUNTING CONTEXT:
${huntContext}

TELEMETRY DATA:
${JSON.stringify(telemetryData, null, 2)}

KNOWN THREAT INTELLIGENCE:
${threatIntelBlock}`;

  try {
    const { text } = await invokeWithPrompt("threat-hunting", userMessage, "correlation", orgId, 6144);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("AI threat hunt unavailable, returning heuristic fallback", { error: String(error) });
    return buildHeuristicThreatHunt(huntContext, telemetryData);
  }
}

/**
 * Analyze behavioral patterns for insider threats and account compromise
 */
export async function analyzeBehavior(
  entityContext: any,
  activityData: any,
  baselineData: any,
  orgId?: string,
): Promise<BehavioralAnalysisResult> {
  const userMessage = `Analyze behavioral patterns in this telemetry for anomalies and threats.

USER/ENTITY CONTEXT:
${JSON.stringify(entityContext, null, 2)}

ACTIVITY TELEMETRY:
${JSON.stringify(activityData, null, 2)}

BASELINE BEHAVIOR:
${JSON.stringify(baselineData, null, 2)}`;

  try {
    const { text } = await invokeWithPrompt("behavioral-analysis", userMessage, "correlation", orgId, 4096);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("AI behavioral analysis unavailable, returning heuristic fallback", { error: String(error) });
    return buildHeuristicBehavioralAnalysis(entityContext, activityData, baselineData);
  }
}

/**
 * Predict attacker's next moves and attack paths
 */
export async function predictAttackPaths(
  compromiseState: any,
  networkTopology: any,
  crownJewels: string[],
  securityControls: any,
  orgId?: string,
): Promise<AttackPathPredictionResult> {
  const userMessage = `Predict the attacker's next moves and possible attack paths.

CURRENT COMPROMISE STATE:
${JSON.stringify(compromiseState, null, 2)}

NETWORK TOPOLOGY:
${JSON.stringify(networkTopology, null, 2)}

HIGH-VALUE ASSETS:
${JSON.stringify(crownJewels, null, 2)}

SECURITY CONTROLS:
${JSON.stringify(securityControls, null, 2)}`;

  try {
    const { text } = await invokeWithPrompt("attack-path-prediction", userMessage, "narrative", orgId, 6144);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("AI attack path prediction unavailable, returning heuristic fallback", { error: String(error) });
    return buildHeuristicAttackPaths(compromiseState, crownJewels);
  }
}

// ==========================================
// Heuristic Fallback Functions
// ==========================================
// These provide meaningful data-driven responses when AI/LLM is unavailable,
// using deterministic analysis of the provided telemetry data.

function buildHeuristicInvestigation(incident: any, alerts: any[]): DeepInvestigationResult {
  const uniqueIPs = new Set(alerts.map((a) => a.sourceIp).filter(Boolean));
  const uniqueHosts = new Set(alerts.map((a) => a.hostname).filter(Boolean));
  const tactics = new Set(alerts.map((a) => a.mitreTactic).filter(Boolean));
  const techniques = new Set(alerts.map((a) => a.mitreTechnique).filter(Boolean));
  const categories = new Set(alerts.map((a) => a.category).filter(Boolean));

  return {
    summary: `Heuristic analysis of incident "${incident.title}" based on ${alerts.length} correlated alerts. AI-enhanced analysis unavailable — results derived from statistical pattern matching.`,
    findings: [
      {
        title: "Alert Correlation Summary",
        severity: incident.severity || "medium",
        description: `${alerts.length} alerts across ${uniqueHosts.size} hosts and ${uniqueIPs.size} source IPs. Categories: ${Array.from(categories).join(", ") || "unknown"}.`,
        evidence: alerts.slice(0, 5).map((a) => `[${a.severity}] ${a.title} (${a.sourceIp || "no IP"})`),
        mitreTactics: Array.from(tactics),
        mitreTechniques: Array.from(techniques),
      },
    ],
    timeline: alerts
      .filter((a) => a.detectedAt)
      .sort((a, b) => new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime())
      .slice(0, 10)
      .map((a) => ({
        timestamp: a.detectedAt,
        event: a.title,
        significance: a.severity === "critical" ? "high" : a.severity === "high" ? "medium" : "low",
      })),
    attackNarrative: `This is a data-driven summary (AI unavailable). ${alerts.length} alerts were correlated into this incident spanning ${uniqueHosts.size} hosts. MITRE ATT&CK coverage: ${Array.from(tactics).join(", ") || "not mapped"}.`,
    recommendations: [
      "Review all correlated alerts for false positives",
      "Isolate affected hosts if compromise is confirmed",
      "Check for lateral movement indicators",
      "Preserve forensic evidence before remediation",
    ],
    confidenceScore: 0.4,
    dataSource: "heuristic_fallback",
  } as any;
}

function buildHeuristicThreatHunt(huntContext: string, telemetryData: any): ThreatHuntingResult {
  const dataPoints = Array.isArray(telemetryData) ? telemetryData.length : 0;
  return {
    huntMissionId: "heuristic_" + Date.now(),
    hypotheses: [
      {
        id: "heuristic_h1",
        hypothesis: `Statistical analysis of ${dataPoints} telemetry data points for context: ${huntContext}`,
        rationale: "Heuristic analysis only — AI-enhanced hunting unavailable",
        priority: "medium",
        testingMethod: "manual_review",
        expectedIndicators: [],
        confidence: 0.3,
      },
    ],
    findings: [],
    anomalies: [],
    huntSummary: {
      hypothesesTested: 1,
      threatsConfirmed: 0,
      threatsLikelyButUnconfirmed: 0,
      anomaliesRequiringInvestigation: 0,
      cleanFindings: 0,
    },
    nextHuntRecommendations: [
      "Manually review telemetry data for anomalies",
      "Cross-reference with known threat intelligence feeds",
      "Consider enabling AI services for deeper analysis",
    ],
    toolingGaps: ["AI-enhanced pattern recognition unavailable"],
  };
}

function buildHeuristicBehavioralAnalysis(
  entityContext: any,
  activityData: any,
  baselineData: any,
): BehavioralAnalysisResult {
  const activities = Array.isArray(activityData) ? activityData.length : 0;
  return {
    entityId: entityContext?.id || "unknown",
    entityType: entityContext?.type || "unknown",
    analysisTimeframe: "last_30_days",
    behavioralScore: 50,
    riskLevel: "medium",
    anomalies: [],
    behavioralBaseline: {
      typical_login_hours: "unknown — AI analysis unavailable",
      typical_geo_locations: [],
      typical_resources: [],
      typical_data_volume: "unknown",
      typical_authentication: [],
    },
    deviationsFromBaseline: [],
    riskFactors: [
      {
        factor: "AI analysis unavailable — heuristic assessment only",
        riskWeight: 0.3,
      },
    ],
    recommendation:
      "Manual review recommended. AI behavioral analysis is unavailable. Review entity activity patterns and compare against known baselines.",
    confidenceStatement: `Low confidence (heuristic only). Analyzed ${activities} activity records without AI enhancement.`,
  };
}

function buildHeuristicAttackPaths(compromiseState: any, crownJewels: string[]): AttackPathPredictionResult {
  return {
    currentCompromiseState: {
      accessLevel: compromiseState?.accessLevel || "unknown",
      compromisedHosts: compromiseState?.compromisedHosts || [],
      compromisedAccounts: compromiseState?.compromisedAccounts || [],
      establishedPersistence: compromiseState?.establishedPersistence || [],
      c2Channels: compromiseState?.c2Channels || [],
    },
    inferredObjectives: [
      {
        objective: "Unknown — AI analysis unavailable",
        confidence: 0,
        reasoning: "Heuristic fallback cannot infer attacker objectives",
      },
    ],
    predictedAttackPaths: crownJewels.map((asset, i) => ({
      pathId: `heuristic_path_${i}`,
      objective: `Reach ${asset}`,
      probability: 0,
      steps: [],
      total_probability: 0,
      estimated_time: "unknown",
      indicators: [],
    })),
    defenseRecommendations: [
      {
        path: "general",
        priority: 1,
        defenses: [
          {
            control: "Enable AI services for automated attack path prediction",
            effectiveness: 0,
            cost: "unknown",
          },
        ],
      },
    ],
    blindSpots: [
      "AI-enhanced attack path prediction unavailable",
      "Manual assessment recommended for high-value asset exposure",
    ],
    worstCaseScenario: {
      scenario: "Unable to predict — AI analysis unavailable",
      probability: 0,
      impact: "unknown",
      time_to_scenario: "unknown",
      prevention: "Manually assess attack paths to high-value assets and review network segmentation",
    },
  };
}
