import { db, pool } from "./db";
import { entities } from "@shared/schema";
import type { Alert, Incident } from "@shared/schema";
import { inArray } from "drizzle-orm";
import { getEnrichmentForEntity } from "./threat-enrichment";
import { getCachedOsintIndicators } from "./osint-feeds";
import { config as appConfig } from "./config";
import { logger } from "./logger";
import {
  invokeModel as gatewayInvoke,
  invokeModelStream as gatewayInvokeStream,
  getCircuitBreakerStatus,
  getModelCacheStats,
  clearModelCache,
} from "./ai/model-gateway";
import type { ModelInvokeResult, StreamCallbacks } from "./ai/model-gateway";
import {
  getPrompt,
  recordPromptInvocation,
  initializeDefaultPrompts,
  getPromptCatalogSummary,
  getAllPrompts,
  getPromptAuditLog,
  getPromptVersionHistory,
  getPromptVersion,
} from "./ai/prompt-registry";
import { getOrgUsageSummary, getAllOrgUsageSummaries, setOrgBudget } from "./ai/budget";
import { registerEnhancedPrompts } from "./ai/enhanced-prompts";
import { buildRAGContext, formatRAGContextForPrompt, type RAGContext } from "./ai/vector-search";
import { buildFewShotAugmentedPrompt, getSuppressedSourcesForContext } from "./ai/active-learning";
import { buildBudgetedNarrativeMessage } from "./ai/narrative-budget";

initializeDefaultPrompts().catch((err) => log.error("Failed to initialize default prompts", { error: String(err) }));
registerEnhancedPrompts();

const log = logger.child("ai");

type InferenceTier = "triage" | "narrative" | "correlation" | "investigation";

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

// In-memory inference log removed — all inference data is now persisted to the
// ai_inference_log DB table via persistInferenceEntry(). The getInferenceMetrics()
// function queries the DB directly, eliminating heap pressure under load and
// surviving restarts.

// ─── Persistent Inference Log (DB-backed) ─────────────────────────────────────

async function persistInferenceEntry(
  metrics: InferenceMetrics,
  success: boolean = true,
  errorMessage?: string,
  orgId?: string,
): Promise<void> {
  try {

    await pool.query(
      `INSERT INTO ai_inference_log (tier, model, prompt_id, prompt_version, input_tokens, output_tokens, latency_ms, cost_estimate_usd, cached, success, error_message, org_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        metrics.tier,
        metrics.model,
        metrics.promptId || null,
        metrics.promptVersion || null,
        metrics.inputTokensEstimate,
        metrics.outputTokensEstimate,
        metrics.latencyMs,
        metrics.costEstimateUsd,
        metrics.cached,
        success,
        errorMessage || null,
        orgId || null,
      ],
    );
  } catch (err) {
    log.warn("Failed to persist inference log entry", { error: String(err) });
  }
}

export async function getInferenceHistory(options: {
  tier?: string;
  limit?: number;
  since?: Date;
  orgId?: string;
}): Promise<
  Array<{
    id: number;
    tier: string;
    model: string;
    promptId: string | null;
    promptVersion: number | null;
    inputTokens: number;
    outputTokens: number;
    latencyMs: number;
    costEstimateUsd: number;
    cached: boolean;
    success: boolean;
    errorMessage: string | null;
    orgId: string | null;
    createdAt: string;
  }>
> {

  const safeLimit = Math.min(Math.max(options.limit || 100, 1), 1000);
  const since = options.since || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // default 7 days

  let query: string;
  let params: unknown[];
  if (options.tier && options.orgId) {
    query = `SELECT * FROM ai_inference_log WHERE tier = $1 AND created_at >= $2 AND org_id = $3 ORDER BY created_at DESC LIMIT $4`;
    params = [options.tier, since.toISOString(), options.orgId, safeLimit];
  } else if (options.tier) {
    query = `SELECT * FROM ai_inference_log WHERE tier = $1 AND created_at >= $2 ORDER BY created_at DESC LIMIT $3`;
    params = [options.tier, since.toISOString(), safeLimit];
  } else if (options.orgId) {
    query = `SELECT * FROM ai_inference_log WHERE created_at >= $1 AND org_id = $2 ORDER BY created_at DESC LIMIT $3`;
    params = [since.toISOString(), options.orgId, safeLimit];
  } else {
    query = `SELECT * FROM ai_inference_log WHERE created_at >= $1 ORDER BY created_at DESC LIMIT $2`;
    params = [since.toISOString(), safeLimit];
  }

  const result = await pool.query(query, params);
  return result.rows.map((row: Record<string, unknown>) => ({
    id: row.id as number,
    tier: row.tier as string,
    model: row.model as string,
    promptId: (row.prompt_id as string) || null,
    promptVersion: (row.prompt_version as number) || null,
    inputTokens: row.input_tokens as number,
    outputTokens: row.output_tokens as number,
    latencyMs: row.latency_ms as number,
    costEstimateUsd: row.cost_estimate_usd as number,
    cached: row.cached as boolean,
    success: row.success as boolean,
    errorMessage: (row.error_message as string) || null,
    orgId: (row.org_id as string) || null,
    createdAt: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
  }));
}

export async function getInferenceStats(
  days: number = 7,
  orgId?: string,
): Promise<{
  dailyStats: Array<{
    date: string;
    totalRequests: number;
    successCount: number;
    errorCount: number;
    avgLatencyMs: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    totalCostUsd: number;
  }>;
  tierStats: Record<
    string,
    {
      totalRequests: number;
      successRate: number;
      avgLatencyMs: number;
      p95LatencyMs: number;
      totalCostUsd: number;
    }
  >;
}> {

  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const orgFilter = orgId ? ` AND org_id = $2` : ``;
  const dailyParams: unknown[] = orgId ? [since, orgId] : [since];

  // Daily aggregation
  const dailyResult = await pool.query(
    `SELECT
       DATE(created_at) as date,
       COUNT(*)::int as total_requests,
       COUNT(*) FILTER (WHERE success = true)::int as success_count,
       COUNT(*) FILTER (WHERE success = false)::int as error_count,
       COALESCE(AVG(latency_ms), 0)::int as avg_latency_ms,
       COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latency_ms), 0)::int as p50_latency_ms,
       COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::int as p95_latency_ms,
       COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms), 0)::int as p99_latency_ms,
       COALESCE(SUM(cost_estimate_usd), 0) as total_cost_usd
     FROM ai_inference_log
     WHERE created_at >= $1${orgFilter}
     GROUP BY DATE(created_at)
     ORDER BY date ASC`,
    dailyParams,
  );

  // Per-tier aggregation
  const tierResult = await pool.query(
    `SELECT
       tier,
       COUNT(*)::int as total_requests,
       CASE WHEN COUNT(*) > 0 THEN COUNT(*) FILTER (WHERE success = true)::float / COUNT(*)::float ELSE 1 END as success_rate,
       COALESCE(AVG(latency_ms), 0)::int as avg_latency_ms,
       COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::int as p95_latency_ms,
       COALESCE(SUM(cost_estimate_usd), 0) as total_cost_usd
     FROM ai_inference_log
     WHERE created_at >= $1${orgFilter}
     GROUP BY tier`,
    dailyParams,
  );

  const dailyStats = dailyResult.rows.map((row: Record<string, unknown>) => ({
    date: row.date ? (row.date as Date).toISOString().split("T")[0] : "",
    totalRequests: row.total_requests as number,
    successCount: row.success_count as number,
    errorCount: row.error_count as number,
    avgLatencyMs: row.avg_latency_ms as number,
    p50LatencyMs: row.p50_latency_ms as number,
    p95LatencyMs: row.p95_latency_ms as number,
    p99LatencyMs: row.p99_latency_ms as number,
    totalCostUsd: Number(row.total_cost_usd) || 0,
  }));

  const tierStats: Record<
    string,
    { totalRequests: number; successRate: number; avgLatencyMs: number; p95LatencyMs: number; totalCostUsd: number }
  > = {};
  for (const row of tierResult.rows) {
    const r = row as Record<string, unknown>;
    tierStats[r.tier as string] = {
      totalRequests: r.total_requests as number,
      successRate: Number(r.success_rate) || 1,
      avgLatencyMs: r.avg_latency_ms as number,
      p95LatencyMs: r.p95_latency_ms as number,
      totalCostUsd: Number(r.total_cost_usd) || 0,
    };
  }

  return { dailyStats, tierStats };
}

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
      : tier === "investigation"
        ? {
            modelId: appConfig.ai.investigation.modelId,
            sagemakerEndpoint: undefined,
            maxTokens: maxTokensOverride || appConfig.ai.investigation.maxTokens,
            temperature: appConfig.ai.investigation.temperature,
          }
        : {
            modelId: appConfig.ai.modelId,
            sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
            maxTokens: maxTokensOverride || appConfig.ai.maxTokens,
            temperature: appConfig.ai.temperature,
          };

  // Inject few-shot examples from active learning if available
  // Use the inference tier (triage/correlation/narrative) as the domain key,
  // not the promptId — few-shot examples are stored by domain
  let augmentedSystemPrompt = prompt.systemPrompt;
  try {
    const fewShotBlock = await buildFewShotAugmentedPrompt(tier, orgId);
    if (fewShotBlock) {
      augmentedSystemPrompt = `${prompt.systemPrompt}\n\n${fewShotBlock}`;
    }
  } catch (err) {
    log.warn("Failed to build few-shot augmented prompt", { promptId, tier, error: String(err) });
  }

  const result: ModelInvokeResult = await gatewayInvoke({
    modelId: modelConfig.modelId,
    backend: appConfig.ai.backend,
    systemPrompt: augmentedSystemPrompt,
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

  // Persist to DB (non-blocking) — no in-memory array needed
  persistInferenceEntry(metrics, true, undefined, orgId).catch((err) =>
    log.warn("Failed to persist inference entry", { error: String(err), orgId }),
  );

  return { text: result.text, metrics };
}

/**
 * Stream an AI invocation via SSE. Sends text chunks as they arrive from the model.
 * The onChunk callback receives each text delta; onComplete fires when done.
 */
export async function invokeWithPromptStream(
  promptId: string,
  userMessage: string,
  tier: InferenceTier,
  callbacks: StreamCallbacks,
  orgId?: string,
  maxTokensOverride?: number,
): Promise<void> {
  const prompt = await getPrompt(promptId);
  if (!prompt) {
    callbacks.onError(new Error(`Prompt "${promptId}" not found in registry`));
    return;
  }

  if (prompt.deprecated) {
    log.warn("Using deprecated prompt (streaming)", { promptId, version: prompt.version });
  }

  const modelConfig =
    tier === "triage"
      ? {
          modelId: appConfig.ai.triage.modelId,
          sagemakerEndpoint: appConfig.ai.triage.sagemakerEndpoint,
          maxTokens: maxTokensOverride || appConfig.ai.triage.maxTokens,
          temperature: appConfig.ai.triage.temperature,
        }
      : tier === "investigation"
        ? {
            modelId: appConfig.ai.investigation.modelId,
            sagemakerEndpoint: undefined,
            maxTokens: maxTokensOverride || appConfig.ai.investigation.maxTokens,
            temperature: appConfig.ai.investigation.temperature,
          }
        : {
            modelId: appConfig.ai.modelId,
            sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
            maxTokens: maxTokensOverride || appConfig.ai.maxTokens,
            temperature: appConfig.ai.temperature,
          };

  // Inject few-shot examples from active learning (same as non-streaming path)
  let augmentedSystemPrompt = prompt.systemPrompt;
  try {
    const fewShotBlock = await buildFewShotAugmentedPrompt(tier, orgId);
    if (fewShotBlock) {
      augmentedSystemPrompt = `${prompt.systemPrompt}\n\n${fewShotBlock}`;
    }
  } catch (err) {
    log.warn("Failed to build few-shot augmented prompt (streaming)", { promptId, tier, error: String(err) });
  }

  await gatewayInvokeStream(
    {
      modelId: modelConfig.modelId,
      backend: appConfig.ai.backend,
      systemPrompt: augmentedSystemPrompt,
      userMessage,
      maxTokens: modelConfig.maxTokens,
      temperature: modelConfig.temperature,
      topP: appConfig.ai.topP,
      sagemakerEndpoint: modelConfig.sagemakerEndpoint,
      orgId,
      promptId: prompt.id,
      promptVersion: prompt.version,
      tier,
      skipCache: true, // streaming should always skip cache
    },
    {
      onChunk: callbacks.onChunk,
      onComplete: async (fullText, metrics) => {
        recordPromptInvocation(prompt.id, prompt.version, {
          tier,
          modelId: modelConfig.modelId,
          latencyMs: metrics.latencyMs,
          cached: false,
          orgId,
        }).catch((err) => log.warn("Failed to record streaming prompt invocation", { error: String(err) }));

        const im: InferenceMetrics = {
          tier,
          model: modelConfig.modelId,
          inputTokensEstimate: metrics.inputTokens,
          outputTokensEstimate: metrics.outputTokens,
          latencyMs: metrics.latencyMs,
          costEstimateUsd: 0,
          cached: false,
          promptId: prompt.id,
          promptVersion: prompt.version,
        };
        // Persist to DB (non-blocking) — no in-memory array needed
        persistInferenceEntry(im, true, undefined, orgId).catch((err) =>
          log.warn("Failed to persist inference entry", { error: String(err), orgId }),
        );

        await callbacks.onComplete(fullText, metrics);
      },
      onError: callbacks.onError,
    },
  );
}

/**
 * Stream a narrative generation via SSE. Builds the user message and streams
 * the AI response chunk-by-chunk.
 */
export async function streamNarrative(
  incident: Incident,
  alerts: Alert[],
  threatIntelCtx: ThreatIntelContext,
  callbacks: StreamCallbacks,
  orgId?: string,
): Promise<void> {
  const userMessage = buildNarrativeUserMessage(incident, alerts);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;
  await invokeWithPromptStream("narrative", finalUserMessage, "narrative", callbacks, orgId, 6144);
}

/**
 * Stream a deep investigation via SSE.
 */
export async function streamDeepInvestigation(
  incident: Incident,
  alerts: Alert[],
  threatIntelCtx: ThreatIntelContext | undefined,
  callbacks: StreamCallbacks,
  orgId?: string,
): Promise<void> {
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
      hostname: a.hostname,
      mitreTactic: a.mitreTactic,
      mitreTechnique: a.mitreTechnique,
      detectedAt: a.detectedAt,
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

  await invokeWithPromptStream("deep-investigation", userMessage, "investigation", callbacks, orgId, 8192);
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
  suppressedSources?: string[];
  /** Items that were summarized rather than included in full (low-relevance). */
  droppedSummary?: string;
}

export async function buildThreatIntelContext(alerts: Alert[]): Promise<ThreatIntelContext> {
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

    // Check suppressed sources BEFORE early return so alerts without IOCs still get suppression info
    try {
      const orgId = alerts[0]?.orgId;
      if (orgId) {
        const suppressedKeys = await getSuppressedSourcesForContext(orgId);
        if (suppressedKeys.size > 0) {
          const suppressedList: string[] = [];
          suppressedKeys.forEach((key) => {
            suppressedList.push(key.replace("::", "/"));
          });
          result.suppressedSources = suppressedList;
          log.info("Active learning: suppressed low-signal sources from AI context", {
            orgId,
            suppressedCount: suppressedList.length,
          });
        }
      }
    } catch (err) {
      log.warn("Failed to check suppressed sources", { error: String(err) });
    }

    if (iocSet.size === 0) return result;

    const iocValues = Array.from(iocSet.keys());

    try {
      const matchingEntities = await db.select().from(entities).where(inArray(entities.value, iocValues)).limit(100);

      for (const entity of matchingEntities) {
        const enrichment = getEnrichmentForEntity(entity.metadata as Record<string, unknown> | null);
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
      const tagStr = item.tags.length > 0 ? ` [tags: ${item.tags.join(", ")}]` : "";
      const line = `- ${item.ioc} (${item.iocType}): ${item.verdict.toUpperCase()} (score: ${item.reputationScore.toFixed(2)}) via ${item.provider}${tagStr}`;
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
      const tagStr = item.tags.length > 0 ? ` [tags: ${item.tags.join(", ")}]` : "";
      const line = `- ${item.ioc} (${item.iocType}): Matched in ${item.feedName} - threat: ${item.threat} (confidence: ${item.confidence})${tagStr}`;
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
  const hasEnrichment = ctx.enrichmentResults.length > 0;
  const hasOsint = ctx.osintMatches.length > 0;
  const hasSuppressed = ctx.suppressedSources && ctx.suppressedSources.length > 0;
  const hasHistorical = !!ctx.historicalContext;
  const hasDropped = !!ctx.droppedSummary;
  if (!hasEnrichment && !hasOsint && !hasSuppressed && !hasHistorical && !hasDropped) {
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

  // Note suppressed sources if any
  if (ctx.suppressedSources && ctx.suppressedSources.length > 0) {
    lines.push(
      `NOTE: The following alert source/category combinations have been auto-suppressed due to persistently high false positive rates (>70%): ${ctx.suppressedSources.join(", ")}. Treat alerts from these sources with extra skepticism and weight other evidence more heavily.`,
    );
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
  alertsData: Alert[],
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<CorrelationResult> {
  const userMessage = buildCorrelationUserMessage(alertsData);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("correlation", finalUserMessage, "correlation", orgId);
  return JSON.parse(extractJson(text));
}

function buildCorrelationUserMessage(alertsData: Alert[]): string {
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
  incident: Incident,
  alerts: Alert[],
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<NarrativeResult> {
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";

  // Token budget: pack highest-severity alerts within budget, reserve space for response
  const budgeted = buildBudgetedNarrativeMessage(incident, alerts, threatIntelBlock, 6144, 2048);

  if (budgeted.alertsTruncated > 0) {
    log.info("Narrative token budget applied", {
      incidentId: incident.id,
      alertsIncluded: budgeted.alertsIncluded,
      alertsTruncated: budgeted.alertsTruncated,
      totalInputTokens: budgeted.totalInputTokens,
    });
  }

  const finalUserMessage = budgeted.message;

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

function buildNarrativeUserMessage(incident: Incident, alerts: Alert[]): string {
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
  alertData: Alert,
  threatIntelCtx?: ThreatIntelContext,
  orgId?: string,
): Promise<TriageResult> {
  const userMessage = buildTriageUserMessage(alertData);
  const threatIntelBlock = threatIntelCtx ? formatThreatIntelForPrompt(threatIntelCtx) : "";
  const finalUserMessage = threatIntelBlock ? `${userMessage}\n\n${threatIntelBlock}` : userMessage;

  const { text } = await invokeWithPrompt("triage", finalUserMessage, "triage", orgId);
  return JSON.parse(extractJson(text));
}

function buildTriageUserMessage(alertData: Alert): string {
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

export async function getInferenceMetrics(): Promise<{
  recentOperations: InferenceMetrics[];
  totalCostUsd: number;
  operationsByTier: Record<string, { count: number; avgLatencyMs: number; totalCostUsd: number; cachedCount: number }>;
}> {
  try {


    // Fetch recent 20 operations from DB
    const recentResult = await pool.query(
      `SELECT tier, model, prompt_id, prompt_version, input_tokens, output_tokens,
              latency_ms, cost_estimate_usd, cached
       FROM ai_inference_log ORDER BY created_at DESC LIMIT 20`,
    );
    const recentOperations: InferenceMetrics[] = recentResult.rows.map((r: Record<string, unknown>) => ({
      tier: r.tier as InferenceTier,
      model: r.model as string,
      inputTokensEstimate: r.input_tokens as number,
      outputTokensEstimate: r.output_tokens as number,
      latencyMs: r.latency_ms as number,
      costEstimateUsd: Number(r.cost_estimate_usd) || 0,
      cached: r.cached as boolean,
      promptId: (r.prompt_id as string) || undefined,
      promptVersion: (r.prompt_version as number) || undefined,
    }));

    // Aggregate by tier from DB
    const tierResult = await pool.query(
      `SELECT tier,
              COUNT(*)::int AS cnt,
              COALESCE(AVG(latency_ms), 0)::int AS avg_latency,
              COALESCE(SUM(cost_estimate_usd), 0) AS total_cost,
              COUNT(*) FILTER (WHERE cached = true)::int AS cached_count
       FROM ai_inference_log GROUP BY tier`,
    );
    const byTier: Record<string, { count: number; avgLatencyMs: number; totalCostUsd: number; cachedCount: number }> =
      {};
    let totalCostUsd = 0;
    for (const row of tierResult.rows) {
      const r = row as Record<string, unknown>;
      const cost = Number(r.total_cost) || 0;
      byTier[r.tier as string] = {
        count: r.cnt as number,
        avgLatencyMs: r.avg_latency as number,
        totalCostUsd: cost,
        cachedCount: r.cached_count as number,
      };
      totalCostUsd += cost;
    }

    return {
      recentOperations,
      totalCostUsd: Math.round(totalCostUsd * 1000000) / 1000000,
      operationsByTier: byTier,
    };
  } catch (err) {
    log.warn("Failed to fetch inference metrics from DB", { error: String(err) });
    return { recentOperations: [], totalCostUsd: 0, operationsByTier: {} };
  }
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
  getPromptVersion,
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
    initialAccess: Record<string, unknown>;
    nodes: Array<Record<string, unknown>>;
    edges: Array<Record<string, unknown>>;
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
    infrastructureFingerprint: Record<string, unknown>;
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
    evidence: Array<Record<string, unknown>>;
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
    evidence: Array<Record<string, unknown>>;
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
  incident: Incident,
  alerts: Alert[],
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
    const { text } = await invokeWithPrompt("deep-investigation", userMessage, "investigation", orgId, 8192);
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
  telemetryData: Record<string, unknown> | Array<Record<string, unknown>>,
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
  entityContext: Record<string, unknown>,
  activityData: Record<string, unknown> | Array<Record<string, unknown>>,
  baselineData: Record<string, unknown>,
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
  compromiseState: Record<string, unknown>,
  networkTopology: Record<string, unknown>,
  crownJewels: string[],
  securityControls: Record<string, unknown>,
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
    const { text } = await invokeWithPrompt("attack-path-prediction", userMessage, "investigation", orgId, 6144);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("AI attack path prediction unavailable, returning heuristic fallback", { error: String(error) });
    return buildHeuristicAttackPaths(compromiseState, crownJewels);
  }
}

// ==========================================
// ─── Multi-Turn Investigation Chat ──────────────────────────────────────────────
export interface InvestigationChatResponse {
  reply: string;
  suggestedFollowups: string[];
  referencedTechniques: string[];
  confidence: number;
}

export async function conductMultiTurnInvestigation(
  incidentContext: string,
  conversationHistory: Array<{ role: string; content: string }>,
  userMessage: string,
  orgId: string,
): Promise<InvestigationChatResponse> {
  const historyBlock = conversationHistory.map((m) => `[${m.role.toUpperCase()}]: ${m.content}`).join("\n\n");

  const prompt = `You are a senior SOC analyst conducting a deep investigation on a security incident.

INCIDENT CONTEXT:
${incidentContext}

CONVERSATION HISTORY:
${historyBlock}

NEW ANALYST QUESTION:
${userMessage}

Respond as a JSON object with these fields:
- reply: Your detailed analytical response
- suggestedFollowups: Array of 2-3 follow-up questions the analyst should consider
- referencedTechniques: Array of MITRE ATT&CK technique IDs referenced (e.g. ["T1059", "T1078"])
- confidence: Number 0-1 indicating your confidence in the analysis`;

  try {
    const { text } = await invokeWithPrompt("multi-turn-investigation", prompt, "investigation", orgId, 8192);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("Multi-turn investigation unavailable, returning fallback", { error: String(error) });
    return {
      reply: `Based on the available evidence, here is a preliminary analysis of your question: "${userMessage}". Further manual investigation is recommended as AI analysis is currently unavailable.`,
      suggestedFollowups: [
        "What lateral movement indicators are present?",
        "Are there any persistence mechanisms established?",
        "What data exfiltration channels should we check?",
      ],
      referencedTechniques: [],
      confidence: 0.1,
    };
  }
}

// ─── AI-Generated Detection Rules ───────────────────────────────────────────────
export interface GeneratedDetectionRule {
  name: string;
  description: string;
  sigmaRule: string;
  conditionTree: Record<string, unknown>;
  mitreTactic: string;
  mitreTechnique: string;
  confidence: number;
  falsePositiveNotes: string;
  eventTypes: string[];
}

export interface DetectionRuleGenerationResult {
  rules: GeneratedDetectionRule[];
  analysisNotes: string;
  coverageGaps: string[];
}

export async function generateDetectionRules(
  incidentSummary: string,
  attackTechniques: string[],
  indicators: string[],
  orgId: string,
): Promise<DetectionRuleGenerationResult> {
  const userMessage = `Generate Sigma-compatible detection rules based on this attack analysis.

INCIDENT SUMMARY:
${incidentSummary}

ATTACK TECHNIQUES OBSERVED:
${attackTechniques.join(", ")}

INDICATORS OF COMPROMISE:
${indicators.join("\n")}

Generate detection rules as JSON:
{
  "rules": [
    {
      "name": "Rule name",
      "description": "What it detects",
      "sigmaRule": "Full Sigma YAML as a string",
      "conditionTree": { "field": "value", "operator": "contains" },
      "mitreTactic": "tactic-name",
      "mitreTechnique": "T1234",
      "confidence": 0.85,
      "falsePositiveNotes": "When this might false-positive",
      "eventTypes": ["process_creation", "network_connection"]
    }
  ],
  "analysisNotes": "Summary of detection strategy",
  "coverageGaps": ["Areas not covered by these rules"]
}`;

  try {
    const { text } = await invokeWithPrompt("detection-rule-generation", userMessage, "investigation", orgId, 8192);
    return JSON.parse(extractJson(text));
  } catch (error) {
    log.warn("Detection rule generation unavailable, returning fallback", { error: String(error) });
    return {
      rules: attackTechniques.map((tech) => ({
        name: `Auto-detect ${tech}`,
        description: `Detection rule for ${tech} technique observed in incident`,
        sigmaRule: `title: Auto-detect ${tech}\nstatus: experimental\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\nlevel: medium`,
        conditionTree: { EventID: 1 },
        mitreTactic: "unknown",
        mitreTechnique: tech,
        confidence: 0.3,
        falsePositiveNotes: "AI-generated rule — requires manual tuning",
        eventTypes: ["process_creation"],
      })),
      analysisNotes: "Fallback rules generated — AI analysis was unavailable",
      coverageGaps: ["Full behavioral analysis not available", "Lateral movement detection may be incomplete"],
    };
  }
}

// Heuristic Fallback Functions
// ==========================================
// These provide meaningful data-driven responses when AI/LLM is unavailable,
// using deterministic analysis of the provided telemetry data.

function buildHeuristicInvestigation(incident: Incident, alerts: Alert[]): DeepInvestigationResult {
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
  } as unknown as DeepInvestigationResult; /* eslint-disable-line @typescript-eslint/no-unsafe-return -- heuristic fallback returns simplified shape consumed by JSON serialization */
}

function buildHeuristicThreatHunt(huntContext: string, telemetryData: Record<string, unknown> | Array<Record<string, unknown>>): ThreatHuntingResult {
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
  entityContext: Record<string, unknown>,
  activityData: Record<string, unknown> | Array<Record<string, unknown>>,
  baselineData: Record<string, unknown>,
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

function buildHeuristicAttackPaths(compromiseState: Record<string, unknown>, crownJewels: string[]): AttackPathPredictionResult {
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
