import { BedrockRuntimeClient, ConverseCommand, ConverseStreamCommand } from "@aws-sdk/client-bedrock-runtime";
import { SageMakerRuntimeClient, InvokeEndpointCommand } from "@aws-sdk/client-sagemaker-runtime";
import { config as appConfig } from "../config";
import { logger } from "../logger";
import { getAwsClientConfig } from "../aws-credentials";
import { trackUsage, checkBudget } from "./budget";
import { countTokens } from "./tokenizer";
import { broadcastEvent } from "../event-bus";

const log = logger.child("model-gateway");

const bedrockClient = new BedrockRuntimeClient(getAwsClientConfig());
const sagemakerClient = new SageMakerRuntimeClient(getAwsClientConfig());

export type ModelBackend = "bedrock" | "sagemaker";

export interface ModelInvokeOptions {
  modelId: string;
  backend: ModelBackend;
  systemPrompt: string;
  userMessage: string;
  maxTokens: number;
  temperature: number;
  topP: number;
  sagemakerEndpoint?: string;
  orgId?: string;
  promptId?: string;
  promptVersion?: number;
  tier?: string;
  skipCache?: boolean;
}

export interface ModelInvokeResult {
  text: string;
  inputTokensEstimate: number;
  outputTokensEstimate: number;
  latencyMs: number;
  costEstimateUsd: number;
  modelId: string;
  backend: ModelBackend;
  cached: boolean;
}

const COST_TABLE: Record<string, { input: number; output: number }> = {
  "amazon.nova-pro-v1:0": { input: 0.0008, output: 0.0032 },
  "amazon.nova-lite-v1:0": { input: 0.00006, output: 0.00024 },
  "mistral.mistral-large-2402-v1:0": { input: 0.004, output: 0.012 },
  "anthropic.claude-3-sonnet-20240229-v1:0": { input: 0.003, output: 0.015 },
  "anthropic.claude-3-haiku-20240307-v1:0": { input: 0.00025, output: 0.00125 },
  "anthropic.claude-sonnet-4-20250514-v1:0": { input: 0.003, output: 0.015 },
  "anthropic.claude-3-5-sonnet-20241022-v2:0": { input: 0.003, output: 0.015 },
  "default-triage": { input: 0.00015, output: 0.0002 },
  default: { input: 0.003, output: 0.015 },
};

const TRIAGE_RATES = { input: 0.00015, output: 0.0002 };

function estimateCost(modelId: string, inputTokens: number, outputTokens: number, tier?: string): number {
  if (tier === "triage") {
    return inputTokens * TRIAGE_RATES.input + outputTokens * TRIAGE_RATES.output;
  }
  const rates = COST_TABLE[modelId] || COST_TABLE["default"];
  return inputTokens * rates.input + outputTokens * rates.output;
}

interface CircuitState {
  failures: number;
  lastFailure: number;
  openUntil: number;
}

const circuitBreakers = new Map<string, CircuitState>();
const CIRCUIT_FAILURE_THRESHOLD = 5;
const CIRCUIT_RESET_MS = 60_000;

function getCircuitKey(backend: ModelBackend, modelId: string): string {
  return `${backend}:${modelId}`;
}

function isCircuitOpen(key: string): boolean {
  const state = circuitBreakers.get(key);
  if (!state) return false;
  if (Date.now() > state.openUntil) {
    circuitBreakers.delete(key);
    return false;
  }
  return state.failures >= CIRCUIT_FAILURE_THRESHOLD;
}

function recordCircuitFailure(key: string): void {
  const state = circuitBreakers.get(key) || { failures: 0, lastFailure: 0, openUntil: 0 };
  state.failures++;
  state.lastFailure = Date.now();
  if (state.failures >= CIRCUIT_FAILURE_THRESHOLD) {
    const isNewTrip = state.openUntil < Date.now();
    state.openUntil = Date.now() + CIRCUIT_RESET_MS;
    if (isNewTrip) {
      gatewayMetrics.circuitBreakerTrips++;
      const [backend, ...modelParts] = key.split(":");
      const modelId = modelParts.join(":");
      broadcastEvent({
        type: "system.ai_circuit_open",
        orgId: null,
        data: {
          modelId,
          backend,
          resetAt: new Date(state.openUntil).toISOString(),
          failureCount: state.failures,
        },
      });
    }
    log.warn("Circuit breaker opened for model", { key, failures: state.failures, resetMs: CIRCUIT_RESET_MS });
  }
  circuitBreakers.set(key, state);
}

function recordCircuitSuccess(key: string): void {
  circuitBreakers.delete(key);
}

interface CacheEntry {
  result: ModelInvokeResult;
  expiresAt: number;
}

const responseCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE_ENTRIES = 200;

interface GatewayMetrics {
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  totalErrors: number;
  retries: number;
  circuitBreakerTrips: number;
  latencyHistory: { timestamp: number; modelId: string; backend: ModelBackend; latencyMs: number; cached: boolean }[];
  errorHistory: { timestamp: number; modelId: string; backend: ModelBackend; error: string; retryable: boolean }[];
  modelStats: Map<string, { requests: number; errors: number; totalLatencyMs: number; cacheHits: number }>;
  startedAt: number;
}

const gatewayMetrics: GatewayMetrics = {
  totalRequests: 0,
  cacheHits: 0,
  cacheMisses: 0,
  totalErrors: 0,
  retries: 0,
  circuitBreakerTrips: 0,
  latencyHistory: [],
  errorHistory: [],
  modelStats: new Map(),
  startedAt: Date.now(),
};

const MAX_HISTORY_ENTRIES = 200;

function getOrCreateModelStats(modelId: string) {
  let stats = gatewayMetrics.modelStats.get(modelId);
  if (!stats) {
    stats = { requests: 0, errors: 0, totalLatencyMs: 0, cacheHits: 0 };
    gatewayMetrics.modelStats.set(modelId, stats);
  }
  return stats;
}

function recordLatency(modelId: string, backend: ModelBackend, latencyMs: number, cached: boolean): void {
  gatewayMetrics.latencyHistory.push({ timestamp: Date.now(), modelId, backend, latencyMs, cached });
  if (gatewayMetrics.latencyHistory.length > MAX_HISTORY_ENTRIES) {
    gatewayMetrics.latencyHistory.splice(0, gatewayMetrics.latencyHistory.length - MAX_HISTORY_ENTRIES);
  }
}

function recordGatewayError(modelId: string, backend: ModelBackend, error: string, retryable: boolean): void {
  gatewayMetrics.totalErrors++;
  gatewayMetrics.errorHistory.push({ timestamp: Date.now(), modelId, backend, error, retryable });
  if (gatewayMetrics.errorHistory.length > MAX_HISTORY_ENTRIES) {
    gatewayMetrics.errorHistory.splice(0, gatewayMetrics.errorHistory.length - MAX_HISTORY_ENTRIES);
  }
  const stats = getOrCreateModelStats(modelId);
  stats.errors++;
}

function buildCacheKey(opts: ModelInvokeOptions): string {
  const raw = `${opts.modelId}|${opts.systemPrompt}|${opts.userMessage}|${opts.maxTokens}|${opts.temperature}`;
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    hash = (hash << 5) - hash + ch;
    hash |= 0;
  }
  return `mc:${hash}`;
}

function getCached(key: string): ModelInvokeResult | undefined {
  const entry = responseCache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    responseCache.delete(key);
    return undefined;
  }
  return { ...entry.result, cached: true };
}

function putCache(key: string, result: ModelInvokeResult): void {
  if (responseCache.size >= MAX_CACHE_ENTRIES) {
    const oldest = responseCache.keys().next().value;
    if (oldest) responseCache.delete(oldest);
  }
  responseCache.set(key, { result, expiresAt: Date.now() + CACHE_TTL_MS });
}

export function clearModelCache(): void {
  responseCache.clear();
}

export function getModelCacheStats(): { size: number; maxSize: number } {
  return { size: responseCache.size, maxSize: MAX_CACHE_ENTRIES };
}

interface BedrockResult {
  text: string;
  inputTokens: number | null;
  outputTokens: number | null;
}

async function invokeBedrockRaw(opts: ModelInvokeOptions): Promise<BedrockResult> {
  try {
    const command = new ConverseCommand({
      modelId: opts.modelId,
      messages: [{ role: "user", content: [{ text: opts.userMessage }] }],
      system: [{ text: opts.systemPrompt }],
      inferenceConfig: {
        maxTokens: opts.maxTokens,
        temperature: opts.temperature,
        topP: opts.topP,
      },
    });

    const response = await bedrockClient.send(command);
    const outputContent = response.output?.message?.content;
    if (!outputContent || outputContent.length === 0) {
      throw new Error("Empty response from Bedrock model");
    }
    return {
      text: outputContent[0].text || "",
      inputTokens: response.usage?.inputTokens ?? null,
      outputTokens: response.usage?.outputTokens ?? null,
    };
  } catch (error: unknown) {
    const err = error as { name?: string; message?: string };
    if (err.name === "ValidationException" && err.message?.includes("system")) {
      const fallback = new ConverseCommand({
        modelId: opts.modelId,
        messages: [{ role: "user", content: [{ text: `${opts.systemPrompt}\n\n${opts.userMessage}` }] }],
        inferenceConfig: { maxTokens: opts.maxTokens, temperature: opts.temperature, topP: opts.topP },
      });
      const fbResp = await bedrockClient.send(fallback);
      const fbContent = fbResp.output?.message?.content;
      if (!fbContent || fbContent.length === 0) throw new Error("Empty response from Bedrock model (fallback)");
      return {
        text: fbContent[0].text || "",
        inputTokens: fbResp.usage?.inputTokens ?? null,
        outputTokens: fbResp.usage?.outputTokens ?? null,
      };
    }
    throw error;
  }
}

async function invokeSageMakerRaw(opts: ModelInvokeOptions): Promise<string> {
  const endpoint = opts.sagemakerEndpoint;
  if (!endpoint) {
    throw new Error("SageMaker endpoint is required when backend=sagemaker");
  }

  const payload = {
    inputs: `<s>[INST] ${opts.systemPrompt}\n\n${opts.userMessage} [/INST]`,
    parameters: {
      max_new_tokens: opts.maxTokens,
      temperature: opts.temperature,
      top_p: opts.topP,
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

  if (Array.isArray(result) && result[0]?.generated_text) return result[0].generated_text;
  if (result.generated_text) return result.generated_text;
  if (typeof result === "string") return result;
  throw new Error("Unexpected SageMaker response format");
}

function classifyModelError(error: unknown): { retryable: boolean; message: string } {
  const err = error as { name?: string; message?: string };
  const name = err.name || "";
  const msg = err.message || "";

  if (name === "ThrottlingException" || msg.includes("429") || msg.includes("rate limit")) {
    return { retryable: true, message: "Rate limit exceeded on model endpoint. Retry after a brief delay." };
  }
  if (name === "AccessDeniedException" || name === "UnrecognizedClientException") {
    return {
      retryable: false,
      message: "AWS credentials are invalid or lack model access. Verify IAM role permissions.",
    };
  }
  if (name === "ResourceNotFoundException" || name === "ModelNotReadyException") {
    return { retryable: false, message: `Model ${msg} is not available. Enable it in the AWS console.` };
  }
  if (name === "ModelError" || name === "ValidationError") {
    return { retryable: false, message: `Model error: ${msg}` };
  }
  if (msg.includes("timeout") || msg.includes("ECONNRESET") || msg.includes("ECONNREFUSED")) {
    return { retryable: true, message: `Network error: ${msg}` };
  }
  return { retryable: false, message: `AI invocation failed: ${msg}` };
}

const MAX_RETRIES = 2;
const RETRY_BASE_MS = 1000;

export async function invokeModel(opts: ModelInvokeOptions): Promise<ModelInvokeResult> {
  const circuitKey = getCircuitKey(opts.backend, opts.modelId);
  if (isCircuitOpen(circuitKey)) {
    throw new Error(`Circuit breaker open for ${opts.backend}:${opts.modelId}. Service is temporarily unavailable.`);
  }

  if (opts.orgId) {
    const budgetOk = await checkBudget(opts.orgId);
    if (!budgetOk.allowed) {
      throw new Error(`AI budget exceeded for org ${opts.orgId}: ${budgetOk.reason}`);
    }
  }

  const cacheKey = buildCacheKey(opts);
  if (!opts.skipCache) {
    const cached = getCached(cacheKey);
    if (cached) {
      gatewayMetrics.cacheHits++;
      const stats = getOrCreateModelStats(opts.modelId);
      stats.cacheHits++;
      recordLatency(opts.modelId, opts.backend, 0, true);
      log.info("Model response served from cache", { modelId: opts.modelId, promptId: opts.promptId });
      return cached;
    }
  }

  gatewayMetrics.totalRequests++;
  if (!opts.skipCache) gatewayMetrics.cacheMisses++;
  const modelStats = getOrCreateModelStats(opts.modelId);
  modelStats.requests++;

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const delayMs = RETRY_BASE_MS * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      gatewayMetrics.retries++;
      log.warn("Retrying model invocation", { modelId: opts.modelId, attempt, delayMs });
    }

    const start = Date.now();
    try {
      let text: string;
      let apiInputTokens: number | null = null;
      let apiOutputTokens: number | null = null;

      if (opts.backend === "sagemaker") {
        text = await invokeSageMakerRaw(opts);
      } else {
        const bedrockResult = await invokeBedrockRaw(opts);
        text = bedrockResult.text;
        apiInputTokens = bedrockResult.inputTokens;
        apiOutputTokens = bedrockResult.outputTokens;
      }

      const latencyMs = Date.now() - start;
      const inputTokensEstimate = apiInputTokens ?? countTokens(opts.systemPrompt + opts.userMessage);
      const outputTokensEstimate = apiOutputTokens ?? countTokens(text);
      const costEstimateUsd = estimateCost(opts.modelId, inputTokensEstimate, outputTokensEstimate, opts.tier);

      recordCircuitSuccess(circuitKey);
      modelStats.totalLatencyMs += latencyMs;
      recordLatency(opts.modelId, opts.backend, latencyMs, false);

      const result: ModelInvokeResult = {
        text,
        inputTokensEstimate,
        outputTokensEstimate,
        latencyMs,
        costEstimateUsd,
        modelId: opts.modelId,
        backend: opts.backend,
        cached: false,
      };

      if (opts.orgId) {
        await trackUsage(opts.orgId, {
          inputTokens: inputTokensEstimate,
          outputTokens: outputTokensEstimate,
          costUsd: costEstimateUsd,
          modelId: opts.modelId,
          promptId: opts.promptId,
          promptVersion: opts.promptVersion,
          latencyMs,
        });
      }

      if (opts.temperature <= 0.2 && !opts.skipCache) {
        putCache(cacheKey, result);
      }

      return result;
    } catch (error: unknown) {
      const classified = classifyModelError(error);
      lastError = new Error(classified.message);
      recordGatewayError(opts.modelId, opts.backend, classified.message, classified.retryable);
      if (classified.retryable) recordCircuitFailure(circuitKey);

      if (!classified.retryable || attempt >= MAX_RETRIES) {
        log.error("Model invocation failed (non-retryable or max retries)", {
          modelId: opts.modelId,
          backend: opts.backend,
          attempt,
          error: classified.message,
        });
        throw lastError;
      }
    }
  }

  throw lastError || new Error("Model invocation failed after retries");
}

export function getCircuitBreakerStatus(): Record<
  string,
  { failures: number; isOpen: boolean; resetAt: string | null }
> {
  const result: Record<string, { failures: number; isOpen: boolean; resetAt: string | null }> = {};
  for (const [key, state] of Array.from(circuitBreakers.entries())) {
    result[key] = {
      failures: state.failures,
      isOpen: state.failures >= CIRCUIT_FAILURE_THRESHOLD && Date.now() < state.openUntil,
      resetAt: state.openUntil > Date.now() ? new Date(state.openUntil).toISOString() : null,
    };
  }
  return result;
}

export interface GatewayDashboardData {
  uptime: number;
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate: number;
  cacheSize: number;
  cacheMaxSize: number;
  totalErrors: number;
  errorRate: number;
  retries: number;
  circuitBreakerTrips: number;
  circuitBreakers: Record<string, { failures: number; isOpen: boolean; resetAt: string | null }>;
  latencyHistory: { timestamp: number; modelId: string; backend: ModelBackend; latencyMs: number; cached: boolean }[];
  errorHistory: { timestamp: number; modelId: string; backend: ModelBackend; error: string; retryable: boolean }[];
  modelStats: Record<
    string,
    { requests: number; errors: number; avgLatencyMs: number; cacheHits: number; errorRate: number }
  >;
  config: {
    circuitBreakerThreshold: number;
    circuitBreakerResetMs: number;
    cacheTtlMs: number;
    maxCacheEntries: number;
    maxRetries: number;
    retryBaseMs: number;
    costTable: Record<string, { input: number; output: number }>;
  };
}

export function getGatewayDashboardData(): GatewayDashboardData {
  const totalAttempts = gatewayMetrics.cacheHits + gatewayMetrics.cacheMisses;
  const cacheHitRate = totalAttempts > 0 ? gatewayMetrics.cacheHits / totalAttempts : 0;
  const errorRate = gatewayMetrics.totalRequests > 0 ? gatewayMetrics.totalErrors / gatewayMetrics.totalRequests : 0;

  const modelStatsObj: Record<
    string,
    { requests: number; errors: number; avgLatencyMs: number; cacheHits: number; errorRate: number }
  > = {};
  for (const [modelId, stats] of Array.from(gatewayMetrics.modelStats.entries())) {
    modelStatsObj[modelId] = {
      requests: stats.requests,
      errors: stats.errors,
      avgLatencyMs: stats.requests > 0 ? Math.round(stats.totalLatencyMs / stats.requests) : 0,
      cacheHits: stats.cacheHits,
      errorRate: stats.requests > 0 ? Math.round((stats.errors / stats.requests) * 10000) / 100 : 0,
    };
  }

  return {
    uptime: Date.now() - gatewayMetrics.startedAt,
    totalRequests: gatewayMetrics.totalRequests,
    cacheHits: gatewayMetrics.cacheHits,
    cacheMisses: gatewayMetrics.cacheMisses,
    cacheHitRate: Math.round(cacheHitRate * 10000) / 100,
    cacheSize: responseCache.size,
    cacheMaxSize: MAX_CACHE_ENTRIES,
    totalErrors: gatewayMetrics.totalErrors,
    errorRate: Math.round(errorRate * 10000) / 100,
    retries: gatewayMetrics.retries,
    circuitBreakerTrips: gatewayMetrics.circuitBreakerTrips,
    circuitBreakers: getCircuitBreakerStatus(),
    latencyHistory: gatewayMetrics.latencyHistory.slice(-100),
    errorHistory: gatewayMetrics.errorHistory.slice(-50),
    modelStats: modelStatsObj,
    config: {
      circuitBreakerThreshold: CIRCUIT_FAILURE_THRESHOLD,
      circuitBreakerResetMs: CIRCUIT_RESET_MS,
      cacheTtlMs: CACHE_TTL_MS,
      maxCacheEntries: MAX_CACHE_ENTRIES,
      maxRetries: MAX_RETRIES,
      retryBaseMs: RETRY_BASE_MS,
      costTable: COST_TABLE,
    },
  };
}

// ─── Streaming Support ──────────────────────────────────────────────────────

export interface StreamCallbacks {
  onChunk: (text: string) => void;
  onComplete: (
    fullText: string,
    metrics: { inputTokens: number; outputTokens: number; latencyMs: number },
  ) => void | Promise<void>;
  onError: (error: Error) => void;
}

/**
 * Stream a model invocation via Bedrock ConverseStream. Calls onChunk for each
 * text delta, then onComplete with the full accumulated text and token metrics.
 * Falls back to non-streaming invokeModel if backend is sagemaker.
 */
export async function invokeModelStream(opts: ModelInvokeOptions, callbacks: StreamCallbacks): Promise<void> {
  // SageMaker doesn't support streaming via Converse API — fall back to non-streaming
  if (opts.backend === "sagemaker") {
    try {
      const result = await invokeModel(opts);
      callbacks.onChunk(result.text);
      await callbacks.onComplete(result.text, {
        inputTokens: result.inputTokensEstimate,
        outputTokens: result.outputTokensEstimate,
        latencyMs: result.latencyMs,
      });
    } catch (err) {
      callbacks.onError(err instanceof Error ? err : new Error(String(err)));
    }
    return;
  }

  const circuitKey = getCircuitKey(opts.backend, opts.modelId);
  if (isCircuitOpen(circuitKey)) {
    callbacks.onError(
      new Error(`Circuit breaker open for ${opts.backend}:${opts.modelId}. Service is temporarily unavailable.`),
    );
    return;
  }

  if (opts.orgId) {
    const budgetOk = await checkBudget(opts.orgId);
    if (!budgetOk.allowed) {
      callbacks.onError(new Error(`AI budget exceeded for org ${opts.orgId}: ${budgetOk.reason}`));
      return;
    }
  }

  gatewayMetrics.totalRequests++;
  const modelStats = getOrCreateModelStats(opts.modelId);
  modelStats.requests++;

  const start = Date.now();

  try {
    const command = new ConverseStreamCommand({
      modelId: opts.modelId,
      messages: [{ role: "user" as const, content: [{ text: opts.userMessage }] }],
      system: [{ text: opts.systemPrompt }],
      inferenceConfig: {
        maxTokens: opts.maxTokens,
        temperature: opts.temperature,
        topP: opts.topP,
      },
    });

    const response = await bedrockClient.send(command);
    const stream = response.stream;
    if (!stream) {
      throw new Error("No stream returned from Bedrock ConverseStream");
    }

    let fullText = "";
    let apiInputTokens = 0;
    let apiOutputTokens = 0;

    for await (const event of stream) {
      if (event.contentBlockDelta) {
        const delta = event.contentBlockDelta.delta;
        if (delta && "text" in delta && delta.text) {
          fullText += delta.text;
          callbacks.onChunk(delta.text);
        }
      } else if (event.metadata) {
        apiInputTokens = event.metadata.usage?.inputTokens ?? 0;
        apiOutputTokens = event.metadata.usage?.outputTokens ?? 0;
      }
    }

    const latencyMs = Date.now() - start;
    const inputTokens = apiInputTokens || countTokens(opts.systemPrompt + opts.userMessage);
    const outputTokens = apiOutputTokens || countTokens(fullText);

    recordCircuitSuccess(circuitKey);
    modelStats.totalLatencyMs += latencyMs;
    recordLatency(opts.modelId, opts.backend, latencyMs, false);

    if (opts.orgId) {
      const costEstimateUsd = estimateCost(opts.modelId, inputTokens, outputTokens, opts.tier);
      await trackUsage(opts.orgId, {
        inputTokens,
        outputTokens,
        costUsd: costEstimateUsd,
        modelId: opts.modelId,
        promptId: opts.promptId,
        promptVersion: opts.promptVersion,
        latencyMs,
      });
    }

    await callbacks.onComplete(fullText, { inputTokens, outputTokens, latencyMs });
  } catch (error: unknown) {
    const classified = classifyModelError(error);
    recordGatewayError(opts.modelId, opts.backend, classified.message, classified.retryable);
    if (classified.retryable) recordCircuitFailure(circuitKey);
    callbacks.onError(new Error(classified.message));
  }
}

export function resetGatewayMetrics(): void {
  gatewayMetrics.totalRequests = 0;
  gatewayMetrics.cacheHits = 0;
  gatewayMetrics.cacheMisses = 0;
  gatewayMetrics.totalErrors = 0;
  gatewayMetrics.retries = 0;
  gatewayMetrics.circuitBreakerTrips = 0;
  gatewayMetrics.latencyHistory = [];
  gatewayMetrics.errorHistory = [];
  gatewayMetrics.modelStats.clear();
  gatewayMetrics.startedAt = Date.now();
}
