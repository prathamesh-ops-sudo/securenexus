import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { SageMakerRuntimeClient, InvokeEndpointCommand } from "@aws-sdk/client-sagemaker-runtime";
import { config as appConfig } from "../config";
import { logger } from "../logger";
import { getAwsClientConfig } from "../aws-credentials";
import { trackUsage, checkBudget } from "./budget";

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
  "mistral.mistral-large-2402-v1:0": { input: 0.000004, output: 0.000012 },
  "anthropic.claude-3-sonnet": { input: 0.000003, output: 0.000015 },
  "anthropic.claude-3-haiku": { input: 0.00000025, output: 0.00000125 },
  "default-triage": { input: 0.00000015, output: 0.0000002 },
  "default": { input: 0.000002, output: 0.000006 },
};

const TRIAGE_RATES = { input: 0.00000015, output: 0.0000002 };

function estimateCost(modelId: string, inputTokens: number, outputTokens: number, tier?: string): number {
  if (tier === "triage") {
    return (inputTokens * TRIAGE_RATES.input) + (outputTokens * TRIAGE_RATES.output);
  }
  const rates = COST_TABLE[modelId] || COST_TABLE["default"];
  return (inputTokens * rates.input) + (outputTokens * rates.output);
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
    state.openUntil = Date.now() + CIRCUIT_RESET_MS;
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

function buildCacheKey(opts: ModelInvokeOptions): string {
  const raw = `${opts.modelId}|${opts.systemPrompt}|${opts.userMessage}|${opts.maxTokens}|${opts.temperature}`;
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    hash = ((hash << 5) - hash) + ch;
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

async function invokeBedrockRaw(opts: ModelInvokeOptions): Promise<string> {
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
    return outputContent[0].text || "";
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
      return fbContent[0].text || "";
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
    return { retryable: false, message: "AWS credentials are invalid or lack model access. Verify IAM role permissions." };
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
    const budgetOk = checkBudget(opts.orgId);
    if (!budgetOk.allowed) {
      throw new Error(`AI budget exceeded for org ${opts.orgId}: ${budgetOk.reason}`);
    }
  }

  const cacheKey = buildCacheKey(opts);
  if (!opts.skipCache) {
    const cached = getCached(cacheKey);
    if (cached) {
      log.info("Model response served from cache", { modelId: opts.modelId, promptId: opts.promptId });
      return cached;
    }
  }

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const delayMs = RETRY_BASE_MS * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      log.warn("Retrying model invocation", { modelId: opts.modelId, attempt, delayMs });
    }

    const start = Date.now();
    try {
      const text = opts.backend === "sagemaker"
        ? await invokeSageMakerRaw(opts)
        : await invokeBedrockRaw(opts);

      const latencyMs = Date.now() - start;
      const inputTokensEstimate = Math.ceil((opts.systemPrompt.length + opts.userMessage.length) / 4);
      const outputTokensEstimate = Math.ceil(text.length / 4);
      const costEstimateUsd = estimateCost(opts.modelId, inputTokensEstimate, outputTokensEstimate, opts.tier);

      recordCircuitSuccess(circuitKey);

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
        trackUsage(opts.orgId, {
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

export function getCircuitBreakerStatus(): Record<string, { failures: number; isOpen: boolean; resetAt: string | null }> {
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
