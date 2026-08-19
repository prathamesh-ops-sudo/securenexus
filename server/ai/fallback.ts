import { getCircuitBreakerStatus } from "./model-gateway";
import { logger } from "../logger";

const log = logger.child("ai-fallback");

interface FallbackCacheEntry<T> {
  data: T;
  cachedAt: string;
}

const fallbackCache = new Map<string, FallbackCacheEntry<unknown>>();
const MAX_FALLBACK_ENTRIES = 500;

export interface AiFallbackResult<T> {
  data: T | null;
  source: "live" | "cached" | "unavailable";
  cachedAt?: string;
}

export class AiUnavailableError extends Error {
  readonly code = "AI_UNAVAILABLE";
  readonly operation: string;

  constructor(operation: string, cause?: unknown) {
    super(`AI unavailable for ${operation}${cause ? `: ${String(cause)}` : ""}`);
    this.name = "AiUnavailableError";
    this.operation = operation;
  }
}

export function isAiAvailable(): boolean {
  const status = getCircuitBreakerStatus();
  const entries = Object.values(status);
  if (entries.length === 0) return true; // no circuits tracked = assume available
  return entries.some((s) => !s.isOpen); // at least one model circuit is closed
}

export async function withAiFallback<T>(cacheKey: string, fn: () => Promise<T>): Promise<AiFallbackResult<T>> {
  // Check if all circuits are open -- serve from cache without attempting call
  if (!isAiAvailable()) {
    const cached = fallbackCache.get(cacheKey) as FallbackCacheEntry<T> | undefined;
    if (cached) {
      log.info("Serving cached AI result (all circuits open)", { cacheKey, cachedAt: cached.cachedAt });
      return { data: cached.data, source: "cached", cachedAt: cached.cachedAt };
    }
    log.warn("AI unavailable and no cached result", { cacheKey });
    return { data: null, source: "unavailable" };
  }

  try {
    const result = await fn();
    // Cache successful result
    if (fallbackCache.size >= MAX_FALLBACK_ENTRIES) {
      const oldest = fallbackCache.keys().next().value;
      if (oldest) fallbackCache.delete(oldest);
    }
    fallbackCache.set(cacheKey, { data: result, cachedAt: new Date().toISOString() });
    return { data: result, source: "live" };
  } catch (err) {
    // On failure, try to serve stale cached result
    const cached = fallbackCache.get(cacheKey) as FallbackCacheEntry<T> | undefined;
    if (cached) {
      log.warn("AI call failed, serving cached result", {
        cacheKey,
        error: String(err),
        cachedAt: cached.cachedAt,
      });
      return { data: cached.data, source: "cached", cachedAt: cached.cachedAt };
    }
    log.error("AI call failed with no cached fallback", { cacheKey, error: String(err) });
    return { data: null, source: "unavailable" };
  }
}

export function clearFallbackCache(): void {
  fallbackCache.clear();
}

export function getFallbackCacheSize(): number {
  return fallbackCache.size;
}
