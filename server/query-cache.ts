import { createHash } from "crypto";

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
  createdAt: number;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 200;

const cache = new Map<string, CacheEntry<unknown>>();

export function cacheGet<T>(key: string): T | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return entry.data as T;
}

export function cacheSet<T>(key: string, data: T, ttlMs: number = DEFAULT_TTL_MS): void {
  if (cache.size >= MAX_ENTRIES) {
    evictExpiredOrOldest();
  }
  cache.set(key, {
    data,
    expiresAt: Date.now() + ttlMs,
    createdAt: Date.now(),
  });
}

export function cacheInvalidate(pattern: string): number {
  let removed = 0;
  for (const key of cache.keys()) {
    if (key.startsWith(pattern)) {
      cache.delete(key);
      removed++;
    }
  }
  return removed;
}

export function cacheInvalidateAll(): void {
  cache.clear();
}

export function cacheStats(): { size: number; maxEntries: number; hitRate: string } {
  return {
    size: cache.size,
    maxEntries: MAX_ENTRIES,
    hitRate: totalRequests > 0 ? `${((totalHits / totalRequests) * 100).toFixed(1)}%` : "0%",
  };
}

let totalHits = 0;
let totalRequests = 0;

export function cacheGetWithStats<T>(key: string): { data: T | undefined; hit: boolean } {
  totalRequests++;
  const data = cacheGet<T>(key);
  const hit = data !== undefined;
  if (hit) totalHits++;
  return { data, hit };
}

export function buildCacheKey(prefix: string, params: Record<string, unknown>): string {
  const normalized = JSON.stringify(params, Object.keys(params).sort());
  const hash = createHash("md5").update(normalized).digest("hex").slice(0, 12);
  return `${prefix}:${hash}`;
}

function evictExpiredOrOldest(): void {
  const now = Date.now();
  let oldestKey: string | null = null;
  let oldestTime = Infinity;

  for (const [key, entry] of cache.entries()) {
    if (now > entry.expiresAt) {
      cache.delete(key);
      return;
    }
    if (entry.createdAt < oldestTime) {
      oldestTime = entry.createdAt;
      oldestKey = key;
    }
  }

  if (oldestKey) {
    cache.delete(oldestKey);
  }
}

export const CACHE_TTL = {
  DASHBOARD_STATS: 5 * 60 * 1000,
  DASHBOARD_ANALYTICS: 10 * 60 * 1000,
  INGESTION_STATS: 3 * 60 * 1000,
  ENTITY_GRAPH: 5 * 60 * 1000,
  COMPLIANCE_SUMMARY: 10 * 60 * 1000,
} as const;
