import { createHash } from "crypto";

/**
 * Cache Architecture (per-instance memory tier)
 *
 * Tier 1 – In-process Map (this module)
 *   Scope   : single Node process
 *   Eviction: LRU-style (expired first, then oldest)
 *   Use case: dashboard stats, analytics, ingestion stats
 *
 * Tier 2 – Shared cache (Redis / ElastiCache) – not yet wired
 *   When horizontally scaling, promote hot keys here.
 *   The API surface below (cacheGetOrLoad, buildCacheKey) is
 *   designed so a Redis adapter can be swapped in without
 *   changing call sites.
 *
 * Every cache key MUST be tenant-scoped via buildCacheKey which
 * includes orgId in the hash input. Global (cross-org) keys
 * must pass orgId = "__global__" explicitly.
 */

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
  createdAt: number;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 500;

const cache = new Map<string, CacheEntry<unknown>>();

interface PrefixMetrics {
  hits: number;
  misses: number;
  evictions: number;
  staleReads: number;
}

const prefixMetricsMap = new Map<string, PrefixMetrics>();

function extractPrefix(key: string): string {
  const idx = key.indexOf(":");
  return idx > 0 ? key.slice(0, idx) : key;
}

function getPrefixMetrics(prefix: string): PrefixMetrics {
  let m = prefixMetricsMap.get(prefix);
  if (!m) {
    m = { hits: 0, misses: 0, evictions: 0, staleReads: 0 };
    prefixMetricsMap.set(prefix, m);
  }
  return m;
}

let totalHits = 0;
let totalMisses = 0;
let totalEvictions = 0;

export function cacheGet<T>(key: string): T | undefined {
  const entry = cache.get(key);
  const prefix = extractPrefix(key);
  const pm = getPrefixMetrics(prefix);

  if (!entry) {
    totalMisses++;
    pm.misses++;
    return undefined;
  }
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    totalEvictions++;
    pm.evictions++;
    pm.staleReads++;
    totalMisses++;
    pm.misses++;
    return undefined;
  }
  totalHits++;
  pm.hits++;
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
  for (const key of Array.from(cache.keys())) {
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

const totalRequests = (): number => totalHits + totalMisses;

export function cacheStats(): {
  size: number;
  maxEntries: number;
  hitRate: string;
  totalHits: number;
  totalMisses: number;
  totalEvictions: number;
  prefixBreakdown: Record<string, PrefixMetrics>;
} {
  const tr = totalRequests();
  const breakdown: Record<string, PrefixMetrics> = {};
  for (const [prefix, m] of Array.from(prefixMetricsMap.entries())) {
    breakdown[prefix] = { ...m };
  }
  return {
    size: cache.size,
    maxEntries: MAX_ENTRIES,
    hitRate: tr > 0 ? `${((totalHits / tr) * 100).toFixed(1)}%` : "0%",
    totalHits,
    totalMisses,
    totalEvictions,
    prefixBreakdown: breakdown,
  };
}

export function cacheGetWithStats<T>(key: string): { data: T | undefined; hit: boolean } {
  const data = cacheGet<T>(key);
  const hit = data !== undefined;
  return { data, hit };
}

const inflightRequests = new Map<string, Promise<unknown>>();

export async function cacheGetOrLoad<T>(
  key: string,
  loader: () => Promise<T>,
  ttlMs: number = DEFAULT_TTL_MS,
): Promise<T> {
  const cached = cacheGet<T>(key);
  if (cached !== undefined) return cached;

  const existing = inflightRequests.get(key) as Promise<T> | undefined;
  if (existing) return existing;

  const promise = loader().then((result) => {
    cacheSet(key, result, ttlMs);
    inflightRequests.delete(key);
    return result;
  }).catch((err) => {
    inflightRequests.delete(key);
    throw err;
  });

  inflightRequests.set(key, promise);
  return promise;
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

  for (const [key, entry] of Array.from(cache.entries())) {
    if (now > entry.expiresAt) {
      cache.delete(key);
      totalEvictions++;
      getPrefixMetrics(extractPrefix(key)).evictions++;
      return;
    }
    if (entry.createdAt < oldestTime) {
      oldestTime = entry.createdAt;
      oldestKey = key;
    }
  }

  if (oldestKey) {
    cache.delete(oldestKey);
    totalEvictions++;
    getPrefixMetrics(extractPrefix(oldestKey)).evictions++;
  }
}

export const CACHE_TTL = {
  DASHBOARD_STATS: 5 * 60 * 1000,
  DASHBOARD_ANALYTICS: 10 * 60 * 1000,
  INGESTION_STATS: 3 * 60 * 1000,
  ENTITY_GRAPH: 5 * 60 * 1000,
  COMPLIANCE_SUMMARY: 10 * 60 * 1000,
} as const;
