import { randomBytes } from "crypto";
import { logger } from "./logger";

const log = logger.child("scaling-state");

const POD_ID = process.env.POD_NAME || process.env.HOSTNAME || `pod-${randomBytes(4).toString("hex")}`;

export function getPodId(): string {
  return POD_ID;
}

type ScalingTier = "local-ok" | "needs-shared-store" | "already-shared";

interface StateStoreEntry {
  name: string;
  file: string;
  tier: ScalingTier;
  description: string;
  sharedStoreUpgrade: string;
  currentBackend: "in-memory" | "database" | "s3";
}

const STATE_REGISTRY: StateStoreEntry[] = [
  {
    name: "SSE Client Map",
    file: "event-bus.ts",
    tier: "local-ok",
    description: "SSE connections are inherently per-pod (TCP socket bound to the process). Each pod manages its own connected clients.",
    sharedStoreUpgrade: "Use Redis Pub/Sub to broadcast events across pods. Each pod subscribes to a shared channel and forwards events to its local SSE clients.",
    currentBackend: "in-memory",
  },
  {
    name: "Query Cache",
    file: "query-cache.ts",
    tier: "local-ok",
    description: "Per-instance LRU cache for dashboard/analytics queries. Cache miss simply hits DB — no correctness issue, only redundant DB load across pods.",
    sharedStoreUpgrade: "Swap Map backing store to Redis GET/SET with TTL. The cacheGetOrLoad API is already designed for this swap.",
    currentBackend: "in-memory",
  },
  {
    name: "SLI Metric Buckets",
    file: "sli-middleware.ts",
    tier: "local-ok",
    description: "Per-pod latency/error buckets flushed to DB every 60s. Metrics are additive — each pod contributes its own slice. DB queries aggregate across all pods.",
    sharedStoreUpgrade: "No upgrade needed. Per-pod collection with DB aggregation is the correct pattern for distributed metrics.",
    currentBackend: "in-memory",
  },
  {
    name: "OSINT Feed Cache",
    file: "osint-feeds.ts",
    tier: "local-ok",
    description: "Cached OSINT feed results with 1-hour TTL. Multiple pods may fetch the same feed independently — slightly wasteful but no correctness issue.",
    sharedStoreUpgrade: "Move feed cache to Redis with shared TTL. All pods read from Redis, only one pod fetches on cache miss (use Redis SETNX for distributed lock).",
    currentBackend: "in-memory",
  },
  {
    name: "Connector Provider Concurrency",
    file: "connector-engine.ts",
    tier: "local-ok",
    description: "Per-pod concurrency limits and backoff for connector providers. Each pod independently rate-limits its own outbound requests.",
    sharedStoreUpgrade: "Use Redis INCR/DECR for global concurrency counting. Backoff state in Redis with TTL keys.",
    currentBackend: "in-memory",
  },
  {
    name: "Slow Query Log",
    file: "db-performance.ts",
    tier: "local-ok",
    description: "Diagnostic-only in-memory ring buffer of recent slow queries. Per-pod is fine for local debugging.",
    sharedStoreUpgrade: "Write slow queries to a DB table for cross-pod visibility. Or use centralized logging (CloudWatch/Datadog).",
    currentBackend: "in-memory",
  },
  {
    name: "AI Circuit Breakers",
    file: "ai/model-gateway.ts",
    tier: "needs-shared-store",
    description: "Circuit breaker state for AI model endpoints. Per-pod state means pod A can trip its circuit while pod B continues sending requests to a failing model.",
    sharedStoreUpgrade: "Store circuit state in Redis: INCR failure count with TTL, check count before invocation. Use Redis EXPIRE for automatic reset.",
    currentBackend: "in-memory",
  },
  {
    name: "AI Response Cache",
    file: "ai/model-gateway.ts",
    tier: "local-ok",
    description: "Short-lived (5 min) response cache for deterministic AI queries (temperature <= 0.2). Cache miss means a model invocation — acceptable inconsistency.",
    sharedStoreUpgrade: "Move to Redis for cross-pod cache sharing. Use hash of prompt as key, serialized result as value.",
    currentBackend: "in-memory",
  },
  {
    name: "AI Budget Tracking",
    file: "ai/budget.ts",
    tier: "needs-shared-store",
    description: "Per-org daily budget and invocation tracking. Per-pod state means org can spend N*budget by hitting N pods. Critical for cost control.",
    sharedStoreUpgrade: "Use Redis INCRBYFLOAT for atomic cost accumulation. Store budget config in DB. Flush usage records to DB periodically.",
    currentBackend: "in-memory",
  },
  {
    name: "AI Prompt Registry",
    file: "ai/prompt-registry.ts",
    tier: "needs-shared-store",
    description: "Prompt templates and version history. Per-pod state means prompt updates on pod A are invisible to pod B. Audit log is also per-pod.",
    sharedStoreUpgrade: "Store prompts in DB table. Load into memory on startup, refresh periodically or via event-bus notification. Audit log already goes to DB.",
    currentBackend: "in-memory",
  },
  {
    name: "Webhook Circuit Breakers",
    file: "outbound-security.ts",
    tier: "needs-shared-store",
    description: "Circuit breaker state for webhook delivery endpoints. Per-pod state means failures on pod A don't protect pod B from sending to a dead endpoint.",
    sharedStoreUpgrade: "Store circuit state in Redis with TTL. Use INCR for failure count, GET to check before delivery.",
    currentBackend: "in-memory",
  },
  {
    name: "Webhook Rate Buckets",
    file: "outbound-security.ts",
    tier: "needs-shared-store",
    description: "Per-webhook rate limiting (100/min). Per-pod state means actual rate can be N*100 across N pods.",
    sharedStoreUpgrade: "Use Redis sliding window rate limiter (ZADD + ZRANGEBYSCORE) or simple INCR with EXPIRE.",
    currentBackend: "in-memory",
  },
  {
    name: "SLO Breach Cooldown",
    file: "slo-alerting.ts",
    tier: "needs-shared-store",
    description: "Notification cooldown map to prevent duplicate breach alerts. Per-pod state means each pod sends its own notifications — N pods = N duplicate alerts.",
    sharedStoreUpgrade: "Use Redis SETNX with TTL for cooldown keys. Only the pod that wins the SETNX sends the notification.",
    currentBackend: "in-memory",
  },
  {
    name: "Job Queue Active IDs",
    file: "job-queue.ts",
    tier: "already-shared",
    description: "Job dedup and locking uses DB-based FOR UPDATE SKIP LOCKED. The in-memory activeJobIds Set only tracks this worker's own heartbeats — correct for distributed use.",
    sharedStoreUpgrade: "No upgrade needed. Already uses DB-based distributed locking.",
    currentBackend: "database",
  },
];

export interface ScalingReadinessReport {
  podId: string;
  timestamp: string;
  totalStores: number;
  byTier: Record<ScalingTier, number>;
  horizontalReady: boolean;
  criticalIssues: string[];
  stores: StateStoreEntry[];
}

export function getScalingReadinessReport(): ScalingReadinessReport {
  const byTier: Record<ScalingTier, number> = {
    "local-ok": 0,
    "needs-shared-store": 0,
    "already-shared": 0,
  };

  const criticalIssues: string[] = [];

  for (const store of STATE_REGISTRY) {
    byTier[store.tier]++;
    if (store.tier === "needs-shared-store") {
      criticalIssues.push(`${store.name} (${store.file}): ${store.description}`);
    }
  }

  return {
    podId: POD_ID,
    timestamp: new Date().toISOString(),
    totalStores: STATE_REGISTRY.length,
    byTier,
    horizontalReady: byTier["needs-shared-store"] === 0,
    criticalIssues,
    stores: STATE_REGISTRY,
  };
}

export function getStateRegistry(): StateStoreEntry[] {
  return [...STATE_REGISTRY];
}

const shutdownHandlers: Array<{ name: string; handler: () => Promise<void> | void }> = [];

export function registerShutdownHandler(name: string, handler: () => Promise<void> | void): void {
  shutdownHandlers.push({ name, handler });
}

let draining = false;

export function isDraining(): boolean {
  return draining;
}

export async function gracefulShutdown(signal: string): Promise<void> {
  if (draining) return;
  draining = true;
  log.info("Graceful shutdown initiated", { signal, podId: POD_ID, handlers: shutdownHandlers.length });

  for (const { name, handler } of shutdownHandlers) {
    try {
      await handler();
      log.info("Shutdown handler completed", { name });
    } catch (err) {
      log.error("Shutdown handler failed", { name, error: String(err) });
    }
  }

  log.info("All shutdown handlers completed", { podId: POD_ID });
}

export function initializeScalingState(): void {
  log.info("Pod identity established", { podId: POD_ID });
  log.info("State store registry loaded", {
    total: STATE_REGISTRY.length,
    localOk: STATE_REGISTRY.filter((s) => s.tier === "local-ok").length,
    needsSharedStore: STATE_REGISTRY.filter((s) => s.tier === "needs-shared-store").length,
    alreadyShared: STATE_REGISTRY.filter((s) => s.tier === "already-shared").length,
  });

  const needsShared = STATE_REGISTRY.filter((s) => s.tier === "needs-shared-store");
  if (needsShared.length > 0) {
    log.warn("Running with per-pod state that needs shared store for horizontal scaling", {
      stores: needsShared.map((s) => s.name),
      recommendation: "Deploy Redis/ElastiCache and migrate these stores before scaling beyond 1 replica",
    });
  }

  process.on("SIGTERM", () => {
    gracefulShutdown("SIGTERM").catch((err) => log.error("SIGTERM shutdown error", { error: String(err) }));
  });
  process.on("SIGINT", () => {
    gracefulShutdown("SIGINT").catch((err) => log.error("SIGINT shutdown error", { error: String(err) }));
  });
}
