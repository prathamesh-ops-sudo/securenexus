import type { Request, Response, NextFunction } from "express";
import { getPoolHealth } from "../db";
import { logger } from "../logger";

const log = logger.child("pool-circuit-breaker");

const UTILIZATION_THRESHOLD = 80;
const CACHE_DURATION_MS = 1000;
const RETRY_AFTER_SECONDS = 5;

const EXEMPT_PATH_PREFIXES = ["/api/health", "/api/metrics", "/api/ops/health", "/api/ops/metrics"];

let cachedUtilization = 0;
let lastCheckedAt = 0;

/** @internal Reset cached state — test use only */
export function _resetPoolCircuitBreakerCache(): void {
  cachedUtilization = 0;
  lastCheckedAt = 0;
}

export function poolCircuitBreakerMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Exempt health and metrics endpoints
  for (const prefix of EXEMPT_PATH_PREFIXES) {
    if (req.path.startsWith(prefix)) {
      next();
      return;
    }
  }

  // Refresh cached utilization if stale (> 1 second old)
  const now = Date.now();
  if (now - lastCheckedAt > CACHE_DURATION_MS) {
    const health = getPoolHealth();
    cachedUtilization = health.utilizationPercent;
    lastCheckedAt = now;
  }

  if (cachedUtilization >= UTILIZATION_THRESHOLD) {
    log.warn("Pool circuit breaker: rejecting request", {
      utilizationPercent: cachedUtilization,
      orgId: (req as unknown as Record<string, unknown>).orgId,
      path: req.path,
    });
    res.status(503).set("Retry-After", String(RETRY_AFTER_SECONDS)).json({
      error: "Service temporarily unavailable",
      retryAfter: RETRY_AFTER_SECONDS,
    });
    return;
  }

  next();
}
