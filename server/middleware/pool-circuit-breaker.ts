import type { Request, Response, NextFunction } from "express";
import { ERROR_CODES, replyError } from "../api-response";
import { getPoolHealth } from "../db";
import { logger } from "../logger";

const log = logger.child("pool-circuit-breaker");

const UTILIZATION_THRESHOLD = 80;
const CACHE_DURATION_MS = 1000;
const RETRY_AFTER_SECONDS = 5;

const EXEMPT_PATH_PREFIXES = ["/api/health", "/api/metrics", "/api/ops/health", "/api/ops/metrics"];

let cachedUtilization = 0;
let cachedWaitingRequests = 0;
let lastCheckedAt = 0;

/** @internal Reset cached state — test use only */
export function _resetPoolCircuitBreakerCache(): void {
  cachedUtilization = 0;
  cachedWaitingRequests = 0;
  lastCheckedAt = 0;
}

export function poolCircuitBreakerMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.path !== "/api" && !req.path.startsWith("/api/")) {
    next();
    return;
  }

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
    cachedWaitingRequests = health.waitingRequests;
    lastCheckedAt = now;
  }

  if (cachedUtilization >= UTILIZATION_THRESHOLD && cachedWaitingRequests > 0) {
    log.warn("Pool circuit breaker: rejecting request", {
      utilizationPercent: cachedUtilization,
      waitingRequests: cachedWaitingRequests,
      orgId: (req as unknown as Record<string, unknown>).orgId,
      path: req.path,
    });
    res.set("Retry-After", String(RETRY_AFTER_SECONDS));
    replyError(res, 503, [
      {
        code: ERROR_CODES.SERVICE_UNAVAILABLE,
        message: "Database capacity is temporarily saturated. Please retry shortly.",
      },
    ]);
    return;
  }

  next();
}
