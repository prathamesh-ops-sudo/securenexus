import type { Request, Response, NextFunction } from "express";
import { replyRateLimit, ERROR_CODES } from "../api-response";
import { logger } from "../logger";
import { storage } from "../storage";

const log = logger.child("org-rate-limit");

type PlanTier = "free" | "pro" | "enterprise";

const WINDOW_MS = 15 * 60 * 1000;

const PLAN_REQUEST_LIMITS: Record<PlanTier, number> = {
  free: 1_000,
  pro: 5_000,
  enterprise: 10_000,
};

interface BucketEntry {
  count: number;
  resetAt: number;
}

interface BucketEntryWithLimit extends BucketEntry {
  limit: number;
}

const buckets = new Map<string, BucketEntryWithLimit>();

function cleanupBuckets(): void {
  const now = Date.now();
  buckets.forEach((entry, key) => {
    if (entry.resetAt <= now) {
      buckets.delete(key);
    }
  });
}

setInterval(cleanupBuckets, 5 * 60 * 1000).unref();

async function resolveOrgPlan(orgId: string): Promise<PlanTier> {
  try {
    const org = await storage.getOrganization(orgId);
    if (org && (org as any).plan) {
      const plan = (org as any).plan as string;
      if (plan === "enterprise" || plan === "pro" || plan === "free") {
        return plan;
      }
    }
  } catch {
    log.debug("Failed to resolve org plan, defaulting to free", { orgId });
  }
  return "free";
}

export async function orgRateLimitMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (req.path === "/ops/health" || req.path === "/ops/ready" || req.path === "/ops/live" || req.path === "/health") {
    next();
    return;
  }

  const orgId: string | undefined = (req as any).orgId;
  const key = orgId || req.ip || "unknown";

  const now = Date.now();
  let bucket = buckets.get(key);

  let limit = PLAN_REQUEST_LIMITS.free;
  if (orgId) {
    const plan = await resolveOrgPlan(orgId);
    limit = PLAN_REQUEST_LIMITS[plan];
  }

  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + WINDOW_MS, limit };
    buckets.set(key, bucket);
  }

  bucket.limit = limit;
  bucket.count++;

  const remaining = Math.max(0, limit - bucket.count);
  const resetSeconds = Math.ceil((bucket.resetAt - now) / 1000);

  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  res.setHeader("X-RateLimit-Reset", String(resetSeconds));

  if (bucket.count > limit) {
    log.warn("Org rate limit exceeded", {
      key,
      orgId: orgId ?? null,
      count: bucket.count,
      limit,
      windowMs: WINDOW_MS,
    });
    replyRateLimit(
      res,
      `Rate limit exceeded. ${limit} requests per 15 minutes allowed for your plan.`,
      ERROR_CODES.RATE_LIMITED,
    );
    return;
  }

  next();
}

export function getOrgRateLimitStats(): {
  activeBuckets: number;
  bucketDetails: Array<{ key: string; count: number; remaining: number; resetAt: string }>;
} {
  const now = Date.now();
  const details: Array<{ key: string; count: number; remaining: number; resetAt: string }> = [];
  buckets.forEach((entry, key) => {
    if (entry.resetAt > now) {
      details.push({
        key: key.slice(0, 8) + "...",
        count: entry.count,
        remaining: Math.max(0, entry.limit - entry.count),
        resetAt: new Date(entry.resetAt).toISOString(),
      });
    }
  });
  return { activeBuckets: details.length, bucketDetails: details.slice(0, 20) };
}
