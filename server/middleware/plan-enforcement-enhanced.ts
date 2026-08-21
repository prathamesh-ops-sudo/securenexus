import type { Request, Response, NextFunction } from "express";
import type { UsageRecord } from "../../shared/schema";
import { storage } from "../storage";
import { logger } from "../logger";
import { replyRateLimit } from "../api-response";

const log = logger.child("plan-enforcement");

/**
 * Enterprise-Grade Plan Enforcement Middleware
 *
 * Enforces subscription plan limits across all features:
 * - Alert ingestion limits
 * - Connector limits
 * - User limits
 * - AI analysis limits
 * - Retention limits
 * - API rate limits (plan-aware)
 */

export interface PlanLimits {
  alerts: number; // -1 = unlimited
  connectors: number;
  users: number;
  retention_days: number;
  ai_analyses: number;
  api_calls_per_hour: number;
}

const PLAN_LIMITS: Record<string, PlanLimits> = {
  free: {
    alerts: 100,
    connectors: 2,
    users: 1,
    retention_days: 7,
    ai_analyses: 10,
    api_calls_per_hour: 100,
  },
  pro: {
    alerts: 10000,
    connectors: 10,
    users: 5,
    retention_days: 30,
    ai_analyses: 100,
    api_calls_per_hour: 1000,
  },
  enterprise: {
    alerts: -1, // unlimited
    connectors: -1,
    users: -1,
    retention_days: 365,
    ai_analyses: -1,
    api_calls_per_hour: 10000,
  },
};

/**
 * Get current plan for organization
 */
async function getCurrentPlan(orgId: string): Promise<string> {
  try {
    const subscription = await storage.getSubscription(orgId);

    if (!subscription) {
      return "free";
    }

    if (subscription.status === "active" && subscription.planId) {
      const plan = await storage.getPlan(subscription.planId);
      return plan?.name || "free";
    }

    if (subscription.trialEndDate && new Date(subscription.trialEndDate) > new Date()) {
      const plan = await storage.getPlan(subscription.planId);
      return plan?.name || "pro";
    }

    return "free";
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    log.error("Failed to get current plan", { error: message, orgId });
    return "free";
  }
}

/**
 * Get plan limits for organization
 */
export async function getPlanLimits(orgId: string): Promise<PlanLimits> {
  const plan = await getCurrentPlan(orgId);
  return PLAN_LIMITS[plan] || PLAN_LIMITS.free;
}

/**
 * Get current usage for organization
 */
interface UsageSummaryMap {
  alerts_ingested: number;
  connectors: number;
  users: number;
  ai_analyses: number;
  [key: string]: number;
}

function buildUsageMap(records: UsageRecord[]): UsageSummaryMap {
  const usageMap: UsageSummaryMap = {
    alerts_ingested: 0,
    connectors: 0,
    users: 0,
    ai_analyses: 0,
  };
  for (const record of records) {
    usageMap[record.metric] = record.value;
  }
  return usageMap;
}

function currentPeriodStart(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

async function getCurrentUsage(orgId: string): Promise<UsageSummaryMap> {
  try {
    const records = await storage.getUsageRecords(orgId, currentPeriodStart());
    return buildUsageMap(records);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    log.error("Failed to get current usage", { error: message, orgId });
    return {
      alerts_ingested: 0,
      connectors: 0,
      users: 0,
      ai_analyses: 0,
    };
  }
}

/**
 * Check if limit is exceeded
 */
async function isLimitExceeded(
  orgId: string,
  limit: keyof PlanLimits,
): Promise<{ exceeded: boolean; current: number; limit: number; percentage: number }> {
  const limits = await getPlanLimits(orgId);
  const usage = await getCurrentUsage(orgId);

  const limitValue = limits[limit];

  const LIMIT_TO_METRIC: Record<string, string> = {
    alerts: "alerts_ingested",
    ai_analyses: "ai_analyses",
    connectors: "connectors",
    users: "users",
  };
  const metricKey = LIMIT_TO_METRIC[limit] || limit;
  const currentUsage = usage[metricKey] || 0;

  // -1 means unlimited
  if (limitValue === -1) {
    return {
      exceeded: false,
      current: currentUsage,
      limit: -1,
      percentage: 0,
    };
  }
  const percentage = Math.round((currentUsage / limitValue) * 100);

  return {
    exceeded: currentUsage >= limitValue,
    current: currentUsage,
    limit: limitValue,
    percentage,
  };
}

/**
 * Middleware: Enforce plan limit for specific feature
 *
 * Usage:
 * app.post('/api/alerts', enforcePlanLimit('alerts'), handler);
 */
export function enforcePlanLimit(limit: keyof PlanLimits) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;

      if (!orgId) {
        return res.status(403).json({
          error: "No organization context",
          code: "NO_ORG_CONTEXT",
        });
      }

      const result = await isLimitExceeded(orgId, limit);

      if (result.exceeded) {
        const plan = await getCurrentPlan(orgId);

        log.warn("Plan limit exceeded", {
          orgId,
          limit,
          current: result.current,
          max: result.limit,
          plan,
        });

        return res.status(402).json({
          error: "Plan limit exceeded",
          code: "PLAN_LIMIT_EXCEEDED",
          limit,
          current: result.current,
          max: result.limit,
          percentage: result.percentage,
          plan,
          message: `You've reached your ${limit} limit (${result.current}/${result.limit}). Upgrade your plan to continue.`,
          upgradeUrl: "/billing",
        });
      }

      // Check soft limit (80% threshold) - add warning header
      if (result.percentage >= 80 && result.limit !== -1) {
        res.setHeader("X-Usage-Warning", `${limit}: ${result.percentage}% used`);
        res.setHeader("X-Usage-Current", String(result.current));
        res.setHeader("X-Usage-Limit", String(result.limit));
      }

      next();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Plan enforcement error", { error: message, limit });
      next();
    }
  };
}

/**
 * Middleware: Check multiple limits
 */
export function enforceMultipleLimits(limits: Array<keyof PlanLimits>) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;

      if (!orgId) {
        return res.status(403).json({
          error: "No organization context",
          code: "NO_ORG_CONTEXT",
        });
      }

      for (const limit of limits) {
        const result = await isLimitExceeded(orgId, limit);

        if (result.exceeded) {
          const plan = await getCurrentPlan(orgId);

          return res.status(402).json({
            error: "Plan limit exceeded",
            code: "PLAN_LIMIT_EXCEEDED",
            limit,
            current: result.current,
            max: result.limit,
            plan,
            message: `You've reached your ${limit} limit. Upgrade to continue.`,
            upgradeUrl: "/billing",
          });
        }
      }

      next();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Multiple limits enforcement error", { error: message });
      next();
    }
  };
}

/**
 * Middleware: Log usage for billing purposes
 */
export function trackUsage(metric: keyof PlanLimits) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;

      if (orgId) {
        // Increment usage counter
        await storage.incrementUsage(orgId, metric);
      }

      next();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Usage tracking error", { error: message, metric });
      next();
    }
  };
}

/**
 * Middleware: Rate limiting based on plan (plan-aware rate limiting)
 */
export function planAwareRateLimit() {
  const usageMap = new Map<string, { count: number; resetAt: number }>();

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Session traffic is protected by the interactive user limiter. This quota is
      // reserved for authenticated API-key and bearer-token traffic.
      if (!(req as any).apiKey) {
        return next();
      }

      const orgId = (req as any).orgId || (req as any).user?.orgId;

      if (!orgId) {
        return next();
      }

      const now = Date.now();
      const hourMs = 60 * 60 * 1000;

      // Get or create usage entry
      let usage = usageMap.get(orgId);
      if (!usage || usage.resetAt < now) {
        usage = { count: 0, resetAt: now + hourMs };
        usageMap.set(orgId, usage);
      }

      // Increment count
      usage.count++;

      // Get plan limits
      const limits = await getPlanLimits(orgId);
      const rateLimit = limits.api_calls_per_hour;

      // Set rate limit headers
      res.setHeader("X-RateLimit-Limit", String(rateLimit));
      res.setHeader("X-RateLimit-Remaining", String(Math.max(0, rateLimit - usage.count)));
      res.setHeader("X-RateLimit-Reset", String(usage.resetAt));

      // Check if exceeded
      if (rateLimit !== -1 && usage.count > rateLimit) {
        log.warn("Rate limit exceeded", {
          orgId,
          count: usage.count,
          limit: rateLimit,
        });

        const retryAfter = Math.max(1, Math.ceil((usage.resetAt - now) / 1000));
        res.setHeader("Retry-After", String(retryAfter));
        return replyRateLimit(
          res,
          `You've exceeded your API rate limit (${rateLimit} requests per hour). Upgrade your plan for higher limits.`,
          "RATE_LIMIT_EXCEEDED",
        );
      }

      next();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      log.error("Plan-aware rate limiting error", { error: message });
      next();
    }
  };
}

/**
 * Get usage summary for organization
 */
interface UsageLimitDetail {
  current: number;
  limit: number;
  percentage: number;
  exceeded: boolean;
}

interface UsageSummaryResult {
  plan: string;
  usage: {
    alerts: UsageLimitDetail;
    connectors: UsageLimitDetail;
    users: UsageLimitDetail;
    ai_analyses: UsageLimitDetail;
  };
  warnings: string[];
  blockers: string[];
}

function calculatePercentage(current: number, limit: number): number {
  if (limit === -1) return 0;
  if (limit === 0) return current > 0 ? 100 : 0;
  return Math.round((current / limit) * 100);
}

function buildLimitDetail(current: number, limit: number): UsageLimitDetail {
  return {
    current,
    limit,
    percentage: calculatePercentage(current, limit),
    exceeded: limit !== -1 && current >= limit,
  };
}

export async function getUsageSummary(orgId: string): Promise<UsageSummaryResult> {
  try {
    const limits = await getPlanLimits(orgId);
    const usage = await getCurrentUsage(orgId);
    const plan = await getCurrentPlan(orgId);

    const alertsUsed = usage.alerts_ingested;
    const connectorsUsed = usage.connectors;
    const usersUsed = usage.users;
    const aiAnalysesUsed = usage.ai_analyses;

    return {
      plan,
      usage: {
        alerts: buildLimitDetail(alertsUsed, limits.alerts),
        connectors: buildLimitDetail(connectorsUsed, limits.connectors),
        users: buildLimitDetail(usersUsed, limits.users),
        ai_analyses: buildLimitDetail(aiAnalysesUsed, limits.ai_analyses),
      },
      warnings: [],
      blockers: [],
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    log.error("Failed to get usage summary", { error: message, orgId });
    throw error;
  }
}
