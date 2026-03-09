import type { Request, Response, NextFunction } from 'express';
import { storage } from '../storage';
import { logger } from '../logger';

const log = logger.child('plan-enforcement');

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
    const org = await storage.getOrganization(orgId);
    
    if (!org) {
      return 'free';
    }

    // Check if has active subscription
    if (org.stripeSubscriptionId && org.subscriptionStatus === 'active') {
      // Check subscription details from Stripe or stored plan
      // For now, return 'pro' if has subscription
      // In production, this should check the actual Stripe subscription
      return org.planId || 'pro';
    }

    // Check if in trial
    if (org.trialEndsAt && new Date(org.trialEndsAt) > new Date()) {
      return org.trialPlan || 'pro'; // Default trial to pro features
    }

    return 'free';
  } catch (error: any) {
    log.error('Failed to get current plan', { error: error.message, orgId });
    return 'free'; // Default to free on error
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
async function getCurrentUsage(orgId: string): Promise<any> {
  try {
    return await storage.getUsageByOrg(orgId);
  } catch (error: any) {
    log.error('Failed to get current usage', { error: error.message, orgId });
    return {
      alertsIngested: 0,
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
  limit: keyof PlanLimits
): Promise<{ exceeded: boolean; current: number; limit: number; percentage: number }> {
  const limits = await getPlanLimits(orgId);
  const usage = await getCurrentUsage(orgId);

  const limitValue = limits[limit];

  // -1 means unlimited
  if (limitValue === -1) {
    return {
      exceeded: false,
      current: usage[limit] || 0,
      limit: -1,
      percentage: 0,
    };
  }

  // Map limit key to usage key
  let usageKey = limit;
  if (limit === 'alerts') usageKey = 'alertsIngested';

  const currentUsage = usage[usageKey] || 0;
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
          error: 'No organization context',
          code: 'NO_ORG_CONTEXT',
        });
      }

      const result = await isLimitExceeded(orgId, limit);

      if (result.exceeded) {
        const plan = await getCurrentPlan(orgId);
        
        log.warn('Plan limit exceeded', {
          orgId,
          limit,
          current: result.current,
          max: result.limit,
          plan,
        });

        return res.status(402).json({
          error: 'Plan limit exceeded',
          code: 'PLAN_LIMIT_EXCEEDED',
          limit,
          current: result.current,
          max: result.limit,
          percentage: result.percentage,
          plan,
          message: `You've reached your ${limit} limit (${result.current}/${result.limit}). Upgrade your plan to continue.`,
          upgradeUrl: '/billing',
        });
      }

      // Check soft limit (80% threshold) - add warning header
      if (result.percentage >= 80 && result.limit !== -1) {
        res.setHeader('X-Usage-Warning', `${limit}: ${result.percentage}% used`);
        res.setHeader('X-Usage-Current', String(result.current));
        res.setHeader('X-Usage-Limit', String(result.limit));
      }

      next();
    } catch (error: any) {
      log.error('Plan enforcement error', { error: error.message, limit });
      // On error, allow request to proceed (fail open)
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
          error: 'No organization context',
          code: 'NO_ORG_CONTEXT',
        });
      }

      for (const limit of limits) {
        const result = await isLimitExceeded(orgId, limit);

        if (result.exceeded) {
          const plan = await getCurrentPlan(orgId);

          return res.status(402).json({
            error: 'Plan limit exceeded',
            code: 'PLAN_LIMIT_EXCEEDED',
            limit,
            current: result.current,
            max: result.limit,
            plan,
            message: `You've reached your ${limit} limit. Upgrade to continue.`,
            upgradeUrl: '/billing',
          });
        }
      }

      next();
    } catch (error: any) {
      log.error('Multiple limits enforcement error', { error: error.message });
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
    } catch (error: any) {
      log.error('Usage tracking error', { error: error.message, metric });
      next(); // Continue even if tracking fails
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
      const orgId = (req as any).orgId || (req as any).user?.orgId;

      if (!orgId) {
        return next(); // No org context, skip rate limiting
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
      res.setHeader('X-RateLimit-Limit', String(rateLimit));
      res.setHeader('X-RateLimit-Remaining', String(Math.max(0, rateLimit - usage.count)));
      res.setHeader('X-RateLimit-Reset', String(usage.resetAt));

      // Check if exceeded
      if (rateLimit !== -1 && usage.count > rateLimit) {
        log.warn('Rate limit exceeded', {
          orgId,
          count: usage.count,
          limit: rateLimit,
        });

        return res.status(429).json({
          error: 'Rate limit exceeded',
          code: 'RATE_LIMIT_EXCEEDED',
          message: `You've exceeded your API rate limit (${rateLimit} requests per hour). Upgrade your plan for higher limits.`,
          retryAfter: Math.ceil((usage.resetAt - now) / 1000),
          upgradeUrl: '/billing',
        });
      }

      next();
    } catch (error: any) {
      log.error('Plan-aware rate limiting error', { error: error.message });
      next(); // Continue on error
    }
  };
}

/**
 * Get usage summary for organization
 */
export async function getUsageSummary(orgId: string): Promise<any> {
  try {
    const limits = await getPlanLimits(orgId);
    const usage = await getCurrentUsage(orgId);
    const plan = await getCurrentPlan(orgId);

    const calculatePercentage = (current: number, limit: number): number => {
      if (limit === -1) return 0;
      return Math.round((current / limit) * 100);
    };

    return {
      plan,
      usage: {
        alerts: {
          current: usage.alertsIngested || 0,
          limit: limits.alerts,
          percentage: calculatePercentage(usage.alertsIngested || 0, limits.alerts),
          exceeded: limits.alerts !== -1 && (usage.alertsIngested || 0) >= limits.alerts,
        },
        connectors: {
          current: usage.connectors || 0,
          limit: limits.connectors,
          percentage: calculatePercentage(usage.connectors || 0, limits.connectors),
          exceeded: limits.connectors !== -1 && (usage.connectors || 0) >= limits.connectors,
        },
        users: {
          current: usage.users || 0,
          limit: limits.users,
          percentage: calculatePercentage(usage.users || 0, limits.users),
          exceeded: limits.users !== -1 && (usage.users || 0) >= limits.users,
        },
        ai_analyses: {
          current: usage.ai_analyses || 0,
          limit: limits.ai_analyses,
          percentage: calculatePercentage(usage.ai_analyses || 0, limits.ai_analyses),
          exceeded: limits.ai_analyses !== -1 && (usage.ai_analyses || 0) >= limits.ai_analyses,
        },
      },
      warnings: [],
      blockers: [],
    };
  } catch (error: any) {
    log.error('Failed to get usage summary', { error: error.message, orgId });
    throw error;
  }
}
