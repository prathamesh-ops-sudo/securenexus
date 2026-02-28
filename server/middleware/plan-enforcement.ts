import type { Request, Response, NextFunction } from "express";
import { storage } from "../storage";
import { logger } from "../logger";
import { replyError } from "../api-response";

const log = logger.child("plan-enforcement");

const PLAN_LIMITS: Record<string, Record<string, number>> = {
  free: {
    alerts_ingested: 10000,
    connectors: 3,
    users: 5,
    api_keys: 2,
    playbooks: 5,
    ai_analyses: 100,
    api_calls: 10000,
    connector_syncs: 500,
  },
  pro: {
    alerts_ingested: 100000,
    connectors: 25,
    users: 50,
    api_keys: 20,
    playbooks: 50,
    ai_analyses: 5000,
    api_calls: 100000,
    connector_syncs: 5000,
  },
  enterprise: {
    alerts_ingested: -1,
    connectors: -1,
    users: -1,
    api_keys: -1,
    playbooks: -1,
    ai_analyses: -1,
    api_calls: -1,
    connector_syncs: -1,
  },
};

function getCurrentPeriodStart(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

async function resolveOrgLimits(orgId: string): Promise<{ tier: string; limits: Record<string, number> }> {
  const sub = await storage.getSubscription(orgId);
  let tier = "free";
  if (sub) {
    const plan = await storage.getPlan(sub.planId);
    if (plan) tier = plan.name;
  }

  const orgPlanLimit = await storage.getOrgPlanLimit(orgId);
  const baseLimits = PLAN_LIMITS[tier] || PLAN_LIMITS.free;

  if (orgPlanLimit) {
    return {
      tier: orgPlanLimit.planTier || tier,
      limits: {
        ...baseLimits,
        alerts_ingested: orgPlanLimit.eventsPerMonth,
        connectors: orgPlanLimit.maxConnectors,
        ai_analyses: orgPlanLimit.aiTokensPerMonth,
        api_calls: orgPlanLimit.apiCallsPerMonth,
        connector_syncs: orgPlanLimit.automationRunsPerMonth,
      },
    };
  }

  return { tier, limits: baseLimits };
}

const RESOURCE_COUNT_METRICS = new Set(["connectors", "api_keys", "playbooks"]);

async function getCurrentUsage(orgId: string, metric: string): Promise<number> {
  if (RESOURCE_COUNT_METRICS.has(metric)) {
    return getActiveResourceCount(orgId, metric);
  }
  const periodStart = getCurrentPeriodStart();
  const record = await storage.getUsageRecord(orgId, metric, periodStart);
  return record?.value ?? 0;
}

async function getActiveResourceCount(orgId: string, metric: string): Promise<number> {
  switch (metric) {
    case "connectors":
      return storage.countActiveConnectors(orgId);
    case "api_keys":
      return storage.countActiveApiKeys(orgId);
    case "playbooks":
      return storage.countActivePlaybooks(orgId);
    default:
      return 0;
  }
}

export function enforcePlanLimit(metric: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      if (!orgId) return next();

      const { tier, limits } = await resolveOrgLimits(orgId);
      const limit = limits[metric];

      if (limit === undefined || limit === -1) return next();

      const current = await getCurrentUsage(orgId, metric);

      if (current >= limit) {
        log.warn("Plan limit reached", { orgId, metric, current, limit, tier });
        return replyError(res, 429, [
          {
            code: "PLAN_LIMIT_REACHED",
            message: `Plan limit reached for ${metric}. Current: ${current}/${limit}. Upgrade your plan to increase limits.`,
            details: { metric, current, limit, tier, upgradeUrl: "/billing" },
          },
        ]);
      }

      next();
    } catch (err) {
      log.error("Plan enforcement check failed", { error: String(err) });
      next();
    }
  };
}

export async function getUsageSummary(orgId: string): Promise<{
  tier: string;
  metrics: Record<string, { current: number; limit: number; pct: number; status: "ok" | "warning" | "critical" }>;
}> {
  const { tier, limits } = await resolveOrgLimits(orgId);
  const periodStart = getCurrentPeriodStart();
  const records = await storage.getUsageRecords(orgId, periodStart);

  const recordMap = new Map<string, number>();
  for (const r of records) {
    recordMap.set(r.metric, r.value);
  }

  const metrics: Record<
    string,
    { current: number; limit: number; pct: number; status: "ok" | "warning" | "critical" }
  > = {};

  for (const [metric, limit] of Object.entries(limits)) {
    const current = RESOURCE_COUNT_METRICS.has(metric)
      ? await getActiveResourceCount(orgId, metric)
      : (recordMap.get(metric) ?? 0);
    if (limit === -1) {
      metrics[metric] = { current, limit: -1, pct: 0, status: "ok" };
      continue;
    }
    const pct = limit > 0 ? Math.round((current / limit) * 100) : 0;
    let status: "ok" | "warning" | "critical" = "ok";
    if (pct >= 100) status = "critical";
    else if (pct >= 80) status = "warning";
    metrics[metric] = { current, limit, pct, status };
  }

  return { tier, metrics };
}

export async function incrementAndCheck(
  orgId: string,
  metric: string,
  amount: number = 1,
): Promise<{ allowed: boolean; current: number; limit: number; pct: number }> {
  const { limits } = await resolveOrgLimits(orgId);
  const limit = limits[metric];

  if (limit === undefined || limit === -1) {
    await storage.incrementUsage(orgId, metric, amount);
    return { allowed: true, current: 0, limit: -1, pct: 0 };
  }

  const periodStart = getCurrentPeriodStart();
  const existing = await storage.getUsageRecord(orgId, metric, periodStart);
  const current = existing?.value ?? 0;

  if (current + amount > limit) {
    return { allowed: false, current, limit, pct: Math.round((current / limit) * 100) };
  }

  const updated = await storage.incrementUsage(orgId, metric, amount);
  const pct = limit > 0 ? Math.round((updated.value / limit) * 100) : 0;
  return { allowed: true, current: updated.value, limit, pct };
}
