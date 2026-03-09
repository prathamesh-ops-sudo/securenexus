import { storage } from "./storage";
import { logger } from "./logger";

const log = logger.child("tiered-packaging");

export interface PlanTier {
  id: string;
  name: string;
  displayName: string;
  description: string;
  monthlyPriceCents: number;
  annualPriceCents: number;
  limits: PlanLimits;
  features: string[];
  recommended?: boolean;
  badge?: string;
}

export interface PlanLimits {
  users: number;
  dataSources: number;
  retentionDays: number;
  automationRunsPerMonth: number;
  aiTokensPerMonth: number;
  apiCallsPerMonth: number;
  storageGb: number;
  eventsPerMonth: number;
  burstAllowancePct: number;
}

export interface UsageSnapshot {
  metric: string;
  label: string;
  current: number;
  limit: number;
  unit: string;
  pctUsed: number;
  softThreshold: number;
  hardThreshold: number;
  status: "ok" | "warning" | "critical";
}

export interface BurstStatus {
  enabled: boolean;
  burstAllowancePct: number;
  activeBursts: BurstEntry[];
  remainingBurstBudget: number;
}

export interface BurstEntry {
  metric: string;
  activatedAt: string;
  expiresAt: string;
  extraCapacityPct: number;
}

export interface UpgradeRecommendation {
  currentTier: string;
  recommendedTier: string;
  reasons: RecommendationReason[];
  estimatedMonthlySavings: number;
  roiProjection: RoiProjection;
}

export interface RecommendationReason {
  metric: string;
  label: string;
  currentUsage: number;
  currentLimit: number;
  upgradedLimit: number;
  pctUsed: number;
  severity: "info" | "warning" | "critical";
}

export interface RoiProjection {
  currentCostCents: number;
  projectedCostCents: number;
  additionalCapacity: string[];
  paybackPeriodDays: number;
}

export interface UsageForecast {
  metric: string;
  label: string;
  currentUsage: number;
  limit: number;
  dailyRate: number;
  projectedHitDate: string | null;
  daysUntilLimit: number | null;
  trend: "increasing" | "stable" | "decreasing";
  confidence: number;
}

const PLAN_TIERS: PlanTier[] = [
  {
    id: "free",
    name: "free",
    displayName: "Free",
    description: "Get started with essential security monitoring for small teams",
    monthlyPriceCents: 0,
    annualPriceCents: 0,
    limits: {
      users: 5,
      dataSources: 3,
      retentionDays: 7,
      automationRunsPerMonth: 100,
      aiTokensPerMonth: 5000,
      apiCallsPerMonth: 10000,
      storageGb: 1,
      eventsPerMonth: 10000,
      burstAllowancePct: 0,
    },
    features: [
      "Basic alert triage",
      "3 data source connectors",
      "7-day log retention",
      "Community support",
      "Basic dashboards",
    ],
  },
  {
    id: "starter",
    name: "starter",
    displayName: "Starter",
    description: "For growing teams that need more visibility and automation",
    monthlyPriceCents: 4900,
    annualPriceCents: 47000,
    limits: {
      users: 25,
      dataSources: 10,
      retentionDays: 30,
      automationRunsPerMonth: 1000,
      aiTokensPerMonth: 50000,
      apiCallsPerMonth: 50000,
      storageGb: 10,
      eventsPerMonth: 100000,
      burstAllowancePct: 10,
    },
    features: [
      "AI-assisted triage",
      "10 data source connectors",
      "30-day log retention",
      "Email support",
      "Custom dashboards",
      "Playbook automation",
      "API access",
    ],
  },
  {
    id: "professional",
    name: "professional",
    displayName: "Professional",
    description: "Full-featured SOC platform for mid-size security teams",
    monthlyPriceCents: 14900,
    annualPriceCents: 143000,
    limits: {
      users: 100,
      dataSources: 50,
      retentionDays: 90,
      automationRunsPerMonth: 10000,
      aiTokensPerMonth: 500000,
      apiCallsPerMonth: 500000,
      storageGb: 100,
      eventsPerMonth: 1000000,
      burstAllowancePct: 20,
    },
    features: [
      "SOC Co-Pilot AI analyst",
      "50 data source connectors",
      "90-day log retention",
      "Priority support (4h SLA)",
      "Advanced analytics & reporting",
      "SOAR automation",
      "Threat intelligence feeds",
      "Compliance frameworks",
      "Custom integrations",
    ],
    recommended: true,
    badge: "Most Popular",
  },
  {
    id: "enterprise",
    name: "enterprise",
    displayName: "Enterprise",
    description: "Unlimited scale with dedicated support for large organizations",
    monthlyPriceCents: 0,
    annualPriceCents: 0,
    limits: {
      users: -1,
      dataSources: -1,
      retentionDays: 365,
      automationRunsPerMonth: -1,
      aiTokensPerMonth: -1,
      apiCallsPerMonth: -1,
      storageGb: -1,
      eventsPerMonth: -1,
      burstAllowancePct: 50,
    },
    features: [
      "Unlimited users & data sources",
      "365-day log retention",
      "Dedicated success manager",
      "24/7 premium support (1h SLA)",
      "Custom AI model training",
      "MSSP / multi-tenant support",
      "SSO & SCIM provisioning",
      "Data residency controls",
      "Audit log exports",
      "Custom SLAs",
    ],
    badge: "Contact Sales",
  },
];

const SOFT_THRESHOLD = 80;
const HARD_THRESHOLD = 95;

const burstStore = new Map<string, BurstEntry[]>();

export function getAllPlanTiers(): PlanTier[] {
  return PLAN_TIERS;
}

export function getPlanTierById(tierId: string): PlanTier | undefined {
  return PLAN_TIERS.find((p) => p.id === tierId);
}

function getTierIndex(tierId: string): number {
  return PLAN_TIERS.findIndex((p) => p.id === tierId);
}

function getNextTier(currentTierId: string): PlanTier | undefined {
  const idx = getTierIndex(currentTierId);
  if (idx < 0 || idx >= PLAN_TIERS.length - 1) return undefined;
  return PLAN_TIERS[idx + 1];
}

function metricLabel(metric: string): string {
  const labels: Record<string, string> = {
    users: "Team Members",
    dataSources: "Data Sources",
    retentionDays: "Retention Period",
    automationRunsPerMonth: "Automation Runs",
    aiTokensPerMonth: "AI / Copilot Tokens",
    apiCallsPerMonth: "API Calls",
    storageGb: "Storage",
    eventsPerMonth: "Events Ingested",
  };
  return labels[metric] || metric;
}

function metricUnit(metric: string): string {
  const units: Record<string, string> = {
    users: "members",
    dataSources: "connectors",
    retentionDays: "days",
    automationRunsPerMonth: "runs/month",
    aiTokensPerMonth: "tokens/month",
    apiCallsPerMonth: "calls/month",
    storageGb: "GB",
    eventsPerMonth: "events/month",
  };
  return units[metric] || "";
}

function getCurrentPeriodStart(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

async function resolveCurrentTier(orgId: string): Promise<PlanTier> {
  const sub = await storage.getSubscription(orgId);
  if (sub) {
    const plan = await storage.getPlan(sub.planId);
    if (plan) {
      const tier = PLAN_TIERS.find((t) => t.name === plan.name);
      if (tier) return tier;
    }
  }
  const orgLimit = await storage.getOrgPlanLimit(orgId);
  if (orgLimit?.planTier) {
    const tier = PLAN_TIERS.find((t) => t.name === orgLimit.planTier);
    if (tier) return tier;
  }
  return PLAN_TIERS[0];
}

async function getMetricUsage(orgId: string, metric: string): Promise<number> {
  const resourceMetrics = new Set(["users", "dataSources"]);
  if (resourceMetrics.has(metric)) {
    if (metric === "users") {
      const members = await storage.getOrgMemberships(orgId);
      return members.length;
    }
    if (metric === "dataSources") {
      return storage.countActiveConnectors(orgId);
    }
  }
  const metricMapping: Record<string, string> = {
    automationRunsPerMonth: "connector_syncs",
    aiTokensPerMonth: "ai_analyses",
    apiCallsPerMonth: "api_calls",
    eventsPerMonth: "alerts_ingested",
    storageGb: "storage_gb",
  };
  const storageMetric = metricMapping[metric] || metric;
  const periodStart = getCurrentPeriodStart();
  const record = await storage.getUsageRecord(orgId, storageMetric, periodStart);
  return record?.value ?? 0;
}

export async function getCurrentPlanAndUsage(orgId: string): Promise<{
  plan: PlanTier;
  billingCycle: "monthly" | "annual";
  billingCycleStart: string;
  billingCycleEnd: string;
  metrics: UsageSnapshot[];
  quotaAlerts: UsageSnapshot[];
}> {
  const plan = await resolveCurrentTier(orgId);
  const now = new Date();
  const cycleStart = getCurrentPeriodStart();
  const cycleEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));

  const sub = await storage.getSubscription(orgId);
  const billingCycle: "monthly" | "annual" =
    sub && typeof (sub as any).billingCycle === "string"
      ? ((sub as any).billingCycle as "monthly" | "annual")
      : "monthly";

  const metricKeys: (keyof PlanLimits)[] = [
    "users",
    "dataSources",
    "eventsPerMonth",
    "automationRunsPerMonth",
    "aiTokensPerMonth",
    "apiCallsPerMonth",
    "storageGb",
  ];

  const metrics: UsageSnapshot[] = [];
  const quotaAlerts: UsageSnapshot[] = [];

  for (const key of metricKeys) {
    const limit = plan.limits[key];
    if (typeof limit !== "number") continue;
    if (limit === -1) {
      metrics.push({
        metric: key,
        label: metricLabel(key),
        current: await getMetricUsage(orgId, key),
        limit: -1,
        unit: metricUnit(key),
        pctUsed: 0,
        softThreshold: SOFT_THRESHOLD,
        hardThreshold: HARD_THRESHOLD,
        status: "ok",
      });
      continue;
    }
    const current = await getMetricUsage(orgId, key);
    const pctUsed = limit > 0 ? Math.round((current / limit) * 100) : 0;
    let status: "ok" | "warning" | "critical" = "ok";
    if (pctUsed >= HARD_THRESHOLD) status = "critical";
    else if (pctUsed >= SOFT_THRESHOLD) status = "warning";

    const snapshot: UsageSnapshot = {
      metric: key,
      label: metricLabel(key),
      current,
      limit,
      unit: metricUnit(key),
      pctUsed,
      softThreshold: SOFT_THRESHOLD,
      hardThreshold: HARD_THRESHOLD,
      status,
    };
    metrics.push(snapshot);
    if (status !== "ok") quotaAlerts.push(snapshot);
  }

  return {
    plan,
    billingCycle,
    billingCycleStart: cycleStart.toISOString(),
    billingCycleEnd: cycleEnd.toISOString(),
    metrics,
    quotaAlerts,
  };
}

export async function getUsageForecast(orgId: string): Promise<UsageForecast[]> {
  const plan = await resolveCurrentTier(orgId);
  const now = new Date();
  const cycleEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  const dayOfMonth = now.getUTCDate();

  const forecastMetrics: (keyof PlanLimits)[] = [
    "eventsPerMonth",
    "automationRunsPerMonth",
    "aiTokensPerMonth",
    "apiCallsPerMonth",
  ];

  const forecasts: UsageForecast[] = [];

  for (const key of forecastMetrics) {
    const limit = plan.limits[key];
    if (typeof limit !== "number" || limit === -1) continue;

    const current = await getMetricUsage(orgId, key);
    const dailyRate = dayOfMonth > 0 ? current / dayOfMonth : 0;

    let projectedHitDate: string | null = null;
    let daysUntilLimit: number | null = null;
    let trend: "increasing" | "stable" | "decreasing" = "stable";

    if (dailyRate > 0 && limit > 0) {
      const daysToHit = Math.ceil((limit - current) / dailyRate);
      if (daysToHit > 0) {
        daysUntilLimit = daysToHit;
        const hitDate = new Date(now.getTime() + daysToHit * 24 * 60 * 60 * 1000);
        projectedHitDate = hitDate.toISOString();
      }
      const expectedAtDay = (limit / 30) * dayOfMonth;
      if (current > expectedAtDay * 1.2) trend = "increasing";
      else if (current < expectedAtDay * 0.8) trend = "decreasing";
    }

    const daysInMonth = Math.ceil(
      (cycleEnd.getTime() - new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).getTime()) /
        (24 * 60 * 60 * 1000),
    );
    const confidence = Math.min(Math.round((dayOfMonth / daysInMonth) * 100), 95);

    forecasts.push({
      metric: key,
      label: metricLabel(key),
      currentUsage: current,
      limit,
      dailyRate: Math.round(dailyRate * 100) / 100,
      projectedHitDate,
      daysUntilLimit,
      trend,
      confidence,
    });
  }

  return forecasts;
}

export async function getUpgradeRecommendation(orgId: string): Promise<UpgradeRecommendation | null> {
  const plan = await resolveCurrentTier(orgId);
  const nextTier = getNextTier(plan.id);
  if (!nextTier) return null;

  const metricKeys: (keyof PlanLimits)[] = [
    "users",
    "dataSources",
    "eventsPerMonth",
    "automationRunsPerMonth",
    "aiTokensPerMonth",
    "apiCallsPerMonth",
    "storageGb",
  ];

  const reasons: RecommendationReason[] = [];

  for (const key of metricKeys) {
    const currentLimit = plan.limits[key];
    if (typeof currentLimit !== "number" || currentLimit === -1) continue;
    const current = await getMetricUsage(orgId, key);
    const pctUsed = currentLimit > 0 ? Math.round((current / currentLimit) * 100) : 0;
    if (pctUsed < 60) continue;

    const upgradedLimit = nextTier.limits[key];
    let severity: "info" | "warning" | "critical" = "info";
    if (pctUsed >= HARD_THRESHOLD) severity = "critical";
    else if (pctUsed >= SOFT_THRESHOLD) severity = "warning";

    reasons.push({
      metric: key,
      label: metricLabel(key),
      currentUsage: current,
      currentLimit,
      upgradedLimit: typeof upgradedLimit === "number" ? upgradedLimit : -1,
      pctUsed,
      severity,
    });
  }

  if (reasons.length === 0) return null;

  const currentCostCents = plan.monthlyPriceCents;
  const projectedCostCents = nextTier.monthlyPriceCents;

  const additionalCapacity: string[] = [];
  for (const r of reasons) {
    if (r.upgradedLimit === -1) {
      additionalCapacity.push(`${r.label}: Unlimited`);
    } else {
      const increase = r.upgradedLimit - r.currentLimit;
      additionalCapacity.push(`${r.label}: +${increase.toLocaleString()}`);
    }
  }

  const criticalCount = reasons.filter((r) => r.severity === "critical").length;
  const paybackPeriodDays = criticalCount >= 2 ? 7 : criticalCount === 1 ? 14 : 30;
  const estimatedMonthlySavings = criticalCount > 0 ? Math.round(projectedCostCents * 0.15) : 0;

  return {
    currentTier: plan.id,
    recommendedTier: nextTier.id,
    reasons: reasons.sort((a, b) => {
      const sev = { critical: 0, warning: 1, info: 2 };
      return sev[a.severity] - sev[b.severity];
    }),
    estimatedMonthlySavings,
    roiProjection: {
      currentCostCents,
      projectedCostCents,
      additionalCapacity,
      paybackPeriodDays,
    },
  };
}

export function getBurstStatus(orgId: string, plan: PlanTier): BurstStatus {
  const key = `burst:${orgId}`;
  const now = Date.now();
  const entries = (burstStore.get(key) || []).filter((e) => new Date(e.expiresAt).getTime() > now);
  burstStore.set(key, entries);

  const totalBurstUsed = entries.reduce((sum, e) => sum + e.extraCapacityPct, 0);
  const remaining = Math.max(0, plan.limits.burstAllowancePct - totalBurstUsed);

  return {
    enabled: plan.limits.burstAllowancePct > 0,
    burstAllowancePct: plan.limits.burstAllowancePct,
    activeBursts: entries,
    remainingBurstBudget: remaining,
  };
}

export function activateBurst(
  orgId: string,
  metric: string,
  extraCapacityPct: number,
  durationHours: number,
  plan: PlanTier,
): { success: boolean; error?: string; burst?: BurstEntry } {
  if (plan.limits.burstAllowancePct <= 0) {
    return { success: false, error: "Burst capacity is not available on your current plan" };
  }

  const status = getBurstStatus(orgId, plan);
  if (extraCapacityPct > status.remainingBurstBudget) {
    return {
      success: false,
      error: `Requested burst (${extraCapacityPct}%) exceeds remaining budget (${status.remainingBurstBudget}%)`,
    };
  }

  if (durationHours < 1 || durationHours > 72) {
    return { success: false, error: "Burst duration must be between 1 and 72 hours" };
  }

  const now = new Date();
  const entry: BurstEntry = {
    metric,
    activatedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + durationHours * 60 * 60 * 1000).toISOString(),
    extraCapacityPct,
  };

  const key = `burst:${orgId}`;
  const existing = burstStore.get(key) || [];
  existing.push(entry);
  burstStore.set(key, existing);

  log.info("Burst capacity activated", { orgId, metric, extraCapacityPct, durationHours });

  return { success: true, burst: entry };
}
