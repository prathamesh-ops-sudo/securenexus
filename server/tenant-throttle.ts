import { logger } from "./logger";
import { getPodId } from "./scaling-state";
import { storage } from "./storage";
import type { Request, Response, NextFunction } from "express";
import { replyRateLimit, ERROR_CODES } from "./api-response";

const log = logger.child("tenant-throttle");

export type PlanTier = "free" | "pro" | "enterprise";

export interface TenantQuotas {
  ingestionEventsPerMinute: number;
  ingestionEventsPerDay: number;
  aiTokensPerDay: number;
  aiInvocationsPerMinute: number;
  connectorSyncsPerHour: number;
  connectorMaxConcurrent: number;
  apiCallsPerMinute: number;
  apiCallsPerDay: number;
  maxStorageGb: number;
  maxSseConnections: number;
}

const PLAN_QUOTAS: Record<PlanTier, TenantQuotas> = {
  free: {
    ingestionEventsPerMinute: 100,
    ingestionEventsPerDay: 10_000,
    aiTokensPerDay: 5_000,
    aiInvocationsPerMinute: 5,
    connectorSyncsPerHour: 6,
    connectorMaxConcurrent: 1,
    apiCallsPerMinute: 60,
    apiCallsPerDay: 10_000,
    maxStorageGb: 5,
    maxSseConnections: 3,
  },
  pro: {
    ingestionEventsPerMinute: 1_000,
    ingestionEventsPerDay: 500_000,
    aiTokensPerDay: 50_000,
    aiInvocationsPerMinute: 30,
    connectorSyncsPerHour: 60,
    connectorMaxConcurrent: 5,
    apiCallsPerMinute: 300,
    apiCallsPerDay: 500_000,
    maxStorageGb: 100,
    maxSseConnections: 20,
  },
  enterprise: {
    ingestionEventsPerMinute: 10_000,
    ingestionEventsPerDay: 5_000_000,
    aiTokensPerDay: 500_000,
    aiInvocationsPerMinute: 100,
    connectorSyncsPerHour: 360,
    connectorMaxConcurrent: 20,
    apiCallsPerMinute: 1_000,
    apiCallsPerDay: 5_000_000,
    maxStorageGb: 1_000,
    maxSseConnections: 100,
  },
};

const orgQuotaOverrides = new Map<string, Partial<TenantQuotas>>();

export function getOrgQuotas(orgId: string, plan: PlanTier): TenantQuotas {
  const base = PLAN_QUOTAS[plan];
  const overrides = orgQuotaOverrides.get(orgId);
  if (!overrides) return { ...base };
  return { ...base, ...overrides };
}

export function setOrgQuotaOverride(orgId: string, overrides: Partial<TenantQuotas>): void {
  const current = orgQuotaOverrides.get(orgId) || {};
  orgQuotaOverrides.set(orgId, { ...current, ...overrides });
  log.info("Quota override set", { orgId, overrides });
}

export function clearOrgQuotaOverride(orgId: string): void {
  orgQuotaOverrides.delete(orgId);
  log.info("Quota override cleared", { orgId });
}

interface SlidingWindowCounter {
  windowStartMs: number;
  count: number;
}

interface OrgUsageState {
  ingestionPerMinute: SlidingWindowCounter;
  ingestionPerDay: SlidingWindowCounter;
  aiTokensPerDay: SlidingWindowCounter;
  aiInvocationsPerMinute: SlidingWindowCounter;
  connectorSyncsPerHour: SlidingWindowCounter;
  apiCallsPerMinute: SlidingWindowCounter;
  apiCallsPerDay: SlidingWindowCounter;
  activeConnectorSyncs: number;
  activeSseConnections: number;
}

const orgUsage = new Map<string, OrgUsageState>();

const ONE_MINUTE = 60 * 1000;
const ONE_HOUR = 60 * 60 * 1000;
const ONE_DAY = 24 * 60 * 60 * 1000;

function getOrCreateUsage(orgId: string): OrgUsageState {
  let state = orgUsage.get(orgId);
  if (!state) {
    const now = Date.now();
    state = {
      ingestionPerMinute: { windowStartMs: now, count: 0 },
      ingestionPerDay: { windowStartMs: now, count: 0 },
      aiTokensPerDay: { windowStartMs: now, count: 0 },
      aiInvocationsPerMinute: { windowStartMs: now, count: 0 },
      connectorSyncsPerHour: { windowStartMs: now, count: 0 },
      apiCallsPerMinute: { windowStartMs: now, count: 0 },
      apiCallsPerDay: { windowStartMs: now, count: 0 },
      activeConnectorSyncs: 0,
      activeSseConnections: 0,
    };
    orgUsage.set(orgId, state);
  }
  return state;
}

function resetWindowIfExpired(counter: SlidingWindowCounter, windowMs: number): void {
  const now = Date.now();
  if (now - counter.windowStartMs >= windowMs) {
    counter.windowStartMs = now;
    counter.count = 0;
  }
}

export type QuotaCategory = "ingestion" | "ai_tokens" | "ai_invocations" | "connector_sync" | "api_calls" | "sse_connections";

export interface QuotaCheckResult {
  allowed: boolean;
  category: QuotaCategory;
  current: number;
  limit: number;
  remaining: number;
  retryAfterSeconds?: number;
  message?: string;
}

export function checkIngestionQuota(orgId: string, plan: PlanTier, eventCount: number = 1): QuotaCheckResult {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  resetWindowIfExpired(state.ingestionPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.ingestionPerDay, ONE_DAY);

  if (state.ingestionPerMinute.count + eventCount > quotas.ingestionEventsPerMinute) {
    const retryAfter = Math.ceil((ONE_MINUTE - (Date.now() - state.ingestionPerMinute.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "ingestion",
      current: state.ingestionPerMinute.count,
      limit: quotas.ingestionEventsPerMinute,
      remaining: Math.max(0, quotas.ingestionEventsPerMinute - state.ingestionPerMinute.count),
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `Ingestion rate limit exceeded: ${state.ingestionPerMinute.count}/${quotas.ingestionEventsPerMinute} events/min`,
    };
  }

  if (state.ingestionPerDay.count + eventCount > quotas.ingestionEventsPerDay) {
    const retryAfter = Math.ceil((ONE_DAY - (Date.now() - state.ingestionPerDay.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "ingestion",
      current: state.ingestionPerDay.count,
      limit: quotas.ingestionEventsPerDay,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `Daily ingestion limit exceeded: ${state.ingestionPerDay.count}/${quotas.ingestionEventsPerDay} events/day`,
    };
  }

  return {
    allowed: true,
    category: "ingestion",
    current: state.ingestionPerMinute.count,
    limit: quotas.ingestionEventsPerMinute,
    remaining: quotas.ingestionEventsPerMinute - state.ingestionPerMinute.count - eventCount,
  };
}

export function recordIngestion(orgId: string, eventCount: number = 1): void {
  const state = getOrCreateUsage(orgId);
  resetWindowIfExpired(state.ingestionPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.ingestionPerDay, ONE_DAY);
  state.ingestionPerMinute.count += eventCount;
  state.ingestionPerDay.count += eventCount;
}

export function checkAiTokenQuota(orgId: string, plan: PlanTier, tokenCount: number): QuotaCheckResult {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  resetWindowIfExpired(state.aiTokensPerDay, ONE_DAY);

  if (state.aiTokensPerDay.count + tokenCount > quotas.aiTokensPerDay) {
    const retryAfter = Math.ceil((ONE_DAY - (Date.now() - state.aiTokensPerDay.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "ai_tokens",
      current: state.aiTokensPerDay.count,
      limit: quotas.aiTokensPerDay,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `Daily AI token limit exceeded: ${state.aiTokensPerDay.count}/${quotas.aiTokensPerDay} tokens/day`,
    };
  }

  return {
    allowed: true,
    category: "ai_tokens",
    current: state.aiTokensPerDay.count,
    limit: quotas.aiTokensPerDay,
    remaining: quotas.aiTokensPerDay - state.aiTokensPerDay.count - tokenCount,
  };
}

export function checkAiInvocationQuota(orgId: string, plan: PlanTier): QuotaCheckResult {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  resetWindowIfExpired(state.aiInvocationsPerMinute, ONE_MINUTE);

  if (state.aiInvocationsPerMinute.count + 1 > quotas.aiInvocationsPerMinute) {
    const retryAfter = Math.ceil((ONE_MINUTE - (Date.now() - state.aiInvocationsPerMinute.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "ai_invocations",
      current: state.aiInvocationsPerMinute.count,
      limit: quotas.aiInvocationsPerMinute,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `AI invocation rate limit: ${state.aiInvocationsPerMinute.count}/${quotas.aiInvocationsPerMinute} calls/min`,
    };
  }

  return {
    allowed: true,
    category: "ai_invocations",
    current: state.aiInvocationsPerMinute.count,
    limit: quotas.aiInvocationsPerMinute,
    remaining: quotas.aiInvocationsPerMinute - state.aiInvocationsPerMinute.count - 1,
  };
}

export function recordAiUsage(orgId: string, tokenCount: number): void {
  const state = getOrCreateUsage(orgId);
  resetWindowIfExpired(state.aiTokensPerDay, ONE_DAY);
  resetWindowIfExpired(state.aiInvocationsPerMinute, ONE_MINUTE);
  state.aiTokensPerDay.count += tokenCount;
  state.aiInvocationsPerMinute.count++;
}

export function checkConnectorSyncQuota(orgId: string, plan: PlanTier): QuotaCheckResult {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  resetWindowIfExpired(state.connectorSyncsPerHour, ONE_HOUR);

  if (state.connectorSyncsPerHour.count + 1 > quotas.connectorSyncsPerHour) {
    const retryAfter = Math.ceil((ONE_HOUR - (Date.now() - state.connectorSyncsPerHour.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "connector_sync",
      current: state.connectorSyncsPerHour.count,
      limit: quotas.connectorSyncsPerHour,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `Connector sync rate limit: ${state.connectorSyncsPerHour.count}/${quotas.connectorSyncsPerHour} syncs/hour`,
    };
  }

  if (state.activeConnectorSyncs >= quotas.connectorMaxConcurrent) {
    return {
      allowed: false,
      category: "connector_sync",
      current: state.activeConnectorSyncs,
      limit: quotas.connectorMaxConcurrent,
      remaining: 0,
      retryAfterSeconds: 10,
      message: `Concurrent connector sync limit: ${state.activeConnectorSyncs}/${quotas.connectorMaxConcurrent} active`,
    };
  }

  return {
    allowed: true,
    category: "connector_sync",
    current: state.connectorSyncsPerHour.count,
    limit: quotas.connectorSyncsPerHour,
    remaining: quotas.connectorSyncsPerHour - state.connectorSyncsPerHour.count - 1,
  };
}

export function recordConnectorSyncStart(orgId: string): void {
  const state = getOrCreateUsage(orgId);
  resetWindowIfExpired(state.connectorSyncsPerHour, ONE_HOUR);
  state.connectorSyncsPerHour.count++;
  state.activeConnectorSyncs++;
}

export function recordConnectorSyncEnd(orgId: string): void {
  const state = getOrCreateUsage(orgId);
  state.activeConnectorSyncs = Math.max(0, state.activeConnectorSyncs - 1);
}

export function checkApiCallQuota(orgId: string, plan: PlanTier): QuotaCheckResult {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  resetWindowIfExpired(state.apiCallsPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.apiCallsPerDay, ONE_DAY);

  if (state.apiCallsPerMinute.count + 1 > quotas.apiCallsPerMinute) {
    const retryAfter = Math.ceil((ONE_MINUTE - (Date.now() - state.apiCallsPerMinute.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "api_calls",
      current: state.apiCallsPerMinute.count,
      limit: quotas.apiCallsPerMinute,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `API rate limit: ${state.apiCallsPerMinute.count}/${quotas.apiCallsPerMinute} calls/min`,
    };
  }

  if (state.apiCallsPerDay.count + 1 > quotas.apiCallsPerDay) {
    const retryAfter = Math.ceil((ONE_DAY - (Date.now() - state.apiCallsPerDay.windowStartMs)) / 1000);
    return {
      allowed: false,
      category: "api_calls",
      current: state.apiCallsPerDay.count,
      limit: quotas.apiCallsPerDay,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfter),
      message: `Daily API limit: ${state.apiCallsPerDay.count}/${quotas.apiCallsPerDay} calls/day`,
    };
  }

  return {
    allowed: true,
    category: "api_calls",
    current: state.apiCallsPerMinute.count,
    limit: quotas.apiCallsPerMinute,
    remaining: quotas.apiCallsPerMinute - state.apiCallsPerMinute.count - 1,
  };
}

export function recordApiCall(orgId: string): void {
  const state = getOrCreateUsage(orgId);
  resetWindowIfExpired(state.apiCallsPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.apiCallsPerDay, ONE_DAY);
  state.apiCallsPerMinute.count++;
  state.apiCallsPerDay.count++;
}

export function checkSseConnectionQuota(orgId: string, plan: PlanTier): QuotaCheckResult {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  if (state.activeSseConnections >= quotas.maxSseConnections) {
    return {
      allowed: false,
      category: "sse_connections",
      current: state.activeSseConnections,
      limit: quotas.maxSseConnections,
      remaining: 0,
      message: `SSE connection limit: ${state.activeSseConnections}/${quotas.maxSseConnections} active`,
    };
  }

  return {
    allowed: true,
    category: "sse_connections",
    current: state.activeSseConnections,
    limit: quotas.maxSseConnections,
    remaining: quotas.maxSseConnections - state.activeSseConnections - 1,
  };
}

export function recordSseConnect(orgId: string): void {
  const state = getOrCreateUsage(orgId);
  state.activeSseConnections++;
}

export function recordSseDisconnect(orgId: string): void {
  const state = getOrCreateUsage(orgId);
  state.activeSseConnections = Math.max(0, state.activeSseConnections - 1);
}

export interface OrgQuotaStatus {
  orgId: string;
  plan: PlanTier;
  quotas: TenantQuotas;
  usage: {
    ingestionPerMinute: { current: number; limit: number; pct: number };
    ingestionPerDay: { current: number; limit: number; pct: number };
    aiTokensPerDay: { current: number; limit: number; pct: number };
    aiInvocationsPerMinute: { current: number; limit: number; pct: number };
    connectorSyncsPerHour: { current: number; limit: number; pct: number };
    connectorActiveSyncs: { current: number; limit: number; pct: number };
    apiCallsPerMinute: { current: number; limit: number; pct: number };
    apiCallsPerDay: { current: number; limit: number; pct: number };
    sseConnections: { current: number; limit: number; pct: number };
  };
  warnings: string[];
  throttled: boolean;
}

function usagePct(current: number, limit: number): number {
  if (limit <= 0) return 0;
  return Math.round((current / limit) * 100);
}

export function getOrgQuotaStatus(orgId: string, plan: PlanTier): OrgQuotaStatus {
  const quotas = getOrgQuotas(orgId, plan);
  const state = getOrCreateUsage(orgId);

  resetWindowIfExpired(state.ingestionPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.ingestionPerDay, ONE_DAY);
  resetWindowIfExpired(state.aiTokensPerDay, ONE_DAY);
  resetWindowIfExpired(state.aiInvocationsPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.connectorSyncsPerHour, ONE_HOUR);
  resetWindowIfExpired(state.apiCallsPerMinute, ONE_MINUTE);
  resetWindowIfExpired(state.apiCallsPerDay, ONE_DAY);

  const usage = {
    ingestionPerMinute: { current: state.ingestionPerMinute.count, limit: quotas.ingestionEventsPerMinute, pct: usagePct(state.ingestionPerMinute.count, quotas.ingestionEventsPerMinute) },
    ingestionPerDay: { current: state.ingestionPerDay.count, limit: quotas.ingestionEventsPerDay, pct: usagePct(state.ingestionPerDay.count, quotas.ingestionEventsPerDay) },
    aiTokensPerDay: { current: state.aiTokensPerDay.count, limit: quotas.aiTokensPerDay, pct: usagePct(state.aiTokensPerDay.count, quotas.aiTokensPerDay) },
    aiInvocationsPerMinute: { current: state.aiInvocationsPerMinute.count, limit: quotas.aiInvocationsPerMinute, pct: usagePct(state.aiInvocationsPerMinute.count, quotas.aiInvocationsPerMinute) },
    connectorSyncsPerHour: { current: state.connectorSyncsPerHour.count, limit: quotas.connectorSyncsPerHour, pct: usagePct(state.connectorSyncsPerHour.count, quotas.connectorSyncsPerHour) },
    connectorActiveSyncs: { current: state.activeConnectorSyncs, limit: quotas.connectorMaxConcurrent, pct: usagePct(state.activeConnectorSyncs, quotas.connectorMaxConcurrent) },
    apiCallsPerMinute: { current: state.apiCallsPerMinute.count, limit: quotas.apiCallsPerMinute, pct: usagePct(state.apiCallsPerMinute.count, quotas.apiCallsPerMinute) },
    apiCallsPerDay: { current: state.apiCallsPerDay.count, limit: quotas.apiCallsPerDay, pct: usagePct(state.apiCallsPerDay.count, quotas.apiCallsPerDay) },
    sseConnections: { current: state.activeSseConnections, limit: quotas.maxSseConnections, pct: usagePct(state.activeSseConnections, quotas.maxSseConnections) },
  };

  const warnings: string[] = [];
  const WARNING_THRESHOLD = 80;
  for (const [key, val] of Object.entries(usage)) {
    if (val.pct >= WARNING_THRESHOLD) {
      warnings.push(`${key}: ${val.pct}% used (${val.current}/${val.limit})`);
    }
  }

  const throttled = Object.values(usage).some((v) => v.pct >= 100);

  return { orgId, plan, quotas, usage, warnings, throttled };
}

export function tenantApiThrottleMiddleware(detectPlan: (req: Request) => PlanTier) {
  return (req: Request, res: Response, next: NextFunction) => {
    const orgId = (req as any).orgId;
    if (!orgId) return next();

    const plan = detectPlan(req);
    const check = checkApiCallQuota(orgId, plan);

    if (!check.allowed) {
      res.setHeader("Retry-After", String(check.retryAfterSeconds || 60));
      res.setHeader("X-RateLimit-Limit", String(check.limit));
      res.setHeader("X-RateLimit-Remaining", "0");
      return replyRateLimit(res, check.message || "API rate limit exceeded", ERROR_CODES.RATE_LIMITED);
    }

    recordApiCall(orgId);

    res.setHeader("X-RateLimit-Limit", String(check.limit));
    res.setHeader("X-RateLimit-Remaining", String(check.remaining));

    next();
  };
}

export function initializeTenantThrottle(): void {
  log.info("Tenant throttle module initialized", { podId: getPodId(), plans: Object.keys(PLAN_QUOTAS) });
}
