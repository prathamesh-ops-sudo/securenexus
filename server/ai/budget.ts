import { logger } from "../logger";

const log = logger.child("ai-budget");

export interface UsageRecord {
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  modelId: string;
  promptId?: string;
  promptVersion?: number;
  latencyMs: number;
  timestamp?: number;
}

interface OrgBudgetState {
  totalCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  invocationCount: number;
  records: UsageRecord[];
  windowStart: number;
}

const orgBudgets = new Map<string, OrgBudgetState>();

const DEFAULT_DAILY_BUDGET_USD = 50;
const DEFAULT_DAILY_INVOCATION_CAP = 5000;
const BUDGET_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_RECORDS_PER_ORG = 500;

interface OrgBudgetConfig {
  dailyBudgetUsd: number;
  dailyInvocationCap: number;
}

const orgBudgetConfigs = new Map<string, OrgBudgetConfig>();

export function setOrgBudget(orgId: string, budgetUsd: number, invocationCap: number): void {
  orgBudgetConfigs.set(orgId, { dailyBudgetUsd: budgetUsd, dailyInvocationCap: invocationCap });
}

function getOrgConfig(orgId: string): OrgBudgetConfig {
  return orgBudgetConfigs.get(orgId) || { dailyBudgetUsd: DEFAULT_DAILY_BUDGET_USD, dailyInvocationCap: DEFAULT_DAILY_INVOCATION_CAP };
}

function getOrCreateState(orgId: string): OrgBudgetState {
  let state = orgBudgets.get(orgId);
  const now = Date.now();

  if (!state || (now - state.windowStart) > BUDGET_WINDOW_MS) {
    state = {
      totalCostUsd: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      invocationCount: 0,
      records: [],
      windowStart: now,
    };
    orgBudgets.set(orgId, state);
  }

  return state;
}

export function checkBudget(orgId: string): { allowed: boolean; reason?: string } {
  const state = getOrCreateState(orgId);
  const budgetConfig = getOrgConfig(orgId);

  if (state.totalCostUsd >= budgetConfig.dailyBudgetUsd) {
    log.warn("AI budget exceeded", { orgId, spent: state.totalCostUsd, limit: budgetConfig.dailyBudgetUsd });
    return { allowed: false, reason: `Daily AI spend limit of $${budgetConfig.dailyBudgetUsd.toFixed(2)} reached ($${state.totalCostUsd.toFixed(4)} used)` };
  }

  if (state.invocationCount >= budgetConfig.dailyInvocationCap) {
    log.warn("AI invocation cap reached", { orgId, count: state.invocationCount, cap: budgetConfig.dailyInvocationCap });
    return { allowed: false, reason: `Daily invocation cap of ${budgetConfig.dailyInvocationCap} reached (${state.invocationCount} used)` };
  }

  return { allowed: true };
}

export function trackUsage(orgId: string, record: UsageRecord): void {
  const state = getOrCreateState(orgId);

  state.totalCostUsd += record.costUsd;
  state.totalInputTokens += record.inputTokens;
  state.totalOutputTokens += record.outputTokens;
  state.invocationCount++;

  state.records.push({ ...record, timestamp: Date.now() });
  if (state.records.length > MAX_RECORDS_PER_ORG) {
    state.records.splice(0, state.records.length - MAX_RECORDS_PER_ORG);
  }

  const budgetConfig = getOrgConfig(orgId);
  const usagePercent = (state.totalCostUsd / budgetConfig.dailyBudgetUsd) * 100;
  if (usagePercent >= 80 && usagePercent < 100) {
    log.warn("AI budget at 80%+", { orgId, spent: state.totalCostUsd, limit: budgetConfig.dailyBudgetUsd, percent: Math.round(usagePercent) });
  }
}

export interface OrgUsageSummary {
  orgId: string;
  windowStart: string;
  totalCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  invocationCount: number;
  budgetLimitUsd: number;
  invocationCap: number;
  budgetUsedPercent: number;
  invocationUsedPercent: number;
  recentRecords: UsageRecord[];
  byModel: Record<string, { count: number; costUsd: number; avgLatencyMs: number }>;
  byPrompt: Record<string, { count: number; costUsd: number; avgLatencyMs: number }>;
}

export function getOrgUsageSummary(orgId: string): OrgUsageSummary {
  const state = getOrCreateState(orgId);
  const budgetConfig = getOrgConfig(orgId);

  const byModel: Record<string, { count: number; costUsd: number; avgLatencyMs: number }> = {};
  const byPrompt: Record<string, { count: number; costUsd: number; avgLatencyMs: number }> = {};

  for (const r of state.records) {
    if (!byModel[r.modelId]) byModel[r.modelId] = { count: 0, costUsd: 0, avgLatencyMs: 0 };
    byModel[r.modelId].count++;
    byModel[r.modelId].costUsd += r.costUsd;
    byModel[r.modelId].avgLatencyMs += r.latencyMs;

    const pk = r.promptId || "unknown";
    if (!byPrompt[pk]) byPrompt[pk] = { count: 0, costUsd: 0, avgLatencyMs: 0 };
    byPrompt[pk].count++;
    byPrompt[pk].costUsd += r.costUsd;
    byPrompt[pk].avgLatencyMs += r.latencyMs;
  }

  for (const key of Object.keys(byModel)) {
    if (byModel[key].count > 0) byModel[key].avgLatencyMs = Math.round(byModel[key].avgLatencyMs / byModel[key].count);
  }
  for (const key of Object.keys(byPrompt)) {
    if (byPrompt[key].count > 0) byPrompt[key].avgLatencyMs = Math.round(byPrompt[key].avgLatencyMs / byPrompt[key].count);
  }

  return {
    orgId,
    windowStart: new Date(state.windowStart).toISOString(),
    totalCostUsd: Math.round(state.totalCostUsd * 1000000) / 1000000,
    totalInputTokens: state.totalInputTokens,
    totalOutputTokens: state.totalOutputTokens,
    invocationCount: state.invocationCount,
    budgetLimitUsd: budgetConfig.dailyBudgetUsd,
    invocationCap: budgetConfig.dailyInvocationCap,
    budgetUsedPercent: Math.round((state.totalCostUsd / budgetConfig.dailyBudgetUsd) * 10000) / 100,
    invocationUsedPercent: Math.round((state.invocationCount / budgetConfig.dailyInvocationCap) * 10000) / 100,
    recentRecords: state.records.slice(-20),
    byModel,
    byPrompt,
  };
}

export function getAllOrgUsageSummaries(): OrgUsageSummary[] {
  const summaries: OrgUsageSummary[] = [];
  for (const orgId of Array.from(orgBudgets.keys())) {
    summaries.push(getOrgUsageSummary(orgId));
  }
  return summaries;
}
