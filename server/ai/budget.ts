import { pool } from "../db";
import { logger } from "../logger";

const log = logger.child("ai-budget");

const DEFAULT_DAILY_BUDGET_USD = 50;
const DEFAULT_DAILY_INVOCATION_CAP = 5000;

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

interface BudgetRow {
  org_id: string;
  budget_usd: number;
  invocation_cap: number;
  daily_spend_usd: number;
  daily_invocations: number;
  daily_input_tokens: number;
  daily_output_tokens: number;
  last_reset_at: Date | null;
  updated_at: Date | null;
}

const TABLE_ENSURED = { done: false };

async function ensureTable(): Promise<void> {
  if (TABLE_ENSURED.done) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS org_ai_budgets (
      org_id VARCHAR PRIMARY KEY,
      budget_usd DOUBLE PRECISION NOT NULL DEFAULT 50,
      invocation_cap INTEGER NOT NULL DEFAULT 5000,
      daily_spend_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
      daily_invocations INTEGER NOT NULL DEFAULT 0,
      daily_input_tokens INTEGER NOT NULL DEFAULT 0,
      daily_output_tokens INTEGER NOT NULL DEFAULT 0,
      last_reset_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_org_ai_budgets_org_id ON org_ai_budgets (org_id)
  `);
  TABLE_ENSURED.done = true;
}

async function ensureOrgRow(orgId: string): Promise<void> {
  await ensureTable();
  await pool.query(
    `INSERT INTO org_ai_budgets (org_id, budget_usd, invocation_cap, daily_spend_usd, daily_invocations, daily_input_tokens, daily_output_tokens, last_reset_at, updated_at)
     VALUES ($1, $2, $3, 0, 0, 0, 0, NOW(), NOW())
     ON CONFLICT (org_id) DO NOTHING`,
    [orgId, DEFAULT_DAILY_BUDGET_USD, DEFAULT_DAILY_INVOCATION_CAP],
  );
}

async function getRow(orgId: string): Promise<BudgetRow> {
  await ensureOrgRow(orgId);
  const result = await pool.query(`SELECT * FROM org_ai_budgets WHERE org_id = $1`, [orgId]);
  return result.rows[0] as BudgetRow;
}

export async function setOrgBudget(orgId: string, budgetUsd: number, invocationCap: number): Promise<void> {
  await ensureOrgRow(orgId);
  await pool.query(
    `UPDATE org_ai_budgets
     SET budget_usd = $2, invocation_cap = $3, updated_at = NOW()
     WHERE org_id = $1`,
    [orgId, budgetUsd, invocationCap],
  );
  log.info("Org AI budget updated", { orgId, budgetUsd, invocationCap });
}

export async function checkBudget(orgId: string): Promise<{ allowed: boolean; reason?: string }> {
  const row = await getRow(orgId);

  if (row.daily_spend_usd >= row.budget_usd) {
    log.warn("AI budget exceeded", { orgId, spent: row.daily_spend_usd, limit: row.budget_usd });
    return {
      allowed: false,
      reason: `Daily AI spend limit of $${row.budget_usd.toFixed(2)} reached ($${row.daily_spend_usd.toFixed(4)} used)`,
    };
  }

  if (row.daily_invocations >= row.invocation_cap) {
    log.warn("AI invocation cap reached", { orgId, count: row.daily_invocations, cap: row.invocation_cap });
    return {
      allowed: false,
      reason: `Daily invocation cap of ${row.invocation_cap} reached (${row.daily_invocations} used)`,
    };
  }

  return { allowed: true };
}

export async function trackUsage(orgId: string, record: UsageRecord): Promise<void> {
  await ensureOrgRow(orgId);

  const result = await pool.query(
    `UPDATE org_ai_budgets
     SET daily_spend_usd = daily_spend_usd + $2,
         daily_invocations = daily_invocations + 1,
         daily_input_tokens = daily_input_tokens + $3,
         daily_output_tokens = daily_output_tokens + $4,
         updated_at = NOW()
     WHERE org_id = $1
     RETURNING daily_spend_usd, budget_usd`,
    [orgId, record.costUsd, record.inputTokens, record.outputTokens],
  );

  if (result.rows.length > 0) {
    const updated = result.rows[0] as { daily_spend_usd: number; budget_usd: number };
    const usagePercent = (updated.daily_spend_usd / updated.budget_usd) * 100;
    if (usagePercent >= 80 && usagePercent < 100) {
      log.warn("AI budget at 80%+", {
        orgId,
        spent: updated.daily_spend_usd,
        limit: updated.budget_usd,
        percent: Math.round(usagePercent),
      });
    }
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

function rowToSummary(row: BudgetRow): OrgUsageSummary {
  const budgetUsd = row.budget_usd;
  const invocationCap = row.invocation_cap;
  const windowStart = row.last_reset_at ? new Date(row.last_reset_at).toISOString() : new Date().toISOString();

  return {
    orgId: row.org_id,
    windowStart,
    totalCostUsd: Math.round(row.daily_spend_usd * 1000000) / 1000000,
    totalInputTokens: row.daily_input_tokens,
    totalOutputTokens: row.daily_output_tokens,
    invocationCount: row.daily_invocations,
    budgetLimitUsd: budgetUsd,
    invocationCap,
    budgetUsedPercent: budgetUsd > 0 ? Math.round((row.daily_spend_usd / budgetUsd) * 10000) / 100 : 0,
    invocationUsedPercent: invocationCap > 0 ? Math.round((row.daily_invocations / invocationCap) * 10000) / 100 : 0,
    recentRecords: [],
    byModel: {},
    byPrompt: {},
  };
}

export async function getOrgUsageSummary(orgId: string): Promise<OrgUsageSummary> {
  const row = await getRow(orgId);
  return rowToSummary(row);
}

export async function getAllOrgUsageSummaries(): Promise<OrgUsageSummary[]> {
  await ensureTable();
  const result = await pool.query(`SELECT * FROM org_ai_budgets ORDER BY org_id`);
  return (result.rows as BudgetRow[]).map(rowToSummary);
}

export async function resetDailyBudgets(): Promise<number> {
  await ensureTable();
  const result = await pool.query(
    `UPDATE org_ai_budgets
     SET daily_spend_usd = 0,
         daily_invocations = 0,
         daily_input_tokens = 0,
         daily_output_tokens = 0,
         last_reset_at = NOW(),
         updated_at = NOW()
     WHERE daily_spend_usd > 0 OR daily_invocations > 0`,
  );

  const count = result.rowCount ?? 0;
  if (count > 0) {
    log.info("Daily AI budgets reset", { orgsReset: count });
  }
  return count;
}

let resetTimer: ReturnType<typeof setTimeout> | null = null;

function msUntilMidnightUTC(): number {
  const now = new Date();
  const tomorrow = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0));
  return tomorrow.getTime() - now.getTime();
}

export function startBudgetResetScheduler(): void {
  if (resetTimer) return;

  function scheduleNext(): void {
    const delayMs = msUntilMidnightUTC();
    log.info("Next AI budget reset scheduled", { delayMs, resetAt: new Date(Date.now() + delayMs).toISOString() });

    resetTimer = setTimeout(() => {
      resetDailyBudgets()
        .then((count) => {
          log.info("Scheduled daily budget reset completed", { orgsReset: count });
        })
        .catch((err) => {
          log.error("Scheduled daily budget reset failed", { error: String(err) });
        })
        .finally(() => {
          resetTimer = null;
          scheduleNext();
        });
    }, delayMs);
  }

  scheduleNext();
}

export function stopBudgetResetScheduler(): void {
  if (resetTimer) {
    clearTimeout(resetTimer);
    resetTimer = null;
    log.info("AI budget reset scheduler stopped");
  }
}
