import { and, asc, eq, sql } from "drizzle-orm";
import { huntResults, huntSchedules, threatHunts } from "@shared/schema";
import { db } from "./db";
import { executeHunt, type HuntExecutionResult } from "./hunt-engine";
import { logger } from "./logger";
import { registerShutdownHandler } from "./scaling-state";

const SCHEDULER_INTERVAL_MS = 60 * 1000;
const MAX_SCHEDULES_PER_PASS = 100;
const log = logger.child("hunt-scheduler");

type HuntSchedule = typeof huntSchedules.$inferSelect;
type Hunt = typeof threatHunts.$inferSelect;

export function computeNextHuntRun(cadence: string, hourUtc: number, dayOfWeek: number | null, now = new Date()): Date {
  const next = new Date(now);
  next.setUTCHours(hourUtc, 0, 0, 0);

  switch (cadence) {
    case "daily":
      if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
      break;
    case "weekly": {
      const diff = dayOfWeek === null ? 7 : (dayOfWeek - now.getUTCDay() + 7) % 7;
      next.setUTCDate(next.getUTCDate() + (diff === 0 && next <= now ? 7 : diff));
      break;
    }
    case "biweekly":
      next.setUTCDate(next.getUTCDate() + 14);
      break;
    case "monthly":
      next.setUTCMonth(next.getUTCMonth() + 1);
      break;
    default:
      next.setUTCDate(next.getUTCDate() + 1);
      break;
  }

  return next;
}

export async function claimDueHuntSchedule(id: string, orgId: string, now = new Date()): Promise<HuntSchedule | null> {
  const [candidate] = await db
    .select()
    .from(huntSchedules)
    .where(and(eq(huntSchedules.id, id), eq(huntSchedules.orgId, orgId)));
  if (!candidate) return null;
  const nextRunAt = computeNextHuntRun(candidate.cadence, candidate.hourUtc, candidate.dayOfWeek, now);

  const [claimed] = await db
    .update(huntSchedules)
    .set({ nextRunAt })
    .where(
      and(
        eq(huntSchedules.id, id),
        eq(huntSchedules.orgId, orgId),
        eq(huntSchedules.enabled, true),
        sql`${huntSchedules.nextRunAt} IS NOT NULL AND ${huntSchedules.nextRunAt} <= ${now}`,
      ),
    )
    .returning();

  if (!claimed) return null;
  return claimed;
}

function failedExecution(error: unknown): HuntExecutionResult {
  const reason = error instanceof Error ? error.message : String(error);
  return {
    status: "failed",
    eventCount: 0,
    events: [],
    executionDurationMs: 0,
    targetTable: "alerts",
    explanation: "Hunt execution failed.",
    reason,
  };
}

function rejectedHuntExecution(hunt: Hunt): HuntExecutionResult {
  let reason = "This hunt is not executable.";
  if (hunt.queryType === "custom") {
    reason = 'Query type "custom" is not executable.';
  } else if (hunt.compiledQuery) {
    try {
      const compiled = JSON.parse(hunt.compiledQuery) as {
        rejectionReason?: unknown;
        reason?: unknown;
        explanation?: unknown;
      };
      if (typeof compiled.rejectionReason === "string") reason = compiled.rejectionReason;
      else if (typeof compiled.reason === "string") reason = compiled.reason;
      else if (typeof compiled.explanation === "string") reason = compiled.explanation;
    } catch {
      // Preserve the rejected hunt when an older compiled payload is malformed.
    }
  }
  return {
    status: "rejected",
    eventCount: 0,
    events: [],
    executionDurationMs: 0,
    targetTable: "alerts",
    explanation: reason,
    reason,
  };
}

export async function persistHuntExecution(
  hunt: Hunt,
  orgId: string,
  result: HuntExecutionResult,
  executedBy: string | null = null,
): Promise<typeof huntResults.$inferSelect | null> {
  const now = new Date();
  if (result.status !== "completed") {
    await db
      .update(threatHunts)
      .set({
        status: result.status,
        lastRunAt: now,
        lastRunDurationMs: result.executionDurationMs,
        lastRunEventCount: null,
        updatedAt: now,
      })
      .where(and(eq(threatHunts.id, hunt.id), eq(threatHunts.orgId, orgId)));
    return null;
  }

  const [savedResult] = await db
    .insert(huntResults)
    .values({
      orgId,
      huntId: hunt.id,
      eventCount: result.eventCount,
      eventsJson: result.events,
      executionDurationMs: result.executionDurationMs,
      executedBy,
    })
    .returning();

  await db
    .update(threatHunts)
    .set({
      status: "completed",
      lastRunAt: now,
      lastRunDurationMs: result.executionDurationMs,
      lastRunEventCount: result.eventCount,
      updatedAt: now,
    })
    .where(and(eq(threatHunts.id, hunt.id), eq(threatHunts.orgId, orgId)));

  return savedResult;
}

export async function runClaimedHuntSchedule(
  schedule: HuntSchedule,
  executor: typeof executeHunt = executeHunt,
): Promise<HuntExecutionResult | null> {
  const [hunt] = await db
    .select()
    .from(threatHunts)
    .where(and(eq(threatHunts.id, schedule.huntId), eq(threatHunts.orgId, schedule.orgId)));

  if (!hunt) {
    log.warn("Scheduled hunt not found for claimed schedule", { scheduleId: schedule.id, orgId: schedule.orgId });
    await db
      .update(huntSchedules)
      .set({ lastRunAt: new Date() })
      .where(and(eq(huntSchedules.id, schedule.id), eq(huntSchedules.orgId, schedule.orgId)));
    return null;
  }

  let result: HuntExecutionResult;
  if (hunt.status === "rejected" || hunt.queryType === "custom") {
    result = rejectedHuntExecution(hunt);
  } else {
    try {
      result = await executor(hunt.queryType, hunt.queryText, schedule.orgId, 100);
    } catch (error) {
      result = failedExecution(error);
    }
  }

  await persistHuntExecution(hunt, schedule.orgId, result);
  await db
    .update(huntSchedules)
    .set({ lastRunAt: new Date() })
    .where(and(eq(huntSchedules.id, schedule.id), eq(huntSchedules.orgId, schedule.orgId)));

  return result;
}

export async function runDueHuntSchedules(now = new Date()): Promise<number> {
  const due = await db
    .select()
    .from(huntSchedules)
    .where(
      and(
        eq(huntSchedules.enabled, true),
        sql`${huntSchedules.nextRunAt} IS NOT NULL AND ${huntSchedules.nextRunAt} <= ${now}`,
      ),
    )
    .orderBy(asc(huntSchedules.nextRunAt))
    .limit(MAX_SCHEDULES_PER_PASS);

  let claimedCount = 0;
  for (const candidate of due) {
    const claimed = await claimDueHuntSchedule(candidate.id, candidate.orgId, now);
    if (!claimed) continue;
    claimedCount += 1;
    await runClaimedHuntSchedule(claimed);
  }
  return claimedCount;
}

let schedulerTimer: ReturnType<typeof setInterval> | null = null;
let startupTimer: ReturnType<typeof setTimeout> | null = null;

export function startHuntScheduler(): void {
  if (schedulerTimer) return;
  startupTimer = setTimeout(() => {
    startupTimer = null;
    runDueHuntSchedules().catch((error) => log.error("Initial hunt schedule pass failed", { error: String(error) }));
  }, 10_000);
  schedulerTimer = setInterval(() => {
    runDueHuntSchedules().catch((error) => log.error("Hunt schedule pass failed", { error: String(error) }));
  }, SCHEDULER_INTERVAL_MS);
  registerShutdownHandler("hunt-scheduler", () => {
    if (startupTimer) clearTimeout(startupTimer);
    if (schedulerTimer) clearInterval(schedulerTimer);
    startupTimer = null;
    schedulerTimer = null;
  });
  log.info("Hunt scheduler started", { intervalMs: SCHEDULER_INTERVAL_MS });
}
