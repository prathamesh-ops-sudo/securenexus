import { and, eq } from "drizzle-orm";
import { aiAnalystDecisions, aiReplayRuns } from "@shared/schema";
import { db, pool } from "../db";
import { storage } from "../storage";
import { buildThreatIntelContext, triageAlert } from "../ai";
import { createDecisionReceipt, finalizeDecisionReceipt, persistDecisionEvidence } from "./decision-receipts";
import { finalizeDecisionIntegrity } from "./decision-integrity";
import { logger } from "../logger";
import { generateSocRealityReport } from "./soc-reality-report";
import { deriveDecisionOutcome } from "./decision-outcome";

const log = logger.child("historical-replay");
const BATCH_SIZE = 20;
const MAX_CONSECUTIVE_FAILURES = 3;

export function buildReplayDecisionFields(
  result: {
    escalationRequired: boolean;
    falsePositiveLikelihood: number;
    confidence?: number | null;
  },
  timeToDecisionMs: number,
): {
  outcome: ReturnType<typeof deriveDecisionOutcome>;
  confidenceScore: number | null;
  timeToDecisionMs: number;
} {
  return {
    outcome: deriveDecisionOutcome(result),
    confidenceScore: result.confidence ?? null,
    timeToDecisionMs,
  };
}

export function buildReplaySelection(run: {
  orgId: string;
  fromAt: Date;
  toAt: Date;
  source: string | null;
  severity: string | null;
}): { where: string; values: unknown[] } {
  const values: unknown[] = [run.orgId, run.fromAt, run.toAt];
  const filters = ["org_id = $1", "detected_at >= $2", "detected_at < $3"];
  if (run.source) {
    values.push(run.source);
    filters.push(`source = $${values.length}`);
  }
  if (run.severity) {
    values.push(run.severity);
    filters.push(`severity = $${values.length}`);
  }
  return { where: filters.join(" AND "), values };
}

async function updateRun(runId: string, values: Record<string, unknown>): Promise<void> {
  const assignments = Object.keys(values).map((key, index) => `"${key}" = $${index + 2}`);
  await pool.query(`UPDATE ai_replay_runs SET ${assignments.join(", ")}, updated_at = NOW() WHERE id = $1`, [
    runId,
    ...Object.values(values),
  ]);
}

async function persistSocRealityReport(runId: string): Promise<void> {
  try {
    const [run] = await db.select().from(aiReplayRuns).where(eq(aiReplayRuns.id, runId)).limit(1);
    if (!run) return;
    const report = await generateSocRealityReport(run.orgId, run);
    await updateRun(runId, { report });
  } catch (error) {
    log.warn("Failed to persist SOC Reality Report", { runId, error: String(error) });
  }
}

async function runOneAlert(run: typeof aiReplayRuns.$inferSelect, alertId: string): Promise<"succeeded" | "failed"> {
  const startedAt = Date.now();
  const alert = await storage.getAlert(alertId);
  if (!alert || alert.orgId !== run.orgId) return "failed";

  const [existingDecision] = await db
    .select({ status: aiAnalystDecisions.status })
    .from(aiAnalystDecisions)
    .where(
      and(
        eq(aiAnalystDecisions.orgId, run.orgId),
        eq(aiAnalystDecisions.alertId, alert.id),
        eq(aiAnalystDecisions.replayRunId, run.id),
      ),
    )
    .limit(1);
  if (existingDecision) return existingDecision.status === "completed" ? "succeeded" : "failed";

  let decisionId: string | undefined;
  try {
    decisionId = await createDecisionReceipt({
      orgId: run.orgId,
      alertId: alert.id,
      incidentId: alert.incidentId,
      tier: "tier3_assisted",
      autonomyMode: "observe_only",
      replayRunId: run.id,
    });
    const threatIntelContext = await buildThreatIntelContext([alert]);
    const result = await triageAlert(alert, threatIntelContext, run.orgId, decisionId);
    await finalizeDecisionReceipt(run.orgId, decisionId, {
      ...buildReplayDecisionFields(result, Date.now() - startedAt),
      status: "completed",
      reasoning: result.reasoning,
      executiveSummary: result.recommendedAction,
      autonomyMode: "observe_only",
      replayRunId: run.id,
      retrievalStatus: result.retrievalStatus ?? (result.retrievalUnavailable ? "unavailable" : "empty"),
    });
    await persistDecisionEvidence(run.orgId, decisionId, alert, null);
    await finalizeDecisionIntegrity(run.orgId, decisionId);
    return "succeeded";
  } catch (error) {
    if (decisionId) {
      await finalizeDecisionReceipt(run.orgId, decisionId, {
        outcome: null,
        confidenceScore: null,
        timeToDecisionMs: Date.now() - startedAt,
        status: "failed",
        autonomyMode: "observe_only",
        replayRunId: run.id,
        reasoning: error instanceof Error ? error.message : String(error),
        retrievalStatus: "unavailable",
      }).catch((finalizationError) =>
        log.warn("Failed to finalize replay decision", { runId: run.id, decisionId, error: String(finalizationError) }),
      );
      await finalizeDecisionIntegrity(run.orgId, decisionId).catch((integrityError) =>
        log.warn("Failed to finalize replay decision integrity", {
          runId: run.id,
          decisionId,
          error: String(integrityError),
        }),
      );
    }
    log.warn("Historical replay alert failed", { runId: run.id, alertId, error: String(error) });
    return "failed";
  }
}

async function processHistoricalReplayLocked(runId: string): Promise<Record<string, unknown>> {
  if (!runId) return { error: "Replay run ID is required" };
  const [run] = await db.select().from(aiReplayRuns).where(eq(aiReplayRuns.id, runId)).limit(1);
  if (!run) return { error: "Replay run not found", runId };
  if (run.status === "completed" || run.status === "failed" || run.status === "cancelled") {
    return { runId, status: run.status, processedCount: run.processedCount };
  }

  await updateRun(runId, { status: "running", started_at: run.startedAt ?? new Date() });
  const { where, values } = buildReplaySelection(run);
  const totalResult = await pool.query<{ count: string }>(
    `SELECT COUNT(*)::text AS count FROM alerts WHERE ${where}`,
    values,
  );
  const totalCount = Number(totalResult.rows[0]?.count ?? 0);
  await updateRun(runId, { total_count: totalCount });

  const alertResult = await pool.query<{ id: string }>(
    `SELECT id FROM alerts WHERE ${where} ORDER BY detected_at ASC, id ASC LIMIT ${BATCH_SIZE} OFFSET $${values.length + 1}`,
    [...values, run.cursor],
  );
  if (alertResult.rows.length === 0) {
    await updateRun(runId, {
      status: "completed",
      total_count: totalCount,
      completed_at: new Date(),
    });
    await persistSocRealityReport(runId);
    return { runId, status: "completed", processedCount: run.processedCount, totalCount };
  }

  const concurrency = Math.max(1, Math.min(run.concurrency, alertResult.rows.length));
  const outcomes: Array<"succeeded" | "failed"> = [];
  for (let i = 0; i < alertResult.rows.length; i += concurrency) {
    const chunk = alertResult.rows.slice(i, i + concurrency);
    outcomes.push(...(await Promise.all(chunk.map(({ id }) => runOneAlert(run, id)))));
  }
  const succeeded = outcomes.filter((outcome) => outcome === "succeeded").length;
  const failed = outcomes.length - succeeded;
  const consecutiveFailures = failed > 0 ? run.consecutiveFailures + failed : 0;
  const processedCount = run.processedCount + outcomes.length;
  const nextCursor = run.cursor + outcomes.length;
  const terminalFailure = consecutiveFailures >= MAX_CONSECUTIVE_FAILURES;
  await updateRun(runId, {
    status: terminalFailure ? "failed" : "pending",
    cursor: nextCursor,
    processed_count: processedCount,
    succeeded_count: run.succeededCount + succeeded,
    failed_count: run.failedCount + failed,
    consecutive_failures: consecutiveFailures,
    ...(terminalFailure
      ? {
          error: `Replay stopped after ${MAX_CONSECUTIVE_FAILURES} consecutive model failures`,
          completed_at: new Date(),
        }
      : {}),
  });
  if (terminalFailure) await persistSocRealityReport(runId);
  return {
    runId,
    status: terminalFailure ? "failed" : "pending",
    processedCount,
    succeededCount: run.succeededCount + succeeded,
    failedCount: run.failedCount + failed,
    totalCount,
  };
}

export async function processHistoricalReplay(runId: string): Promise<Record<string, unknown>> {
  const lockClient = await pool.connect();
  try {
    const lockResult = await lockClient.query<{ acquired: boolean }>(
      "SELECT pg_try_advisory_lock(hashtext($1)) AS acquired",
      [runId],
    );
    if (!lockResult.rows[0]?.acquired) {
      return { runId, status: "pending", skipped: "already_running" };
    }
    return await processHistoricalReplayLocked(runId);
  } finally {
    await lockClient.query("SELECT pg_advisory_unlock(hashtext($1))", [runId]).catch((error) => {
      log.warn("Failed to release historical replay lock", { runId, error: String(error) });
    });
    lockClient.release();
  }
}
