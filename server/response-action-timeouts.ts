import { sql } from "drizzle-orm";
import { db } from "./db";
import { logger } from "./logger";
import { registerShutdownHandler } from "./scaling-state";

const log = logger.child("response-action-timeouts");
const TIMEOUT_SWEEP_INTERVAL_MS = 30_000;

interface TimedOutResponseActionRow {
  id: string;
  org_id: string;
  status: string;
  result_error: string;
}

export interface TimedOutResponseAction {
  id: string;
  orgId: string;
  status: string;
  resultError: string;
}

/**
 * Expire approved actions that were never picked up and executing actions
 * that never received an agent result. The conditional update makes this
 * safe when multiple application instances run the sweep concurrently.
 */
export async function expireTimedOutResponseActions(orgId?: string): Promise<TimedOutResponseAction[]> {
  const organizationClause = orgId ? sql`AND org_id = ${orgId}` : sql``;
  const result = await db.execute(sql`
    UPDATE agent_response_actions
    SET status = 'timed_out',
        completed_at = NOW(),
        result_error = CASE
          WHEN status = 'approved' THEN
            'Timed out waiting for sensor pickup after ' || timeout_seconds || ' seconds'
          ELSE
            'Timed out waiting for sensor result after ' || timeout_seconds || ' seconds'
        END,
        updated_at = NOW()
    WHERE status IN ('approved', 'executing')
      ${organizationClause}
      AND (
        (
          status = 'approved'
          AND COALESCE(approved_at, created_at) + (timeout_seconds * INTERVAL '1 second') <= NOW()
        )
        OR (
          status = 'executing'
          AND dispatched_at IS NOT NULL
          AND dispatched_at + (timeout_seconds * INTERVAL '1 second') <= NOW()
        )
      )
    RETURNING id, org_id, status, result_error
  `);

  const rows = (result as unknown as { rows?: TimedOutResponseActionRow[] }).rows || [];
  return rows.map((row) => ({
    id: row.id,
    orgId: row.org_id,
    status: row.status,
    resultError: row.result_error,
  }));
}

let timeoutTimer: ReturnType<typeof setInterval> | null = null;

export function startResponseActionTimeoutScheduler(): void {
  if (timeoutTimer) return;

  const sweep = () => {
    expireTimedOutResponseActions().catch((error) => {
      log.error("Response action timeout sweep failed", { error: String(error) });
    });
  };

  sweep();
  timeoutTimer = setInterval(sweep, TIMEOUT_SWEEP_INTERVAL_MS);
  registerShutdownHandler("response-action-timeouts", () => {
    if (timeoutTimer) {
      clearInterval(timeoutTimer);
      timeoutTimer = null;
    }
  });
  log.info("Response action timeout scheduler started", { intervalMs: TIMEOUT_SWEEP_INTERVAL_MS });
}

export function stopResponseActionTimeoutScheduler(): void {
  if (!timeoutTimer) return;
  clearInterval(timeoutTimer);
  timeoutTimer = null;
}
