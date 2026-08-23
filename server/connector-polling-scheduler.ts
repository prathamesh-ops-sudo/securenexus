import type { Connector } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import { db } from "./db";
import { logger } from "./logger";
import { enqueueJob } from "./job-queue";
import { registerShutdownHandler } from "./scaling-state";
import { checkQuota, consumeQuota } from "./middleware/plan-enforcement";
import { getQuotaExhaustedScheduleUpdate, MIN_CONNECTOR_INTERVAL_MIN } from "./connector-schedule";
import { connectors } from "@shared/schema";

const log = logger.child("connector-polling-scheduler");
export const CONNECTOR_SCHEDULER_INTERVAL_MS = 60_000;
const TICK_ADVISORY_LOCK = 741932;
const MAX_CONNECTORS_PER_TICK = 100;

export interface ConnectorPollingDependencies {
  claimDueConnectors: () => Promise<Connector[]>;
  enqueue: (connector: Connector) => Promise<unknown>;
  checkQuota: (orgId: string) => Promise<{ allowed: boolean }>;
  consumeQuota: (orgId: string) => Promise<void>;
  markQuotaExhausted: (connector: Connector) => Promise<void>;
}

export async function claimDueConnectors(): Promise<Connector[]> {
  return db.transaction(async (tx) => {
    const lockResult = await tx.execute(sql`SELECT pg_try_advisory_xact_lock(${TICK_ADVISORY_LOCK}) AS locked`);
    const locked = Boolean((lockResult.rows as Array<{ locked: boolean }>)[0]?.locked);
    if (!locked) return [];

    const result = await tx.execute(sql`
      UPDATE connectors
      SET next_sync_at = NOW() + (GREATEST(5, LEAST(1440, effective_polling_interval_min)) * INTERVAL '1 minute'),
          effective_polling_interval_min = GREATEST(5, LEAST(1440, effective_polling_interval_min)),
          schedule_reason = 'queued',
          updated_at = NOW()
      WHERE id IN (
        SELECT id
        FROM connectors
        WHERE auto_sync_enabled = true
          AND needs_reconnection = false
          AND status = 'active'
          AND next_sync_at IS NOT NULL
          AND next_sync_at <= NOW()
        ORDER BY next_sync_at ASC
        LIMIT ${MAX_CONNECTORS_PER_TICK}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING *
    `);
    return ((result.rows as Array<Record<string, unknown>>) ?? []).map((row) => ({
      id: String(row.id),
      orgId: row.org_id ? String(row.org_id) : null,
      name: String(row.name),
      type: String(row.type),
      authType: String(row.auth_type),
      config: row.config,
      status: String(row.status),
      pollingIntervalMin: row.polling_interval_min as number | null,
      autoSyncEnabled: Boolean(row.auto_sync_enabled),
      autoSyncPausedByAuth: Boolean(row.auto_sync_paused_by_auth),
      effectivePollingIntervalMin: Number(row.effective_polling_interval_min),
      nextSyncAt: row.next_sync_at as Date | null,
      consecutiveFailures: Number(row.consecutive_failures),
      scheduleReason: String(row.schedule_reason),
      needsReconnection: Boolean(row.needs_reconnection),
      lastSyncAt: row.last_sync_at as Date | null,
      lastSyncStatus: row.last_sync_status as string | null,
      lastSyncAlerts: row.last_sync_alerts as number | null,
      lastSyncError: row.last_sync_error as string | null,
      totalAlertsSynced: row.total_alerts_synced as number | null,
      createdBy: row.created_by as string | null,
      createdAt: row.created_at as Date | null,
      updatedAt: row.updated_at as Date | null,
    })) as Connector[];
  });
}

async function markQuotaExhausted(connector: Connector): Promise<void> {
  await db
    .update(connectors)
    .set({
      ...getQuotaExhaustedScheduleUpdate(connector),
      updatedAt: new Date(),
    })
    .where(eq(connectors.id, connector.id));
}

const defaultDependencies: ConnectorPollingDependencies = {
  claimDueConnectors,
  enqueue: async (connector) => enqueueJob("connector_sync", connector.orgId as string, { connectorId: connector.id }),
  checkQuota: async (orgId) => checkQuota(orgId, "connector_syncs"),
  consumeQuota: async (orgId) => {
    await consumeQuota(orgId, "connector_syncs");
  },
  markQuotaExhausted,
};

export async function runConnectorPollingTick(
  dependencies: ConnectorPollingDependencies = defaultDependencies,
): Promise<number> {
  const dueConnectors = await dependencies.claimDueConnectors();
  let enqueued = 0;

  for (const connector of dueConnectors) {
    if (!connector.orgId) {
      log.warn("Skipping connector without organization", { connectorId: connector.id });
      continue;
    }
    if (!connector.autoSyncEnabled || connector.needsReconnection || connector.status !== "active") {
      log.debug("Skipping connector that is not eligible for automatic sync", {
        connectorId: connector.id,
        status: connector.status,
        autoSyncEnabled: connector.autoSyncEnabled,
        needsReconnection: connector.needsReconnection,
      });
      continue;
    }

    const quota = await dependencies.checkQuota(connector.orgId);
    if (!quota.allowed) {
      await dependencies.markQuotaExhausted(connector);
      log.warn("Scheduled connector sync skipped because plan quota is exhausted", {
        connectorId: connector.id,
        orgId: connector.orgId,
      });
      continue;
    }

    try {
      const job = await dependencies.enqueue(connector);
      if (job !== null) {
        enqueued++;
        try {
          await dependencies.consumeQuota(connector.orgId);
        } catch (error: unknown) {
          log.error("Scheduled connector sync was enqueued but quota metering failed", {
            connectorId: connector.id,
            orgId: connector.orgId,
            error: String(error),
          });
        }
      }
    } catch (error: unknown) {
      await db
        .update(connectors)
        .set({
          nextSyncAt: new Date(Date.now() + MIN_CONNECTOR_INTERVAL_MIN * 60_000),
          scheduleReason: "enqueue_failed",
          updatedAt: new Date(),
        })
        .where(eq(connectors.id, connector.id));
      log.error("Failed to enqueue scheduled connector sync", {
        connectorId: connector.id,
        orgId: connector.orgId,
        error: String(error),
      });
    }
  }

  if (dueConnectors.length > 0) {
    log.info("Connector polling tick completed", {
      due: dueConnectors.length,
      enqueued,
    });
  }
  return enqueued;
}

let timer: ReturnType<typeof setInterval> | null = null;

export function stopConnectorPollingScheduler(): void {
  if (!timer) return;
  clearInterval(timer);
  timer = null;
  log.info("Connector polling scheduler stopped");
}

export function startConnectorPollingScheduler(): void {
  if (timer) return;
  const run = (): void => {
    runConnectorPollingTick().catch((error: unknown) =>
      log.error("Connector polling tick failed", { error: String(error) }),
    );
  };
  run();
  timer = setInterval(run, CONNECTOR_SCHEDULER_INTERVAL_MS);
  registerShutdownHandler("connector-polling-scheduler", stopConnectorPollingScheduler);
  log.info("Connector polling scheduler started", { intervalMs: CONNECTOR_SCHEDULER_INTERVAL_MS });
}
