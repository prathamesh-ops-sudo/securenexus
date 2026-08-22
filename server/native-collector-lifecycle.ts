import { and, isNull, lt, sql } from "drizzle-orm";
import { db } from "./db";
import { collectorInstances } from "../shared/schema";
import { logger } from "./logger";
import { registerShutdownHandler } from "./scaling-state";

const log = logger.child("native-collector-lifecycle");
const DEGRADED_AFTER_MS = 90_000;
const OFFLINE_AFTER_MS = 300_000;
const SWEEP_INTERVAL_MS = 60_000;

export const COLLECTOR_LIFECYCLE_STATES = [
  "never-enrolled",
  "enrolled-but-never-heartbeated",
  "online-but-zero-telemetry",
  "receiving-telemetry",
  "degraded",
  "offline",
  "revoked",
] as const;

export type CollectorLifecycleState = (typeof COLLECTOR_LIFECYCLE_STATES)[number];

export function getCollectorLifecycleState(collector: {
  revokedAt: Date | null;
  lastHeartbeatAt: Date | null;
  lastDataAt: Date | null;
  createdAt: Date | null;
}): CollectorLifecycleState {
  if (collector.revokedAt) return "revoked";
  if (!collector.lastHeartbeatAt) return "enrolled-but-never-heartbeated";

  const heartbeatAge = Date.now() - collector.lastHeartbeatAt.getTime();
  if (heartbeatAge >= OFFLINE_AFTER_MS) return "offline";
  if (heartbeatAge >= DEGRADED_AFTER_MS) return "degraded";
  if (!collector.lastDataAt) return "online-but-zero-telemetry";
  return "receiving-telemetry";
}

async function sweepCollectorLifecycle(): Promise<void> {
  const degradedCutoff = new Date(Date.now() - DEGRADED_AFTER_MS);
  const offlineCutoff = new Date(Date.now() - OFFLINE_AFTER_MS);
  await db
    .update(collectorInstances)
    .set({ lifecycleState: "offline", status: "offline", updatedAt: new Date() })
    .where(
      and(
        isNull(collectorInstances.revokedAt),
        lt(collectorInstances.lastHeartbeatAt, offlineCutoff),
        sql`${collectorInstances.lastHeartbeatAt} IS NOT NULL`,
      ),
    );
  await db
    .update(collectorInstances)
    .set({ lifecycleState: "degraded", status: "degraded", updatedAt: new Date() })
    .where(
      and(
        isNull(collectorInstances.revokedAt),
        lt(collectorInstances.lastHeartbeatAt, degradedCutoff),
        sql`${collectorInstances.lastHeartbeatAt} IS NOT NULL`,
        sql`${collectorInstances.lastHeartbeatAt} >= ${offlineCutoff}`,
      ),
    );
}

let timer: ReturnType<typeof setInterval> | null = null;

export function startNativeCollectorLifecycleScheduler(): void {
  if (timer) return;
  const sweep = (): void => {
    sweepCollectorLifecycle().catch((error: unknown) => {
      log.error("Native collector lifecycle sweep failed", { error: String(error) });
    });
  };
  sweep();
  timer = setInterval(sweep, SWEEP_INTERVAL_MS);
  registerShutdownHandler("native-collector-lifecycle", stopNativeCollectorLifecycleScheduler);
  log.info("Native collector lifecycle scheduler started", { intervalMs: SWEEP_INTERVAL_MS });
}

export function stopNativeCollectorLifecycleScheduler(): void {
  if (!timer) return;
  clearInterval(timer);
  timer = null;
}
