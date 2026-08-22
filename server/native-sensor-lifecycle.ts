import { and, isNull, lt, sql } from "drizzle-orm";
import { db } from "./db";
import { nativeSensors } from "../shared/schema";
import { logger } from "./logger";
import { registerShutdownHandler } from "./scaling-state";

const log = logger.child("native-sensor-lifecycle");
const DEGRADED_AFTER_MS = 90_000;
const OFFLINE_AFTER_MS = 300_000;
const SWEEP_INTERVAL_MS = 60_000;

export const SENSOR_LIFECYCLE_STATES = [
  "never-enrolled",
  "enrolled-but-never-heartbeated",
  "online-but-zero-telemetry",
  "receiving-telemetry",
  "degraded",
  "offline",
  "revoked",
] as const;

export type SensorLifecycleState = (typeof SENSOR_LIFECYCLE_STATES)[number];

export function getSensorLifecycleState(sensor: {
  revokedAt: Date | null;
  lastHeartbeat: Date | null;
  lastTelemetryAt: Date | null;
  createdAt: Date | null;
}): SensorLifecycleState {
  if (sensor.revokedAt) return "revoked";
  if (!sensor.lastHeartbeat) return "enrolled-but-never-heartbeated";

  const now = Date.now();
  const heartbeatAge = now - sensor.lastHeartbeat.getTime();
  if (heartbeatAge >= OFFLINE_AFTER_MS) return "offline";
  if (heartbeatAge >= DEGRADED_AFTER_MS) return "degraded";
  if (!sensor.lastTelemetryAt) return "online-but-zero-telemetry";
  return "receiving-telemetry";
}

async function sweepNativeSensorLifecycle(): Promise<void> {
  const degradedCutoff = new Date(Date.now() - DEGRADED_AFTER_MS);
  const offlineCutoff = new Date(Date.now() - OFFLINE_AFTER_MS);

  await db
    .update(nativeSensors)
    .set({ status: "offline", updatedAt: new Date() })
    .where(
      and(
        isNull(nativeSensors.revokedAt),
        lt(nativeSensors.lastHeartbeat, offlineCutoff),
        sql`${nativeSensors.lastHeartbeat} IS NOT NULL`,
      ),
    );

  await db
    .update(nativeSensors)
    .set({ status: "degraded", updatedAt: new Date() })
    .where(
      and(
        isNull(nativeSensors.revokedAt),
        lt(nativeSensors.lastHeartbeat, degradedCutoff),
        sql`${nativeSensors.lastHeartbeat} IS NOT NULL`,
        sql`${nativeSensors.lastHeartbeat} >= ${offlineCutoff}`,
      ),
    );
}

let timer: ReturnType<typeof setInterval> | null = null;

export function startNativeSensorLifecycleScheduler(): void {
  if (timer) return;

  const sweep = (): void => {
    sweepNativeSensorLifecycle().catch((error: unknown) => {
      log.error("Native sensor lifecycle sweep failed", { error: String(error) });
    });
  };

  sweep();
  timer = setInterval(sweep, SWEEP_INTERVAL_MS);
  registerShutdownHandler("native-sensor-lifecycle", stopNativeSensorLifecycleScheduler);
  log.info("Native sensor lifecycle scheduler started", { intervalMs: SWEEP_INTERVAL_MS });
}

export function stopNativeSensorLifecycleScheduler(): void {
  if (!timer) return;
  clearInterval(timer);
  timer = null;
}
