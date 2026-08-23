import type { Connector, ConnectorJobRun } from "@shared/schema";
import { storage } from "./storage";

export const MIN_CONNECTOR_INTERVAL_MIN = 5;
export const MAX_CONNECTOR_INTERVAL_MIN = 1440;
export const CONNECTOR_FAILURE_STATUS_THRESHOLD = 3;

export function clampConnectorInterval(intervalMin: number | null | undefined): number {
  const value = Number.isFinite(intervalMin) ? Math.trunc(intervalMin as number) : MIN_CONNECTOR_INTERVAL_MIN;
  return Math.max(MIN_CONNECTOR_INTERVAL_MIN, Math.min(MAX_CONNECTOR_INTERVAL_MIN, value));
}

export type ConnectorScheduleReason =
  | "auto_sync_off"
  | "connector_inactive"
  | "scheduled"
  | "queued"
  | "backing_off_after_failure"
  | "throttled"
  | "needs_reconnection"
  | "quota_exhausted"
  | "enqueue_failed";

export interface ConnectorScheduleUpdate {
  autoSyncEnabled: boolean;
  effectivePollingIntervalMin: number;
  nextSyncAt: Date | null;
  consecutiveFailures: number;
  scheduleReason: ConnectorScheduleReason;
  needsReconnection: boolean;
  autoSyncPausedByAuth: boolean;
  status: string;
}

function isAuthenticationFailure(jobRun: ConnectorJobRun): boolean {
  return (
    jobRun.errorType === "auth_error" ||
    jobRun.httpStatus === 401 ||
    jobRun.httpStatus === 403 ||
    /(?:^|[^0-9])(?:401|403)(?:[^0-9]|$)/.test(jobRun.errorMessage ?? "")
  );
}

export function getConnectorScheduleUpdate(
  connector: Connector,
  jobRun: ConnectorJobRun,
  now = new Date(),
): ConnectorScheduleUpdate {
  const baseInterval = clampConnectorInterval(connector.pollingIntervalMin);
  const priorFailures = connector.consecutiveFailures ?? 0;

  if (jobRun.status === "success" || jobRun.status === "partial") {
    const shouldRestoreAutoSync =
      connector.status !== "inactive" && (connector.autoSyncEnabled || connector.autoSyncPausedByAuth);
    return {
      autoSyncEnabled: shouldRestoreAutoSync,
      effectivePollingIntervalMin: baseInterval,
      nextSyncAt: shouldRestoreAutoSync ? new Date(now.getTime() + baseInterval * 60_000) : null,
      consecutiveFailures: 0,
      scheduleReason: shouldRestoreAutoSync ? "scheduled" : "auto_sync_off",
      needsReconnection: false,
      autoSyncPausedByAuth: false,
      status: connector.status === "inactive" ? "inactive" : "active",
    };
  }

  const consecutiveFailures = priorFailures + 1;
  if (isAuthenticationFailure(jobRun)) {
    return {
      autoSyncEnabled: false,
      effectivePollingIntervalMin: baseInterval,
      nextSyncAt: null,
      consecutiveFailures,
      scheduleReason: "needs_reconnection",
      needsReconnection: true,
      autoSyncPausedByAuth: connector.autoSyncEnabled || connector.autoSyncPausedByAuth,
      status: "error",
    };
  }

  const effectivePollingIntervalMin = clampConnectorInterval(baseInterval * 2 ** consecutiveFailures);
  return {
    autoSyncEnabled: connector.autoSyncEnabled,
    effectivePollingIntervalMin,
    nextSyncAt: connector.autoSyncEnabled ? new Date(now.getTime() + effectivePollingIntervalMin * 60_000) : null,
    consecutiveFailures,
    scheduleReason: jobRun.throttled ? "throttled" : "backing_off_after_failure",
    needsReconnection: false,
    autoSyncPausedByAuth: connector.autoSyncPausedByAuth,
    status: consecutiveFailures >= CONNECTOR_FAILURE_STATUS_THRESHOLD ? "error" : "active",
  };
}

export async function applyConnectorJobScheduleResult(
  connector: Connector,
  jobRun: ConnectorJobRun,
  now = new Date(),
): Promise<ConnectorScheduleUpdate> {
  const update = getConnectorScheduleUpdate(connector, jobRun, now);
  await storage.updateConnector(connector.id, update);
  return update;
}

export function getQuotaExhaustedScheduleUpdate(
  connector: Connector,
  now = new Date(),
): Pick<ConnectorScheduleUpdate, "nextSyncAt" | "scheduleReason"> {
  const interval = clampConnectorInterval(connector.effectivePollingIntervalMin ?? connector.pollingIntervalMin);
  return {
    nextSyncAt: new Date(now.getTime() + interval * 60_000),
    scheduleReason: "quota_exhausted",
  };
}
