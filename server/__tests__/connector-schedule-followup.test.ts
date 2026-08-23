import { describe, expect, it } from "vitest";
import type { Connector, ConnectorJobRun } from "@shared/schema";
import { bodySchemas } from "../request-validator";
import { getConnectorScheduleUpdate } from "../connector-schedule";

function connector(overrides: Partial<Connector> = {}): Connector {
  return {
    id: "connector-1",
    orgId: "org-1",
    name: "Test connector",
    type: "splunk",
    authType: "api_key",
    config: {},
    status: "active",
    pollingIntervalMin: 5,
    autoSyncEnabled: true,
    autoSyncPausedByAuth: false,
    effectivePollingIntervalMin: 5,
    nextSyncAt: new Date(0),
    consecutiveFailures: 0,
    scheduleReason: "scheduled",
    needsReconnection: false,
    lastSyncAt: null,
    lastSyncStatus: null,
    lastSyncAlerts: 0,
    lastSyncError: null,
    totalAlertsSynced: 0,
    createdBy: null,
    createdAt: new Date(0),
    updatedAt: new Date(0),
    ...overrides,
  };
}

function failedRun(overrides: Partial<ConnectorJobRun> = {}): ConnectorJobRun {
  return {
    id: "job-1",
    connectorId: "connector-1",
    orgId: "org-1",
    status: "failed",
    attempt: 3,
    maxAttempts: 3,
    alertsReceived: 0,
    alertsCreated: 0,
    alertsDeduped: 0,
    alertsFailed: 0,
    latencyMs: 1,
    errorMessage: "HTTP 503",
    errorType: "throttle",
    httpStatus: 503,
    throttled: true,
    isDeadLetter: true,
    retryStrategy: "exponential",
    backoffSeconds: null,
    nextRetryAt: null,
    checkpointData: null,
    checkpointAt: null,
    paginationCursor: null,
    fetchWindowStart: null,
    fetchWindowEnd: null,
    startedAt: new Date(0),
    completedAt: new Date(0),
    ...overrides,
  };
}

describe("connector schedule hardening", () => {
  it("restores only auto-sync that was enabled before an auth pause", () => {
    const paused = getConnectorScheduleUpdate(
      connector(),
      failedRun({ errorType: "auth_error", httpStatus: 401, errorMessage: "HTTP 401" }),
      new Date(0),
    ) as Connector & { autoSyncPausedByAuth?: boolean };

    expect(paused.autoSyncPausedByAuth).toBe(true);

    const recovered = getConnectorScheduleUpdate(
      connector({ ...paused, autoSyncEnabled: false }),
      failedRun({ status: "success", errorType: null, httpStatus: null, throttled: false }),
      new Date(0),
    ) as Connector & { autoSyncEnabled: boolean };

    expect(recovered.autoSyncEnabled).toBe(true);

    const manuallyDisabled = getConnectorScheduleUpdate(
      connector({ autoSyncEnabled: false }),
      failedRun({ errorType: "auth_error", httpStatus: 401, errorMessage: "HTTP 401" }),
      new Date(0),
    ) as Connector & { autoSyncPausedByAuth?: boolean };
    const manualRecovery = getConnectorScheduleUpdate(
      connector({ ...manuallyDisabled, autoSyncEnabled: false }),
      failedRun({ status: "success", errorType: null, httpStatus: null, throttled: false }),
      new Date(0),
    ) as Connector & { autoSyncEnabled: boolean };

    expect(manuallyDisabled.autoSyncPausedByAuth).toBe(false);
    expect(manualRecovery.autoSyncEnabled).toBe(false);
  });

  it("marks a connector failing after repeated non-auth failures", () => {
    const update = getConnectorScheduleUpdate(
      connector({ consecutiveFailures: 2 }),
      failedRun(),
      new Date(0),
    ) as Connector & { status?: string };

    expect(update.status).toBe("error");
  });

  it("rejects pollingIntervalMin on the general connector update schema", () => {
    const result = bodySchemas.connectorUpdate.safeParse({ pollingIntervalMin: 15 });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.message).toContain("/api/connectors/:id/schedule");
    }
  });
});
