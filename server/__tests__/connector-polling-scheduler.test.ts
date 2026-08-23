import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Connector, ConnectorJobRun } from "@shared/schema";

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../db", () => ({ db: {} }));
vi.mock("../job-queue", () => ({ enqueueJob: vi.fn() }));
vi.mock("../scaling-state", () => ({ registerShutdownHandler: vi.fn() }));
vi.mock("../middleware/plan-enforcement", () => ({
  checkQuota: vi.fn(),
  consumeQuota: vi.fn(),
  incrementAndCheck: vi.fn(),
}));
vi.mock("../storage", () => ({ storage: { updateConnector: vi.fn() } }));

import { getConnectorScheduleUpdate } from "../connector-schedule";
import { runConnectorPollingTick, type ConnectorPollingDependencies } from "../connector-polling-scheduler";

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
    createdAt: new Date(),
    updatedAt: new Date(),
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
    latencyMs: 10,
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
    startedAt: new Date(),
    completedAt: new Date(),
    ...overrides,
  };
}

describe("connector polling scheduler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("enqueues due connectors and never schedules disabled connectors", async () => {
    const enqueue = vi.fn().mockResolvedValue({ id: "job-1" });
    const consumeQuota = vi.fn().mockResolvedValue(undefined);
    const deps: ConnectorPollingDependencies = {
      claimDueConnectors: vi
        .fn()
        .mockResolvedValue([connector(), connector({ id: "disabled", autoSyncEnabled: false })]),
      enqueue,
      checkQuota: vi.fn().mockResolvedValue({ allowed: true }),
      consumeQuota,
      markQuotaExhausted: vi.fn(),
    };

    await runConnectorPollingTick(deps);

    expect(enqueue).toHaveBeenCalledTimes(1);
    expect(enqueue).toHaveBeenCalledWith(expect.objectContaining({ id: "connector-1" }));
    expect(consumeQuota).toHaveBeenCalledTimes(1);
  });

  it("does not double enqueue when concurrent ticks contend for the database claim", async () => {
    let claimed = false;
    const candidate = connector();
    const claim = vi.fn().mockImplementation(async () => {
      if (claimed) return [];
      claimed = true;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return [candidate];
    });
    const enqueue = vi.fn().mockResolvedValue({ id: "job-1" });
    const deps: ConnectorPollingDependencies = {
      claimDueConnectors: claim,
      enqueue,
      checkQuota: vi.fn().mockResolvedValue({ allowed: true }),
      consumeQuota: vi.fn().mockResolvedValue(undefined),
      markQuotaExhausted: vi.fn(),
    };

    await Promise.all([runConnectorPollingTick(deps), runConnectorPollingTick(deps)]);

    expect(enqueue).toHaveBeenCalledTimes(1);
  });

  it("records exponential backoff progression for throttled failures", () => {
    const first = getConnectorScheduleUpdate(connector(), failedRun(), new Date(0));
    const second = getConnectorScheduleUpdate(
      connector({ consecutiveFailures: first.consecutiveFailures }),
      failedRun(),
      new Date(0),
    );

    expect(first.effectivePollingIntervalMin).toBe(10);
    expect(second.effectivePollingIntervalMin).toBe(20);
    expect(first.scheduleReason).toBe("throttled");
  });

  it("pauses authentication failures and resumes after a successful sync", () => {
    const paused = getConnectorScheduleUpdate(
      connector(),
      failedRun({ errorType: "auth_error", httpStatus: 401, errorMessage: "HTTP 401" }),
      new Date(0),
    );
    expect(paused.autoSyncEnabled).toBe(false);
    expect(paused.needsReconnection).toBe(true);
    expect(paused.nextSyncAt).toBeNull();
    expect(paused.scheduleReason).toBe("needs_reconnection");

    const recovered = getConnectorScheduleUpdate(
      connector(paused),
      failedRun({ status: "success", errorType: null, httpStatus: null, throttled: false }),
      new Date(0),
    );
    expect(recovered.autoSyncEnabled).toBe(true);
    expect(recovered.needsReconnection).toBe(false);
    expect(recovered.consecutiveFailures).toBe(0);
    expect(recovered.nextSyncAt).toEqual(new Date(300_000));
  });

  it("persists quota exhaustion instead of silently omitting the connector", async () => {
    const markQuotaExhausted = vi.fn();
    const consumeQuota = vi.fn().mockResolvedValue(undefined);
    const deps: ConnectorPollingDependencies = {
      claimDueConnectors: vi.fn().mockResolvedValue([connector()]),
      enqueue: vi.fn(),
      checkQuota: vi.fn().mockResolvedValue({ allowed: false }),
      consumeQuota,
      markQuotaExhausted,
    };

    await runConnectorPollingTick(deps);

    expect(deps.enqueue).not.toHaveBeenCalled();
    expect(markQuotaExhausted).toHaveBeenCalledWith(expect.objectContaining({ id: "connector-1" }));
    expect(consumeQuota).not.toHaveBeenCalled();
  });

  it("does not consume quota when enqueue is deduplicated", async () => {
    const consumeQuota = vi.fn().mockResolvedValue(undefined);
    const deps: ConnectorPollingDependencies = {
      claimDueConnectors: vi.fn().mockResolvedValue([connector()]),
      enqueue: vi.fn().mockResolvedValue(null),
      checkQuota: vi.fn().mockResolvedValue({ allowed: true }),
      consumeQuota,
      markQuotaExhausted: vi.fn(),
    };

    await runConnectorPollingTick(deps);

    expect(consumeQuota).not.toHaveBeenCalled();
  });
});
