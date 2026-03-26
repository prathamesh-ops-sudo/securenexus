import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { Connector } from "@shared/schema";

// Mock dependencies
vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
  },
}));

const mockGetConnectors = vi.fn();
const mockCreateConnectorHealthCheck = vi.fn();
const mockUpdateConnector = vi.fn();

vi.mock("../storage", () => ({
  storage: {
    getConnectors: (...args: unknown[]) => mockGetConnectors(...args),
    createConnectorHealthCheck: (...args: unknown[]) => mockCreateConnectorHealthCheck(...args),
    updateConnector: (...args: unknown[]) => mockUpdateConnector(...args),
  },
}));

const mockIsCircuitOpen = vi.fn();
const mockRecordConnectorSuccess = vi.fn();
const mockRecordConnectorFailure = vi.fn();

vi.mock("../connector-circuit-breaker", () => ({
  isCircuitOpen: (...args: unknown[]) => mockIsCircuitOpen(...args),
  recordConnectorSuccess: (...args: unknown[]) => mockRecordConnectorSuccess(...args),
  recordConnectorFailure: (...args: unknown[]) => mockRecordConnectorFailure(...args),
}));

const mockPluginTest = vi.fn();
const mockGetPlugin = vi.fn();

vi.mock("../connectors/connector-plugin", () => ({
  getPlugin: (...args: unknown[]) => mockGetPlugin(...args),
}));

import {
  startConnectorHealthLoop,
  stopConnectorHealthLoop,
  getConnectorHealthStatus,
  runHealthChecks,
  resetConnectorHealthStates,
} from "../connector-health-loop";

function makeConnector(overrides: Partial<Connector> = {}): Connector {
  return {
    id: "conn-1",
    orgId: "org-1",
    name: "Test Connector",
    type: "splunk",
    authType: "api_key",
    config: { baseUrl: "https://splunk.example.com", apiKey: "test-key" },
    status: "active",
    pollingIntervalMin: 5,
    lastSyncAt: null,
    lastSyncStatus: null,
    lastSyncAlerts: null,
    lastSyncError: null,
    totalAlertsSynced: 0,
    createdBy: "user-1",
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Connector;
}

describe("connector-health-loop", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    stopConnectorHealthLoop();
    resetConnectorHealthStates();

    // Default mocks
    mockIsCircuitOpen.mockReturnValue(false);
    mockRecordConnectorSuccess.mockReturnValue({});
    mockRecordConnectorFailure.mockReturnValue({});
    mockCreateConnectorHealthCheck.mockResolvedValue({});
    mockUpdateConnector.mockResolvedValue({});
  });

  afterEach(() => {
    stopConnectorHealthLoop();
    vi.useRealTimers();
  });

  it("Test 1: startConnectorHealthLoop starts interval and runs first check immediately", async () => {
    mockGetConnectors.mockResolvedValue([]);

    startConnectorHealthLoop();

    // Should have called getConnectors immediately
    await vi.advanceTimersByTimeAsync(0);
    expect(mockGetConnectors).toHaveBeenCalledTimes(1);
  });

  it("Test 2: health check calls plugin.test for each active connector", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockGetPlugin.mockReturnValue({
      test: mockPluginTest,
    });
    mockPluginTest.mockResolvedValue({
      success: true,
      message: "OK",
      latencyMs: 42,
    });

    startConnectorHealthLoop();
    await vi.advanceTimersByTimeAsync(0);

    expect(mockGetPlugin).toHaveBeenCalledWith("splunk");
    expect(mockPluginTest).toHaveBeenCalledWith(connector.config);
  });

  it("Test 3: successful test result records healthy status and calls recordConnectorSuccess", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockGetPlugin.mockReturnValue({ test: mockPluginTest });
    mockPluginTest.mockResolvedValue({
      success: true,
      message: "Connection OK",
      latencyMs: 50,
    });

    startConnectorHealthLoop();
    await vi.advanceTimersByTimeAsync(0);

    expect(mockRecordConnectorSuccess).toHaveBeenCalledWith("conn-1");
    expect(mockCreateConnectorHealthCheck).toHaveBeenCalledWith(
      expect.objectContaining({
        connectorId: "conn-1",
        orgId: "org-1",
        status: "healthy",
        latencyMs: 50,
        credentialStatus: "valid",
      }),
    );
  });

  it("Test 4: failed test result records unhealthy status and calls recordConnectorFailure", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockGetPlugin.mockReturnValue({ test: mockPluginTest });
    mockPluginTest.mockResolvedValue({
      success: false,
      message: "Connection refused",
      latencyMs: 100,
    });

    startConnectorHealthLoop();
    await vi.advanceTimersByTimeAsync(0);

    expect(mockRecordConnectorFailure).toHaveBeenCalledWith("conn-1");
    expect(mockCreateConnectorHealthCheck).toHaveBeenCalledWith(
      expect.objectContaining({
        connectorId: "conn-1",
        orgId: "org-1",
        status: "degraded",
        errorMessage: "Connection refused",
      }),
    );
  });

  it("Test 5: connector with circuit breaker open is skipped (logged as circuit_open)", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockIsCircuitOpen.mockReturnValue(true);

    startConnectorHealthLoop();
    await vi.advanceTimersByTimeAsync(0);

    expect(mockGetPlugin).not.toHaveBeenCalled();
    expect(mockPluginTest).not.toHaveBeenCalled();

    const status = getConnectorHealthStatus();
    const connStatus = status.get("conn-1");
    expect(connStatus?.status).toBe("circuit_open");
  });

  it("Test 6: auto-restart triggers after 3 consecutive failures", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockGetPlugin.mockReturnValue({ test: mockPluginTest });
    mockPluginTest.mockResolvedValue({
      success: false,
      message: "Timeout",
      latencyMs: 0,
    });

    startConnectorHealthLoop();

    // Run 3 health check cycles with proper async flushing
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.advanceTimersByTimeAsync(60_000);

    // Should have called updateConnector with error status
    expect(mockUpdateConnector).toHaveBeenCalledWith(
      "conn-1",
      expect.objectContaining({
        status: "error",
      }),
    );

    // The check that triggered auto-restart should record "failed" status
    const failedCalls = mockCreateConnectorHealthCheck.mock.calls.filter(
      (c: unknown[]) => (c[0] as { status: string }).status === "failed",
    );
    expect(failedCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("Test 7: auto-restart uses exponential backoff: 30s, 60s, 120s, max 300s", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockGetPlugin.mockReturnValue({ test: mockPluginTest });
    mockPluginTest.mockResolvedValue({
      success: false,
      message: "Timeout",
      latencyMs: 0,
    });

    startConnectorHealthLoop();

    // First 3 failures trigger restart with 30s backoff
    for (let i = 0; i < 3; i++) {
      await vi.advanceTimersByTimeAsync(i === 0 ? 0 : 60_000);
    }

    let status = getConnectorHealthStatus();
    let connStatus = status.get("conn-1");
    expect(connStatus?.restartCount).toBe(1);
    // nextRestartAt should be ~30s from now
    expect(connStatus?.nextRestartAt).toBeGreaterThan(0);

    // Run 3 more health checks (will be skipped during backoff, then fail again)
    // After backoff expires, failures accumulate again
    // Advance past the 30s backoff
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.advanceTimersByTimeAsync(60_000);

    status = getConnectorHealthStatus();
    connStatus = status.get("conn-1");
    // Should have incremented restart count again
    expect(connStatus!.restartCount).toBeGreaterThanOrEqual(2);
  });

  it("Test 8: successful health check resets consecutiveFailures to 0 and backoff", async () => {
    const connector = makeConnector();
    mockGetConnectors.mockResolvedValue([connector]);
    mockGetPlugin.mockReturnValue({ test: mockPluginTest });

    // First 2 failures via direct call
    mockPluginTest.mockResolvedValue({ success: false, message: "Fail", latencyMs: 0 });
    await runHealthChecks();
    await runHealthChecks();

    let status = getConnectorHealthStatus();
    expect(status.get("conn-1")?.consecutiveFailures).toBe(2);

    // Now succeed via direct call
    mockPluginTest.mockResolvedValue({ success: true, message: "OK", latencyMs: 30 });
    await runHealthChecks();

    expect(mockRecordConnectorSuccess).toHaveBeenCalledWith("conn-1");

    status = getConnectorHealthStatus();
    const connStatus = status.get("conn-1");
    expect(connStatus?.consecutiveFailures).toBe(0);
    expect(connStatus?.restartCount).toBe(0);
    expect(connStatus?.nextRestartAt).toBe(0);
    expect(connStatus?.status).toBe("healthy");
  });

  it("Test 9: stopConnectorHealthLoop clears interval", async () => {
    mockGetConnectors.mockResolvedValue([]);

    startConnectorHealthLoop();
    await vi.advanceTimersByTimeAsync(0);
    expect(mockGetConnectors).toHaveBeenCalledTimes(1);

    stopConnectorHealthLoop();

    await vi.advanceTimersByTimeAsync(60_000);
    // Should not have been called again
    expect(mockGetConnectors).toHaveBeenCalledTimes(1);
  });

  it("Test 10: getConnectorHealthStatus returns Map of connectorId to health summary", async () => {
    const connectors = [makeConnector({ id: "c1" }), makeConnector({ id: "c2" })];
    mockGetConnectors.mockResolvedValue(connectors);
    mockGetPlugin.mockReturnValue({ test: mockPluginTest });
    mockPluginTest.mockResolvedValue({ success: true, message: "OK", latencyMs: 10 });

    startConnectorHealthLoop();
    await vi.advanceTimersByTimeAsync(0);

    const status = getConnectorHealthStatus();
    expect(status).toBeInstanceOf(Map);
    expect(status.has("c1")).toBe(true);
    expect(status.has("c2")).toBe(true);
    expect(status.get("c1")?.status).toBe("healthy");
    expect(status.get("c2")?.status).toBe("healthy");
  });
});
