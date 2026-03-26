import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { Connector } from "@shared/schema";

// ---------------------------------------------------------------------------
// Mocks – follow patterns from connector-health-loop.test.ts
// ---------------------------------------------------------------------------

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

vi.mock("../config", () => ({
  config: {
    nodeEnv: "test",
  },
}));

const mockCreateConnectorJobRun = vi.fn();
const mockUpdateConnectorJobRun = vi.fn();
const mockGetConnectors = vi.fn();
const mockCreateConnectorHealthCheck = vi.fn();
const mockUpdateConnector = vi.fn();

vi.mock("../storage", () => ({
  storage: {
    createConnectorJobRun: (...args: unknown[]) => mockCreateConnectorJobRun(...args),
    updateConnectorJobRun: (...args: unknown[]) => mockUpdateConnectorJobRun(...args),
    getConnectors: (...args: unknown[]) => mockGetConnectors(...args),
    createConnectorHealthCheck: (...args: unknown[]) => mockCreateConnectorHealthCheck(...args),
    updateConnector: (...args: unknown[]) => mockUpdateConnector(...args),
  },
}));

vi.mock("../tracing", () => ({
  startSpan: (_component: string, _name: string, fn: () => unknown) => fn(),
  addSpanAttribute: vi.fn(),
}));

vi.mock("../distributed-concurrency", () => ({
  distributedAcquireSlot: vi.fn().mockResolvedValue(true),
  distributedReleaseSlot: vi.fn().mockResolvedValue(undefined),
  distributedCheckBackoff: vi.fn().mockResolvedValue(0),
  distributedApplyBackoff: vi.fn().mockResolvedValue(undefined),
  distributedClearBackoff: vi.fn().mockResolvedValue(undefined),
  distributedSetMaxConcurrency: vi.fn().mockResolvedValue(undefined),
  distributedGetProviderStats: vi.fn().mockResolvedValue({}),
}));

const mockPluginFetch = vi.fn();
const mockPluginNormalize = vi.fn();
const mockPluginTest = vi.fn();
const mockGetPlugin = vi.fn();

vi.mock("../connectors/connector-plugin", () => ({
  getPlugin: (...args: unknown[]) => mockGetPlugin(...args),
  getAllPluginTypes: () => ["splunk"],
  getPluginMetadata: () => null,
}));

vi.mock("../connectors/registry", () => ({
  initializeConnectorPlugins: vi.fn(),
}));

// We use the REAL circuit breaker module for some tests
// but must mock the logger dependency it uses (already done above)

import {
  isCircuitOpen,
  resetConnectorCircuitBreaker,
  getAllCircuitBreakerStates,
} from "../connector-circuit-breaker";

import { syncConnector, syncConnectorWithRetry } from "../connector-engine";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConnector(overrides: Partial<Connector> = {}): Connector {
  return {
    id: "conn-fail-1",
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

function makeMockPlugin() {
  return {
    type: "splunk",
    alertSource: "splunk",
    normalizerKey: "splunk",
    metadata: {} as never,
    test: mockPluginTest,
    fetch: mockPluginFetch,
    normalize: mockPluginNormalize,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("connector-failure-modes", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Reset all circuit breaker state between tests
    const states = getAllCircuitBreakerStates();
    for (const key of states.keys()) {
      resetConnectorCircuitBreaker(key);
    }

    // Default mock plugin returned by getPlugin
    mockGetPlugin.mockReturnValue(makeMockPlugin());

    // Default storage mocks for syncConnectorWithRetry
    mockCreateConnectorJobRun.mockResolvedValue({
      id: "job-1",
      connectorId: "conn-fail-1",
      orgId: "org-1",
      status: "running",
      attempt: 1,
      maxAttempts: 3,
    });
    mockUpdateConnectorJobRun.mockImplementation((_id: string, updates: Record<string, unknown>) => {
      return Promise.resolve({
        id: "job-1",
        connectorId: "conn-fail-1",
        orgId: "org-1",
        ...updates,
      });
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // =========================================================================
  // 1. Error classification tests
  // =========================================================================

  describe("Error classification", () => {
    it("classifies timeout errors as network_error", async () => {
      const connector = makeConnector({ id: "conn-timeout-1" });
      vi.useFakeTimers();
      mockPluginFetch.mockRejectedValue(new Error("Connection timeout after 30s"));

      await syncConnectorWithRetry(connector, 1);

      const lastCall = mockUpdateConnectorJobRun.mock.calls[mockUpdateConnectorJobRun.mock.calls.length - 1];
      const updates = lastCall[1] as Record<string, unknown>;
      expect(updates.errorMessage).toBe("Connection timeout after 30s");
      expect(updates.errorType).toBe("network_error");
      expect(updates.throttled).toBe(false);
      expect(updates.httpStatus).toBeUndefined();
      vi.useRealTimers();
    });

    it("classifies 401 Unauthorized as auth_error with httpStatus 401", async () => {
      const connector = makeConnector();
      vi.useFakeTimers();
      mockPluginFetch.mockRejectedValue(new Error("401 Unauthorized"));

      const retryResult = await syncConnectorWithRetry(connector, 1);

      expect(retryResult.jobRun.errorType).toBe("auth_error");
      expect(retryResult.jobRun.httpStatus).toBe(401);
      expect(retryResult.jobRun.throttled).toBe(false);
      vi.useRealTimers();
    });

    it("classifies 403 Forbidden as auth_error with httpStatus 403", async () => {
      const connector = makeConnector();
      vi.useFakeTimers();
      mockPluginFetch.mockRejectedValue(new Error("403 Forbidden"));

      const retryResult = await syncConnectorWithRetry(connector, 1);

      expect(retryResult.jobRun.errorType).toBe("auth_error");
      expect(retryResult.jobRun.httpStatus).toBe(403);
      expect(retryResult.jobRun.throttled).toBe(false);
      vi.useRealTimers();
    });

    it("classifies 429 Too Many Requests as throttle with httpStatus 429", async () => {
      const connector = makeConnector();
      vi.useFakeTimers();
      mockPluginFetch.mockRejectedValue(new Error("429 Too Many Requests"));

      const retryResult = await syncConnectorWithRetry(connector, 1);

      expect(retryResult.jobRun.errorType).toBe("throttle");
      expect(retryResult.jobRun.httpStatus).toBe(429);
      expect(retryResult.jobRun.throttled).toBe(true);
      vi.useRealTimers();
    });
  });

  // =========================================================================
  // 2. Circuit breaker integration tests
  // =========================================================================

  describe("Circuit breaker integration", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("circuit breaker opens after 5 failures, 6th sync returns circuit breaker error", async () => {
      const connector = makeConnector({ id: "conn-cb-1" });
      mockPluginFetch.mockRejectedValue(new Error("Server error"));

      // Fail 5 times to open the circuit breaker
      for (let i = 0; i < 5; i++) {
        await syncConnector(connector);
      }

      expect(isCircuitOpen("conn-cb-1")).toBe(true);

      // 6th call should return circuit breaker error without calling plugin
      mockPluginFetch.mockClear();
      const result = await syncConnector(connector);

      expect(result.errors[0]).toContain("Circuit breaker open");
      expect(result.alertsReceived).toBe(0);
      expect(mockPluginFetch).not.toHaveBeenCalled();
    });

    it("circuit breaker half-opens after 30s, allowing a probe request through", async () => {
      const connector = makeConnector({ id: "conn-cb-2" });
      mockPluginFetch.mockRejectedValue(new Error("Server error"));

      // Open the circuit breaker
      for (let i = 0; i < 5; i++) {
        await syncConnector(connector);
      }
      expect(isCircuitOpen("conn-cb-2")).toBe(true);

      // Advance past the 30s half-open window
      vi.advanceTimersByTime(30_001);

      // Now isCircuitOpen returns false (half-open allows a probe)
      expect(isCircuitOpen("conn-cb-2")).toBe(false);

      // A sync attempt should now go through to the plugin
      mockPluginFetch.mockClear();
      mockPluginFetch.mockResolvedValue([]);
      const result = await syncConnector(connector);

      expect(mockPluginFetch).toHaveBeenCalledTimes(1);
      expect(result.errors).toHaveLength(0);
    });
  });

  // =========================================================================
  // 3. Large result handling tests
  // =========================================================================

  describe("Large result handling", () => {
    it("processes 500 items returned by plugin.fetch through normalization", async () => {
      const connector = makeConnector();

      // Generate 500 raw events
      const rawEvents = Array.from({ length: 500 }, (_, i) => ({
        id: `event-${i}`,
        title: `Alert ${i}`,
        severity: "high",
      }));
      mockPluginFetch.mockResolvedValue(rawEvents);

      // Each normalize call returns a valid partial alert
      mockPluginNormalize.mockImplementation((raw: { id: string; title: string }) => ({
        title: raw.title,
        source: "splunk",
        severity: "high",
        sourceEventId: raw.id,
      }));

      const result = await syncConnector(connector);

      expect(result.alertsReceived).toBe(500);
      expect(result.rawAlerts).toHaveLength(500);
      expect(result.alertsFailed).toBe(0);
      expect(result.errors).toHaveLength(0);
      expect(mockPluginNormalize).toHaveBeenCalledTimes(500);
    });
  });

  // =========================================================================
  // 4. Retry behavior tests
  // =========================================================================

  describe("Retry behavior", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("syncConnectorWithRetry retries on failure and succeeds on second attempt", async () => {
      const connector = makeConnector({ id: "conn-retry-1" });

      // Reset circuit breaker for this connector to avoid interference
      resetConnectorCircuitBreaker("conn-retry-1");

      // First call fails, second call succeeds
      let callCount = 0;
      mockPluginFetch.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject(new Error("Temporary network error"));
        }
        return Promise.resolve([{ id: "alert-1", title: "Test Alert" }]);
      });
      mockPluginNormalize.mockReturnValue({
        title: "Test Alert",
        source: "splunk",
        severity: "medium",
        sourceEventId: "alert-1",
      });

      const resultPromise = syncConnectorWithRetry(connector, 3);

      // The retry loop waits with exponential backoff (2^1 = 2 seconds for first retry)
      await vi.advanceTimersByTimeAsync(2_000);

      const result = await resultPromise;

      expect(result.jobRun.status).toBe("success");
      expect(result.syncResult.alertsReceived).toBe(1);
      expect(callCount).toBe(2);
    });

    it("syncConnectorWithRetry marks job as failed after exhausting all attempts", async () => {
      const connector = makeConnector({ id: "conn-retry-2" });
      resetConnectorCircuitBreaker("conn-retry-2");

      mockPluginFetch.mockRejectedValue(new Error("Persistent failure"));

      const resultPromise = syncConnectorWithRetry(connector, 2);

      // Advance past backoff: 2^1 = 2s first retry wait
      await vi.advanceTimersByTimeAsync(2_000);

      const result = await resultPromise;

      expect(result.jobRun.status).toBe("failed");
      expect(result.jobRun.isDeadLetter).toBe(true);
      expect(result.syncResult.errors).toContain("Persistent failure");
    });
  });

  // =========================================================================
  // 5. Additional edge case tests
  // =========================================================================

  describe("Edge cases", () => {
    it("unknown connector type returns error without calling plugin", async () => {
      const connector = makeConnector({ type: "nonexistent" });
      mockGetPlugin.mockReturnValue(undefined);

      const result = await syncConnector(connector);

      expect(result.errors[0]).toContain("Unknown connector type");
      expect(result.alertsReceived).toBe(0);
      expect(mockPluginFetch).not.toHaveBeenCalled();
    });

    it("normalization failures are counted as alertsFailed while valid alerts succeed", async () => {
      const connector = makeConnector();

      mockPluginFetch.mockResolvedValue([
        { id: "good-1", title: "Good Alert" },
        { id: "bad-1", title: "Bad Alert" },
        { id: "good-2", title: "Good Alert 2" },
      ]);

      let normalizeCallIdx = 0;
      mockPluginNormalize.mockImplementation(() => {
        normalizeCallIdx++;
        if (normalizeCallIdx === 2) {
          throw new Error("Invalid alert format");
        }
        return {
          title: "Normalized Alert",
          source: "splunk",
          severity: "medium",
        };
      });

      const result = await syncConnector(connector);

      expect(result.alertsReceived).toBe(3);
      expect(result.rawAlerts).toHaveLength(2);
      expect(result.alertsFailed).toBe(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain("Normalization failed");
    });
  });
});
