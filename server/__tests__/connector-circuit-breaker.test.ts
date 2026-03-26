import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";

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

import {
  recordConnectorFailure,
  recordConnectorSuccess,
  isCircuitOpen,
  getCircuitBreakerState,
  getAllCircuitBreakerStates,
  resetConnectorCircuitBreaker,
} from "../connector-circuit-breaker";

describe("connector-circuit-breaker", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // Reset all circuit breaker state between tests
    const states = getAllCircuitBreakerStates();
    for (const key of states.keys()) {
      resetConnectorCircuitBreaker(key);
    }
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("Test 1: new circuit breaker starts in closed state with 0 failures", () => {
    const state = getCircuitBreakerState("conn-1");
    expect(state.connectorId).toBe("conn-1");
    expect(state.state).toBe("closed");
    expect(state.failures).toBe(0);
    expect(state.failureTimestamps).toEqual([]);
    expect(state.openUntil).toBe(0);
    expect(state.lastFailure).toBe(0);
  });

  it("Test 2: recording 4 failures keeps circuit closed (threshold is 5)", () => {
    for (let i = 0; i < 4; i++) {
      recordConnectorFailure("conn-2");
    }
    const state = getCircuitBreakerState("conn-2");
    expect(state.state).toBe("closed");
    expect(state.failures).toBe(4);
    expect(isCircuitOpen("conn-2")).toBe(false);
  });

  it("Test 3: recording 5 failures within 60s opens circuit", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-3");
    }
    const state = getCircuitBreakerState("conn-3");
    expect(state.state).toBe("open");
    expect(state.failures).toBe(5);
    expect(state.openUntil).toBeGreaterThan(0);
  });

  it("Test 4: isCircuitOpen returns true when circuit is open", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-4");
    }
    expect(isCircuitOpen("conn-4")).toBe(true);
  });

  it("Test 5: after 30s half-open window, isCircuitOpen returns false (half-open)", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-5");
    }
    expect(isCircuitOpen("conn-5")).toBe(true);

    // Advance past the 30s half-open window
    vi.advanceTimersByTime(30_001);

    expect(isCircuitOpen("conn-5")).toBe(false);
    const state = getCircuitBreakerState("conn-5");
    expect(state.state).toBe("half-open");
  });

  it("Test 6: recording success in half-open state closes circuit (resets failures to 0)", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-6");
    }
    // Move to half-open
    vi.advanceTimersByTime(30_001);
    isCircuitOpen("conn-6"); // triggers half-open transition

    const result = recordConnectorSuccess("conn-6");
    expect(result.state).toBe("closed");
    expect(result.failures).toBe(0);
    expect(result.failureTimestamps).toEqual([]);
    expect(result.openUntil).toBe(0);
  });

  it("Test 7: recording failure in half-open state re-opens circuit", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-7");
    }
    // Move to half-open
    vi.advanceTimersByTime(30_001);
    isCircuitOpen("conn-7"); // triggers half-open transition

    const result = recordConnectorFailure("conn-7");
    expect(result.state).toBe("open");
    expect(result.openUntil).toBeGreaterThan(Date.now());
  });

  it("Test 8: failures older than 60s window are not counted toward threshold", () => {
    // Record 3 failures
    for (let i = 0; i < 3; i++) {
      recordConnectorFailure("conn-8");
    }

    // Advance past the 60s failure window
    vi.advanceTimersByTime(61_000);

    // Record 2 more failures (total 5, but only 2 in window)
    for (let i = 0; i < 2; i++) {
      recordConnectorFailure("conn-8");
    }

    const state = getCircuitBreakerState("conn-8");
    expect(state.state).toBe("closed");
    expect(state.failures).toBe(2); // only 2 within window
    expect(isCircuitOpen("conn-8")).toBe(false);
  });

  it("Test 9: resetConnectorCircuitBreaker clears all state", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-9");
    }
    expect(getCircuitBreakerState("conn-9").state).toBe("open");

    resetConnectorCircuitBreaker("conn-9");

    const state = getCircuitBreakerState("conn-9");
    expect(state.state).toBe("closed");
    expect(state.failures).toBe(0);
    expect(state.openUntil).toBe(0);
  });

  it("Test 10: getCircuitBreakerState returns correct state object", () => {
    for (let i = 0; i < 5; i++) {
      recordConnectorFailure("conn-10");
    }
    const state = getCircuitBreakerState("conn-10");
    expect(state).toMatchObject({
      connectorId: "conn-10",
      state: "open",
      failures: 5,
    });
    expect(state.openUntil).toBeGreaterThan(0);
    expect(state.failureTimestamps).toHaveLength(5);
  });

  it("Test 11: getAllCircuitBreakerStates returns Map of all tracked connectors", () => {
    recordConnectorFailure("conn-a");
    recordConnectorFailure("conn-b");

    const allStates = getAllCircuitBreakerStates();
    expect(allStates).toBeInstanceOf(Map);
    expect(allStates.has("conn-a")).toBe(true);
    expect(allStates.has("conn-b")).toBe(true);
    expect(allStates.size).toBe(2);
  });
});
