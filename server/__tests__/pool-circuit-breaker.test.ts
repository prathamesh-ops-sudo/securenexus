import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../db", () => ({
  getPoolHealth: vi.fn(),
}));

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

import { getPoolHealth } from "../db";
import { poolCircuitBreakerMiddleware, _resetPoolCircuitBreakerCache } from "../middleware/pool-circuit-breaker";

const mockedGetPoolHealth = vi.mocked(getPoolHealth);

function createMocks(pathOverride = "/api/alerts") {
  const req = { path: pathOverride, orgId: "org-123" } as any;
  const res = {
    status: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as any;
  const next = vi.fn();
  return { req, res, next };
}

describe("poolCircuitBreakerMiddleware", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetPoolCircuitBreakerCache();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("calls next() when pool utilization is below 80%", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 10,
      idleConnections: 5,
      waitingRequests: 0,
      maxConnections: 20,
      utilizationPercent: 50,
      healthy: true,
    });

    const { req, res, next } = createMocks();
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("returns 503 with Retry-After header when utilization >= 80%", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 16,
      idleConnections: 0,
      waitingRequests: 3,
      maxConnections: 20,
      utilizationPercent: 80,
      healthy: false,
    });

    const { req, res, next } = createMocks();
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.set).toHaveBeenCalledWith("Retry-After", "5");
    expect(res.json).toHaveBeenCalledWith({
      data: null,
      meta: {},
      errors: [
        {
          code: "SERVICE_UNAVAILABLE",
          message: "Database capacity is temporarily saturated. Please retry shortly.",
        },
      ],
    });
  });

  it("does not shed a warm idle pool", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 5,
      idleConnections: 5,
      waitingRequests: 0,
      maxConnections: 5,
      utilizationPercent: 0,
      healthy: true,
    });

    const { req, res, next } = createMocks();
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("serves HTML paths even when the database is saturated", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 20,
      idleConnections: 0,
      waitingRequests: 3,
      maxConnections: 20,
      utilizationPercent: 100,
      healthy: false,
    });

    const { req, res, next } = createMocks("/login");
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("exempts /api/health path and always calls next()", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 20,
      idleConnections: 0,
      waitingRequests: 5,
      maxConnections: 20,
      utilizationPercent: 100,
      healthy: false,
    });

    const { req, res, next } = createMocks("/api/health");
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("exempts /api/metrics path and always calls next()", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 20,
      idleConnections: 0,
      waitingRequests: 5,
      maxConnections: 20,
      utilizationPercent: 100,
      healthy: false,
    });

    const { req, res, next } = createMocks("/api/metrics");
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("caches utilization and does not call getPoolHealth on every request within 1 second", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 5,
      idleConnections: 3,
      waitingRequests: 0,
      maxConnections: 20,
      utilizationPercent: 25,
      healthy: true,
    });

    // First call — triggers getPoolHealth
    const m1 = createMocks();
    poolCircuitBreakerMiddleware(m1.req, m1.res, m1.next);
    expect(mockedGetPoolHealth).toHaveBeenCalledTimes(1);

    // Second call within same second — uses cached value
    const m2 = createMocks();
    poolCircuitBreakerMiddleware(m2.req, m2.res, m2.next);
    expect(mockedGetPoolHealth).toHaveBeenCalledTimes(1);

    // Advance past 1 second
    vi.advanceTimersByTime(1100);

    // Third call — cache stale, triggers getPoolHealth again
    const m3 = createMocks();
    poolCircuitBreakerMiddleware(m3.req, m3.res, m3.next);
    expect(mockedGetPoolHealth).toHaveBeenCalledTimes(2);

    // All should have called next
    expect(m1.next).toHaveBeenCalled();
    expect(m2.next).toHaveBeenCalled();
    expect(m3.next).toHaveBeenCalled();
  });

  it("returns 503 for utilization above 80%", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 18,
      idleConnections: 0,
      waitingRequests: 2,
      maxConnections: 20,
      utilizationPercent: 90,
      healthy: false,
    });

    const { req, res, next } = createMocks();
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it("exempts /api/ops/health subpaths", () => {
    mockedGetPoolHealth.mockReturnValue({
      totalConnections: 20,
      idleConnections: 0,
      waitingRequests: 5,
      maxConnections: 20,
      utilizationPercent: 100,
      healthy: false,
    });

    const { req, res, next } = createMocks("/api/ops/health");
    poolCircuitBreakerMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});
