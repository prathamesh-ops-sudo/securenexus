import { describe, expect, it, vi } from "vitest";

vi.mock("pg", () => ({
  default: {
    Pool: class MockPool {
      totalCount = 5;
      idleCount = 5;
      waitingCount = 0;
      on = vi.fn();
      query = vi.fn();
      end = vi.fn();
    },
  },
}));

vi.mock("drizzle-orm/node-postgres", () => ({
  drizzle: vi.fn(() => ({})),
}));

vi.mock("@shared/schema", () => ({}));

vi.mock("../config", () => ({
  config: {
    nodeEnv: "development",
    databaseUrl: "postgres://localhost/securenexus",
    databaseSslCaPath: undefined,
  },
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

import { getPoolHealth, pool } from "../db";

const mockPool = pool as unknown as {
  totalCount: number;
  idleCount: number;
  waitingCount: number;
};

describe("database pool health", () => {
  it("reports zero utilization for a warm idle pool", () => {
    mockPool.totalCount = 5;
    mockPool.idleCount = 5;
    mockPool.waitingCount = 0;

    expect(getPoolHealth()).toMatchObject({
      totalConnections: 5,
      idleConnections: 5,
      waitingRequests: 0,
      maxConnections: 5,
      utilizationPercent: 0,
      healthy: true,
    });
  });

  it("measures in-use connections and keeps waiting requests separate", () => {
    mockPool.totalCount = 5;
    mockPool.idleCount = 1;
    mockPool.waitingCount = 2;

    expect(getPoolHealth()).toMatchObject({
      utilizationPercent: 80,
      waitingRequests: 2,
      healthy: false,
    });
  });
});
