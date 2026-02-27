import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "@shared/schema";
import { config } from "./config";
import { logger } from "./logger";

const log = logger.child("db-pool");
const { Pool } = pg;

const PRODUCTION_ENVS = new Set(["production", "staging", "uat"]);
const isProd = PRODUCTION_ENVS.has(config.nodeEnv);

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: isProd ? 20 : 5,
  min: isProd ? 4 : 1,
  idleTimeoutMillis: isProd ? 30_000 : 10_000,
  connectionTimeoutMillis: 5_000,
  statement_timeout: isProd ? 30_000 : 60_000,
  query_timeout: isProd ? 30_000 : 60_000,
  application_name: `securenexus-${config.nodeEnv}`,
  allowExitOnIdle: !isProd,
});

pool.on("error", (err) => {
  log.error("Unexpected pool error on idle client", { error: String(err) });
});

pool.on("connect", (client) => {
  client.query(`SET statement_timeout = '${isProd ? 30000 : 60000}'`).catch((err: unknown) => {
    log.warn("Failed to set statement_timeout on new connection", {
      error: String(err),
    });
  });
});

export interface PoolHealthMetrics {
  totalConnections: number;
  idleConnections: number;
  waitingRequests: number;
  maxConnections: number;
  utilizationPercent: number;
  healthy: boolean;
}

export function getPoolHealth(): PoolHealthMetrics {
  const total = pool.totalCount;
  const idle = pool.idleCount;
  const waiting = pool.waitingCount;
  const max = isProd ? 20 : 5;
  const utilization = max > 0 ? Math.round((total / max) * 100) : 0;

  return {
    totalConnections: total,
    idleConnections: idle,
    waitingRequests: waiting,
    maxConnections: max,
    utilizationPercent: utilization,
    healthy: waiting === 0 && total <= max,
  };
}

let healthCheckInterval: ReturnType<typeof setInterval> | null = null;

export function startPoolHealthMonitor(intervalMs = 60_000): void {
  if (healthCheckInterval) return;

  healthCheckInterval = setInterval(() => {
    const health = getPoolHealth();

    if (health.waitingRequests > 0) {
      log.warn("Connection pool has waiting requests", {
        waiting: health.waitingRequests,
        total: health.totalConnections,
        idle: health.idleConnections,
        max: health.maxConnections,
      });
    }

    if (health.utilizationPercent > 80) {
      log.warn("Connection pool utilization above 80%", {
        utilization: `${health.utilizationPercent}%`,
        total: health.totalConnections,
        max: health.maxConnections,
      });
    }
  }, intervalMs);
}

export function stopPoolHealthMonitor(): void {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
  }
}

export async function checkPoolConnectivity(): Promise<{
  connected: boolean;
  latencyMs: number;
  serverVersion: string;
}> {
  const start = Date.now();
  try {
    const result = await pool.query("SELECT version() AS ver");
    const latencyMs = Date.now() - start;
    const serverVersion = (result.rows[0] as { ver: string }).ver;
    return { connected: true, latencyMs, serverVersion };
  } catch (err) {
    log.error("Pool connectivity check failed", {
      error: String(err),
      latencyMs: Date.now() - start,
    });
    return {
      connected: false,
      latencyMs: Date.now() - start,
      serverVersion: "unknown",
    };
  }
}

export async function drainPool(): Promise<void> {
  stopPoolHealthMonitor();
  await pool.end();
  log.info("Connection pool drained");
}

export const db = drizzle(pool, { schema });
