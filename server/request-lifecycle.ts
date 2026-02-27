import type { Request, Response, NextFunction } from "express";
import { logger } from "./logger";
import { isDraining } from "./scaling-state";
import { checkPoolConnectivity, getPoolHealth } from "./db";

const log = logger.child("request-lifecycle");

let inFlightCount = 0;
let serverReady = false;

export function getInFlightCount(): number {
  return inFlightCount;
}

export function isServerReady(): boolean {
  return serverReady;
}

export function markServerReady(): void {
  serverReady = true;
  log.info("Server marked as ready");
}

export function markServerNotReady(): void {
  serverReady = false;
  log.info("Server marked as not ready");
}

export function inFlightMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.path === "/api/ops/ready" || req.path === "/api/ops/live" || req.path === "/api/ops/health") {
    next();
    return;
  }

  inFlightCount++;
  res.on("finish", () => {
    inFlightCount--;
  });
  res.on("close", () => {
    if (inFlightCount > 0) inFlightCount--;
  });
  next();
}

export async function waitForInFlightDrain(timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  while (inFlightCount > 0 && Date.now() - start < timeoutMs) {
    log.info("Waiting for in-flight requests to drain", { inFlight: inFlightCount });
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  if (inFlightCount > 0) {
    log.warn("In-flight drain timeout reached", { remaining: inFlightCount });
  } else {
    log.info("All in-flight requests drained");
  }
}

export interface ReadinessStatus {
  ready: boolean;
  timestamp: string;
  checks: {
    database: { connected: boolean; latencyMs: number };
    pool: { healthy: boolean; utilization: number; waiting: number };
    draining: boolean;
    inFlight: number;
  };
}

export async function checkReadiness(): Promise<ReadinessStatus> {
  const draining = isDraining();
  const inFlight = inFlightCount;

  if (draining) {
    return {
      ready: false,
      timestamp: new Date().toISOString(),
      checks: {
        database: { connected: false, latencyMs: 0 },
        pool: { healthy: false, utilization: 0, waiting: 0 },
        draining: true,
        inFlight,
      },
    };
  }

  const dbCheck = await checkPoolConnectivity();
  const poolHealth = getPoolHealth();

  return {
    ready: dbCheck.connected && poolHealth.healthy && !draining,
    timestamp: new Date().toISOString(),
    checks: {
      database: { connected: dbCheck.connected, latencyMs: dbCheck.latencyMs },
      pool: {
        healthy: poolHealth.healthy,
        utilization: poolHealth.utilizationPercent,
        waiting: poolHealth.waitingRequests,
      },
      draining,
      inFlight,
    },
  };
}

export interface LivenessStatus {
  alive: boolean;
  timestamp: string;
  uptime: number;
  pid: number;
  memoryMB: number;
}

export function checkLiveness(): LivenessStatus {
  const mem = process.memoryUsage();
  return {
    alive: true,
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    pid: process.pid,
    memoryMB: Math.round(mem.rss / 1024 / 1024),
  };
}
