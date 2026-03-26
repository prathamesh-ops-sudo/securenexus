import type { Express, Request, Response } from "express";
import { getCatalogSummary, getAllEventSchemas, getEventsByDomain, type EventDomain } from "../event-catalog";
import { checkLiveness } from "../request-lifecycle";
import { getPoolHealth, checkPoolConnectivity } from "../db";
import { getJobStats } from "../storage/jobs";
import { getConnectors } from "../storage/connectors";
import { logger } from "../logger";

const log = logger.child("health");

async function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  const timeout = new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms));
  return Promise.race([promise, timeout]);
}

export function registerHealthRoutes(app: Express): void {
  app.get("/api/health", async (_req, res) => {
    const liveness = checkLiveness();

    // DB pool health (synchronous -- reads from pool object)
    const dbPool = getPoolHealth();

    // DB connectivity check (async, 2s timeout)
    const dbConnectivity = await withTimeout(
      checkPoolConnectivity(),
      2000,
      { connected: false, latencyMs: -1, serverVersion: "timeout" },
    );

    // Job queue depth (async, 2s timeout)
    const jobQueue = await withTimeout(
      getJobStats(),
      2000,
      { pending: -1, running: -1, completed: -1, failed: -1 },
    );

    // Connector status summary (async, 2s timeout)
    // Pass no orgId to get all connectors across orgs (health check is internal)
    const connectorSummary = await withTimeout(
      getConnectors().then((connectors) => {
        const byStatus: Record<string, number> = {};
        for (const c of connectors) {
          const s = c.status || "unknown";
          byStatus[s] = (byStatus[s] || 0) + 1;
        }
        return { total: connectors.length, byStatus };
      }),
      2000,
      { total: -1, byStatus: {} },
    );

    // AI service availability -- check if AWS_REGION and AWS credentials are configured
    // A lightweight check without actually invoking Bedrock (which would cost money)
    const aiAvailable = !!(process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION);

    // Compute overall status
    const subsystemHealthy =
      dbPool.healthy &&
      dbConnectivity.connected &&
      jobQueue.pending !== -1; // -1 means timeout/failure

    const overallStatus = subsystemHealthy ? "ok" : "degraded";

    res.json({
      status: overallStatus,
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      uptime: liveness.uptime,
      pid: liveness.pid,
      memoryMB: liveness.memoryMB,
      subsystems: {
        database: {
          pool: dbPool,
          connectivity: {
            connected: dbConnectivity.connected,
            latencyMs: dbConnectivity.latencyMs,
          },
        },
        jobQueue: jobQueue,
        connectors: connectorSummary,
        ai: {
          configured: aiAvailable,
          status: aiAvailable ? "available" : "not_configured",
        },
      },
    });
  });

  // Versioned API
  app.get("/api/v1/status", async (_req, res) => {
    res.json({
      version: "1.0.0",
      name: "SecureNexus API",
      status: "operational",
      timestamp: new Date().toISOString(),
    });
  });

  app.get("/api/v1/event-catalog", (_req, res) => {
    const domain = _req.query.domain as string | undefined;
    if (domain) {
      const events = getEventsByDomain(domain as EventDomain);
      res.json({ ok: true, data: events });
      return;
    }
    res.json({ ok: true, data: { summary: getCatalogSummary(), events: getAllEventSchemas() } });
  });
}
