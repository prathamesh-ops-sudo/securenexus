import { storage } from "./storage";
import { db } from "./db";

const JOB_HANDLERS: Record<string, (job: any) => Promise<any>> = {
  connector_sync: async (job) => {
    try {
      const { syncConnector } = await import("./connector-engine");
      const connector = await storage.getConnector(job.payload?.connectorId);
      if (!connector) {
        return { synced: false, error: "Connector not found" };
      }
      const result = await syncConnector(connector);
      return { synced: true, ...result };
    } catch (err: any) {
      return { synced: false, type: "connector_sync", error: err.message || String(err) };
    }
  },
  threat_enrichment: async (job) => {
    try {
      const { enrichEntity } = await import("./threat-enrichment");
      const result = await enrichEntity(job.payload?.alertId, true, job.payload?.orgId);
      return { enriched: true, results: result };
    } catch (err: any) {
      return { enriched: false, type: "threat_enrichment", error: err.message || String(err) };
    }
  },
  report_generation: async (job) => {
    try {
      const { generateReportData } = await import("./report-engine");
      const result = await generateReportData(job.payload?.templateId, job.payload?.orgId);
      return { generated: true, ...result };
    } catch (err: any) {
      return { generated: false, type: "report_generation", error: err.message || String(err) };
    }
  },
  cache_refresh: async (job) => {
    try {
      const orgId = job.payload?.orgId || "default";
      const stats = await storage.getDashboardStats(orgId);
      const analytics = await storage.getDashboardAnalytics(orgId);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
      await storage.upsertCachedMetrics({ orgId, metricType: "stats", payload: stats, expiresAt });
      await storage.upsertCachedMetrics({ orgId, metricType: "analytics", payload: analytics, expiresAt });
      return { refreshed: true, orgId, expiresAt: expiresAt.toISOString() };
    } catch (err: any) {
      return { refreshed: false, type: "cache_refresh", error: err.message || String(err) };
    }
  },
  archive_alerts: async (job) => {
    try {
      const orgId = job.payload?.orgId || "default";
      const beforeDate = job.payload?.beforeDate ? new Date(job.payload.beforeDate) : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const reason = job.payload?.reason || "cold_storage";
      const { sql } = await import("drizzle-orm");
      const oldAlerts = await db.execute(sql`SELECT id FROM alerts WHERE org_id = ${orgId} AND created_at < ${beforeDate}`);
      const alertIds = ((oldAlerts as any).rows || []).map((r: any) => r.id);
      if (alertIds.length > 0) {
        const archived = await storage.archiveAlerts(orgId, alertIds, reason);
        return { archived, orgId, beforeDate: beforeDate.toISOString() };
      }
      return { archived: 0, orgId, message: "No alerts to archive" };
    } catch (err: any) {
      return { archived: false, type: "archive_alerts", error: err.message || String(err) };
    }
  },
  daily_stats_rollup: async (job) => {
    try {
      const orgId = job.payload?.orgId || "default";
      const date = job.payload?.date || new Date().toISOString().split("T")[0];
      const { sql } = await import("drizzle-orm");
      const result = await db.execute(sql`
        SELECT
          count(*) as total,
          count(*) FILTER (WHERE severity = 'critical') as critical_count,
          count(*) FILTER (WHERE severity = 'high') as high_count,
          count(*) FILTER (WHERE severity = 'medium') as medium_count,
          count(*) FILTER (WHERE severity = 'low') as low_count,
          count(*) FILTER (WHERE severity = 'informational') as info_count
        FROM alerts
        WHERE org_id = ${orgId}
          AND created_at::date = ${date}::date
      `);
      const row = ((result as any).rows?.[0]) || {};
      await storage.upsertAlertDailyStat({
        orgId,
        date,
        totalAlerts: Number(row.total) || 0,
        criticalCount: Number(row.critical_count) || 0,
        highCount: Number(row.high_count) || 0,
        mediumCount: Number(row.medium_count) || 0,
        lowCount: Number(row.low_count) || 0,
        infoCount: Number(row.info_count) || 0,
        sourceCounts: {},
        categoryCounts: {},
      });
      return { rolledUp: true, orgId, date };
    } catch (err: any) {
      return { rolledUp: false, type: "daily_stats_rollup", error: err.message || String(err) };
    }
  },
  sli_collection: async (_job) => {
    try {
      const { evaluateSlos } = await import("./sli-middleware");
      const evaluations = await evaluateSlos();
      const breaches = evaluations.filter(e => e.breached);
      return { collected: true, totalSlos: evaluations.length, breaches: breaches.length };
    } catch (err: any) {
      return { collected: false, type: "sli_collection", error: err.message || String(err) };
    }
  },
};

let workerRunning = false;
let workerInterval: NodeJS.Timeout | null = null;
const POLL_INTERVAL_MS = 5000;
const MAX_CONCURRENT = 2;
let activeJobs = 0;

export function startJobWorker(): void {
  if (workerRunning) return;
  workerRunning = true;

  console.log("[JobWorker] Started - polling every 5s");

  workerInterval = setInterval(async () => {
    if (activeJobs >= MAX_CONCURRENT) return;

    try {
      const job = await storage.claimNextJob();
      if (!job) return;

      activeJobs++;
      processJob(job).finally(() => { activeJobs--; });
    } catch (err) {
      console.error("[JobWorker] Poll error:", err);
    }
  }, POLL_INTERVAL_MS);
}

export function stopJobWorker(): void {
  workerRunning = false;
  if (workerInterval) {
    clearInterval(workerInterval);
    workerInterval = null;
  }
  console.log("[JobWorker] Stopped");
}

async function processJob(job: any): Promise<void> {
  const handler = JOB_HANDLERS[job.type];
  if (!handler) {
    await storage.updateJob(job.id, {
      status: "failed",
      lastError: `Unknown job type: ${job.type}`,
      completedAt: new Date(),
    });
    return;
  }

  try {
    console.log(`[JobWorker] Processing job ${job.id} (${job.type})`);
    const result = await handler(job);
    await storage.updateJob(job.id, {
      status: "completed",
      result,
      completedAt: new Date(),
    });
    console.log(`[JobWorker] Completed job ${job.id}`);
  } catch (err: any) {
    const attempts = (job.attempts || 0);
    const maxAttempts = job.maxAttempts || 3;

    if (attempts >= maxAttempts) {
      await storage.updateJob(job.id, {
        status: "failed",
        lastError: err.message || String(err),
        completedAt: new Date(),
      });
      console.error(`[JobWorker] Job ${job.id} failed permanently after ${attempts} attempts`);
    } else {
      const backoffMs = Math.min(60000, 1000 * Math.pow(2, attempts));
      const runAt = new Date(Date.now() + backoffMs);
      await storage.updateJob(job.id, {
        status: "pending",
        lastError: err.message || String(err),
        runAt,
      });
      console.warn(`[JobWorker] Job ${job.id} failed, retrying at ${runAt.toISOString()}`);
    }
  }
}

export function getWorkerStatus(): { running: boolean; activeJobs: number; pollIntervalMs: number } {
  return { running: workerRunning, activeJobs, pollIntervalMs: POLL_INTERVAL_MS };
}

export async function enqueueJob(type: string, orgId: string, payload: any, priority?: number): Promise<any> {
  return storage.createJob({
    orgId,
    type,
    status: "pending",
    payload,
    priority: priority || 0,
    runAt: new Date(),
    attempts: 0,
    maxAttempts: 3,
  });
}
