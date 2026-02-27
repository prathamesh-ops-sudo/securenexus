import { storage } from "./storage";
import { db } from "./db";
import { logger } from "./logger";
import { createHash, randomBytes } from "crypto";
import { sql } from "drizzle-orm";
import { startSpan } from "./tracing";

const DEAD_LETTER_MAX_ATTEMPTS = 3;
const VISIBILITY_TIMEOUT_MS = 120_000;
const HEARTBEAT_INTERVAL_MS = 30_000;
const LEASE_EXTENSION_MS = 120_000;
const STALE_JOB_REAPER_INTERVAL_MS = 60_000;
const DEDUP_TTL_MS = 60_000;

const workerId = `worker-${randomBytes(8).toString("hex")}`;

function buildJobFingerprint(type: string, orgId: string, payload: unknown): string {
  const data = JSON.stringify({ type, orgId, payload });
  return createHash("md5").update(data).digest("hex").slice(0, 16);
}

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
      const orgId = job.payload?.orgId;
      if (!orgId) {
        logger.child("job-queue").warn(`Job ${job.id} missing orgId in payload — skipping`);
        return { refreshed: false, error: "Missing orgId in job payload" };
      }
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
      const orgId = job.payload?.orgId;
      if (!orgId) {
        logger.child("job-queue").warn(`Job ${job.id} missing orgId in payload — skipping`);
        return { refreshed: false, error: "Missing orgId in job payload" };
      }
      const beforeDate = job.payload?.beforeDate
        ? new Date(job.payload.beforeDate)
        : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const reason = job.payload?.reason || "cold_storage";
      const oldAlerts = await db.execute(
        sql`SELECT id FROM alerts WHERE org_id = ${orgId} AND created_at < ${beforeDate}`,
      );
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
      const orgId = job.payload?.orgId;
      if (!orgId) {
        logger.child("job-queue").warn(`Job ${job.id} missing orgId in payload — skipping`);
        return { refreshed: false, error: "Missing orgId in job payload" };
      }
      const date = job.payload?.date || new Date().toISOString().split("T")[0];
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
      const row = (result as any).rows?.[0] || {};
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
      const breaches = evaluations.filter((e) => e.breached);
      return { collected: true, totalSlos: evaluations.length, breaches: breaches.length };
    } catch (err: any) {
      return { collected: false, type: "sli_collection", error: err.message || String(err) };
    }
  },
};

let workerRunning = false;
let workerInterval: NodeJS.Timeout | null = null;
let heartbeatInterval: NodeJS.Timeout | null = null;
let reaperInterval: NodeJS.Timeout | null = null;
const POLL_INTERVAL_MS = 5000;
const MAX_CONCURRENT = 4;
let activeJobs = 0;
const activeJobIds = new Set<string>();

async function claimNextJobDistributed(): Promise<any | undefined> {
  const lockedUntil = new Date(Date.now() + VISIBILITY_TIMEOUT_MS);
  const result = await db.execute(sql`
    UPDATE job_queue
    SET status = 'running',
        started_at = NOW(),
        attempts = attempts + 1,
        locked_by = ${workerId},
        locked_until = ${lockedUntil}
    WHERE id = (
      SELECT id FROM job_queue
      WHERE status = 'pending' AND run_at <= NOW()
      ORDER BY priority DESC, run_at ASC
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    RETURNING *
  `);
  const rows = result.rows as any[];
  if (!rows || rows.length === 0) return undefined;
  const row = rows[0];
  return {
    id: row.id,
    orgId: row.org_id,
    type: row.type,
    status: row.status,
    payload: row.payload,
    result: row.result,
    priority: row.priority,
    runAt: row.run_at,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    lastError: row.last_error,
    lockedBy: row.locked_by,
    lockedUntil: row.locked_until,
    fingerprint: row.fingerprint,
    createdAt: row.created_at,
  };
}

async function extendLease(jobId: string): Promise<boolean> {
  const newLockedUntil = new Date(Date.now() + LEASE_EXTENSION_MS);
  const result = await db.execute(sql`
    UPDATE job_queue
    SET locked_until = ${newLockedUntil}
    WHERE id = ${jobId} AND locked_by = ${workerId} AND status = 'running'
  `);
  return (result as any).rowCount > 0;
}

async function runHeartbeats(): Promise<void> {
  for (const jobId of Array.from(activeJobIds)) {
    try {
      const extended = await extendLease(jobId);
      if (!extended) {
        logger.child("job-queue").warn(`Heartbeat failed for job ${jobId} — lease lost`);
        activeJobIds.delete(jobId);
      }
    } catch (err) {
      logger.child("job-queue").error(`Heartbeat error for job ${jobId}`, { error: String(err) });
    }
  }
}

async function reapStaleJobs(): Promise<void> {
  try {
    const result = await db.execute(sql`
      UPDATE job_queue
      SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
          locked_by = NULL,
          locked_until = NULL,
          last_error = CASE WHEN attempts >= max_attempts THEN 'Lease expired — max attempts exhausted' ELSE 'Lease expired — returned to queue' END,
          completed_at = CASE WHEN attempts >= max_attempts THEN NOW() ELSE completed_at END
      WHERE status = 'running'
        AND locked_until < NOW()
        AND locked_until IS NOT NULL
      RETURNING id, status
    `);
    const rows = (result as any).rows || [];
    if (rows.length > 0) {
      const reaped = rows.filter((r: any) => r.status === "pending");
      const deadLettered = rows.filter((r: any) => r.status === "failed");
      if (reaped.length > 0) {
        logger.child("job-queue").warn(`Reaped ${reaped.length} stale jobs back to pending`, {
          jobIds: reaped.map((r: any) => r.id),
        });
      }
      if (deadLettered.length > 0) {
        logger.child("job-queue").error(`Dead-lettered ${deadLettered.length} jobs — max attempts exhausted`, {
          jobIds: deadLettered.map((r: any) => r.id),
        });
      }
    }
  } catch (err) {
    logger.child("job-queue").error("Stale job reaper error", { error: String(err) });
  }
}

async function isDuplicateInDb(type: string, orgId: string, payload: unknown): Promise<boolean> {
  const fp = buildJobFingerprint(type, orgId, payload);
  const result = await db.execute(sql`
    SELECT id FROM job_queue
    WHERE fingerprint = ${fp}
      AND fingerprint_expires_at > NOW()
      AND status IN ('pending', 'running')
    LIMIT 1
  `);
  const rows = (result as any).rows || [];
  return rows.length > 0;
}

export function startJobWorker(): void {
  if (workerRunning) return;
  workerRunning = true;

  logger
    .child("job-queue")
    .info(
      `Started distributed worker ${workerId} — polling every ${POLL_INTERVAL_MS}ms, max concurrency ${MAX_CONCURRENT}`,
    );

  workerInterval = setInterval(async () => {
    if (activeJobs >= MAX_CONCURRENT) return;

    try {
      const job = await claimNextJobDistributed();
      if (!job) return;

      activeJobs++;
      activeJobIds.add(job.id);
      processJob(job).finally(() => {
        activeJobs--;
        activeJobIds.delete(job.id);
      });
    } catch (err) {
      logger.child("job-queue").error("Poll error:", { error: String(err) });
    }
  }, POLL_INTERVAL_MS);

  heartbeatInterval = setInterval(() => {
    runHeartbeats().catch((err) => logger.child("job-queue").error("Heartbeat sweep error", { error: String(err) }));
  }, HEARTBEAT_INTERVAL_MS);

  reaperInterval = setInterval(() => {
    reapStaleJobs().catch((err) => logger.child("job-queue").error("Reaper sweep error", { error: String(err) }));
  }, STALE_JOB_REAPER_INTERVAL_MS);
}

export function stopJobWorker(): void {
  workerRunning = false;
  if (workerInterval) {
    clearInterval(workerInterval);
    workerInterval = null;
  }
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
  if (reaperInterval) {
    clearInterval(reaperInterval);
    reaperInterval = null;
  }
  logger.child("job-queue").info(`Stopped worker ${workerId}`);
}

async function processJob(job: any): Promise<void> {
  const handler = JOB_HANDLERS[job.type];
  if (!handler) {
    const res = await db.execute(sql`
      UPDATE job_queue
      SET status = 'failed',
          last_error = ${`Unknown job type: ${job.type}`},
          completed_at = NOW(),
          locked_by = NULL,
          locked_until = NULL
      WHERE id = ${job.id} AND locked_by = ${workerId}
    `);
    if ((res as any).rowCount === 0) {
      logger.child("job-queue").warn(`Lease lost for job ${job.id} — skipping failed update`);
    }
    return;
  }

  try {
    logger.child("job-queue").info(`Processing job ${job.id} (${job.type}) [worker=${workerId}]`);
    const result = await startSpan("job-queue", `job:${job.type}`, () => handler(job), {
      "job.id": job.id,
      "job.type": job.type,
      "job.orgId": job.orgId ?? "",
      "job.attempt": job.attempts ?? 1,
    });
    const res = await db.execute(sql`
      UPDATE job_queue
      SET status = 'completed',
          result = ${JSON.stringify(result)}::jsonb,
          completed_at = NOW(),
          locked_by = NULL,
          locked_until = NULL
      WHERE id = ${job.id} AND locked_by = ${workerId}
    `);
    if ((res as any).rowCount === 0) {
      logger.child("job-queue").warn(`Lease lost for job ${job.id} — completed result discarded`);
    } else {
      logger.child("job-queue").info(`Completed job ${job.id}`);
    }
  } catch (err: any) {
    const attempts = job.attempts || 0;
    const maxAttempts = job.maxAttempts || DEAD_LETTER_MAX_ATTEMPTS;
    const errorMsg = err.message || String(err);

    if (attempts >= maxAttempts) {
      const res = await db.execute(sql`
        UPDATE job_queue
        SET status = 'failed',
            last_error = ${errorMsg},
            completed_at = NOW(),
            locked_by = NULL,
            locked_until = NULL
        WHERE id = ${job.id} AND locked_by = ${workerId}
      `);
      if ((res as any).rowCount === 0) {
        logger.child("job-queue").warn(`Lease lost for job ${job.id} — failed update discarded`);
      } else {
        logger.child("job-queue").error(`Job ${job.id} failed permanently after ${attempts} attempts`);
      }
    } else {
      const backoffMs = Math.min(60000, 1000 * Math.pow(2, attempts));
      const runAt = new Date(Date.now() + backoffMs);
      const res = await db.execute(sql`
        UPDATE job_queue
        SET status = 'pending',
            last_error = ${errorMsg},
            run_at = ${runAt},
            locked_by = NULL,
            locked_until = NULL
        WHERE id = ${job.id} AND locked_by = ${workerId}
      `);
      if ((res as any).rowCount === 0) {
        logger.child("job-queue").warn(`Lease lost for job ${job.id} — retry update discarded`);
      } else {
        logger.child("job-queue").warn(`Job ${job.id} failed, retrying at ${runAt.toISOString()}`);
      }
    }
  }
}

export function getWorkerStatus(): {
  running: boolean;
  workerId: string;
  activeJobs: number;
  activeJobIds: string[];
  pollIntervalMs: number;
  maxConcurrent: number;
  visibilityTimeoutMs: number;
} {
  return {
    running: workerRunning,
    workerId,
    activeJobs,
    activeJobIds: Array.from(activeJobIds),
    pollIntervalMs: POLL_INTERVAL_MS,
    maxConcurrent: MAX_CONCURRENT,
    visibilityTimeoutMs: VISIBILITY_TIMEOUT_MS,
  };
}

export async function enqueueJob(type: string, orgId: string, payload: any, priority?: number): Promise<any> {
  const fp = buildJobFingerprint(type, orgId, payload);
  const isDuplicate = await isDuplicateInDb(type, orgId, payload);
  if (isDuplicate) {
    logger.child("job-queue").info(`Dedup: skipping duplicate job ${type} for org ${orgId} (fingerprint=${fp})`);
    return null;
  }
  return storage.createJob({
    orgId,
    type,
    status: "pending",
    payload,
    priority: priority || 0,
    runAt: new Date(),
    attempts: 0,
    maxAttempts: DEAD_LETTER_MAX_ATTEMPTS,
    fingerprint: fp,
    fingerprintExpiresAt: new Date(Date.now() + DEDUP_TTL_MS),
  } as any);
}

export async function scheduleJob(
  type: string,
  orgId: string,
  payload: any,
  runAt: Date,
  priority?: number,
): Promise<any> {
  const fp = buildJobFingerprint(type, orgId, payload);
  const isDuplicate = await isDuplicateInDb(type, orgId, payload);
  if (isDuplicate) {
    logger
      .child("job-queue")
      .info(`Dedup: skipping duplicate scheduled job ${type} for org ${orgId} (fingerprint=${fp})`);
    return null;
  }
  return storage.createJob({
    orgId,
    type,
    status: "pending",
    payload,
    priority: priority || 0,
    runAt,
    attempts: 0,
    maxAttempts: DEAD_LETTER_MAX_ATTEMPTS,
    fingerprint: fp,
    fingerprintExpiresAt: new Date(runAt.getTime() + DEDUP_TTL_MS),
  } as any);
}

export async function getDeadLetterJobs(): Promise<any[]> {
  return storage.getJobs(undefined, "failed", undefined, 100);
}

export async function retryDeadLetterJob(jobId: string): Promise<any> {
  const job = await storage.getJob(jobId);
  if (!job || job.status !== "failed") return null;
  return storage.updateJob(jobId, {
    status: "pending",
    attempts: 0,
    lastError: null,
    runAt: new Date(),
    lockedBy: null,
    lockedUntil: null,
  } as any);
}

export async function cleanupExpiredFingerprints(): Promise<number> {
  const result = await db.execute(sql`
    UPDATE job_queue
    SET fingerprint = NULL, fingerprint_expires_at = NULL
    WHERE fingerprint IS NOT NULL
      AND fingerprint_expires_at < NOW()
      AND status IN ('completed', 'failed')
  `);
  return (result as any).rowCount || 0;
}
