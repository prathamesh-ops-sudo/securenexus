import type { Express, Request, Response } from "express";
import { getOrgId, p, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import {
  PERFORMANCE_BUDGETS,
  getCacheHitRatio,
  getIndexHitRates,
  getRecentSlowQueries,
  getTableScanStats,
  getUnusedIndexes,
} from "../db-performance";
import { getPoolHealth, checkPoolConnectivity } from "../db";
import { getDeadLetterJobs, retryDeadLetterJob, scheduleJob } from "../job-queue";
import { getOutboxProcessorStatus } from "../outbox-processor";
import { cacheInvalidate, cacheStats } from "../query-cache";
import { getTableSizes, getPartitionConfigs, runArchivalJob } from "../partition-strategy";
import { runFullRollup, getRollupConfig } from "../metrics-rollup";

export function registerAdminRoutes(app: Express): void {
  app.get("/api/secret-rotations/expiring", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const daysAhead = parseInt(req.query.days as string, 10) || 30;
      const expiring = await storage.getExpiringSecretRotations(daysAhead);
      res.json(expiring);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch expiring rotations" });
    }
  });

  app.get(
    "/api/v1/outbox/events",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const status = typeof req.query.status === "string" ? req.query.status : undefined;
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        const offset = Number(req.query.offset ?? 0) || 0;
        const { items, total } = await storage.getOutboxEvents(orgId, status, limit, offset);
        return sendEnvelope(res, items, { meta: { offset, limit, total, status: status ?? null } });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "OUTBOX_LIST_FAILED", message: "Failed to fetch outbox events", details: error?.message }],
        });
      }
    },
  );

  app.post(
    "/api/v1/outbox/replay/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const eventId = p(req.params.id);
        const replayed = await storage.replayOutboxEvent(eventId);
        if (!replayed) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Event not found or not eligible for replay" }],
          });
        }
        await storage.createAuditLog({
          orgId: (req as any).user?.orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "outbox_event_replayed",
          resourceType: "outbox_event",
          resourceId: eventId,
        });
        return sendEnvelope(res, replayed);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "REPLAY_FAILED", message: "Failed to replay event", details: error?.message }],
        });
      }
    },
  );

  app.post(
    "/api/v1/outbox/replay-batch",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { eventIds } = req.body;
        if (!Array.isArray(eventIds) || eventIds.length === 0) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "eventIds array is required" }],
          });
        }
        const maxBatchSize = 50;
        const ids = eventIds.slice(0, maxBatchSize);
        const results: { id: string; replayed: boolean }[] = [];
        for (const id of ids) {
          const replayed = await storage.replayOutboxEvent(id);
          results.push({ id, replayed: !!replayed });
        }
        return sendEnvelope(res, results, {
          meta: { requested: ids.length, replayed: results.filter((r) => r.replayed).length },
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "BATCH_REPLAY_FAILED", message: "Failed to replay events", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/outbox/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const processorStatus = getOutboxProcessorStatus();
        return sendEnvelope(res, processorStatus);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "STATUS_FAILED", message: "Failed to fetch outbox status", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/cache/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        return sendEnvelope(res, cacheStats());
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "CACHE_STATS_FAILED", message: "Failed to fetch cache stats", details: error?.message }],
        });
      }
    },
  );

  app.post(
    "/api/v1/cache/invalidate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { pattern } = req.body;
        if (!pattern || typeof pattern !== "string") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "pattern string is required" }],
          });
        }
        const removed = cacheInvalidate(pattern);
        return sendEnvelope(res, { removed, pattern });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "CACHE_INVALIDATE_FAILED", message: "Failed to invalidate cache", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/jobs/dead-letter",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const deadLetterJobs = await getDeadLetterJobs();
        return sendEnvelope(res, deadLetterJobs, { meta: { total: deadLetterJobs.length } });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "DEAD_LETTER_FAILED", message: "Failed to fetch dead letter jobs", details: error?.message },
          ],
        });
      }
    },
  );

  app.post(
    "/api/v1/jobs/dead-letter/:id/retry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const jobId = p(req.params.id);
        const retried = await retryDeadLetterJob(jobId);
        if (!retried) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Job not found or not in failed state" }],
          });
        }
        return sendEnvelope(res, retried);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "RETRY_FAILED", message: "Failed to retry dead letter job", details: error?.message }],
        });
      }
    },
  );

  app.post(
    "/api/v1/jobs/schedule",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { type, payload, runAt, priority } = req.body;
        if (!type || !runAt) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "type and runAt are required" }],
          });
        }
        const orgId = getOrgId(req);
        const scheduledJob = await scheduleJob(type, orgId, payload || {}, new Date(runAt), priority);
        return sendEnvelope(res, scheduledJob, { status: 201 });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SCHEDULE_FAILED", message: "Failed to schedule job", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/monitoring/db-performance",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const [indexHitRates, tableScanStats, unusedIndexes, cacheHitRatio, slowQueries] = await Promise.all([
          getIndexHitRates(),
          getTableScanStats(),
          getUnusedIndexes(),
          getCacheHitRatio(),
          Promise.resolve(getRecentSlowQueries()),
        ]);

        return sendEnvelope(res, {
          performanceBudgets: PERFORMANCE_BUDGETS,
          indexHitRates,
          tableScanStats,
          unusedIndexes,
          cacheHitRatio,
          recentSlowQueries: slowQueries,
          queryCacheStats: cacheStats(),
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "DB_PERF_FAILED", message: "Failed to fetch DB performance metrics", details: error?.message },
          ],
        });
      }
    },
  );

  app.get(
    "/api/v1/monitoring/index-stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const [indexHitRates, unusedIndexes] = await Promise.all([getIndexHitRates(), getUnusedIndexes()]);
        return sendEnvelope(res, { indexHitRates, unusedIndexes });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INDEX_STATS_FAILED", message: "Failed to fetch index stats", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/monitoring/slow-queries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        return sendEnvelope(res, { recentSlowQueries: getRecentSlowQueries() });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "SLOW_QUERIES_FAILED", message: "Failed to fetch slow queries", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/monitoring/pool-health",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const [health, connectivity] = await Promise.all([Promise.resolve(getPoolHealth()), checkPoolConnectivity()]);
        return sendEnvelope(res, { pool: health, connectivity });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "POOL_HEALTH_FAILED", message: "Failed to fetch pool health", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/monitoring/table-sizes",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const sizes = await getTableSizes();
        const configs = getPartitionConfigs();
        return sendEnvelope(res, { tables: sizes, partitionConfigs: configs });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TABLE_SIZES_FAILED", message: "Failed to fetch table sizes", details: error?.message }],
        });
      }
    },
  );

  app.post(
    "/api/v1/admin/archival/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const result = await runArchivalJob();
        await storage.createAuditLog({
          orgId: (req as any).user?.orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "manual_archival_run",
          resourceType: "system",
          details: {
            archived: result.results.reduce((s, r) => s + r.archivedCount, 0),
            pruned: result.pruned.reduce((s, r) => s + r.deleted, 0),
            errors: result.errors.length,
          },
        });
        return sendEnvelope(res, result);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ARCHIVAL_FAILED", message: "Failed to run archival job", details: error?.message }],
        });
      }
    },
  );

  app.post(
    "/api/v1/admin/metrics-rollup/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const recovery = req.query.recovery === "true";
        const result = await runFullRollup(recovery);
        await storage.createAuditLog({
          orgId: (req as any).user?.orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "manual_metrics_rollup",
          resourceType: "system",
          details: {
            hourlyRows: result.hourly.rowsInserted,
            dailyRows: result.daily.rowsInserted,
            rawPruned: result.retention.rawDeleted,
            hourlyPruned: result.retention.hourlyDeleted,
          },
        });
        return sendEnvelope(res, result);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ROLLUP_FAILED", message: "Failed to run metrics rollup", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/metrics-rollup/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        return sendEnvelope(res, {
          rollupConfig: getRollupConfig(),
          partitionConfigs: getPartitionConfigs(),
        });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "CONFIG_FAILED", message: "Failed to fetch rollup config", details: error?.message }],
        });
      }
    },
  );
}
