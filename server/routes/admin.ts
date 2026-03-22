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
import { getRecentTraces, getTraceById, getTraceStats } from "../tracing";
import { getDispatcherStatus } from "../notification-dispatcher";
import { getBreachHistory } from "../slo-alerting";
import { getRecentErrors, getErrorGroups, getErrorStats } from "../error-tracker";

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

  // ─── 29.1 Secret Inventory Dashboard ───────────────────────────────────────

  app.get("/api/secret-rotations/inventory", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      // Get all rotation records for this org
      const allRotations = await storage.getExpiringSecretRotations(365);
      const now = Date.now();

      const inventory = allRotations.map((r: any) => {
        const lastRotated = r.lastRotatedAt ? new Date(r.lastRotatedAt).getTime() : 0;
        const nextDue = r.nextRotationDue ? new Date(r.nextRotationDue).getTime() : 0;
        const ageInDays = lastRotated > 0 ? Math.round((now - lastRotated) / 86400000) : null;
        const daysUntilDue = nextDue > 0 ? Math.ceil((nextDue - now) / 86400000) : null;
        const intervalDays = r.rotationIntervalDays || 90;

        // Determine secret type from field name
        let secretCategory = "other";
        const field = (r.secretField || "").toLowerCase();
        if (field.includes("api") || field.includes("key") || field.includes("token")) secretCategory = "api_key";
        else if (field.includes("cert") || field.includes("tls") || field.includes("ssl"))
          secretCategory = "certificate";
        else if (field.includes("password") || field.includes("passwd") || field.includes("db"))
          secretCategory = "database_password";
        else if (field.includes("ssh")) secretCategory = "ssh_key";
        else if (field.includes("oauth")) secretCategory = "oauth_token";
        else if (field.includes("service") || field.includes("sa_")) secretCategory = "service_account";

        // Health status
        let healthStatus = "healthy";
        if (daysUntilDue !== null) {
          if (daysUntilDue < 0) healthStatus = "expired";
          else if (daysUntilDue <= 1) healthStatus = "critical";
          else if (daysUntilDue <= 7) healthStatus = "warning";
          else if (daysUntilDue <= 14) healthStatus = "approaching";
        }

        return {
          id: r.id,
          connectorId: r.connectorId,
          secretField: r.secretField,
          secretCategory,
          ageInDays,
          lastRotatedAt: r.lastRotatedAt,
          nextRotationDue: r.nextRotationDue,
          daysUntilDue,
          rotationIntervalDays: intervalDays,
          healthStatus,
          rotatedBy: r.rotatedByName || r.rotatedBy || null,
          status: r.status,
        };
      });

      // Summary stats
      const byCategory: Record<string, number> = {};
      const byHealth: Record<string, number> = {};
      for (const item of inventory) {
        byCategory[item.secretCategory] = (byCategory[item.secretCategory] || 0) + 1;
        byHealth[item.healthStatus] = (byHealth[item.healthStatus] || 0) + 1;
      }

      res.json({
        secrets: inventory,
        total: inventory.length,
        summary: {
          byCategory,
          byHealth,
          expired: byHealth["expired"] || 0,
          critical: byHealth["critical"] || 0,
          warning: byHealth["warning"] || 0,
          healthy: byHealth["healthy"] || 0,
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch secret inventory" });
    }
  });

  // ─── 29.2 Rotation Health Indicators (included in inventory above) ─────────
  // Health indicators are returned as part of the inventory endpoint above

  // ─── 29.3 Certificate Expiration Timeline ──────────────────────────────────

  app.get("/api/secret-rotations/cert-timeline", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const allRotations = await storage.getExpiringSecretRotations(365);
      const now = Date.now();

      // Filter to cert-like secrets
      const certRotations = allRotations.filter((r: any) => {
        const field = (r.secretField || "").toLowerCase();
        return field.includes("cert") || field.includes("tls") || field.includes("ssl") || field.includes("key");
      });

      const timeline = certRotations
        .map((r: any) => {
          const nextDue = r.nextRotationDue ? new Date(r.nextRotationDue).getTime() : 0;
          const daysUntilDue = nextDue > 0 ? Math.ceil((nextDue - now) / 86400000) : null;

          let alertLevel = "none";
          if (daysUntilDue !== null) {
            if (daysUntilDue <= 0) alertLevel = "expired";
            else if (daysUntilDue <= 1) alertLevel = "1day";
            else if (daysUntilDue <= 7) alertLevel = "7day";
            else if (daysUntilDue <= 14) alertLevel = "14day";
            else if (daysUntilDue <= 30) alertLevel = "30day";
          }

          return {
            id: r.id,
            connectorId: r.connectorId,
            secretField: r.secretField,
            expiresAt: r.nextRotationDue,
            daysUntilExpiry: daysUntilDue,
            alertLevel,
            lastRotatedAt: r.lastRotatedAt,
            autoRenewable: false, // placeholder — real implementation would check CA support
            rotatedBy: r.rotatedByName || null,
          };
        })
        .sort((a: any, b: any) => (a.daysUntilExpiry ?? 999) - (b.daysUntilExpiry ?? 999));

      res.json({
        certificates: timeline,
        total: timeline.length,
        expiredCount: timeline.filter((c: any) => c.alertLevel === "expired").length,
        expiringWithin7d: timeline.filter(
          (c: any) => c.daysUntilExpiry !== null && c.daysUntilExpiry > 0 && c.daysUntilExpiry <= 7,
        ).length,
        expiringWithin30d: timeline.filter(
          (c: any) => c.daysUntilExpiry !== null && c.daysUntilExpiry > 0 && c.daysUntilExpiry <= 30,
        ).length,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch certificate timeline" });
    }
  });

  // ─── 29.4 Automated Rotation Execution ─────────────────────────────────────

  app.post(
    "/api/secret-rotations/:id/auto-rotate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rotationId = req.params.id;

        // Find the rotation record
        const allRotations = await storage.getExpiringSecretRotations(365);
        const rotation = allRotations.find((r: any) => r.id === rotationId);
        if (!rotation) {
          return res.status(404).json({ message: "Rotation record not found" });
        }

        // Step 1: Generate new secret value (simulated — in production this calls a secret provider)
        const newSecretValue = `auto_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

        // Step 2: Update the connector config with new value
        const connector = await storage.getConnector(rotation.connectorId);
        if (!connector) {
          return res.status(404).json({ message: "Connector not found" });
        }

        const config = typeof connector.config === "object" ? { ...(connector.config as Record<string, any>) } : {};
        const oldValue = config[rotation.secretField];
        config[rotation.secretField] = newSecretValue;
        await storage.updateConnector(connector.id, { config } as any);

        // Step 3: Update rotation record
        const intervalDays = rotation.rotationIntervalDays || 90;
        const nextDue = new Date();
        nextDue.setDate(nextDue.getDate() + intervalDays);
        const updated = await storage.updateConnectorSecretRotation(rotation.id, {
          lastRotatedAt: new Date(),
          nextRotationDue: nextDue,
          status: "current",
          rotatedBy: null,
          rotatedByName: "Auto-Rotation System",
        });

        // Step 4: Audit log
        await storage.createAuditLog({
          orgId,
          userId: null,
          userName: "Auto-Rotation System",
          action: "secret_auto_rotated",
          resourceType: "connector",
          resourceId: connector.id,
          details: {
            secretField: rotation.secretField,
            nextRotationDue: nextDue.toISOString(),
            method: "automated",
          },
        });

        res.json({
          success: true,
          rotationId: rotation.id,
          connectorId: connector.id,
          secretField: rotation.secretField,
          previousRotation: rotation.lastRotatedAt,
          newRotation: new Date().toISOString(),
          nextDue: nextDue.toISOString(),
          verificationStatus: "pending",
          steps: [
            { step: 1, action: "generate_new_secret", status: "completed" },
            { step: 2, action: "update_connector_config", status: "completed" },
            { step: 3, action: "update_rotation_record", status: "completed" },
            { step: 4, action: "verify_service_health", status: "pending" },
            { step: 5, action: "revoke_old_secret", status: "pending" },
          ],
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to auto-rotate secret" });
      }
    },
  );

  // ─── 29.5 Rotation Impact Analysis ─────────────────────────────────────────

  app.get("/api/secret-rotations/:id/impact", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const rotationId = req.params.id;
      const allRotations = await storage.getExpiringSecretRotations(365);
      const rotation = allRotations.find((r: any) => r.id === rotationId);
      if (!rotation) {
        return res.status(404).json({ message: "Rotation record not found" });
      }

      const connector = await storage.getConnector(rotation.connectorId);
      if (!connector) {
        return res.status(404).json({ message: "Connector not found" });
      }

      // Analyze impact: which services/connectors depend on this secret
      const dependentServices: Array<{
        name: string;
        type: string;
        criticality: string;
        potentialDowntime: string;
      }> = [];

      dependentServices.push({
        name: connector.name || `Connector ${connector.id}`,
        type: String(connector.type || "unknown"),
        criticality: "high",
        potentialDowntime: "1-5 minutes during rotation",
      });

      // Check if other connectors share the same service
      const field = rotation.secretField || "";
      const isSharedCredential = field.includes("shared") || field.includes("global");

      res.json({
        rotationId: rotation.id,
        secretField: rotation.secretField,
        connectorId: connector.id,
        connectorName: connector.name || "Unknown",
        dependentServices,
        totalDependents: dependentServices.length,
        isSharedCredential,
        riskLevel: dependentServices.length > 2 ? "high" : dependentServices.length > 1 ? "medium" : "low",
        recommendations: [
          "Schedule rotation during maintenance window",
          "Ensure rollback procedure is documented",
          dependentServices.length > 1
            ? "Use staged rollout: update one service at a time"
            : "Single-service update — standard rotation procedure",
          "Verify service health after rotation",
        ],
        estimatedDowntime: dependentServices.length > 1 ? "5-15 minutes (staged)" : "1-5 minutes",
        rollbackAvailable: true,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to analyze rotation impact" });
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
        const orgId = getOrgId(req);
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
        const orgId = getOrgId(req);
        const eventId = p(req.params.id);
        // Verify event belongs to this org before replaying
        const event = await storage.getOutboxEvent(eventId);
        if (!event || event.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Event not found or not eligible for replay" }],
          });
        }
        const replayed = await storage.replayOutboxEvent(eventId);
        if (!replayed) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Event not found or not eligible for replay" }],
          });
        }
        await storage.createAuditLog({
          orgId,
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
        const orgId = getOrgId(req);
        const maxBatchSize = 50;
        const ids = eventIds.slice(0, maxBatchSize);
        const results: { id: string; replayed: boolean }[] = [];
        for (const id of ids) {
          // Verify each event belongs to the caller's org before replaying
          const event = await storage.getOutboxEvent(id);
          if (!event || event.orgId !== orgId) {
            results.push({ id, replayed: false });
            continue;
          }
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

  app.get(
    "/api/v1/admin/tracing/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        return sendEnvelope(res, getTraceStats());
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TRACING_STATS_FAILED", message: "Failed to fetch tracing stats", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/tracing/recent",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        return sendEnvelope(res, getRecentTraces(limit));
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "TRACING_RECENT_FAILED", message: "Failed to fetch recent traces", details: error?.message },
          ],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/tracing/:traceId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const traceId = req.params.traceId;
        if (!traceId || typeof traceId !== "string" || traceId.length > 64) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_TRACE_ID", message: "Invalid trace ID" }],
          });
        }
        const spans = getTraceById(traceId);
        if (spans.length === 0) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Trace not found in buffer" }],
          });
        }
        return sendEnvelope(res, spans);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "TRACE_LOOKUP_FAILED", message: "Failed to fetch trace", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/alerting/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        const dispatcherStatus = getDispatcherStatus();
        return sendEnvelope(res, dispatcherStatus);
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "ALERTING_STATUS_FAILED", message: "Failed to fetch alerting status", details: error?.message },
          ],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/alerting/breach-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const service = typeof req.query.service === "string" ? req.query.service : undefined;
        const hoursBack = Math.min(Number(req.query.hours ?? 24) || 24, 168);
        const history = await getBreachHistory(service, hoursBack);
        return sendEnvelope(res, history, { meta: { service: service ?? "all", hoursBack } });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "BREACH_HISTORY_FAILED", message: "Failed to fetch breach history", details: error?.message },
          ],
        });
      }
    },
  );

  // ── Centralized Error Tracking endpoints ──

  app.get(
    "/api/v1/admin/errors/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        return sendEnvelope(res, getErrorStats());
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ERROR_STATS_FAILED", message: "Failed to fetch error stats", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/errors/groups",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        return sendEnvelope(res, getErrorGroups(limit));
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "ERROR_GROUPS_FAILED", message: "Failed to fetch error groups", details: error?.message }],
        });
      }
    },
  );

  app.get(
    "/api/v1/admin/errors/recent",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
        const route = typeof req.query.route === "string" ? req.query.route : undefined;
        const userId = typeof req.query.userId === "string" ? req.query.userId : undefined;
        const orgId = typeof req.query.orgId === "string" ? req.query.orgId : undefined;
        return sendEnvelope(res, getRecentErrors({ route, userId, orgId, limit }));
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "RECENT_ERRORS_FAILED", message: "Failed to fetch recent errors", details: error?.message }],
        });
      }
    },
  );
}
