import type { Express, Request, Response } from "express";
import { logger, p, publishOutboxEvent, sanitizeConfig, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, requirePermission, resolveOrgContext } from "../rbac";
import { bodySchemas, validateBody, validatePathId } from "../request-validator";
import { validateConnectorConfig } from "../connector-config-validator";
import {
  getAllConnectorTypes,
  getConnectorMetadata,
  getProviderSyncStats,
  setProviderConcurrency,
  syncConnector,
  syncConnectorWithRetry,
  testConnector,
  type ConnectorConfig,
} from "../connector-engine";
import { parsePaginationParams } from "../db-performance";
import { cacheInvalidate } from "../query-cache";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { sendEmail } from "../email-service";
import { getConnectorHealthStatus } from "../connector-health-loop";
import {
  getAllCircuitBreakerStates,
  getCircuitBreakerState,
  resetConnectorCircuitBreaker,
} from "../connector-circuit-breaker";
import { resolveAndLinkEntities } from "../entity-resolver";
import { correlateAlert } from "../correlation-engine";
import { errorMessage, errorStack } from "../utils/errors";

export function registerConnectorsRoutes(app: Express): void {
  // Connector Engine Routes
  app.get("/api/connectors/types", isAuthenticated, async (_req, res) => {
    const types = getAllConnectorTypes();
    const metadata = types.map((t) => ({ type: t, ...getConnectorMetadata(t) })).filter((m) => m.name);
    res.json(metadata);
  });

  app.get("/api/connectors", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { offset, limit } = parsePaginationParams(req.query as Record<string, unknown>);

      // Use DB-layer pagination instead of loading all connectors into memory
      const { items } = await storage.getConnectorsPaginated({ orgId, offset, limit });
      const sanitized = items.map((c) => ({ ...c, config: sanitizeConfig(c.config) }));
      res.json(sanitized);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connectors" });
    }
  });

  app.get("/api/connectors/dead-letters", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { offset, limit } = parsePaginationParams(req.query as Record<string, unknown>);

      // Use DB-layer pagination instead of loading all dead-letter runs into memory
      const { items } = await storage.getDeadLetterJobRunsPaginated({ orgId, offset, limit });
      res.json(items);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dead-letter job runs" });
    }
  });

  // Retry a dead-letter job run
  app.post(
    "/api/connectors/dead-letters/:id/retry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId;
        const jobRun = await storage.getConnectorJobRunById(p(req.params.id));
        if (!jobRun || !jobRun.isDeadLetter) {
          return res.status(404).json({ message: "Dead letter entry not found" });
        }
        if (jobRun.orgId && jobRun.orgId !== orgId) {
          return res.status(404).json({ message: "Dead letter entry not found" });
        }
        const connector = await storage.getConnector(jobRun.connectorId);
        if (!connector) {
          return res.status(404).json({ message: "Associated connector no longer exists" });
        }
        // Mark old dead letter as retried
        await storage.updateConnectorJobRun(jobRun.id, {
          isDeadLetter: false,
          status: "retried",
        });
        // Trigger a fresh sync
        const { jobRun: newJobRun, syncResult } = await syncConnectorWithRetry(connector);
        await storage.createAuditLog({
          orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "dead_letter_retried",
          resourceType: "connector",
          resourceId: connector.id,
          details: { originalJobRunId: jobRun.id, newJobRunId: newJobRun.id },
        });
        cacheInvalidate("dashboard:");
        res.json({
          success: newJobRun.status !== "failed",
          newJobRunId: newJobRun.id,
          status: newJobRun.status,
          alertsReceived: syncResult.alertsReceived,
          errors: syncResult.errors,
        });
      } catch (error: unknown) {
        logger.child("routes").error("Dead letter retry failed", { error: String(error) });
        res.status(500).json({ message: "Failed to retry dead letter entry" });
      }
    },
  );

  // Check dead letter count and alert admins if threshold exceeded
  app.post(
    "/api/connectors/dead-letters/check-alert",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId;
        const allDeadLetters = await storage.getDeadLetterJobRuns(orgId);
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const recentDeadLetters = allDeadLetters.filter((dl) => dl.startedAt && new Date(dl.startedAt) >= oneHourAgo);
        if (recentDeadLetters.length >= 10) {
          // Fetch org admin emails
          const org = await storage.getOrganization(orgId);
          const orgName = org?.name || orgId;
          const adminUsers = await storage.getOrgAdminEmails(orgId);
          if (adminUsers.length > 0) {
            await sendEmail({
              to: adminUsers,
              subject: `[SecureNexus] Dead Letter Alert: ${recentDeadLetters.length} failed connector jobs in the last hour`,
              html: `
                <h2>Dead Letter Queue Alert</h2>
                <p>Organization <strong>${orgName}</strong> has accumulated <strong>${recentDeadLetters.length}</strong> dead-letter entries in the past hour.</p>
                <p>This indicates connector sync failures that have exhausted all retry attempts.</p>
                <h3>Recent Failures:</h3>
                <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;font-size:13px;">
                  <tr><th>Connector</th><th>Error</th><th>Time</th></tr>
                  ${recentDeadLetters
                    .slice(0, 10)
                    .map(
                      (dl) =>
                        `<tr><td>${dl.connectorId}</td><td>${dl.errorMessage || "Unknown"}</td><td>${dl.startedAt ? new Date(dl.startedAt).toISOString() : "-"}</td></tr>`,
                    )
                    .join("")}
                </table>
                <p>Please review the Dead Letter Queue tab on the Connectors page.</p>
              `,
            });
          }
          res.json({ alerted: true, count: recentDeadLetters.length, recipients: adminUsers.length });
        } else {
          res.json({ alerted: false, count: recentDeadLetters.length });
        }
      } catch (error: unknown) {
        logger.child("routes").error("Dead letter alert check failed", { error: String(error) });
        res.status(500).json({ message: "Failed to check dead letter alerts" });
      }
    },
  );

  // ============================
  // Connector Health Status (aggregated from in-memory health loop + circuit breakers)
  // ============================
  app.get("/api/connectors/health-status", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      if (!orgId) {
        return res.status(401).json({ message: "Organization context required" });
      }

      // Fetch all connectors for the user's org
      const { items: connectors } = await storage.getConnectorsPaginated({ orgId, offset: 0, limit: 1000 });

      const healthStates = getConnectorHealthStatus();
      const circuitBreakerStates = getAllCircuitBreakerStates();

      const results = connectors.map((connector) => {
        const health = healthStates.get(connector.id);
        const cb = circuitBreakerStates.get(connector.id);

        return {
          connectorId: connector.id,
          connectorName: connector.name,
          connectorType: connector.type,
          health: health
            ? {
                status: health.status,
                consecutiveFailures: health.consecutiveFailures,
                lastCheckAt: health.lastCheckAt || null,
                lastSuccessAt: health.lastSuccessAt || null,
                latencyMs: health.latencyMs,
                restartCount: health.restartCount,
                nextRestartAt: health.nextRestartAt || null,
              }
            : null,
          circuitBreaker: cb
            ? {
                state: cb.state,
                failures: cb.failures,
                openUntil: cb.openUntil || null,
              }
            : null,
        };
      });

      res.json(results);
    } catch (error: unknown) {
      logger.child("routes").error("Failed to fetch connector health status", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch connector health status" });
    }
  });

  // Reset circuit breaker for a specific connector
  app.post(
    "/api/connectors/:id/circuit-breaker/reset",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId;
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector || connector.orgId !== orgId) {
          return res.status(404).json({ message: "Connector not found" });
        }

        resetConnectorCircuitBreaker(connector.id);
        const newState = getCircuitBreakerState(connector.id);

        await storage.createAuditLog({
          orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "circuit_breaker_reset",
          resourceType: "connector",
          resourceId: connector.id,
          details: { connectorName: connector.name, connectorType: connector.type },
        });

        res.json({
          connectorId: connector.id,
          circuitBreaker: {
            state: newState.state,
            failures: newState.failures,
            openUntil: newState.openUntil || null,
          },
        });
      } catch (error: unknown) {
        logger.child("routes").error("Failed to reset circuit breaker", { error: String(error) });
        res.status(500).json({ message: "Failed to reset circuit breaker" });
      }
    },
  );

  app.get("/api/connectors/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }
      const safeConfig = sanitizeConfig(connector.config);
      res.json({ ...connector, config: safeConfig });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connector" });
    }
  });

  app.post(
    "/api/connectors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    enforcePlanLimit("connectors"),
    validateBody(bodySchemas.connectorCreate),
    async (req, res) => {
      try {
        const { name, type, authType, config, pollingIntervalMin } = (req as any).validatedBody;
        const configValidation = validateConnectorConfig(type, config);
        if (!configValidation.valid) {
          return res.status(400).json({ message: "Invalid connector configuration", errors: configValidation.errors });
        }
        const connector = await storage.createConnector({
          name,
          type,
          authType,
          config,
          pollingIntervalMin: pollingIntervalMin || 5,
          createdBy: (req as any).user?.id,
          orgId: (req as any).orgId,
        });
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "connector_created",
          resourceType: "connector",
          resourceId: connector.id,
          details: { type, name },
        });
        publishOutboxEvent(connector.orgId, "connector.synced", "connector", connector.id, {
          type,
          name,
        });
        // connectors is a resource-count metric — enforcement queries active count directly
        res.status(201).json({ ...connector, config: sanitizeConfig(connector.config) });
      } catch (error: unknown) {
        logger.child("routes").error("Route error", { error: String(error) });
        res.status(500).json({ message: "Failed to create connector. Please try again." });
      }
    },
  );

  app.patch(
    "/api/connectors/:id",
    isAuthenticated,
    resolveOrgContext,
    requirePermission("connectors", "write"),
    validatePathId("id"),
    validateBody(bodySchemas.connectorUpdate),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector || !orgId || connector.orgId !== orgId) {
          return res.status(404).json({ message: "Connector not found" });
        }
        const { name, config, status, pollingIntervalMin } = (req as any).validatedBody;
        const updateData: any = {};
        if (name) updateData.name = name;
        if (config) {
          const existingConfig = connector.config as ConnectorConfig;
          const newConfig = { ...existingConfig };
          for (const [key, value] of Object.entries(config)) {
            if (value !== "••••••••" && value !== undefined) {
              (newConfig as any)[key] = value;
            }
          }
          updateData.config = newConfig;
        }
        if (status) updateData.status = status;
        if (pollingIntervalMin) updateData.pollingIntervalMin = pollingIntervalMin;
        const updated = await storage.updateConnector(p(req.params.id), updateData);
        if (!updated) {
          return res.status(404).json({ message: "Connector not found" });
        }
        res.json({ ...updated, config: sanitizeConfig(updated.config) });
      } catch (error: unknown) {
        logger.child("routes").error("Route error", { error: String(error) });
        res.status(500).json({ message: "Failed to update connector. Please try again." });
      }
    },
  );

  app.delete(
    "/api/connectors/:id",
    isAuthenticated,
    resolveOrgContext,
    requirePermission("connectors", "admin"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector || !orgId || connector.orgId !== orgId) {
          return res.status(404).json({ message: "Connector not found" });
        }
        await storage.deleteConnector(p(req.params.id));
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "connector_deleted",
          resourceType: "connector",
          resourceId: p(req.params.id),
          details: { type: connector.type, name: connector.name },
        });
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete connector" });
      }
    },
  );

  app.post("/api/connectors/:id/test", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }
      const config = connector.config as ConnectorConfig;
      const result = await testConnector(connector.type, config);
      res.json(result);
    } catch (error: unknown) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  app.post("/api/connectors/test", isAuthenticated, validateBody(bodySchemas.connectorTest), async (req, res) => {
    try {
      const { type, config } = (req as any).validatedBody;
      const configValidation = validateConnectorConfig(type, config);
      if (!configValidation.valid) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid connector configuration", errors: configValidation.errors });
      }
      const result = await testConnector(type, config);
      res.json(result);
    } catch (error: unknown) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  // Reset connector sync state to force full re-sync
  app.post("/api/connectors/:id/reset-sync", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }
      await storage.updateConnectorSyncStatus(connector.id, {
        lastSyncAt: null as unknown as Date,
        lastSyncAlerts: 0,
      });
      sendEnvelope(res, { success: true, message: "Sync state reset — next sync will pull all historical alerts" });
    } catch (error) {
      logger.child("routes").error("Reset sync error", { error: String(error) });
      res.status(500).json({ message: "Failed to reset sync state" });
    }
  });

  app.post("/api/connectors/:id/sync", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      let connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }

      // Support ?fullSync=true to ignore lastSyncAt and pull all historical alerts
      if (req.query.fullSync === "true" && connector.lastSyncAt) {
        await storage.updateConnectorSyncStatus(connector.id, {
          lastSyncAt: null as unknown as Date,
          lastSyncAlerts: 0,
        });
        connector = (await storage.getConnector(connector.id))!;
      }

      await storage.updateConnector(connector.id, { status: "syncing" } as any);

      const { jobRun, syncResult } = await syncConnectorWithRetry(connector);

      let created = 0;
      let deduped = 0;
      let failed = syncResult.alertsFailed;
      const UPSERT_BATCH = 50;

      for (let i = 0; i < syncResult.rawAlerts.length; i += UPSERT_BATCH) {
        const batch = syncResult.rawAlerts.slice(i, i + UPSERT_BATCH);
        const results = await Promise.allSettled(batch.map((alertData) => storage.upsertAlert(alertData as any)));
        for (const r of results) {
          if (r.status === "fulfilled") {
            if (r.value.isNew) {
              created++;
              // Fire-and-forget entity extraction and correlation
              resolveAndLinkEntities(r.value.alert)
                .then(() => correlateAlert(r.value.alert))
                .catch((err) => {
                  logger.child("connectors").warn("Entity/correlation warning during sync", { error: String(err) });
                });
            } else deduped++;
          } else {
            failed++;
            syncResult.errors.push(`DB insert failed: ${r.reason?.message ?? "unknown"}`);
          }
        }
      }

      const totalSynced = (connector.totalAlertsSynced || 0) + created;
      const syncStatus = syncResult.errors.length > 0 && created === 0 ? "error" : "success";

      await storage.updateConnectorSyncStatus(connector.id, {
        lastSyncAt: new Date(),
        lastSyncStatus: syncStatus,
        lastSyncAlerts: created,
        lastSyncError: syncResult.errors.length > 0 ? syncResult.errors[0] : undefined,
        totalAlertsSynced: totalSynced,
      });

      await storage.updateConnector(connector.id, { status: syncStatus === "error" ? "error" : "active" } as any);

      await storage.createIngestionLog({
        source: connector.type,
        status: syncStatus,
        alertsReceived: syncResult.alertsReceived,
        alertsCreated: created,
        alertsDeduped: deduped,
        alertsFailed: failed,
        errorMessage: syncResult.errors.length > 0 ? syncResult.errors.join("; ") : undefined,
        requestId: `sync_${connector.id}_${Date.now()}`,
      });

      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Analyst",
        action: "connector_synced",
        resourceType: "connector",
        resourceId: connector.id,
        details: {
          type: connector.type,
          received: syncResult.alertsReceived,
          created,
          deduped,
          failed,
          jobRunId: jobRun.id,
        },
      });

      cacheInvalidate("dashboard:");
      cacheInvalidate("ingestion:");

      res.json({
        success: syncStatus !== "error",
        jobRunId: jobRun.id,
        alertsReceived: syncResult.alertsReceived,
        alertsCreated: created,
        alertsDeduped: deduped,
        alertsFailed: failed,
        errors: syncResult.errors,
      });
    } catch (error: unknown) {
      const connector = await storage.getConnector(p(req.params.id));
      if (connector) {
        await storage.updateConnectorSyncStatus(connector.id, {
          lastSyncAt: new Date(),
          lastSyncStatus: "error",
          lastSyncAlerts: 0,
          lastSyncError: errorMessage(error),
        });
        await storage.updateConnector(connector.id, { status: "error" } as any);
      }
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Sync failed. Please try again." });
    }
  });

  app.get("/api/connectors/:id/jobs", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const runs = await storage.getConnectorJobRuns(p(req.params.id), limit);
      res.json(runs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch job runs" });
    }
  });

  app.get("/api/connectors/:id/metrics", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const metrics = await storage.getConnectorMetrics(p(req.params.id));
      res.json(metrics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connector metrics" });
    }
  });

  app.post("/api/connectors/:id/health-check", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const startTime = Date.now();
      let status = "healthy";
      let errMsg: string | undefined;
      try {
        const result = await testConnector(connector.type, config);
        if (!result.success) {
          status = "unhealthy";
          errMsg = result.message || "Connection test failed";
        }
      } catch (err: unknown) {
        status = "unhealthy";
        errMsg = errorMessage(err) || "Connection test error";
      }
      const latencyMs = Date.now() - startTime;
      const healthCheck = await storage.createConnectorHealthCheck({
        connectorId: connector.id,
        orgId: connector.orgId,
        status,
        latencyMs,
        errorMessage: errMsg,
        credentialStatus: status === "healthy" ? "valid" : "unknown",
      });
      res.status(201).json(healthCheck);
    } catch (error) {
      res.status(500).json({ message: "Failed to run health check" });
    }
  });

  app.get("/api/connectors/:id/health", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const checks = await storage.getConnectorHealthChecks(p(req.params.id), limit);
      res.json(checks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch health checks" });
    }
  });

  // ============================
  // Connector Secret Rotation
  // ============================
  app.get("/api/connectors/:id/secret-rotations", isAuthenticated, async (req, res) => {
    try {
      const rotations = await storage.getConnectorSecretRotations(p(req.params.id));
      res.json(rotations);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch secret rotations" });
    }
  });

  app.post(
    "/api/connectors/:id/secret-rotations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = (req as any).orgId;
        const user = (req as any).user;
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector) return res.status(404).json({ message: "Connector not found" });
        const { secretField, rotationIntervalDays } = req.body;
        if (!secretField) return res.status(400).json({ message: "secretField is required" });
        const intervalDays = rotationIntervalDays || 90;
        const nextDue = new Date();
        nextDue.setDate(nextDue.getDate() + intervalDays);
        const rotation = await storage.createConnectorSecretRotation({
          connectorId: connector.id,
          orgId,
          secretField,
          rotationIntervalDays: intervalDays,
          lastRotatedAt: new Date(),
          nextRotationDue: nextDue,
          rotatedBy: user?.id,
          rotatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
        });
        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
          action: "connector_secret_rotation_created",
          resourceType: "connector",
          resourceId: connector.id,
          details: { secretField, rotationIntervalDays: intervalDays },
        });
        res.status(201).json(rotation);
      } catch (error) {
        res.status(500).json({ message: "Failed to create secret rotation" });
      }
    },
  );

  app.post(
    "/api/connectors/:id/secret-rotations/:rotationId/rotate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = (req as any).orgId;
        const user = (req as any).user;
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector) return res.status(404).json({ message: "Connector not found" });
        const { newSecretValue } = req.body;
        if (!newSecretValue) return res.status(400).json({ message: "newSecretValue is required" });

        const rotations = await storage.getConnectorSecretRotations(connector.id);
        const rotation = rotations.find((r) => r.id === req.params.rotationId);
        if (!rotation) return res.status(404).json({ message: "Rotation record not found" });

        const config = typeof connector.config === "object" ? { ...(connector.config as Record<string, any>) } : {};
        config[rotation.secretField] = newSecretValue;
        await storage.updateConnector(connector.id, { config } as any);

        const intervalDays = rotation.rotationIntervalDays || 90;
        const nextDue = new Date();
        nextDue.setDate(nextDue.getDate() + intervalDays);
        const updated = await storage.updateConnectorSecretRotation(rotation.id, {
          lastRotatedAt: new Date(),
          nextRotationDue: nextDue,
          status: "current",
          rotatedBy: user?.id,
          rotatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
        });
        await storage.createAuditLog({
          orgId,
          userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
          action: "connector_secret_rotated",
          resourceType: "connector",
          resourceId: connector.id,
          details: { secretField: rotation.secretField, nextRotationDue: nextDue.toISOString() },
        });
        res.json({ success: true, rotation: updated });
      } catch (error) {
        res.status(500).json({ message: "Failed to rotate secret" });
      }
    },
  );

  // ============================
  // Connector Job Run Replay
  // ============================
  app.post(
    "/api/connectors/:id/jobs/:jobId/replay",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = (req as any).orgId;
        const user = (req as any).user;
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector) return res.status(404).json({ message: "Connector not found" });
        const config = connector.config as ConnectorConfig;
        const startTime = Date.now();
        const jobRun = await storage.createConnectorJobRun({
          connectorId: connector.id,
          orgId,
          status: "running",
        });
        try {
          const syncResult = await syncConnector(connector);
          const latency = Date.now() - startTime;
          await storage.updateConnectorJobRun(jobRun.id, {
            status: "success",
            completedAt: new Date(),
            latencyMs: latency,
            alertsReceived: syncResult.alertsReceived || 0,
          });
          await storage.updateConnectorSyncStatus(connector.id, {
            lastSyncAt: new Date(),
            lastSyncStatus: "success",
            lastSyncAlerts: syncResult.alertsReceived || 0,
          });
          res.json({ success: true, jobRunId: jobRun.id, alertsReceived: syncResult.alertsReceived || 0 });
        } catch (syncError: unknown) {
          await storage.updateConnectorJobRun(jobRun.id, {
            status: "failed",
            completedAt: new Date(),
            latencyMs: Date.now() - startTime,
            errorMessage: errorMessage(syncError),
          });
          res.json({ success: false, jobRunId: jobRun.id, error: errorMessage(syncError) });
        }
      } catch (error) {
        res.status(500).json({ message: "Failed to replay job" });
      }
    },
  );

  // ── 37.5: Connector Credential Rotation Status ──
  app.get("/api/connectors/:id/credential-status", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }
      const rotations = await storage.getConnectorSecretRotations(connector.id);
      const healthChecks = await storage.getConnectorHealthChecks(connector.id, 1);
      const latestHealth = healthChecks[0];

      const credentialFields = rotations.map((r) => ({
        field: r.secretField,
        lastRotated: r.lastRotatedAt,
        nextDue: r.nextRotationDue,
        intervalDays: r.rotationIntervalDays,
        status: r.status,
        rotatedBy: r.rotatedByName,
        isExpiringSoon: r.nextRotationDue ? new Date(r.nextRotationDue).getTime() - Date.now() < 14 * 86400000 : false,
        isExpired: r.nextRotationDue ? new Date(r.nextRotationDue).getTime() < Date.now() : false,
      }));

      res.json({
        connectorId: connector.id,
        connectorName: connector.name,
        credentialStatus: latestHealth?.credentialStatus || "unknown",
        credentialExpiresAt: latestHealth?.credentialExpiresAt || null,
        rotationSchedules: credentialFields,
        totalSchedules: credentialFields.length,
        expiringSoon: credentialFields.filter((c) => c.isExpiringSoon).length,
        expired: credentialFields.filter((c) => c.isExpired).length,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch credential status" });
    }
  });

  // ── 37.6: Connector Rate Limiting Status ──
  app.get("/api/connectors/:id/rate-limit-status", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }
      const metrics = await storage.getConnectorMetrics(p(req.params.id));
      const jobs = await storage.getConnectorJobRuns(p(req.params.id), 50);
      const throttledJobs = jobs.filter((j) => j.throttled);
      const recentThrottles = throttledJobs.filter(
        (j) => j.startedAt && new Date(j.startedAt).getTime() > Date.now() - 3600000,
      );

      res.json({
        connectorId: connector.id,
        connectorName: connector.name,
        pollingIntervalMin: connector.pollingIntervalMin || 5,
        throttleCount: metrics?.throttleCount ?? 0,
        errorRate: metrics?.errorRate ?? 0,
        recentThrottles: recentThrottles.length,
        totalThrottledJobs: throttledJobs.length,
        adaptiveThrottling: {
          enabled: true,
          currentMultiplier: recentThrottles.length > 3 ? 2.0 : recentThrottles.length > 0 ? 1.5 : 1.0,
          effectiveIntervalMin:
            (connector.pollingIntervalMin || 5) *
            (recentThrottles.length > 3 ? 2.0 : recentThrottles.length > 0 ? 1.5 : 1.0),
          reason:
            recentThrottles.length > 3
              ? "Heavy throttling detected — interval doubled"
              : recentThrottles.length > 0
                ? "Moderate throttling — interval increased 50%"
                : "No throttling — operating at full speed",
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch rate limit status" });
    }
  });

  // ── 37.7: Connector Data Mapping Configuration ──
  app.get("/api/connectors/:id/field-mapping", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }

      // Return the default field mapping for this connector type
      const defaultMappings: Record<string, { sourceField: string; targetField: string; transform?: string }[]> = {
        crowdstrike: [
          { sourceField: "detection_id", targetField: "externalId" },
          { sourceField: "max_severity_displayname", targetField: "severity" },
          { sourceField: "scenario", targetField: "title" },
          { sourceField: "description", targetField: "description" },
          { sourceField: "created_timestamp", targetField: "timestamp" },
          { sourceField: "tactic", targetField: "category", transform: "lowercase" },
        ],
        sentinelone: [
          { sourceField: "id", targetField: "externalId" },
          { sourceField: "threatInfo.confidenceLevel", targetField: "severity", transform: "map_severity" },
          { sourceField: "threatInfo.threatName", targetField: "title" },
          { sourceField: "threatInfo.classification", targetField: "category" },
          { sourceField: "createdAt", targetField: "timestamp" },
        ],
        splunk: [
          { sourceField: "sid", targetField: "externalId" },
          { sourceField: "severity", targetField: "severity" },
          { sourceField: "search_name", targetField: "title" },
          { sourceField: "description", targetField: "description" },
          { sourceField: "_time", targetField: "timestamp" },
        ],
      };

      const typeKey = connector.type.toLowerCase().replace(/[^a-z]/g, "");
      const mapping = defaultMappings[typeKey] || [
        { sourceField: "id", targetField: "externalId" },
        { sourceField: "severity", targetField: "severity" },
        { sourceField: "title", targetField: "title" },
        { sourceField: "description", targetField: "description" },
        { sourceField: "timestamp", targetField: "timestamp" },
      ];

      const customMappings = (connector.config as any)?.fieldMappings || null;

      res.json({
        connectorId: connector.id,
        connectorType: connector.type,
        defaultMappings: mapping,
        customMappings,
        targetSchema: [
          { field: "externalId", type: "string", required: true, description: "Unique ID from source system" },
          { field: "severity", type: "enum", required: true, description: "critical | high | medium | low | info" },
          { field: "title", type: "string", required: true, description: "Alert title" },
          { field: "description", type: "string", required: false, description: "Alert description" },
          { field: "timestamp", type: "datetime", required: true, description: "When the alert occurred" },
          { field: "category", type: "string", required: false, description: "Alert category (e.g., MITRE tactic)" },
          { field: "source", type: "string", required: false, description: "Source system name" },
        ],
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch field mapping" });
    }
  });

  // ── 37.8: Connector Pipeline Verification ──
  app.get("/api/connectors/:id/pipeline-status", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }
      const jobs = await storage.getConnectorJobRuns(p(req.params.id), 10);
      const healthChecks = await storage.getConnectorHealthChecks(connector.id, 1);

      const stages = [
        {
          stage: "connect",
          status:
            healthChecks.length > 0 && healthChecks[0].status === "healthy"
              ? "pass"
              : connector.status === "active"
                ? "pass"
                : "fail",
          detail: healthChecks.length > 0 ? `Last health check: ${healthChecks[0].status}` : "No health checks run",
        },
        {
          stage: "fetch_events",
          status: jobs.some((j) => (j.alertsReceived ?? 0) > 0) ? "pass" : jobs.length > 0 ? "warn" : "unknown",
          detail:
            jobs.length > 0 ? `Last fetch: ${jobs[0].alertsReceived ?? 0} events received` : "No sync runs recorded",
        },
        {
          stage: "normalize",
          status: jobs.some((j) => (j.alertsCreated ?? 0) > 0)
            ? "pass"
            : jobs.some((j) => (j.alertsReceived ?? 0) > 0)
              ? "warn"
              : "unknown",
          detail:
            jobs.length > 0
              ? `Last run: ${jobs[0].alertsCreated ?? 0} alerts created from ${jobs[0].alertsReceived ?? 0} events`
              : "No normalization data",
        },
        {
          stage: "create_alerts",
          status: (connector.totalAlertsSynced ?? 0) > 0 ? "pass" : "unknown",
          detail: `Total alerts synced: ${connector.totalAlertsSynced ?? 0}`,
        },
      ];

      const overallStatus = stages.every((s) => s.status === "pass")
        ? "healthy"
        : stages.some((s) => s.status === "fail")
          ? "unhealthy"
          : "partial";

      res.json({
        connectorId: connector.id,
        connectorName: connector.name,
        connectorType: connector.type,
        overallStatus,
        stages,
        lastSyncAt: connector.lastSyncAt,
        lastSyncStatus: connector.lastSyncStatus,
        totalAlertsSynced: connector.totalAlertsSynced ?? 0,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch pipeline status" });
    }
  });

  // ── 37.9: Connector Response Action Capabilities ──
  app.get("/api/connectors/:id/response-actions", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector || !orgId || connector.orgId !== orgId) {
        return res.status(404).json({ message: "Connector not found" });
      }

      // Define response actions per connector type
      const actionsByType: Record<
        string,
        { action: string; description: string; category: string; requiresApproval: boolean }[]
      > = {
        crowdstrike: [
          {
            action: "isolate_host",
            description: "Network-isolate a compromised endpoint",
            category: "EDR",
            requiresApproval: true,
          },
          {
            action: "contain_host",
            description: "Apply containment policy to endpoint",
            category: "EDR",
            requiresApproval: true,
          },
          {
            action: "kill_process",
            description: "Terminate a malicious process",
            category: "EDR",
            requiresApproval: false,
          },
          {
            action: "quarantine_file",
            description: "Quarantine a suspicious file",
            category: "EDR",
            requiresApproval: false,
          },
        ],
        sentinelone: [
          {
            action: "isolate_endpoint",
            description: "Disconnect endpoint from network",
            category: "EDR",
            requiresApproval: true,
          },
          {
            action: "rollback_threat",
            description: "Roll back threat changes",
            category: "EDR",
            requiresApproval: true,
          },
          { action: "kill_process", description: "Kill malicious process", category: "EDR", requiresApproval: false },
        ],
        paloalto: [
          {
            action: "block_ip",
            description: "Block IP address at firewall",
            category: "Firewall",
            requiresApproval: true,
          },
          { action: "block_url", description: "Block malicious URL", category: "Firewall", requiresApproval: false },
          {
            action: "quarantine_host",
            description: "Quarantine host via firewall policy",
            category: "Firewall",
            requiresApproval: true,
          },
        ],
        okta: [
          {
            action: "disable_account",
            description: "Disable compromised user account",
            category: "Identity",
            requiresApproval: true,
          },
          {
            action: "force_mfa",
            description: "Force MFA re-enrollment",
            category: "Identity",
            requiresApproval: false,
          },
          {
            action: "revoke_sessions",
            description: "Revoke all active sessions",
            category: "Identity",
            requiresApproval: false,
          },
        ],
      };

      const typeKey = connector.type.toLowerCase().replace(/[^a-z]/g, "");
      const supportedActions = actionsByType[typeKey] || [];

      res.json({
        connectorId: connector.id,
        connectorName: connector.name,
        connectorType: connector.type,
        supportsResponseActions: supportedActions.length > 0,
        actions: supportedActions,
        totalActions: supportedActions.length,
        requiresApprovalCount: supportedActions.filter((a) => a.requiresApproval).length,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch response actions" });
    }
  });

  // ── 37.8: Connector Health Summary (all connectors) ──
  app.get("/api/connectors/health-summary", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { items } = await storage.getConnectorsPaginated({ orgId, offset: 0, limit: 200 });

      const summary = await Promise.all(
        items.map(async (c) => {
          const healthChecks = await storage.getConnectorHealthChecks(c.id, 1);
          const latestHealth = healthChecks[0];
          const metrics = await storage.getConnectorMetrics(c.id);
          return {
            id: c.id,
            name: c.name,
            type: c.type,
            status: c.status,
            lastSyncAt: c.lastSyncAt,
            lastSyncStatus: c.lastSyncStatus,
            totalAlertsSynced: c.totalAlertsSynced ?? 0,
            healthStatus: latestHealth?.status || "unknown",
            latencyMs: latestHealth?.latencyMs || null,
            credentialStatus: latestHealth?.credentialStatus || "unknown",
            successRate: metrics?.successRate ?? null,
            errorRate: metrics?.errorRate ?? 0,
            eventsLast24h: c.lastSyncAlerts ?? 0,
            dlqDepth: 0, // Populated below if applicable
          };
        }),
      );

      // Get DLQ counts per connector
      try {
        const dlqItems = await storage.getDeadLetterJobRuns(orgId);
        for (const dl of dlqItems) {
          const entry = summary.find((s) => s.id === dl.connectorId);
          if (entry) entry.dlqDepth++;
        }
      } catch {
        /* DLQ may be empty */
      }

      const healthy = summary.filter((s) => s.healthStatus === "healthy" || s.status === "active").length;
      const unhealthy = summary.filter((s) => s.healthStatus === "unhealthy" || s.status === "error").length;
      const unknown = summary.filter(
        (s) => s.healthStatus === "unknown" && s.status !== "active" && s.status !== "error",
      ).length;

      res.json({
        total: summary.length,
        healthy,
        unhealthy,
        unknown,
        connectors: summary,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch health summary" });
    }
  });

  app.get("/api/v1/connectors", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const search = typeof req.query.search === "string" ? req.query.search : undefined;
      const type = typeof req.query.type === "string" ? req.query.type : undefined;
      const status = typeof req.query.status === "string" ? req.query.status : undefined;
      const sortBy = typeof req.query.sortBy === "string" ? req.query.sortBy : undefined;
      const sortOrder = req.query.sortOrder === "asc" ? ("asc" as const) : ("desc" as const);

      const { items, total } = await storage.getConnectorsPaginatedWithSort({
        orgId,
        offset,
        limit,
        search,
        type,
        status,
        sortBy,
        sortOrder,
      });

      const sanitized = items.map((c) => ({ ...c, config: sanitizeConfig(c.config) }));

      return sendEnvelope(res, sanitized, {
        meta: {
          offset,
          limit,
          total,
          search: search ?? null,
          type: type ?? null,
          status: status ?? null,
          sortBy: sortBy ?? "createdAt",
          sortOrder,
        },
      });
    } catch (error: unknown) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          { code: "CONNECTORS_LIST_FAILED", message: "Failed to fetch connectors", details: errorMessage(error) },
        ],
      });
    }
  });

  app.get(
    "/api/v1/connectors/sync-stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        return sendEnvelope(res, await getProviderSyncStats());
      } catch (error: unknown) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "SYNC_STATS_FAILED", message: "Failed to fetch provider sync stats", details: errorMessage(error) },
          ],
        });
      }
    },
  );

  app.put(
    "/api/v1/connectors/concurrency",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { provider, maxConcurrency } = req.body;
        if (!provider || typeof provider !== "string") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "provider string is required" }],
          });
        }
        const limit = Number(maxConcurrency);
        if (!Number.isFinite(limit) || limit < 1 || limit > 20) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_REQUEST", message: "maxConcurrency must be between 1 and 20" }],
          });
        }
        await setProviderConcurrency(provider, limit);
        return sendEnvelope(res, { provider, maxConcurrency: limit });
      } catch (error: unknown) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "CONCURRENCY_UPDATE_FAILED",
              message: "Failed to update provider concurrency",
              details: errorMessage(error),
            },
          ],
        });
      }
    },
  );
}
