import type { Express, Request, Response } from "express";
import { logger, p, publishOutboxEvent, sanitizeConfig, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
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

export function registerConnectorsRoutes(app: Express): void {
  // Connector Engine Routes
  app.get("/api/connectors/types", isAuthenticated, async (_req, res) => {
    const types = getAllConnectorTypes();
    const metadata = types.map((t) => ({ type: t, ...getConnectorMetadata(t) })).filter((m) => m.name);
    res.json(metadata);
  });

  app.get("/api/connectors", isAuthenticated, async (req, res) => {
    try {
      const { offset, limit } = parsePaginationParams(req.query as Record<string, unknown>);
      const allConnectors = await storage.getConnectors();
      const sanitized = allConnectors.map((c) => ({ ...c, config: sanitizeConfig(c.config) }));
      res.json(sanitized.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connectors" });
    }
  });

  app.get("/api/connectors/dead-letters", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.organizationId;
      const { offset, limit } = parsePaginationParams(req.query as Record<string, unknown>);
      const runs = await storage.getDeadLetterJobRuns(orgId);
      res.json(runs.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dead-letter job runs" });
    }
  });

  app.get("/api/connectors/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
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
        storage.incrementUsage(connector.orgId || (req as any).user?.orgId, "connectors").catch(() => {});
        res.status(201).json(connector);
      } catch (error: any) {
        logger.child("routes").error("Route error", { error: String(error) });
        res.status(500).json({ message: "Failed to create connector. Please try again." });
      }
    },
  );

  app.patch(
    "/api/connectors/:id",
    isAuthenticated,
    validatePathId("id"),
    validateBody(bodySchemas.connectorUpdate),
    async (req, res) => {
      try {
        const connector = await storage.getConnector(p(req.params.id));
        if (!connector) return res.status(404).json({ message: "Connector not found" });
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
        res.json(updated);
      } catch (error: any) {
        logger.child("routes").error("Route error", { error: String(error) });
        res.status(500).json({ message: "Failed to update connector. Please try again." });
      }
    },
  );

  app.delete("/api/connectors/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
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
  });

  app.post("/api/connectors/:id/test", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const result = await testConnector(connector.type, config);
      res.json(result);
    } catch (error: any) {
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
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  app.post("/api/connectors/:id/sync", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });

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
            if (r.value.isNew) created++;
            else deduped++;
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
    } catch (error: any) {
      const connector = await storage.getConnector(p(req.params.id));
      if (connector) {
        await storage.updateConnectorSyncStatus(connector.id, {
          lastSyncAt: new Date(),
          lastSyncStatus: "error",
          lastSyncAlerts: 0,
          lastSyncError: error.message,
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
      let errorMessage: string | undefined;
      try {
        const result = await testConnector(connector.type, config);
        if (!result.success) {
          status = "unhealthy";
          errorMessage = result.message || "Connection test failed";
        }
      } catch (err: any) {
        status = "unhealthy";
        errorMessage = err.message || "Connection test error";
      }
      const latencyMs = Date.now() - startTime;
      const healthCheck = await storage.createConnectorHealthCheck({
        connectorId: connector.id,
        orgId: connector.orgId,
        status,
        latencyMs,
        errorMessage,
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
        } catch (syncError: any) {
          await storage.updateConnectorJobRun(jobRun.id, {
            status: "failed",
            completedAt: new Date(),
            latencyMs: Date.now() - startTime,
            errorMessage: syncError.message,
          });
          res.json({ success: false, jobRunId: jobRun.id, error: syncError.message });
        }
      } catch (error) {
        res.status(500).json({ message: "Failed to replay job" });
      }
    },
  );

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
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CONNECTORS_LIST_FAILED", message: "Failed to fetch connectors", details: error?.message }],
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
        return sendEnvelope(res, getProviderSyncStats());
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            { code: "SYNC_STATS_FAILED", message: "Failed to fetch provider sync stats", details: error?.message },
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
        setProviderConcurrency(provider, limit);
        return sendEnvelope(res, { provider, maxConcurrency: limit });
      } catch (error: any) {
        return sendEnvelope(res, null, {
          status: 500,
          errors: [
            {
              code: "CONCURRENCY_UPDATE_FAILED",
              message: "Failed to update provider concurrency",
              details: error?.message,
            },
          ],
        });
      }
    },
  );
}
