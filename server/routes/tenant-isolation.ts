import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { replyBadRequest } from "../api-response";
import {
  getTenantIsolationConfig,
  setTenantIsolationConfig,
  assessNoisyNeighbor,
  provisionDedicatedSchema,
  registerDedicatedInstance,
  getDedicatedInstance,
  getTenantIsolationReport,
  type IsolationLevel,
  type PlanTier,
} from "../tenant-isolation";
import {
  getOrgQuotas,
  setOrgQuotaOverride,
  clearOrgQuotaOverride,
  getOrgQuotaStatus,
  checkIngestionQuota,
  checkAiTokenQuota,
  checkConnectorSyncQuota,
  type PlanTier as ThrottlePlanTier,
} from "../tenant-throttle";
import { logger } from "../logger";
import { storage } from "../storage";

const log = logger.child("tenant-isolation-routes");

const VALID_ISOLATION_LEVELS: ReadonlySet<string> = new Set(["shared", "dedicated-schema", "dedicated-instance", "dedicated-cluster"]);
const VALID_PLANS: ReadonlySet<string> = new Set(["free", "pro", "enterprise"]);

function isValidPlan(v: unknown): v is PlanTier {
  return typeof v === "string" && VALID_PLANS.has(v);
}

function isValidIsolationLevel(v: unknown): v is IsolationLevel {
  return typeof v === "string" && VALID_ISOLATION_LEVELS.has(v);
}

async function detectOrgPlan(orgId: string): Promise<PlanTier> {
  try {
    const planLimit = await storage.getOrgPlanLimit(orgId);
    if (planLimit && typeof planLimit.planTier === "string" && VALID_PLANS.has(planLimit.planTier)) {
      return planLimit.planTier as PlanTier;
    }
  } catch {
    /* fall through */
  }
  return "free";
}

export function registerTenantIsolationRoutes(app: Express): void {
  app.get("/api/tenant-isolation/config", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const plan = await detectOrgPlan(orgId);
      const config = getTenantIsolationConfig(orgId, plan);
      res.json(config);
    } catch (error) {
      log.error("Failed to get tenant isolation config", { error: String(error) });
      res.status(500).json({ message: "Failed to get tenant isolation config" });
    }
  });

  app.put("/api/tenant-isolation/config", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const { isolationLevel, connectionPoolSize, maxConnectionsPerOrg, resourceGroup } = req.body;

      if (isolationLevel !== undefined && !isValidIsolationLevel(isolationLevel)) {
        return replyBadRequest(res, "Invalid isolation level. Must be: shared, dedicated-schema, dedicated-instance, dedicated-cluster");
      }

      if (connectionPoolSize !== undefined && (typeof connectionPoolSize !== "number" || connectionPoolSize < 1 || connectionPoolSize > 200)) {
        return replyBadRequest(res, "connectionPoolSize must be between 1 and 200");
      }

      if (maxConnectionsPerOrg !== undefined && (typeof maxConnectionsPerOrg !== "number" || maxConnectionsPerOrg < 1 || maxConnectionsPerOrg > 500)) {
        return replyBadRequest(res, "maxConnectionsPerOrg must be between 1 and 500");
      }

      const updates: Record<string, unknown> = {};
      if (isolationLevel !== undefined) updates.isolationLevel = isolationLevel;
      if (connectionPoolSize !== undefined) updates.connectionPoolSize = connectionPoolSize;
      if (maxConnectionsPerOrg !== undefined) updates.maxConnectionsPerOrg = maxConnectionsPerOrg;
      if (resourceGroup !== undefined && typeof resourceGroup === "string") updates.resourceGroup = resourceGroup;

      const config = setTenantIsolationConfig(orgId, updates as any);

      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "tenant_isolation_config_updated",
        resourceType: "tenant_isolation",
        details: updates,
      }).catch((err) => log.error("Failed to create audit log", { error: String(err) }));

      res.json(config);
    } catch (error) {
      log.error("Failed to update tenant isolation config", { error: String(error) });
      res.status(500).json({ message: "Failed to update tenant isolation config" });
    }
  });

  app.get("/api/tenant-isolation/noisy-neighbor", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const metrics = assessNoisyNeighbor(orgId);
      res.json(metrics);
    } catch (error) {
      log.error("Failed to assess noisy neighbor", { error: String(error) });
      res.status(500).json({ message: "Failed to assess noisy neighbor metrics" });
    }
  });

  app.post("/api/tenant-isolation/provision-schema", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const result = await provisionDedicatedSchema(orgId);
      res.json(result);
    } catch (error) {
      log.error("Failed to provision dedicated schema", { error: String(error) });
      res.status(500).json({ message: "Failed to provision dedicated schema" });
    }
  });

  app.post("/api/tenant-isolation/register-instance", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const { instanceIdentifier, endpoint, port, instanceClass, allocatedStorageGb } = req.body;

      if (!instanceIdentifier || typeof instanceIdentifier !== "string") {
        return replyBadRequest(res, "instanceIdentifier is required");
      }
      if (!endpoint || typeof endpoint !== "string") {
        return replyBadRequest(res, "endpoint is required");
      }
      if (!port || typeof port !== "number" || port < 1 || port > 65535) {
        return replyBadRequest(res, "port must be a valid port number (1-65535)");
      }

      const config = registerDedicatedInstance(orgId, {
        instanceIdentifier,
        endpoint,
        port,
        status: "available",
        instanceClass: instanceClass || "db.r6g.large",
        allocatedStorageGb: allocatedStorageGb || 100,
      });

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: "Admin",
        action: "dedicated_instance_registered",
        resourceType: "tenant_isolation",
        details: { instanceIdentifier, endpoint },
      }).catch((err) => log.error("Failed to create audit log", { error: String(err) }));

      res.json(config);
    } catch (error) {
      log.error("Failed to register dedicated instance", { error: String(error) });
      res.status(500).json({ message: "Failed to register dedicated instance" });
    }
  });

  app.get("/api/tenant-isolation/dedicated-instance", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const instance = getDedicatedInstance(orgId);
      if (!instance) {
        return res.json({ configured: false, message: "No dedicated instance configured for this organization" });
      }
      res.json({ configured: true, instance });
    } catch (error) {
      log.error("Failed to get dedicated instance", { error: String(error) });
      res.status(500).json({ message: "Failed to get dedicated instance info" });
    }
  });

  app.get("/api/tenant-isolation/report", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const report = getTenantIsolationReport();
      res.json(report);
    } catch (error) {
      log.error("Failed to get tenant isolation report", { error: String(error) });
      res.status(500).json({ message: "Failed to get tenant isolation report" });
    }
  });

  app.get("/api/tenant-quotas", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const plan = await detectOrgPlan(orgId);
      const quotas = getOrgQuotas(orgId, plan as ThrottlePlanTier);
      res.json({ orgId, plan, quotas });
    } catch (error) {
      log.error("Failed to get tenant quotas", { error: String(error) });
      res.status(500).json({ message: "Failed to get tenant quotas" });
    }
  });

  app.get("/api/tenant-quotas/status", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const plan = await detectOrgPlan(orgId);
      const status = getOrgQuotaStatus(orgId, plan as ThrottlePlanTier);
      res.json(status);
    } catch (error) {
      log.error("Failed to get quota status", { error: String(error) });
      res.status(500).json({ message: "Failed to get quota status" });
    }
  });

  app.put("/api/tenant-quotas/override", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const overrides = req.body;

      if (!overrides || typeof overrides !== "object") {
        return replyBadRequest(res, "Request body must be an object with quota overrides");
      }

      const allowedFields: ReadonlySet<string> = new Set([
        "ingestionEventsPerMinute", "ingestionEventsPerDay", "aiTokensPerDay",
        "aiInvocationsPerMinute", "connectorSyncsPerHour", "connectorMaxConcurrent",
        "apiCallsPerMinute", "apiCallsPerDay", "maxStorageGb", "maxSseConnections",
      ]);

      const sanitized: Record<string, number> = {};
      for (const [key, value] of Object.entries(overrides)) {
        if (!allowedFields.has(key)) continue;
        if (typeof value !== "number" || value < 0 || !Number.isFinite(value)) {
          return replyBadRequest(res, `Invalid value for ${key}: must be a non-negative finite number`);
        }
        sanitized[key] = Math.floor(value);
      }

      if (Object.keys(sanitized).length === 0) {
        return replyBadRequest(res, "No valid quota overrides provided");
      }

      setOrgQuotaOverride(orgId, sanitized as any);

      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "tenant_quota_override_set",
        resourceType: "tenant_quotas",
        details: sanitized,
      }).catch((err) => log.error("Failed to create audit log", { error: String(err) }));

      const plan = await detectOrgPlan(orgId);
      const status = getOrgQuotaStatus(orgId, plan as ThrottlePlanTier);
      res.json(status);
    } catch (error) {
      log.error("Failed to set quota override", { error: String(error) });
      res.status(500).json({ message: "Failed to set quota override" });
    }
  });

  app.delete("/api/tenant-quotas/override", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      clearOrgQuotaOverride(orgId);

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: "Admin",
        action: "tenant_quota_override_cleared",
        resourceType: "tenant_quotas",
      }).catch((err) => log.error("Failed to create audit log", { error: String(err) }));

      const plan = await detectOrgPlan(orgId);
      const status = getOrgQuotaStatus(orgId, plan as ThrottlePlanTier);
      res.json(status);
    } catch (error) {
      log.error("Failed to clear quota override", { error: String(error) });
      res.status(500).json({ message: "Failed to clear quota override" });
    }
  });

  app.get("/api/tenant-quotas/check/:category", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const category = req.params.category;
      const plan = await detectOrgPlan(orgId);
      const planTier = plan as ThrottlePlanTier;

      switch (category) {
        case "ingestion": {
          const count = parseInt(String(req.query.count || "1"), 10);
          if (isNaN(count) || count < 1) return replyBadRequest(res, "count must be a positive integer");
          res.json(checkIngestionQuota(orgId, planTier, count));
          break;
        }
        case "ai_tokens": {
          const tokens = parseInt(String(req.query.tokens || "100"), 10);
          if (isNaN(tokens) || tokens < 1) return replyBadRequest(res, "tokens must be a positive integer");
          res.json(checkAiTokenQuota(orgId, planTier, tokens));
          break;
        }
        case "connector_sync":
          res.json(checkConnectorSyncQuota(orgId, planTier));
          break;
        default:
          return replyBadRequest(res, "Invalid category. Must be: ingestion, ai_tokens, connector_sync");
      }
    } catch (error) {
      log.error("Failed to check quota", { error: String(error) });
      res.status(500).json({ message: "Failed to check quota" });
    }
  });
}
