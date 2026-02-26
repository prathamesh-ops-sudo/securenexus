import type { Express } from "express";
import { getOrgId, logger, replyError, reply } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import {
  getRetentionPolicies,
  getLifecycleStatus,
  exportToColdStorage,
  listColdStorageArchives,
  rehydrateFromColdStorage,
  executeDeletion,
  type DataType,
  type PlanTier,
} from "../data-lifecycle";
import { getScalingReadinessReport, getStateRegistry, getPodId } from "../scaling-state";

const VALID_DATA_TYPES: ReadonlySet<string> = new Set([
  "alerts", "incidents", "audit_logs", "sli_metrics",
  "jobs", "connector_job_runs", "outbox_events", "ingestion_logs",
]);

const VALID_PLAN_TIERS: ReadonlySet<string> = new Set(["free", "pro", "enterprise"]);

function isValidDataType(v: unknown): v is DataType {
  return typeof v === "string" && VALID_DATA_TYPES.has(v);
}

function isValidPlan(v: unknown): v is PlanTier {
  return typeof v === "string" && VALID_PLAN_TIERS.has(v);
}

export function registerLifecycleRoutes(app: Express): void {
  app.get("/api/lifecycle/policies", isAuthenticated, async (req, res) => {
    try {
      const plan = (req.query.plan as string) || "free";
      if (!isValidPlan(plan)) {
        return replyError(res, 400, [{ code: "INVALID_PLAN", message: "Plan must be free, pro, or enterprise" }]);
      }
      const policies = getRetentionPolicies(plan);
      return reply(res, { plan, policies });
    } catch (err) {
      logger.child("lifecycle").error("Failed to get retention policies", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get retention policies" }]);
    }
  });

  app.get("/api/lifecycle/status", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const plan = (req.query.plan as string) || "free";
      if (!isValidPlan(plan)) {
        return replyError(res, 400, [{ code: "INVALID_PLAN", message: "Plan must be free, pro, or enterprise" }]);
      }
      const status = await getLifecycleStatus(orgId, plan);
      return reply(res, { orgId, plan, status });
    } catch (err) {
      logger.child("lifecycle").error("Failed to get lifecycle status", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get lifecycle status" }]);
    }
  });

  app.post("/api/lifecycle/export", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { dataType, olderThanDays } = req.body;

      if (!isValidDataType(dataType)) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPE", message: "Invalid or missing dataType" }]);
      }
      if (typeof olderThanDays !== "number" || olderThanDays < 1) {
        return replyError(res, 400, [{ code: "INVALID_DAYS", message: "olderThanDays must be a positive number" }]);
      }

      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - olderThanDays);

      const result = await exportToColdStorage(orgId, dataType, cutoff);
      return reply(res, result);
    } catch (err) {
      logger.child("lifecycle").error("Export to cold storage failed", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Export to cold storage failed" }]);
    }
  });

  app.get("/api/lifecycle/archives", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const dataType = req.query.dataType as string;

      if (!isValidDataType(dataType)) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPE", message: "Invalid or missing dataType query param" }]);
      }

      const archives = await listColdStorageArchives(orgId, dataType);
      return reply(res, { orgId, dataType, archives });
    } catch (err) {
      logger.child("lifecycle").error("Failed to list archives", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to list archives" }]);
    }
  });

  app.post("/api/lifecycle/rehydrate", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { dataType, batchId } = req.body;

      if (!isValidDataType(dataType)) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPE", message: "Invalid or missing dataType" }]);
      }
      if (!batchId || typeof batchId !== "string") {
        return replyError(res, 400, [{ code: "INVALID_BATCH_ID", message: "batchId is required" }]);
      }

      const result = await rehydrateFromColdStorage(orgId, dataType, batchId);
      return reply(res, result);
    } catch (err) {
      logger.child("lifecycle").error("Rehydration failed", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Rehydration failed" }]);
    }
  });

  app.post("/api/lifecycle/delete", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const user = (req as any).user;
      const { dataType, reason, olderThanDays, specificIds, dryRun } = req.body;

      if (!isValidDataType(dataType)) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPE", message: "Invalid or missing dataType" }]);
      }
      if (!reason || typeof reason !== "string" || reason.length < 3) {
        return replyError(res, 400, [{ code: "INVALID_REASON", message: "reason is required (min 3 chars)" }]);
      }

      const result = await executeDeletion({
        orgId,
        dataType,
        reason,
        requestedBy: user?.id || "unknown",
        olderThanDays: typeof olderThanDays === "number" ? olderThanDays : undefined,
        specificIds: Array.isArray(specificIds) ? specificIds.filter((id: unknown) => typeof id === "string") : undefined,
        dryRun: dryRun === true,
      });
      return reply(res, result);
    } catch (err) {
      logger.child("lifecycle").error("Deletion failed", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Deletion failed" }]);
    }
  });

  app.get("/api/scaling/readiness", isAuthenticated, async (_req, res) => {
    try {
      const report = getScalingReadinessReport();
      return reply(res, report);
    } catch (err) {
      logger.child("scaling").error("Failed to get readiness report", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get readiness report" }]);
    }
  });

  app.get("/api/scaling/state-registry", isAuthenticated, async (_req, res) => {
    try {
      const registry = getStateRegistry();
      return reply(res, { podId: getPodId(), stores: registry });
    } catch (err) {
      logger.child("scaling").error("Failed to get state registry", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get state registry" }]);
    }
  });
}
