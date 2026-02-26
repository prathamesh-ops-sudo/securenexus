import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, publishOutboxEvent, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireOrgId, requirePermission, resolveOrgContext } from "../rbac";
import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../request-validator";
import { insertAlertSchema } from "@shared/schema";
import { parsePaginationParams } from "../db-performance";
import { findRelatedAlertsByEntity, getEntitiesForAlert } from "../entity-resolver";
import { cacheInvalidate } from "../query-cache";

export function registerAlertsRoutes(app: Express): void {
  // Alerts
  app.get("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const { search } = req.query;
      const { offset, limit, sortOrder } = parsePaginationParams(req.query as Record<string, unknown>);
      if (search && typeof search === "string") {
        const results = await storage.searchAlerts(search);
        return res.json(results.slice(offset, offset + limit));
      }
      const allAlerts = await storage.getAlerts();
      const sorted = sortOrder === "asc" ? [...allAlerts].reverse() : allAlerts;
      res.json(sorted.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.get("/api/v1/alerts", isAuthenticated, validateQuery(querySchemas.alertsList), async (req, res) => {
    try {
      const { offset, limit, search, severity, status, source, sortBy, sortOrder } = (req as any).validatedQuery;

      const { items, total } = await storage.getAlertsPaginatedWithSort({
        offset,
        limit,
        search,
        severity,
        status,
        source,
        sortBy,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, search: search ?? null, severity: severity ?? null, status: status ?? null, source: source ?? null, sortBy: sortBy ?? "createdAt", sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "ALERTS_LIST_FAILED",
            message: "Failed to fetch alerts",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.get("/api/alerts/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert" });
    }
  });

  app.post("/api/alerts", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const parsed = insertAlertSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid alert data", errors: parsed.error.flatten() });
      }
      const alert = await storage.createAlert(parsed.data);
      publishOutboxEvent(alert.orgId, "alert.created", "alert", alert.id, {
        title: alert.title, severity: alert.severity, source: alert.source, status: alert.status,
      });
      cacheInvalidate("dashboard:");
      res.status(201).json(alert);
    } catch (error) {
      logger.child("routes").error("Error creating alert", { error: String(error) });
      res.status(500).json({ message: "Failed to create alert" });
    }
  });

  app.patch("/api/alerts/:id", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), validatePathId("id"), async (req, res) => {
    try {
      const parsed = insertAlertSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }
      const alert = await storage.updateAlert(p(req.params.id), parsed.data);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      publishOutboxEvent(alert.orgId, "alert.updated", "alert", alert.id, {
        changes: Object.keys(parsed.data),
      });
      cacheInvalidate("dashboard:");
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert" });
    }
  });

  app.patch("/api/alerts/:id/status", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), validatePathId("id"), async (req, res) => {
    try {
      const { status, incidentId } = req.body;
      if (!status) return res.status(400).json({ message: "Status required" });
      const alert = await storage.updateAlertStatus(p(req.params.id), status, incidentId);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      const closedStatuses = ["resolved", "closed", "false_positive"];
      const outboxEventType = closedStatuses.includes(status) ? "alert.closed" : "alert.updated";
      publishOutboxEvent(alert.orgId, outboxEventType, "alert", alert.id, {
        status, previousStatus: req.body.previousStatus || null,
      });
      cacheInvalidate("dashboard:");
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert status" });
    }
  });

  app.post("/api/alerts/bulk-update", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const { alertIds, status, suppressed, assignedTo } = req.body || {};
      const orgId = (req as any).user?.orgId;
      if (!Array.isArray(alertIds) || alertIds.length === 0) {
        return res.status(400).json({ message: "alertIds array is required" });
      }

      let updatedCount = 0;
      for (const id of alertIds) {
        const alertId = p(String(id));
        const existing = await storage.getAlert(alertId);
        if (!existing || (orgId && existing.orgId && existing.orgId !== orgId)) continue;
        const patch: Record<string, any> = {};
        if (typeof status === "string" && status.length > 0) patch.status = status;
        if (typeof suppressed === "boolean") {
          patch.suppressed = suppressed;
          patch.suppressedBy = suppressed ? ((req as any).user?.id || null) : null;
        }
        if (typeof assignedTo === "string") patch.assignedTo = assignedTo.trim() || null;
        if (Object.keys(patch).length === 0) continue;
        const updated = await storage.updateAlert(alertId, patch as any);
        if (updated) updatedCount++;
      }

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "alerts_bulk_update",
        resourceType: "alert",
        details: { updatedCount, status: status || null, suppressed: typeof suppressed === "boolean" ? suppressed : null, assignedTo: assignedTo || null },
      });

      res.json({ updatedCount });
    } catch (error) {
      logger.child("routes").error("Bulk alert update failed", { error: String(error) });
      res.status(500).json({ message: "Failed to bulk update alerts" });
    }
  });

  // Alert tags
  app.get("/api/alerts/:id/tags", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const alertTags = await storage.getAlertTags(p(req.params.id));
      res.json(alertTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert tags" });
    }
  });

  app.post("/api/alerts/:id/tags", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.incidentTagAdd), async (req, res) => {
    try {
      const { tagId } = (req as any).validatedBody;
      await storage.addAlertTag(p(req.params.id), tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/alerts/:alertId/tags/:tagId", isAuthenticated, validatePathId("alertId"), validatePathId("tagId"), async (req, res) => {
    try {
      await storage.removeAlertTag(p(req.params.alertId), p(req.params.tagId));
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  app.get("/api/alerts/:id/entities", isAuthenticated, async (req, res) => {
    try {
      const alertEntityList = await getEntitiesForAlert(p(req.params.id));
      res.json(alertEntityList);
    } catch (error) { res.status(500).json({ message: "Failed to fetch alert entities" }); }
  });

  app.get("/api/alerts/:id/related", isAuthenticated, async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.id));
      const related = await findRelatedAlertsByEntity(p(req.params.id), alert?.orgId);
      res.json(related);
    } catch (error) { res.status(500).json({ message: "Failed to fetch related alerts" }); }
  });

  app.post("/api/alerts/:id/suppress", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      const alert = await storage.updateAlert(p(req.params.id), { suppressed: true, suppressedBy: userId });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to suppress alert" });
    }
  });

  app.post("/api/alerts/:id/unsuppress", isAuthenticated, async (req, res) => {
    try {
      const alert = await storage.updateAlert(p(req.params.id), { suppressed: false, suppressedBy: null });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to unsuppress alert" });
    }
  });

  // Alert Confidence Calibration
  app.patch("/api/alerts/:id/confidence", isAuthenticated, async (req, res) => {
    try {
      const { confidenceScore, confidenceSource, confidenceNotes } = req.body;
      const alert = await storage.updateAlert(p(req.params.id), { confidenceScore, confidenceSource, confidenceNotes });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert confidence" });
    }
  });

  // === Alert Archive (Cold Storage) ===
  app.get("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = parseInt(req.query.limit as string, 10) || 100;
      const offset = parseInt(req.query.offset as string, 10) || 0;
      const [items, count] = await Promise.all([
        storage.getArchivedAlerts(orgId, limit, offset),
        storage.getArchivedAlertCount(orgId),
      ]);
      res.json({ items, total: count, limit, offset });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch archived alerts" });
    }
  });

  app.post("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { alertIds, reason } = req.body;
      if (!alertIds || !Array.isArray(alertIds) || alertIds.length === 0) {
        return res.status(400).json({ message: "alertIds array required" });
      }
      const count = await storage.archiveAlerts(orgId, alertIds, reason || "manual");
      res.json({ archived: count });
    } catch (error) {
      res.status(500).json({ message: "Failed to archive alerts" });
    }
  });

  app.post("/api/alerts/archive/restore", isAuthenticated, async (req, res) => {
    try {
      const { ids } = req.body;
      if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "ids array required" });
      }
      const count = await storage.restoreArchivedAlerts(ids);
      res.json({ restored: count });
    } catch (error) {
      res.status(500).json({ message: "Failed to restore archived alerts" });
    }
  });

  app.delete("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const beforeDate = req.query.beforeDate as string;
      if (!beforeDate) {
        return res.status(400).json({ message: "beforeDate query param required" });
      }
      const count = await storage.deleteArchivedAlerts(orgId, new Date(beforeDate));
      res.json({ deleted: count });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete archived alerts" });
    }
  });

}
