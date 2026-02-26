import type { Express, Request, Response } from "express";
import { dispatchWebhookEvent, getOrgId, logger, p, publishOutboxEvent, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireOrgId, requirePermission, resolveOrgContext } from "../rbac";
import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../request-validator";
import { insertCommentSchema, insertEvidenceItemSchema, insertIncidentSchema, insertInvestigationHypothesisSchema, insertInvestigationTaskSchema, insertTagSchema } from "@shared/schema";
import { dispatchAction, type ActionContext } from "../action-dispatcher";
import { parsePaginationParams } from "../db-performance";
import { getEntitiesForIncident } from "../entity-resolver";
import { broadcastEvent } from "../event-bus";
import { cacheInvalidate } from "../query-cache";

export function registerIncidentsRoutes(app: Express): void {
  // Incidents
  app.get("/api/incidents", isAuthenticated, async (req, res) => {
    try {
      const { offset, limit, sortOrder } = parsePaginationParams(req.query as Record<string, unknown>);
      const allIncidents = await storage.getIncidents();
      const sorted = sortOrder === "asc" ? [...allIncidents].reverse() : allIncidents;
      res.json(sorted.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incidents" });
    }
  });

  app.get("/api/v1/incidents", isAuthenticated, validateQuery(querySchemas.incidentsList), async (req, res) => {
    try {
      const { offset, limit, queue, search, severity, status, sortBy, sortOrder } = (req as any).validatedQuery;

      const { items, total } = await storage.getIncidentsPaginatedWithSort({
        offset,
        limit,
        search,
        severity,
        status,
        queue,
        sortBy,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, queue: queue ?? null, search: search ?? null, severity: severity ?? null, status: status ?? null, sortBy: sortBy ?? "createdAt", sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "INCIDENTS_LIST_FAILED",
            message: "Failed to fetch incidents",
            details: error?.message,
          },
        ],
      });
    }
  });

  // Incident Queues (must be before :id route)
  app.get("/api/incidents/queues", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const allIncidents = await storage.getIncidents(orgId);
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const unassigned = allIncidents.filter(i => !i.assignedTo && (i.status === "open" || i.status === "investigating"));
      const escalated = allIncidents.filter(i => i.escalated === true);
      const aging = allIncidents.filter(i => i.createdAt && new Date(i.createdAt) < sevenDaysAgo && i.status !== "resolved" && i.status !== "closed");
      res.json({ unassigned, escalated, aging });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident queues" });
    }
  });

  app.get("/api/incidents/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident" });
    }
  });

  app.get("/api/incidents/:id/alerts", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.id));
      res.json(incidentAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident alerts" });
    }
  });

  app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const parsed = insertIncidentSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid incident data", errors: parsed.error.flatten() });
      }
      const incident = await storage.createIncident(parsed.data);
      broadcastEvent({
        type: "incident:created",
        orgId: incident.orgId || null,
        data: {
          incidentId: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          priority: incident.priority,
        },
      });
      dispatchWebhookEvent(incident.orgId, "incident.created", incident);
      publishOutboxEvent(incident.orgId, "incident.created", "incident", incident.id, {
        title: incident.title, severity: incident.severity, status: incident.status, priority: incident.priority,
      });
      cacheInvalidate("dashboard:");
      res.status(201).json(incident);
    } catch (error) {
      logger.child("routes").error("Error creating incident", { error: String(error) });
      res.status(500).json({ message: "Failed to create incident" });
    }
  });

  app.patch("/api/incidents/:id", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), validatePathId("id"), async (req, res) => {
    try {
      const parsed = insertIncidentSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }

      const existingIncident = await storage.getIncident(p(req.params.id));
      if (!existingIncident) return res.status(404).json({ message: "Incident not found" });

      const updateData: any = { ...parsed.data, updatedAt: new Date() };

      if (parsed.data.status && parsed.data.status !== existingIncident.status) {
        if (parsed.data.status === "contained") {
          updateData.containedAt = new Date();
        }
        if (parsed.data.status === "resolved" || parsed.data.status === "closed") {
          updateData.resolvedAt = new Date();
        }
      }

      if (parsed.data.escalated === true && !existingIncident.escalated) {
        updateData.escalatedAt = new Date();
      }

      const incident = await storage.updateIncident(p(req.params.id), updateData);
      if (!incident) return res.status(404).json({ message: "Incident not found" });

      const userId = (req as any).userId || "system";
      const userName = (req as any).userDisplayName || "Unknown";
      const auditBase = {
        userId,
        userName,
        resourceType: "incident" as const,
        resourceId: incident.id,
        orgId: incident.orgId,
        ipAddress: req.ip,
      };

      if (parsed.data.status && parsed.data.status !== existingIncident.status) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_status_change",
          details: { from: existingIncident.status, to: parsed.data.status },
        });
      }

      if (parsed.data.priority !== undefined && parsed.data.priority !== existingIncident.priority) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_priority_change",
          details: { from: existingIncident.priority, to: parsed.data.priority },
        });
      }

      if (parsed.data.assignedTo !== undefined && parsed.data.assignedTo !== existingIncident.assignedTo) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_assignment_change",
          details: { from: existingIncident.assignedTo || null, to: parsed.data.assignedTo },
        });
      }

      if (parsed.data.escalated !== undefined && parsed.data.escalated !== existingIncident.escalated) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_escalated",
          details: { escalated: parsed.data.escalated },
        });
      }

      broadcastEvent({
        type: "incident:updated",
        orgId: incident.orgId || null,
        data: {
          incidentId: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          priority: incident.priority,
          changes: Object.keys(parsed.data),
        },
      });

      dispatchWebhookEvent(incident.orgId, "incident.updated", incident);

      const closedStatuses = ["resolved", "closed"];
      let incidentOutboxType = "incident.updated";
      if (parsed.data.status && closedStatuses.includes(parsed.data.status)) {
        incidentOutboxType = "incident.closed";
      } else if (parsed.data.escalated === true && !existingIncident.escalated) {
        incidentOutboxType = "incident.escalated";
      }
      publishOutboxEvent(incident.orgId, incidentOutboxType, "incident", incident.id, {
        changes: Object.keys(parsed.data), status: incident.status, severity: incident.severity,
      });
      cacheInvalidate("dashboard:");
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to update incident" });
    }
  });

  app.post("/api/incidents/bulk-update", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const { incidentIds, status, assignedTo, escalated, priority } = req.body || {};
      const orgId = (req as any).user?.orgId;
      if (!Array.isArray(incidentIds) || incidentIds.length === 0) {
        return res.status(400).json({ message: "incidentIds array is required" });
      }

      let updatedCount = 0;
      for (const id of incidentIds) {
        const incidentId = p(String(id));
        const existing = await storage.getIncident(incidentId);
        if (!existing || (orgId && existing.orgId && existing.orgId !== orgId)) continue;
        const patch: Record<string, any> = { updatedAt: new Date() };
        if (typeof status === "string" && status.length > 0) {
          patch.status = status;
          if (status === "contained") patch.containedAt = new Date();
          if (status === "resolved" || status === "closed") patch.resolvedAt = new Date();
        }
        if (typeof assignedTo === "string") patch.assignedTo = assignedTo.trim() || null;
        if (typeof escalated === "boolean") {
          patch.escalated = escalated;
          if (escalated && !existing.escalated) patch.escalatedAt = new Date();
        }
        if (typeof priority === "number") patch.priority = priority;
        if (Object.keys(patch).length <= 1) continue;
        const updated = await storage.updateIncident(incidentId, patch as any);
        if (updated) updatedCount++;
      }

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "incidents_bulk_update",
        resourceType: "incident",
        details: { updatedCount, status: status || null, assignedTo: assignedTo || null, escalated: typeof escalated === "boolean" ? escalated : null, priority: priority || null },
      });

      res.json({ updatedCount });
    } catch (error) {
      logger.child("routes").error("Bulk incident update failed", { error: String(error) });
      res.status(500).json({ message: "Failed to bulk update incidents" });
    }
  });

  app.get("/api/incidents/:id/activity", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const logs = await storage.getAuditLogsByResource("incident", p(req.params.id));
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident activity" });
    }
  });

  // Incident comments
  app.get("/api/incidents/:id/comments", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const comments = await storage.getComments(p(req.params.id));
      res.json(comments);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch comments" });
    }
  });

  app.post("/api/incidents/:id/comments", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const parsed = insertCommentSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.id),
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid comment data", errors: parsed.error.flatten() });
      }
      const comment = await storage.createComment(parsed.data);
      res.status(201).json(comment);
    } catch (error) {
      res.status(500).json({ message: "Failed to create comment" });
    }
  });

  app.delete("/api/comments/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const deleted = await storage.deleteComment(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Comment not found" });
      res.json({ message: "Comment deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete comment" });
    }
  });

  // Incident tags
  app.get("/api/incidents/:id/tags", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const incTags = await storage.getIncidentTags(p(req.params.id));
      res.json(incTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident tags" });
    }
  });

  app.post("/api/incidents/:id/tags", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.incidentTagAdd), async (req, res) => {
    try {
      const { tagId } = req.body;
      if (!tagId) return res.status(400).json({ message: "tagId required" });
      await storage.addIncidentTag(p(req.params.id), tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/incidents/:incidentId/tags/:tagId", isAuthenticated, validatePathId("incidentId"), validatePathId("tagId"), async (req, res) => {
    try {
      await storage.removeIncidentTag(p(req.params.incidentId), p(req.params.tagId));
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  // Tags
  app.get("/api/tags", isAuthenticated, async (req, res) => {
    try {
      const allTags = await storage.getTags();
      res.json(allTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch tags" });
    }
  });

  app.post("/api/tags", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertTagSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid tag data", errors: parsed.error.flatten() });
      }
      const tag = await storage.createTag(parsed.data);
      res.status(201).json(tag);
    } catch (error) {
      res.status(500).json({ message: "Failed to create tag" });
    }
  });

  app.get("/api/incidents/:id/entities", isAuthenticated, async (req, res) => {
    try {
      const incidentEntities = await getEntitiesForIncident(p(req.params.id));
      res.json(incidentEntities);
    } catch (error) { res.status(500).json({ message: "Failed to fetch incident entities" }); }
  });

  app.post("/api/incidents/:id/push", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const { platform, project, priority } = req.body;
      if (!platform) return res.status(400).json({ message: "Missing required field: platform (jira or servicenow)" });
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId || incident.orgId || undefined,
        incidentId: incident.id,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        storage,
      };
      const actionType = platform === "servicenow" ? "create_servicenow_ticket" : "create_jira_ticket";
      const result = await dispatchAction(actionType, {
        summary: `[SecureNexus] ${incident.title}`,
        description: incident.aiSummary || incident.summary || incident.title,
        priority: priority || (incident.severity === "critical" ? "highest" : incident.severity === "high" ? "high" : "medium"),
        project: project || "SEC",
      }, context);
      await storage.createAuditLog({
        orgId: context.orgId,
        userId: user?.id,
        userName: context.userName,
        action: "incident_pushed_to_ticketing",
        resourceType: "incident",
        resourceId: incident.id,
        details: { platform, ticketId: result.details?.ticketId },
      });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Push to ticketing error", { error: String(error) });
      res.status(500).json({ message: "Failed to push incident to ticketing system" });
    }
  });

  app.post("/api/incidents/:id/notify", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const { channelType, message: customMessage } = req.body;
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId || incident.orgId || undefined,
        incidentId: incident.id,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        storage,
      };
      const notifyType = `notify_${channelType || "slack"}`;
      const result = await dispatchAction(notifyType, {
        message: customMessage || `Security Incident: ${incident.title} [Severity: ${incident.severity}] - Status: ${incident.status}`,
        channel: "#security-alerts",
      }, context);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Notification error", { error: String(error) });
      res.status(500).json({ message: "Failed to send notification" });
    }
  });

  app.get("/api/incidents/:id/root-cause-summary", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const relatedAlerts = await storage.getAlertsByIncident(incident.id);
      const byCategory = relatedAlerts.reduce((acc: Record<string, number>, a) => {
        acc[a.category || "other"] = (acc[a.category || "other"] || 0) + 1;
        return acc;
      }, {});
      const topCategory = Object.entries(byCategory).sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown";
      const impactedAssets = Array.from(new Set(relatedAlerts.flatMap((a) => [a.sourceIp, a.destIp, a.hostname].filter(Boolean)))).slice(0, 6);
      const summary = `Correlated ${relatedAlerts.length} alerts indicate a likely ${topCategory.replace(/_/g, " ")} driven campaign. Most evidence converges on shared entities (${impactedAssets.slice(0, 3).join(", ") || "none"}) with escalating severity and temporal proximity. Recommended next step: validate initial access vector and contain high-risk assets first.`;
      res.json({
        incidentId: incident.id,
        summary,
        contributingSignals: Object.entries(byCategory).map(([category, count]) => ({ category, count })),
        impactedAssets,
      });
    } catch (error) { res.status(500).json({ message: "Failed to build root cause summary" }); }
  });

  // ==========================================
  // Evidence Items (for an incident)
  // ==========================================
  app.get("/api/incidents/:incidentId/evidence", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const items = await storage.getEvidenceItems(p(req.params.incidentId), user?.orgId);
      res.json(items);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch evidence items" });
    }
  });

  app.post("/api/incidents/:incidentId/evidence", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertEvidenceItemSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.incidentId),
        orgId,
        createdBy: user?.id || null,
        createdByName: userName,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid evidence data", errors: parsed.error.flatten() });
      }
      const item = await storage.createEvidenceItem(parsed.data);
      res.status(201).json(item);
    } catch (error) {
      res.status(500).json({ message: "Failed to create evidence item" });
    }
  });

  app.delete("/api/incidents/:incidentId/evidence/:evidenceId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getEvidenceItem(p(req.params.evidenceId));
      if (!existing) return res.status(404).json({ message: "Evidence item not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteEvidenceItem(p(req.params.evidenceId));
      if (!deleted) return res.status(404).json({ message: "Evidence item not found" });
      res.json({ message: "Evidence item deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete evidence item" });
    }
  });

  // ==========================================
  // Investigation Hypotheses (for an incident)
  // ==========================================
  app.get("/api/incidents/:incidentId/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const hypotheses = await storage.getHypotheses(p(req.params.incidentId), user?.orgId);
      res.json(hypotheses);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch hypotheses" });
    }
  });

  app.post("/api/incidents/:incidentId/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertInvestigationHypothesisSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.incidentId),
        orgId,
        createdBy: user?.id || null,
        createdByName: userName,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid hypothesis data", errors: parsed.error.flatten() });
      }
      const hypothesis = await storage.createHypothesis(parsed.data);
      res.status(201).json(hypothesis);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create hypothesis" });
    }
  });

  app.patch("/api/incidents/:incidentId/hypotheses/:hypothesisId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getHypothesis(p(req.params.hypothesisId));
      if (!existing) return res.status(404).json({ message: "Hypothesis not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { orgId: _ignoreOrgId, incidentId: _ignoreIncidentId, ...updateData } = req.body;
      if (updateData.status === "validated" || updateData.status === "confirmed") {
        updateData.validatedAt = new Date();
      }
      const hypothesis = await storage.updateHypothesis(p(req.params.hypothesisId), updateData);
      if (!hypothesis) return res.status(404).json({ message: "Hypothesis not found" });
      res.json(hypothesis);
    } catch (error) {
      res.status(500).json({ message: "Failed to update hypothesis" });
    }
  });

  app.delete("/api/incidents/:incidentId/hypotheses/:hypothesisId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getHypothesis(p(req.params.hypothesisId));
      if (!existing) return res.status(404).json({ message: "Hypothesis not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteHypothesis(p(req.params.hypothesisId));
      if (!deleted) return res.status(404).json({ message: "Hypothesis not found" });
      res.json({ message: "Hypothesis deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete hypothesis" });
    }
  });

  // ==========================================
  // Investigation Tasks (for an incident)
  // ==========================================
  app.get("/api/incidents/:incidentId/tasks", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const tasks = await storage.getInvestigationTasks(p(req.params.incidentId), user?.orgId);
      res.json(tasks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch tasks" });
    }
  });

  app.post("/api/incidents/:incidentId/tasks", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertInvestigationTaskSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.incidentId),
        orgId,
        createdBy: user?.id || null,
        createdByName: userName,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid task data", errors: parsed.error.flatten() });
      }
      const task = await storage.createInvestigationTask(parsed.data);
      res.status(201).json(task);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create task" });
    }
  });

  app.patch("/api/incidents/:incidentId/tasks/:taskId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getInvestigationTask(p(req.params.taskId));
      if (!existing) return res.status(404).json({ message: "Task not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { orgId: _ignoreOrgId, incidentId: _ignoreIncidentId, ...updateData } = req.body;
      if ((updateData.status === "done" || updateData.status === "completed") && existing.status !== "done" && existing.status !== "completed") {
        updateData.completedAt = new Date();
      }
      const task = await storage.updateInvestigationTask(p(req.params.taskId), updateData);
      if (!task) return res.status(404).json({ message: "Task not found" });
      res.json(task);
    } catch (error) {
      res.status(500).json({ message: "Failed to update task" });
    }
  });

  app.delete("/api/incidents/:incidentId/tasks/:taskId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getInvestigationTask(p(req.params.taskId));
      if (!existing) return res.status(404).json({ message: "Task not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteInvestigationTask(p(req.params.taskId));
      if (!deleted) return res.status(404).json({ message: "Task not found" });
      res.json({ message: "Task deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete task" });
    }
  });

  // ==========================================
  // Evidence Export
  // ==========================================
  app.get("/api/incidents/:incidentId/evidence-export", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });

      const [evidence, hypotheses, tasks, incidentAlerts, timeline] = await Promise.all([
        storage.getEvidenceItems(p(req.params.incidentId), user?.orgId),
        storage.getHypotheses(p(req.params.incidentId), user?.orgId),
        storage.getInvestigationTasks(p(req.params.incidentId), user?.orgId),
        storage.getAlertsByIncident(p(req.params.incidentId)),
        storage.getAuditLogsByResource("incident", p(req.params.incidentId)),
      ]);

      res.json({
        exportedAt: new Date().toISOString(),
        incident,
        evidence,
        hypotheses,
        tasks,
        alerts: incidentAlerts,
        timeline,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to generate evidence export" });
    }
  });

  // SLA Application
  app.post("/api/incidents/:id/apply-sla", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });

      if (incident.ackDueAt || incident.containDueAt || incident.resolveDueAt) {
        return res.status(400).json({ message: "SLA timers already set for this incident" });
      }

      const orgId = (req as any).user?.orgId;
      const policies = await storage.getIncidentSlaPolicies(orgId);
      const policy = policies.find(p => p.severity === incident.severity && p.enabled === true);
      if (!policy) return res.status(404).json({ message: "No enabled SLA policy found for severity: " + incident.severity });

      const createdAt = incident.createdAt ? new Date(incident.createdAt).getTime() : Date.now();
      const ackDueAt = new Date(createdAt + policy.ackMinutes * 60 * 1000);
      const containDueAt = new Date(createdAt + policy.containMinutes * 60 * 1000);
      const resolveDueAt = new Date(createdAt + policy.resolveMinutes * 60 * 1000);

      const updated = await storage.updateIncident(p(req.params.id), { ackDueAt, containDueAt, resolveDueAt });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to apply SLA policy" });
    }
  });

  // Incident Acknowledge
  app.post("/api/incidents/:id/acknowledge", isAuthenticated, async (req, res) => {
    try {
      const updated = await storage.updateIncident(p(req.params.id), { ackAt: new Date() });
      if (!updated) return res.status(404).json({ message: "Incident not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to acknowledge incident" });
    }
  });

  // Post-Incident Reviews
  app.get("/api/incidents/:incidentId/pir", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const reviews = await storage.getPostIncidentReviews(orgId, p(req.params.incidentId));
      res.json(reviews);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch post-incident reviews" });
    }
  });

  app.post("/api/incidents/:incidentId/pir", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const userName = (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Unknown";
      const review = await storage.createPostIncidentReview({
        ...req.body,
        orgId,
        incidentId: p(req.params.incidentId),
        createdBy: userId,
        createdByName: userName,
      });
      res.status(201).json(review);
    } catch (error) {
      res.status(500).json({ message: "Failed to create post-incident review" });
    }
  });

}
