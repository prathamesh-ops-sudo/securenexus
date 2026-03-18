import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, publishOutboxEvent, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireOrgId, requirePermission, resolveOrgContext } from "../rbac";
import { bodySchemas, querySchemas, validateBody, validatePathId, validateQuery } from "../request-validator";
import { insertAlertSchema } from "@shared/schema";
import { parsePaginationParams } from "../db-performance";
import { findRelatedAlertsByEntity, getEntitiesForAlert } from "../entity-resolver";
import { cacheInvalidate } from "../query-cache";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { validateAlertFieldLengths } from "../normalizer";
import { enrichAlert, getAlertEnrichment, reEnrichAlert } from "../alert-enrichment";

// 2.13: Valid alert status transitions — enforce state machine server-side
const VALID_ALERT_TRANSITIONS: Record<string, string[]> = {
  new: ["triaged", "correlated", "investigating", "resolved", "dismissed", "false_positive"],
  triaged: ["investigating", "correlated", "resolved", "dismissed", "false_positive"],
  correlated: ["triaged", "investigating", "resolved", "dismissed", "false_positive"],
  investigating: ["resolved", "dismissed", "false_positive", "triaged"],
  resolved: ["new", "investigating"], // reopening allowed via explicit transition back
  dismissed: ["new", "investigating"], // can reopen dismissed alerts
  false_positive: ["new", "investigating"], // can reopen false positives
};

function isValidStatusTransition(currentStatus: string, newStatus: string): boolean {
  if (currentStatus === newStatus) return true; // no-op is always valid
  const allowed = VALID_ALERT_TRANSITIONS[currentStatus];
  if (!allowed) return true; // unknown current status — allow (backwards compat)
  return allowed.includes(newStatus);
}

export function registerAlertsRoutes(app: Express): void {
  // Alerts
  app.get("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { search } = req.query;
      const severity = req.query.severity as string | undefined;
      const status = req.query.status as string | undefined;
      const source = req.query.source as string | undefined;
      const { offset, limit, sortOrder } = parsePaginationParams(req.query as Record<string, unknown>);

      // Use DB-layer pagination instead of loading all alerts into memory
      const { items, total } = await storage.getAlertsPaginatedWithSort({
        orgId,
        offset,
        limit,
        search: search && typeof search === "string" ? search : undefined,
        severity,
        status,
        source,
        sortBy: "createdAt",
        sortOrder: sortOrder || "desc",
      });

      res.json(items);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.get("/api/v1/alerts", isAuthenticated, validateQuery(querySchemas.alertsList), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { offset, limit, search, severity, status, source, suppressed, sortBy, sortOrder } = (req as any)
        .validatedQuery;

      const { items, total } = await storage.getAlertsPaginatedWithSort({
        orgId,
        offset,
        limit,
        search,
        severity,
        status,
        source,
        suppressed,
        sortBy,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: {
          offset,
          limit,
          total,
          search: search ?? null,
          severity: severity ?? null,
          status: status ?? null,
          source: source ?? null,
          suppressed: suppressed ?? null,
          sortBy: sortBy ?? "createdAt",
          sortOrder,
        },
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
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert" });
    }
  });

  app.post(
    "/api/alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    enforcePlanLimit("alerts_ingested"),
    async (req, res) => {
      try {
        const parsed = insertAlertSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid alert data", errors: parsed.error.flatten() });
        }
        const lengthCheck = validateAlertFieldLengths(parsed.data);
        if (!lengthCheck.valid) {
          return res.status(400).json({ message: "Field length exceeded", errors: lengthCheck.errors });
        }
        const alert = await storage.createAlert(parsed.data);
        publishOutboxEvent(alert.orgId, "alert.created", "alert", alert.id, {
          title: alert.title,
          severity: alert.severity,
          source: alert.source,
          status: alert.status,
        });
        cacheInvalidate("dashboard:");
        if (alert.orgId) {
          try {
            await storage.incrementUsage(alert.orgId, "alerts_ingested");
          } catch (e) {
            logger.child("routes").warn("Usage tracking failed", { error: String(e), orgId: alert.orgId });
          }
        }
        res.status(201).json(alert);
      } catch (error) {
        logger.child("routes").error("Error creating alert", { error: String(error) });
        res.status(500).json({ message: "Failed to create alert" });
      }
    },
  );

  app.patch(
    "/api/alerts/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const parsed = insertAlertSchema.partial().safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
        }
        const lengthCheck = validateAlertFieldLengths(parsed.data);
        if (!lengthCheck.valid) {
          return res.status(400).json({ message: "Field length exceeded", errors: lengthCheck.errors });
        }
        // 2.13: Validate status transition if status is being changed
        if (parsed.data.status) {
          const existing = await storage.getAlert(p(req.params.id));
          if (existing && !isValidStatusTransition(existing.status, parsed.data.status)) {
            return res.status(422).json({
              message: `Invalid status transition from "${existing.status}" to "${parsed.data.status}"`,
              currentStatus: existing.status,
              requestedStatus: parsed.data.status,
              allowedTransitions: VALID_ALERT_TRANSITIONS[existing.status] || [],
            });
          }
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
    },
  );

  app.patch(
    "/api/alerts/:id/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const { status, incidentId } = req.body;
        if (!status) return res.status(400).json({ message: "Status required" });
        // 2.13: Validate status transition
        const existingForStatus = await storage.getAlert(p(req.params.id));
        if (existingForStatus && !isValidStatusTransition(existingForStatus.status, status)) {
          return res.status(422).json({
            message: `Invalid status transition from "${existingForStatus.status}" to "${status}"`,
            currentStatus: existingForStatus.status,
            requestedStatus: status,
            allowedTransitions: VALID_ALERT_TRANSITIONS[existingForStatus.status] || [],
          });
        }
        const alert = await storage.updateAlertStatus(p(req.params.id), status, incidentId);
        if (!alert) return res.status(404).json({ message: "Alert not found" });
        const closedStatuses = ["resolved", "closed", "false_positive"];
        const outboxEventType = closedStatuses.includes(status) ? "alert.closed" : "alert.updated";
        publishOutboxEvent(alert.orgId, outboxEventType, "alert", alert.id, {
          status,
          previousStatus: req.body.previousStatus || null,
        });
        cacheInvalidate("dashboard:");
        res.json(alert);
      } catch (error) {
        res.status(500).json({ message: "Failed to update alert status" });
      }
    },
  );

  app.post(
    "/api/alerts/bulk-update",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const { alertIds, status, suppressed, assignedTo } = req.body || {};
        const orgId = getOrgId(req);
        if (!Array.isArray(alertIds) || alertIds.length === 0) {
          return res.status(400).json({ message: "alertIds array is required" });
        }

        let updatedCount = 0;
        for (const id of alertIds) {
          const alertId = p(String(id));
          const existing = await storage.getAlert(alertId);
          if (!existing || existing.orgId !== orgId) continue;
          const patch: Record<string, any> = {};
          if (typeof status === "string" && status.length > 0) patch.status = status;
          if (typeof suppressed === "boolean") {
            patch.suppressed = suppressed;
            patch.suppressedBy = suppressed ? (req as any).user?.id || null : null;
          }
          if (typeof assignedTo === "string") patch.assignedTo = assignedTo.trim() || null;
          if (Object.keys(patch).length === 0) continue;
          const updated = await storage.updateAlert(alertId, patch as any);
          if (updated) updatedCount++;
        }

        await storage.createAuditLog({
          orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "alerts_bulk_update",
          resourceType: "alert",
          details: {
            updatedCount,
            status: status || null,
            suppressed: typeof suppressed === "boolean" ? suppressed : null,
            assignedTo: assignedTo || null,
          },
        });

        res.json({ updatedCount });
      } catch (error) {
        logger.child("routes").error("Bulk alert update failed", { error: String(error) });
        res.status(500).json({ message: "Failed to bulk update alerts" });
      }
    },
  );

  // Alert tags
  app.get("/api/alerts/:id/tags", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const alertTags = await storage.getAlertTags(p(req.params.id));
      res.json(alertTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert tags" });
    }
  });

  app.post(
    "/api/alerts/:id/tags",
    isAuthenticated,
    validatePathId("id"),
    validateBody(bodySchemas.incidentTagAdd),
    async (req, res) => {
      try {
        const { tagId } = (req as any).validatedBody;
        await storage.addAlertTag(p(req.params.id), tagId);
        res.status(201).json({ message: "Tag added" });
      } catch (error) {
        res.status(500).json({ message: "Failed to add tag" });
      }
    },
  );

  app.delete(
    "/api/alerts/:alertId/tags/:tagId",
    isAuthenticated,
    validatePathId("alertId"),
    validatePathId("tagId"),
    async (req, res) => {
      try {
        await storage.removeAlertTag(p(req.params.alertId), p(req.params.tagId));
        res.json({ message: "Tag removed" });
      } catch (error) {
        res.status(500).json({ message: "Failed to remove tag" });
      }
    },
  );

  app.get("/api/alerts/:id/entities", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const alertEntityList = await getEntitiesForAlert(p(req.params.id));
      res.json(alertEntityList);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert entities" });
    }
  });

  app.get("/api/alerts/:id/related", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const related = await findRelatedAlertsByEntity(p(req.params.id), alert.orgId);
      res.json(related);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch related alerts" });
    }
  });

  app.post("/api/alerts/:id/suppress", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const existing = await storage.getAlert(p(req.params.id));
      if (!existing || !orgId || existing.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const alert = await storage.updateAlert(p(req.params.id), { suppressed: true, suppressedBy: userId });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to suppress alert" });
    }
  });

  app.post("/api/alerts/:id/unsuppress", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const existing = await storage.getAlert(p(req.params.id));
      if (!existing || !orgId || existing.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
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
      const orgId = (req as any).user?.orgId;
      const existing = await storage.getAlert(p(req.params.id));
      if (!existing || !orgId || existing.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const { confidenceScore, confidenceSource, confidenceNotes } = req.body;
      const lengthCheck = validateAlertFieldLengths({ confidenceNotes });
      if (!lengthCheck.valid) {
        return res.status(400).json({ message: "Field length exceeded", errors: lengthCheck.errors });
      }
      const alert = await storage.updateAlert(p(req.params.id), { confidenceScore, confidenceSource, confidenceNotes });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert confidence" });
    }
  });

  // === 2.11: SLA lifecycle — auto-set timestamps on status transitions ===
  app.patch(
    "/api/alerts/:id/acknowledge",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getAlert(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Alert not found" });
        }
        const now = new Date();
        const patch: Record<string, unknown> = {
          status: "triaged",
          acknowledgedAt: existing.acknowledgedAt || now,
        };
        const alert = await storage.updateAlert(p(req.params.id), patch as any);
        if (!alert) return res.status(404).json({ message: "Alert not found" });
        cacheInvalidate("dashboard:");
        res.json(alert);
      } catch (error) {
        res.status(500).json({ message: "Failed to acknowledge alert" });
      }
    },
  );

  app.patch(
    "/api/alerts/:id/investigate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getAlert(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Alert not found" });
        }
        const now = new Date();
        const patch: Record<string, unknown> = {
          status: "investigating",
          acknowledgedAt: existing.acknowledgedAt || now,
          investigatingAt: existing.investigatingAt || now,
        };
        const alert = await storage.updateAlert(p(req.params.id), patch as any);
        if (!alert) return res.status(404).json({ message: "Alert not found" });
        cacheInvalidate("dashboard:");
        res.json(alert);
      } catch (error) {
        res.status(500).json({ message: "Failed to mark alert as investigating" });
      }
    },
  );

  app.patch(
    "/api/alerts/:id/resolve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getAlert(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Alert not found" });
        }
        const now = new Date();
        const patch: Record<string, unknown> = {
          status: "resolved",
          acknowledgedAt: existing.acknowledgedAt || now,
          investigatingAt: existing.investigatingAt || now,
          resolvedAt: existing.resolvedAt || now,
        };
        const alert = await storage.updateAlert(p(req.params.id), patch as any);
        if (!alert) return res.status(404).json({ message: "Alert not found" });
        cacheInvalidate("dashboard:");
        res.json(alert);
      } catch (error) {
        res.status(500).json({ message: "Failed to resolve alert" });
      }
    },
  );

  // === 2.11: Alert SLA policies CRUD ===
  app.get("/api/alert-sla-policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policies = await storage.getAlertSlaPolicies(orgId);
      res.json(policies);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert SLA policies" });
    }
  });

  app.post(
    "/api/alert-sla-policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("settings", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, severity, ackMinutes, investigateMinutes, resolveMinutes } = req.body;
        if (!name || !severity || !ackMinutes || !investigateMinutes || !resolveMinutes) {
          return res.status(400).json({ message: "All fields required" });
        }
        const policy = await storage.createAlertSlaPolicy({
          orgId,
          name,
          severity,
          ackMinutes,
          investigateMinutes,
          resolveMinutes,
        });
        res.status(201).json(policy);
      } catch (error) {
        res.status(500).json({ message: "Failed to create SLA policy" });
      }
    },
  );

  // === 2.12: Alert Enrichment endpoints ===
  app.get("/api/alerts/:id/enrichment", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const enrichment = await getAlertEnrichment(p(req.params.id));
      res.json(enrichment || { geoIp: null, whois: null, virusTotal: null, mitre: null, enrichedAt: null });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert enrichment" });
    }
  });

  app.post(
    "/api/alerts/:id/enrich",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getAlert(p(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ message: "Alert not found" });
        }
        const enrichment = await reEnrichAlert(p(req.params.id));
        res.json(enrichment);
      } catch (error) {
        res.status(500).json({ message: "Failed to enrich alert" });
      }
    },
  );

  // === 2.9: Dedup cluster detail endpoint ===
  app.get("/api/dedup-clusters/:id/alerts", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const clusterAlerts = await storage.getAlertsByDedupCluster(p(req.params.id), orgId);
      res.json(clusterAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch cluster alerts" });
    }
  });

  // === 2.15: Alert → Incident escalation with pre-fill ===
  app.post(
    "/api/alerts/:id/escalate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const alert = await storage.getAlert(p(req.params.id));
        if (!alert || alert.orgId !== orgId) {
          return res.status(404).json({ message: "Alert not found" });
        }
        // Build pre-filled incident data from alert
        const incidentData = {
          orgId,
          title: `[Escalated] ${alert.title}`,
          summary: alert.description || `Escalated from alert: ${alert.title}`,
          severity: alert.severity === "informational" ? "low" : alert.severity,
          status: "open",
          priority:
            alert.severity === "critical" ? 1 : alert.severity === "high" ? 2 : alert.severity === "medium" ? 3 : 4,
          mitreTactics: alert.mitreTactic ? [alert.mitreTactic] : [],
          mitreTechniques: alert.mitreTechnique ? [alert.mitreTechnique] : [],
          affectedAssets: [alert.hostname, alert.sourceIp, alert.destIp].filter(Boolean),
          iocs: [alert.sourceIp, alert.destIp, alert.domain, alert.fileHash, alert.url].filter(Boolean),
          ...(req.body.overrides || {}),
        };
        const incident = await storage.createIncident(incidentData as any);
        // Link the alert to the new incident
        await storage.updateAlert(p(req.params.id), {
          incidentId: incident.id,
          status: "investigating",
          acknowledgedAt: alert.acknowledgedAt || new Date(),
          investigatingAt: alert.investigatingAt || new Date(),
        } as any);
        publishOutboxEvent(orgId, "incident.created", "incident", incident.id, {
          title: incident.title,
          severity: incident.severity,
          escalatedFromAlert: alert.id,
        });
        cacheInvalidate("dashboard:");
        res.status(201).json({ incident, alertId: alert.id });
      } catch (error) {
        logger.child("routes").error("Failed to escalate alert to incident", { error: String(error) });
        res.status(500).json({ message: "Failed to escalate alert" });
      }
    },
  );

  // === 2.16: Alert → Playbook trigger ===
  app.get("/api/alerts/:id/available-playbooks", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      const allPlaybooks = await storage.getPlaybooks(orgId);
      // Filter by trigger type — show manual and alert-related playbooks
      const matching = allPlaybooks.filter((pb) => {
        const trigger = pb.trigger || "";
        if (trigger === "manual") return true;
        if (trigger === "alert_created" || trigger === "alert_severity") return true;
        return true;
      });
      res.json(
        matching.map((pb) => ({
          id: pb.id,
          name: pb.name,
          description: pb.description,
          trigger: pb.trigger,
          status: pb.status,
          enabled: pb.status === "active",
        })),
      );
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch available playbooks" });
    }
  });

  app.post(
    "/api/alerts/:id/trigger-playbook",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id;
        const { playbookId } = req.body;
        if (!playbookId) {
          return res.status(400).json({ message: "playbookId is required" });
        }
        const alert = await storage.getAlert(p(req.params.id));
        if (!alert || alert.orgId !== orgId) {
          return res.status(404).json({ message: "Alert not found" });
        }
        const playbook = await storage.getPlaybook(playbookId);
        if (!playbook || playbook.orgId !== orgId) {
          return res.status(404).json({ message: "Playbook not found" });
        }
        // Create execution with alert context pre-filled
        const execution = await storage.createPlaybookExecution({
          playbookId,
          triggeredBy: userId || "system",
          status: "pending",
          triggerData: {
            alertId: alert.id,
            alertTitle: alert.title,
            alertSeverity: alert.severity,
            alertSource: alert.source,
            alertCategory: alert.category,
            sourceIp: alert.sourceIp,
            destIp: alert.destIp,
            hostname: alert.hostname,
            domain: alert.domain,
            mitreTactic: alert.mitreTactic,
            mitreTechnique: alert.mitreTechnique,
          },
        } as any);
        publishOutboxEvent(orgId, "playbook.triggered", "playbook", playbookId, {
          executionId: execution.id,
          alertId: alert.id,
          playbookName: playbook.name,
        });
        res.status(201).json({ execution, playbookName: playbook.name, alertId: alert.id });
      } catch (error) {
        logger.child("routes").error("Failed to trigger playbook from alert", { error: String(error) });
        res.status(500).json({ message: "Failed to trigger playbook" });
      }
    },
  );

  // === 2.17: Alert → War Room link ===
  app.get("/api/alerts/:id/war-room", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert || !orgId || alert.orgId !== orgId) {
        return res.status(404).json({ message: "Alert not found" });
      }
      // If alert is linked to an incident, check for war rooms
      if (!alert.incidentId) {
        return res.json({ hasWarRoom: false, warRoom: null });
      }
      const rooms = await storage.getWarRooms(orgId);
      const linkedRoom = rooms.find((r) => r.incidentId === alert.incidentId && r.status !== "closed");
      if (linkedRoom) {
        return res.json({
          hasWarRoom: true,
          warRoom: {
            id: linkedRoom.id,
            name: linkedRoom.name,
            status: linkedRoom.status,
            severity: linkedRoom.severity,
            incidentId: linkedRoom.incidentId,
            createdAt: linkedRoom.createdAt,
          },
        });
      }
      res.json({ hasWarRoom: false, warRoom: null });
    } catch (error) {
      res.status(500).json({ message: "Failed to check war room link" });
    }
  });

  // === Alert Archive (Cold Storage) ===
  app.get("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(Math.max(1, parseInt(req.query.limit as string, 10) || 50), 200);
      const offset = Math.max(0, parseInt(req.query.offset as string, 10) || 0);
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
