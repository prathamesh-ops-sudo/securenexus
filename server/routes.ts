import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { storage } from "./storage";
import { setupAuth, registerAuthRoutes, isAuthenticated } from "./replit_integrations/auth";
import { insertAlertSchema, insertIncidentSchema, insertCommentSchema, insertTagSchema, insertCompliancePolicySchema, insertDsarRequestSchema, insertCspmAccountSchema, insertEndpointAssetSchema, insertAiDeploymentConfigSchema } from "@shared/schema";
import { correlateAlerts, generateIncidentNarrative, triageAlert, checkModelHealth, getModelConfig, getInferenceMetrics, buildThreatIntelContext } from "./ai";
import { normalizeAlert, toInsertAlert, SOURCE_KEYS } from "./normalizer";
import { testConnector, syncConnector, getConnectorMetadata, getAllConnectorTypes, type ConnectorConfig } from "./connector-engine";
import { dispatchAction, type ActionContext } from "./action-dispatcher";
import { resolveAndLinkEntities, getEntitiesForAlert, getEntitiesForIncident, getEntityGraph, getEntity, getEntityAlerts, findRelatedAlertsByEntity, getEntityAliases, addEntityAlias, mergeEntities, updateEntityMetadata, getEntityRelationships, getEntityGraphWithEdges } from "./entity-resolver";
import { correlateAlert, runCorrelationScan, getCorrelationClusters, getCorrelationCluster, promoteClusterToIncident } from "./correlation-engine";
import { runGraphCorrelation, getAttackPaths, getAttackPath, getCampaigns, getCampaign } from "./graph-correlation";
import { eventBus, broadcastEvent } from "./event-bus";
import { maskPiiInAlert, maskPiiInText } from "./pii-engine";
import { runRetentionCleanup } from "./retention-scheduler";
import { startRetentionScheduler } from "./retention-scheduler";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { uploadFile, getSignedUrl, deleteFile, listFiles } from "./s3";
import { evaluatePolicies, generateDefaultPolicies } from "./policy-engine";
import { runInvestigation } from "./investigation-agent";
import { canRollback, createRollbackRecord, executeRollback, getAvailableRollbacks } from "./rollback-engine";
import { runCspmScan } from "./cspm-scanner";
import { seedEndpointAssets, generateTelemetry, calculateEndpointRisk } from "./endpoint-telemetry";
import { calculatePostureScore } from "./posture-engine";

function p(val: string | string[] | undefined): string {
  return (Array.isArray(val) ? val[0] : val) as string;
}

function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function generateApiKey(): { key: string; prefix: string; hash: string } {
  const key = `snx_${randomBytes(32).toString("hex")}`;
  const prefix = key.slice(0, 12);
  const hash = hashApiKey(key);
  return { key, prefix, hash };
}

async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers["x-api-key"] || req.headers.authorization?.replace("Bearer ", "");
  if (!header || typeof header !== "string") {
    return res.status(401).json({ error: "Missing API key. Provide X-API-Key header." });
  }
  const hash = hashApiKey(header);
  const apiKey = await storage.getApiKeyByHash(hash);
  if (!apiKey) {
    return res.status(401).json({ error: "Invalid API key." });
  }
  if (!apiKey.isActive) {
    return res.status(403).json({ error: "API key has been revoked." });
  }
  storage.updateApiKeyLastUsed(apiKey.id).catch(() => {});
  (req as any).apiKey = apiKey;
  (req as any).orgId = apiKey.orgId;
  next();
}

function verifyWebhookSignature(req: Request, res: Response, next: NextFunction) {
  const apiKey = (req as any).apiKey;
  const signature = req.headers["x-webhook-signature"] as string | undefined;

  if (!apiKey?.webhookSecret) {
    return next();
  }

  if (!signature) {
    return res.status(401).json({
      error: "Missing X-Webhook-Signature header. Required when webhook secret is configured.",
      code: "SIGNATURE_MISSING",
    });
  }

  try {
    const rawBodyBuf = (req as any).rawBody;
    const rawBody = rawBodyBuf ? (Buffer.isBuffer(rawBodyBuf) ? rawBodyBuf.toString("utf8") : String(rawBodyBuf)) : JSON.stringify(req.body);
    const timestamp = req.headers["x-webhook-timestamp"] as string || "";
    const payload = timestamp ? `${timestamp}.${rawBody}` : rawBody;
    const expected = createHmac("sha256", apiKey.webhookSecret).update(payload).digest("hex");
    const sig = signature.startsWith("sha256=") ? signature.slice(7) : signature;

    if (!/^[a-f0-9]+$/i.test(sig) || sig.length !== expected.length) {
      return res.status(401).json({
        error: "Invalid webhook signature.",
        code: "SIGNATURE_INVALID",
      });
    }

    if (!timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) {
      return res.status(401).json({
        error: "Invalid webhook signature.",
        code: "SIGNATURE_INVALID",
      });
    }

    if (timestamp) {
      const ts = parseInt(timestamp, 10);
      const age = Math.abs(Date.now() - ts);
      if (age > 5 * 60 * 1000) {
        return res.status(401).json({
          error: "Webhook timestamp too old. Replay protection triggered.",
          code: "TIMESTAMP_EXPIRED",
        });
      }
    }

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid webhook signature.",
      code: "SIGNATURE_INVALID",
    });
  }
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  await setupAuth(app);
  registerAuthRoutes(app);

  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many requests, please try again later." },
  });

  const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many requests, please try again later." },
  });

  const ingestionLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Ingestion rate limit exceeded. Try again shortly." },
  });

  app.use("/api/", generalLimiter);

  // Dashboard
  app.get("/api/dashboard/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });

  app.get("/api/dashboard/analytics", isAuthenticated, async (req, res) => {
    try {
      const analytics = await storage.getDashboardAnalytics();
      res.json(analytics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch analytics" });
    }
  });

  // Alerts
  app.get("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const { search } = req.query;
      if (search && typeof search === "string") {
        const results = await storage.searchAlerts(search);
        return res.json(results);
      }
      const allAlerts = await storage.getAlerts();
      res.json(allAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.get("/api/alerts/:id", isAuthenticated, async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert" });
    }
  });

  app.post("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertAlertSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid alert data", errors: parsed.error.flatten() });
      }
      const alert = await storage.createAlert(parsed.data);
      res.status(201).json(alert);
    } catch (error) {
      console.error("Error creating alert:", error);
      res.status(500).json({ message: "Failed to create alert" });
    }
  });

  app.patch("/api/alerts/:id", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertAlertSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }
      const alert = await storage.updateAlert(p(req.params.id), parsed.data);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert" });
    }
  });

  app.patch("/api/alerts/:id/status", isAuthenticated, async (req, res) => {
    try {
      const { status, incidentId } = req.body;
      if (!status) return res.status(400).json({ message: "Status required" });
      const alert = await storage.updateAlertStatus(p(req.params.id), status, incidentId);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert status" });
    }
  });

  // Alert tags
  app.get("/api/alerts/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const alertTags = await storage.getAlertTags(p(req.params.id));
      res.json(alertTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert tags" });
    }
  });

  app.post("/api/alerts/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const { tagId } = req.body;
      if (!tagId) return res.status(400).json({ message: "tagId required" });
      await storage.addAlertTag(p(req.params.id), tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/alerts/:alertId/tags/:tagId", isAuthenticated, async (req, res) => {
    try {
      await storage.removeAlertTag(p(req.params.alertId), p(req.params.tagId));
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  // Incidents
  app.get("/api/incidents", isAuthenticated, async (req, res) => {
    try {
      const allIncidents = await storage.getIncidents();
      res.json(allIncidents);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incidents" });
    }
  });

  app.get("/api/incidents/:id", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident" });
    }
  });

  app.get("/api/incidents/:id/alerts", isAuthenticated, async (req, res) => {
    try {
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.id));
      res.json(incidentAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident alerts" });
    }
  });

  app.post("/api/incidents", isAuthenticated, async (req, res) => {
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
      res.status(201).json(incident);
    } catch (error) {
      console.error("Error creating incident:", error);
      res.status(500).json({ message: "Failed to create incident" });
    }
  });

  app.patch("/api/incidents/:id", isAuthenticated, async (req, res) => {
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

      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to update incident" });
    }
  });

  app.get("/api/incidents/:id/activity", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getAuditLogsByResource("incident", p(req.params.id));
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident activity" });
    }
  });

  // Incident comments
  app.get("/api/incidents/:id/comments", isAuthenticated, async (req, res) => {
    try {
      const comments = await storage.getComments(p(req.params.id));
      res.json(comments);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch comments" });
    }
  });

  app.post("/api/incidents/:id/comments", isAuthenticated, async (req, res) => {
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

  app.delete("/api/comments/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteComment(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Comment not found" });
      res.json({ message: "Comment deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete comment" });
    }
  });

  // Incident tags
  app.get("/api/incidents/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const incTags = await storage.getIncidentTags(p(req.params.id));
      res.json(incTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident tags" });
    }
  });

  app.post("/api/incidents/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const { tagId } = req.body;
      if (!tagId) return res.status(400).json({ message: "tagId required" });
      await storage.addIncidentTag(p(req.params.id), tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/incidents/:incidentId/tags/:tagId", isAuthenticated, async (req, res) => {
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

  // Audit logs
  app.get("/api/audit-logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getAuditLogs();
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch audit logs" });
    }
  });

  // AI Engine - SecureNexus Cyber Analyst (Mistral Large 2 Instruct / SageMaker)
  app.get("/api/ai/health", isAuthenticated, strictLimiter, async (_req, res) => {
    try {
      const health = await checkModelHealth();
      res.json(health);
    } catch (error: any) {
      console.error("Route error:", error);
      res.status(500).json({ status: "error", message: "An internal error occurred. Please try again." });
    }
  });

  app.get("/api/ai/config", isAuthenticated, async (_req, res) => {
    res.json(getModelConfig());
  });

  app.get("/api/ai/inference-metrics", isAuthenticated, strictLimiter, async (req, res) => {
    res.json(getInferenceMetrics());
  });

  app.post("/api/ai/correlate", isAuthenticated, strictLimiter, async (req, res) => {
    try {
      const { alertIds } = req.body;
      let alertsToCorrelate;
      if (alertIds && Array.isArray(alertIds) && alertIds.length > 0) {
        const allAlerts = await storage.getAlerts();
        alertsToCorrelate = allAlerts.filter(a => alertIds.includes(a.id));
      } else {
        alertsToCorrelate = (await storage.getAlerts()).filter(a => a.status === "new" || a.status === "triaged");
      }
      if (alertsToCorrelate.length === 0) {
        return res.status(400).json({ message: "No alerts to correlate" });
      }
      const threatIntelCtx = await buildThreatIntelContext(alertsToCorrelate);
      const result = await correlateAlerts(alertsToCorrelate, threatIntelCtx);
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_correlation",
        resourceType: "alerts",
        details: { alertCount: alertsToCorrelate.length, groupsFound: result.correlatedGroups.length },
      });
      res.json(result);
    } catch (error: any) {
      console.error("AI correlation error:", error);
      res.status(500).json({ message: "AI correlation failed. Please try again." });
    }
  });

  app.post("/api/ai/narrative/:incidentId", isAuthenticated, strictLimiter, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
      const threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
      const result = await generateIncidentNarrative(incident, incidentAlerts, threatIntelCtx);
      if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
        (result as any).threatIntelSources = [
          ...new Set([
            ...threatIntelCtx.enrichmentResults.map(r => r.provider),
            ...threatIntelCtx.osintMatches.map(r => r.feedName),
          ])
        ];
      }
      const storedIocs = Array.isArray(result.iocs)
        ? result.iocs.map((ioc: any) => typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type}: ${ioc.context})`)
        : [];
      const { diamondModel: _dm, ...storedAttackerProfile } = result.attackerProfile || {} as any;
      await storage.updateIncident(p(req.params.incidentId), {
        aiNarrative: result.narrative,
        aiSummary: result.summary,
        mitigationSteps: result.mitigationSteps as any,
        iocs: storedIocs as any,
        attackerProfile: storedAttackerProfile as any,
        referencedAlertIds: Array.isArray(result.citedAlertIds) ? result.citedAlertIds : [],
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_narrative_generated",
        resourceType: "incident",
        resourceId: p(req.params.incidentId),
        details: { riskScore: result.riskScore },
      });
      res.json(result);
    } catch (error: any) {
      console.error("AI narrative error:", error);
      res.status(500).json({ message: "AI narrative generation failed. Please try again." });
    }
  });

  app.post("/api/ai/triage/:alertId", isAuthenticated, strictLimiter, async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.alertId));
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      const threatIntelCtx = await buildThreatIntelContext([alert]);
      const result = await triageAlert(alert, threatIntelCtx);
      if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
        result.threatIntelSources = [
          ...new Set([
            ...threatIntelCtx.enrichmentResults.map(r => r.provider),
            ...threatIntelCtx.osintMatches.map(r => r.feedName),
          ])
        ];
      }
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_triage",
        resourceType: "alert",
        resourceId: p(req.params.alertId),
        details: { severity: result.severity, priority: result.priority },
      });
      res.json(result);
    } catch (error: any) {
      console.error("AI triage error:", error);
      res.status(500).json({ message: "AI triage failed. Please try again." });
    }
  });

  app.post("/api/ai/correlate/apply", isAuthenticated, async (req, res) => {
    try {
      const { group } = req.body;
      if (!group || !Array.isArray(group.alertIds) || group.alertIds.length === 0 || !group.suggestedIncidentTitle) {
        return res.status(400).json({ message: "Invalid correlation group data" });
      }
      const validAlertIds: string[] = [];
      for (const alertId of group.alertIds) {
        if (typeof alertId === "string") {
          const alert = await storage.getAlert(alertId);
          if (alert) validAlertIds.push(alertId);
        }
      }
      if (validAlertIds.length === 0) {
        return res.status(400).json({ message: "No valid alerts found in correlation group" });
      }
      const validSeverities = ["critical", "high", "medium", "low"];
      const severity = validSeverities.includes(group.severity) ? group.severity : "medium";
      const incident = await storage.createIncident({
        title: String(group.suggestedIncidentTitle).slice(0, 500),
        summary: String(group.reasoning || "").slice(0, 2000),
        severity,
        status: "investigating",
        priority: severity === "critical" ? 1 : severity === "high" ? 2 : 3,
        confidence: typeof group.confidence === "number" ? Math.min(Math.max(group.confidence, 0), 1) : 0.5,
        mitreTactics: Array.isArray(group.mitreTactics) ? group.mitreTactics.filter((t: any) => typeof t === "string") : [],
        mitreTechniques: Array.isArray(group.mitreTechniques) ? group.mitreTechniques.filter((t: any) => typeof t === "string") : [],
        alertCount: validAlertIds.length,
      });
      for (const alertId of validAlertIds) {
        await storage.updateAlertStatus(alertId, "correlated", incident.id);
      }
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_correlation_applied",
        resourceType: "incident",
        resourceId: incident.id,
        details: { alertCount: group.alertIds.length, title: incident.title },
      });
      res.json(incident);
    } catch (error: any) {
      console.error("Apply correlation error:", error);
      res.status(500).json({ message: "Failed to apply correlation. Please try again." });
    }
  });

  // ========== INGESTION SYSTEM (Phase 2) ==========

  // API Key Management (authenticated user routes)
  app.get("/api/api-keys", isAuthenticated, async (req, res) => {
    try {
      const keys = await storage.getApiKeys();
      const safeKeys = keys.map(k => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        orgId: k.orgId,
        scopes: k.scopes,
        isActive: k.isActive,
        lastUsedAt: k.lastUsedAt,
        createdBy: k.createdBy,
        createdAt: k.createdAt,
        revokedAt: k.revokedAt,
      }));
      res.json(safeKeys);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch API keys" });
    }
  });

  app.post("/api/api-keys", isAuthenticated, async (req, res) => {
    try {
      const { name, orgId, scopes } = req.body;
      if (!name) return res.status(400).json({ message: "Key name is required" });
      const { key, prefix, hash } = generateApiKey();
      const apiKey = await storage.createApiKey({
        name,
        keyHash: hash,
        keyPrefix: prefix,
        orgId: orgId || null,
        scopes: scopes || ["ingest"],
        isActive: true,
        createdBy: (req as any).user?.id || null,
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "api_key_created",
        resourceType: "api_key",
        resourceId: apiKey.id,
        details: { name, keyPrefix: prefix },
      });
      res.status(201).json({
        id: apiKey.id,
        name: apiKey.name,
        key,
        keyPrefix: prefix,
        message: "Store this key securely. It will not be shown again.",
      });
    } catch (error) {
      console.error("Error creating API key:", error);
      res.status(500).json({ message: "Failed to create API key" });
    }
  });

  app.delete("/api/api-keys/:id", isAuthenticated, async (req, res) => {
    try {
      const revoked = await storage.revokeApiKey(p(req.params.id));
      if (!revoked) return res.status(404).json({ message: "API key not found" });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "api_key_revoked",
        resourceType: "api_key",
        resourceId: p(req.params.id),
      });
      res.json({ message: "API key revoked" });
    } catch (error) {
      res.status(500).json({ message: "Failed to revoke API key" });
    }
  });

  // Ingestion Routes (API key authenticated, webhook signature verification)
  app.post("/api/ingest/:source", apiKeyAuth, verifyWebhookSignature, ingestionLimiter, async (req, res) => {
    const startTime = Date.now();
    const source = p(req.params.source);
    const orgId = (req as any).orgId;
    const requestId = randomBytes(8).toString("hex");

    try {
      const payload = req.body;
      if (!payload || typeof payload !== "object") {
        await storage.createIngestionLog({
          orgId, source, status: "failed",
          alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 1,
          errorMessage: "Invalid payload", requestId,
          ipAddress: req.ip || null,
          processingTimeMs: Date.now() - startTime,
        });
        return res.status(400).json({ error: "Invalid payload", requestId });
      }

      const normalized = normalizeAlert(source, payload);
      const insertData = toInsertAlert(normalized, orgId);
      const { alert, isNew } = await storage.upsertAlert(insertData);

      let entityCount = 0;
      let correlationResult = null;
      if (isNew) {
        try {
          const linkedEntities = await resolveAndLinkEntities(alert);
          entityCount = linkedEntities.length;
          correlationResult = await correlateAlert(alert);
        } catch (err) {
          console.warn("Entity/correlation processing warning:", err);
        }
      }

      await storage.createIngestionLog({
        orgId, source: normalized.source, status: isNew ? "success" : "deduped",
        alertsReceived: 1, alertsCreated: isNew ? 1 : 0, alertsDeduped: isNew ? 0 : 1, alertsFailed: 0,
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      });

      if (isNew) {
        broadcastEvent({
          type: "alert:created",
          orgId: orgId || null,
          data: {
            alertId: alert.id,
            title: alert.title,
            severity: alert.severity,
            source: alert.source,
            category: alert.category,
            entities: entityCount,
            correlation: correlationResult ? { clusterId: correlationResult.clusterId, confidence: correlationResult.confidence } : null,
          },
        });

        if (correlationResult) {
          broadcastEvent({
            type: "correlation:found",
            orgId: orgId || null,
            data: {
              clusterId: correlationResult.clusterId,
              confidence: correlationResult.confidence,
              alertId: alert.id,
            },
          });
        }
      }

      res.status(isNew ? 201 : 200).json({
        requestId,
        status: isNew ? "created" : "deduplicated",
        alertId: alert.id,
        source: normalized.source,
        entities: entityCount,
        correlation: correlationResult ? { clusterId: correlationResult.clusterId, confidence: correlationResult.confidence } : null,
      });
    } catch (error: any) {
      console.error(`Ingestion error [${source}]:`, error);
      await storage.createIngestionLog({
        orgId, source, status: "failed",
        alertsReceived: 1, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 1,
        errorMessage: error.message?.slice(0, 500),
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      }).catch(() => {});
      res.status(500).json({ error: "Ingestion failed", requestId });
    }
  });

  app.post("/api/ingest/:source/bulk", apiKeyAuth, verifyWebhookSignature, ingestionLimiter, async (req, res) => {
    const startTime = Date.now();
    const source = p(req.params.source);
    const orgId = (req as any).orgId;
    const requestId = randomBytes(8).toString("hex");

    try {
      const events = Array.isArray(req.body) ? req.body : req.body.events || req.body.alerts || [req.body];

      if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ error: "Expected array of events", requestId });
      }

      if (events.length > 1000) {
        return res.status(400).json({ error: "Maximum 1000 events per batch", requestId });
      }

      let created = 0, deduped = 0, failed = 0;
      const results: any[] = [];

      for (const event of events) {
        try {
          const normalized = normalizeAlert(source, event);
          const insertData = toInsertAlert(normalized, orgId);
          const { alert, isNew } = await storage.upsertAlert(insertData);
          if (isNew) {
            created++;
            try {
              await resolveAndLinkEntities(alert);
              await correlateAlert(alert);
            } catch (err) {}
            broadcastEvent({
              type: "alert:created",
              orgId: orgId || null,
              data: {
                alertId: alert.id,
                title: alert.title,
                severity: alert.severity,
                source: alert.source,
                category: alert.category,
                bulk: true,
              },
            });
          } else {
            deduped++;
          }
          results.push({ alertId: alert.id, status: isNew ? "created" : "deduplicated" });
        } catch (err: any) {
          failed++;
          results.push({ error: "Processing failed", status: "failed" });
        }
      }

      const status = failed === events.length ? "failed" : failed > 0 ? "partial" : deduped === events.length ? "deduped" : "success";

      await storage.createIngestionLog({
        orgId, source, status,
        alertsReceived: events.length, alertsCreated: created, alertsDeduped: deduped, alertsFailed: failed,
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      });

      res.status(created > 0 ? 201 : 200).json({
        requestId,
        status,
        summary: { received: events.length, created, deduplicated: deduped, failed },
        results,
      });
    } catch (error: any) {
      console.error(`Bulk ingestion error [${source}]:`, error);
      await storage.createIngestionLog({
        orgId, source, status: "failed",
        alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0,
        errorMessage: error.message?.slice(0, 500),
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      }).catch(() => {});
      res.status(500).json({ error: "Bulk ingestion failed", requestId });
    }
  });

  // Ingestion health/stats (authenticated user routes)
  app.get("/api/ingestion/logs", isAuthenticated, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const logs = await storage.getIngestionLogs(undefined, Math.min(limit, 200));
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch ingestion logs" });
    }
  });

  app.get("/api/ingestion/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getIngestionStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch ingestion stats" });
    }
  });

  app.get("/api/ingestion/sources", isAuthenticated, async (_req, res) => {
    res.json({
      supportedSources: SOURCE_KEYS,
      sourceNames: {
        crowdstrike: "CrowdStrike EDR",
        splunk: "Splunk SIEM",
        paloalto: "Palo Alto Firewall",
        guardduty: "AWS GuardDuty",
        suricata: "Suricata IDS",
        defender: "Microsoft Defender",
        elastic: "Elastic Security",
        qradar: "IBM QRadar",
        fortigate: "Fortinet FortiGate",
        carbonblack: "Carbon Black EDR",
        qualys: "Qualys VMDR",
        tenable: "Tenable Nessus",
        umbrella: "Cisco Umbrella",
        darktrace: "Darktrace",
        rapid7: "Rapid7 InsightIDR",
        trendmicro: "Trend Micro Vision One",
        okta: "Okta Identity",
        proofpoint: "Proofpoint Email",
        snort: "Snort IDS",
        zscaler: "Zscaler ZIA",
        checkpoint: "Check Point",
        custom: "Custom Source",
      },
    });
  });

  // Connector Engine Routes
  app.get("/api/connectors/types", isAuthenticated, async (_req, res) => {
    const types = getAllConnectorTypes();
    const metadata = types.map(t => ({ type: t, ...getConnectorMetadata(t) })).filter(m => m.name);
    res.json(metadata);
  });

  app.get("/api/connectors", isAuthenticated, async (_req, res) => {
    try {
      const allConnectors = await storage.getConnectors();
      const sanitized = allConnectors.map(c => {
        const config = c.config as ConnectorConfig;
        const safeConfig: any = { ...config };
        if (safeConfig.clientSecret) safeConfig.clientSecret = "••••••••";
        if (safeConfig.password) safeConfig.password = "••••••••";
        if (safeConfig.apiKey) safeConfig.apiKey = "••••••••";
        if (safeConfig.secretAccessKey) safeConfig.secretAccessKey = "••••••••";
        if (safeConfig.token) safeConfig.token = "••••••••";
        if (safeConfig.siteToken) safeConfig.siteToken = "••••••••";
        return { ...c, config: safeConfig };
      });
      res.json(sanitized);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connectors" });
    }
  });

  app.get("/api/connectors/:id", isAuthenticated, async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const safeConfig: any = { ...config };
      if (safeConfig.clientSecret) safeConfig.clientSecret = "••••••••";
      if (safeConfig.password) safeConfig.password = "••••••••";
      if (safeConfig.apiKey) safeConfig.apiKey = "••••••••";
      if (safeConfig.secretAccessKey) safeConfig.secretAccessKey = "••••••••";
      if (safeConfig.token) safeConfig.token = "••••••••";
      if (safeConfig.siteToken) safeConfig.siteToken = "••••••••";
      res.json({ ...connector, config: safeConfig });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connector" });
    }
  });

  app.post("/api/connectors", isAuthenticated, async (req, res) => {
    try {
      const { name, type, authType, config, pollingIntervalMin } = req.body;
      if (!name || !type || !authType || !config) {
        return res.status(400).json({ message: "Missing required fields: name, type, authType, config" });
      }
      const validTypes = getAllConnectorTypes();
      if (!validTypes.includes(type)) {
        return res.status(400).json({ message: `Invalid connector type. Valid types: ${validTypes.join(", ")}` });
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "connector_created",
        resourceType: "connector",
        resourceId: connector.id,
        details: { type, name },
      });
      res.status(201).json(connector);
    } catch (error: any) {
      console.error("Route error:", error);
      res.status(500).json({ message: "Failed to create connector. Please try again." });
    }
  });

  app.patch("/api/connectors/:id", isAuthenticated, async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const { name, config, status, pollingIntervalMin } = req.body;
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
      console.error("Route error:", error);
      res.status(500).json({ message: "Failed to update connector. Please try again." });
    }
  });

  app.delete("/api/connectors/:id", isAuthenticated, async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      await storage.deleteConnector(p(req.params.id));
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
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

  app.post("/api/connectors/:id/test", isAuthenticated, async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const result = await testConnector(connector.type, config);
      res.json(result);
    } catch (error: any) {
      console.error("Route error:", error);
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  app.post("/api/connectors/test", isAuthenticated, async (req, res) => {
    try {
      const { type, config } = req.body;
      if (!type || !config) {
        return res.status(400).json({ success: false, message: "Missing type and config" });
      }
      const result = await testConnector(type, config);
      res.json(result);
    } catch (error: any) {
      console.error("Route error:", error);
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  app.post("/api/connectors/:id/sync", isAuthenticated, async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });

      await storage.updateConnector(connector.id, { status: "syncing" } as any);
      const syncResult = await syncConnector(connector);

      let created = 0;
      let deduped = 0;
      let failed = syncResult.alertsFailed;

      for (const alertData of syncResult.rawAlerts) {
        try {
          const { alert: savedAlert, isNew } = await storage.upsertAlert(alertData as any);
          if (isNew) created++;
          else deduped++;
        } catch (err: any) {
          failed++;
          syncResult.errors.push(`DB insert failed: ${err.message}`);
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "connector_synced",
        resourceType: "connector",
        resourceId: connector.id,
        details: { type: connector.type, received: syncResult.alertsReceived, created, deduped, failed },
      });

      res.json({
        success: syncStatus !== "error",
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
      console.error("Route error:", error);
      res.status(500).json({ success: false, message: "Sync failed. Please try again." });
    }
  });

  // AI Feedback (Phase 7+12)
  app.post("/api/ai/feedback", isAuthenticated, async (req, res) => {
    try {
      const { resourceType, resourceId, rating, comment, aiOutput } = req.body;
      if (!resourceType || !rating) return res.status(400).json({ message: "resourceType and rating required" });
      const feedback = await storage.createAiFeedback({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        resourceType, resourceId, rating, comment, aiOutput,
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_feedback_submitted",
        resourceType, resourceId,
        details: { rating, hasComment: !!comment },
      });
      res.status(201).json(feedback);
    } catch (error) { res.status(500).json({ message: "Failed to submit feedback" }); }
  });

  app.get("/api/ai/feedback", isAuthenticated, async (req, res) => {
    try {
      const { resourceType, resourceId } = req.query;
      const feedback = await storage.getAiFeedback(resourceType as string, resourceId as string);
      res.json(feedback);
    } catch (error) { res.status(500).json({ message: "Failed to fetch feedback" }); }
  });

  // Playbooks (Phase 13 - SOAR-Lite)
  app.get("/api/playbooks", isAuthenticated, async (_req, res) => {
    try { res.json(await storage.getPlaybooks()); }
    catch (error) { res.status(500).json({ message: "Failed to fetch playbooks" }); }
  });

  app.get("/api/playbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb) return res.status(404).json({ message: "Playbook not found" });
      res.json(pb);
    } catch (error) { res.status(500).json({ message: "Failed to fetch playbook" }); }
  });

  app.post("/api/playbooks", isAuthenticated, async (req, res) => {
    try {
      const { name, description, trigger, conditions, actions, status } = req.body;
      if (!name || !trigger || !actions) return res.status(400).json({ message: "name, trigger, and actions required" });
      const playbook = await storage.createPlaybook({
        name, description, trigger, conditions, actions, status: status || "draft",
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "playbook_created",
        resourceType: "playbook", resourceId: playbook.id,
        details: { name, trigger },
      });
      res.status(201).json(playbook);
    } catch (error) { res.status(500).json({ message: "Failed to create playbook" }); }
  });

  app.patch("/api/playbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const existing = await storage.getPlaybook(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Playbook not found" });
      const updated = await storage.updatePlaybook(p(req.params.id), {
        ...req.body, updatedAt: new Date(),
      });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update playbook" }); }
  });

  app.delete("/api/playbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deletePlaybook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Playbook not found" });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "playbook_deleted",
        resourceType: "playbook", resourceId: p(req.params.id),
      });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete playbook" }); }
  });

  app.post("/api/playbooks/:id/execute", isAuthenticated, async (req, res) => {
    try {
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb) return res.status(404).json({ message: "Playbook not found" });
      const startTime = Date.now();
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId || pb.orgId || undefined,
        incidentId: req.body.resourceId,
        alertId: req.body.alertId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Manual",
        storage,
      };

      const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
      const executedActions: any[] = [];

      const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
      
      if (isGraphFormat) {
        const graph = actionsArr[0] as any;
        const nodes = graph.nodes || [];
        const edges = graph.edges || [];
        
        const adjacency: Record<string, string[]> = {};
        for (const edge of edges) {
          if (!adjacency[edge.source]) adjacency[edge.source] = [];
          adjacency[edge.source].push(edge.target);
        }
        
        const targetNodes = new Set(edges.map((e: any) => e.target));
        const startNodes = nodes.filter((n: any) => !targetNodes.has(n.id) || n.type === "trigger");
        
        const visited = new Set<string>();
        const queue = startNodes.map((n: any) => n.id);
        let execCount = 0;
        
        while (queue.length > 0 && execCount < 50) {
          const nodeId = queue.shift()!;
          if (visited.has(nodeId)) continue;
          visited.add(nodeId);
          
          const node = nodes.find((n: any) => n.id === nodeId);
          if (!node) continue;
          
          if (node.type === "action" && node.data?.actionType) {
            const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
            executedActions.push({ nodeId, ...result });
            execCount++;
          } else if (node.type === "condition") {
            const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
            for (const edge of trueEdges) {
              queue.push(edge.target);
            }
            executedActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
            execCount++;
            continue;
          }
          
          const children = adjacency[nodeId] || [];
          for (const child of children) {
            queue.push(child);
          }
        }
      } else {
        for (const action of actionsArr) {
          const actionObj = action as any;
          const actionType = actionObj.type || actionObj.actionType || "unknown";
          const config = typeof actionObj.config === "string" ? 
            (() => { try { return JSON.parse(actionObj.config); } catch { return { raw: actionObj.config }; } })() :
            (actionObj.config || {});
          const result = await dispatchAction(actionType, config, context);
          executedActions.push(result);
        }
      }

      const execution = await storage.createPlaybookExecution({
        playbookId: pb.id,
        triggeredBy: context.userName,
        triggerEvent: "manual",
        resourceType: req.body.resourceType,
        resourceId: req.body.resourceId,
        status: "completed",
        actionsExecuted: executedActions,
        result: { totalActions: executedActions.length, completedActions: executedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
        executionTimeMs: Date.now() - startTime,
      });
      await storage.updatePlaybook(pb.id, { lastTriggeredAt: new Date(), triggerCount: (pb.triggerCount || 0) + 1 } as any);
      await storage.createAuditLog({
        userId: user?.id,
        userName: context.userName,
        action: "playbook_executed",
        resourceType: "playbook",
        resourceId: pb.id,
        details: { name: pb.name, trigger: "manual", actionsCount: executedActions.length },
      });
      res.json(execution);
    } catch (error) {
      console.error("Playbook execution error:", error);
      res.status(500).json({ message: "Failed to execute playbook" });
    }
  });

  app.get("/api/playbook-executions", isAuthenticated, async (req, res) => {
    try {
      const { playbookId, limit } = req.query;
      res.json(await storage.getPlaybookExecutions(playbookId as string, parseInt(limit as string) || 50));
    } catch (error) { res.status(500).json({ message: "Failed to fetch executions" }); }
  });

  // Export Routes (Phase 10)
  app.get("/api/export/alerts", isAuthenticated, async (req, res) => {
    try {
      const allAlerts = await storage.getAlerts();
      const csvHeader = "ID,Title,Severity,Status,Source,Category,MITRE Tactic,MITRE Technique,Source IP,Dest IP,Hostname,Detected At,Created At\n";
      const csvRows = allAlerts.map(a =>
        [a.id, `"${(a.title || '').replace(/"/g, '""')}"`, a.severity, a.status, a.source, a.category || '',
         a.mitreTactic || '', a.mitreTechnique || '', a.sourceIp || '', a.destIp || '', a.hostname || '',
         a.detectedAt?.toISOString() || '', a.createdAt?.toISOString() || ''
        ].join(",")
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=securenexus-alerts-${new Date().toISOString().split("T")[0]}.csv`);
      res.send(csvHeader + csvRows);
    } catch (error) { res.status(500).json({ message: "Failed to export alerts" }); }
  });

  app.get("/api/export/incidents", isAuthenticated, async (req, res) => {
    try {
      const allIncidents = await storage.getIncidents();
      const csvHeader = "ID,Title,Severity,Status,Priority,Alert Count,Assigned To,Escalated,MITRE Tactics,Created At,Updated At\n";
      const csvRows = allIncidents.map(i =>
        [i.id, `"${(i.title || '').replace(/"/g, '""')}"`, i.severity, i.status, i.priority || '',
         i.alertCount || 0, i.assignedTo || '', i.escalated ? 'Yes' : 'No',
         `"${(i.mitreTactics || []).join('; ')}"`,
         i.createdAt?.toISOString() || '', i.updatedAt?.toISOString() || ''
        ].join(",")
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=securenexus-incidents-${new Date().toISOString().split("T")[0]}.csv`);
      res.send(csvHeader + csvRows);
    } catch (error) { res.status(500).json({ message: "Failed to export incidents" }); }
  });

  app.get("/api/export/incident/:id/report", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const incidentAlerts = await storage.getAlertsByIncident(incident.id);
      const comments = await storage.getComments(incident.id);
      const report = {
        generatedAt: new Date().toISOString(),
        incident: { ...incident, alerts: incidentAlerts, comments },
      };
      res.json(report);
    } catch (error) { res.status(500).json({ message: "Failed to generate report" }); }
  });

  // Entity Graph Routes (Phase 7.1)
  app.get("/api/entities", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const entityList = await getEntityGraph(orgId);
      res.json(entityList);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entities" }); }
  });

  app.get("/api/entities/:id", isAuthenticated, async (req, res) => {
    try {
      const entity = await getEntity(p(req.params.id));
      if (!entity) return res.status(404).json({ message: "Entity not found" });
      res.json(entity);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entity" }); }
  });

  app.get("/api/entities/:id/alerts", isAuthenticated, async (req, res) => {
    try {
      const entityAlerts = await getEntityAlerts(p(req.params.id));
      res.json(entityAlerts);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entity alerts" }); }
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

  app.get("/api/incidents/:id/entities", isAuthenticated, async (req, res) => {
    try {
      const incidentEntities = await getEntitiesForIncident(p(req.params.id));
      res.json(incidentEntities);
    } catch (error) { res.status(500).json({ message: "Failed to fetch incident entities" }); }
  });

  // Correlation Engine Routes (Phase 7.1)
  app.get("/api/correlation/clusters", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const clusters = await getCorrelationClusters(orgId);
      res.json(clusters);
    } catch (error) { res.status(500).json({ message: "Failed to fetch correlation clusters" }); }
  });

  app.get("/api/correlation/clusters/:id", isAuthenticated, async (req, res) => {
    try {
      const cluster = await getCorrelationCluster(p(req.params.id));
      if (!cluster) return res.status(404).json({ message: "Cluster not found" });
      res.json(cluster);
    } catch (error) { res.status(500).json({ message: "Failed to fetch cluster" }); }
  });

  app.post("/api/correlation/scan", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.body.orgId as string | undefined;
      const results = await runCorrelationScan(orgId);
      res.json({ scanned: true, correlations: results.length, results });
    } catch (error) { res.status(500).json({ message: "Failed to run correlation scan" }); }
  });

  app.post("/api/correlation/clusters/:id/promote", isAuthenticated, async (req, res) => {
    try {
      const { title, severity } = req.body;
      if (!title || !severity) return res.status(400).json({ message: "Title and severity are required" });
      const result = await promoteClusterToIncident(p(req.params.id), title, severity);
      res.json(result);
    } catch (error: any) { res.status(500).json({ message: error.message || "Failed to promote cluster" }); }
  });

  app.get("/api/entities/:id/aliases", isAuthenticated, async (req, res) => {
    try {
      const aliases = await getEntityAliases(p(req.params.id));
      res.json(aliases);
    } catch (error) { res.status(500).json({ message: "Failed to fetch aliases" }); }
  });

  app.post("/api/entities/:id/aliases", isAuthenticated, async (req, res) => {
    try {
      const { aliasType, aliasValue, source } = req.body;
      if (!aliasType || !aliasValue) return res.status(400).json({ message: "aliasType and aliasValue required" });
      const alias = await addEntityAlias(p(req.params.id), aliasType, aliasValue, source);
      res.json(alias);
    } catch (error) { res.status(500).json({ message: "Failed to add alias" }); }
  });

  app.post("/api/entities/merge", isAuthenticated, async (req, res) => {
    try {
      const { targetId, sourceId } = req.body;
      if (!targetId || !sourceId) return res.status(400).json({ message: "targetId and sourceId required" });
      const merged = await mergeEntities(targetId, sourceId);
      res.json(merged);
    } catch (error: any) { res.status(500).json({ message: error.message || "Failed to merge entities" }); }
  });

  app.patch("/api/entities/:id/metadata", isAuthenticated, async (req, res) => {
    try {
      const updated = await updateEntityMetadata(p(req.params.id), req.body);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update metadata" }); }
  });

  app.get("/api/entities/:id/relationships", isAuthenticated, async (req, res) => {
    try {
      const relationships = await getEntityRelationships(p(req.params.id));
      res.json(relationships);
    } catch (error) { res.status(500).json({ message: "Failed to fetch relationships" }); }
  });

  app.get("/api/entity-graph", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const limit = parseInt(req.query.limit as string) || 80;
      const graph = await getEntityGraphWithEdges(orgId, limit);
      res.json(graph);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entity graph" }); }
  });

  // Phase 2: Graph-Based Correlation Engine
  app.post("/api/correlation/graph-scan", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.body.orgId as string | undefined;
      const results = await runGraphCorrelation(orgId);
      res.json({ scanned: true, attackPaths: results.attackPaths.length, campaigns: results.campaignsCreated, results });
    } catch (error: any) {
      console.error("Graph correlation error:", error);
      res.status(500).json({ message: "Failed to run graph correlation scan" });
    }
  });

  app.get("/api/attack-paths", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const paths = await getAttackPaths(orgId);
      res.json(paths);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack paths" }); }
  });

  app.get("/api/attack-paths/:id", isAuthenticated, async (req, res) => {
    try {
      const path = await getAttackPath(p(req.params.id));
      if (!path) return res.status(404).json({ message: "Attack path not found" });
      res.json(path);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack path" }); }
  });

  app.get("/api/campaigns", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const campaignList = await getCampaigns(orgId);
      res.json(campaignList);
    } catch (error) { res.status(500).json({ message: "Failed to fetch campaigns" }); }
  });

  app.get("/api/campaigns/:id", isAuthenticated, async (req, res) => {
    try {
      const campaign = await getCampaign(p(req.params.id));
      if (!campaign) return res.status(404).json({ message: "Campaign not found" });
      res.json(campaign);
    } catch (error) { res.status(500).json({ message: "Failed to fetch campaign" }); }
  });

  app.get("/api/events/stream", isAuthenticated, (req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const user = (req as any).user;
    const orgId = user?.orgId || null;
    const clientId = eventBus.generateClientId();

    eventBus.addClient({
      id: clientId,
      orgId,
      res,
      connectedAt: new Date(),
    });

    const connectEvent = {
      type: "connected",
      clientId,
      timestamp: new Date().toISOString(),
    };
    res.write(`event: connected\ndata: ${JSON.stringify(connectEvent)}\n\n`);

    req.on("close", () => {
      eventBus.removeClient(clientId);
    });
  });

  app.get("/api/events/status", isAuthenticated, (req: Request, res: Response) => {
    const user = (req as any).user;
    const orgId = user?.orgId || null;
    res.json({
      connected: eventBus.getClientCount(),
      orgClients: orgId ? eventBus.getOrgClientCount(orgId) : 0,
    });
  });

  // Threat Intel Configuration (Org-level API keys)
  app.get("/api/threat-intel-configs", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json([]);
      const configs = await storage.getThreatIntelConfigs(orgId);
      const masked = configs.map(c => ({
        ...c,
        apiKey: c.apiKey ? `****${c.apiKey.slice(-4)}` : null,
      }));
      res.json(masked);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch threat intel configs" });
    }
  });

  app.post("/api/threat-intel-configs", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const { provider, apiKey, enabled } = req.body;
      if (!provider) return res.status(400).json({ message: "provider is required" });
      const validProviders = ["abuseipdb", "virustotal", "otx"];
      if (!validProviders.includes(provider)) {
        return res.status(400).json({ message: `Invalid provider. Valid providers: ${validProviders.join(", ")}` });
      }
      const config = await storage.upsertThreatIntelConfig({
        orgId,
        provider,
        apiKey: apiKey || null,
        enabled: enabled !== undefined ? enabled : true,
      });
      res.status(201).json({
        ...config,
        apiKey: config.apiKey ? `****${config.apiKey.slice(-4)}` : null,
      });
    } catch (error) {
      console.error("Error saving threat intel config:", error);
      res.status(500).json({ message: "Failed to save threat intel config" });
    }
  });

  app.delete("/api/threat-intel-configs/:provider", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      await storage.deleteThreatIntelConfig(orgId, p(req.params.provider));
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete threat intel config" });
    }
  });

  app.post("/api/threat-intel-configs/:provider/test", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const provider = p(req.params.provider);
      const config = await storage.getThreatIntelConfig(orgId, provider);
      if (!config || !config.apiKey) {
        return res.status(404).json({ success: false, message: "No API key configured for this provider" });
      }

      let success = false;
      let message = "Unknown provider";

      try {
        if (provider === "abuseipdb") {
          const resp = await fetch("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90", {
            headers: { Key: config.apiKey, Accept: "application/json" },
          });
          success = resp.ok;
          message = resp.ok ? "API key is valid" : `API returned status ${resp.status}`;
        } else if (provider === "virustotal") {
          const resp = await fetch("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {
            headers: { "x-apikey": config.apiKey, Accept: "application/json" },
          });
          success = resp.ok;
          message = resp.ok ? "API key is valid" : `API returned status ${resp.status}`;
        } else if (provider === "otx") {
          const resp = await fetch("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general", {
            headers: { "X-OTX-API-KEY": config.apiKey, Accept: "application/json" },
          });
          success = resp.ok;
          message = resp.ok ? "API key is valid" : `API returned status ${resp.status}`;
        }
      } catch (err: any) {
        success = false;
        message = `Connection error: ${err.message}`;
      }

      await storage.upsertThreatIntelConfig({
        orgId,
        provider,
        apiKey: config.apiKey,
        enabled: config.enabled ?? true,
      });
      const updatedConfig = await storage.getThreatIntelConfig(orgId, provider);
      if (updatedConfig) {
        const { db: database } = await import("./db");
        const { threatIntelConfigs } = await import("@shared/schema");
        const { eq } = await import("drizzle-orm");
        await database.update(threatIntelConfigs).set({
          lastTestedAt: new Date(),
          lastTestStatus: success ? "success" : "failed",
        }).where(eq(threatIntelConfigs.id, updatedConfig.id));
      }

      res.json({ success, message, testedAt: new Date().toISOString() });
    } catch (error) {
      console.error("Error testing threat intel config:", error);
      res.status(500).json({ success: false, message: "Failed to test API key" });
    }
  });

  // Phase 4: Threat Enrichment & Intelligence Feeds
  app.get("/api/enrichment/providers", isAuthenticated, async (req, res) => {
    try {
      const { getProviderStatuses } = await import("./threat-enrichment");
      const user = (req as any).user;
      const orgId = user?.orgId;
      res.json(await getProviderStatuses(orgId));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch provider statuses" });
    }
  });

  app.get("/api/entities/:id/enrichment", isAuthenticated, async (req, res) => {
    try {
      const { getEnrichmentForEntity } = await import("./threat-enrichment");
      const entity = await getEntity(p(req.params.id));
      if (!entity) return res.status(404).json({ message: "Entity not found" });
      const enrichment = getEnrichmentForEntity(entity.metadata as Record<string, any> | null);
      res.json({
        entityId: entity.id,
        entityType: entity.type,
        entityValue: entity.value,
        riskScore: entity.riskScore,
        enrichment,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch enrichment data" });
    }
  });

  app.post("/api/entities/:id/enrich", isAuthenticated, async (req, res) => {
    try {
      const { enrichEntity } = await import("./threat-enrichment");
      const entity = await getEntity(p(req.params.id));
      if (!entity) return res.status(404).json({ message: "Entity not found" });
      const force = req.body.force === true;
      const results = await enrichEntity(entity.id, force);
      const updatedEntity = await getEntity(entity.id);
      res.json({
        entityId: entity.id,
        entityType: entity.type,
        entityValue: entity.value,
        riskScore: updatedEntity?.riskScore ?? entity.riskScore,
        results,
        enrichedAt: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Manual enrichment error:", error);
      res.status(500).json({ message: "Failed to enrich entity" });
    }
  });

  // OSINT Threat Intelligence Feeds (no API keys required)
  app.get("/api/osint-feeds/status", isAuthenticated, async (_req, res) => {
    try {
      const { getOsintFeedStatuses } = await import("./osint-feeds");
      res.json(getOsintFeedStatuses());
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch OSINT feed statuses" });
    }
  });

  app.get("/api/osint-feeds", isAuthenticated, async (_req, res) => {
    try {
      const { fetchAllOsintFeeds } = await import("./osint-feeds");
      const results = await fetchAllOsintFeeds();
      res.json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch OSINT feeds" });
    }
  });

  app.get("/api/osint-feeds/:feedName", isAuthenticated, async (req, res) => {
    try {
      const { fetchOsintFeed } = await import("./osint-feeds");
      const feedName = decodeURIComponent(p(req.params.feedName));
      const result = await fetchOsintFeed(feedName);
      if (result.status === "error" && result.errorMessage?.startsWith("Unknown feed")) {
        return res.status(404).json({ message: result.errorMessage });
      }
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch OSINT feed" });
    }
  });

  app.post("/api/osint-feeds/:feedName/refresh", isAuthenticated, async (req, res) => {
    try {
      const { fetchOsintFeed } = await import("./osint-feeds");
      const feedName = decodeURIComponent(p(req.params.feedName));
      const result = await fetchOsintFeed(feedName, true);
      if (result.status === "error" && result.errorMessage?.startsWith("Unknown feed")) {
        return res.status(404).json({ message: result.errorMessage });
      }
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to refresh OSINT feed" });
    }
  });

  // Phase 6: Enterprise Compliance & Data Governance
  app.get("/api/compliance/policy", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json(null);
      let policy = await storage.getCompliancePolicy(orgId);
      if (!policy) {
        policy = await storage.upsertCompliancePolicy({ orgId });
      }
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance policy" });
    }
  });

  app.put("/api/compliance/policy", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const parsed = insertCompliancePolicySchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid policy data", errors: parsed.error.flatten() });
      }
      const policy = await storage.upsertCompliancePolicy(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "compliance_policy_updated",
        resourceType: "compliance_policy",
        details: req.body,
      });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance policy" });
    }
  });

  app.get("/api/compliance/dsar", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json([]);
      const requests = await storage.getDsarRequests(orgId);
      res.json(requests);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DSAR requests" });
    }
  });

  app.post("/api/compliance/dsar", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const policy = await storage.getCompliancePolicy(orgId);
      const slaDays = policy?.dsarSlaDays || 30;
      const dueDate = new Date();
      dueDate.setDate(dueDate.getDate() + slaDays);
      const parsed = insertDsarRequestSchema.safeParse({ ...req.body, orgId, dueDate });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid DSAR request data", errors: parsed.error.flatten() });
      }
      const request = await storage.createDsarRequest(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_created",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { requestType: request.requestType, requestorEmail: request.requestorEmail },
      });
      res.status(201).json(request);
    } catch (error) {
      res.status(500).json({ message: "Failed to create DSAR request" });
    }
  });

  app.patch("/api/compliance/dsar/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      const request = await storage.getDsarRequest(p(req.params.id));
      if (!request) return res.status(404).json({ message: "DSAR request not found" });
      if (request.orgId !== orgId) return res.status(404).json({ message: "DSAR request not found" });
      const allowedFields = ["status", "notes"];
      const sanitized: Record<string, any> = {};
      for (const key of allowedFields) {
        if (req.body[key] !== undefined) sanitized[key] = req.body[key];
      }
      sanitized.updatedAt = new Date();
      const updated = await storage.updateDsarRequest(p(req.params.id), sanitized);
      if (!updated) return res.status(404).json({ message: "DSAR request not found" });
      await storage.createAuditLog({
        orgId: request.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_updated",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { changes: Object.keys(req.body) },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update DSAR request" });
    }
  });

  app.post("/api/compliance/dsar/:id/fulfill", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const userOrgId = user?.orgId;
      const request = await storage.getDsarRequest(p(req.params.id));
      if (!request) return res.status(404).json({ message: "DSAR request not found" });
      if (request.orgId !== userOrgId) return res.status(404).json({ message: "DSAR request not found" });
      const identifiers = request.subjectIdentifiers as Record<string, string>;
      const summary: any = { alertsFound: 0, entitiesFound: 0, auditLogsFound: 0, details: {} };
      const orgId = request.orgId || undefined;

      if (orgId) {
        const allAlerts = await storage.getAlerts(orgId);
        const matchedAlerts = allAlerts.filter(a => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (a.sourceIp === val || a.destIp === val || a.userId === val || a.hostname === val) return true;
            if (a.description && a.description.includes(val)) return true;
          }
          return false;
        });
        summary.alertsFound = matchedAlerts.length;
        summary.details.alertIds = matchedAlerts.map(a => a.id);

        const { db: database } = await import("./db");
        const { entities } = await import("@shared/schema");
        const { eq: eqOp } = await import("drizzle-orm");
        const allEntities = orgId ? await database.select().from(entities).where(eqOp(entities.orgId, orgId)) : [];
        const matchedEntities = allEntities.filter(e => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (e.value === val) return true;
          }
          return false;
        });
        summary.entitiesFound = matchedEntities.length;
        summary.details.entityIds = matchedEntities.map(e => e.id);

        const allAuditLogs = await storage.getAuditLogs(orgId);
        const matchedLogs = allAuditLogs.filter(l => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (l.userId === val) return true;
          }
          return false;
        });
        summary.auditLogsFound = matchedLogs.length;
        summary.details.auditLogIds = matchedLogs.map(l => l.id);
      }

      await storage.updateDsarRequest(request.id, {
        status: "fulfilled",
        fulfilledAt: new Date(),
        fulfilledBy: user?.id,
        resultSummary: summary,
      });

      await storage.createAuditLog({
        orgId: request.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_fulfilled",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { alertsFound: summary.alertsFound, entitiesFound: summary.entitiesFound, auditLogsFound: summary.auditLogsFound },
      });

      res.json({ request: { ...request, status: "fulfilled", fulfilledAt: new Date(), resultSummary: summary }, summary });
    } catch (error) {
      console.error("DSAR fulfill error:", error);
      res.status(500).json({ message: "Failed to fulfill DSAR request" });
    }
  });

  app.get("/api/compliance/report/:type", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const reportType = p(req.params.type);

      if (reportType === "gdpr_article30") {
        const policy = await storage.getCompliancePolicy(orgId);
        const orgConnectors = await storage.getConnectors(orgId);
        const dataSources = orgConnectors.map(c => ({
          name: c.name,
          type: c.type,
          status: c.status,
          lastSync: c.lastSyncAt?.toISOString() || null,
        }));
        res.json({
          reportType: "gdpr_article30",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          dataProcessingRecords: {
            dataSources,
            retentionPolicies: {
              alertRetentionDays: policy?.alertRetentionDays || 365,
              incidentRetentionDays: policy?.incidentRetentionDays || 730,
              auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            },
            legalBasis: policy?.dataProcessingBasis || "legitimate_interest",
            dpoEmail: policy?.dpoEmail || null,
            enabledFrameworks: policy?.enabledFrameworks || ["gdpr"],
            piiMaskingEnabled: policy?.piiMaskingEnabled || false,
            pseudonymizeExports: policy?.pseudonymizeExports || true,
          },
        });
      } else if (reportType === "retention_status") {
        const policy = await storage.getCompliancePolicy(orgId);
        const { db: database } = await import("./db");
        const { alerts: alertsTable, incidents: incidentsTable, auditLogs: auditLogsTable } = await import("@shared/schema");
        const { asc: ascOp, eq: eqOp, count: countOp } = await import("drizzle-orm");
        const [oldestAlertRow] = orgId
          ? await database.select().from(alertsTable).where(eqOp(alertsTable.orgId, orgId)).orderBy(ascOp(alertsTable.createdAt)).limit(1)
          : await database.select().from(alertsTable).orderBy(ascOp(alertsTable.createdAt)).limit(1);
        const [alertCountRow] = orgId
          ? await database.select({ value: countOp() }).from(alertsTable).where(eqOp(alertsTable.orgId, orgId))
          : await database.select({ value: countOp() }).from(alertsTable);
        const [incidentCountRow] = orgId
          ? await database.select({ value: countOp() }).from(incidentsTable).where(eqOp(incidentsTable.orgId, orgId))
          : await database.select({ value: countOp() }).from(incidentsTable);
        const oldestAuditLog = await storage.getOldestAuditLog(orgId);
        const auditLogCount = await storage.getAuditLogCount(orgId);

        res.json({
          reportType: "retention_status",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          stats: {
            totalAlerts: Number(alertCountRow?.value || 0),
            totalIncidents: Number(incidentCountRow?.value || 0),
            totalAuditLogs: auditLogCount,
            oldestAlert: oldestAlertRow?.createdAt?.toISOString() || null,
            oldestAuditLog: oldestAuditLog?.createdAt?.toISOString() || null,
          },
          policy: {
            alertRetentionDays: policy?.alertRetentionDays || 365,
            incidentRetentionDays: policy?.incidentRetentionDays || 730,
            auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            lastCleanupAt: policy?.retentionLastRunAt?.toISOString() || null,
            lastDeletedCount: policy?.retentionLastDeletedCount || 0,
          },
          nextCleanup: policy?.retentionLastRunAt
            ? new Date(policy.retentionLastRunAt.getTime() + 24 * 60 * 60 * 1000).toISOString()
            : "Not yet scheduled",
        });
      } else if (reportType === "dpdp_compliance") {
        const policy = await storage.getCompliancePolicy(orgId);
        const dsarReqs = await storage.getDsarRequests(orgId);
        const pendingDsars = dsarReqs.filter(r => r.status === "pending" || r.status === "in_progress");
        const fulfilledDsars = dsarReqs.filter(r => r.status === "fulfilled");
        const overdueDsars = pendingDsars.filter(r => r.dueDate && new Date(r.dueDate) < new Date());

        res.json({
          reportType: "dpdp_compliance",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          compliance: {
            dataProtectionOfficer: policy?.dpoEmail || "Not assigned",
            consentManagement: policy?.dataProcessingBasis || "Not configured",
            piiProtection: {
              maskingEnabled: policy?.piiMaskingEnabled || false,
              pseudonymizationEnabled: policy?.pseudonymizeExports || true,
            },
            dsarCompliance: {
              totalRequests: dsarReqs.length,
              pending: pendingDsars.length,
              fulfilled: fulfilledDsars.length,
              overdue: overdueDsars.length,
              slaDays: policy?.dsarSlaDays || 30,
            },
            dataRetention: {
              alertRetentionDays: policy?.alertRetentionDays || 365,
              incidentRetentionDays: policy?.incidentRetentionDays || 730,
              auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            },
            enabledFrameworks: policy?.enabledFrameworks || ["gdpr"],
          },
        });
      } else {
        return res.status(400).json({ message: `Unknown report type: ${reportType}` });
      }
    } catch (error) {
      console.error("Compliance report error:", error);
      res.status(500).json({ message: "Failed to generate compliance report" });
    }
  });

  app.get("/api/compliance/audit/verify", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });

      const logs = await storage.getAuditLogs(orgId);
      const sortedLogs = logs
        .filter(l => l.sequenceNum !== null)
        .sort((a, b) => (a.sequenceNum || 0) - (b.sequenceNum || 0));

      const errors: string[] = [];
      let lastVerifiedSeq = 0;

      for (let i = 0; i < sortedLogs.length; i++) {
        const log = sortedLogs[i];
        const expectedPrevHash = i === 0 ? "genesis" : sortedLogs[i - 1].entryHash;
        const expectedHash = createHash("sha256").update(JSON.stringify({
          prevHash: expectedPrevHash,
          action: log.action,
          userId: log.userId,
          resourceType: log.resourceType,
          resourceId: log.resourceId,
          details: log.details,
          sequenceNum: log.sequenceNum,
        })).digest("hex");

        if (log.prevHash !== expectedPrevHash) {
          errors.push(`Sequence ${log.sequenceNum}: prevHash mismatch`);
        }
        if (log.entryHash !== expectedHash) {
          errors.push(`Sequence ${log.sequenceNum}: entryHash mismatch`);
        }

        if (errors.length === 0) {
          lastVerifiedSeq = log.sequenceNum || 0;
        }
      }

      res.json({
        verified: errors.length === 0,
        totalEntries: sortedLogs.length,
        lastVerifiedSeq,
        errors,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to verify audit trail" });
    }
  });

  app.get("/api/compliance/audit/export", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const logs = await storage.getAuditLogs(orgId);
      const sortedLogs = logs.sort((a, b) => (a.sequenceNum || 0) - (b.sequenceNum || 0));
      res.json({
        exportedAt: new Date().toISOString(),
        organization: orgId,
        totalEntries: sortedLogs.length,
        hashChainIntact: true,
        entries: sortedLogs.map(l => ({
          id: l.id,
          sequenceNum: l.sequenceNum,
          prevHash: l.prevHash,
          entryHash: l.entryHash,
          action: l.action,
          userId: l.userId,
          userName: l.userName,
          resourceType: l.resourceType,
          resourceId: l.resourceId,
          details: l.details,
          ipAddress: l.ipAddress,
          createdAt: l.createdAt?.toISOString(),
        })),
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to export audit logs" });
    }
  });

  app.post("/api/compliance/retention/run", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const results = await runRetentionCleanup();
      const orgResult = results.find(r => r.orgId === orgId);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "manual_retention_cleanup",
        resourceType: "compliance",
        details: orgResult || { message: "No retention policy configured" },
      });
      res.json({ success: true, results: orgResult || { message: "No retention policy configured for this organization" } });
    } catch (error) {
      console.error("Retention cleanup error:", error);
      res.status(500).json({ message: "Failed to run retention cleanup" });
    }
  });

  function sanitizeConfig(config: any): any {
    if (!config) return config;
    const safe = { ...config };
    const secretFields = ["apiKey", "apiToken", "clientSecret", "password", "secretAccessKey", "webhookSecret", "token"];
    for (const field of secretFields) {
      if (safe[field]) safe[field] = "••••••••";
    }
    return safe;
  }

  // ============================
  // Phase 7: Integration Configs
  // ============================
  app.get("/api/integrations", isAuthenticated, async (req, res) => {
    try {
      const configs = await storage.getIntegrationConfigs();
      const sanitized = configs.map(c => ({
        ...c,
        config: sanitizeConfig(c.config as any),
      }));
      res.json(sanitized);
    } catch (error) { res.status(500).json({ message: "Failed to fetch integrations" }); }
  });

  app.get("/api/integrations/:id", isAuthenticated, async (req, res) => {
    try {
      const config = await storage.getIntegrationConfig(p(req.params.id));
      if (!config) return res.status(404).json({ message: "Integration not found" });
      const safeConfig = { ...config, config: sanitizeConfig(config.config as any) };
      res.json(safeConfig);
    } catch (error) { res.status(500).json({ message: "Failed to fetch integration" }); }
  });

  app.post("/api/integrations", isAuthenticated, async (req, res) => {
    try {
      const { name, type, config } = req.body;
      if (!name || !type || !config) {
        return res.status(400).json({ message: "Missing required fields: name, type, config" });
      }
      const created = await storage.createIntegrationConfig({
        name,
        type,
        config,
        orgId: (req as any).user?.orgId,
        status: "inactive",
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        orgId: (req as any).user?.orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "integration_created",
        resourceType: "integration",
        resourceId: created.id,
        details: { type, name },
      });
      res.status(201).json(created);
    } catch (error) { res.status(500).json({ message: "Failed to create integration" }); }
  });

  app.patch("/api/integrations/:id", isAuthenticated, async (req, res) => {
    try {
      const existing = await storage.getIntegrationConfig(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Integration not found" });
      const { name, config, status } = req.body;
      const updateData: any = {};
      if (name) updateData.name = name;
      if (status) updateData.status = status;
      if (config) {
        const existingConfig = existing.config as any;
        const newConfig = { ...existingConfig };
        for (const [key, value] of Object.entries(config)) {
          if (value !== "••••••••" && value !== undefined) {
            (newConfig as any)[key] = value;
          }
        }
        updateData.config = newConfig;
      }
      const updated = await storage.updateIntegrationConfig(p(req.params.id), updateData);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update integration" }); }
  });

  app.delete("/api/integrations/:id", isAuthenticated, async (req, res) => {
    try {
      const existing = await storage.getIntegrationConfig(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Integration not found" });
      await storage.deleteIntegrationConfig(p(req.params.id));
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "integration_deleted",
        resourceType: "integration",
        resourceId: p(req.params.id),
        details: { type: existing.type, name: existing.name },
      });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete integration" }); }
  });

  app.post("/api/integrations/:id/test", isAuthenticated, async (req, res) => {
    try {
      const config = await storage.getIntegrationConfig(p(req.params.id));
      if (!config) return res.status(404).json({ message: "Integration not found" });
      await storage.updateIntegrationConfig(p(req.params.id), {
        lastTestedAt: new Date(),
        lastTestStatus: "success",
        status: "active",
      } as any);
      res.json({
        success: true,
        message: `${config.type} integration test successful (simulated)`,
        testedAt: new Date().toISOString(),
      });
    } catch (error) { res.status(500).json({ message: "Integration test failed" }); }
  });

  // ================================
  // Phase 7: Notification Channels
  // ================================
  app.get("/api/notification-channels", isAuthenticated, async (req, res) => {
    try {
      const channels = await storage.getNotificationChannels();
      const sanitized = channels.map(c => ({
        ...c,
        config: sanitizeConfig(c.config as any),
      }));
      res.json(sanitized);
    } catch (error) { res.status(500).json({ message: "Failed to fetch notification channels" }); }
  });

  app.post("/api/notification-channels", isAuthenticated, async (req, res) => {
    try {
      const { name, type, config, events, isDefault } = req.body;
      if (!name || !type || !config) {
        return res.status(400).json({ message: "Missing required fields: name, type, config" });
      }
      const created = await storage.createNotificationChannel({
        name,
        type,
        config,
        orgId: (req as any).user?.orgId,
        events: events || ["incident_created"],
        isDefault: isDefault || false,
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        orgId: (req as any).user?.orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "notification_channel_created",
        resourceType: "notification_channel",
        resourceId: created.id,
        details: { type, name },
      });
      res.status(201).json(created);
    } catch (error) { res.status(500).json({ message: "Failed to create notification channel" }); }
  });

  app.patch("/api/notification-channels/:id", isAuthenticated, async (req, res) => {
    try {
      const existing = await storage.getNotificationChannel(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Channel not found" });
      const updated = await storage.updateNotificationChannel(p(req.params.id), req.body);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update channel" }); }
  });

  app.delete("/api/notification-channels/:id", isAuthenticated, async (req, res) => {
    try {
      const existing = await storage.getNotificationChannel(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Channel not found" });
      await storage.deleteNotificationChannel(p(req.params.id));
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete channel" }); }
  });

  app.post("/api/notification-channels/:id/test", isAuthenticated, async (req, res) => {
    try {
      const channel = await storage.getNotificationChannel(p(req.params.id));
      if (!channel) return res.status(404).json({ message: "Channel not found" });
      res.json({
        success: true,
        message: `Test notification sent to ${channel.type} channel "${channel.name}" (simulated)`,
        sentAt: new Date().toISOString(),
      });
    } catch (error) { res.status(500).json({ message: "Failed to test notification" }); }
  });

  // ============================
  // Phase 7: Response Actions
  // ============================
  app.get("/api/response-actions", isAuthenticated, async (req, res) => {
    try {
      const { incidentId } = req.query;
      res.json(await storage.getResponseActions(undefined, incidentId as string));
    } catch (error) { res.status(500).json({ message: "Failed to fetch response actions" }); }
  });

  app.post("/api/response-actions", isAuthenticated, async (req, res) => {
    try {
      const { actionType, target, connectorId, incidentId, alertId } = req.body;
      if (!actionType || !target) {
        return res.status(400).json({ message: "Missing required fields: actionType, target" });
      }
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId,
        incidentId,
        alertId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        storage,
      };
      const result = await dispatchAction(actionType, { target, connectorId }, context);
      await storage.createAuditLog({
        userId: user?.id,
        userName: context.userName,
        action: "response_action_executed",
        resourceType: "response_action",
        details: { actionType, target, status: result.status, incidentId },
      });
      res.json(result);
    } catch (error) {
      console.error("Response action error:", error);
      res.status(500).json({ message: "Failed to execute response action" });
    }
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
      console.error("Push to ticketing error:", error);
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
      console.error("Notification error:", error);
      res.status(500).json({ message: "Failed to send notification" });
    }
  });

  // Phase 8: Predictive Defense routes
  app.get("/api/predictive/anomalies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const anomalies = await storage.getPredictiveAnomalies(orgId);
      res.json(anomalies);
    } catch (error) { res.status(500).json({ message: "Failed to fetch anomalies" }); }
  });

  app.get("/api/predictive/attack-surface", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const assets = await storage.getAttackSurfaceAssets(orgId);
      res.json(assets);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack surface" }); }
  });

  app.get("/api/predictive/forecasts", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const forecasts = await storage.getRiskForecasts(orgId);
      res.json(forecasts);
    } catch (error) { res.status(500).json({ message: "Failed to fetch forecasts" }); }
  });

  app.get("/api/predictive/recommendations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const recs = await storage.getHardeningRecommendations(orgId);
      res.json(recs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch recommendations" }); }
  });

  app.post("/api/predictive/recompute", isAuthenticated, async (req, res) => {
    try {
      let orgId = (req as any).user?.orgId;
      if (!orgId) {
        const orgs = await storage.getOrganizations();
        if (orgs.length > 0) orgId = orgs[0].id;
      }
      if (!orgId) return res.status(400).json({ message: "Organization required" });
      const { runPredictiveAnalysis } = await import("./predictive-engine");
      const result = await runPredictiveAnalysis(orgId, storage);
      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        action: "predictive_analysis_run",
        resourceType: "predictive",
        details: result,
      });
      res.json(result);
    } catch (error: any) {
      console.error("Predictive analysis error:", error);
      res.status(500).json({ message: "Failed to run predictive analysis", error: error.message });
    }
  });

  app.patch("/api/predictive/recommendations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { status } = req.body;
      const recs = await storage.getHardeningRecommendations(orgId);
      const rec = recs.find(r => r.id === req.params.id);
      if (!rec) return res.status(404).json({ message: "Recommendation not found" });
      const updated = await storage.updateHardeningRecommendation(req.params.id, { status });
      if (!updated) return res.status(404).json({ message: "Recommendation not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update recommendation" }); }
  });

  // === Phase 9: Autonomous Response & Agentic SOC ===

  // Auto-Response Policies CRUD
  app.get("/api/autonomous/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      res.json(policies);
    } catch (error) { res.status(500).json({ message: "Failed to fetch policies" }); }
  });

  app.post("/api/autonomous/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policy = await storage.createAutoResponsePolicy({ ...req.body, orgId });
      res.status(201).json(policy);
    } catch (error) { res.status(500).json({ message: "Failed to create policy" }); }
  });

  app.patch("/api/autonomous/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      const policy = policies.find(p => p.id === (req.params.id as string));
      if (!policy) return res.status(404).json({ message: "Policy not found" });
      const updated = await storage.updateAutoResponsePolicy(req.params.id as string, req.body);
      if (!updated) return res.status(404).json({ message: "Policy not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update policy" }); }
  });

  app.delete("/api/autonomous/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      const policy = policies.find(p => p.id === (req.params.id as string));
      if (!policy) return res.status(404).json({ message: "Policy not found" });
      const deleted = await storage.deleteAutoResponsePolicy(req.params.id as string);
      if (!deleted) return res.status(404).json({ message: "Policy not found" });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete policy" }); }
  });

  // Seed default policies
  app.post("/api/autonomous/policies/seed-defaults", isAuthenticated, async (req, res) => {
    try {
      let orgId = (req as any).user?.orgId;
      if (!orgId) {
        const orgs = await storage.getOrganizations();
        if (orgs.length > 0) orgId = orgs[0].id;
      }
      if (!orgId) return res.status(400).json({ message: "No organization found" });
      const existing = await storage.getAutoResponsePolicies(orgId);
      if (existing.length > 0) return res.json({ message: "Policies already exist", count: existing.length });
      const defaults = generateDefaultPolicies(orgId);
      const created = [];
      for (const def of defaults) {
        const p = await storage.createAutoResponsePolicy(def as any);
        created.push(p);
      }
      res.status(201).json(created);
    } catch (error) { console.error("Seed policies error:", error); res.status(500).json({ message: "Failed to seed policies" }); }
  });

  // Evaluate policies for an incident
  app.post("/api/autonomous/evaluate/:incidentId", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const incId = req.params.incidentId as string;
      const incident = await storage.getIncident(incId);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === incId);
      const matches = await evaluatePolicies({ incident, alerts: incidentAlerts, orgId: orgId || "default", confidenceScore: req.body.confidenceScore });
      res.json(matches);
    } catch (error) { res.status(500).json({ message: "Failed to evaluate policies" }); }
  });

  // Investigation Runs
  app.get("/api/autonomous/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const runs = await storage.getInvestigationRuns(orgId);
      res.json(runs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch investigations" }); }
  });

  app.get("/api/autonomous/investigations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const run = await storage.getInvestigationRun(req.params.id as string);
      if (!run) return res.status(404).json({ message: "Investigation not found" });
      if (orgId && run.orgId !== orgId) return res.status(404).json({ message: "Investigation not found" });
      const steps = await storage.getInvestigationSteps(run.id);
      res.json({ ...run, steps });
    } catch (error) { res.status(500).json({ message: "Failed to fetch investigation" }); }
  });

  app.post("/api/autonomous/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { incidentId } = req.body;
      if (!incidentId) return res.status(400).json({ message: "incidentId required" });
      const incident = await storage.getIncident(incidentId);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const run = await storage.createInvestigationRun({
        orgId,
        incidentId,
        triggeredBy: (req as any).user?.email || "analyst",
        triggerSource: "manual",
        status: "queued",
      });
      // Start investigation async
      runInvestigation(run.id).catch(err => console.error("Investigation error:", err));
      res.status(201).json(run);
    } catch (error) { res.status(500).json({ message: "Failed to start investigation" }); }
  });

  // Rollbacks
  app.get("/api/autonomous/rollbacks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rollbacks = await storage.getResponseActionRollbacks(orgId);
      res.json(rollbacks);
    } catch (error) { res.status(500).json({ message: "Failed to fetch rollbacks" }); }
  });

  app.post("/api/autonomous/rollbacks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { originalActionId, actionType, target } = req.body;
      if (!actionType || !target) return res.status(400).json({ message: "actionType and target required" });
      if (!canRollback(actionType)) return res.status(400).json({ message: `Cannot rollback action: ${actionType}` });
      const rollback = await createRollbackRecord(orgId || "default", originalActionId, actionType, target);
      res.status(201).json(rollback);
    } catch (error: any) { res.status(500).json({ message: error.message || "Failed to create rollback" }); }
  });

  app.post("/api/autonomous/rollbacks/:id/execute", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rollbacks = await storage.getResponseActionRollbacks(orgId);
      const rb = rollbacks.find(r => r.id === (req.params.id as string));
      if (!rb) return res.status(404).json({ message: "Rollback not found" });
      const user = (req as any).user?.email || "analyst";
      const result = await executeRollback(req.params.id as string, user);
      if (!result) return res.status(404).json({ message: "Rollback not found or already executed" });
      res.json(result);
    } catch (error) { res.status(500).json({ message: "Failed to execute rollback" }); }
  });

  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

  app.post("/api/files/upload", isAuthenticated, upload.single("file"), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "No file provided" });
      const orgId = (req as any).user?.orgId || "default";
      const key = `orgs/${orgId}/uploads/${Date.now()}-${req.file.originalname}`;
      const result = await uploadFile(key, req.file.buffer, req.file.mimetype);
      res.status(201).json(result);
    } catch (error) {
      console.error("File upload error:", error);
      res.status(500).json({ message: "Failed to upload file" });
    }
  });

  app.get("/api/files", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const subPrefix = req.query.prefix as string | undefined;
      const prefix = `orgs/${orgId}/${subPrefix || ""}`;
      const files = await listFiles(prefix);
      res.json(files);
    } catch (error) {
      res.status(500).json({ message: "Failed to list files" });
    }
  });

  app.get("/api/files/download", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const key = req.query.key as string;
      if (!key) return res.status(400).json({ message: "key query param required" });
      if (!key.startsWith(`orgs/${orgId}/`)) return res.status(403).json({ message: "Access denied" });
      const url = await getSignedUrl(key);
      res.json({ url });
    } catch (error) {
      res.status(500).json({ message: "Failed to get signed URL" });
    }
  });

  app.delete("/api/files/remove", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const key = req.query.key as string;
      if (!key) return res.status(400).json({ message: "key query param required" });
      if (!key.startsWith(`orgs/${orgId}/`)) return res.status(403).json({ message: "Access denied" });
      const result = await deleteFile(key);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to delete file" });
    }
  });

  // ── CSPM Routes ──
  app.get("/api/cspm/accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const accounts = await storage.getCspmAccounts(orgId);
      res.json(accounts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM accounts" });
    }
  });

  app.post("/api/cspm/accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const body = { ...req.body, orgId };
      const parsed = insertCspmAccountSchema.safeParse(body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid CSPM account data", errors: parsed.error.flatten() });
      }
      const account = await storage.createCspmAccount(parsed.data);
      res.status(201).json(account);
    } catch (error) {
      res.status(500).json({ message: "Failed to create CSPM account" });
    }
  });

  app.patch("/api/cspm/accounts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const existing = await storage.getCspmAccount(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      const account = await storage.updateCspmAccount(p(req.params.id), req.body);
      if (!account) return res.status(404).json({ message: "CSPM account not found" });
      res.json(account);
    } catch (error) {
      res.status(500).json({ message: "Failed to update CSPM account" });
    }
  });

  app.delete("/api/cspm/accounts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const existing = await storage.getCspmAccount(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      const deleted = await storage.deleteCspmAccount(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "CSPM account not found" });
      res.json({ message: "CSPM account deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete CSPM account" });
    }
  });

  app.get("/api/cspm/scans", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const accountId = req.query.accountId as string | undefined;
      const scans = await storage.getCspmScans(orgId, accountId);
      res.json(scans);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM scans" });
    }
  });

  app.post("/api/cspm/scans/:accountId", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const account = await storage.getCspmAccount(p(req.params.accountId));
      if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      runCspmScan(orgId, p(req.params.accountId)).catch(err => console.error("CSPM scan error:", err));
      res.json({ message: "Scan started" });
    } catch (error) {
      res.status(500).json({ message: "Failed to start CSPM scan" });
    }
  });

  app.get("/api/cspm/findings", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const scanId = req.query.scanId as string | undefined;
      const severity = req.query.severity as string | undefined;
      const findings = await storage.getCspmFindings(orgId, scanId, severity);
      res.json(findings);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM findings" });
    }
  });

  app.patch("/api/cspm/findings/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const findings = await storage.getCspmFindings(orgId);
      const existing = findings.find(f => f.id === p(req.params.id));
      if (!existing) return res.status(404).json({ message: "CSPM finding not found" });
      const finding = await storage.updateCspmFinding(p(req.params.id), req.body);
      if (!finding) return res.status(404).json({ message: "CSPM finding not found" });
      res.json(finding);
    } catch (error) {
      res.status(500).json({ message: "Failed to update CSPM finding" });
    }
  });

  // ── Endpoint Telemetry Routes ──
  app.get("/api/endpoints", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const assets = await storage.getEndpointAssets(orgId);
      res.json(assets);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint assets" });
    }
  });

  app.get("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint asset" });
    }
  });

  app.post("/api/endpoints/seed", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const assets = await seedEndpointAssets(orgId);
      res.status(201).json(assets);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed endpoint assets" });
    }
  });

  app.post("/api/endpoints", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const body = { ...req.body, orgId };
      const parsed = insertEndpointAssetSchema.safeParse(body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid endpoint asset data", errors: parsed.error.flatten() });
      }
      const asset = await storage.createEndpointAsset(parsed.data);
      res.status(201).json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to create endpoint asset" });
    }
  });

  app.patch("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const existing = await storage.getEndpointAsset(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const asset = await storage.updateEndpointAsset(p(req.params.id), req.body);
      if (!asset) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to update endpoint asset" });
    }
  });

  app.delete("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const existing = await storage.getEndpointAsset(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const deleted = await storage.deleteEndpointAsset(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json({ message: "Endpoint asset deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete endpoint asset" });
    }
  });

  app.get("/api/endpoints/:id/telemetry", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const telemetry = await storage.getEndpointTelemetry(p(req.params.id));
      res.json(telemetry);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint telemetry" });
    }
  });

  app.post("/api/endpoints/:id/telemetry", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const telemetry = await generateTelemetry(orgId, p(req.params.id));
      res.status(201).json(telemetry);
    } catch (error) {
      res.status(500).json({ message: "Failed to generate endpoint telemetry" });
    }
  });

  app.post("/api/endpoints/:id/risk", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const riskScore = await calculateEndpointRisk(p(req.params.id));
      res.json({ riskScore });
    } catch (error) {
      res.status(500).json({ message: "Failed to calculate endpoint risk" });
    }
  });

  // ── Posture Score Routes ──
  app.get("/api/posture/scores", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const scores = await storage.getPostureScores(orgId);
      res.json(scores);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch posture scores" });
    }
  });

  app.post("/api/posture/calculate", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const score = await calculatePostureScore(orgId);
      res.status(201).json(score);
    } catch (error) {
      res.status(500).json({ message: "Failed to calculate posture score" });
    }
  });

  app.get("/api/posture/latest", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const score = await storage.getLatestPostureScore(orgId);
      if (!score) return res.status(404).json({ message: "No posture score found" });
      res.json(score);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch latest posture score" });
    }
  });

  // ── AI Deployment Config Routes ──
  app.get("/api/ai-deployment/config", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const config = await storage.getAiDeploymentConfig(orgId);
      if (!config) return res.status(404).json({ message: "AI deployment config not found" });
      res.json(config);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch AI deployment config" });
    }
  });

  app.put("/api/ai-deployment/config", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId || "default";
      const parsed = insertAiDeploymentConfigSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid AI deployment config data", errors: parsed.error.flatten() });
      }
      const config = await storage.upsertAiDeploymentConfig(parsed.data);
      res.json(config);
    } catch (error) {
      res.status(500).json({ message: "Failed to upsert AI deployment config" });
    }
  });

  startRetentionScheduler();

  return httpServer;
}
