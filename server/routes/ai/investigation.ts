import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole } from "../../rbac";
import {
  conductDeepInvestigation,
  conductThreatHunt,
  analyzeBehavior,
  predictAttackPaths,
  buildThreatIntelContext,
  conductMultiTurnInvestigation,
} from "../../ai";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";
import { withAiFallback } from "../../ai/fallback";
import { persistAttackGraph } from "./helpers";
import { pool } from "../../db";

const log = logger.child("routes-ai-investigation");

export function registerAiInvestigationRoutes(app: Express): void {
  // POST /api/ai/deep-investigation/:incidentId
  app.post(
    "/api/ai/deep-investigation/:incidentId",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const incident = await storage.getIncident(p(req.params.incidentId));
        if (!incident) return res.status(404).json({ message: "Incident not found" });

        const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
        if (incidentAlerts.length === 0) {
          return res.status(400).json({ message: "No alerts associated with this incident" });
        }

        const threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        const orgId = (req as any).orgId || (req as any).user?.orgId;

        const investigationCacheKey = `investigation:${incident.id}`;
        const fallbackResult = await withAiFallback(investigationCacheKey, () =>
          conductDeepInvestigation(incident, incidentAlerts, threatIntelCtx, orgId),
        );
        if (fallbackResult.source === "unavailable") {
          return res
            .status(503)
            .json({ message: "AI deep investigation temporarily unavailable", status: "ai_unavailable" });
        }
        const result = fallbackResult.data!;

        persistAttackGraph(result as unknown as Record<string, unknown>, incident.id, orgId).catch((err) => {
          logger.child("ai").warn("Failed to persist attack graph", { error: String(err) });
        });

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_deep_investigation",
          resourceType: "incident",
          resourceId: incident.id,
          details: { alertCount: incidentAlerts.length, confidence: result.investigationConfidence },
        });

        storage
          .incrementUsage(orgId, "ai_analyses")
          .catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Deep investigation error", { error: String(error) });
        res.status(500).json({ message: "Deep investigation failed. Please try again." });
      }
    },
  );

  // POST /api/ai/threat-hunt
  app.post(
    "/api/ai/threat-hunt",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const { huntContext, telemetryData } = req.body;

        if (!huntContext || !telemetryData) {
          return res.status(400).json({ message: "huntContext and telemetryData are required" });
        }

        const orgId = (req as any).orgId || (req as any).user?.orgId;

        let threatIntelCtx: Awaited<ReturnType<typeof buildThreatIntelContext>> | undefined;
        if (telemetryData.alerts && Array.isArray(telemetryData.alerts)) {
          threatIntelCtx = await buildThreatIntelContext(telemetryData.alerts);
        }

        const huntCacheKey = `threat-hunt:${orgId}:${Date.now()}`;
        const fallbackResult = await withAiFallback(huntCacheKey, () =>
          conductThreatHunt(huntContext, telemetryData, threatIntelCtx, orgId),
        );
        if (fallbackResult.source === "unavailable") {
          return res
            .status(503)
            .json({ message: "AI threat hunting temporarily unavailable", status: "ai_unavailable" });
        }
        const result = fallbackResult.data!;

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_threat_hunt",
          resourceType: "telemetry",
          details: {
            huntMissionId: result.huntMissionId,
            threatsFound: result.huntSummary.threatsConfirmed,
            hypothesesTested: result.huntSummary.hypothesesTested,
          },
        });

        storage
          .incrementUsage(orgId, "ai_analyses")
          .catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Threat hunting error", { error: String(error) });
        res.status(500).json({ message: "Threat hunting failed. Please try again." });
      }
    },
  );

  // POST /api/ai/behavioral-analysis
  app.post(
    "/api/ai/behavioral-analysis",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const { entityContext, activityData, baselineData } = req.body;

        if (!entityContext || !activityData || !baselineData) {
          return res.status(400).json({
            message: "entityContext, activityData, and baselineData are required",
          });
        }

        const orgId = (req as any).orgId || (req as any).user?.orgId;
        const behaviorCacheKey = `behavior:${orgId}:${entityContext.entityId || "unknown"}`;
        const fallbackResult = await withAiFallback(behaviorCacheKey, () =>
          analyzeBehavior(entityContext, activityData, baselineData, orgId),
        );
        if (fallbackResult.source === "unavailable") {
          return res
            .status(503)
            .json({ message: "AI behavioral analysis temporarily unavailable", status: "ai_unavailable" });
        }
        const result = fallbackResult.data!;

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_behavioral_analysis",
          resourceType: "entity",
          resourceId: entityContext.entityId || "unknown",
          details: {
            riskLevel: result.riskLevel,
            behavioralScore: result.behavioralScore,
            anomalyCount: result.anomalies.length,
          },
        });

        storage
          .incrementUsage(orgId, "ai_analyses")
          .catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Behavioral analysis error", { error: String(error) });
        res.status(500).json({ message: "Behavioral analysis failed. Please try again." });
      }
    },
  );

  // Attack Graph Persistence API

  // GET /api/ai/investigation-graphs/:incidentId
  app.get("/api/ai/investigation-graphs/:incidentId", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      if (!orgId) return res.status(403).json({ message: "Organization context required" });

      const graphs = await storage.getAttackGraphsByIncident(p(req.params.incidentId), orgId);

      const result = await Promise.all(
        graphs.map(async (graph) => {
          const [nodes, edges] = await Promise.all([
            storage.getAttackGraphNodes(graph.id),
            storage.getAttackGraphEdges(graph.id),
          ]);
          return { ...graph, nodes, edges };
        }),
      );

      res.json(result);
    } catch (error: any) {
      logger.child("ai").error("Failed to fetch investigation graphs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch investigation graphs" });
    }
  });

  // GET /api/ai/investigation-graphs
  app.get("/api/ai/investigation-graphs", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      if (!orgId) return res.status(403).json({ message: "Organization context required" });

      const limit = Math.min(parseInt(String(req.query.limit || "50"), 10) || 50, 200);
      const days = req.query.days ? parseInt(String(req.query.days), 10) : undefined;

      const graphs = await storage.getAttackGraphsByOrg(orgId, limit, days);
      res.json(graphs);
    } catch (error: any) {
      logger.child("ai").error("Failed to fetch org investigation graphs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch investigation graphs" });
    }
  });

  // GET /api/ai/investigation-graphs/detail/:graphId
  app.get("/api/ai/investigation-graphs/detail/:graphId", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      if (!orgId) return res.status(403).json({ message: "Organization context required" });

      const graph = await storage.getAttackGraph(p(req.params.graphId));
      if (!graph || graph.orgId !== orgId) {
        return res.status(404).json({ message: "Attack graph not found" });
      }

      const [nodes, edges] = await Promise.all([
        storage.getAttackGraphNodes(graph.id),
        storage.getAttackGraphEdges(graph.id),
      ]);

      res.json({ ...graph, nodes, edges });
    } catch (error: any) {
      logger.child("ai").error("Failed to fetch attack graph detail", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack graph" });
    }
  });

  // DELETE /api/ai/investigation-graphs/:graphId
  app.delete(
    "/api/ai/investigation-graphs/:graphId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId || (req as any).user?.orgId;
        if (!orgId) return res.status(403).json({ message: "Organization context required" });

        const graph = await storage.getAttackGraph(p(req.params.graphId));
        if (!graph || graph.orgId !== orgId) {
          return res.status(404).json({ message: "Attack graph not found" });
        }

        await storage.deleteAttackGraph(graph.id);
        res.json({ message: "Attack graph deleted" });
      } catch (error: any) {
        logger.child("ai").error("Failed to delete attack graph", { error: String(error) });
        res.status(500).json({ message: "Failed to delete attack graph" });
      }
    },
  );

  // POST /api/ai/predict-attack-paths
  app.post(
    "/api/ai/predict-attack-paths",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const { compromiseState, networkTopology, crownJewels, securityControls } = req.body;

        if (!compromiseState) {
          return res.status(400).json({ message: "compromiseState is required" });
        }

        const orgId = (req as any).orgId || (req as any).user?.orgId;

        const attackPathCacheKey = `attack-path:${orgId}:${Date.now()}`;
        const fallbackResult = await withAiFallback(attackPathCacheKey, () =>
          predictAttackPaths(compromiseState, networkTopology || {}, crownJewels || [], securityControls || {}, orgId),
        );
        if (fallbackResult.source === "unavailable") {
          return res
            .status(503)
            .json({ message: "AI attack path prediction temporarily unavailable", status: "ai_unavailable" });
        }
        const result = fallbackResult.data!;

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_attack_path_prediction",
          resourceType: "compromise",
          details: {
            accessLevel: result.currentCompromiseState.accessLevel,
            predictedPaths: result.predictedAttackPaths.length,
            highestProbability: Math.max(...result.predictedAttackPaths.map((p) => p.probability)),
          },
        });

        storage
          .incrementUsage(orgId, "ai_analyses")
          .catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Attack path prediction error", { error: String(error) });
        res.status(500).json({ message: "Attack path prediction failed. Please try again." });
      }
    },
  );

  // Multi-Turn Investigation Chat
  app.post(
    "/api/ai/investigation/:incidentId/chat",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const incidentId = String(req.params.incidentId);
        const orgId = getOrgId(req);
        const { message, threadId } = req.body;

        if (!message || typeof message !== "string") {
          return res.status(400).json({ message: "message is required" });
        }

        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const activeThreadId = String(threadId || `thread_${incidentId}_${Date.now()}`);

        const history = await storage.getChatThread(activeThreadId, orgId);
        const conversationHistory = history.map((m) => ({
          role: m.role,
          content: m.content,
        }));

        const incidentAlerts = await storage.getAlertsByIncident(incidentId);
        const categories = Array.from(new Set(incidentAlerts.map((a) => a.category).filter(Boolean)));
        const incidentContext = `Incident: ${incident.title}\nSeverity: ${incident.severity}\nStatus: ${incident.status}\nSummary: ${incident.summary || "N/A"}\nAlerts: ${incidentAlerts.length} correlated alerts\nCategories: ${categories.join(", ")}`;

        await storage.createChatMessage({
          orgId,
          incidentId,
          threadId: activeThreadId,
          role: "user",
          content: message,
        });

        const chatCacheKey = `investigation-chat:${activeThreadId}:${message.slice(0, 50)}`;
        const fallbackResult = await withAiFallback(chatCacheKey, () =>
          conductMultiTurnInvestigation(incidentContext, conversationHistory, message, orgId),
        );
        if (fallbackResult.source === "unavailable") {
          return res
            .status(503)
            .json({ message: "AI investigation chat temporarily unavailable", status: "ai_unavailable" });
        }
        const aiResponse = fallbackResult.data!;

        await storage.createChatMessage({
          orgId,
          incidentId,
          threadId: activeThreadId,
          role: "assistant",
          content: aiResponse.reply,
          metadata: {
            suggestedFollowups: aiResponse.suggestedFollowups,
            referencedTechniques: aiResponse.referencedTechniques,
            confidence: aiResponse.confidence,
          },
        });

        storage
          .incrementUsage(orgId, "ai_analyses")
          .catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));

        res.json({
          threadId: activeThreadId,
          reply: aiResponse.reply,
          suggestedFollowups: aiResponse.suggestedFollowups,
          referencedTechniques: aiResponse.referencedTechniques,
          confidence: aiResponse.confidence,
        });
      } catch (error: any) {
        logger.child("ai").error("Investigation chat error", { error: String(error) });
        res.status(500).json({ message: "Investigation chat failed. Please try again." });
      }
    },
  );

  // GET /api/ai/investigation/:incidentId/thread
  app.get(
    "/api/ai/investigation/:incidentId/thread",
    isAuthenticated,
    resolveOrgContext,
    async (req: Request, res: Response) => {
      try {
        const incidentId = String(req.params.incidentId);
        const orgId = getOrgId(req);

        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const messages = await storage.getChatThreadsByIncident(incidentId, orgId);

        const threads: Record<string, typeof messages> = {};
        for (const msg of messages) {
          if (!threads[msg.threadId]) {
            threads[msg.threadId] = [];
          }
          threads[msg.threadId].push(msg);
        }

        res.json({ incidentId, threads });
      } catch (error: any) {
        logger.child("ai").error("Get investigation thread error", { error: String(error) });
        res.status(500).json({ message: "Failed to retrieve investigation thread." });
      }
    },
  );

  // Confidence Indicators
  app.get(
    "/api/ai/confidence-indicators/:incidentId",
    isAuthenticated,
    resolveOrgContext,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const incidentId = p(req.params.incidentId);
        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const alerts = await storage.getAlertsByIncident(incidentId);
        const sourceCount = new Set(alerts.map((a) => a.source).filter(Boolean)).size;
        const hasMitre = alerts.some((a) => a.mitreTactic || a.mitreTechnique);
        const hasIocs = alerts.some((a) => a.sourceIp || a.destIp || a.hostname);
        const alertDiversity = new Set(alerts.map((a) => a.category).filter(Boolean)).size;
        const hasNarrative = !!(incident as any).aiNarrative;

        const factors: { factor: string; weight: number; present: boolean; explanation: string }[] = [
          {
            factor: "multiple_sources",
            weight: 0.2,
            present: sourceCount >= 2,
            explanation:
              sourceCount >= 2
                ? `${sourceCount} distinct data sources corroborate findings`
                : "Single source — limited cross-validation",
          },
          {
            factor: "mitre_mapping",
            weight: 0.15,
            present: hasMitre,
            explanation: hasMitre
              ? "Attack techniques mapped to MITRE ATT&CK framework"
              : "No MITRE technique mapping available",
          },
          {
            factor: "ioc_presence",
            weight: 0.2,
            present: hasIocs,
            explanation: hasIocs
              ? "Observable indicators (IPs, hostnames) support attribution"
              : "No concrete indicators of compromise found",
          },
          {
            factor: "alert_diversity",
            weight: 0.15,
            present: alertDiversity >= 2,
            explanation:
              alertDiversity >= 2
                ? `${alertDiversity} distinct alert categories strengthen correlation`
                : "Single category — may be noise",
          },
          {
            factor: "ai_narrative",
            weight: 0.15,
            present: hasNarrative,
            explanation: hasNarrative ? "AI narrative generated and reviewed" : "No AI narrative generated yet",
          },
          {
            factor: "sufficient_evidence",
            weight: 0.15,
            present: alerts.length >= 3,
            explanation:
              alerts.length >= 3
                ? `${alerts.length} correlated alerts provide sufficient evidence`
                : `Only ${alerts.length} alert(s) — limited evidence base`,
          },
        ];

        const score = factors.reduce((sum, f) => sum + (f.present ? f.weight : 0), 0);
        const level = score >= 0.75 ? "high" : score >= 0.45 ? "medium" : "low";

        res.json({
          incidentId,
          confidenceScore: Math.round(score * 100) / 100,
          confidenceLevel: level,
          factors,
          evidenceSummary: {
            alertCount: alerts.length,
            sourceCount,
            hasNarrative,
            hasMitre,
            hasIocs,
            alertDiversity,
          },
        });
      } catch (error: any) {
        logger.child("ai").error("Confidence indicators error", { error: String(error) });
        res.status(500).json({ message: "Failed to compute confidence indicators" });
      }
    },
  );

  // Investigation History Search
  app.get("/api/ai/investigation-history", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const keyword = typeof req.query.keyword === "string" ? req.query.keyword.trim() : undefined;
      const incidentId = typeof req.query.incidentId === "string" ? req.query.incidentId.trim() : undefined;
      const dateFrom = typeof req.query.dateFrom === "string" ? req.query.dateFrom : undefined;
      const dateTo = typeof req.query.dateTo === "string" ? req.query.dateTo : undefined;
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "50"), 10) || 50, 1), 200);
      const offset = Math.max(parseInt(String(req.query.offset || "0"), 10) || 0, 0);

      const conditions: string[] = ["org_id = $1"];
      const params: unknown[] = [orgId];
      let paramIdx = 2;

      if (keyword) {
        conditions.push(`(content ILIKE $${paramIdx} OR role = 'user' AND content ILIKE $${paramIdx})`);
        params.push(`%${keyword.replace(/%/g, "\\%")}%`);
        paramIdx++;
      }

      if (incidentId) {
        conditions.push(`incident_id = $${paramIdx}`);
        params.push(incidentId);
        paramIdx++;
      }

      if (dateFrom) {
        conditions.push(`created_at >= $${paramIdx}`);
        params.push(dateFrom);
        paramIdx++;
      }

      if (dateTo) {
        conditions.push(`created_at <= $${paramIdx}`);
        params.push(dateTo);
        paramIdx++;
      }

      const whereClause = conditions.join(" AND ");
      const countQuery = `SELECT COUNT(*) as total FROM investigation_chat_messages WHERE ${whereClause}`;
      const dataQuery = `SELECT * FROM investigation_chat_messages WHERE ${whereClause} ORDER BY created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
      params.push(limit, offset);

      let total = 0;
      let messages: unknown[] = [];
      try {
        const countResult = await pool.query(countQuery, params.slice(0, paramIdx - 1));
        total = parseInt(String(countResult.rows[0]?.total || "0"), 10);
        const dataResult = await pool.query(dataQuery, params);
        messages = dataResult.rows;
      } catch (err) {
        log.debug("investigation_chat_messages query failed (table may not exist)", { error: String(err) });
      }

      res.json({ items: messages, total, limit, offset });
    } catch (error: any) {
      logger.child("ai").error("Investigation history search error", { error: String(error) });
      res.status(500).json({ message: "Failed to search investigation history" });
    }
  });
}
