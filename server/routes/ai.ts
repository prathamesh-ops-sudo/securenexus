import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { bodySchemas, querySchemas, validateBody, validateQuery } from "../request-validator";
import { insertAiDeploymentConfigSchema } from "@shared/schema";
import {
  buildThreatIntelContext,
  checkModelHealth,
  correlateAlerts,
  generateIncidentNarrative,
  getInferenceMetrics,
  getModelConfig,
  triageAlert,
  getPromptCatalogSummary,
  getAllRegisteredPrompts,
  getPromptAuditLog,
  getPromptVersionHistory,
  getAiOrgUsage,
  getAllAiOrgUsage,
  setAiOrgBudget,
  clearModelCache,
  conductDeepInvestigation,
  conductThreatHunt,
  analyzeBehavior,
  predictAttackPaths,
} from "../ai";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { invokeModel as gatewayInvoke } from "../ai/model-gateway";
import { config as appConfig } from "../config";

export function registerAiRoutes(app: Express): void {
  // AI Engine - SecureNexus Cyber Analyst (Mistral Large 2 Instruct / SageMaker)
  app.get("/api/ai/health", isAuthenticated, strictLimiter, async (_req, res) => {
    try {
      const health = await checkModelHealth();
      res.json(health);
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ status: "error", message: "An internal error occurred. Please try again." });
    }
  });

  app.get("/api/ai/config", isAuthenticated, async (_req, res) => {
    res.json(await getModelConfig());
  });

  app.get("/api/ai/inference-metrics", isAuthenticated, strictLimiter, async (req, res) => {
    res.json(getInferenceMetrics());
  });

  app.post(
    "/api/ai/correlate",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const orgId = (req as any).orgId || (req as any).user?.orgId;
        const { alertIds } = req.body;
        let alertsToCorrelate;
        if (alertIds && Array.isArray(alertIds) && alertIds.length > 0) {
          const allAlerts = await storage.getAlerts(orgId);
          alertsToCorrelate = allAlerts.filter((a) => alertIds.includes(a.id));
        } else {
          alertsToCorrelate = (await storage.getAlerts(orgId)).filter(
            (a) => a.status === "new" || a.status === "triaged",
          );
        }
        if (alertsToCorrelate.length === 0) {
          return res.status(400).json({ message: "No alerts to correlate" });
        }
        const threatIntelCtx = await buildThreatIntelContext(alertsToCorrelate);
        const result = await correlateAlerts(alertsToCorrelate, threatIntelCtx, orgId);
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_correlation",
          resourceType: "alerts",
          details: { alertCount: alertsToCorrelate.length, groupsFound: result.correlatedGroups.length },
        });
        try {
          await storage.incrementUsage(orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", { error: String(e), orgId });
        }
        res.json(result);
      } catch (error: any) {
        const errMsg = error?.message || String(error);
        logger.child("ai").error("AI correlation error", { error: errMsg });
        let userMessage = "AI correlation failed. Please try again.";
        if (errMsg.includes("Circuit breaker open")) {
          userMessage = "AI service is temporarily unavailable due to repeated failures. Please try again later.";
        } else if (errMsg.includes("budget exceeded")) {
          userMessage = "AI budget exceeded for your organization. Contact your admin to increase limits.";
        } else if (errMsg.includes("not found in registry")) {
          userMessage = "AI correlation prompt is not configured. Contact your administrator.";
        } else if (errMsg.length <= 200) {
          userMessage = errMsg;
        }
        res.status(500).json({ message: userMessage });
      }
    },
  );

  app.post(
    "/api/ai/narrative/:incidentId",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const narrativeOrgId = (req as any).orgId || (req as any).user?.orgId;
        const incident = await storage.getIncident(p(req.params.incidentId));
        if (!incident || (narrativeOrgId && incident.orgId && incident.orgId !== narrativeOrgId)) {
          return res.status(404).json({ message: "Incident not found" });
        }
        const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
        const threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        const result = await generateIncidentNarrative(incident, incidentAlerts, threatIntelCtx, narrativeOrgId);
        if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
          (result as any).threatIntelSources = Array.from(
            new Set([
              ...threatIntelCtx.enrichmentResults.map((r) => r.provider),
              ...threatIntelCtx.osintMatches.map((r) => r.feedName),
            ]),
          );
        }
        const storedIocs = Array.isArray(result.iocs)
          ? result.iocs.map((ioc: any) =>
              typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type}: ${ioc.context})`,
            )
          : [];
        const { diamondModel: _dm, ...storedAttackerProfile } = result.attackerProfile || ({} as any);
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
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_narrative_generated",
          resourceType: "incident",
          resourceId: p(req.params.incidentId),
          details: { riskScore: result.riskScore },
        });
        try {
          await storage.incrementUsage((req as any).orgId || (req as any).user?.orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", {
            error: String(e),
            orgId: (req as any).orgId || (req as any).user?.orgId,
          });
        }
        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("AI narrative error", { error: String(error) });
        res.status(500).json({ message: "AI narrative generation failed. Please try again." });
      }
    },
  );

  app.post(
    "/api/ai/triage/:alertId",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const triageOrgId = (req as any).orgId || (req as any).user?.orgId;
        const alert = await storage.getAlert(p(req.params.alertId));
        if (!alert || (triageOrgId && alert.orgId && alert.orgId !== triageOrgId)) {
          return res.status(404).json({ message: "Alert not found" });
        }
        const threatIntelCtx = await buildThreatIntelContext([alert]);
        const result = await triageAlert(alert, threatIntelCtx, triageOrgId);
        if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
          result.threatIntelSources = Array.from(
            new Set([
              ...threatIntelCtx.enrichmentResults.map((r) => r.provider),
              ...threatIntelCtx.osintMatches.map((r) => r.feedName),
            ]),
          );
        }
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_triage",
          resourceType: "alert",
          resourceId: p(req.params.alertId),
          details: { severity: result.severity, priority: result.priority },
        });
        try {
          await storage.incrementUsage((req as any).orgId || (req as any).user?.orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", {
            error: String(e),
            orgId: (req as any).orgId || (req as any).user?.orgId,
          });
        }
        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("AI triage error", { error: String(error) });
        res.status(500).json({ message: "AI triage failed. Please try again." });
      }
    },
  );

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
        mitreTactics: Array.isArray(group.mitreTactics)
          ? group.mitreTactics.filter((t: any) => typeof t === "string")
          : [],
        mitreTechniques: Array.isArray(group.mitreTechniques)
          ? group.mitreTechniques.filter((t: any) => typeof t === "string")
          : [],
        alertCount: validAlertIds.length,
      });
      for (const alertId of validAlertIds) {
        await storage.updateAlertStatus(alertId, "correlated", incident.id);
      }
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Analyst",
        action: "ai_correlation_applied",
        resourceType: "incident",
        resourceId: incident.id,
        details: { alertCount: group.alertIds.length, title: incident.title },
      });
      res.json(incident);
    } catch (error: any) {
      logger.child("routes").error("Apply correlation error", { error: String(error) });
      res.status(500).json({ message: "Failed to apply correlation. Please try again." });
    }
  });

  // AI Feedback (Phase 7+12)
  app.post("/api/ai/feedback", isAuthenticated, validateBody(bodySchemas.aiFeedback), async (req, res) => {
    try {
      const {
        resourceType,
        resourceId,
        rating,
        comment,
        aiOutput,
        correctionReason,
        correctedSeverity,
        correctedCategory,
      } = (req as any).validatedBody;
      const feedbackData: any = {
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Analyst",
        resourceType,
        resourceId,
        rating,
        comment,
        aiOutput,
      };
      if (correctionReason) feedbackData.correctionReason = correctionReason;
      if (correctedSeverity) feedbackData.correctedSeverity = correctedSeverity;
      if (correctedCategory) feedbackData.correctedCategory = correctedCategory;
      const feedback = await storage.createAiFeedback(feedbackData);
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Analyst",
        action: "ai_feedback_submitted",
        resourceType,
        resourceId,
        details: { rating, hasComment: !!comment, correctionReason, correctedSeverity, correctedCategory },
      });
      res.status(201).json(feedback);
    } catch (error) {
      res.status(500).json({ message: "Failed to submit feedback" });
    }
  });

  app.get(
    "/api/ai/feedback/metrics",
    isAuthenticated,
    validateQuery(querySchemas.feedbackMetrics),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const { days } = (req as any).validatedQuery;
        const metrics = await storage.getAiFeedbackMetrics(orgId, days);
        res.json(metrics);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feedback metrics" });
      }
    },
  );

  app.get("/api/ai/feedback/:resourceType/:resourceId", isAuthenticated, async (req, res) => {
    try {
      const feedback = await storage.getAiFeedbackByResource(p(req.params.resourceType), p(req.params.resourceId));
      res.json(feedback);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch feedback for resource" });
    }
  });

  app.get("/api/ai/feedback", isAuthenticated, validateQuery(querySchemas.aiFeedbackByQuery), async (req, res) => {
    try {
      const { resourceType, resourceId } = (req as any).validatedQuery;
      const feedback = await storage.getAiFeedback(resourceType as string, resourceId as string);
      res.json(feedback);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch feedback" });
    }
  });

  app.post("/api/ai/playbook-authoring/propose", isAuthenticated, resolveOrgContext, async (req, res) => {
    const PROPOSAL_TIMEOUT_MS = 30_000;
    const log = logger.child("ai-playbook-propose");
    try {
      const { objective, severity = "high", guardrails = [] } = req.body || {};
      const normalized = String(objective || "Contain suspicious activity").trim();
      const orgId: string | undefined = (req as any).orgId || (req as any).user?.orgId;

      const blocked = new Set(["delete_data", "shutdown_network", "disable_logging"]);
      const fallbackActions = [
        { type: "auto_triage", reason: "Initial enrichment and classification" },
        { type: "assign_analyst", reason: "Ensure analyst ownership" },
        severity === "critical"
          ? { type: "isolate_host", reason: "Containment for critical blast radius" }
          : { type: "notify_slack", reason: "Notify response channel" },
      ].filter((a) => !blocked.has(a.type));

      const fallbackResponse = {
        objective: normalized,
        guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
        proposedActions: fallbackActions,
        requiresAnalystApproval: true,
        source: "fallback" as const,
      };

      const systemPrompt = [
        "You are a SOC playbook architect. Given a security objective and severity, propose a JSON array of response actions.",
        "Each action must have: type (string), reason (string explaining why this step is needed).",
        "BLOCKED action types that must never appear: delete_data, shutdown_network, disable_logging.",
        "Available action types: auto_triage, assign_analyst, notify_slack, isolate_host, block_ip, quarantine_file, enrich_ioc, create_ticket, escalate, snapshot_evidence.",
        "Output ONLY a valid JSON array of action objects. No preamble, no markdown, no commentary.",
      ].join(" ");

      const userMessage = `Objective: ${normalized}\nSeverity: ${severity}\nGuardrails: ${guardrails.length > 0 ? guardrails.join(", ") : "none specified"}`;

      const aiPromise = gatewayInvoke({
        modelId: appConfig.ai.modelId,
        backend: appConfig.ai.backend,
        systemPrompt,
        userMessage,
        maxTokens: 1024,
        temperature: 0.3,
        topP: appConfig.ai.topP,
        sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
        orgId,
        promptId: "playbook-propose",
        skipCache: false,
      });

      const timeoutPromise = new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new Error("PROPOSAL_TIMEOUT")), PROPOSAL_TIMEOUT_MS);
      });

      const result = await Promise.race([aiPromise, timeoutPromise]);

      let proposedActions: { type: string; reason: string }[];
      try {
        const parsed = JSON.parse(result.text.trim());
        proposedActions = (Array.isArray(parsed) ? parsed : []).filter(
          (a: unknown): a is { type: string; reason: string } =>
            typeof a === "object" &&
            a !== null &&
            typeof (a as any).type === "string" &&
            typeof (a as any).reason === "string" &&
            !blocked.has((a as any).type),
        );
      } catch {
        log.warn("AI returned non-JSON, using fallback", { raw: result.text.slice(0, 200) });
        return res.json(fallbackResponse);
      }

      if (proposedActions.length === 0) {
        log.warn("AI returned empty actions, using fallback");
        return res.json(fallbackResponse);
      }

      res.json({
        objective: normalized,
        guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
        proposedActions,
        requiresAnalystApproval: true,
        source: "ai",
        latencyMs: result.latencyMs,
      });
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("PROPOSAL_TIMEOUT")) {
        log.warn("Playbook proposal timed out after 30s, returning fallback");
        const { objective, severity = "high", guardrails = [] } = req.body || {};
        const normalized = String(objective || "Contain suspicious activity").trim();
        const blocked = new Set(["delete_data", "shutdown_network", "disable_logging"]);
        const fallbackActions = [
          { type: "auto_triage", reason: "Initial enrichment and classification" },
          { type: "assign_analyst", reason: "Ensure analyst ownership" },
          severity === "critical"
            ? { type: "isolate_host", reason: "Containment for critical blast radius" }
            : { type: "notify_slack", reason: "Notify response channel" },
        ].filter((a) => !blocked.has(a.type));
        return res.json({
          objective: normalized,
          guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
          proposedActions: fallbackActions,
          requiresAnalystApproval: true,
          source: "fallback_timeout",
        });
      }
      log.error("Playbook proposal failed", { error: errMsg });
      res.status(500).json({ message: "Failed to generate playbook proposal" });
    }
  });

  // ── AI Platform Introspection Routes (3.5) ──

  app.get(
    "/api/ai/budget/usage",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        res.json(await getAiOrgUsage(orgId));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch AI budget usage" });
      }
    },
  );

  app.get(
    "/api/ai/budget/usage/all",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        res.json(await getAllAiOrgUsage());
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch all AI budget usage" });
      }
    },
  );

  app.put(
    "/api/ai/budget",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { dailyBudgetUsd, dailyInvocationCap } = req.body;
        if (typeof dailyBudgetUsd !== "number" || dailyBudgetUsd <= 0 || dailyBudgetUsd > 10000) {
          return res.status(400).json({ message: "dailyBudgetUsd must be a number between 0 and 10000" });
        }
        if (typeof dailyInvocationCap !== "number" || dailyInvocationCap <= 0 || dailyInvocationCap > 100000) {
          return res.status(400).json({ message: "dailyInvocationCap must be a number between 0 and 100000" });
        }
        await setAiOrgBudget(orgId, dailyBudgetUsd, dailyInvocationCap);
        res.json({ orgId, dailyBudgetUsd, dailyInvocationCap, updated: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to update AI budget" });
      }
    },
  );

  app.get("/api/ai/prompts", isAuthenticated, async (_req, res) => {
    try {
      const prompts = await getAllRegisteredPrompts();
      const summary = await getPromptCatalogSummary();
      res.json({ prompts, summary });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt catalog" });
    }
  });

  app.get("/api/ai/prompts/:id", isAuthenticated, async (req, res) => {
    try {
      const prompts = await getAllRegisteredPrompts();
      const prompt = prompts.find((pt) => pt.id === p(req.params.id));
      if (!prompt) return res.status(404).json({ message: "Prompt not found" });
      res.json(prompt);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt" });
    }
  });

  app.get("/api/ai/prompts/:id/history", isAuthenticated, async (req, res) => {
    try {
      const history = await getPromptVersionHistory(p(req.params.id));
      if (history.length === 0) return res.status(404).json({ message: "No version history found for prompt" });
      res.json(history);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt version history" });
    }
  });

  app.get("/api/ai/prompts/:id/audit", isAuthenticated, async (req, res) => {
    try {
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "50"), 10) || 50, 1), 200);
      const auditEntries = await getPromptAuditLog(p(req.params.id), limit);
      res.json(auditEntries);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt audit log" });
    }
  });

  app.get("/api/ai/audit", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "100"), 10) || 100, 1), 500);
      const auditEntries = await getPromptAuditLog(undefined, limit);
      res.json(auditEntries);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch AI audit log" });
    }
  });

  app.post("/api/ai/cache/clear", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (_req, res) => {
    try {
      clearModelCache();
      res.json({ cleared: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to clear model cache" });
    }
  });

  // ── AI Deployment Config Routes ──
  app.get("/api/ai-deployment/config", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const config = await storage.getAiDeploymentConfig(orgId);
      if (!config) return res.json(null);
      res.json(config);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch AI deployment config" });
    }
  });

  app.put(
    "/api/ai-deployment/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertAiDeploymentConfigSchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid AI deployment config data", errors: parsed.error.flatten() });
        }
        const config = await storage.upsertAiDeploymentConfig(parsed.data);
        res.json(config);
      } catch (error) {
        res.status(500).json({ message: "Failed to upsert AI deployment config" });
      }
    },
  );

  // =============================
  // ENHANCED AI CAPABILITIES
  // =============================

  /**
   * POST /api/ai/deep-investigation/:incidentId
   * Conduct deep forensic investigation with advanced analysis
   */
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

        const result = await conductDeepInvestigation(incident, incidentAlerts, threatIntelCtx, orgId);

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

        storage.incrementUsage(orgId, "ai_analyses").catch(() => {});

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Deep investigation error", { error: String(error) });
        res.status(500).json({ message: "Deep investigation failed. Please try again." });
      }
    },
  );

  /**
   * POST /api/ai/threat-hunt
   * Conduct proactive threat hunting mission
   */
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

        // Build threat intel context if telemetry includes alerts
        let threatIntelCtx;
        if (telemetryData.alerts && Array.isArray(telemetryData.alerts)) {
          threatIntelCtx = await buildThreatIntelContext(telemetryData.alerts);
        }

        const result = await conductThreatHunt(huntContext, telemetryData, threatIntelCtx, orgId);

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

        storage.incrementUsage(orgId, "ai_analyses").catch(() => {});

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Threat hunting error", { error: String(error) });
        res.status(500).json({ message: "Threat hunting failed. Please try again." });
      }
    },
  );

  /**
   * POST /api/ai/behavioral-analysis
   * Analyze behavioral patterns for insider threats and account compromise
   */
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
        const result = await analyzeBehavior(entityContext, activityData, baselineData, orgId);

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

        storage.incrementUsage(orgId, "ai_analyses").catch(() => {});

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Behavioral analysis error", { error: String(error) });
        res.status(500).json({ message: "Behavioral analysis failed. Please try again." });
      }
    },
  );

  /**
   * POST /api/ai/predict-attack-paths
   * Predict attacker's next moves and attack paths
   */
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

        const result = await predictAttackPaths(
          compromiseState,
          networkTopology || {},
          crownJewels || [],
          securityControls || {},
          orgId,
        );

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

        storage.incrementUsage(orgId, "ai_analyses").catch(() => {});

        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("Attack path prediction error", { error: String(error) });
        res.status(500).json({ message: "Attack path prediction failed. Please try again." });
      }
    },
  );
}
