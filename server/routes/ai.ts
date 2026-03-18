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
  streamNarrative,
  streamDeepInvestigation,
  conductMultiTurnInvestigation,
  generateDetectionRules,
  getInferenceHistory,
  getInferenceStats,
  getPromptVersion,
} from "../ai";
import { recordFeedbackOutcome } from "../ai/active-learning";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import type { InsertAttackGraphNode, InsertAttackGraphEdge } from "@shared/schema";
import { invokeModel as gatewayInvoke, getCircuitBreakerStatus } from "../ai/model-gateway";
import { config as appConfig } from "../config";
import { eventBus, type BusEvent } from "../event-bus";
import { pool } from "../db";

/**
 * Persist attack graph data from a deep investigation result to the database.
 * Extracts nodes and edges from the result's attackGraph field and stores them
 * in separate normalized tables for querying and visualization.
 */
async function persistAttackGraph(result: Record<string, unknown>, incidentId: string, orgId: string): Promise<void> {
  const attackGraph = result.attackGraph as
    | {
        initialAccess?: unknown;
        nodes?: unknown[];
        edges?: unknown[];
        currentPosition?: string;
        objectivesAchieved?: string[];
        objectivesInProgress?: string[];
      }
    | undefined;

  if (!attackGraph || (!attackGraph.nodes?.length && !attackGraph.edges?.length)) {
    return; // No attack graph data to persist
  }

  const nodes = Array.isArray(attackGraph.nodes) ? attackGraph.nodes : [];
  const edges = Array.isArray(attackGraph.edges) ? attackGraph.edges : [];

  // Compute max depth from nodes
  let maxDepth = 0;
  for (const n of nodes) {
    const d = typeof n === "object" && n && "depth" in n ? Number((n as Record<string, unknown>).depth) || 0 : 0;
    if (d > maxDepth) maxDepth = d;
  }

  // Create the parent graph record
  const graph = await storage.createAttackGraph({
    orgId,
    incidentId,
    initialAccessDescription:
      typeof attackGraph.initialAccess === "string"
        ? attackGraph.initialAccess
        : JSON.stringify(attackGraph.initialAccess ?? null),
    currentPosition: attackGraph.currentPosition || null,
    objectivesAchieved: attackGraph.objectivesAchieved || [],
    objectivesInProgress: attackGraph.objectivesInProgress || [],
    totalNodes: nodes.length,
    totalEdges: edges.length,
    maxDepth,
    confidence: typeof result.investigationConfidence === "number" ? result.investigationConfidence : 0,
    metadata: null,
  });

  // Insert nodes
  if (nodes.length > 0) {
    const nodeRecords: InsertAttackGraphNode[] = nodes.map((n, idx) => {
      const node = (typeof n === "object" && n ? n : {}) as Record<string, unknown>;
      return {
        graphId: graph.id,
        nodeId: String(node.id || node.nodeId || `node-${idx}`),
        nodeType: String(node.type || node.nodeType || "unknown"),
        label: String(node.label || node.name || `Node ${idx}`),
        description: node.description ? String(node.description) : null,
        mitreTechnique: node.mitreTechnique || node.technique ? String(node.mitreTechnique || node.technique) : null,
        mitreTactic: node.mitreTactic || node.tactic ? String(node.mitreTactic || node.tactic) : null,
        confidence: typeof node.confidence === "number" ? node.confidence : null,
        severity: node.severity ? String(node.severity) : null,
        evidence: Array.isArray(node.evidence) ? node.evidence.map(String) : [],
        metadata: node.metadata ? (node.metadata as Record<string, unknown>) : null,
        positionX: typeof node.x === "number" ? node.x : typeof node.positionX === "number" ? node.positionX : null,
        positionY: typeof node.y === "number" ? node.y : typeof node.positionY === "number" ? node.positionY : null,
        depth: typeof node.depth === "number" ? node.depth : idx,
      };
    });
    await storage.createAttackGraphNodes(nodeRecords);
  }

  // Insert edges
  if (edges.length > 0) {
    const edgeRecords: InsertAttackGraphEdge[] = edges.map((e, idx) => {
      const edge = (typeof e === "object" && e ? e : {}) as Record<string, unknown>;
      return {
        graphId: graph.id,
        sourceNodeId: String(edge.source || edge.from || edge.sourceNodeId || `node-${idx}`),
        targetNodeId: String(edge.target || edge.to || edge.targetNodeId || `node-${idx + 1}`),
        relationship: String(edge.relationship || edge.label || edge.type || "connected"),
        technique: edge.technique ? String(edge.technique) : null,
        confidence: typeof edge.confidence === "number" ? edge.confidence : null,
        timestamp: edge.timestamp ? String(edge.timestamp) : null,
        evidence: Array.isArray(edge.evidence) ? edge.evidence.map(String) : [],
        metadata: edge.metadata ? (edge.metadata as Record<string, unknown>) : null,
      };
    });
    await storage.createAttackGraphEdges(edgeRecords);
  }

  logger.child("ai").info("Attack graph persisted", {
    graphId: graph.id,
    incidentId,
    nodes: nodes.length,
    edges: edges.length,
  });
}

export function registerAiRoutes(app: Express): void {
  // --- Circuit breaker event listener: auto-create system alert ---
  eventBus.on("system.ai_circuit_open", (event: BusEvent) => {
    const { modelId, backend, resetAt, failureCount } = event.data;
    storage
      .createAlert({
        title: "AI service circuit breaker opened",
        description: `AI model ${modelId} (${backend}) circuit breaker tripped after ${failureCount} consecutive failures. Service will attempt recovery at ${resetAt}.`,
        source: "system",
        severity: "high",
        status: "new",
        category: "ai_service_failure",
        rawData: { modelId, backend, resetAt, failureCount, eventType: "system.ai_circuit_open" },
      })
      .then((alert) => {
        logger.child("ai").warn("Auto-created alert for AI circuit breaker trip", {
          alertId: alert.id,
          modelId,
          backend,
        });
      })
      .catch((err) => {
        logger.child("ai").error("Failed to auto-create circuit breaker alert", { error: String(err) });
      });
  });

  // --- GET /api/ai/setup-status — first-run setup health checklist ---
  app.get("/api/ai/setup-status", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);

      // 1. Check Bedrock reachability via a lightweight health check
      let bedrockReachable = false;
      try {
        const healthResult = await checkModelHealth();
        bedrockReachable = healthResult.status === "healthy";
      } catch {
        bedrockReachable = false;
      }

      // 2. Check model availability from config
      const modelConfig = await getModelConfig();
      const modelsEnabled = {
        default: !!modelConfig.model,
        investigation: !!appConfig.ai.investigation.modelId,
        triage: !!appConfig.ai.triage.modelId,
      };

      // 3. Check if budget is set for this org
      let budgetSet = false;
      try {
        const budgetResult = await pool.query(`SELECT budget_usd FROM org_ai_budgets WHERE org_id = $1 LIMIT 1`, [
          orgId,
        ]);
        budgetSet = budgetResult.rows.length > 0 && (budgetResult.rows[0] as { budget_usd: number }).budget_usd > 0;
      } catch {
        budgetSet = false;
      }

      // 4. Check if prompts are initialized
      let promptsInitialized = false;
      try {
        const catalog = await getPromptCatalogSummary();
        promptsInitialized = catalog.totalPrompts > 0;
      } catch {
        promptsInitialized = false;
      }

      // 5. Check circuit breaker status
      const circuitBreakers = getCircuitBreakerStatus();
      const circuitHealthy = Object.values(circuitBreakers).every((cb) => !(cb as { isOpen: boolean }).isOpen);

      const allGreen =
        bedrockReachable &&
        Object.values(modelsEnabled).some(Boolean) &&
        budgetSet &&
        promptsInitialized &&
        circuitHealthy;

      res.json({
        ready: allGreen,
        checks: {
          bedrockReachable,
          modelsEnabled,
          budgetSet,
          promptsInitialized,
          circuitHealthy,
        },
      });
    } catch (error: unknown) {
      logger.child("ai").error("Setup status check failed", { error: String(error) });
      res.status(500).json({ message: "Failed to check AI setup status." });
    }
  });

  // --- GET /api/ai/circuit-alerts — recent AI service failure alerts ---
  app.get("/api/ai/circuit-alerts", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
      const result = await pool.query(
        `SELECT id, title, description, severity, status, category, created_at, raw_data
         FROM alerts
         WHERE category = 'ai_service_failure'
           AND status != 'resolved'
           AND created_at >= $1
           AND (org_id = $2 OR org_id IS NULL)
         ORDER BY created_at DESC
         LIMIT 10`,
        [twoHoursAgo, orgId],
      );
      res.json(result.rows);
    } catch (error: unknown) {
      logger.child("ai").error("Circuit alerts query failed", { error: String(error) });
      res.json([]);
    }
  });

  // --- PATCH /api/ai/circuit-alerts/:alertId/dismiss — dismiss a circuit breaker alert ---
  app.patch(
    "/api/ai/circuit-alerts/:alertId/dismiss",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const alertId = p(req.params.alertId);
        const orgId = getOrgId(req);
        // Verify the alert belongs to this org (or is system-wide)
        const check = await pool.query(
          `SELECT id FROM alerts WHERE id = $1 AND (org_id = $2 OR org_id IS NULL) AND category = 'ai_service_failure'`,
          [alertId, orgId],
        );
        if (check.rows.length === 0) {
          return res.status(404).json({ message: "Alert not found." });
        }
        await storage.updateAlert(alertId, { status: "resolved" });
        res.json({ success: true });
      } catch (error: unknown) {
        logger.child("ai").error("Dismiss circuit alert failed", { error: String(error) });
        res.status(500).json({ message: "Failed to dismiss alert." });
      }
    },
  );

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

  // --- GET /api/ai/inference-history — persistent inference log with filters ---
  app.get(
    "/api/ai/inference-history",
    isAuthenticated,
    resolveOrgContext,
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const tier = req.query.tier ? String(req.query.tier) : undefined;
        const limit = req.query.limit ? Math.min(Math.max(parseInt(String(req.query.limit), 10) || 100, 1), 1000) : 100;
        const sinceDays = req.query.days ? Math.min(Math.max(parseInt(String(req.query.days), 10) || 7, 1), 90) : 7;
        const since = new Date(Date.now() - sinceDays * 24 * 60 * 60 * 1000);
        const history = await getInferenceHistory({ tier, limit, since, orgId });
        res.json(history);
      } catch (error: unknown) {
        logger.child("ai").error("Inference history query failed", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch inference history" });
      }
    },
  );

  // --- GET /api/ai/inference-stats — aggregated daily + per-tier stats ---
  app.get(
    "/api/ai/inference-stats",
    isAuthenticated,
    resolveOrgContext,
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const days = req.query.days ? Math.min(Math.max(parseInt(String(req.query.days), 10) || 7, 1), 90) : 7;
        const stats = await getInferenceStats(days, orgId);
        res.json(stats);
      } catch (error: unknown) {
        logger.child("ai").error("Inference stats query failed", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch inference stats" });
      }
    },
  );

  // --- POST /api/ai/test-prompt — dry-run a prompt with sample input (no production side-effects) ---
  app.post(
    "/api/ai/test-prompt",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const { promptId, version, sampleInput } = req.body;
        if (!promptId || typeof promptId !== "string") {
          return res.status(400).json({ message: "promptId is required" });
        }
        if (!sampleInput || typeof sampleInput !== "string") {
          return res.status(400).json({ message: "sampleInput is required" });
        }

        // Fetch the specific version or current version
        let prompt;
        if (typeof version === "number") {
          prompt = await getPromptVersion(promptId, version);
        } else {
          const allPrompts = await getAllRegisteredPrompts();
          prompt = allPrompts.find((pt) => pt.id === promptId);
        }

        if (!prompt) {
          return res.status(404).json({ message: "Prompt not found" });
        }

        // Invoke the model with the prompt but don't record it as a production invocation
        const start = Date.now();
        const result = await gatewayInvoke({
          modelId: appConfig.ai.modelId,
          backend: appConfig.ai.backend,
          systemPrompt: prompt.systemPrompt,
          userMessage: sampleInput,
          maxTokens: prompt.maxTokens,
          temperature: prompt.temperature,
          topP: appConfig.ai.topP,
          sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
          skipCache: true,
        });

        res.json({
          output: result.text,
          latencyMs: Date.now() - start,
          model: result.modelId,
          inputTokens: result.inputTokensEstimate,
          outputTokens: result.outputTokensEstimate,
          cached: result.cached,
          prompt: {
            id: prompt.id,
            version: prompt.version,
            name: prompt.name,
            tier: prompt.tier,
          },
        });
      } catch (error: unknown) {
        logger.child("ai").error("Test prompt failed", { error: String(error) });
        const errMsg = (error as Error).message || String(error);
        res.status(500).json({ message: errMsg.length <= 200 ? errMsg : "Test prompt invocation failed" });
      }
    },
  );

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

  // ── SSE Streaming: Narrative ──
  app.get(
    "/api/ai/narrative/:incidentId/stream",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident || (orgId && incident.orgId && incident.orgId !== orgId)) {
        return res.status(404).json({ message: "Incident not found" });
      }
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));

      // Set SSE headers
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders();

      // Send initial connection event
      res.write(
        `data: ${JSON.stringify({ type: "connected", message: "Stream connected. Building threat context..." })}\n\n`,
      );

      let threatIntelCtx;
      try {
        threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        res.write(
          `data: ${JSON.stringify({ type: "status", message: "Threat context built. Starting AI analysis..." })}\n\n`,
        );
      } catch (err) {
        res.write(
          `data: ${JSON.stringify({ type: "error", message: "Failed to build threat intelligence context" })}\n\n`,
        );
        res.write("data: [DONE]\n\n");
        res.end();
        return;
      }

      await streamNarrative(incident, incidentAlerts, threatIntelCtx, {
        onChunk: (text: string) => {
          if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ type: "chunk", text })}\n\n`);
          }
        },
        onComplete: async (fullText: string, metrics) => {
          try {
            // Parse the completed response and store in DB (same as non-streaming)
            const parsed = (() => {
              try {
                const jsonMatch = fullText.match(/\{[\s\S]*\}/);
                return jsonMatch ? JSON.parse(jsonMatch[0]) : null;
              } catch {
                return null;
              }
            })();

            if (parsed) {
              const storedIocs = Array.isArray(parsed.iocs)
                ? parsed.iocs.map((ioc: any) =>
                    typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type}: ${ioc.context})`,
                  )
                : [];
              const { diamondModel: _dm, ...storedAttackerProfile } = parsed.attackerProfile || ({} as any);
              await storage.updateIncident(p(req.params.incidentId), {
                aiNarrative: parsed.narrative || fullText,
                aiSummary: parsed.summary,
                mitigationSteps: parsed.mitigationSteps as any,
                iocs: storedIocs as any,
                attackerProfile: storedAttackerProfile as any,
                referencedAlertIds: Array.isArray(parsed.citedAlertIds) ? parsed.citedAlertIds : [],
              });
            }

            await storage.createAuditLog({
              userId: (req as any).user?.id,
              userName: (req as any).user?.firstName
                ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
                : "Analyst",
              action: "ai_narrative_generated",
              resourceType: "incident",
              resourceId: p(req.params.incidentId),
              details: { streamed: true, latencyMs: metrics.latencyMs, riskScore: parsed?.riskScore },
            });

            storage.incrementUsage(orgId, "ai_analyses").catch(() => {});
          } catch (e) {
            logger.child("ai").warn("Post-stream processing error", { error: String(e) });
          }

          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "done", latencyMs: metrics.latencyMs })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream completion", { error: String(writeErr) });
          }
        },
        onError: (error: Error) => {
          logger.child("ai").error("Streaming narrative error", { error: error.message });
          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "error", message: error.message })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream error", { error: String(writeErr) });
          }
        },
      });
    },
  );

  // ── SSE Streaming: Deep Investigation ──
  app.get(
    "/api/ai/deep-investigation/:incidentId/stream",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident || (orgId && incident.orgId && incident.orgId !== orgId)) {
        return res.status(404).json({ message: "Incident not found" });
      }

      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
      if (incidentAlerts.length === 0) {
        return res.status(400).json({ message: "No alerts associated with this incident" });
      }

      // Set SSE headers
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Accel-Buffering", "no");
      res.flushHeaders();

      res.write(
        `data: ${JSON.stringify({ type: "connected", message: "Stream connected. Building forensic context..." })}\n\n`,
      );

      let threatIntelCtx;
      try {
        threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
        res.write(
          `data: ${JSON.stringify({ type: "status", message: "Context enriched. Starting deep investigation..." })}\n\n`,
        );
      } catch (err) {
        // Continue without threat intel
        res.write(
          `data: ${JSON.stringify({ type: "status", message: "Proceeding without threat intelligence enrichment..." })}\n\n`,
        );
      }

      await streamDeepInvestigation(incident, incidentAlerts, threatIntelCtx, {
        onChunk: (text: string) => {
          if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ type: "chunk", text })}\n\n`);
          }
        },
        onComplete: async (fullText: string, metrics) => {
          try {
            // Try to extract and persist attack graph from streamed text
            try {
              const parsed = JSON.parse(fullText);
              if (parsed && parsed.attackGraph) {
                await persistAttackGraph(parsed, incident.id, orgId);
              }
            } catch {
              // Stream text may not be valid JSON — that's OK
            }

            await storage.createAuditLog({
              userId: (req as any).user?.id,
              userName: (req as any).user?.firstName
                ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
                : "Analyst",
              action: "ai_deep_investigation",
              resourceType: "incident",
              resourceId: incident.id,
              details: { alertCount: incidentAlerts.length, streamed: true, latencyMs: metrics.latencyMs },
            });
            storage.incrementUsage(orgId, "ai_analyses").catch(() => {});
          } catch (e) {
            logger.child("ai").warn("Post-stream processing error", { error: String(e) });
          }

          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "done", latencyMs: metrics.latencyMs })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream completion", { error: String(writeErr) });
          }
        },
        onError: (error: Error) => {
          logger.child("ai").error("Streaming deep investigation error", { error: error.message });
          try {
            if (!res.writableEnded) {
              res.write(`data: ${JSON.stringify({ type: "error", message: error.message })}\n\n`);
              res.write("data: [DONE]\n\n");
              res.end();
            }
          } catch (writeErr) {
            logger.child("ai").warn("Failed to write stream error", { error: String(writeErr) });
          }
        },
      });
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

      // Active Learning: process feedback for few-shot injection and FP tracking
      const orgId = (req as any).user?.orgId;
      if (orgId) {
        const isOverridden = !!(correctedSeverity || correctedCategory || correctionReason);
        const isDismissed = rating <= 2 && !isOverridden;
        const outcome = isOverridden ? "overridden" : isDismissed ? "dismissed" : "confirmed";

        // Determine alert source/category from the resource being reviewed
        let alertSource = "unknown";
        let alertCategory = "unknown";
        if (resourceType === "alert" && resourceId) {
          try {
            const alert = await storage.getAlert(resourceId);
            if (alert) {
              alertSource = alert.source || "unknown";
              alertCategory = alert.category || "unknown";
            }
          } catch {
            // non-fatal
          }
        }

        // Build context strings for few-shot example
        // originalContext should be the alert data (input to the AI), not the AI's response
        let originalAlertContext = "";
        if (resourceType === "alert" && resourceId) {
          try {
            const alertData = await storage.getAlert(resourceId);
            if (alertData) {
              originalAlertContext = JSON.stringify({
                title: alertData.title,
                description: alertData.description,
                severity: alertData.severity,
                source: alertData.source,
                category: alertData.category,
                sourceIp: alertData.sourceIp,
                destIp: alertData.destIp,
              });
            }
          } catch {
            // non-fatal — fall back to empty context
          }
        }
        const aiOutputStr =
          typeof aiOutput === "object" && aiOutput !== null ? JSON.stringify(aiOutput) : String(aiOutput || "");
        const analystCorrection = [
          correctedSeverity ? `Severity: ${correctedSeverity}` : "",
          correctedCategory ? `Category: ${correctedCategory}` : "",
          comment || "",
        ]
          .filter(Boolean)
          .join("; ");

        recordFeedbackOutcome({
          orgId,
          feedbackId: feedback.id,
          outcome,
          source: alertSource,
          category: alertCategory,
          domain:
            resourceType === "correlation" ? "correlation" : resourceType === "narrative" ? "narrative" : "triage",
          originalContext: originalAlertContext || undefined,
          aiOutput: aiOutputStr || undefined,
          analystCorrection: analystCorrection || undefined,
          reason: correctionReason || comment || undefined,
        }).catch((err) =>
          logger.child("active-learning").warn("Failed to record feedback outcome", { error: String(err) }),
        );
      }

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

        // Persist attack graph if present
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
  // ── Attack Graph Persistence API ──

  /**
   * GET /api/ai/investigation-graphs/:incidentId
   * Fetch all persisted attack graphs for a specific incident
   */
  app.get("/api/ai/investigation-graphs/:incidentId", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      if (!orgId) return res.status(403).json({ message: "Organization context required" });

      const graphs = await storage.getAttackGraphsByIncident(p(req.params.incidentId), orgId);

      // Fetch nodes and edges for each graph
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

  /**
   * GET /api/ai/investigation-graphs
   * Query attack graphs by org and optional time range
   */
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

  /**
   * GET /api/ai/investigation-graphs/detail/:graphId
   * Fetch a single attack graph with all nodes and edges
   */
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

  /**
   * DELETE /api/ai/investigation-graphs/:graphId
   * Delete a persisted attack graph (cascades to nodes/edges)
   */
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

  // ─── Multi-Turn Investigation Chat ──────────────────────────────────────────

  // POST /api/ai/investigation/:incidentId/chat — send a message in investigation thread
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

        // Verify incident belongs to org
        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        // Generate or use existing thread ID
        const activeThreadId = String(threadId || `thread_${incidentId}_${Date.now()}`);

        // Get conversation history for this thread
        const history = await storage.getChatThread(activeThreadId, orgId);
        const conversationHistory = history.map((m) => ({
          role: m.role,
          content: m.content,
        }));

        // Build incident context
        const incidentAlerts = await storage.getAlertsByIncident(incidentId);
        const categories = Array.from(new Set(incidentAlerts.map((a) => a.category).filter(Boolean)));
        const incidentContext = `Incident: ${incident.title}\nSeverity: ${incident.severity}\nStatus: ${incident.status}\nSummary: ${incident.summary || "N/A"}\nAlerts: ${incidentAlerts.length} correlated alerts\nCategories: ${categories.join(", ")}`;

        // Store user message
        await storage.createChatMessage({
          orgId,
          incidentId,
          threadId: activeThreadId,
          role: "user",
          content: message,
        });

        // Get AI response via Claude Opus (investigation tier)
        const aiResponse = await conductMultiTurnInvestigation(incidentContext, conversationHistory, message, orgId);

        // Store assistant response
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

        storage.incrementUsage(orgId, "ai_analyses").catch(() => {});

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

  // GET /api/ai/investigation/:incidentId/thread — retrieve conversation history
  app.get(
    "/api/ai/investigation/:incidentId/thread",
    isAuthenticated,
    resolveOrgContext,
    async (req: Request, res: Response) => {
      try {
        const incidentId = String(req.params.incidentId);
        const orgId = getOrgId(req);

        // Verify incident belongs to org
        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const messages = await storage.getChatThreadsByIncident(incidentId, orgId);

        // Group messages by threadId
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

  // ─── AI-Generated Detection Rules ──────────────────────────────────────────

  // POST /api/ai/investigation/:incidentId/generate-rules — auto-generate detection rules
  app.post(
    "/api/ai/investigation/:incidentId/generate-rules",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const incidentId = String(req.params.incidentId);
        const orgId = getOrgId(req);

        // Verify incident belongs to org
        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const incidentAlerts = await storage.getAlertsByIncident(incidentId);
        const techniques = Array.from(new Set(incidentAlerts.map((a) => a.mitreTechnique).filter(Boolean))) as string[];
        const indicators = incidentAlerts
          .flatMap((a) => [a.sourceIp, a.hostname].filter(Boolean))
          .filter((v, i, arr) => arr.indexOf(v) === i) as string[];

        const incidentSummary = `${incident.title}: ${incident.summary || "No description"} — Severity: ${incident.severity}, Alerts: ${incidentAlerts.length}`;

        // Generate rules via Claude Opus
        const result = await generateDetectionRules(incidentSummary, techniques, indicators, orgId);

        // Persist generated rules
        const savedRules = [];
        for (const rule of result.rules) {
          const saved = await storage.createAiGeneratedRule({
            orgId,
            sourceIncidentId: incidentId,
            name: rule.name,
            description: rule.description,
            ruleContent: rule.conditionTree,
            sigmaNormalized: rule.sigmaRule,
            confidence: rule.confidence,
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechnique,
            generatedBy: "claude-opus",
          });
          savedRules.push(saved);
        }

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_generate_detection_rules",
          resourceType: "incident",
          resourceId: String(incidentId),
          details: {
            rulesGenerated: savedRules.length,
            techniques,
            analysisNotes: result.analysisNotes,
          },
        });

        storage.incrementUsage(orgId, "ai_analyses").catch(() => {});

        res.json({
          rules: savedRules,
          analysisNotes: result.analysisNotes,
          coverageGaps: result.coverageGaps,
        });
      } catch (error: any) {
        logger.child("ai").error("Detection rule generation error", { error: String(error) });
        res.status(500).json({ message: "Detection rule generation failed. Please try again." });
      }
    },
  );

  // GET /api/ai/generated-rules — get all AI-generated rules for the org
  app.get("/api/ai/generated-rules", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "50"), 10) || 50, 1), 200);
      const rules = await storage.getAiGeneratedRulesByOrg(orgId, limit);
      res.json(rules);
    } catch (error: any) {
      logger.child("ai").error("Get AI-generated rules error", { error: String(error) });
      res.status(500).json({ message: "Failed to retrieve AI-generated rules." });
    }
  });

  // PATCH /api/ai/generated-rules/:ruleId — update status of AI-generated rule (accept/reject)
  app.patch(
    "/api/ai/generated-rules/:ruleId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const ruleId = String(req.params.ruleId);
        const orgId = getOrgId(req);

        const rule = await storage.getAiGeneratedRule(ruleId);
        if (!rule || rule.orgId !== orgId) {
          return res.status(404).json({ message: "Rule not found" });
        }

        const allowedFields = ["status", "reviewedBy", "reviewedAt"] as const;
        const allowedStatuses = new Set(["draft", "review", "accepted", "rejected"]);
        const update: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            update[field] = req.body[field];
          }
        }

        if (update.status && !allowedStatuses.has(update.status as string)) {
          return res.status(400).json({ message: "Invalid status. Must be one of: draft, review, accepted, rejected" });
        }

        if (Object.keys(update).length === 0) {
          return res.status(400).json({ message: "No valid fields to update" });
        }

        const updated = await storage.updateAiGeneratedRule(ruleId, update);
        res.json(updated);
      } catch (error: any) {
        logger.child("ai").error("Update AI-generated rule error", { error: String(error) });
        res.status(500).json({ message: "Failed to update rule." });
      }
    },
  );
}
