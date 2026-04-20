import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole, requireOrgId } from "../../rbac";
import {
  checkModelHealth,
  getModelConfig,
  getInferenceMetrics,
  getInferenceHistory,
  getInferenceStats,
  clearModelCache,
  getAiOrgUsage,
  getAllAiOrgUsage,
  setAiOrgBudget,
  getPromptCatalogSummary,
} from "../../ai";
import { getCircuitBreakerStatus } from "../../ai/model-gateway";
import { config as appConfig } from "../../config";
import { pool } from "../../db";
import { invokeModel as gatewayInvoke } from "../../ai/model-gateway";
import { getAllRegisteredPrompts, getPromptVersion } from "../../ai";

const log = logger.child("routes-ai-setup");

export function registerAiSetupRoutes(app: Express): void {
  // --- GET /api/ai/setup-status --- first-run setup health checklist ---
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

  // --- GET /api/ai/circuit-alerts --- recent AI service failure alerts ---
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

  // --- PATCH /api/ai/circuit-alerts/:alertId/dismiss --- dismiss a circuit breaker alert ---
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

  // AI Engine - Health
  app.get("/api/ai/health", isAuthenticated, strictLimiter, async (_req, res) => {
    try {
      const health = await checkModelHealth();
      res.json(health);
    } catch (error: unknown) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ status: "error", message: "An internal error occurred. Please try again." });
    }
  });

  app.get("/api/ai/config", isAuthenticated, async (_req, res) => {
    res.json(await getModelConfig());
  });

  app.get("/api/ai/inference-metrics", isAuthenticated, strictLimiter, async (req, res) => {
    res.json(await getInferenceMetrics());
  });

  // --- GET /api/ai/inference-history --- persistent inference log with filters ---
  app.get(
    "/api/ai/inference-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
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

  // --- GET /api/ai/inference-stats --- aggregated daily + per-tier stats ---
  app.get(
    "/api/ai/inference-stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
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

  // --- POST /api/ai/test-prompt --- dry-run a prompt with sample input ---
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

  // --- POST /api/ai/cache/clear ---
  app.post("/api/ai/cache/clear", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (_req, res) => {
    try {
      clearModelCache();
      res.json({ cleared: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to clear model cache" });
    }
  });

  // --- Budget routes ---
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

  // --- 36.1: Budget Burn-Down Chart ---
  app.get(
    "/api/ai/budget/burn-down",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const usage = await getAiOrgUsage(orgId);
        const now = new Date();
        const dayOfMonth = now.getDate();
        const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
        const totalSpent = (usage as any).dailySpendUsd ?? 0;
        const monthlyLimit = (usage as any).budgetLimitUsd ?? (usage as any).budgetUsd ?? 100;
        const remaining = Math.max(monthlyLimit - totalSpent * dayOfMonth, 0);
        const dailyAvgSpend = dayOfMonth > 0 ? (totalSpent * dayOfMonth) / dayOfMonth : 0;
        const daysRemaining = daysInMonth - dayOfMonth;
        const projectedTotal = totalSpent * dayOfMonth + dailyAvgSpend * daysRemaining;
        const exhaustionDay = dailyAvgSpend > 0 ? Math.ceil(remaining / dailyAvgSpend) : null;
        const exhaustionDate =
          exhaustionDay !== null && exhaustionDay <= daysRemaining
            ? new Date(now.getTime() + exhaustionDay * 86400000).toISOString()
            : null;

        // Generate daily data points for the chart
        const dailyPoints: { day: number; consumed: number; remaining: number; projected: number }[] = [];
        for (let d = 1; d <= daysInMonth; d++) {
          const consumed = d <= dayOfMonth ? dailyAvgSpend * d : dailyAvgSpend * dayOfMonth;
          const proj = dailyAvgSpend * d;
          dailyPoints.push({
            day: d,
            consumed: parseFloat(consumed.toFixed(2)),
            remaining: parseFloat(Math.max(monthlyLimit - consumed, 0).toFixed(2)),
            projected: parseFloat(Math.min(proj, monthlyLimit).toFixed(2)),
          });
        }

        res.json({
          monthlyLimit,
          totalSpent: parseFloat((totalSpent * dayOfMonth).toFixed(2)),
          remaining: parseFloat(remaining.toFixed(2)),
          dailyAvgSpend: parseFloat(dailyAvgSpend.toFixed(2)),
          projectedTotal: parseFloat(projectedTotal.toFixed(2)),
          exhaustionDate,
          exhaustionDay,
          daysRemaining,
          dailyPoints,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch budget burn-down data" });
      }
    },
  );

  // --- 36.2: Budget Alert Thresholds ---
  app.get(
    "/api/ai/budget/thresholds",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rows = await pool.query(
          `SELECT budget_usd, invocation_cap, daily_spend_usd, daily_invocations
           FROM org_ai_budgets WHERE org_id = $1 LIMIT 1`,
          [orgId],
        );
        const budget = rows.rows[0] as
          | { budget_usd: number; invocation_cap: number; daily_spend_usd: number; daily_invocations: number }
          | undefined;
        const monthlyLimit = budget?.budget_usd ?? 100;
        const dayOfMonth = new Date().getDate();
        const currentSpend = (budget?.daily_spend_usd ?? 0) * dayOfMonth;
        const pct = monthlyLimit > 0 ? (currentSpend / monthlyLimit) * 100 : 0;

        const thresholds = [
          { level: 50, label: "50% consumed", breached: pct >= 50, currentPct: parseFloat(pct.toFixed(1)) },
          { level: 75, label: "75% consumed", breached: pct >= 75, currentPct: parseFloat(pct.toFixed(1)) },
          { level: 90, label: "90% consumed", breached: pct >= 90, currentPct: parseFloat(pct.toFixed(1)) },
          { level: 100, label: "Budget exhausted", breached: pct >= 100, currentPct: parseFloat(pct.toFixed(1)) },
        ];

        res.json({
          thresholds,
          currentPct: parseFloat(pct.toFixed(1)),
          monthlyLimit,
          currentSpend: parseFloat(currentSpend.toFixed(2)),
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch budget thresholds" });
      }
    },
  );

  // --- 36.3: Budget Allocation by Use Case ---
  app.get(
    "/api/ai/budget/allocation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const usage = await getAiOrgUsage(orgId);
        const monthlyLimit = (usage as any).budgetLimitUsd ?? (usage as any).budgetUsd ?? 100;

        const allocations = [
          {
            useCase: "Alert Triage",
            allocatedPct: 40,
            allocatedUsd: parseFloat((monthlyLimit * 0.4).toFixed(2)),
            actualUsd: 0,
            actualPct: 0,
          },
          {
            useCase: "Investigations",
            allocatedPct: 30,
            allocatedUsd: parseFloat((monthlyLimit * 0.3).toFixed(2)),
            actualUsd: 0,
            actualPct: 0,
          },
          {
            useCase: "Report Generation",
            allocatedPct: 20,
            allocatedUsd: parseFloat((monthlyLimit * 0.2).toFixed(2)),
            actualUsd: 0,
            actualPct: 0,
          },
          {
            useCase: "Other",
            allocatedPct: 10,
            allocatedUsd: parseFloat((monthlyLimit * 0.1).toFixed(2)),
            actualUsd: 0,
            actualPct: 0,
          },
        ];

        try {
          const historyResult = await pool.query(
            `SELECT prompt_id, COUNT(*) as cnt FROM ai_inference_logs WHERE org_id = $1 AND created_at >= date_trunc('month', CURRENT_DATE) GROUP BY prompt_id`,
            [orgId],
          );
          const totalCalls = historyResult.rows.reduce((s: number, r: any) => s + parseInt(r.cnt, 10), 0);
          if (totalCalls > 0) {
            const dayOfMonth = new Date().getDate();
            const totalSpend = (usage as any).dailySpendUsd ? (usage as any).dailySpendUsd * dayOfMonth : 0;
            for (const row of historyResult.rows) {
              const pid = (row as any).prompt_id as string;
              const cnt = parseInt((row as any).cnt, 10);
              const fraction = cnt / totalCalls;
              const cost = totalSpend * fraction;
              if (pid.includes("triage")) {
                allocations[0].actualUsd += cost;
                allocations[0].actualPct += fraction * 100;
              } else if (pid.includes("investigation") || pid.includes("narrative") || pid.includes("deep")) {
                allocations[1].actualUsd += cost;
                allocations[1].actualPct += fraction * 100;
              } else if (pid.includes("report") || pid.includes("rule")) {
                allocations[2].actualUsd += cost;
                allocations[2].actualPct += fraction * 100;
              } else {
                allocations[3].actualUsd += cost;
                allocations[3].actualPct += fraction * 100;
              }
            }
            for (const a of allocations) {
              a.actualUsd = parseFloat(a.actualUsd.toFixed(2));
              a.actualPct = parseFloat(a.actualPct.toFixed(1));
            }
          }
        } catch {
          /* inference logs table may not exist */
        }

        res.json({ monthlyLimit, allocations });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch budget allocation" });
      }
    },
  );

  // --- 36.4: Cost per Investigation/Action Breakdown ---
  app.get(
    "/api/ai/budget/cost-breakdown",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const usage = await getAiOrgUsage(orgId);
        const dailySpend = (usage as any).dailySpendUsd ?? 0;
        const dailyInvocations = (usage as any).dailyInvocations ?? 0;
        const avgCostPerInvocation = dailyInvocations > 0 ? dailySpend / dailyInvocations : 0;

        const operations = [
          {
            operation: "Alert Triage",
            avgCost: parseFloat((avgCostPerInvocation * 0.8).toFixed(4)),
            avgTokens: 1200,
            estimatedMonthlyCount: Math.round(dailyInvocations * 30 * 0.4),
            estimatedMonthlyCost: parseFloat((dailySpend * 30 * 0.4).toFixed(2)),
          },
          {
            operation: "Incident Investigation",
            avgCost: parseFloat((avgCostPerInvocation * 3.5).toFixed(4)),
            avgTokens: 4500,
            estimatedMonthlyCount: Math.round(dailyInvocations * 30 * 0.15),
            estimatedMonthlyCost: parseFloat((dailySpend * 30 * 0.25).toFixed(2)),
          },
          {
            operation: "Rule Generation",
            avgCost: parseFloat((avgCostPerInvocation * 2.0).toFixed(4)),
            avgTokens: 2800,
            estimatedMonthlyCount: Math.round(dailyInvocations * 30 * 0.1),
            estimatedMonthlyCost: parseFloat((dailySpend * 30 * 0.15).toFixed(2)),
          },
          {
            operation: "Narrative Generation",
            avgCost: parseFloat((avgCostPerInvocation * 2.5).toFixed(4)),
            avgTokens: 3200,
            estimatedMonthlyCount: Math.round(dailyInvocations * 30 * 0.1),
            estimatedMonthlyCost: parseFloat((dailySpend * 30 * 0.1).toFixed(2)),
          },
          {
            operation: "Threat Correlation",
            avgCost: parseFloat((avgCostPerInvocation * 1.5).toFixed(4)),
            avgTokens: 2000,
            estimatedMonthlyCount: Math.round(dailyInvocations * 30 * 0.15),
            estimatedMonthlyCost: parseFloat((dailySpend * 30 * 0.1).toFixed(2)),
          },
        ];

        res.json({
          avgCostPerInvocation: parseFloat(avgCostPerInvocation.toFixed(4)),
          dailySpend: parseFloat(dailySpend.toFixed(2)),
          dailyInvocations,
          operations,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch cost breakdown" });
      }
    },
  );

  // --- 36.5: Hard Budget Enforcement Status ---
  app.get(
    "/api/ai/budget/enforcement",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rows = await pool.query(
          `SELECT budget_usd, invocation_cap, daily_spend_usd, daily_invocations
           FROM org_ai_budgets WHERE org_id = $1 LIMIT 1`,
          [orgId],
        );
        const budget = rows.rows[0] as
          | { budget_usd: number; invocation_cap: number; daily_spend_usd: number; daily_invocations: number }
          | undefined;
        const monthlyLimit = budget?.budget_usd ?? 100;
        const dayOfMonth = new Date().getDate();
        const currentSpend = (budget?.daily_spend_usd ?? 0) * dayOfMonth;
        const pct = monthlyLimit > 0 ? (currentSpend / monthlyLimit) * 100 : 0;
        const invocationPct = budget ? ((budget.daily_invocations ?? 0) / (budget.invocation_cap ?? 5000)) * 100 : 0;

        let enforcementLevel: string;
        let actions: string[];
        if (pct >= 100 || invocationPct >= 100) {
          enforcementLevel = "hard_limit";
          actions = [
            "Non-critical AI features disabled",
            "Switched to cheaper models (e.g., claude-3-haiku)",
            "Requests queued for next billing cycle",
            "Only critical alert triage allowed",
          ];
        } else if (pct >= 90 || invocationPct >= 90) {
          enforcementLevel = "degraded";
          actions = [
            "Switched to cheaper models for non-critical tasks",
            "Batch processing enabled to reduce costs",
            "Report generation paused",
          ];
        } else if (pct >= 75 || invocationPct >= 75) {
          enforcementLevel = "warning";
          actions = ["Admin notifications sent", "Budget approaching limit — consider increasing"];
        } else {
          enforcementLevel = "normal";
          actions = ["All AI features operating normally"];
        }

        res.json({
          enforcementLevel,
          actions,
          budgetPct: parseFloat(pct.toFixed(1)),
          invocationPct: parseFloat(invocationPct.toFixed(1)),
          monthlyLimit,
          currentSpend: parseFloat(currentSpend.toFixed(2)),
          invocationCap: budget?.invocation_cap ?? 5000,
          currentInvocations: budget?.daily_invocations ?? 0,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch enforcement status" });
      }
    },
  );

  // --- 36.6: Budget Rollover and Adjustment ---
  app.post(
    "/api/ai/budget/rollover",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { newLimit, rolloverUnused } = req.body;

        const rows = await pool.query(
          `SELECT budget_usd, daily_spend_usd FROM org_ai_budgets WHERE org_id = $1 LIMIT 1`,
          [orgId],
        );
        const budget = rows.rows[0] as { budget_usd: number; daily_spend_usd: number } | undefined;
        const currentLimit = budget?.budget_usd ?? 100;
        const dayOfMonth = new Date().getDate();
        const currentSpend = (budget?.daily_spend_usd ?? 0) * dayOfMonth;
        const unused = Math.max(currentLimit - currentSpend, 0);

        let finalLimit = typeof newLimit === "number" && newLimit > 0 ? newLimit : currentLimit;
        if (rolloverUnused === true) {
          finalLimit += unused;
        }

        await pool.query(`UPDATE org_ai_budgets SET budget_usd = $1, updated_at = NOW() WHERE org_id = $2`, [
          finalLimit,
          orgId,
        ]);

        await storage.createAuditLog({
          orgId,
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Admin",
          action: "ai_budget_adjusted",
          resourceType: "ai_budget",
          resourceId: orgId,
          details: {
            previousLimit: currentLimit,
            newLimit: finalLimit,
            rolloverAmount: rolloverUnused ? unused : 0,
            midMonthAdjustment: dayOfMonth > 1,
          },
        });

        res.json({
          previousLimit: currentLimit,
          newLimit: finalLimit,
          rolloverAmount: rolloverUnused ? parseFloat(unused.toFixed(2)) : 0,
          currentSpend: parseFloat(currentSpend.toFixed(2)),
          auditLogged: true,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to adjust budget" });
      }
    },
  );
}
