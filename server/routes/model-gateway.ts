import type { Express } from "express";
import { z } from "zod";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import {
  getGatewayDashboardData,
  getCircuitBreakerStatus,
  getModelCacheStats,
  clearModelCache,
  resetGatewayMetrics,
} from "../ai/model-gateway";
import { getOrgUsageSummary, getAllOrgUsageSummaries } from "../ai/budget";
import { getPromptCatalogSummary, getAllPrompts } from "../ai/prompt-registry";

const log = logger.child("model-gateway-routes");

export function registerModelGatewayRoutes(app: Express): void {
  const authChain = [isAuthenticated, resolveOrgContext, requireOrgId];
  const adminChain = [...authChain, requireMinRole("admin")];

  app.get("/api/model-gateway/dashboard", ...authChain, async (_req, res) => {
    try {
      const dashboard = getGatewayDashboardData();
      const promptCatalog = await getPromptCatalogSummary();
      const allUsage = await getAllOrgUsageSummaries();

      let totalCostUsd = 0;
      let totalInvocations = 0;
      let totalInputTokens = 0;
      let totalOutputTokens = 0;
      let unknownCostInvocations = 0;
      for (const summary of allUsage) {
        totalCostUsd += summary.totalCostUsd;
        totalInvocations += summary.invocationCount;
        totalInputTokens += summary.totalInputTokens;
        totalOutputTokens += summary.totalOutputTokens;
        unknownCostInvocations += summary.unknownCostCount;
      }

      res.json({
        gateway: dashboard,
        promptCatalog,
        aggregateUsage: {
          totalCostUsd: Math.round(totalCostUsd * 1000000) / 1000000,
          totalInvocations,
          totalInputTokens,
          totalOutputTokens,
          unknownCostInvocations,
          orgCount: allUsage.length,
        },
      });
    } catch (error) {
      log.error("Failed to fetch gateway dashboard", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch gateway dashboard data" });
    }
  });

  app.get("/api/model-gateway/circuit-breakers", ...authChain, async (_req, res) => {
    try {
      res.json(getCircuitBreakerStatus());
    } catch (error) {
      log.error("Failed to fetch circuit breaker status", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch circuit breaker status" });
    }
  });

  app.get("/api/model-gateway/cache", ...authChain, async (_req, res) => {
    try {
      res.json(getModelCacheStats());
    } catch (error) {
      log.error("Failed to fetch cache stats", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch cache stats" });
    }
  });

  app.get("/api/model-gateway/prompts", ...authChain, async (_req, res) => {
    try {
      const prompts = await getAllPrompts();
      res.json(prompts);
    } catch (error) {
      log.error("Failed to fetch prompts", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch prompts" });
    }
  });

  app.get("/api/model-gateway/usage", ...authChain, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      if (orgId) {
        res.json(await getOrgUsageSummary(orgId));
      } else {
        res.json(await getAllOrgUsageSummaries());
      }
    } catch (error) {
      log.error("Failed to fetch usage data", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch usage data" });
    }
  });

  app.post("/api/model-gateway/cache/clear", ...adminChain, async (_req, res) => {
    try {
      clearModelCache();
      log.info("Model cache cleared by admin");
      res.json({ message: "Cache cleared successfully" });
    } catch (error) {
      log.error("Failed to clear cache", { error: String(error) });
      res.status(500).json({ message: "Failed to clear cache" });
    }
  });

  app.post("/api/model-gateway/metrics/reset", ...adminChain, async (_req, res) => {
    try {
      resetGatewayMetrics();
      log.info("Gateway metrics reset by admin");
      res.json({ message: "Metrics reset successfully" });
    } catch (error) {
      log.error("Failed to reset metrics", { error: String(error) });
      res.status(500).json({ message: "Failed to reset metrics" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 33.4 Model Health Monitoring with Auto-Failover
  // ═══════════════════════════════════════════════════════════════════════════

  interface ModelHealthStatus {
    modelId: string;
    backend: string;
    status: "healthy" | "degraded" | "unhealthy" | "unknown";
    latencyP50Ms: number;
    latencyP95Ms: number;
    errorRate: number;
    throughputRpm: number;
    lastChecked: string;
    circuitBreakerOpen: boolean;
    failoverTarget: string | null;
  }

  const failoverConfig = new Map<string, string>([
    ["amazon.nova-pro-v1:0", "amazon.nova-lite-v1:0"],
    ["amazon.nova-lite-v1:0", "mistral.mistral-large-2402-v1:0"],
    ["mistral.mistral-large-2402-v1:0", "amazon.nova-lite-v1:0"],
    ["anthropic.claude-3-5-sonnet-20241022-v2:0", "amazon.nova-pro-v1:0"],
    ["anthropic.claude-3-haiku-20240307-v1:0", "amazon.nova-lite-v1:0"],
  ]);

  app.get("/api/model-gateway/health", ...authChain, async (_req, res) => {
    try {
      const dashboard = getGatewayDashboardData();
      const cbStatus = getCircuitBreakerStatus();
      const healthStatuses: ModelHealthStatus[] = [];

      for (const [modelId, stats] of Object.entries(dashboard.modelStats)) {
        const latencies = dashboard.latencyHistory
          .filter((l) => l.modelId === modelId)
          .map((l) => l.latencyMs)
          .sort((a, b) => a - b);

        const p50 = latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.5)] : 0;
        const p95 = latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.95)] : 0;

        // Determine health status based on error rate and latency
        let status: "healthy" | "degraded" | "unhealthy" | "unknown" = "unknown";
        if (stats.requests > 0) {
          if (stats.errorRate > 20) status = "unhealthy";
          else if (stats.errorRate > 5 || p95 > 10000) status = "degraded";
          else status = "healthy";
        }

        // Check circuit breaker
        const cbKey = Object.keys(cbStatus).find((k) => k.includes(modelId));
        const isOpen = cbKey ? cbStatus[cbKey].isOpen : false;
        if (isOpen) status = "unhealthy";

        healthStatuses.push({
          modelId,
          backend: "bedrock",
          status,
          latencyP50Ms: p50,
          latencyP95Ms: p95,
          errorRate: stats.errorRate,
          throughputRpm: stats.requests > 0 ? Math.round(stats.requests / (dashboard.uptime / 60000)) : 0,
          lastChecked: new Date().toISOString(),
          circuitBreakerOpen: isOpen,
          failoverTarget: failoverConfig.get(modelId) || null,
        });
      }

      // Add models from failover config that don't have stats yet
      for (const [modelId, target] of Array.from(failoverConfig.entries())) {
        if (!healthStatuses.find((h) => h.modelId === modelId)) {
          healthStatuses.push({
            modelId,
            backend: "bedrock",
            status: "unknown",
            latencyP50Ms: 0,
            latencyP95Ms: 0,
            errorRate: 0,
            throughputRpm: 0,
            lastChecked: new Date().toISOString(),
            circuitBreakerOpen: false,
            failoverTarget: target,
          });
        }
      }

      res.json({ models: healthStatuses, failoverConfig: Object.fromEntries(failoverConfig) });
    } catch (error) {
      log.error("Failed to fetch model health", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch model health data" });
    }
  });

  const updateFailoverSchema = z.object({
    modelId: z.string().min(1),
    failoverTarget: z.string().min(1),
  });

  app.put("/api/model-gateway/failover", ...adminChain, async (req, res) => {
    try {
      const parsed = updateFailoverSchema.safeParse(req.body);
      if (!parsed.success)
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
      failoverConfig.set(parsed.data.modelId, parsed.data.failoverTarget);
      log.info("Failover config updated", { modelId: parsed.data.modelId, target: parsed.data.failoverTarget });
      res.json({ modelId: parsed.data.modelId, failoverTarget: parsed.data.failoverTarget });
    } catch (error) {
      log.error("Failed to update failover config", { error: String(error) });
      res.status(500).json({ message: "Failed to update failover configuration" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 33.5 Token Usage Tracking Per Request
  // ═══════════════════════════════════════════════════════════════════════════

  interface TokenUsageRecord {
    id: string;
    timestamp: string;
    modelId: string;
    promptId: string | null;
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
    costUsd: number;
    latencyMs: number;
    orgId: string | null;
    useCase: string;
  }

  const tokenUsageLog: TokenUsageRecord[] = [];
  const MAX_TOKEN_USAGE_LOG = 1000;

  app.get("/api/model-gateway/token-usage", ...authChain, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const modelId = typeof req.query.modelId === "string" ? req.query.modelId : null;
      const useCase = typeof req.query.useCase === "string" ? req.query.useCase : null;
      const limit = Math.min(parseInt(String(req.query.limit || "100"), 10), 500);

      let filtered = orgId ? tokenUsageLog.filter((r) => r.orgId === orgId) : [...tokenUsageLog];
      if (modelId) filtered = filtered.filter((r) => r.modelId === modelId);
      if (useCase) filtered = filtered.filter((r) => r.useCase === useCase);

      const recent = filtered.slice(-limit);

      // Aggregate stats
      const totalInput = recent.reduce((sum, r) => sum + r.inputTokens, 0);
      const totalOutput = recent.reduce((sum, r) => sum + r.outputTokens, 0);
      const totalCost = recent.reduce((sum, r) => sum + r.costUsd, 0);
      const avgLatency = recent.length > 0 ? recent.reduce((sum, r) => sum + r.latencyMs, 0) / recent.length : 0;

      // Per-model breakdown
      const byModel: Record<string, { inputTokens: number; outputTokens: number; costUsd: number; requests: number }> =
        {};
      for (const record of recent) {
        if (!byModel[record.modelId])
          byModel[record.modelId] = { inputTokens: 0, outputTokens: 0, costUsd: 0, requests: 0 };
        byModel[record.modelId].inputTokens += record.inputTokens;
        byModel[record.modelId].outputTokens += record.outputTokens;
        byModel[record.modelId].costUsd += record.costUsd;
        byModel[record.modelId].requests++;
      }

      // Per-use-case breakdown
      const byUseCase: Record<
        string,
        { inputTokens: number; outputTokens: number; costUsd: number; requests: number }
      > = {};
      for (const record of recent) {
        const uc = record.useCase || "unknown";
        if (!byUseCase[uc]) byUseCase[uc] = { inputTokens: 0, outputTokens: 0, costUsd: 0, requests: 0 };
        byUseCase[uc].inputTokens += record.inputTokens;
        byUseCase[uc].outputTokens += record.outputTokens;
        byUseCase[uc].costUsd += record.costUsd;
        byUseCase[uc].requests++;
      }

      res.json({
        records: recent.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()),
        summary: {
          totalInputTokens: totalInput,
          totalOutputTokens: totalOutput,
          totalTokens: totalInput + totalOutput,
          totalCostUsd: Math.round(totalCost * 1000000) / 1000000,
          avgLatencyMs: Math.round(avgLatency),
          requestCount: recent.length,
        },
        byModel,
        byUseCase,
      });
    } catch (error) {
      log.error("Failed to fetch token usage", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch token usage data" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 33.6 Model Version Management
  // ═══════════════════════════════════════════════════════════════════════════

  app.get("/api/model-gateway/versions", ...authChain, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const usage = await getOrgUsageSummary(orgId);
      res.json({
        versions: [],
        configuredModelId: process.env.AI_MODEL_ID || null,
        usage: usage
          ? {
              invocationCount: usage.invocationCount,
              totalInputTokens: usage.totalInputTokens,
              totalOutputTokens: usage.totalOutputTokens,
              totalCostUsd: usage.totalCostUsd,
            }
          : null,
        available: Boolean(process.env.AI_MODEL_ID),
        reason: process.env.AI_MODEL_ID
          ? null
          : "No model is configured. Configure an AI model and usage accounting to report model telemetry.",
      });
    } catch (error) {
      log.error("Failed to fetch model versions", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch model versions" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 33.3 Cost Forecasting Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  app.get("/api/model-gateway/cost-forecast", ...authChain, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const usage = orgId ? await getOrgUsageSummary(orgId) : null;

      const dashboard = getGatewayDashboardData();
      const uptimeDays = dashboard.uptime / 86400000;
      const dailyRate = uptimeDays > 0 ? (usage?.totalCostUsd || 0) / uptimeDays : 0;

      const forecast = {
        currentPeriod: {
          totalCostUsd: usage?.totalCostUsd || 0,
          totalInvocations: usage?.invocationCount || 0,
          totalInputTokens: usage?.totalInputTokens || 0,
          totalOutputTokens: usage?.totalOutputTokens || 0,
          unknownCostInvocations: usage?.unknownCostCount || 0,
          daysElapsed: Math.round(uptimeDays * 10) / 10,
        },
        projections: {
          daily: Math.round(dailyRate * 1000000) / 1000000,
          weekly: Math.round(dailyRate * 7 * 1000000) / 1000000,
          monthly: Math.round(dailyRate * 30 * 1000000) / 1000000,
          quarterly: Math.round(dailyRate * 90 * 1000000) / 1000000,
        },
        byModel: Object.entries(dashboard.modelStats).map(([modelId, stats]) => {
          const modelCostTable = dashboard.config.costTable[modelId] || dashboard.config.costTable["default"];
          const estimatedCostPerReq = modelCostTable
            ? modelCostTable.input * 500 + modelCostTable.output * 200 // Estimated avg tokens
            : null;
          return {
            modelId,
            requests: stats.requests,
            estimatedCostPerRequest:
              estimatedCostPerReq === null ? null : Math.round(estimatedCostPerReq * 1000000) / 1000000,
            projectedMonthlyCost:
              estimatedCostPerReq !== null && uptimeDays > 0
                ? Math.round((stats.requests / uptimeDays) * 30 * estimatedCostPerReq * 100) / 100
                : null,
          };
        }),
        budgetStatus: {
          budgetUsd: usage?.budgetLimitUsd || null,
          usedUsd: usage?.totalCostUsd || 0,
          unknownCostInvocations: usage?.unknownCostCount || 0,
          remainingUsd: usage?.budgetLimitUsd ? usage.budgetLimitUsd - (usage?.totalCostUsd || 0) : null,
          percentUsed: usage?.budgetLimitUsd
            ? Math.round(((usage?.totalCostUsd || 0) / usage.budgetLimitUsd) * 100)
            : null,
          projectedExceedDate: null as string | null,
        },
      };

      // Project when budget will be exceeded
      if (forecast.budgetStatus.remainingUsd !== null && dailyRate > 0) {
        const daysRemaining = forecast.budgetStatus.remainingUsd / dailyRate;
        if (daysRemaining > 0 && daysRemaining < 365) {
          const exceedDate = new Date(Date.now() + daysRemaining * 86400000);
          forecast.budgetStatus.projectedExceedDate = exceedDate.toISOString().split("T")[0];
        }
      }

      res.json(forecast);
    } catch (error) {
      log.error("Failed to generate cost forecast", { error: String(error) });
      res.status(500).json({ message: "Failed to generate cost forecast" });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 33.1 & 33.2 Model Comparison Data + Routing Rules
  // ═══════════════════════════════════════════════════════════════════════════

  interface RoutingRule {
    id: string;
    name: string;
    useCase: string;
    modelId: string;
    priority: number;
    conditions: { field: string; operator: string; value: string }[];
    enabled: boolean;
  }

  const routingRules: RoutingRule[] = [
    {
      id: "rr-1",
      name: "Triage → Nova Lite",
      useCase: "triage",
      modelId: "amazon.nova-lite-v1:0",
      priority: 1,
      conditions: [{ field: "tier", operator: "eq", value: "triage" }],
      enabled: true,
    },
    {
      id: "rr-2",
      name: "Deep Investigation → Nova Pro",
      useCase: "deep_investigation",
      modelId: "amazon.nova-pro-v1:0",
      priority: 1,
      conditions: [{ field: "tier", operator: "eq", value: "deep-investigation" }],
      enabled: true,
    },
    {
      id: "rr-3",
      name: "Narrative → Nova Pro",
      useCase: "narrative",
      modelId: "amazon.nova-pro-v1:0",
      priority: 1,
      conditions: [{ field: "tier", operator: "eq", value: "narrative" }],
      enabled: true,
    },
    {
      id: "rr-4",
      name: "Auto-Response → Nova Lite",
      useCase: "auto_response",
      modelId: "amazon.nova-lite-v1:0",
      priority: 1,
      conditions: [{ field: "tier", operator: "eq", value: "auto-response" }],
      enabled: true,
    },
    {
      id: "rr-5",
      name: "Detection Rule Gen → Nova Pro",
      useCase: "detection_rule",
      modelId: "amazon.nova-pro-v1:0",
      priority: 1,
      conditions: [{ field: "tier", operator: "eq", value: "detection-rule" }],
      enabled: true,
    },
  ];

  app.get("/api/model-gateway/routing-rules", ...authChain, async (_req, res) => {
    try {
      res.json(routingRules);
    } catch (error) {
      log.error("Failed to fetch routing rules", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch routing rules" });
    }
  });

  const updateRuleSchema = z.object({
    id: z.string().min(1),
    modelId: z.string().min(1).optional(),
    enabled: z.boolean().optional(),
    priority: z.number().min(0).max(100).optional(),
  });

  app.put("/api/model-gateway/routing-rules", ...adminChain, async (req, res) => {
    try {
      const parsed = updateRuleSchema.safeParse(req.body);
      if (!parsed.success)
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
      const rule = routingRules.find((r) => r.id === parsed.data.id);
      if (!rule) return res.status(404).json({ message: "Routing rule not found" });
      if (parsed.data.modelId !== undefined) rule.modelId = parsed.data.modelId;
      if (parsed.data.enabled !== undefined) rule.enabled = parsed.data.enabled;
      if (parsed.data.priority !== undefined) rule.priority = parsed.data.priority;
      log.info("Routing rule updated", { ruleId: rule.id, name: rule.name });
      res.json(rule);
    } catch (error) {
      log.error("Failed to update routing rule", { error: String(error) });
      res.status(500).json({ message: "Failed to update routing rule" });
    }
  });

  app.get("/api/model-gateway/comparison", ...authChain, async (_req, res) => {
    try {
      const dashboard = getGatewayDashboardData();
      const comparison = Object.entries(dashboard.modelStats).map(([modelId, stats]) => {
        const costInfo = dashboard.config.costTable[modelId] || dashboard.config.costTable["default"];
        const latencies = dashboard.latencyHistory
          .filter((l) => l.modelId === modelId)
          .map((l) => l.latencyMs)
          .sort((a, b) => a - b);

        return {
          modelId,
          requests: stats.requests,
          errors: stats.errors,
          errorRate: stats.errorRate,
          avgLatencyMs: stats.avgLatencyMs,
          p50LatencyMs: latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.5)] : 0,
          p95LatencyMs: latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.95)] : 0,
          p99LatencyMs: latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.99)] : 0,
          cacheHits: stats.cacheHits,
          costPerInputToken: costInfo?.input ?? null,
          costPerOutputToken: costInfo?.output ?? null,
          estimatedCostPerRequest: costInfo ? costInfo.input * 500 + costInfo.output * 200 : null,
        };
      });
      res.json(comparison);
    } catch (error) {
      log.error("Failed to generate model comparison", { error: String(error) });
      res.status(500).json({ message: "Failed to generate comparison data" });
    }
  });
}
