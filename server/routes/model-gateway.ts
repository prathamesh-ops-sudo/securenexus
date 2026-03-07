import type { Express } from "express";
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
      const promptCatalog = getPromptCatalogSummary();
      const allUsage = await getAllOrgUsageSummaries();

      let totalCostUsd = 0;
      let totalInvocations = 0;
      let totalInputTokens = 0;
      let totalOutputTokens = 0;
      for (const summary of allUsage) {
        totalCostUsd += summary.totalCostUsd;
        totalInvocations += summary.invocationCount;
        totalInputTokens += summary.totalInputTokens;
        totalOutputTokens += summary.totalOutputTokens;
      }

      res.json({
        gateway: dashboard,
        promptCatalog,
        aggregateUsage: {
          totalCostUsd: Math.round(totalCostUsd * 1000000) / 1000000,
          totalInvocations,
          totalInputTokens,
          totalOutputTokens,
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
      const prompts = getAllPrompts();
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
}
