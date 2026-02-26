import type { Express, Request, Response } from "express";
import { getOrgId, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";

export function registerOnboardingRoutes(app: Express): void {
  // Onboarding status (v1) - summarizes whether key assets are configured for this org
  app.get("/api/v1/onboarding/status", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [integrations, ingestionStats, endpoints, cspmAccounts] = await Promise.all([
        storage.getIntegrationConfigs(orgId),
        storage.getIngestionStats(orgId),
        storage.getEndpointAssets(orgId),
        storage.getCspmAccounts(orgId),
      ]);

      const hasIntegrations = integrations.length > 0;
      const hasIngestion = (ingestionStats.totalIngested ?? 0) > 0;
      const hasEndpoints = endpoints.length > 0;
      const hasCspmAccounts = cspmAccounts.length > 0;

      const completedSteps = [
        hasIntegrations && "integrations",
        hasIngestion && "ingestion",
        hasEndpoints && "endpoints",
        hasCspmAccounts && "cspm",
      ].filter(Boolean);

      const status = {
        steps: {
          integrations: { completed: hasIntegrations, count: integrations.length },
          ingestion: { completed: hasIngestion, totalIngested: ingestionStats.totalIngested ?? 0 },
          endpoints: { completed: hasEndpoints, count: endpoints.length },
          cspm: { completed: hasCspmAccounts, count: cspmAccounts.length },
        },
        completedCount: completedSteps.length,
        totalSteps: 4,
      };

      return sendEnvelope(res, status);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "ONBOARDING_STATUS_FAILED",
            message: "Failed to fetch onboarding status",
            details: error?.message,
          },
        ],
      });
    }
  });

}
