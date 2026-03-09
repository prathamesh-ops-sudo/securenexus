import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  getAllPlanTiers,
  getCurrentPlanAndUsage,
  getUsageForecast,
  getUpgradeRecommendation,
  getBurstStatus,
  activateBurst,
} from "../tiered-packaging-engine";

const log = logger.child("tiered-packaging");

export function registerTieredPackagingRoutes(app: Express): void {
  app.get("/api/tiered-packaging/plans", isAuthenticated, async (_req: Request, res: Response) => {
    try {
      const plans = getAllPlanTiers();
      return sendEnvelope(res, plans);
    } catch (err) {
      log.error("Failed to fetch tiered plans", { error: String(err) });
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "PLANS_FETCH_FAILED", message: "Failed to fetch plan tiers" }],
      });
    }
  });

  app.get(
    "/api/tiered-packaging/current-plan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await getCurrentPlanAndUsage(orgId);
        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to fetch current plan", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "CURRENT_PLAN_FAILED", message: "Failed to fetch current plan and usage" }],
        });
      }
    },
  );

  app.get(
    "/api/tiered-packaging/usage-forecast",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const forecasts = await getUsageForecast(orgId);
        return sendEnvelope(res, forecasts);
      } catch (err) {
        log.error("Failed to generate usage forecast", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "FORECAST_FAILED", message: "Failed to generate usage forecast" }],
        });
      }
    },
  );

  app.get(
    "/api/tiered-packaging/upgrade-recommendation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const recommendation = await getUpgradeRecommendation(orgId);
        return sendEnvelope(res, recommendation);
      } catch (err) {
        log.error("Failed to generate upgrade recommendation", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "RECOMMENDATION_FAILED", message: "Failed to generate upgrade recommendation" }],
        });
      }
    },
  );

  app.get(
    "/api/tiered-packaging/burst-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const planData = await getCurrentPlanAndUsage(orgId);
        const status = getBurstStatus(orgId, planData.plan);
        return sendEnvelope(res, status);
      } catch (err) {
        log.error("Failed to fetch burst status", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "BURST_STATUS_FAILED", message: "Failed to fetch burst capacity status" }],
        });
      }
    },
  );

  app.post(
    "/api/tiered-packaging/burst-activate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { metric, extraCapacityPct, durationHours } = req.body;

        if (!metric || typeof metric !== "string") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "MISSING_FIELDS", message: "metric is required" }],
          });
        }
        if (typeof extraCapacityPct !== "number" || extraCapacityPct <= 0) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FIELD", message: "extraCapacityPct must be a positive number" }],
          });
        }
        if (typeof durationHours !== "number" || durationHours < 1 || durationHours > 72) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "INVALID_FIELD", message: "durationHours must be between 1 and 72" }],
          });
        }

        const planData = await getCurrentPlanAndUsage(orgId);
        const result = activateBurst(orgId, metric, extraCapacityPct, durationHours, planData.plan);

        if (!result.success) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "BURST_ACTIVATION_FAILED", message: result.error || "Failed to activate burst" }],
          });
        }

        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to activate burst", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "BURST_ACTIVATE_FAILED", message: "Failed to activate burst capacity" }],
        });
      }
    },
  );
}
