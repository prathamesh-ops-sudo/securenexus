import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  getExecutiveDashboard,
  getBoardSummaries,
  getBoardSummaryById,
  generateBoardSummary,
  getMetricsByCategory,
} from "../executive-risk-engine";
import type { SummaryPeriod } from "../executive-risk-engine";

const log = logger.child("executive-risk");

const VALID_PERIODS: SummaryPeriod[] = ["weekly", "monthly", "quarterly"];
const VALID_CATEGORIES = ["action", "vanity"] as const;

export function registerExecutiveRiskRoutes(app: Express): void {
  app.get(
    "/api/executive-risk/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const dashboard = getExecutiveDashboard(orgId);
        return sendEnvelope(res, dashboard);
      } catch (err) {
        log.error("Failed to get executive dashboard", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch executive risk dashboard" }],
        });
      }
    },
  );

  app.get(
    "/api/executive-risk/metrics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const category = typeof req.query.category === "string" ? req.query.category : undefined;
        if (category && !VALID_CATEGORIES.includes(category as (typeof VALID_CATEGORIES)[number])) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [
              { code: "VALIDATION_ERROR", message: `Invalid category. Must be one of: ${VALID_CATEGORIES.join(", ")}` },
            ],
          });
        }
        const metrics = category
          ? getMetricsByCategory(category as "action" | "vanity")
          : [...getMetricsByCategory("action"), ...getMetricsByCategory("vanity")];
        return sendEnvelope(res, metrics);
      } catch (err) {
        log.error("Failed to get metrics", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch metrics" }],
        });
      }
    },
  );

  app.get(
    "/api/executive-risk/summaries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summaries = getBoardSummaries(orgId);
        return sendEnvelope(res, summaries);
      } catch (err) {
        log.error("Failed to get board summaries", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch board summaries" }],
        });
      }
    },
  );

  app.get(
    "/api/executive-risk/summaries/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summaryId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const summary = getBoardSummaryById(orgId, summaryId);
        if (!summary) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Board summary not found" }],
          });
        }
        return sendEnvelope(res, summary);
      } catch (err) {
        log.error("Failed to get board summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to fetch board summary" }],
        });
      }
    },
  );

  app.post(
    "/api/executive-risk/summaries/generate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = req.user as { id?: string } | undefined;
        const period = typeof req.body.period === "string" ? req.body.period : "monthly";

        if (!VALID_PERIODS.includes(period as SummaryPeriod)) {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [
              { code: "VALIDATION_ERROR", message: `Invalid period. Must be one of: ${VALID_PERIODS.join(", ")}` },
            ],
          });
        }

        const summary = generateBoardSummary(orgId, period as SummaryPeriod, user?.id || "unknown");
        return sendEnvelope(res, summary, { status: 201 });
      } catch (err) {
        log.error("Failed to generate board summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to generate board summary" }],
        });
      }
    },
  );
}
