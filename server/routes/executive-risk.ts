import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { logger, getOrgId, sendEnvelope, storage as coreStorage } from "./shared";
import * as storage from "../storage/executive-risk";
import { z } from "zod";

const log = logger.child("executive-risk");

const VALID_PERIODS = ["weekly", "monthly", "quarterly"] as const;
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
        const [summaries, metrics] = await Promise.all([
          storage.getBoardSummaries(orgId),
          storage.getExecutiveMetrics(orgId),
        ]);
        const actionMetrics = metrics.filter((m) => m.category === "action");
        const vanityMetrics = metrics.filter((m) => m.category === "vanity");
        return sendEnvelope(res, {
          summaries,
          actionMetrics,
          vanityMetrics,
          totalSummaries: summaries.length,
          totalMetrics: metrics.length,
        });
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
        const orgId = getOrgId(req);
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
          ? await storage.getExecutiveMetricsByCategory(orgId, category)
          : await storage.getExecutiveMetrics(orgId);
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

  app.post(
    "/api/executive-risk/metrics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { name, description, category, value, unit, trend, target } = req.body;
        if (!name || typeof name !== "string") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "VALIDATION_ERROR", message: "name is required" }],
          });
        }
        const metric = await storage.createExecutiveMetric({
          orgId,
          name,
          description: description || null,
          category: category || "action",
          value: value ?? 0,
          unit: unit || "count",
          trend: trend || "stable",
          target: target ?? null,
        });
        return sendEnvelope(res, metric, { status: 201 });
      } catch (err) {
        log.error("Failed to create metric", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to create metric" }],
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
        const summaries = await storage.getBoardSummaries(orgId);
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
        const summaryId = String(req.params.id);
        const summary = await storage.getBoardSummary(summaryId);
        if (!summary || summary.orgId !== orgId) {
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
    "/api/executive-risk/summaries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = req.user as { id?: string } | undefined;
        const { title, period, executiveSynopsis, keyFindings, riskPosture, recommendations } = req.body;

        if (!title || typeof title !== "string") {
          return sendEnvelope(res, null, {
            status: 400,
            errors: [{ code: "VALIDATION_ERROR", message: "title is required" }],
          });
        }
        const validPeriod =
          typeof period === "string" && VALID_PERIODS.includes(period as (typeof VALID_PERIODS)[number])
            ? period
            : "monthly";

        const summary = await storage.createBoardSummary({
          orgId,
          title,
          period: validPeriod,
          executiveSynopsis: executiveSynopsis || null,
          keyFindings: keyFindings || [],
          riskPosture: riskPosture || {},
          recommendations: recommendations || [],
          generatedBy: user?.id || "unknown",
        });
        return sendEnvelope(res, summary, { status: 201 });
      } catch (err) {
        log.error("Failed to create board summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to create board summary" }],
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
      const parsed = z.object({ period: z.enum(VALID_PERIODS) }).safeParse(req.body);
      if (!parsed.success) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "VALIDATION_ERROR", message: "period must be weekly, monthly, or quarterly" }],
        });
      }
      const orgId = getOrgId(req);
      const user = req.user as { id?: string; username?: string } | undefined;
      const metrics = await storage.getExecutiveMetrics(orgId);
      const findings = metrics.map((metric) => ({
        metric: metric.name,
        value: metric.value,
        unit: metric.unit,
        trend: metric.trend,
      }));
      const summary = await storage.createBoardSummary({
        orgId,
        period: parsed.data.period,
        title: `${parsed.data.period[0].toUpperCase()}${parsed.data.period.slice(1)} Executive Risk Summary`,
        executiveSynopsis:
          metrics.length > 0
            ? `This summary contains ${metrics.length} persisted executive metrics for the organization.`
            : "No persisted executive metrics were available for this period.",
        keyFindings: findings,
        riskPosture: { source: "executive_metrics", metricCount: metrics.length },
        recommendations: [],
        generatedBy: user?.id || "unknown",
      });
      await coreStorage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "executive_risk_summary_generated",
        resourceType: "board_summary",
        resourceId: summary.id,
        details: { period: parsed.data.period, metricCount: metrics.length },
      });
      return sendEnvelope(res, summary, { status: 201 });
    },
  );

  app.delete(
    "/api/executive-risk/summaries/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summaryId = String(req.params.id);
        const summary = await storage.getBoardSummary(summaryId);
        if (!summary || summary.orgId !== orgId) {
          return sendEnvelope(res, null, {
            status: 404,
            errors: [{ code: "NOT_FOUND", message: "Board summary not found" }],
          });
        }
        await storage.deleteBoardSummary(summaryId);
        return sendEnvelope(res, { deleted: true });
      } catch (err) {
        log.error("Failed to delete board summary", { error: String(err) });
        return sendEnvelope(res, null, {
          status: 500,
          errors: [{ code: "INTERNAL_ERROR", message: "Failed to delete board summary" }],
        });
      }
    },
  );
}
