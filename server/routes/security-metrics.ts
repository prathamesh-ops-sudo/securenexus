import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, gte, lte, count, asc } from "drizzle-orm";
import {
  securityKpiSnapshots,
  vulnerabilitySlaTargets,
  securityToolOverlaps,
  boardKpiConfigs,
  incidents,
  alerts,
  METRIC_KPI_TYPES,
  METRIC_PERIOD_TYPES,
  SLA_SEVERITY_TARGETS,
} from "../../shared/schema";
import {
  computeMttrMttd,
  computeSecurityRoi,
  computeSlaCompliance,
  computeCoverageHeatmap,
  computePeerBenchmarks,
  persistKpiSnapshot,
  computeBudgetOptimization,
  computeFalsePositiveRate,
} from "../metrics-calculator";

const log = logger.child("security-metrics");

const ALLOWED_SLA_FIELDS = ["severity", "targetHours", "enabled"];
const ALLOWED_OVERLAP_FIELDS = ["capability", "tools", "annualCost", "recommendation", "potentialSavings"];
const ALLOWED_BOARD_KPI_FIELDS = [
  "kpiType",
  "displayName",
  "position",
  "visible",
  "targetValue",
  "warningThreshold",
  "criticalThreshold",
];

export function registerSecurityMetricsRoutes(app: Express): void {
  // ==========================================================================
  // Board Dashboard — 5 KPIs
  // ==========================================================================

  // GET /api/security-metrics/dashboard
  app.get(
    "/api/security-metrics/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const periodDays = Math.min(Number(req.query.days) || 30, 365);
        const periodEnd = new Date();
        const periodStart = new Date(Date.now() - periodDays * 86400000);

        const [mttrMttd, roi, sla, fpRate] = await Promise.all([
          computeMttrMttd(orgId, periodStart, periodEnd),
          computeSecurityRoi(orgId, periodStart, periodEnd),
          computeSlaCompliance(orgId),
          computeFalsePositiveRate(orgId, periodStart, periodEnd),
        ]);

        // Coverage score from heatmap
        const heatmap = await computeCoverageHeatmap(orgId);
        const coveredCells = heatmap.filter((c) => c.covered).length;
        const coverageScore = heatmap.length > 0 ? Math.round((coveredCells / heatmap.length) * 100) : 0;

        // Peer benchmarks
        const orgMetrics: Record<string, number> = {
          mttr: mttrMttd.mttrMinutes,
          mttd: mttrMttd.mttdMinutes,
          false_positive_rate: fpRate.rate,
          automated_response_rate: roi.automatedResponseRate,
        };
        if (sla.overall !== null) orgMetrics.sla_compliance = sla.overall;
        const benchmarks = computePeerBenchmarks(orgMetrics);

        res.json({
          kpis: {
            mttr: {
              value: mttrMttd.mttrMinutes,
              trend: mttrMttd.mttrTrend,
              unit: "minutes",
              label: "Mean Time to Respond",
            },
            roi: {
              value: roi.roiMultiplier,
              savings: roi.estimatedSavings,
              unit: "x",
              label: "Security ROI",
            },
            slaCompliance: {
              value: sla.overall,
              unit: "percent",
              label: "SLA Compliance",
            },
            coverage: {
              value: coverageScore,
              unit: "percent",
              label: "Detection Coverage",
            },
            falsePositiveRate: {
              value: fpRate.rate,
              unit: "percent",
              label: "False Positive Rate",
            },
          },
          mttrMttd,
          roi,
          sla,
          coverageScore,
          falsePositiveRate: fpRate,
          benchmarks,
          period: { start: periodStart.toISOString(), end: periodEnd.toISOString(), days: periodDays },
        });
      } catch (err) {
        log.error("Failed to compute dashboard KPIs", { error: String(err) });
        res.status(500).json({ error: "Failed to compute dashboard KPIs" });
      }
    },
  );

  // ==========================================================================
  // MTTR / MTTD Trend
  // ==========================================================================

  // GET /api/security-metrics/mttr-trend
  app.get(
    "/api/security-metrics/mttr-trend",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(Number(req.query.limit) || 30, 90);

        const snapshots = await db
          .select()
          .from(securityKpiSnapshots)
          .where(and(eq(securityKpiSnapshots.orgId, orgId), eq(securityKpiSnapshots.kpiType, "mttr")))
          .orderBy(desc(securityKpiSnapshots.periodStart))
          .limit(limit);

        res.json(snapshots.reverse());
      } catch (err) {
        log.error("Failed to get MTTR trend", { error: String(err) });
        res.status(500).json({ error: "Failed to get MTTR trend" });
      }
    },
  );

  // ==========================================================================
  // KPI Snapshot CRUD & Recompute
  // ==========================================================================

  // POST /api/security-metrics/snapshot
  app.post(
    "/api/security-metrics/snapshot",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const now = new Date();
        const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const dayEnd = new Date(dayStart.getTime() + 86400000);

        const metrics = await computeMttrMttd(orgId, dayStart, now);
        const fpRate = await computeFalsePositiveRate(orgId, dayStart, now);
        const sla = await computeSlaCompliance(orgId);

        const snapshotWrites = [
          persistKpiSnapshot(orgId, "mttr", metrics.mttrMinutes, "daily", dayStart, dayEnd, "minutes"),
          persistKpiSnapshot(orgId, "mttd", metrics.mttdMinutes, "daily", dayStart, dayEnd, "minutes"),
          persistKpiSnapshot(orgId, "false_positive_rate", fpRate.rate, "daily", dayStart, dayEnd, "percent"),
        ];
        if (sla.overall !== null) {
          snapshotWrites.push(
            persistKpiSnapshot(orgId, "sla_compliance", sla.overall, "daily", dayStart, dayEnd, "percent"),
          );
        }
        await Promise.all(snapshotWrites);

        res.json({ success: true, message: "KPI snapshots saved" });
      } catch (err) {
        log.error("Failed to persist KPI snapshots", { error: String(err) });
        res.status(500).json({ error: "Failed to persist KPI snapshots" });
      }
    },
  );

  // GET /api/security-metrics/snapshots
  app.get(
    "/api/security-metrics/snapshots",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { kpiType, period, limit: limitStr } = req.query;
        const limit = Math.min(Number(limitStr) || 90, 365);

        const conditions = [eq(securityKpiSnapshots.orgId, orgId)];
        if (kpiType && typeof kpiType === "string") {
          conditions.push(eq(securityKpiSnapshots.kpiType, kpiType));
        }
        if (period && typeof period === "string") {
          conditions.push(eq(securityKpiSnapshots.period, period));
        }

        const snapshots = await db
          .select()
          .from(securityKpiSnapshots)
          .where(and(...conditions))
          .orderBy(desc(securityKpiSnapshots.periodStart))
          .limit(limit);

        res.json(snapshots);
      } catch (err) {
        log.error("Failed to list KPI snapshots", { error: String(err) });
        res.status(500).json({ error: "Failed to list KPI snapshots" });
      }
    },
  );

  // ==========================================================================
  // SLA Compliance
  // ==========================================================================

  // GET /api/security-metrics/sla-compliance
  app.get(
    "/api/security-metrics/sla-compliance",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await computeSlaCompliance(orgId);
        res.json(result);
      } catch (err) {
        log.error("Failed to compute SLA compliance", { error: String(err) });
        res.status(500).json({ error: "Failed to compute SLA compliance" });
      }
    },
  );

  // GET /api/security-metrics/sla-targets
  app.get(
    "/api/security-metrics/sla-targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const targets = await db
          .select()
          .from(vulnerabilitySlaTargets)
          .where(eq(vulnerabilitySlaTargets.orgId, orgId))
          .orderBy(asc(vulnerabilitySlaTargets.severity));
        res.json(targets);
      } catch (err) {
        log.error("Failed to list SLA targets", { error: String(err) });
        res.status(500).json({ error: "Failed to list SLA targets" });
      }
    },
  );

  // POST /api/security-metrics/sla-targets
  app.post(
    "/api/security-metrics/sla-targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_SLA_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.severity || !body.targetHours) {
          return res.status(400).json({ error: "severity and targetHours are required" });
        }

        // Upsert by org + severity
        const existing = await db
          .select()
          .from(vulnerabilitySlaTargets)
          .where(
            and(eq(vulnerabilitySlaTargets.orgId, orgId), eq(vulnerabilitySlaTargets.severity, String(body.severity))),
          );

        if (existing.length > 0) {
          const [updated] = await db
            .update(vulnerabilitySlaTargets)
            .set({ ...body, updatedAt: new Date() })
            .where(eq(vulnerabilitySlaTargets.id, existing[0].id))
            .returning();
          return res.json(updated);
        }

        const [created] = await db
          .insert(vulnerabilitySlaTargets)
          .values({ ...body, orgId } as typeof vulnerabilitySlaTargets.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to upsert SLA target", { error: String(err) });
        res.status(500).json({ error: "Failed to upsert SLA target" });
      }
    },
  );

  // ==========================================================================
  // Coverage Heatmap
  // ==========================================================================

  // GET /api/security-metrics/coverage-heatmap
  app.get(
    "/api/security-metrics/coverage-heatmap",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const heatmap = await computeCoverageHeatmap(orgId);
        const coveredCount = heatmap.filter((c) => c.covered).length;
        res.json({
          cells: heatmap,
          coverageScore: heatmap.length > 0 ? Math.round((coveredCount / heatmap.length) * 100) : 0,
          total: heatmap.length,
          covered: coveredCount,
        });
      } catch (err) {
        log.error("Failed to compute coverage heatmap", { error: String(err) });
        res.status(500).json({ error: "Failed to compute coverage heatmap" });
      }
    },
  );

  // ==========================================================================
  // Budget Optimization
  // ==========================================================================

  // GET /api/security-metrics/budget-optimization
  app.get(
    "/api/security-metrics/budget-optimization",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await computeBudgetOptimization(orgId);
        res.json(result);
      } catch (err) {
        log.error("Failed to compute budget optimization", { error: String(err) });
        res.status(500).json({ error: "Failed to compute budget optimization" });
      }
    },
  );

  // POST /api/security-metrics/tool-overlaps
  app.post(
    "/api/security-metrics/tool-overlaps",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_OVERLAP_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.capability || !body.tools) {
          return res.status(400).json({ error: "capability and tools are required" });
        }

        const [created] = await db
          .insert(securityToolOverlaps)
          .values({ ...body, orgId } as typeof securityToolOverlaps.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create tool overlap", { error: String(err) });
        res.status(500).json({ error: "Failed to create tool overlap" });
      }
    },
  );

  // DELETE /api/security-metrics/tool-overlaps/:id
  app.delete(
    "/api/security-metrics/tool-overlaps/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(securityToolOverlaps)
          .where(and(eq(securityToolOverlaps.id, String(req.params.id)), eq(securityToolOverlaps.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Tool overlap not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete tool overlap", { error: String(err) });
        res.status(500).json({ error: "Failed to delete tool overlap" });
      }
    },
  );

  // ==========================================================================
  // Peer Benchmarking
  // ==========================================================================

  // GET /api/security-metrics/peer-benchmark
  app.get(
    "/api/security-metrics/peer-benchmark",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const periodEnd = new Date();
        const periodStart = new Date(Date.now() - 30 * 86400000);

        const [metrics, fpRate, sla, roi] = await Promise.all([
          computeMttrMttd(orgId, periodStart, periodEnd),
          computeFalsePositiveRate(orgId, periodStart, periodEnd),
          computeSlaCompliance(orgId),
          computeSecurityRoi(orgId, periodStart, periodEnd),
        ]);

        const orgMetrics: Record<string, number> = {
          mttr: metrics.mttrMinutes,
          mttd: metrics.mttdMinutes,
          false_positive_rate: fpRate.rate,
          automated_response_rate: roi.automatedResponseRate,
        };
        if (sla.overall !== null) orgMetrics.sla_compliance = sla.overall;

        const benchmarks = computePeerBenchmarks(orgMetrics);
        res.json({ benchmarks, orgMetrics });
      } catch (err) {
        log.error("Failed to compute peer benchmarks", { error: String(err) });
        res.status(500).json({ error: "Failed to compute peer benchmarks" });
      }
    },
  );

  // ==========================================================================
  // Board KPI Configuration
  // ==========================================================================

  // GET /api/security-metrics/board-config
  app.get(
    "/api/security-metrics/board-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const configs = await db
          .select()
          .from(boardKpiConfigs)
          .where(eq(boardKpiConfigs.orgId, orgId))
          .orderBy(asc(boardKpiConfigs.position));
        res.json(configs);
      } catch (err) {
        log.error("Failed to list board KPI configs", { error: String(err) });
        res.status(500).json({ error: "Failed to list board KPI configs" });
      }
    },
  );

  // POST /api/security-metrics/board-config
  app.post(
    "/api/security-metrics/board-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_BOARD_KPI_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.kpiType || !body.displayName) {
          return res.status(400).json({ error: "kpiType and displayName are required" });
        }

        const [created] = await db
          .insert(boardKpiConfigs)
          .values({ ...body, orgId } as typeof boardKpiConfigs.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create board KPI config", { error: String(err) });
        res.status(500).json({ error: "Failed to create board KPI config" });
      }
    },
  );

  // PATCH /api/security-metrics/board-config/:id
  app.patch(
    "/api/security-metrics/board-config/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_BOARD_KPI_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [updated] = await db
          .update(boardKpiConfigs)
          .set(updates)
          .where(and(eq(boardKpiConfigs.id, String(req.params.id)), eq(boardKpiConfigs.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Board KPI config not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update board KPI config", { error: String(err) });
        res.status(500).json({ error: "Failed to update board KPI config" });
      }
    },
  );

  // DELETE /api/security-metrics/board-config/:id
  app.delete(
    "/api/security-metrics/board-config/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(boardKpiConfigs)
          .where(and(eq(boardKpiConfigs.id, String(req.params.id)), eq(boardKpiConfigs.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Board KPI config not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete board KPI config", { error: String(err) });
        res.status(500).json({ error: "Failed to delete board KPI config" });
      }
    },
  );

  // ==========================================================================
  // Reference Data
  // ==========================================================================

  // GET /api/security-metrics/kpi-types
  app.get("/api/security-metrics/kpi-types", isAuthenticated, (_req: Request, res: Response) => {
    res.json({
      kpiTypes: METRIC_KPI_TYPES,
      periodTypes: METRIC_PERIOD_TYPES,
      slaSeverities: SLA_SEVERITY_TARGETS,
    });
  });
}
