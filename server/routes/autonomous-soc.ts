import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { db } from "../db";
import { aiAnalystDecisions, autonomyLog } from "@shared/schema";
import { eq, desc, and, sql, gte } from "drizzle-orm";
import { z } from "zod";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { getOrgId } from "./shared";
import { logger } from "../logger";
import { triageAlert, overrideDecision, approveDecision, getAutonomousSOCStats } from "../ai/autonomous-analyst";
import { getDecisionReceipt } from "../ai/decision-receipts";

const log = logger.child("autonomous-soc-routes");

const triageSchema = z.object({
  alertId: z.string().min(1),
  forceTier: z.enum(["tier1_autonomous", "tier2_semi_autonomous", "tier3_assisted"]).optional(),
});

const overrideSchema = z.object({
  reason: z.string().min(1).max(2000),
  newOutcome: z.string().min(1),
});

const approveSchema = z.object({
  reviewedBy: z.string().optional(),
});

export function registerAutonomousSocRoutes(app: Express): void {
  // ═══════════════════════════════════════════════
  // DASHBOARD & STATS
  // ═══════════════════════════════════════════════

  /**
   * GET /api/autonomous-soc/stats
   * Get SOC dashboard statistics — tier breakdown, confidence averages, trends
   */
  app.get(
    "/api/autonomous-soc/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const stats = await getAutonomousSOCStats(orgId);
        return res.json(stats);
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch SOC stats", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch SOC statistics" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // TRIAGE
  // ═══════════════════════════════════════════════

  /**
   * POST /api/autonomous-soc/triage
   * Trigger autonomous triage on an alert
   */
  app.post(
    "/api/autonomous-soc/triage",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const validated = triageSchema.parse(req.body);
        const user = (req as any).user;

        const result = await triageAlert({
          alertId: validated.alertId,
          orgId,
          userId: user?.id,
          userName: user?.name || user?.email,
          forcetier: validated.forceTier,
        });

        log.info("Triage completed", {
          orgId,
          alertId: validated.alertId,
          tier: result.tier,
          outcome: result.outcome,
          confidence: result.confidenceScore,
        });

        return res.json(result);
      } catch (error: unknown) {
        const err = error as Error;
        if ((err as any).name === "ZodError") {
          return res.status(400).json({ error: "Invalid request", details: (err as any).errors });
        }
        log.error("Triage failed", { error: err.message });
        return res.status(500).json({ error: err.message || "Triage failed" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // DECISIONS
  // ═══════════════════════════════════════════════

  /**
   * GET /api/autonomous-soc/decisions
   * List AI analyst decisions with pagination
   */
  app.get(
    "/api/autonomous-soc/decisions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(parseInt(String(req.query.limit) || "50", 10), 200);
        const offset = parseInt(String(req.query.offset) || "0", 10);
        const tier = req.query.tier as string | undefined;
        const status = req.query.status as string | undefined;

        const conditions = [eq(aiAnalystDecisions.orgId, orgId)];
        if (tier) conditions.push(eq(aiAnalystDecisions.tier, tier));
        if (status) conditions.push(eq(aiAnalystDecisions.status, status));

        const decisions = await db
          .select()
          .from(aiAnalystDecisions)
          .where(and(...conditions))
          .orderBy(desc(aiAnalystDecisions.createdAt))
          .limit(limit)
          .offset(offset);

        const [countResult] = await db
          .select({ count: sql<number>`count(*)` })
          .from(aiAnalystDecisions)
          .where(and(...conditions));

        return res.json({
          decisions,
          total: Number(countResult?.count ?? 0),
          limit,
          offset,
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch decisions", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch decisions" });
      }
    },
  );

  /**
   * GET /api/autonomous-soc/decisions/:id
   * Get a single decision with full details
   */
  app.get(
    "/api/autonomous-soc/decisions/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const decisionId = String(req.params.id);

        const [decision] = await db
          .select()
          .from(aiAnalystDecisions)
          .where(and(eq(aiAnalystDecisions.id, decisionId), eq(aiAnalystDecisions.orgId, orgId)))
          .limit(1);

        if (!decision) {
          return res.status(404).json({ error: "Decision not found" });
        }
        const receipt = await getDecisionReceipt(orgId, decisionId);

        // Get related autonomy log entries
        const logs = await db
          .select()
          .from(autonomyLog)
          .where(and(eq(autonomyLog.decisionId, decisionId), eq(autonomyLog.orgId, orgId)))
          .orderBy(desc(autonomyLog.createdAt))
          .limit(50);

        return res.json({ decision, logs, ...receipt });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch decision", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch decision" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // HUMAN-IN-THE-LOOP
  // ═══════════════════════════════════════════════

  /**
   * POST /api/autonomous-soc/decisions/:id/override
   * Human override of an AI decision
   */
  app.post(
    "/api/autonomous-soc/decisions/:id/override",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const decisionId = String(req.params.id);
        const validated = overrideSchema.parse(req.body);
        const user = (req as any).user;
        const overrideBy = user?.email || user?.id || "unknown";

        await overrideDecision(decisionId, orgId, overrideBy, validated.reason, validated.newOutcome);

        log.info("Decision overridden", { orgId, decisionId, overrideBy });
        return res.json({ message: "Decision overridden successfully" });
      } catch (error: unknown) {
        const err = error as Error;
        if ((err as any).name === "ZodError") {
          return res.status(400).json({ error: "Invalid request", details: (err as any).errors });
        }
        log.error("Failed to override decision", { error: err.message });
        return res.status(500).json({ error: err.message || "Failed to override decision" });
      }
    },
  );

  /**
   * POST /api/autonomous-soc/decisions/:id/approve
   * Approve a Tier 2 decision (human-in-the-loop)
   */
  app.post(
    "/api/autonomous-soc/decisions/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const decisionId = String(req.params.id);
        const user = (req as any).user;
        const reviewedBy = user?.email || user?.id || "unknown";

        await approveDecision(decisionId, orgId, reviewedBy);

        log.info("Decision approved", { orgId, decisionId, reviewedBy });
        return res.json({ message: "Decision approved and actions dispatched" });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to approve decision", { error: err.message });
        return res.status(500).json({ error: err.message || "Failed to approve decision" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // AUDIT LOG
  // ═══════════════════════════════════════════════

  /**
   * GET /api/autonomous-soc/audit-log
   * Get autonomy audit trail
   */
  app.get(
    "/api/autonomous-soc/audit-log",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(parseInt(String(req.query.limit) || "100", 10), 500);
        const offset = parseInt(String(req.query.offset) || "0", 10);
        const action = req.query.action as string | undefined;
        const tier = req.query.tier as string | undefined;

        const conditions = [eq(autonomyLog.orgId, orgId)];
        if (action) conditions.push(eq(autonomyLog.action, action));
        if (tier) conditions.push(eq(autonomyLog.tier, tier));

        const logs = await db
          .select()
          .from(autonomyLog)
          .where(and(...conditions))
          .orderBy(desc(autonomyLog.createdAt))
          .limit(limit)
          .offset(offset);

        const [countResult] = await db
          .select({ count: sql<number>`count(*)` })
          .from(autonomyLog)
          .where(and(...conditions));

        return res.json({
          logs,
          total: Number(countResult?.count ?? 0),
          limit,
          offset,
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch audit log", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch audit log" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // CONFIGURATION
  // ═══════════════════════════════════════════════

  /**
   * GET /api/autonomous-soc/config
   * Get autonomous SOC configuration for the org
   */
  app.get(
    "/api/autonomous-soc/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        // 63.2 — Confidence threshold tuning per action type
        return res.json({
          tier1: {
            enabled: true,
            confidenceThreshold: 0.95,
            autoActions: ["notify_slack", "auto_triage", "add_tag"],
            maxAutoActionsPerHour: 100,
          },
          tier2: {
            enabled: true,
            confidenceThreshold: 0.7,
            requiresApproval: true,
            approvalTimeoutMinutes: 30,
          },
          tier3: {
            enabled: true,
            confidenceThreshold: 0,
            humanLed: true,
          },
          global: {
            correlationWindowDays: 90,
            maxConcurrentTriages: 10,
            fpRateLearning: true,
            autoCloseOnFp: true,
          },
          // 63.2 — Per-action confidence thresholds
          actionThresholds: {
            auto_resolve: { minConfidence: 0.9, label: "Auto-Resolve (Benign)" },
            auto_contain: { minConfidence: 0.95, label: "Auto-Contain (Isolate)" },
            escalate_tier2: { minConfidence: 0.7, label: "Escalate to Tier 2" },
            require_review: { minConfidence: 0, label: "Require Manual Review" },
            auto_block: { minConfidence: 0.92, label: "Auto-Block IP/Domain" },
            create_incident: { minConfidence: 0.8, label: "Create Incident" },
          },
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch SOC config", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch configuration" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // 63.3 — PERFORMANCE METRICS
  // ═══════════════════════════════════════════════

  app.get(
    "/api/autonomous-soc/performance-metrics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const metricsResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total_decisions,
            COUNT(*) FILTER (WHERE tier = 'tier1_autonomous') AS tier1_count,
            COUNT(*) FILTER (WHERE outcome = 'false_negative') AS fn_count,
            COUNT(*) FILTER (WHERE outcome IN ('escalate_human','needs_investigation')) AS escalation_count,
            COUNT(*) FILTER (WHERE human_override = true) AS override_count,
            ROUND(AVG(time_to_decision_ms))::int AS avg_time_ms,
            ROUND(AVG(confidence_score), 3)::float AS avg_confidence
          FROM ai_analyst_decisions
          WHERE org_id = ${orgId}
        `);

        const row = metricsResult.rows[0] || {};
        const totalDec = Number(row.total_decisions) || 0;
        const tier1Count = Number(row.tier1_count) || 0;
        const fnCount = Number(row.fn_count) || 0;
        const escalationCount = Number(row.escalation_count) || 0;
        const overrideCount = Number(row.override_count) || 0;

        return res.json({
          alertsPerHour: totalDec > 0 ? Math.round(totalDec / Math.max(1, 720)) : 0,
          falseNegativeRate: totalDec > 0 ? Number((fnCount / totalDec).toFixed(4)) : 0,
          escalationPercentage: totalDec > 0 ? Number(((escalationCount / totalDec) * 100).toFixed(1)) : 0,
          overridePercentage: totalDec > 0 ? Number(((overrideCount / totalDec) * 100).toFixed(1)) : 0,
          timeSavedMinutes: tier1Count * 15,
          avgDecisionTimeMs: row.avg_time_ms == null ? null : Number(row.avg_time_ms),
          avgConfidence: row.avg_confidence == null ? null : Number(row.avg_confidence),
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch performance metrics", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch performance metrics" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // 63.4 — GRACEFUL DEGRADATION STATUS
  // ═══════════════════════════════════════════════

  app.get(
    "/api/autonomous-soc/degradation-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        return res.json({
          available: false,
          status: "unavailable",
          reason:
            "AI health, fallback rule inventory, human queue, and budget utilization are not persisted as an operational status snapshot.",
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch degradation status", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch degradation status" });
      }
    },
  );

  // ═══════════════════════════════════════════════
  // 63.5 — LEARNING FROM OVERRIDES
  // ═══════════════════════════════════════════════

  app.get(
    "/api/autonomous-soc/override-patterns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const overrides = await db
          .select()
          .from(aiAnalystDecisions)
          .where(and(eq(aiAnalystDecisions.orgId, orgId), eq(aiAnalystDecisions.humanOverride, true)))
          .orderBy(desc(aiAnalystDecisions.updatedAt))
          .limit(50);

        // Group by original outcome to find patterns
        const patterns: Record<string, { count: number; avgConfidence: number; totalConf: number }> = {};
        for (const o of overrides) {
          const key = o.outcome || "unknown";
          if (!patterns[key]) patterns[key] = { count: 0, avgConfidence: 0, totalConf: 0 };
          patterns[key].count++;
          if (o.confidenceScore != null) patterns[key].totalConf += o.confidenceScore;
        }
        for (const key of Object.keys(patterns)) {
          patterns[key].avgConfidence =
            patterns[key].count > 0 ? Number((patterns[key].totalConf / patterns[key].count).toFixed(3)) : 0;
        }

        return res.json({
          totalOverrides: overrides.length,
          patterns: Object.entries(patterns).map(([outcome, data]) => ({
            originalOutcome: outcome,
            overrideCount: data.count,
            avgOriginalConfidence: data.avgConfidence,
            suggestedAdjustment: data.count >= 5 ? -Math.min(data.count, 15) : 0,
            status: data.count >= 5 ? "applied" : "pending",
          })),
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch override patterns", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch override patterns" });
      }
    },
  );
}
