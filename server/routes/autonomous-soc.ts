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

        // Get related autonomy log entries
        const logs = await db
          .select()
          .from(autonomyLog)
          .where(eq(autonomyLog.decisionId, decisionId))
          .orderBy(desc(autonomyLog.createdAt))
          .limit(50);

        return res.json({ decision, logs });
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
        });
      } catch (error: unknown) {
        const err = error as Error;
        log.error("Failed to fetch SOC config", { error: err.message });
        return res.status(500).json({ error: "Failed to fetch configuration" });
      }
    },
  );
}
