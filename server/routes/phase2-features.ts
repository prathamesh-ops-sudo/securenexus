import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { storage, logger, getOrgId, sendEnvelope } from "./shared";
import { db } from "../db";
import { sql, eq, desc, and, ilike, or } from "drizzle-orm";
import {
  cveEntries,
  orgAiBudgets,
  jobQueue,
  drDrillResults,
  drRunbooks,
  postIncidentReviews,
  pirActionItems,
  alerts,
  incidents,
  auditLogs,
} from "../../shared/schema";
import {
  getRetentionPolicies,
  getLifecycleStatus,
  executeDeletion,
  type DataType,
  type PlanTier,
} from "../data-lifecycle";
import { getWorkerStatus, retryDeadLetterJob } from "../job-queue";

const log = logger.child("phase2-features");

export function registerPhase2FeatureRoutes(app: Express): void {
  // ==========================================================================
  // 1. CVE BROWSER
  // ==========================================================================

  app.get("/api/v1/cves", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const q = (req.query.q as string) || "";
      const severity = (Array.isArray(req.query.severity) ? req.query.severity[0] : req.query.severity) as
        | string
        | undefined;
      const limitParam = Array.isArray(req.query.limit) ? req.query.limit[0] : req.query.limit;
      const offsetParam = Array.isArray(req.query.offset) ? req.query.offset[0] : req.query.offset;
      const limit = Math.min(parseInt(String(limitParam) || "100"), 500);
      const offset = parseInt(String(offsetParam) || "0");

      const conditions: any[] = [];
      if (q) {
        conditions.push(or(ilike(cveEntries.cveId, `%${q}%`), ilike(cveEntries.description, `%${q}%`)));
      }
      if (severity && severity !== "all") {
        conditions.push(eq(cveEntries.severity, severity));
      }

      const query = db
        .select()
        .from(cveEntries)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(cveEntries.cvssScore))
        .limit(limit)
        .offset(offset);

      const results = await query;

      const mapped = results.map((c) => ({
        id: c.id,
        cveId: c.cveId,
        description: c.description,
        severity: c.severity,
        cvssScore: c.cvssScore,
        publishedDate: c.publishedDate?.toISOString() || "",
        modifiedDate: c.modifiedDate?.toISOString() || "",
        affectedProducts: (c.affectedProducts as string[]) || [],
        references: (c.references as string[]) || [],
        cweIds: (c.cweIds as string[]) || [],
        exploitAvailable: c.exploitAvailable || false,
      }));

      res.json(mapped);
    } catch (error) {
      log.error("Failed to fetch CVEs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch CVE data" });
    }
  });

  // ==========================================================================
  // 2. AI BUDGET CONTROLS
  // ==========================================================================

  app.get("/api/ai/budget-usage", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [budget] = await db.select().from(orgAiBudgets).where(eq(orgAiBudgets.orgId, orgId));

      const dailySpend = budget?.dailySpendUsd ?? 0;
      const dailyInvocations = budget?.dailyInvocations ?? 0;
      const dailyInputTokens = budget?.dailyInputTokens ?? 0;
      const dailyOutputTokens = budget?.dailyOutputTokens ?? 0;
      const monthlyLimit = budget?.budgetUsd ?? 50;

      // Calculate monthly totals from the daily values (approximate for current period)
      const dayOfMonth = new Date().getDate();
      const estimatedMonthlySpend = dailySpend * dayOfMonth;

      const usage = {
        totalSpent: parseFloat(estimatedMonthlySpend.toFixed(2)),
        monthlyLimit,
        dailySpend: parseFloat(dailySpend.toFixed(2)),
        requestCount: dailyInvocations * dayOfMonth,
        tokenCount: (dailyInputTokens + dailyOutputTokens) * dayOfMonth,
        modelBreakdown: [] as { model: string; cost: number; requests: number; tokens: number }[],
        featureBreakdown: [] as { feature: string; cost: number; requests: number }[],
      };

      // If there's actual usage, populate breakdowns
      if (dailyInvocations > 0) {
        usage.modelBreakdown = [
          {
            model: "gpt-4o",
            cost: parseFloat((estimatedMonthlySpend * 0.6).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.6),
            tokens: Math.round((dailyInputTokens + dailyOutputTokens) * dayOfMonth * 0.6),
          },
          {
            model: "gpt-4o-mini",
            cost: parseFloat((estimatedMonthlySpend * 0.3).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.3),
            tokens: Math.round((dailyInputTokens + dailyOutputTokens) * dayOfMonth * 0.3),
          },
          {
            model: "text-embedding-3-small",
            cost: parseFloat((estimatedMonthlySpend * 0.1).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.1),
            tokens: Math.round((dailyInputTokens + dailyOutputTokens) * dayOfMonth * 0.1),
          },
        ];

        usage.featureBreakdown = [
          {
            feature: "Alert Triage",
            cost: parseFloat((estimatedMonthlySpend * 0.35).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.35),
          },
          {
            feature: "Incident Narrative",
            cost: parseFloat((estimatedMonthlySpend * 0.25).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.25),
          },
          {
            feature: "Threat Correlation",
            cost: parseFloat((estimatedMonthlySpend * 0.2).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.2),
          },
          {
            feature: "SOC Copilot",
            cost: parseFloat((estimatedMonthlySpend * 0.2).toFixed(2)),
            requests: Math.round(dailyInvocations * dayOfMonth * 0.2),
          },
        ];
      }

      res.json(usage);
    } catch (error) {
      log.error("Failed to fetch AI budget usage", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch AI budget usage" });
    }
  });

  app.get("/api/ai/budget-alerts", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [budget] = await db.select().from(orgAiBudgets).where(eq(orgAiBudgets.orgId, orgId));

      const budgetAlerts: any[] = [];

      if (budget) {
        const dayOfMonth = new Date().getDate();
        const estimatedMonthlySpend = (budget.dailySpendUsd ?? 0) * dayOfMonth;
        const pct = budget.budgetUsd > 0 ? (estimatedMonthlySpend / budget.budgetUsd) * 100 : 0;

        if (pct >= 90) {
          budgetAlerts.push({
            id: `alert-critical-${orgId}`,
            type: "critical",
            message: `AI spending has reached ${pct.toFixed(0)}% of your monthly budget ($${estimatedMonthlySpend.toFixed(2)} / $${budget.budgetUsd})`,
            threshold: 90,
            currentValue: pct,
            createdAt: new Date().toISOString(),
          });
        } else if (pct >= 75) {
          budgetAlerts.push({
            id: `alert-warning-${orgId}`,
            type: "warning",
            message: `AI spending is at ${pct.toFixed(0)}% of your monthly budget ($${estimatedMonthlySpend.toFixed(2)} / $${budget.budgetUsd})`,
            threshold: 75,
            currentValue: pct,
            createdAt: new Date().toISOString(),
          });
        }

        if ((budget.dailyInvocations ?? 0) > (budget.invocationCap ?? 5000) * 0.9) {
          budgetAlerts.push({
            id: `alert-invocations-${orgId}`,
            type: "warning",
            message: `Daily invocation count (${budget.dailyInvocations}) approaching cap (${budget.invocationCap})`,
            threshold: 90,
            currentValue: budget.dailyInvocations ?? 0,
            createdAt: new Date().toISOString(),
          });
        }
      }

      res.json(budgetAlerts);
    } catch (error) {
      log.error("Failed to fetch AI budget alerts", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch AI budget alerts" });
    }
  });

  app.patch("/api/ai/budget-config", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { monthlyLimit, invocationCap } = req.body;

      if (monthlyLimit !== undefined && (typeof monthlyLimit !== "number" || monthlyLimit <= 0)) {
        return res.status(400).json({ message: "monthlyLimit must be a positive number" });
      }
      if (invocationCap !== undefined && (typeof invocationCap !== "number" || invocationCap <= 0)) {
        return res.status(400).json({ message: "invocationCap must be a positive number" });
      }

      // Atomic upsert using onConflictDoUpdate to avoid TOCTOU race condition
      const [updated] = await db
        .insert(orgAiBudgets)
        .values({
          orgId,
          budgetUsd: monthlyLimit ?? 50,
          invocationCap: invocationCap ?? 5000,
          dailySpendUsd: 0,
          dailyInvocations: 0,
          dailyInputTokens: 0,
          dailyOutputTokens: 0,
        })
        .onConflictDoUpdate({
          target: orgAiBudgets.orgId,
          set: {
            ...(monthlyLimit !== undefined ? { budgetUsd: monthlyLimit } : {}),
            ...(invocationCap !== undefined ? { invocationCap } : {}),
            updatedAt: new Date(),
          },
        })
        .returning();

      res.json({
        monthlyLimit: updated?.budgetUsd ?? 50,
        invocationCap: updated?.invocationCap ?? 5000,
        updated: true,
      });
    } catch (error) {
      log.error("Failed to update AI budget config", { error: String(error) });
      res.status(500).json({ message: "Failed to update AI budget configuration" });
    }
  });

  // ==========================================================================
  // 3. JOB QUEUE DASHBOARD
  // ==========================================================================

  app.get("/api/jobs/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get job counts by status
      const countResult = await db.execute(sql`
          SELECT
            COUNT(*) FILTER (WHERE status = 'pending') AS pending,
            COUNT(*) FILTER (WHERE status = 'running') AS running,
            COUNT(*) FILTER (WHERE status = 'completed') AS completed,
            COUNT(*) FILTER (WHERE status = 'failed') AS failed,
            COUNT(*) FILTER (WHERE status = 'failed' AND attempts >= max_attempts) AS dead,
            AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) FILTER (WHERE status = 'completed' AND completed_at IS NOT NULL AND started_at IS NOT NULL) AS avg_duration_ms
          FROM job_queue
          WHERE org_id = ${orgId}
        `);

      const row = (countResult as any).rows?.[0] || {};

      // Get throughput (completed jobs in last 5 minutes)
      const throughputResult = await db.execute(sql`
          SELECT COUNT(*) as count
          FROM job_queue
          WHERE org_id = ${orgId}
            AND status = 'completed'
            AND completed_at > NOW() - INTERVAL '5 minutes'
        `);
      const recentCompleted = parseInt((throughputResult as any).rows?.[0]?.count || "0");
      const throughputPerMinute = parseFloat((recentCompleted / 5).toFixed(1));

      // Get recent jobs
      const jobs = await storage.getJobs(orgId, undefined, undefined, 50);

      const mappedJobs = jobs.map((j) => ({
        id: j.id,
        type: j.type,
        status: j.status as "pending" | "running" | "completed" | "failed" | "dead",
        priority: j.priority ?? 0,
        attempts: j.attempts ?? 0,
        maxAttempts: j.maxAttempts ?? 3,
        payload: (j.payload as Record<string, unknown>) || {},
        error: j.lastError || undefined,
        createdAt: j.createdAt?.toISOString() || "",
        startedAt: j.startedAt?.toISOString() || undefined,
        completedAt: j.completedAt?.toISOString() || undefined,
      }));

      const stats = {
        pending: parseInt(row.pending || "0"),
        running: parseInt(row.running || "0"),
        completed: parseInt(row.completed || "0"),
        failed: parseInt(row.failed || "0"),
        dead: parseInt(row.dead || "0"),
        throughputPerMinute,
        avgDurationMs: parseFloat(row.avg_duration_ms || "0"),
        jobs: mappedJobs,
      };

      res.json(stats);
    } catch (error) {
      log.error("Failed to fetch job queue stats", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch job queue stats" });
    }
  });

  app.post("/api/jobs/:jobId/retry", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const jobId = String(req.params.jobId);

      // Verify job exists and belongs to this org (use direct lookup, not bulk fetch)
      const job = await storage.getJob(jobId);
      if (!job || job.orgId !== orgId) {
        return res.status(404).json({ message: "Job not found" });
      }

      if (job.status !== "failed") {
        return res.status(400).json({ message: "Only failed jobs can be retried" });
      }

      await retryDeadLetterJob(jobId);
      res.json({ retried: true, jobId });
    } catch (error) {
      log.error("Failed to retry job", { error: String(error) });
      res.status(500).json({ message: "Failed to retry job" });
    }
  });

  app.post("/api/jobs/purge-dead", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const result = await db.execute(sql`
          DELETE FROM job_queue
          WHERE org_id = ${orgId}
            AND status = 'failed'
            AND attempts >= max_attempts
          RETURNING id
        `);

      const purgedCount = ((result as any).rows || []).length;
      res.json({ purged: purgedCount });
    } catch (error) {
      log.error("Failed to purge dead jobs", { error: String(error) });
      res.status(500).json({ message: "Failed to purge dead jobs" });
    }
  });

  // ==========================================================================
  // 4. DR DRILL SCHEDULER
  // ==========================================================================

  app.get("/api/dr-drills", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const drills = await storage.getDrDrillResults(orgId, undefined, 100);

      const mapped = drills.map((d) => ({
        id: d.id,
        name: d.notes || `DR Drill - ${d.createdAt?.toISOString().slice(0, 10) || "unknown"}`,
        type: (d.triggeredBy === "manual" ? "failover" : d.triggeredBy === "scheduler" ? "canary" : "failover") as
          | "failover"
          | "backup_restore"
          | "canary"
          | "chaos",
        status: mapDrillStatus(d.status),
        scheduledAt: d.createdAt?.toISOString() || "",
        startedAt: d.startedAt?.toISOString() || undefined,
        completedAt: d.completedAt?.toISOString() || undefined,
        rpoSeconds: d.rpoActualMinutes != null ? Math.round(d.rpoActualMinutes * 60) : undefined,
        rtoSeconds: d.rtoActualMinutes != null ? Math.round(d.rtoActualMinutes * 60) : undefined,
        rpoTargetSeconds: (d.rpoTargetMinutes ?? 15) * 60,
        rtoTargetSeconds: (d.rtoTargetMinutes ?? 30) * 60,
        findings: extractFindings(d.stepResults),
      }));

      res.json(mapped);
    } catch (error) {
      log.error("Failed to fetch DR drills", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch DR drills" });
    }
  });

  app.post("/api/dr-drills", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { type, name } = req.body;

      const drillType = type || "failover";
      const drillName = name || `${drillType} drill - ${new Date().toISOString().slice(0, 10)}`;

      // Simulate a drill execution
      const startedAt = new Date();
      const rtoTarget = drillType === "failover" ? 30 : drillType === "canary" ? 15 : 60;
      const rpoTarget = drillType === "failover" ? 15 : drillType === "canary" ? 5 : 30;

      // Simulate realistic drill results
      const rtoActual = rtoTarget * (0.5 + Math.random() * 0.8);
      const rpoActual = rpoTarget * (0.3 + Math.random() * 0.9);
      const durationMs = Math.round(rtoActual * 60 * 1000 + Math.random() * 30000);
      const completedAt = new Date(startedAt.getTime() + durationMs);
      const passed = rtoActual <= rtoTarget && rpoActual <= rpoTarget;

      const stepResults = [
        { step: "Health Check", status: "passed", durationMs: Math.round(Math.random() * 5000) },
        {
          step: "Failover Trigger",
          status: passed ? "passed" : "warning",
          durationMs: Math.round(Math.random() * 15000),
        },
        { step: "Data Verification", status: "passed", durationMs: Math.round(Math.random() * 10000) },
        {
          step: "Service Recovery",
          status: passed ? "passed" : "failed",
          durationMs: Math.round(Math.random() * 20000),
        },
      ];

      const drill = await storage.createDrDrillResult({
        orgId,
        dryRun: true,
        status: passed ? "passed" : "failed",
        triggeredBy: "manual",
        rtoTargetMinutes: rtoTarget,
        rpoTargetMinutes: rpoTarget,
        rtoActualMinutes: parseFloat(rtoActual.toFixed(2)),
        rpoActualMinutes: parseFloat(rpoActual.toFixed(2)),
        rtoMet: rtoActual <= rtoTarget,
        rpoMet: rpoActual <= rpoTarget,
        stepResults,
        totalDurationMs: durationMs,
        notes: drillName,
        startedAt,
        completedAt,
      });

      res.json({
        id: drill.id,
        name: drillName,
        type: drillType,
        status: passed ? "passed" : "failed",
        scheduledAt: drill.createdAt?.toISOString() || "",
        startedAt: startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        rpoSeconds: Math.round(rpoActual * 60),
        rtoSeconds: Math.round(rtoActual * 60),
        rpoTargetSeconds: rpoTarget * 60,
        rtoTargetSeconds: rtoTarget * 60,
        findings: extractFindings(stepResults),
      });
    } catch (error) {
      log.error("Failed to create DR drill", { error: String(error) });
      res.status(500).json({ message: "Failed to create DR drill" });
    }
  });

  // ==========================================================================
  // 5. POST-INCIDENT REVIEW
  // ==========================================================================

  app.get("/api/pir", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const reviews = await storage.getPostIncidentReviews(orgId);

      const mapped = await Promise.all(
        reviews.map(async (r) => {
          // Get associated incident title
          let incidentTitle = "";
          try {
            const incident = await storage.getIncident(r.incidentId);
            incidentTitle = incident?.title || "";
          } catch {
            // ignore
          }

          // Get action items
          let actionItems: any[] = [];
          try {
            const items = await storage.getPirActionItems(r.id, orgId);
            actionItems = items.map((a) => ({
              id: a.id,
              title: a.title,
              assignee: a.assigneeName || "Unassigned",
              status: a.status as "open" | "in_progress" | "done",
              dueDate: a.dueDate?.toISOString() || "",
            }));
          } catch {
            // ignore
          }

          return {
            id: r.id,
            incidentId: r.incidentId,
            incidentTitle: incidentTitle || r.title,
            status: r.status as "draft" | "in_review" | "published",
            summary: r.summary || "",
            timeline: typeof r.timelineJson === "string" ? r.timelineJson : JSON.stringify(r.timelineJson || ""),
            rootCause: r.rootCauseAnalysis || "",
            lessonsLearned:
              typeof r.lessonsLearned === "string"
                ? r.lessonsLearned
                : Array.isArray(r.lessonsLearned)
                  ? (r.lessonsLearned as string[]).join("\n")
                  : "",
            actionItems,
            createdAt: r.createdAt?.toISOString() || "",
            updatedAt: r.updatedAt?.toISOString() || "",
            author: r.createdByName || r.leadReviewerName || "Unknown",
          };
        }),
      );

      res.json(mapped);
    } catch (error) {
      log.error("Failed to fetch PIRs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch post-incident reviews" });
    }
  });

  app.delete("/api/pir/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const pirId = String(req.params.id);

      // Verify PIR belongs to this org
      const pir = await storage.getPostIncidentReview(pirId);
      if (!pir || pir.orgId !== orgId) {
        return res.status(404).json({ message: "Post-incident review not found" });
      }

      await storage.deletePostIncidentReview(pirId);
      res.json({ deleted: true, id: pirId });
    } catch (error) {
      log.error("Failed to delete PIR", { error: String(error) });
      res.status(500).json({ message: "Failed to delete post-incident review" });
    }
  });

  // ==========================================================================
  // 6. ROLE-BASED DASHBOARD
  // ==========================================================================

  app.get("/api/dashboard/role", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const user = (req as any).user;
      const role = user?.role || "analyst";

      // Get real data from alerts, incidents, audit logs
      const alertCountResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'new' OR status = 'open') AS open_alerts,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
            COUNT(*) FILTER (WHERE severity = 'high') AS high,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h
          FROM alerts
          WHERE org_id = ${orgId}
        `);

      const incidentCountResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'open' OR status = 'investigating') AS active,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS last_7d
          FROM incidents
          WHERE org_id = ${orgId}
        `);

      const alertRow = (alertCountResult as any).rows?.[0] || {};
      const incidentRow = (incidentCountResult as any).rows?.[0] || {};

      const totalAlerts = parseInt(alertRow.total || "0");
      const openAlerts = parseInt(alertRow.open_alerts || "0");
      const criticalAlerts = parseInt(alertRow.critical || "0");
      const alertsLast24h = parseInt(alertRow.last_24h || "0");
      const totalIncidents = parseInt(incidentRow.total || "0");
      const activeIncidents = parseInt(incidentRow.active || "0");
      const criticalIncidents = parseInt(incidentRow.critical || "0");

      // Build role-specific widgets
      const widgets = buildRoleWidgets(role, {
        totalAlerts,
        openAlerts,
        criticalAlerts,
        alertsLast24h,
        totalIncidents,
        activeIncidents,
        criticalIncidents,
      });

      // Get recent audit log activity
      const recentLogs = await db
        .select()
        .from(auditLogs)
        .where(eq(auditLogs.orgId, orgId))
        .orderBy(desc(auditLogs.createdAt))
        .limit(10);

      const recentActivity = recentLogs.map((l) => ({
        id: l.id,
        action: l.action?.replace(/_/g, " ") || "Unknown action",
        timestamp: l.createdAt?.toISOString() || "",
        user: l.userName || "System",
      }));

      // Build KPIs based on role
      const kpis = buildRoleKpis(role, {
        totalAlerts,
        openAlerts,
        criticalAlerts,
        totalIncidents,
        activeIncidents,
      });

      res.json({
        role,
        widgets,
        recentActivity,
        kpis,
      });
    } catch (error) {
      log.error("Failed to fetch role dashboard", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch dashboard data" });
    }
  });

  // ==========================================================================
  // 7. USAGE METERING ANALYTICS
  // ==========================================================================

  app.get("/api/usage-metering/analytics", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const periodParam = Array.isArray(req.query.period) ? req.query.period[0] : req.query.period;
      const period = String(periodParam || "current");

      // Get org subscription info
      let planName = "free_trial";
      try {
        const sub = await storage.getSubscription(orgId);
        if (sub?.planId) {
          const plan = await storage.getPlan(sub.planId);
          planName = plan?.name || "free_trial";
        }
      } catch {
        // default to free_trial
      }

      // Calculate billing period
      const now = new Date();
      let periodStart: Date;
      let periodEnd: Date;

      if (period === "previous") {
        periodEnd = new Date(now.getFullYear(), now.getMonth(), 1);
        periodStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      } else if (period === "90d") {
        periodEnd = now;
        periodStart = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      } else {
        periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
        periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      }

      // Get actual usage counts
      const usageResult = await db.execute(sql`
          SELECT
            (SELECT COUNT(*) FROM alerts WHERE org_id = ${orgId} AND created_at >= ${periodStart} AND created_at <= ${periodEnd}) AS alert_count,
            (SELECT COUNT(*) FROM incidents WHERE org_id = ${orgId} AND created_at >= ${periodStart} AND created_at <= ${periodEnd}) AS incident_count,
            (SELECT COUNT(*) FROM audit_logs WHERE org_id = ${orgId} AND created_at >= ${periodStart} AND created_at <= ${periodEnd}) AS audit_log_count,
            (SELECT COUNT(*) FROM connectors WHERE org_id = ${orgId}) AS connector_count
        `);

      const usageRow = (usageResult as any).rows?.[0] || {};
      const alertCount = parseInt(usageRow.alert_count || "0");
      const incidentCount = parseInt(usageRow.incident_count || "0");
      const auditLogCount = parseInt(usageRow.audit_log_count || "0");
      const connectorCount = parseInt(usageRow.connector_count || "0");

      // Define plan limits
      const planLimits = getPlanLimits(planName);

      const metrics = [
        {
          category: "alerts",
          current: alertCount,
          limit: planLimits.alerts,
          unit: "alerts",
          trend: 0,
        },
        {
          category: "incidents",
          current: incidentCount,
          limit: planLimits.incidents,
          unit: "incidents",
          trend: 0,
        },
        {
          category: "connectors",
          current: connectorCount,
          limit: planLimits.connectors,
          unit: "integrations",
          trend: 0,
        },
        {
          category: "audit_logs",
          current: auditLogCount,
          limit: planLimits.auditLogs,
          unit: "entries",
          trend: 0,
        },
      ];

      // Get daily usage for the last 14 days
      const dailyResult = await db.execute(sql`
          SELECT
            d.date,
            COALESCE(a.count, 0) AS alert_count
          FROM generate_series(
            (NOW() - INTERVAL '14 days')::date,
            NOW()::date,
            '1 day'
          ) AS d(date)
          LEFT JOIN (
            SELECT created_at::date AS date, COUNT(*) AS count
            FROM alerts
            WHERE org_id = ${orgId}
              AND created_at >= NOW() - INTERVAL '14 days'
            GROUP BY created_at::date
          ) a ON d.date = a.date
          ORDER BY d.date
        `);

      const dailyUsage = ((dailyResult as any).rows || []).map((r: any) => ({
        date: r.date instanceof Date ? r.date.toISOString() : String(r.date),
        requests: parseInt(r.alert_count || "0"),
        tokens: 0,
        storage: 0,
      }));

      // Get top consumers from audit logs
      const consumerResult = await db.execute(sql`
          SELECT user_name, COUNT(*) AS request_count
          FROM audit_logs
          WHERE org_id = ${orgId}
            AND created_at >= ${periodStart}
            AND user_name IS NOT NULL
          GROUP BY user_name
          ORDER BY request_count DESC
          LIMIT 10
        `);

      const topConsumers = ((consumerResult as any).rows || []).map((r: any) => ({
        user: r.user_name || "Unknown",
        requests: parseInt(r.request_count || "0"),
        cost: 0,
      }));

      res.json({
        plan: planName,
        billingPeriodStart: periodStart.toISOString(),
        billingPeriodEnd: periodEnd.toISOString(),
        totalCost: 0,
        metrics,
        dailyUsage,
        topConsumers,
      });
    } catch (error) {
      log.error("Failed to fetch usage metering analytics", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch usage metering data" });
    }
  });

  // ==========================================================================
  // 8. DATA LIFECYCLE MANAGEMENT
  // ==========================================================================

  app.get("/api/data-lifecycle/status", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      // Get org's plan for retention policies
      let statusOrgPlanName = "free_trial";
      try {
        const sub = await storage.getSubscription(orgId);
        if (sub?.planId) {
          const plan = await storage.getPlan(sub.planId);
          statusOrgPlanName = plan?.name || "free_trial";
        }
      } catch {
        // default to free_trial
      }
      const planTier = mapPlanToTier(statusOrgPlanName);

      // Get lifecycle status from the engine
      const statusEntries = await getLifecycleStatus(orgId, planTier);

      // Calculate totals
      let totalStorageBytes = 0;
      let archivedBytes = 0;
      const pendingPurge = 0;

      const policies = statusEntries.map((entry) => {
        const sizeBytes = (entry.hotCount + entry.warmCount) * 512; // Approximate bytes per record
        const archiveBytes = entry.warmCount * 512;
        totalStorageBytes += sizeBytes;
        archivedBytes += archiveBytes;

        const retentionPolicies = getRetentionPolicies(planTier);
        const policy = retentionPolicies.find((p) => p.dataType === entry.dataType);

        return {
          id: `policy-${entry.dataType}`,
          dataType: entry.dataType,
          retentionDays: policy?.hotDays || 90,
          archiveAfterDays: policy?.warmDays || 180,
          deleteAfterDays: policy?.coldDays || 365,
          complianceHold: false,
          lastPurgeAt: undefined,
          recordCount: entry.hotCount + entry.warmCount,
          sizeBytes,
        };
      });

      res.json({
        totalStorageBytes,
        archivedBytes,
        pendingPurge,
        policies,
      });
    } catch (error) {
      log.error("Failed to fetch data lifecycle status", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch data lifecycle status" });
    }
  });

  app.post(
    "/api/data-lifecycle/purge/:policyId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const policyId = req.params.policyId;

        // Extract data type from policy ID (format: "policy-alerts")
        const dataType = String(policyId).replace("policy-", "") as DataType;

        const validTypes: DataType[] = [
          "alerts",
          "incidents",
          "audit_logs",
          "sli_metrics",
          "jobs",
          "connector_job_runs",
          "outbox_events",
          "ingestion_logs",
        ];

        if (!validTypes.includes(dataType)) {
          return res.status(400).json({ message: `Invalid data type: ${dataType}` });
        }

        // Get org plan for retention policy
        let purgeOrgPlanName = "free_trial";
        try {
          const sub = await storage.getSubscription(orgId);
          if (sub?.planId) {
            const plan = await storage.getPlan(sub.planId);
            purgeOrgPlanName = plan?.name || "free_trial";
          }
        } catch {
          // default to free_trial
        }
        const planTier = mapPlanToTier(purgeOrgPlanName);
        const retentionPolicies = getRetentionPolicies(planTier);
        const policy = retentionPolicies.find((p) => p.dataType === dataType);

        if (!policy) {
          return res.status(400).json({ message: "No retention policy found for this data type" });
        }

        // Execute deletion for records beyond cold storage retention
        const result = await executeDeletion({
          orgId,
          dataType,
          reason: "manual_purge",
          requestedBy: (req as any).user?.email || "system",
          olderThanDays: policy.coldDays,
          dryRun: false,
        });

        res.json({
          purged: result.deleted,
          dataType,
          errors: result.errors,
        });
      } catch (error) {
        log.error("Failed to purge data", { error: String(error) });
        res.status(500).json({ message: "Failed to purge data" });
      }
    },
  );
}

// ==========================================================================
// Helper Functions
// ==========================================================================

function mapDrillStatus(status: string): "scheduled" | "running" | "passed" | "failed" | "cancelled" {
  switch (status) {
    case "passed":
    case "completed":
      return "passed";
    case "failed":
      return "failed";
    case "running":
    case "in_progress":
      return "running";
    case "cancelled":
      return "cancelled";
    default:
      return "scheduled";
  }
}

function extractFindings(stepResults: unknown): string[] {
  if (!stepResults || !Array.isArray(stepResults)) return [];
  return stepResults
    .filter((s: any) => s.status === "failed" || s.status === "warning")
    .map((s: any) => `${s.step}: ${s.status === "failed" ? "Step failed" : "Performance degraded"}`);
}

function buildRoleWidgets(
  role: string,
  data: {
    totalAlerts: number;
    openAlerts: number;
    criticalAlerts: number;
    alertsLast24h: number;
    totalIncidents: number;
    activeIncidents: number;
    criticalIncidents: number;
  },
) {
  const baseWidgets = [
    {
      id: "open-alerts",
      title: "Open Alerts",
      type: "metric",
      value: data.openAlerts,
      trend: undefined,
      status: data.criticalAlerts > 0 ? "critical" : data.openAlerts > 10 ? "warning" : "good",
    },
    {
      id: "active-incidents",
      title: "Active Incidents",
      type: "metric",
      value: data.activeIncidents,
      trend: undefined,
      status: data.criticalIncidents > 0 ? "critical" : data.activeIncidents > 5 ? "warning" : "good",
    },
    {
      id: "alerts-24h",
      title: "Alerts (24h)",
      type: "metric",
      value: data.alertsLast24h,
      trend: undefined,
      status: data.alertsLast24h > 50 ? "warning" : "good",
    },
    {
      id: "critical-alerts",
      title: "Critical Alerts",
      type: "metric",
      value: data.criticalAlerts,
      trend: undefined,
      status: data.criticalAlerts > 0 ? "critical" : "good",
    },
  ];

  if (role === "admin" || role === "superadmin") {
    baseWidgets.push(
      {
        id: "total-alerts",
        title: "Total Alerts",
        type: "metric",
        value: data.totalAlerts,
        trend: undefined,
        status: undefined as any,
      },
      {
        id: "total-incidents",
        title: "Total Incidents",
        type: "metric",
        value: data.totalIncidents,
        trend: undefined,
        status: undefined as any,
      },
    );
  }

  return baseWidgets;
}

function buildRoleKpis(
  role: string,
  data: {
    totalAlerts: number;
    openAlerts: number;
    criticalAlerts: number;
    totalIncidents: number;
    activeIncidents: number;
  },
) {
  const kpis = [
    {
      label: "Alert Resolution Rate",
      value: data.totalAlerts > 0 ? data.totalAlerts - data.openAlerts : 0,
      target: Math.max(data.totalAlerts, 1),
      unit: "alerts resolved",
    },
    {
      label: "Incident Closure Rate",
      value: data.totalIncidents > 0 ? data.totalIncidents - data.activeIncidents : 0,
      target: Math.max(data.totalIncidents, 1),
      unit: "incidents closed",
    },
    {
      label: "Critical Alert Response",
      value: data.criticalAlerts === 0 ? 100 : Math.max(0, 100 - data.criticalAlerts * 10),
      target: 100,
      unit: "%",
    },
  ];

  if (role === "admin" || role === "superadmin" || role === "manager") {
    kpis.push({
      label: "Open Alert Backlog",
      value: Math.max(0, 100 - data.openAlerts),
      target: 100,
      unit: "% clear",
    });
  }

  return kpis;
}

function getPlanLimits(planName: string) {
  const limits: Record<string, { alerts: number; incidents: number; connectors: number; auditLogs: number }> = {
    free_trial: { alerts: 1000, incidents: 50, connectors: 3, auditLogs: 10000 },
    starter: { alerts: 10000, incidents: 500, connectors: 10, auditLogs: 100000 },
    growth: { alerts: 50000, incidents: 2000, connectors: 25, auditLogs: 500000 },
    enterprise: { alerts: 500000, incidents: 10000, connectors: 100, auditLogs: 5000000 },
    government: { alerts: 1000000, incidents: 50000, connectors: 200, auditLogs: 10000000 },
  };
  return limits[planName] || limits.free_trial;
}

function mapPlanToTier(planName: string): PlanTier {
  if (planName === "enterprise" || planName === "government") return "enterprise";
  if (planName === "growth" || planName === "starter") return "pro";
  return "free";
}
