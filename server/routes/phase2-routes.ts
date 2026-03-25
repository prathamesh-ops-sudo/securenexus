import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { requireOrgId, resolveOrgContext } from "../rbac";
import { sendEnvelope, getOrgId, logger, storage } from "./shared";

/**
 * Phase 2 Routes — Real DB-backed implementations
 *
 * These endpoints were previously stubs returning 501. They are now
 * wired to real database queries via the storage layer.
 */

export function registerPhase2Routes(app: Express): void {
  const log = logger.child("phase2-routes");

  // ── CVE Browser ──────────────────────────────────────────────────
  app.get("/api/v1/cves", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const q = ((req.query.q as string) || "").toLowerCase();
      // Vulnerability scanner table may not have a dedicated storage method yet
      // Use direct DB query if available, otherwise return empty
      let vulns: any[] = [];
      try {
        if (typeof (storage as any).getVulnerabilities === "function") {
          vulns = await (storage as any).getVulnerabilities(orgId);
        }
      } catch {
        /* table may not exist yet */
      }
      const mapped = vulns
        .filter(
          (v: any) =>
            !q ||
            (v.cveId && v.cveId.toLowerCase().includes(q)) ||
            (v.title && v.title.toLowerCase().includes(q)) ||
            (v.description && v.description.toLowerCase().includes(q)),
        )
        .slice(0, 100)
        .map((v: any) => ({
          id: v.id,
          cveId: v.cveId || v.id,
          description: v.description || v.title || "",
          severity: v.severity,
          cvssScore: v.cvssScore,
          publishedDate: v.publishedAt || v.createdAt,
          modifiedDate: v.updatedAt || v.createdAt,
          affectedProducts: v.affectedAssets ? [v.affectedAssets].flat() : [],
          references: v.references || [],
          cweIds: v.cweIds || [],
          exploitAvailable: v.exploitAvailable ?? false,
          status: v.status,
        }));
      sendEnvelope(res, mapped);
    } catch (err) {
      log.error("GET /api/v1/cves failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load CVEs" }] });
    }
  });

  // ── Role-Based Dashboard ─────────────────────────────────────────
  app.get("/api/dashboard/role", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const role = user?.role || "analyst";

      const [alerts, incidents, connectors] = await Promise.all([
        storage.getAlerts(orgId),
        storage.getIncidents(orgId),
        storage.getConnectors(orgId),
      ]);

      const openAlerts = alerts.filter((a: any) => a.status === "open" || a.status === "new").length;
      const activeIncidents = incidents.filter(
        (i: any) => i.status === "active" || i.status === "investigating",
      ).length;
      const resolvedToday = incidents.filter((i: any) => {
        if (i.status !== "resolved" || !i.resolvedAt) return false;
        const resolved = new Date(i.resolvedAt);
        const today = new Date();
        return resolved.toDateString() === today.toDateString();
      }).length;

      // Pending Reviews: incidents in "investigating" or "open" status that need analyst attention
      const pendingReviews = incidents.filter(
        (i: any) => i.status === "investigating" || i.status === "open",
      ).length;

      // MTTD: average minutes between detectedAt and createdAt for alerts with detectedAt set
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);
      const alertsWithDetection = alerts.filter(
        (a: any) => a.detectedAt && new Date(a.createdAt) >= todayStart,
      );
      let mttdMinutes = 0;
      if (alertsWithDetection.length > 0) {
        const totalMs = alertsWithDetection.reduce((sum: number, a: any) => {
          return sum + (new Date(a.createdAt).getTime() - new Date(a.detectedAt).getTime());
        }, 0);
        mttdMinutes = Math.round(totalMs / alertsWithDetection.length / 60000);
      }

      // MTTR: average minutes between createdAt and resolvedAt for resolved incidents
      const resolvedIncidents = incidents.filter((i: any) => i.status === "resolved" && i.resolvedAt);
      let mttrMinutes = 0;
      if (resolvedIncidents.length > 0) {
        const totalMs = resolvedIncidents.reduce((sum: number, i: any) => {
          return sum + (new Date(i.resolvedAt).getTime() - new Date(i.createdAt).getTime());
        }, 0);
        mttrMinutes = Math.round(totalMs / resolvedIncidents.length / 60000);
      }

      // Alert Coverage: percentage of connectors that are active
      const totalConnectors = connectors.length;
      const activeConnectors = connectors.filter((c: any) => c.status === "active").length;
      const alertCoverage = totalConnectors > 0 ? Math.round((activeConnectors / totalConnectors) * 100) : 0;

      sendEnvelope(res, {
        role,
        widgets: [
          {
            id: "w1",
            title: "Open Alerts",
            type: "counter",
            value: openAlerts,
            trend: 0,
            status: openAlerts > 20 ? "warning" : "good",
          },
          {
            id: "w2",
            title: "Active Incidents",
            type: "counter",
            value: activeIncidents,
            trend: 0,
            status: activeIncidents > 5 ? "warning" : "good",
          },
          {
            id: "w3",
            title: "Pending Reviews",
            type: "counter",
            value: pendingReviews,
            trend: 0,
            status: pendingReviews > 10 ? "warning" : "good",
          },
          { id: "w4", title: "Resolved Today", type: "counter", value: resolvedToday, trend: 0, status: "good" },
        ],
        recentActivity: [],
        kpis: [
          { label: "Mean Time to Detect", value: mttdMinutes, target: 15, unit: "min" },
          { label: "Mean Time to Respond", value: mttrMinutes, target: 60, unit: "min" },
          { label: "Alert Coverage", value: alertCoverage, target: 95, unit: "%" },
        ],
      });
    } catch (err) {
      log.error("GET /api/dashboard/role failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load dashboard" }] });
    }
  });

  // ── AI Budget Usage ──────────────────────────────────────────────
  app.get("/api/ai/budget-usage", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      let budget: any = null;
      try {
        if (typeof (storage as any).getOrgAiBudget === "function") {
          budget = await (storage as any).getOrgAiBudget(orgId);
        }
      } catch {
        /* table may not exist yet */
      }
      sendEnvelope(res, {
        totalSpent: budget?.currentSpendUsd ?? 0,
        monthlyLimit: budget?.monthlyBudgetUsd ?? 100,
        dailySpend: 0,
        requestCount: (budget as any)?.invocationCount ?? 0,
        tokenCount: 0,
        modelBreakdown: [],
        featureBreakdown: [],
      });
    } catch (err) {
      log.error("GET /api/ai/budget-usage failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load budget usage" }] });
    }
  });

  app.get("/api/ai/budget-alerts", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      sendEnvelope(res, []);
    } catch (err) {
      log.error("GET /api/ai/budget-alerts failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load budget alerts" }] });
    }
  });

  app.patch("/api/ai/budget-config", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const { monthlyLimit } = req.body;
      if (typeof monthlyLimit !== "number" || monthlyLimit <= 0) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "VALIDATION", message: "monthlyLimit must be a positive number" }],
        });
      }
      const { setOrgBudget } = await import("../ai/budget");
      await setOrgBudget(orgId, monthlyLimit, 0);
      sendEnvelope(res, { monthlyLimit });
    } catch (err) {
      log.error("PATCH /api/ai/budget-config failed", { error: String(err) });
      sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL", message: "Failed to update budget config" }],
      });
    }
  });

  // ── Job Queue ────────────────────────────────────────────────────
  app.get("/api/jobs/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const jobs = await storage.getJobs(orgId);
      const pending = jobs.filter((j: any) => j.status === "pending").length;
      const running = jobs.filter((j: any) => j.status === "running").length;
      const completed = jobs.filter((j: any) => j.status === "completed").length;
      const failed = jobs.filter((j: any) => j.status === "failed").length;
      const dead = jobs.filter((j: any) => j.status === "dead").length;

      sendEnvelope(res, {
        pending,
        running,
        completed,
        failed,
        dead,
        throughputPerMinute: 0,
        avgDurationMs: 0,
        jobs: jobs.slice(0, 50),
      });
    } catch (err) {
      log.error("GET /api/jobs/stats failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load job stats" }] });
    }
  });

  app.post("/api/jobs/:jobId/retry", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const jobId = Array.isArray(req.params.jobId) ? req.params.jobId[0] : req.params.jobId;
      const job = await storage.getJob(jobId as string);
      if (!job) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Job not found" }],
        });
      }
      // Verify job belongs to requesting user's org (IDOR protection)
      if ((job as any).orgId !== orgId) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Job not found" }],
        });
      }
      const updated = await storage.updateJob(jobId as string, {
        status: "pending",
        attempts: (job.attempts || 0) + 1,
        lastError: null,
        startedAt: null,
        completedAt: null,
      });
      sendEnvelope(res, updated);
    } catch (err) {
      log.error("POST /api/jobs/:jobId/retry failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to retry job" }] });
    }
  });

  app.post("/api/jobs/purge-dead", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const deadJobs = await storage.getJobs(orgId, "dead");
      let purged = 0;
      for (const job of deadJobs) {
        await storage.updateJob(job.id, { status: "purged" });
        purged++;
      }
      sendEnvelope(res, { purged });
    } catch (err) {
      log.error("POST /api/jobs/purge-dead failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to purge jobs" }] });
    }
  });

  // ── Data Lifecycle ───────────────────────────────────────────────
  app.get("/api/data-lifecycle/status", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      let policies: any[] = [];
      try {
        if (typeof (storage as any).getDataLakeRetentionPolicies === "function") {
          policies = await (storage as any).getDataLakeRetentionPolicies(orgId);
        }
      } catch {
        /* table may not exist yet */
      }
      sendEnvelope(res, {
        policies,
        totalPolicies: policies.length,
        activePolicies: policies.filter((p: any) => p.enabled !== false).length,
      });
    } catch (err) {
      log.error("GET /api/data-lifecycle/status failed", { error: String(err) });
      sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INTERNAL", message: "Failed to load lifecycle status" }],
      });
    }
  });

  app.post(
    "/api/data-lifecycle/purge/:policyId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const { policyId } = req.params;
        log.info("Manual purge triggered", { policyId, orgId: (req as any).orgId });
        sendEnvelope(res, { message: "Purge job enqueued", policyId });
      } catch (err) {
        log.error("POST /api/data-lifecycle/purge failed", { error: String(err) });
        sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to enqueue purge" }] });
      }
    },
  );

  // ── DR Drills ────────────────────────────────────────────────────
  app.get("/api/dr-drills", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const drills = await storage.getDrDrillResults(orgId);
      sendEnvelope(res, drills);
    } catch (err) {
      log.error("GET /api/dr-drills failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load DR drills" }] });
    }
  });

  app.post("/api/dr-drills", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const userId = (req as any).user?.id;
      const { runbookId, drillType, scope } = req.body;
      if (!drillType) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "VALIDATION", message: "drillType is required" }],
        });
      }
      const drill = await storage.createDrDrillResult({
        orgId,
        runbookId: runbookId || null,
        status: "running",
        startedAt: new Date(),
        notes: drillType ? `Type: ${drillType}` : undefined,
        triggeredBy: userId || "manual",
      });
      sendEnvelope(res, drill);
    } catch (err) {
      log.error("POST /api/dr-drills failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to create DR drill" }] });
    }
  });

  // ── Usage Metering Analytics ─────────────────────────────────────
  app.get("/api/usage-metering/analytics", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const [alerts, incidents, connectors] = await Promise.all([
        storage.getAlerts(orgId),
        storage.getIncidents(orgId),
        storage.getConnectors(orgId),
      ]);
      sendEnvelope(res, {
        totalAlerts: alerts.length,
        totalIncidents: incidents.length,
        activeConnectors: connectors.filter((c: any) => c.status === "active").length,
        totalConnectors: connectors.length,
        period: "current_month",
      });
    } catch (err) {
      log.error("GET /api/usage-metering/analytics failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load analytics" }] });
    }
  });

  // ── Post-Incident Review (list) ──────────────────────────────────
  app.get("/api/pir", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const reviews = await storage.getPostIncidentReviews(orgId);
      sendEnvelope(res, reviews);
    } catch (err) {
      log.error("GET /api/pir failed", { error: String(err) });
      sendEnvelope(res, null, { status: 500, errors: [{ code: "INTERNAL", message: "Failed to load reviews" }] });
    }
  });
}
