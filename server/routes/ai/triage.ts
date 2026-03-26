import type { Express } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext } from "../../rbac";
import { correlateAlerts, buildThreatIntelContext } from "../../ai";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";
import { withAiFallback } from "../../ai/fallback";
import { enqueueJob } from "../../job-queue";

const log = logger.child("routes-ai-triage");

/**
 * Returns the ai_triage job handler function for use by the job queue worker.
 * Exported separately so it can be registered in JOB_HANDLERS and tested independently.
 */
export function getAiTriageHandler(): (job: any) => Promise<any> {
  return async (job: any) => {
    const { alertId, orgId } = job.payload;
    try {
      const { triageAlert, buildThreatIntelContext } = await import("../../ai");
      const alert = await storage.getAlert(alertId);
      if (!alert) {
        return { error: "Alert not found", alertId };
      }
      const threatIntelCtx = await buildThreatIntelContext([alert]);
      const result = await triageAlert(alert, threatIntelCtx, orgId);

      // Broadcast completion via SSE
      const { broadcastEvent } = await import("../../event-bus");
      broadcastEvent({
        type: "ai:triage_complete",
        orgId: orgId || null,
        data: { jobId: job.id, alertId, result },
      });

      return { alertId, result };
    } catch (err: any) {
      return { error: err.message || String(err), alertId };
    }
  };
}

export function registerAiTriageRoutes(app: Express): void {
  // POST /api/ai/triage/:alertId - Async triage via job queue (returns 202 Accepted)
  app.post(
    "/api/ai/triage/:alertId",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const triageOrgId = (req as any).orgId || (req as any).user?.orgId;
        const alert = await storage.getAlert(p(req.params.alertId));
        if (!alert || (triageOrgId && alert.orgId && alert.orgId !== triageOrgId)) {
          return res.status(404).json({ message: "Alert not found" });
        }

        // Enqueue async triage job
        const job = await enqueueJob("ai_triage", triageOrgId, {
          alertId: alert.id,
          orgId: triageOrgId,
        });

        if (!job) {
          // Dedup: job already exists for this alert
          return res.status(202).json({
            jobId: null,
            status: "accepted",
            message: "Triage job already queued for this alert",
          });
        }

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_triage_queued",
          resourceType: "alert",
          resourceId: p(req.params.alertId),
          details: { jobId: job.id },
        });

        try {
          await storage.incrementUsage((req as any).orgId || (req as any).user?.orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", {
            error: String(e),
            orgId: (req as any).orgId || (req as any).user?.orgId,
          });
        }

        res.status(202).json({
          jobId: job.id,
          status: "accepted",
          pollUrl: `/api/ai/triage/jobs/${job.id}`,
        });
      } catch (error: any) {
        logger.child("ai").error("AI triage enqueue error", { error: String(error) });
        res.status(500).json({ message: "AI triage failed. Please try again." });
      }
    },
  );

  // GET /api/ai/triage/jobs/:jobId - Poll triage job status
  app.get(
    "/api/ai/triage/jobs/:jobId",
    isAuthenticated,
    resolveOrgContext,
    async (req, res) => {
      try {
        const jobId = p(req.params.jobId);
        const job = await storage.getJob(jobId);
        if (!job) {
          return res.status(404).json({ message: "Job not found" });
        }

        // Verify org access
        const orgId = (req as any).orgId || (req as any).user?.orgId;
        if (job.orgId && orgId && job.orgId !== orgId) {
          return res.status(404).json({ message: "Job not found" });
        }

        if (job.status === "completed") {
          return res.json({ status: "completed", result: job.result });
        }
        if (job.status === "failed" || job.status === "dead_letter") {
          return res.json({ status: "failed", error: job.lastError || job.error || "Unknown error" });
        }
        res.json({ status: job.status }); // pending, running
      } catch (error: any) {
        logger.child("ai").error("Job poll error", { error: String(error) });
        res.status(500).json({ message: "Failed to check job status" });
      }
    },
  );

  // POST /api/ai/correlate
  app.post(
    "/api/ai/correlate",
    isAuthenticated,
    resolveOrgContext,
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req, res) => {
      try {
        const orgId = (req as any).orgId || (req as any).user?.orgId;
        const { alertIds } = req.body;
        let alertsToCorrelate;
        if (alertIds && Array.isArray(alertIds) && alertIds.length > 0) {
          const allAlerts = await storage.getAlerts(orgId);
          alertsToCorrelate = allAlerts.filter((a) => alertIds.includes(a.id));
        } else {
          alertsToCorrelate = (await storage.getAlerts(orgId)).filter(
            (a) => a.status === "new" || a.status === "triaged",
          );
        }
        if (alertsToCorrelate.length === 0) {
          return res.status(400).json({ message: "No alerts to correlate" });
        }
        const threatIntelCtx = await buildThreatIntelContext(alertsToCorrelate);
        const correlationCacheKey = `correlate:${orgId}:${alertsToCorrelate.map((a) => a.id).sort().join(",")}`;
        const fallbackResult = await withAiFallback(correlationCacheKey, () =>
          correlateAlerts(alertsToCorrelate, threatIntelCtx, orgId),
        );
        if (fallbackResult.source === "unavailable") {
          return res.status(503).json({ message: "AI correlation temporarily unavailable", status: "ai_unavailable" });
        }
        const result = fallbackResult.data!;
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_correlation",
          resourceType: "alerts",
          details: { alertCount: alertsToCorrelate.length, groupsFound: result.correlatedGroups.length },
        });
        try {
          await storage.incrementUsage(orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", { error: String(e), orgId });
        }
        res.json(result);
      } catch (error: any) {
        const errMsg = error?.message || String(error);
        logger.child("ai").error("AI correlation error", { error: errMsg });
        let userMessage = "AI correlation failed. Please try again.";
        if (errMsg.includes("Circuit breaker open")) {
          userMessage = "AI service is temporarily unavailable due to repeated failures. Please try again later.";
        } else if (errMsg.includes("budget exceeded")) {
          userMessage = "AI budget exceeded for your organization. Contact your admin to increase limits.";
        } else if (errMsg.includes("not found in registry")) {
          userMessage = "AI correlation prompt is not configured. Contact your administrator.";
        } else if (errMsg.length <= 200) {
          userMessage = errMsg;
        }
        res.status(500).json({ message: userMessage });
      }
    },
  );

  // POST /api/ai/correlate/apply
  app.post("/api/ai/correlate/apply", isAuthenticated, async (req, res) => {
    try {
      const { group } = req.body;
      if (!group || !Array.isArray(group.alertIds) || group.alertIds.length === 0 || !group.suggestedIncidentTitle) {
        return res.status(400).json({ message: "Invalid correlation group data" });
      }
      const validAlertIds: string[] = [];
      for (const alertId of group.alertIds) {
        if (typeof alertId === "string") {
          const alert = await storage.getAlert(alertId);
          if (alert) validAlertIds.push(alertId);
        }
      }
      if (validAlertIds.length === 0) {
        return res.status(400).json({ message: "No valid alerts found in correlation group" });
      }
      const validSeverities = ["critical", "high", "medium", "low"];
      const severity = validSeverities.includes(group.severity) ? group.severity : "medium";
      const incident = await storage.createIncident({
        title: String(group.suggestedIncidentTitle).slice(0, 500),
        summary: String(group.reasoning || "").slice(0, 2000),
        severity,
        status: "investigating",
        priority: severity === "critical" ? 1 : severity === "high" ? 2 : 3,
        confidence: typeof group.confidence === "number" ? Math.min(Math.max(group.confidence, 0), 1) : 0.5,
        mitreTactics: Array.isArray(group.mitreTactics)
          ? group.mitreTactics.filter((t: any) => typeof t === "string")
          : [],
        mitreTechniques: Array.isArray(group.mitreTechniques)
          ? group.mitreTechniques.filter((t: any) => typeof t === "string")
          : [],
        alertCount: validAlertIds.length,
      });
      for (const alertId of validAlertIds) {
        await storage.updateAlertStatus(alertId, "correlated", incident.id);
      }
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName
          ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
          : "Analyst",
        action: "ai_correlation_applied",
        resourceType: "incident",
        resourceId: incident.id,
        details: { alertCount: group.alertIds.length, title: incident.title },
      });
      res.json(incident);
    } catch (error: any) {
      logger.child("routes").error("Apply correlation error", { error: String(error) });
      res.status(500).json({ message: "Failed to apply correlation. Please try again." });
    }
  });
}
