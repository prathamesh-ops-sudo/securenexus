import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext } from "../../rbac";
import { triageAlert, correlateAlerts, buildThreatIntelContext } from "../../ai";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";

const log = logger.child("routes-ai-triage");

export function registerAiTriageRoutes(app: Express): void {
  // POST /api/ai/triage/:alertId
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
        const threatIntelCtx = await buildThreatIntelContext([alert]);
        const result = await triageAlert(alert, threatIntelCtx, triageOrgId);
        if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
          result.threatIntelSources = Array.from(
            new Set([
              ...threatIntelCtx.enrichmentResults.map((r) => r.provider),
              ...threatIntelCtx.osintMatches.map((r) => r.feedName),
            ]),
          );
        }
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_triage",
          resourceType: "alert",
          resourceId: p(req.params.alertId),
          details: { severity: result.severity, priority: result.priority },
        });
        try {
          await storage.incrementUsage((req as any).orgId || (req as any).user?.orgId, "ai_analyses");
        } catch (e) {
          logger.child("ai").warn("Usage tracking failed", {
            error: String(e),
            orgId: (req as any).orgId || (req as any).user?.orgId,
          });
        }
        res.json(result);
      } catch (error: any) {
        logger.child("ai").error("AI triage error", { error: String(error) });
        res.status(500).json({ message: "AI triage failed. Please try again." });
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
        const result = await correlateAlerts(alertsToCorrelate, threatIntelCtx, orgId);
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
