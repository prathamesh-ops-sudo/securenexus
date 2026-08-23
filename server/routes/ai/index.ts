import type { Express } from "express";
import { eventBus, type BusEvent } from "../../event-bus";
import { storage } from "../shared";
import { logger } from "../shared";
import { registerAiSetupRoutes } from "./setup";
import { registerAiTriageRoutes } from "./triage";
import { registerAiNarrativeRoutes } from "./narrative";
import { registerAiFeedbackRoutes } from "./feedback";
import { registerAiPromptsRoutes } from "./prompts";
import { registerAiActiveLearningRoutes } from "./active-learning";
import { registerAiDeploymentRoutes } from "./deployment";
import { registerAiInvestigationRoutes } from "./investigation";
import { registerAiContextRoutes } from "./context";
import { registerAiModelsRoutes } from "./models";
import { registerAiDetectionRulesRoutes } from "./detection-rules";
import { registerAiAccuracyRoutes } from "./accuracy";
import { registerAiReplayRoutes } from "./replay";
import { registerAiAuditorExportRoutes } from "./auditor-export";
import { isAuthenticated } from "../../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../../rbac";
import { correlateAlerts, generateIncidentNarrative, triageAlert } from "../../ai";
import { z } from "zod";

export function registerAiRoutes(app: Express): void {
  app.post(
    "/api/ai/trigger/:feature",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = (req as any).orgId || (req as any).user?.orgId;
      const feature = String(req.params.feature);
      const input = z.object({ input: z.string().trim().optional() }).safeParse(req.body);
      if (!input.success) return res.status(400).json({ message: "Invalid trigger input." });

      let output: unknown;
      if (feature === "correlate") {
        const alerts = await storage.getAlerts(orgId);
        output = await correlateAlerts(alerts.slice(0, 100), undefined, orgId);
      } else if (feature === "triage") {
        if (!input.data.input) return res.status(400).json({ message: "Provide an alert ID for triage." });
        const alert = await storage.getAlert(input.data.input);
        if (!alert || alert.orgId !== orgId) return res.status(404).json({ message: "Alert not found." });
        output = await triageAlert(alert, undefined, orgId);
      } else if (feature === "narrative") {
        if (!input.data.input)
          return res.status(400).json({ message: "Provide an incident ID for narrative generation." });
        const incident = await storage.getIncident(input.data.input);
        if (!incident || incident.orgId !== orgId) return res.status(404).json({ message: "Incident not found." });
        const alerts = await storage.getAlertsByIncident(incident.id);
        output = await generateIncidentNarrative(incident, alerts, undefined, orgId);
      } else {
        return res.status(422).json({ message: `Manual AI feature '${feature}' is not available.` });
      }
      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.username || "unknown",
        action: "manual_ai_triggered",
        resourceType: "ai_feature",
        resourceId: feature,
        details: { feature },
      });
      return res.json({ feature, status: "success", output });
    },
  );

  // Circuit breaker event listener -- registered ONCE here, not in sub-modules
  eventBus.on("system.ai_circuit_open", (event: BusEvent) => {
    const { modelId, backend, resetAt, failureCount } = event.data;
    storage
      .createAlert({
        title: "AI service circuit breaker opened",
        description: `AI model ${modelId} (${backend}) circuit breaker tripped after ${failureCount} consecutive failures. Service will attempt recovery at ${resetAt}.`,
        source: "system",
        severity: "high",
        status: "new",
        category: "ai_service_failure",
        rawData: { modelId, backend, resetAt, failureCount, eventType: "system.ai_circuit_open" },
      })
      .then((alert) => {
        logger.child("ai").warn("Auto-created alert for AI circuit breaker trip", {
          alertId: alert.id,
          modelId,
          backend,
        });
      })
      .catch((err) => {
        logger.child("ai").error("Failed to auto-create circuit breaker alert", { error: String(err) });
      });
  });

  registerAiSetupRoutes(app);
  registerAiTriageRoutes(app);
  registerAiNarrativeRoutes(app);
  registerAiFeedbackRoutes(app);
  registerAiPromptsRoutes(app);
  registerAiActiveLearningRoutes(app);
  registerAiDeploymentRoutes(app);
  registerAiInvestigationRoutes(app);
  registerAiContextRoutes(app);
  registerAiModelsRoutes(app);
  registerAiDetectionRulesRoutes(app);
  registerAiAccuracyRoutes(app);
  registerAiReplayRoutes(app);
  registerAiAuditorExportRoutes(app);
}
