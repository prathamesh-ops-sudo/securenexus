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

export function registerAiRoutes(app: Express): void {
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
}
