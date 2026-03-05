import type { Express } from "express";
import { getOrgId, storage, logger } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { ENGINE_NAMES } from "@shared/schema";
import { z } from "zod";
import { maskPiiInAlert, detectPiiFields } from "../pii-engine";
import { calculatePostureScore } from "../posture-engine";
import { canRollback } from "../rollback-engine";

const VALID_ENGINES = new Set<string>(ENGINE_NAMES);

const policyConfigSchemas: Record<string, z.ZodObject<any>> = {
  predictive: z.object({
    anomalyZScoreThreshold: z.number().min(0.5).max(10).optional(),
    volumeSpikeMultiplier: z.number().min(1).max(20).optional(),
    severityEscalationMultiplier: z.number().min(1).max(10).optional(),
    offHoursRatioThreshold: z.number().min(0.1).max(1).optional(),
    forecastProbabilityThreshold: z.number().min(0.1).max(1).optional(),
    forecastWindowHoursBase: z.number().min(1).max(720).optional(),
  }),
  pii: z.object({
    maskIps: z.boolean().optional(),
    maskEmails: z.boolean().optional(),
    maskHostnames: z.boolean().optional(),
    maskUserIds: z.boolean().optional(),
    maskingStrategy: z.enum(["full", "partial", "hash"]).optional(),
    customPatterns: z.array(z.string()).optional(),
  }),
  posture: z.object({
    cspmWeight: z.number().min(0).max(100).optional(),
    endpointWeight: z.number().min(0).max(100).optional(),
    incidentWeight: z.number().min(0).max(100).optional(),
    complianceWeight: z.number().min(0).max(100).optional(),
    criticalPenalty: z.number().min(0).max(50).optional(),
    highPenalty: z.number().min(0).max(30).optional(),
  }),
  rollback: z.object({
    autoRollbackEnabled: z.boolean().optional(),
    maxRetryAttempts: z.number().min(1).max(10).optional(),
    rollbackTimeoutMinutes: z.number().min(1).max(1440).optional(),
    reversibleActions: z.array(z.string()).optional(),
  }),
};

function validateEngineName(name: string): name is (typeof ENGINE_NAMES)[number] {
  return VALID_ENGINES.has(name);
}

const DEFAULT_POLICIES: Record<string, Record<string, unknown>> = {
  predictive: {
    anomalyZScoreThreshold: 2.5,
    volumeSpikeMultiplier: 2.5,
    severityEscalationMultiplier: 2,
    offHoursRatioThreshold: 0.5,
    forecastProbabilityThreshold: 0.3,
    forecastWindowHoursBase: 48,
  },
  pii: {
    maskIps: true,
    maskEmails: true,
    maskHostnames: true,
    maskUserIds: true,
    maskingStrategy: "full",
    customPatterns: [],
  },
  posture: {
    cspmWeight: 35,
    endpointWeight: 30,
    incidentWeight: 20,
    complianceWeight: 15,
    criticalPenalty: 15,
    highPenalty: 8,
  },
  rollback: {
    autoRollbackEnabled: false,
    maxRetryAttempts: 3,
    rollbackTimeoutMinutes: 30,
    reversibleActions: ["isolate_host", "block_ip", "disable_user", "quarantine_file"],
  },
};

export function registerEngineControlsRoutes(app: Express): void {
  const authChain = [isAuthenticated, resolveOrgContext, requireOrgId];
  const adminChain = [...authChain, requireMinRole("admin")];

  app.get("/api/engine-controls", ...authChain, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const configs = await storage.getEngineConfigs(orgId);
      const configMap = new Map(configs.map((c) => [c.engineName, c]));
      const result = ENGINE_NAMES.map((name) => {
        const existing = configMap.get(name);
        return (
          existing ?? {
            id: null,
            orgId,
            engineName: name,
            enabled: true,
            dryRunMode: false,
            policyConfig: DEFAULT_POLICIES[name],
            lastDryRunAt: null,
            lastDryRunResult: null,
            updatedBy: null,
            createdAt: null,
            updatedAt: null,
          }
        );
      });
      res.json(result);
    } catch (error) {
      logger.child("engine-controls").error("Failed to fetch engine configs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch engine configs" });
    }
  });

  app.get("/api/engine-controls/:engine", ...authChain, async (req, res) => {
    try {
      const engineName = String(req.params.engine);
      if (!validateEngineName(engineName)) {
        return res
          .status(400)
          .json({ message: `Invalid engine: ${engineName}. Must be one of: ${ENGINE_NAMES.join(", ")}` });
      }
      const orgId = getOrgId(req);
      const config = await storage.getEngineConfig(orgId, engineName);
      res.json(
        config ?? {
          id: null,
          orgId,
          engineName,
          enabled: true,
          dryRunMode: false,
          policyConfig: DEFAULT_POLICIES[engineName],
          lastDryRunAt: null,
          lastDryRunResult: null,
          updatedBy: null,
          createdAt: null,
          updatedAt: null,
        },
      );
    } catch (error) {
      logger.child("engine-controls").error("Failed to fetch engine config", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch engine config" });
    }
  });

  app.put("/api/engine-controls/:engine", ...adminChain, async (req, res) => {
    try {
      const engineName = String(req.params.engine);
      if (!validateEngineName(engineName)) {
        return res.status(400).json({ message: `Invalid engine: ${engineName}` });
      }
      const orgId = getOrgId(req);
      const userId = (req as any).user?.id;

      const bodySchema = z.object({
        enabled: z.boolean().optional(),
        dryRunMode: z.boolean().optional(),
        policyConfig: z.record(z.unknown()).optional(),
      });
      const parsed = bodySchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request body", errors: parsed.error.flatten() });
      }

      if (parsed.data.policyConfig) {
        const policySchema = policyConfigSchemas[engineName];
        if (policySchema) {
          const policyParsed = policySchema.safeParse(parsed.data.policyConfig);
          if (!policyParsed.success) {
            return res.status(400).json({ message: "Invalid policy config", errors: policyParsed.error.flatten() });
          }
        }
      }

      const config = await storage.upsertEngineConfig(orgId, engineName, {
        ...parsed.data,
        updatedBy: userId,
      });

      await storage.createAuditLog({
        orgId,
        userId,
        action: "engine_config_updated",
        resourceType: "engine_config",
        resourceId: engineName,
        details: { engineName, changes: parsed.data },
      });

      res.json(config);
    } catch (error) {
      logger.child("engine-controls").error("Failed to update engine config", { error: String(error) });
      res.status(500).json({ message: "Failed to update engine config" });
    }
  });

  app.post("/api/engine-controls/:engine/dry-run", ...adminChain, async (req, res) => {
    try {
      const engineName = String(req.params.engine);
      if (!validateEngineName(engineName)) {
        return res.status(400).json({ message: `Invalid engine: ${engineName}` });
      }
      const orgId = getOrgId(req);
      const userId = (req as any).user?.id;
      const startTime = Date.now();

      const dryRun = await storage.createEngineDryRun({
        orgId,
        engineName,
        inputParams: req.body.params ?? {},
        status: "running",
        executedBy: userId,
      });

      const savedConfig = await storage.getEngineConfig(orgId, engineName);
      const activePolicy = (savedConfig?.policyConfig as Record<string, unknown>) ?? DEFAULT_POLICIES[engineName];

      let simulatedResult: Record<string, unknown> = {};
      let status = "completed";

      try {
        switch (engineName) {
          case "predictive": {
            const alerts = await storage.getAlerts(orgId);
            simulatedResult = {
              totalAlerts: alerts.length,
              wouldDetect: {
                anomalies: alerts.filter((a) => a.status === "new").length,
                riskForecasts: alerts.filter((a) => a.mitreTactic).length > 0 ? "yes" : "no",
              },
              currentThresholds: activePolicy,
              note: "Dry-run preview: no anomalies/forecasts were persisted",
            };

            await storage.createEngineExplainabilityLog({
              orgId,
              engineName,
              executionId: dryRun.id,
              decisionType: "anomaly_detection",
              decisionOutcome: `Would analyze ${alerts.length} alerts`,
              drivers: [
                { factor: "alert_count", value: alerts.length, weight: 1.0 },
                { factor: "z_score_threshold", value: activePolicy.anomalyZScoreThreshold ?? 2.5, weight: 0.8 },
                { factor: "volume_spike_multiplier", value: activePolicy.volumeSpikeMultiplier ?? 2.5, weight: 0.7 },
              ],
              confidence: 85,
              inputSnapshot: { alertCount: alerts.length, engineName },
            });
            break;
          }
          case "pii": {
            const sampleAlerts = await storage.getAlerts(orgId);
            const sample = sampleAlerts.slice(0, 5);
            const detections = sample.map((alert) => ({
              alertId: alert.id,
              piiFields: detectPiiFields(alert),
              maskedPreview: maskPiiInAlert(alert),
            }));
            simulatedResult = {
              sampleSize: sample.length,
              detections,
              note: "Dry-run preview: no alerts were actually masked",
            };

            await storage.createEngineExplainabilityLog({
              orgId,
              engineName,
              executionId: dryRun.id,
              decisionType: "pii_detection",
              decisionOutcome: `Scanned ${sample.length} alerts, found PII in ${detections.filter((d) => d.piiFields.length > 0).length}`,
              drivers: [
                { factor: "sample_size", value: sample.length, weight: 1.0 },
                { factor: "ip_masking", value: activePolicy.maskIps ?? true, weight: 0.9 },
                { factor: "email_masking", value: activePolicy.maskEmails ?? true, weight: 0.8 },
              ],
              confidence: 92,
              inputSnapshot: { sampleSize: sample.length, engineName },
            });
            break;
          }
          case "posture": {
            const scoreResult = await calculatePostureScore(orgId);
            simulatedResult = {
              currentScore: scoreResult,
              weights: activePolicy,
              note: "Dry-run preview: posture score calculated with current settings",
            };

            await storage.createEngineExplainabilityLog({
              orgId,
              engineName,
              executionId: dryRun.id,
              decisionType: "posture_scoring",
              decisionOutcome: `Overall score: ${scoreResult.overallScore}`,
              drivers: [
                {
                  factor: "cspm_weight",
                  value: activePolicy.cspmWeight ?? 35,
                  weight: ((activePolicy.cspmWeight as number) ?? 35) / 100,
                },
                {
                  factor: "endpoint_weight",
                  value: activePolicy.endpointWeight ?? 30,
                  weight: ((activePolicy.endpointWeight as number) ?? 30) / 100,
                },
                {
                  factor: "incident_weight",
                  value: activePolicy.incidentWeight ?? 20,
                  weight: ((activePolicy.incidentWeight as number) ?? 20) / 100,
                },
                {
                  factor: "compliance_weight",
                  value: activePolicy.complianceWeight ?? 15,
                  weight: ((activePolicy.complianceWeight as number) ?? 15) / 100,
                },
              ],
              confidence: 95,
              inputSnapshot: { orgId, engineName },
            });
            break;
          }
          case "rollback": {
            const actionTypes = ["isolate_host", "block_ip", "disable_user", "quarantine_file", "restart_service"];
            const rollbackability = actionTypes.map((action) => ({
              actionType: action,
              canRollback: canRollback(action),
            }));
            simulatedResult = {
              rollbackability,
              currentSettings: activePolicy,
              note: "Dry-run preview: no rollback actions were executed",
            };

            await storage.createEngineExplainabilityLog({
              orgId,
              engineName,
              executionId: dryRun.id,
              decisionType: "rollback_assessment",
              decisionOutcome: `${rollbackability.filter((r) => r.canRollback).length}/${actionTypes.length} actions reversible`,
              drivers: rollbackability.map((r) => ({
                factor: r.actionType,
                value: r.canRollback,
                weight: r.canRollback ? 1.0 : 0.0,
              })),
              confidence: 100,
              inputSnapshot: { actionTypes, engineName },
            });
            break;
          }
        }
      } catch (engineError) {
        status = "failed";
        simulatedResult = { error: String(engineError) };
        logger.child("engine-controls").error("Dry-run execution error", { engineName, error: String(engineError) });
      }

      const durationMs = Date.now() - startTime;
      const updated = await storage.updateEngineDryRun(dryRun.id, {
        simulatedResult,
        status,
        durationMs,
      });

      await storage.upsertEngineConfig(orgId, engineName, {
        lastDryRunAt: new Date(),
        lastDryRunResult: simulatedResult,
      });

      res.json(updated);
    } catch (error) {
      logger.child("engine-controls").error("Failed to execute dry-run", { error: String(error) });
      res.status(500).json({ message: "Failed to execute dry-run" });
    }
  });

  app.get("/api/engine-controls/:engine/dry-runs", ...authChain, async (req, res) => {
    try {
      const engineName = String(req.params.engine);
      if (!validateEngineName(engineName)) {
        return res.status(400).json({ message: `Invalid engine: ${engineName}` });
      }
      const orgId = getOrgId(req);
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const runs = await storage.getEngineDryRuns(orgId, engineName, limit);
      res.json(runs);
    } catch (error) {
      logger.child("engine-controls").error("Failed to fetch dry-runs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch dry-runs" });
    }
  });

  app.get("/api/engine-controls/:engine/explain", ...authChain, async (req, res) => {
    try {
      const engineName = String(req.params.engine);
      if (!validateEngineName(engineName)) {
        return res.status(400).json({ message: `Invalid engine: ${engineName}` });
      }
      const orgId = getOrgId(req);
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 200);
      const logs = await storage.getEngineExplainabilityLogs(orgId, engineName, limit);
      res.json(logs);
    } catch (error) {
      logger.child("engine-controls").error("Failed to fetch explainability logs", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch explainability logs" });
    }
  });

  app.get("/api/engine-controls/defaults/:engine", ...authChain, async (req, res) => {
    try {
      const engineName = String(req.params.engine);
      if (!validateEngineName(engineName)) {
        return res.status(400).json({ message: `Invalid engine: ${engineName}` });
      }
      res.json(DEFAULT_POLICIES[engineName]);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch defaults" });
    }
  });
}
