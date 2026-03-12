import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getChaosStats,
  getAttackLibrary,
  getSimulationResults,
  runSimulation,
  runBatchSimulation,
  getControlScores,
  getDetectionGaps,
  getValidationSchedules,
  createValidationSchedule,
  updateValidationSchedule,
  deleteValidationSchedule,
  runScheduledValidation,
  getPurpleTeamResults,
  getPurpleTeamScenarios,
  runPurpleTeamExercise,
  getMitreHeatmapData,
  MITRE_TACTICS,
} from "../chaos-engineering-engine";

const VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const VALID_STATUSES = ["pending", "running", "passed", "failed", "error"] as const;
const VALID_FREQUENCIES = ["daily", "weekly", "monthly"] as const;

export function registerChaosEngineeringRoutes(app: Express): void {
  // ─── Stats ───────────────────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getChaosStats(orgId));
    } catch (error) {
      logger.child("routes").error("Chaos stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch chaos engineering stats" });
    }
  });

  // ─── MITRE Tactics ───────────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/tactics", isAuthenticated, async (_req, res) => {
    try {
      res.json(MITRE_TACTICS);
    } catch (error) {
      logger.child("routes").error("Tactics error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch MITRE tactics" });
    }
  });

  // ─── Attack Library ──────────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/library", isAuthenticated, async (req, res) => {
    try {
      const tacticId = typeof req.query.tacticId === "string" ? req.query.tacticId : undefined;
      const severity =
        typeof req.query.severity === "string" &&
        VALID_SEVERITIES.includes(req.query.severity as (typeof VALID_SEVERITIES)[number])
          ? req.query.severity
          : undefined;
      const platform = typeof req.query.platform === "string" ? req.query.platform : undefined;
      res.json(getAttackLibrary(tacticId, severity, platform));
    } catch (error) {
      logger.child("routes").error("Attack library error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack library" });
    }
  });

  // ─── Simulation Results ──────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/simulations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { tacticId?: string; status?: string; severity?: string } = {};
      if (typeof req.query.tacticId === "string") filters.tacticId = req.query.tacticId;
      if (
        typeof req.query.status === "string" &&
        VALID_STATUSES.includes(req.query.status as (typeof VALID_STATUSES)[number])
      )
        filters.status = req.query.status;
      if (
        typeof req.query.severity === "string" &&
        VALID_SEVERITIES.includes(req.query.severity as (typeof VALID_SEVERITIES)[number])
      )
        filters.severity = req.query.severity;
      res.json(getSimulationResults(orgId, filters));
    } catch (error) {
      logger.child("routes").error("Simulations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch simulations" });
    }
  });

  // ─── Run Simulation ──────────────────────────────────────────────────────────
  app.post("/api/chaos-engineering/simulate", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { techniqueId, trigger } = req.body as { techniqueId?: string; trigger?: string };
      if (!techniqueId || typeof techniqueId !== "string") {
        return res.status(400).json({ message: "techniqueId is required" });
      }
      const result = runSimulation(orgId, techniqueId, trigger || "manual");
      res.status(201).json(result);
    } catch (error) {
      const msg = String(error);
      if (msg.includes("TECHNIQUE_NOT_FOUND")) return res.status(404).json({ message: "Technique not found" });
      logger.child("routes").error("Run simulation error", { error: msg });
      res.status(500).json({ message: "Failed to run simulation" });
    }
  });

  // ─── Run Batch Simulation ────────────────────────────────────────────────────
  app.post("/api/chaos-engineering/simulate-batch", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { techniqueIds, trigger } = req.body as { techniqueIds?: string[]; trigger?: string };
      if (!Array.isArray(techniqueIds) || techniqueIds.length === 0) {
        return res.status(400).json({ message: "techniqueIds must be a non-empty array" });
      }
      if (techniqueIds.length > 100) {
        return res.status(400).json({ message: "Maximum 100 techniques per batch" });
      }
      const results = runBatchSimulation(orgId, techniqueIds, trigger || "manual");
      res.status(201).json({ count: results.length, results });
    } catch (error) {
      logger.child("routes").error("Batch simulation error", { error: String(error) });
      res.status(500).json({ message: "Failed to run batch simulation" });
    }
  });

  // ─── Control Effectiveness ───────────────────────────────────────────────────
  app.get("/api/chaos-engineering/controls", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sortBy = typeof req.query.sortBy === "string" ? req.query.sortBy : undefined;
      res.json(getControlScores(orgId, sortBy));
    } catch (error) {
      logger.child("routes").error("Control scores error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch control scores" });
    }
  });

  // ─── Detection Gaps ──────────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/gaps", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const coverageStatus = typeof req.query.coverageStatus === "string" ? req.query.coverageStatus : undefined;
      const priority = typeof req.query.priority === "string" ? req.query.priority : undefined;
      res.json(getDetectionGaps(orgId, coverageStatus, priority));
    } catch (error) {
      logger.child("routes").error("Detection gaps error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch detection gaps" });
    }
  });

  // ─── MITRE Heatmap ───────────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/heatmap", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getMitreHeatmapData(orgId));
    } catch (error) {
      logger.child("routes").error("Heatmap error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch heatmap data" });
    }
  });

  // ─── Validation Schedules ────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/schedules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getValidationSchedules(orgId));
    } catch (error) {
      logger.child("routes").error("Schedules error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch schedules" });
    }
  });

  app.post("/api/chaos-engineering/schedules", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;
      if (!body.name || typeof body.name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!body.frequency || !VALID_FREQUENCIES.includes(body.frequency)) {
        return res.status(400).json({ message: `frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` });
      }
      if (!Array.isArray(body.techniqueIds) || body.techniqueIds.length === 0) {
        return res.status(400).json({ message: "techniqueIds must be a non-empty array" });
      }
      const schedule = createValidationSchedule(orgId, {
        name: body.name,
        description: body.description || "",
        frequency: body.frequency,
        techniqueIds: body.techniqueIds,
        enabled: body.enabled !== false,
      });
      res.status(201).json(schedule);
    } catch (error) {
      logger.child("routes").error("Create schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to create schedule" });
    }
  });

  app.patch("/api/chaos-engineering/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const body = req.body;
      const sanitized: Record<string, unknown> = {};
      if (body.name !== undefined) {
        if (typeof body.name !== "string") return res.status(400).json({ message: "name must be a string" });
        sanitized.name = body.name;
      }
      if (body.description !== undefined)
        sanitized.description = typeof body.description === "string" ? body.description : "";
      if (body.frequency !== undefined) {
        if (!VALID_FREQUENCIES.includes(body.frequency))
          return res.status(400).json({ message: `frequency must be one of: ${VALID_FREQUENCIES.join(", ")}` });
        sanitized.frequency = body.frequency;
      }
      if (body.enabled !== undefined) sanitized.enabled = body.enabled === true;
      if (body.techniqueIds !== undefined) {
        if (!Array.isArray(body.techniqueIds))
          return res.status(400).json({ message: "techniqueIds must be an array" });
        sanitized.techniqueIds = body.techniqueIds;
      }
      const updated = updateValidationSchedule(orgId, id, sanitized);
      if (!updated) return res.status(404).json({ message: "Schedule not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to update schedule" });
    }
  });

  app.delete("/api/chaos-engineering/schedules/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const deleted = deleteValidationSchedule(orgId, id);
      if (!deleted) return res.status(404).json({ message: "Schedule not found" });
      res.json({ message: "Schedule deleted" });
    } catch (error) {
      logger.child("routes").error("Delete schedule error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete schedule" });
    }
  });

  app.post("/api/chaos-engineering/schedules/:id/run", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const results = runScheduledValidation(orgId, id);
      res.status(201).json({ count: results.length, results });
    } catch (error) {
      const msg = String(error);
      if (msg.includes("SCHEDULE_NOT_FOUND")) return res.status(404).json({ message: "Schedule not found" });
      logger.child("routes").error("Run schedule error", { error: msg });
      res.status(500).json({ message: "Failed to run scheduled validation" });
    }
  });

  // ─── Purple Team ─────────────────────────────────────────────────────────────
  app.get("/api/chaos-engineering/purple-team/scenarios", isAuthenticated, async (_req, res) => {
    try {
      res.json(getPurpleTeamScenarios());
    } catch (error) {
      logger.child("routes").error("Purple team scenarios error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch scenarios" });
    }
  });

  app.get("/api/chaos-engineering/purple-team/results", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getPurpleTeamResults(orgId));
    } catch (error) {
      logger.child("routes").error("Purple team results error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch results" });
    }
  });

  app.post("/api/chaos-engineering/purple-team/run", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { scenarioId } = req.body as { scenarioId?: string };
      if (!scenarioId || typeof scenarioId !== "string") {
        return res.status(400).json({ message: "scenarioId is required" });
      }
      const result = runPurpleTeamExercise(orgId, scenarioId);
      res.status(201).json(result);
    } catch (error) {
      const msg = String(error);
      if (msg.includes("SCENARIO_NOT_FOUND")) return res.status(404).json({ message: "Scenario not found" });
      logger.child("routes").error("Run purple team error", { error: msg });
      res.status(500).json({ message: "Failed to run purple team exercise" });
    }
  });
}
