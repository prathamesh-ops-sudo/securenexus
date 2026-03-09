import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getCopilotTriages,
  getTriageById,
  generateTriage,
  updateTriageNotes,
  getCopilotTimelines,
  getTimelineById,
  getCopilotHypotheses,
  updateHypothesisStatus,
  getCopilotActions,
  approveAction,
  rejectAction,
  rollbackAction,
  getCopilotFeedback,
  submitFeedback,
  getCopilotCalibrations,
  getCopilotStats,
  type ActionClass,
  type ActionStatus,
  type TriageVerdict,
  type HypothesisConfidence,
  type FeedbackOutcome,
  type CopilotDomain,
} from "../soc-copilot-engine";

const VALID_VERDICTS: TriageVerdict[] = ["true_positive", "false_positive", "needs_investigation", "benign"];
const VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"];
const VALID_ACTION_CLASSES: ActionClass[] = ["READ", "SUGGEST", "EXECUTE_WITH_APPROVAL", "AUTO_EXECUTE_LOW_RISK"];
const VALID_ACTION_STATUSES: ActionStatus[] = [
  "pending_approval",
  "approved",
  "rejected",
  "executed",
  "rolled_back",
  "auto_executed",
];
const VALID_HYPOTHESIS_CONFIDENCES: HypothesisConfidence[] = ["high", "medium", "low"];
const VALID_HYPOTHESIS_STATUSES = ["active", "confirmed", "rejected", "superseded"];
const VALID_FEEDBACK_OUTCOMES: FeedbackOutcome[] = ["accepted", "overridden", "dismissed"];
const VALID_COPILOT_DOMAINS: CopilotDomain[] = ["triage", "timeline", "hypothesis", "enrichment", "policy"];

export function registerSocCopilotRoutes(app: Express): void {
  app.get("/api/soc-copilot/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getCopilotStats(orgId));
    } catch (error) {
      logger.child("routes").error("SOC copilot stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch SOC copilot stats" });
    }
  });

  app.get("/api/soc-copilot/triages", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { verdict?: TriageVerdict; severity?: string } = {};
      if (typeof req.query.verdict === "string" && VALID_VERDICTS.includes(req.query.verdict as TriageVerdict))
        filters.verdict = req.query.verdict as TriageVerdict;
      if (typeof req.query.severity === "string" && VALID_SEVERITIES.includes(req.query.severity))
        filters.severity = req.query.severity;
      res.json(getCopilotTriages(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot triages error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch triages" });
    }
  });

  app.get("/api/soc-copilot/triages/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const triage = getTriageById(orgId, id);
      if (!triage) return res.status(404).json({ message: "Triage not found" });
      res.json(triage);
    } catch (error) {
      logger.child("routes").error("Get triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch triage" });
    }
  });

  app.post("/api/soc-copilot/triages", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { alertId, alertTitle, severity } = req.body as {
        alertId?: string;
        alertTitle?: string;
        severity?: string;
      };
      if (!alertId || typeof alertId !== "string") return res.status(400).json({ message: "alertId is required" });
      if (!alertTitle || typeof alertTitle !== "string")
        return res.status(400).json({ message: "alertTitle is required" });
      if (!severity || !VALID_SEVERITIES.includes(severity))
        return res.status(400).json({ message: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` });
      const triage = generateTriage(orgId, alertId, alertTitle, severity);
      res.status(201).json(triage);
    } catch (error) {
      logger.child("routes").error("Generate triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to generate triage" });
    }
  });

  app.patch("/api/soc-copilot/triages/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { analystNotes } = req.body as { analystNotes?: string };
      if (analystNotes === undefined || typeof analystNotes !== "string")
        return res.status(400).json({ message: "analystNotes must be a string" });
      const updated = updateTriageNotes(orgId, id, analystNotes);
      if (!updated) return res.status(404).json({ message: "Triage not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to update triage" });
    }
  });

  app.get("/api/soc-copilot/timelines", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getCopilotTimelines(orgId));
    } catch (error) {
      logger.child("routes").error("SOC copilot timelines error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch timelines" });
    }
  });

  app.get("/api/soc-copilot/timelines/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const timeline = getTimelineById(orgId, id);
      if (!timeline) return res.status(404).json({ message: "Timeline not found" });
      res.json(timeline);
    } catch (error) {
      logger.child("routes").error("Get timeline error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch timeline" });
    }
  });

  app.get("/api/soc-copilot/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { incidentId?: string; confidence?: HypothesisConfidence; status?: string } = {};
      if (typeof req.query.incidentId === "string") filters.incidentId = req.query.incidentId;
      if (
        typeof req.query.confidence === "string" &&
        VALID_HYPOTHESIS_CONFIDENCES.includes(req.query.confidence as HypothesisConfidence)
      )
        filters.confidence = req.query.confidence as HypothesisConfidence;
      if (typeof req.query.status === "string" && VALID_HYPOTHESIS_STATUSES.includes(req.query.status))
        filters.status = req.query.status;
      res.json(getCopilotHypotheses(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot hypotheses error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch hypotheses" });
    }
  });

  app.patch("/api/soc-copilot/hypotheses/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const body = req.body;
      if (body.status !== undefined && !VALID_HYPOTHESIS_STATUSES.includes(body.status)) {
        return res.status(400).json({ message: `status must be one of: ${VALID_HYPOTHESIS_STATUSES.join(", ")}` });
      }
      if (body.status === undefined) {
        return res.status(400).json({ message: "status is required" });
      }
      const feedback = typeof body.analystFeedback === "string" ? body.analystFeedback : undefined;
      const updated = updateHypothesisStatus(orgId, id, body.status, feedback);
      if (!updated) return res.status(404).json({ message: "Hypothesis not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update hypothesis error", { error: String(error) });
      res.status(500).json({ message: "Failed to update hypothesis" });
    }
  });

  app.get("/api/soc-copilot/actions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { actionClass?: ActionClass; status?: ActionStatus } = {};
      if (
        typeof req.query.actionClass === "string" &&
        VALID_ACTION_CLASSES.includes(req.query.actionClass as ActionClass)
      )
        filters.actionClass = req.query.actionClass as ActionClass;
      if (typeof req.query.status === "string" && VALID_ACTION_STATUSES.includes(req.query.status as ActionStatus))
        filters.status = req.query.status as ActionStatus;
      res.json(getCopilotActions(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot actions error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch actions" });
    }
  });

  app.post("/api/soc-copilot/actions/:id/approve", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { analystId } = req.body as { analystId?: string };
      if (!analystId || typeof analystId !== "string")
        return res.status(400).json({ message: "analystId is required" });
      const result = approveAction(orgId, id, analystId);
      if (!result) return res.status(404).json({ message: "Action not found or not pending approval" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Approve action error", { error: String(error) });
      res.status(500).json({ message: "Failed to approve action" });
    }
  });

  app.post("/api/soc-copilot/actions/:id/reject", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { analystId } = req.body as { analystId?: string };
      if (!analystId || typeof analystId !== "string")
        return res.status(400).json({ message: "analystId is required" });
      const result = rejectAction(orgId, id, analystId);
      if (!result) return res.status(404).json({ message: "Action not found or not pending approval" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Reject action error", { error: String(error) });
      res.status(500).json({ message: "Failed to reject action" });
    }
  });

  app.post("/api/soc-copilot/actions/:id/rollback", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const result = rollbackAction(orgId, id);
      if (!result) return res.status(404).json({ message: "Action not found or not eligible for rollback" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Rollback action error", { error: String(error) });
      res.status(500).json({ message: "Failed to rollback action" });
    }
  });

  app.get("/api/soc-copilot/feedback", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { actionType?: CopilotDomain; outcome?: FeedbackOutcome } = {};
      if (
        typeof req.query.actionType === "string" &&
        VALID_COPILOT_DOMAINS.includes(req.query.actionType as CopilotDomain)
      )
        filters.actionType = req.query.actionType as CopilotDomain;
      if (
        typeof req.query.outcome === "string" &&
        VALID_FEEDBACK_OUTCOMES.includes(req.query.outcome as FeedbackOutcome)
      )
        filters.outcome = req.query.outcome as FeedbackOutcome;
      res.json(getCopilotFeedback(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot feedback error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch feedback" });
    }
  });

  app.post("/api/soc-copilot/feedback", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = req.body;
      if (!body.actionId || typeof body.actionId !== "string")
        return res.status(400).json({ message: "actionId is required" });
      if (!body.actionType || !VALID_COPILOT_DOMAINS.includes(body.actionType))
        return res.status(400).json({ message: `actionType must be one of: ${VALID_COPILOT_DOMAINS.join(", ")}` });
      if (!body.outcome || !VALID_FEEDBACK_OUTCOMES.includes(body.outcome))
        return res.status(400).json({ message: `outcome must be one of: ${VALID_FEEDBACK_OUTCOMES.join(", ")}` });
      if (!body.analystId || typeof body.analystId !== "string")
        return res.status(400).json({ message: "analystId is required" });
      if (!body.originalSuggestion || typeof body.originalSuggestion !== "string")
        return res.status(400).json({ message: "originalSuggestion is required" });
      if (!body.reason || typeof body.reason !== "string")
        return res.status(400).json({ message: "reason is required" });

      const record = submitFeedback(orgId, {
        actionId: body.actionId,
        actionType: body.actionType,
        outcome: body.outcome,
        analystId: body.analystId,
        originalSuggestion: body.originalSuggestion,
        analystOverride: typeof body.analystOverride === "string" ? body.analystOverride : null,
        reason: body.reason,
        impactOnPolicy: typeof body.impactOnPolicy === "string" ? body.impactOnPolicy : null,
      });
      res.status(201).json(record);
    } catch (error) {
      logger.child("routes").error("Submit feedback error", { error: String(error) });
      res.status(500).json({ message: "Failed to submit feedback" });
    }
  });

  app.get("/api/soc-copilot/calibrations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getCopilotCalibrations(orgId));
    } catch (error) {
      logger.child("routes").error("SOC copilot calibrations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch calibrations" });
    }
  });
}
