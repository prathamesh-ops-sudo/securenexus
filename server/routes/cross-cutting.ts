import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getEvidence,
  getEvidenceById,
  getEvidenceChain,
  recordEvidence,
  getOverrides,
  getPendingOverrides,
  requestOverride,
  approveOverride,
  rejectOverride,
  getDriftSignals,
  getActiveDrift,
  triggerDriftScan,
  acknowledgeDrift,
  resolveDrift,
  getKillSwitches,
  toggleKillSwitch,
  getMilestones,
  achieveMilestone,
  getCrossCuttingStats,
} from "../cross-cutting-engine";
import type { EvidenceSourceType, EvidenceSeverity, KillSwitchState, MilestoneKind } from "../cross-cutting-engine";

const VALID_SOURCE_TYPES: EvidenceSourceType[] = [
  "detection",
  "correlation",
  "prediction",
  "remediation",
  "policy_decision",
  "posture_score",
  "connector_sync",
  "adversarial_test",
  "agent_action",
  "browser_event",
  "drift_signal",
  "manual_entry",
];

const VALID_SEVERITIES: EvidenceSeverity[] = ["info", "low", "medium", "high", "critical"];

const VALID_RISK_LEVELS = ["low", "medium", "high", "critical"] as const;

const VALID_KILL_SWITCH_STATES: KillSwitchState[] = ["armed", "disarmed", "triggered"];

const VALID_MILESTONE_KINDS: MilestoneKind[] = [
  "first_connector",
  "first_alert_closed",
  "first_question_answered",
  "first_finding_resolved",
  "first_incident_prevented",
  "first_playbook_executed",
  "first_policy_enforced",
  "first_report_generated",
];

export function registerCrossCuttingRoutes(app: Express): void {
  app.get("/api/cross-cutting/stats", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = getCrossCuttingStats(orgId);
      res.json({ ok: true, data: stats });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/stats failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/evidence", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const evidence = getEvidence(orgId);
      res.json({ ok: true, data: evidence });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/evidence failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/evidence/:id", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const paramId = String(req.params.id);
      const record = getEvidenceById(orgId, paramId);
      if (!record) {
        res.status(404).json({ ok: false, error: "Evidence record not found" });
        return;
      }
      res.json({ ok: true, data: record });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/evidence/:id failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/evidence/chain/:traceId", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const traceId = String(req.params.traceId);
      const chain = getEvidenceChain(orgId, traceId);
      res.json({ ok: true, data: chain });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/evidence/chain/:traceId failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/evidence", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const {
        sourceType,
        sourceEngine,
        sourceActionId,
        severity,
        summary,
        details,
        parentEvidenceId,
        actorId,
        actorType,
        tags,
      } = req.body;

      if (!sourceType || !VALID_SOURCE_TYPES.includes(sourceType)) {
        res
          .status(400)
          .json({ ok: false, error: `Invalid sourceType. Must be one of: ${VALID_SOURCE_TYPES.join(", ")}` });
        return;
      }
      if (!sourceEngine || typeof sourceEngine !== "string") {
        res.status(400).json({ ok: false, error: "sourceEngine is required" });
        return;
      }
      if (!sourceActionId || typeof sourceActionId !== "string") {
        res.status(400).json({ ok: false, error: "sourceActionId is required" });
        return;
      }
      if (!severity || !VALID_SEVERITIES.includes(severity)) {
        res.status(400).json({ ok: false, error: `Invalid severity. Must be one of: ${VALID_SEVERITIES.join(", ")}` });
        return;
      }
      if (!summary || typeof summary !== "string") {
        res.status(400).json({ ok: false, error: "summary is required" });
        return;
      }
      if (!actorId || typeof actorId !== "string") {
        res.status(400).json({ ok: false, error: "actorId is required" });
        return;
      }
      if (!actorType || !["user", "agent", "service", "system"].includes(actorType)) {
        res.status(400).json({ ok: false, error: "actorType must be user, agent, service, or system" });
        return;
      }

      const record = recordEvidence(orgId, {
        sourceType,
        sourceEngine,
        sourceActionId,
        severity,
        summary,
        details: details ?? {},
        parentEvidenceId,
        actorId,
        actorType,
        tags,
      });
      res.status(201).json({ ok: true, data: record });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`POST /api/cross-cutting/evidence failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/overrides", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const statusFilter = req.query.status as string | undefined;
      let overrides = getOverrides(orgId);
      if (statusFilter) {
        overrides = overrides.filter((o) => o.status === statusFilter);
      }
      res.json({ ok: true, data: overrides });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/overrides failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/overrides/pending", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const pending = getPendingOverrides(orgId);
      res.json({ ok: true, data: pending });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/overrides/pending failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/overrides", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { evidenceId, featureDomain, actionDescription, riskLevel, requestedBy, timeboxMinutes } = req.body;

      if (!evidenceId || typeof evidenceId !== "string") {
        res.status(400).json({ ok: false, error: "evidenceId is required" });
        return;
      }
      if (!featureDomain || typeof featureDomain !== "string") {
        res.status(400).json({ ok: false, error: "featureDomain is required" });
        return;
      }
      if (!actionDescription || typeof actionDescription !== "string") {
        res.status(400).json({ ok: false, error: "actionDescription is required" });
        return;
      }
      if (!riskLevel || !VALID_RISK_LEVELS.includes(riskLevel)) {
        res
          .status(400)
          .json({ ok: false, error: `Invalid riskLevel. Must be one of: ${VALID_RISK_LEVELS.join(", ")}` });
        return;
      }
      if (!requestedBy || typeof requestedBy !== "string") {
        res.status(400).json({ ok: false, error: "requestedBy is required" });
        return;
      }

      const override = requestOverride(orgId, {
        evidenceId,
        featureDomain,
        actionDescription,
        riskLevel,
        requestedBy,
        timeboxMinutes,
      });
      res.status(201).json({ ok: true, data: override });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`POST /api/cross-cutting/overrides failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/overrides/:id/approve", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { reviewedBy, rationale } = req.body;

      if (!reviewedBy || typeof reviewedBy !== "string") {
        res.status(400).json({ ok: false, error: "reviewedBy is required" });
        return;
      }
      if (!rationale || typeof rationale !== "string") {
        res.status(400).json({ ok: false, error: "rationale is required" });
        return;
      }

      const paramId = String(req.params.id);
      const override = approveOverride(orgId, paramId, reviewedBy, rationale);
      res.json({ ok: true, data: override });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("not found")) {
        res.status(404).json({ ok: false, error: message });
        return;
      }
      if (message.includes("not pending")) {
        res.status(409).json({ ok: false, error: message });
        return;
      }
      logger.error(`POST /api/cross-cutting/overrides/:id/approve failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/overrides/:id/reject", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { reviewedBy, rationale } = req.body;

      if (!reviewedBy || typeof reviewedBy !== "string") {
        res.status(400).json({ ok: false, error: "reviewedBy is required" });
        return;
      }
      if (!rationale || typeof rationale !== "string") {
        res.status(400).json({ ok: false, error: "rationale is required" });
        return;
      }

      const paramId = String(req.params.id);
      const override = rejectOverride(orgId, paramId, reviewedBy, rationale);
      res.json({ ok: true, data: override });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("not found")) {
        res.status(404).json({ ok: false, error: message });
        return;
      }
      if (message.includes("not pending")) {
        res.status(409).json({ ok: false, error: message });
        return;
      }
      logger.error(`POST /api/cross-cutting/overrides/:id/reject failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/drift", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const activeOnly = req.query.active === "true";
      const signals = activeOnly ? getActiveDrift(orgId) : getDriftSignals(orgId);
      res.json({ ok: true, data: signals });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/drift failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/drift/scan", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const result = triggerDriftScan(orgId);
      res.json({ ok: true, data: result });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`POST /api/cross-cutting/drift/scan failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/drift/:id/acknowledge", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { acknowledgedBy } = req.body;
      if (!acknowledgedBy || typeof acknowledgedBy !== "string") {
        res.status(400).json({ ok: false, error: "acknowledgedBy is required" });
        return;
      }
      const paramId = String(req.params.id);
      const signal = acknowledgeDrift(orgId, paramId, acknowledgedBy);
      res.json({ ok: true, data: signal });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("not found")) {
        res.status(404).json({ ok: false, error: message });
        return;
      }
      logger.error(`POST /api/cross-cutting/drift/:id/acknowledge failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/drift/:id/resolve", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const paramId = String(req.params.id);
      const signal = resolveDrift(orgId, paramId);
      res.json({ ok: true, data: signal });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("not found")) {
        res.status(404).json({ ok: false, error: message });
        return;
      }
      logger.error(`POST /api/cross-cutting/drift/:id/resolve failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/reliability", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const killSwitches = getKillSwitches(orgId);
      res.json({ ok: true, data: killSwitches });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/reliability failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.patch("/api/cross-cutting/reliability/:id", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { state, actor, reason } = req.body;

      if (!state || !VALID_KILL_SWITCH_STATES.includes(state)) {
        res
          .status(400)
          .json({ ok: false, error: `Invalid state. Must be one of: ${VALID_KILL_SWITCH_STATES.join(", ")}` });
        return;
      }
      if (!actor || typeof actor !== "string") {
        res.status(400).json({ ok: false, error: "actor is required" });
        return;
      }

      const paramId = String(req.params.id);
      const ks = toggleKillSwitch(orgId, paramId, state, actor, reason);
      res.json({ ok: true, data: ks });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("not found")) {
        res.status(404).json({ ok: false, error: message });
        return;
      }
      logger.error(`PATCH /api/cross-cutting/reliability/:id failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/time-to-value", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const milestones = getMilestones(orgId);
      res.json({ ok: true, data: milestones });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`GET /api/cross-cutting/time-to-value failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post("/api/cross-cutting/time-to-value/:kind/achieve", isAuthenticated, (req, res) => {
    try {
      const orgId = getOrgId(req);
      const kind = req.params.kind as MilestoneKind;
      if (!VALID_MILESTONE_KINDS.includes(kind)) {
        res
          .status(400)
          .json({ ok: false, error: `Invalid milestone kind. Must be one of: ${VALID_MILESTONE_KINDS.join(", ")}` });
        return;
      }

      const { actor, actionId, signupTime } = req.body;
      if (!actor || typeof actor !== "string") {
        res.status(400).json({ ok: false, error: "actor is required" });
        return;
      }
      if (!actionId || typeof actionId !== "string") {
        res.status(400).json({ ok: false, error: "actionId is required" });
        return;
      }

      const milestone = achieveMilestone(orgId, kind, actor, actionId, signupTime);
      res.json({ ok: true, data: milestone });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("not found") || message.includes("already achieved")) {
        res.status(409).json({ ok: false, error: message });
        return;
      }
      logger.error(`POST /api/cross-cutting/time-to-value/:kind/achieve failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });
}
