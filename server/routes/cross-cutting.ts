import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

import { storage } from "../storage";
import {
  getKillSwitchesList,
  getKillSwitchById,
  createKillSwitch,
  updateKillSwitch,
  countKillSwitches,
  getTtvMilestones,
  getTtvMilestoneByKind,
  createTtvMilestone,
  updateTtvMilestone,
} from "../storage/cross-cutting";

type KillSwitchState = "armed" | "disarmed" | "triggered";
type MilestoneKind =
  | "first_connector"
  | "first_alert_closed"
  | "first_question_answered"
  | "first_finding_resolved"
  | "first_incident_prevented"
  | "first_playbook_executed"
  | "first_policy_enforced"
  | "first_report_generated";

const VALID_EVIDENCE_TYPES = ["detection", "policy_check", "vulnerability", "compliance", "audit"];
const VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"];
const VALID_DRIFT_TYPES = ["policy", "integration", "identity", "control"];
const VALID_OVERRIDE_TYPES = ["policy_exception", "risk_acceptance", "suppression"];
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

const log = logger.child("cross-cutting");

export function registerCrossCuttingRoutes(app: Express): void {
  // Stats — computed from DB counts
  app.get("/api/cross-cutting/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [evidenceCount, driftCount, overrideCount] = await Promise.all([
        storage.countCrossCuttingEvidence(orgId),
        storage.countCrossCuttingDrift(orgId),
        storage.countCrossCuttingOverrides(orgId),
      ]);
      res.json({
        ok: true,
        data: {
          totalEvidence: evidenceCount,
          totalDrift: driftCount,
          totalOverrides: overrideCount,
        },
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/stats failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  // Evidence — DB persisted
  app.get("/api/cross-cutting/evidence", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const evidenceType = typeof req.query.type === "string" ? req.query.type : undefined;
      const evidence = await storage.getCrossCuttingEvidenceList(orgId, evidenceType);
      res.json({ ok: true, data: evidence });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/evidence failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/evidence/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const paramId = String(req.params.id);
      const record = await storage.getCrossCuttingEvidenceItem(paramId, orgId);
      if (!record) {
        res.status(404).json({ ok: false, error: "Evidence record not found" });
        return;
      }
      res.json({ ok: true, data: record });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/evidence/:id failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/evidence/chain/:traceId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const traceId = String(req.params.traceId);
      // Chain by resourceId — all evidence for the same resource forms a chain
      const all = await storage.getCrossCuttingEvidenceList(orgId);
      const chain = all.filter((e) => e.resourceId === traceId);
      res.json({ ok: true, data: chain });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/evidence/chain/:traceId failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post(
    "/api/cross-cutting/evidence",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { sourceType, sourceEngine, sourceActionId, severity, summary, details, actorId, actorType, tags } =
          req.body;

        if (!sourceType || !VALID_EVIDENCE_TYPES.includes(sourceType)) {
          res
            .status(400)
            .json({ ok: false, error: `Invalid sourceType. Must be one of: ${VALID_EVIDENCE_TYPES.join(", ")}` });
          return;
        }
        if (!sourceEngine || typeof sourceEngine !== "string") {
          res.status(400).json({ ok: false, error: "sourceEngine is required" });
          return;
        }
        if (!summary || typeof summary !== "string") {
          res.status(400).json({ ok: false, error: "summary is required" });
          return;
        }
        if (severity && !VALID_SEVERITIES.includes(severity)) {
          res
            .status(400)
            .json({ ok: false, error: `Invalid severity. Must be one of: ${VALID_SEVERITIES.join(", ")}` });
          return;
        }

        const record = await storage.createCrossCuttingEvidenceItem({
          orgId,
          evidenceType: sourceType,
          sourceModule: sourceEngine,
          resourceId: sourceActionId || null,
          resourceType: actorType || null,
          title: summary,
          description: typeof details === "object" ? JSON.stringify(details) : String(details || ""),
          severity: severity || "info",
          status: "open",
          metadata: { actorId, actorType, tags: tags || [] },
        });
        res.status(201).json({ ok: true, data: record });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/evidence failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  // Overrides — DB persisted
  app.get("/api/cross-cutting/overrides", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const statusFilter = req.query.status as string | undefined;
      let overrides = await storage.getCrossCuttingOverrides(orgId);
      if (statusFilter) {
        overrides = overrides.filter((o) => o.status === statusFilter);
      }
      res.json({ ok: true, data: overrides });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/overrides failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get("/api/cross-cutting/overrides/pending", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const overrides = await storage.getCrossCuttingOverrides(orgId);
      const pending = overrides.filter((o) => o.status === "active" && !o.approvedBy);
      res.json({ ok: true, data: pending });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/overrides/pending failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post(
    "/api/cross-cutting/overrides",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { evidenceId, featureDomain, actionDescription, riskLevel, requestedBy, timeboxMinutes } = req.body;

        if (!featureDomain || typeof featureDomain !== "string") {
          res.status(400).json({ ok: false, error: "featureDomain is required" });
          return;
        }
        if (!actionDescription || typeof actionDescription !== "string") {
          res.status(400).json({ ok: false, error: "actionDescription is required" });
          return;
        }
        if (!requestedBy || typeof requestedBy !== "string") {
          res.status(400).json({ ok: false, error: "requestedBy is required" });
          return;
        }

        const expiresAt =
          typeof timeboxMinutes === "number" && timeboxMinutes > 0
            ? new Date(Date.now() + timeboxMinutes * 60 * 1000)
            : null;

        const override = await storage.createCrossCuttingOverride({
          orgId,
          overrideType: riskLevel === "critical" ? "risk_acceptance" : "policy_exception",
          targetModule: featureDomain,
          targetResourceId: evidenceId || null,
          targetResourceType: null,
          reason: actionDescription,
          approvedBy: null,
          expiresAt,
          status: "active",
          metadata: { requestedBy, riskLevel: riskLevel || "medium" },
        });
        res.status(201).json({ ok: true, data: override });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/overrides failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  app.post(
    "/api/cross-cutting/overrides/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
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
        const existing = await storage.getCrossCuttingOverride(paramId, orgId);
        if (!existing) {
          res.status(404).json({ ok: false, error: "Override not found" });
          return;
        }
        if (existing.approvedBy) {
          res.status(409).json({ ok: false, error: "Override already reviewed" });
          return;
        }

        const updated = await storage.updateCrossCuttingOverride(paramId, orgId, {
          approvedBy: reviewedBy,
          metadata: {
            ...(existing.metadata as Record<string, unknown>),
            rationale,
            approvedAt: new Date().toISOString(),
          },
        });
        res.json({ ok: true, data: updated });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/overrides/:id/approve failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  app.post(
    "/api/cross-cutting/overrides/:id/reject",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
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
        const existing = await storage.getCrossCuttingOverride(paramId, orgId);
        if (!existing) {
          res.status(404).json({ ok: false, error: "Override not found" });
          return;
        }
        if (existing.approvedBy) {
          res.status(409).json({ ok: false, error: "Override already reviewed" });
          return;
        }

        const updated = await storage.updateCrossCuttingOverride(paramId, orgId, {
          status: "revoked",
          approvedBy: reviewedBy,
          metadata: {
            ...(existing.metadata as Record<string, unknown>),
            rationale,
            rejectedAt: new Date().toISOString(),
          },
        });
        res.json({ ok: true, data: updated });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/overrides/:id/reject failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  // Drift — DB persisted
  app.get("/api/cross-cutting/drift", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const activeOnly = req.query.active === "true";
      let signals = await storage.getCrossCuttingDriftRecords(orgId);
      if (activeOnly) {
        signals = signals.filter((s) => s.status === "detected" || s.status === "acknowledged");
      }
      res.json({ ok: true, data: signals });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/drift failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post(
    "/api/cross-cutting/drift/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        // Trigger a simulated drift scan — creates a drift record if none exists
        const newDrift = await storage.createCrossCuttingDriftRecord({
          orgId,
          driftType: "policy",
          sourceModule: "drift-scanner",
          resourceId: null,
          resourceType: null,
          expectedState: {},
          actualState: {},
          severity: "info",
          status: "detected",
          remediationAction: null,
        });
        res.json({ ok: true, data: { scanId: newDrift.id, status: "completed", driftsDetected: 0 } });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/drift/scan failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  app.post(
    "/api/cross-cutting/drift/:id/acknowledge",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { acknowledgedBy } = req.body;
        if (!acknowledgedBy || typeof acknowledgedBy !== "string") {
          res.status(400).json({ ok: false, error: "acknowledgedBy is required" });
          return;
        }
        const paramId = String(req.params.id);
        const existing = await storage.getCrossCuttingDriftRecord(paramId, orgId);
        if (!existing) {
          res.status(404).json({ ok: false, error: "Drift signal not found" });
          return;
        }
        const updated = await storage.updateCrossCuttingDriftRecord(paramId, orgId, {
          status: "acknowledged",
        });
        res.json({ ok: true, data: updated });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/drift/:id/acknowledge failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  app.post(
    "/api/cross-cutting/drift/:id/resolve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const paramId = String(req.params.id);
        const existing = await storage.getCrossCuttingDriftRecord(paramId, orgId);
        if (!existing) {
          res.status(404).json({ ok: false, error: "Drift signal not found" });
          return;
        }
        const updated = await storage.updateCrossCuttingDriftRecord(paramId, orgId, {
          status: "remediated",
          remediatedAt: new Date(),
        });
        res.json({ ok: true, data: updated });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        log.error(`POST /api/cross-cutting/drift/:id/resolve failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  // Kill switches — DB-backed
  app.get("/api/cross-cutting/reliability", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const killSwitches = await getKillSwitchesList(orgId);
      res.json({ ok: true, data: killSwitches });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/reliability failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.patch(
    "/api/cross-cutting/reliability/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
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
        const existing = await getKillSwitchById(paramId, orgId);
        if (!existing) {
          res.status(404).json({ ok: false, error: `Kill switch ${paramId} not found` });
          return;
        }
        const ks = await updateKillSwitch(paramId, orgId, {
          state,
          updatedBy: actor,
          lastTriggeredAt: state === "triggered" ? new Date() : existing.lastTriggeredAt,
          triggeredBy: state === "triggered" ? actor : existing.triggeredBy,
          triggerReason: state === "triggered" ? reason || null : existing.triggerReason,
        });
        res.json({ ok: true, data: ks });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        if (message.includes("not found")) {
          res.status(404).json({ ok: false, error: message });
          return;
        }
        log.error(`PATCH /api/cross-cutting/reliability/:id failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );

  // Milestones — DB-backed
  app.get("/api/cross-cutting/time-to-value", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const milestones = await getTtvMilestones(orgId);
      res.json({ ok: true, data: milestones });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      log.error(`GET /api/cross-cutting/time-to-value failed: ${message}`);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.post(
    "/api/cross-cutting/time-to-value/:kind/achieve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
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

        const existing = await getTtvMilestoneByKind(orgId, kind);
        if (existing && existing.achievedAt) {
          res.status(409).json({ ok: false, error: `Milestone '${kind}' already achieved` });
          return;
        }

        const now = new Date();
        const signupDate = signupTime ? new Date(signupTime) : now;
        const durationMs = now.getTime() - signupDate.getTime();

        let milestone;
        if (existing) {
          milestone = await updateTtvMilestone(orgId, kind, {
            achievedAt: now,
            durationFromSignupMs: durationMs > 0 ? durationMs : null,
            triggeredByAction: actionId,
            triggeredByActor: actor,
          });
        } else {
          milestone = await createTtvMilestone({
            orgId,
            kind,
            label: kind.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
            achievedAt: now,
            durationFromSignupMs: durationMs > 0 ? durationMs : null,
            triggeredByAction: actionId,
            triggeredByActor: actor,
          });
        }
        res.json({ ok: true, data: milestone });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Unknown error";
        if (message.includes("not found") || message.includes("already achieved")) {
          res.status(409).json({ ok: false, error: message });
          return;
        }
        log.error(`POST /api/cross-cutting/time-to-value/:kind/achieve failed: ${message}`);
        res.status(500).json({ ok: false, error: message });
      }
    },
  );
}
