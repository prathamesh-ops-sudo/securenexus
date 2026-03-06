import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getPolicies,
  getPolicyById,
  createPolicy,
  updatePolicy,
  evaluateAction,
  simulatePolicy,
  getDecisionLogs,
  getSimulations,
  requestEmergencyOverride,
  approveEmergencyOverride,
  denyEmergencyOverride,
  getOverrides,
  getGuardrailStats,
} from "../runtime-guardrails-engine";
import type { PolicyAction, PolicyMode, PolicyDecisionVerdict, PolicyScope } from "../runtime-guardrails-engine";

const VALID_ACTIONS: PolicyAction[] = [
  "ai_agent_invoke",
  "ai_agent_tool_call",
  "api_outbound_call",
  "browser_navigation",
  "secret_access",
  "data_egress",
  "file_write",
  "shell_exec",
  "db_query",
  "webhook_dispatch",
];

const VALID_MODES: PolicyMode[] = ["enforce", "dry_run", "audit_only", "disabled"];

const VALID_VERDICTS: PolicyDecisionVerdict[] = ["allow", "deny", "quarantine"];

const VALID_SCOPES: PolicyScope[] = [
  "ai_agent",
  "tool_api",
  "browser_workflow",
  "secret_egress",
  "data_pipeline",
  "global",
];

function isValidAction(val: string): val is PolicyAction {
  return VALID_ACTIONS.includes(val as PolicyAction);
}

function isValidMode(val: string): val is PolicyMode {
  return VALID_MODES.includes(val as PolicyMode);
}

function isValidVerdict(val: string): val is PolicyDecisionVerdict {
  return VALID_VERDICTS.includes(val as PolicyDecisionVerdict);
}

function isValidScope(val: string): val is PolicyScope {
  return VALID_SCOPES.includes(val as PolicyScope);
}

export function registerRuntimeGuardrailsRoutes(app: Express): void {
  app.get("/api/runtime-guardrails/policies", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const policies = getPolicies(orgId);
      res.json(policies);
    } catch (error) {
      logger.child("routes").error("List guardrail policies error", { error: String(error) });
      res.status(500).json({ message: "Failed to list policies" });
    }
  });

  app.get("/api/runtime-guardrails/stats", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const stats = getGuardrailStats(orgId);
      res.json(stats);
    } catch (error) {
      logger.child("routes").error("Guardrail stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch guardrail stats" });
    }
  });

  app.get("/api/runtime-guardrails/decisions", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const decisions = getDecisionLogs(orgId);
      res.json(decisions);
    } catch (error) {
      logger.child("routes").error("List decision logs error", { error: String(error) });
      res.status(500).json({ message: "Failed to list decision logs" });
    }
  });

  app.get("/api/runtime-guardrails/simulations", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const simulations = getSimulations(orgId);
      res.json(simulations);
    } catch (error) {
      logger.child("routes").error("List simulations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list simulations" });
    }
  });

  app.get("/api/runtime-guardrails/overrides", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const overrides = getOverrides(orgId);
      res.json(overrides);
    } catch (error) {
      logger.child("routes").error("List overrides error", { error: String(error) });
      res.status(500).json({ message: "Failed to list overrides" });
    }
  });

  app.get("/api/runtime-guardrails/policies/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const policy = getPolicyById(id, orgId);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(policy);
    } catch (error) {
      logger.child("routes").error("Get policy error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch policy" });
    }
  });

  app.post("/api/runtime-guardrails/policies", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;

      if (!body.name || typeof body.name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!body.scope || !isValidScope(body.scope)) {
        return res.status(400).json({ message: `Invalid scope. Must be one of: ${VALID_SCOPES.join(", ")}` });
      }
      if (!body.mode || !isValidMode(body.mode)) {
        return res.status(400).json({ message: `Invalid mode. Must be one of: ${VALID_MODES.join(", ")}` });
      }
      if (!body.verdict || !isValidVerdict(body.verdict)) {
        return res.status(400).json({ message: `Invalid verdict. Must be one of: ${VALID_VERDICTS.join(", ")}` });
      }
      if (!Array.isArray(body.actions) || body.actions.length === 0) {
        return res.status(400).json({ message: "actions must be a non-empty array" });
      }
      for (const a of body.actions) {
        if (!isValidAction(a)) {
          return res.status(400).json({ message: `Invalid action: ${a}` });
        }
      }
      if (
        body.priority !== undefined &&
        (typeof body.priority !== "number" || body.priority < 0 || body.priority > 100)
      ) {
        return res.status(400).json({ message: "priority must be between 0 and 100" });
      }

      const policy = createPolicy(orgId, {
        name: body.name,
        description: body.description || "",
        scope: body.scope,
        actions: body.actions,
        mode: body.mode,
        priority: body.priority ?? 50,
        conditions: Array.isArray(body.conditions) ? body.conditions : [],
        verdict: body.verdict,
        rateLimit: body.rateLimit || null,
        tags: Array.isArray(body.tags) ? body.tags : [],
        createdBy: body.createdBy || "api",
      });
      res.status(201).json(policy);
    } catch (error) {
      logger.child("routes").error("Create policy error", { error: String(error) });
      res.status(500).json({ message: "Failed to create policy" });
    }
  });

  app.patch("/api/runtime-guardrails/policies/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const body = req.body;

      if (body.mode !== undefined && !isValidMode(body.mode)) {
        return res.status(400).json({ message: `Invalid mode. Must be one of: ${VALID_MODES.join(", ")}` });
      }
      if (body.verdict !== undefined && !isValidVerdict(body.verdict)) {
        return res.status(400).json({ message: `Invalid verdict. Must be one of: ${VALID_VERDICTS.join(", ")}` });
      }
      if (body.scope !== undefined && !isValidScope(body.scope)) {
        return res.status(400).json({ message: `Invalid scope. Must be one of: ${VALID_SCOPES.join(", ")}` });
      }
      if (body.actions !== undefined) {
        if (!Array.isArray(body.actions)) {
          return res.status(400).json({ message: "actions must be an array" });
        }
        for (const a of body.actions) {
          if (!isValidAction(a)) {
            return res.status(400).json({ message: `Invalid action: ${a}` });
          }
        }
      }
      if (
        body.priority !== undefined &&
        (typeof body.priority !== "number" || body.priority < 0 || body.priority > 100)
      ) {
        return res.status(400).json({ message: "priority must be between 0 and 100" });
      }

      const updated = updatePolicy(id, orgId, body);
      if (!updated) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update policy error", { error: String(error) });
      res.status(500).json({ message: "Failed to update policy" });
    }
  });

  app.post("/api/runtime-guardrails/evaluate", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;

      if (!body.action || !isValidAction(body.action)) {
        return res.status(400).json({ message: `Invalid action. Must be one of: ${VALID_ACTIONS.join(", ")}` });
      }
      if (!body.actorId || typeof body.actorId !== "string") {
        return res.status(400).json({ message: "actorId is required" });
      }
      if (!body.actorType || !["user", "agent", "service"].includes(body.actorType)) {
        return res.status(400).json({ message: "actorType must be user, agent, or service" });
      }

      const decision = evaluateAction(orgId, {
        action: body.action,
        actorId: body.actorId,
        actorType: body.actorType,
        resourceId: body.resourceId || "unknown",
        resourceType: body.resourceType || "unknown",
        context: body.context || {},
      });
      res.json(decision);
    } catch (error) {
      logger.child("routes").error("Evaluate action error", { error: String(error) });
      res.status(500).json({ message: "Failed to evaluate action" });
    }
  });

  app.post("/api/runtime-guardrails/simulate", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;

      if (!body.policyId || typeof body.policyId !== "string") {
        return res.status(400).json({ message: "policyId is required" });
      }
      if (!body.action || !isValidAction(body.action)) {
        return res.status(400).json({ message: `Invalid action. Must be one of: ${VALID_ACTIONS.join(", ")}` });
      }

      const simulation = simulatePolicy(orgId, {
        policyId: body.policyId,
        action: body.action,
        context: body.context || {},
      });
      res.json(simulation);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("POLICY_NOT_FOUND")) {
        return res.status(404).json({ message: "Policy not found" });
      }
      logger.child("routes").error("Simulate policy error", { error: errMsg });
      res.status(500).json({ message: "Failed to simulate policy" });
    }
  });

  app.post("/api/runtime-guardrails/overrides", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const body = req.body;

      if (!body.policyId || typeof body.policyId !== "string") {
        return res.status(400).json({ message: "policyId is required" });
      }
      if (!body.requestedBy || typeof body.requestedBy !== "string") {
        return res.status(400).json({ message: "requestedBy is required" });
      }
      if (!body.reason || typeof body.reason !== "string") {
        return res.status(400).json({ message: "reason is required" });
      }
      if (
        body.timeboxMinutes === undefined ||
        typeof body.timeboxMinutes !== "number" ||
        body.timeboxMinutes < 1 ||
        body.timeboxMinutes > 480
      ) {
        return res.status(400).json({ message: "timeboxMinutes must be between 1 and 480" });
      }

      const override = requestEmergencyOverride(orgId, {
        policyId: body.policyId,
        requestedBy: body.requestedBy,
        reason: body.reason,
        timeboxMinutes: body.timeboxMinutes,
      });
      res.status(201).json(override);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("POLICY_NOT_FOUND")) {
        return res.status(404).json({ message: "Policy not found" });
      }
      if (errMsg.includes("TIMEBOX_OUT_OF_RANGE")) {
        return res.status(400).json({ message: "timeboxMinutes must be between 1 and 480" });
      }
      logger.child("routes").error("Request override error", { error: errMsg });
      res.status(500).json({ message: "Failed to request override" });
    }
  });

  app.patch("/api/runtime-guardrails/overrides/:id/approve", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const { approvedBy } = req.body as { approvedBy: string };

      if (!approvedBy || typeof approvedBy !== "string") {
        return res.status(400).json({ message: "approvedBy is required" });
      }

      const result = approveEmergencyOverride(id, orgId, approvedBy);
      if (!result) {
        return res.status(404).json({ message: "Override not found" });
      }
      res.json(result);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("OVERRIDE_NOT_PENDING")) {
        return res.status(400).json({ message: "Override is not in pending state" });
      }
      if (errMsg.includes("SELF_APPROVAL_FORBIDDEN")) {
        return res.status(403).json({ message: "Self-approval is not allowed. A different user must approve." });
      }
      logger.child("routes").error("Approve override error", { error: errMsg });
      res.status(500).json({ message: "Failed to approve override" });
    }
  });

  app.patch("/api/runtime-guardrails/overrides/:id/deny", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const { deniedBy } = req.body as { deniedBy: string };

      if (!deniedBy || typeof deniedBy !== "string") {
        return res.status(400).json({ message: "deniedBy is required" });
      }

      const result = denyEmergencyOverride(id, orgId, deniedBy);
      if (!result) {
        return res.status(404).json({ message: "Override not found" });
      }
      res.json(result);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("OVERRIDE_NOT_PENDING")) {
        return res.status(400).json({ message: "Override is not in pending state" });
      }
      logger.child("routes").error("Deny override error", { error: errMsg });
      res.status(500).json({ message: "Failed to deny override" });
    }
  });
}
