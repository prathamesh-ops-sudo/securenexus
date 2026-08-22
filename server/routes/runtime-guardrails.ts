import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

import { storage } from "../storage";
import { evaluateAction, simulatePolicy, toPolicyRule } from "../runtime-guardrails-engine";
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
  // Policies — persisted to DB
  app.get("/api/runtime-guardrails/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policies = await storage.getRuntimePolicies(orgId);
      res.json(policies);
    } catch (error) {
      logger.child("routes").error("List guardrail policies error", { error: String(error) });
      res.status(500).json({ message: "Failed to list policies" });
    }
  });

  app.get("/api/runtime-guardrails/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [totalPolicies, totalDecisions, overrides] = await Promise.all([
        storage.countRuntimePolicies(orgId),
        storage.countRuntimeDecisions(orgId),
        storage.getRuntimeOverrides(orgId),
      ]);
      const pendingOverrides = overrides.filter((o) => o.status === "pending").length;
      const approvedOverrides = overrides.filter((o) => o.status === "approved").length;
      res.json({
        totalPolicies,
        totalDecisions,
        totalOverrides: overrides.length,
        pendingOverrides,
        approvedOverrides,
      });
    } catch (error) {
      logger.child("routes").error("Guardrail stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch guardrail stats" });
    }
  });

  // Decisions — persisted to DB
  app.get("/api/runtime-guardrails/decisions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 100;
      const decisions = await storage.getRuntimeDecisions(orgId, limit);
      res.json(decisions);
    } catch (error) {
      logger.child("routes").error("List decision logs error", { error: String(error) });
      res.status(500).json({ message: "Failed to list decision logs" });
    }
  });

  // Overrides — persisted to DB
  app.get("/api/runtime-guardrails/overrides", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const statusFilter = typeof req.query.status === "string" ? req.query.status : undefined;
      const overrides = await storage.getRuntimeOverrides(orgId, statusFilter);
      res.json(overrides);
    } catch (error) {
      logger.child("routes").error("List overrides error", { error: String(error) });
      res.status(500).json({ message: "Failed to list overrides" });
    }
  });

  app.get("/api/runtime-guardrails/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const policy = await storage.getRuntimePolicy(id, orgId);
      if (!policy) {
        return res.status(404).json({ message: "Policy not found" });
      }
      res.json(policy);
    } catch (error) {
      logger.child("routes").error("Get policy error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch policy" });
    }
  });

  app.post(
    "/api/runtime-guardrails/policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
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

        // The DB schema has a single `action` field; store the primary action and put the full list in metadata
        const policy = await storage.createRuntimePolicy({
          orgId,
          name: body.name,
          description: body.description || "",
          action: body.actions[0],
          scope: body.scope,
          mode: body.mode,
          conditions: Array.isArray(body.conditions) ? body.conditions : [],
          priority: body.priority ?? 50,
          enabled: true,
          metadata: {
            verdict: body.verdict,
            actions: body.actions,
            rateLimit: body.rateLimit || null,
            tags: Array.isArray(body.tags) ? body.tags : [],
            createdBy: body.createdBy || "api",
          },
        });
        res.status(201).json(policy);
      } catch (error) {
        logger.child("routes").error("Create policy error", { error: String(error) });
        res.status(500).json({ message: "Failed to create policy" });
      }
    },
  );

  app.patch(
    "/api/runtime-guardrails/policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
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

        const updates: Record<string, unknown> = {};
        if (body.name !== undefined) updates.name = body.name;
        if (body.description !== undefined) updates.description = body.description;
        if (body.mode !== undefined) updates.mode = body.mode;
        if (body.scope !== undefined) updates.scope = body.scope;
        if (body.priority !== undefined) updates.priority = body.priority;
        if (body.enabled !== undefined) updates.enabled = body.enabled === true;
        if (body.conditions !== undefined) updates.conditions = body.conditions;
        if (body.actions !== undefined) updates.action = body.actions[0];

        const updated = await storage.updateRuntimePolicy(id, orgId, updates);
        if (!updated) {
          return res.status(404).json({ message: "Policy not found" });
        }
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Update policy error", { error: String(error) });
        res.status(500).json({ message: "Failed to update policy" });
      }
    },
  );

  app.delete(
    "/api/runtime-guardrails/policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const deleted = await storage.deleteRuntimePolicy(id, orgId);
        if (!deleted) {
          return res.status(404).json({ message: "Policy not found" });
        }
        res.json({ message: "Policy deleted" });
      } catch (error) {
        logger.child("routes").error("Delete policy error", { error: String(error) });
        res.status(500).json({ message: "Failed to delete policy" });
      }
    },
  );

  // Evaluate — stateless computation with decision persisted to DB
  app.post(
    "/api/runtime-guardrails/evaluate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
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

        const persistedPolicies = await storage.getRuntimePolicies(orgId);
        const decision = evaluateAction(
          orgId,
          {
            action: body.action,
            actorId: body.actorId,
            actorType: body.actorType,
            resourceId: body.resourceId || "unknown",
            resourceType: body.resourceType || "unknown",
            context: body.context || {},
          },
          { skipLog: true },
          persistedPolicies.map(toPolicyRule),
        );

        // Persist decision to DB
        await storage.createRuntimeDecision({
          orgId,
          policyId: decision.policyId || null,
          policyName: decision.policyName || null,
          action: body.action,
          verdict: decision.verdict,
          reason: decision.reason || null,
          actorId: body.actorId,
          resourceId: body.resourceId || "unknown",
          metadata: {
            actorType: body.actorType,
            resourceType: body.resourceType || "unknown",
            context: body.context || {},
          },
        });

        res.json(decision);
      } catch (error) {
        logger.child("routes").error("Evaluate action error", { error: String(error) });
        res.status(500).json({ message: "Failed to evaluate action" });
      }
    },
  );

  // Simulate — stateless, kept on engine
  app.post(
    "/api/runtime-guardrails/simulate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = req.body;

        if (!body.policyId || typeof body.policyId !== "string") {
          return res.status(400).json({ message: "policyId is required" });
        }
        if (!body.action || !isValidAction(body.action)) {
          return res.status(400).json({ message: `Invalid action. Must be one of: ${VALID_ACTIONS.join(", ")}` });
        }

        const persistedPolicies = await storage.getRuntimePolicies(orgId);
        const simulation = simulatePolicy(
          orgId,
          {
            policyId: body.policyId,
            action: body.action,
            context: body.context || {},
          },
          persistedPolicies.map(toPolicyRule),
        );
        const persistedSimulation = await storage.createRuntimeSimulation({
          orgId,
          policyId: simulation.policyId,
          policyName: simulation.policyName,
          simulatedAction: simulation.simulatedAction,
          inputContext: simulation.inputContext,
          expectedVerdict: simulation.expectedVerdict,
          actualVerdict: simulation.actualVerdict,
          blastRadius: simulation.blastRadius,
          dryRunAt: new Date(simulation.dryRunAt),
          runBy: String((req.user as { id?: string } | undefined)?.id || "authenticated-user"),
        });
        res.json(persistedSimulation);
      } catch (error) {
        const errMsg = String(error);
        if (errMsg.includes("POLICY_NOT_FOUND")) {
          return res.status(404).json({ message: "Policy not found" });
        }
        logger.child("routes").error("Simulate policy error", { error: errMsg });
        res.status(500).json({ message: "Failed to simulate policy" });
      }
    },
  );

  // Overrides — persisted to DB with approval workflow
  app.post(
    "/api/runtime-guardrails/overrides",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
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

        // Verify policy exists
        const policy = await storage.getRuntimePolicy(body.policyId, orgId);
        if (!policy) {
          return res.status(404).json({ message: "Policy not found" });
        }

        const expiresAt = new Date(Date.now() + body.timeboxMinutes * 60 * 1000);
        const override = await storage.createRuntimeOverride({
          orgId,
          policyId: body.policyId,
          requestedBy: body.requestedBy,
          reason: body.reason,
          status: "pending",
          expiresAt,
          metadata: {
            timeboxMinutes: body.timeboxMinutes,
            policyName: policy.name,
          },
        });
        res.status(201).json(override);
      } catch (error) {
        logger.child("routes").error("Request override error", { error: String(error) });
        res.status(500).json({ message: "Failed to request override" });
      }
    },
  );

  app.patch(
    "/api/runtime-guardrails/overrides/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { approvedBy } = req.body as { approvedBy: string };

        if (!approvedBy || typeof approvedBy !== "string") {
          return res.status(400).json({ message: "approvedBy is required" });
        }

        const existing = await storage.getRuntimeOverride(id, orgId);
        if (!existing) {
          return res.status(404).json({ message: "Override not found" });
        }
        if (existing.status !== "pending") {
          return res.status(400).json({ message: "Override is not in pending state" });
        }
        if (existing.requestedBy === approvedBy) {
          return res.status(403).json({ message: "Self-approval is not allowed. A different user must approve." });
        }
        if (existing.expiresAt && new Date(existing.expiresAt) < new Date()) {
          return res.status(400).json({ message: "Override has expired and can no longer be approved" });
        }

        const result = await storage.updateRuntimeOverride(id, orgId, {
          status: "approved",
          approvedBy,
          approvedAt: new Date(),
        });
        res.json(result);
      } catch (error) {
        logger.child("routes").error("Approve override error", { error: String(error) });
        res.status(500).json({ message: "Failed to approve override" });
      }
    },
  );

  app.patch(
    "/api/runtime-guardrails/overrides/:id/deny",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { deniedBy } = req.body as { deniedBy: string };

        if (!deniedBy || typeof deniedBy !== "string") {
          return res.status(400).json({ message: "deniedBy is required" });
        }

        const existing = await storage.getRuntimeOverride(id, orgId);
        if (!existing) {
          return res.status(404).json({ message: "Override not found" });
        }
        if (existing.status !== "pending") {
          return res.status(400).json({ message: "Override is not in pending state" });
        }

        const result = await storage.updateRuntimeOverride(id, orgId, {
          status: "denied",
          metadata: {
            ...(typeof existing.metadata === "object" && existing.metadata !== null ? existing.metadata : {}),
            deniedBy,
            deniedAt: new Date().toISOString(),
          },
        });
        res.json(result);
      } catch (error) {
        logger.child("routes").error("Deny override error", { error: String(error) });
        res.status(500).json({ message: "Failed to deny override" });
      }
    },
  );

  // Simulations are persisted tenant history; calculation remains request-scoped.
  app.get("/api/runtime-guardrails/simulations", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const simulations = await storage.getRuntimeSimulations(orgId, 50);
      res.json(simulations);
    } catch (error) {
      logger.child("routes").error("List simulations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list simulations" });
    }
  });
}
