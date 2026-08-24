/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express } from "express";
import { randomBytes } from "crypto";
import { isAuthenticated } from "../auth";
import type { SessionUser } from "../auth/session";
import { storage } from "../storage";
import { dispatchAction } from "../action-dispatcher";
import { runInvestigation } from "../investigation-agent";
import { logger } from "../logger";
import { z } from "zod";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { getOrgId } from "./shared";
import { reply, replyBadRequest, replyInternal, replyNotFound, replyValidation } from "../api-response";
import { getAiSecuritySettings } from "../ai/security-store";

const log = logger.child("autonomous-routes");

// Validation Schemas
const policySchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  triggerType: z.enum(["incident_created", "incident_severity_change", "alert_created"]).default("alert_created"),
  severityFilter: z.array(z.string()).optional(),
  conditions: z
    .object({
      categories: z.array(z.string()).optional(),
      sources: z.array(z.string()).optional(),
      minAlertCount: z.number().int().nonnegative().optional(),
      minSources: z.number().int().nonnegative().optional(),
    })
    .default({}),
  actions: z.array(
    z.object({
      actionType: z.string(),
      config: z.record(z.unknown()),
      requireApproval: z.boolean().default(false),
    }),
  ),
  cooldownMinutes: z.number().min(0).max(10080).default(60),
  maxActionsPerHour: z.number().min(1).max(1000).default(10),
  status: z.enum(["active", "inactive", "testing"]).default("active"),
  confidenceThreshold: z.number().min(0).max(1).optional(),
  requiresApproval: z.boolean().default(false),
});

const rollbackSchema = z.object({
  responseActionId: z.string(),
  reason: z.string().optional(),
});

export function registerAutonomousRoutes(app: Express): void {
  // =============================
  // AUTONOMOUS POLICIES
  // =============================

  /**
   * GET /api/autonomous/policies
   * List all autonomous response policies for the organization
   */
  app.get(
    "/api/autonomous/policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const policies = await storage.getAutoResponsePolicies(orgId);

        return reply(res, policies || [], { total: policies?.length || 0 });
      } catch (error: any) {
        log.error("Failed to fetch autonomous policies", { error: error.message });
        return replyInternal(res, "Failed to fetch autonomous policies");
      }
    },
  );

  /**
   * POST /api/autonomous/policies/seed-defaults
   * Seed default autonomous response policies
   */
  app.post(
    "/api/autonomous/policies/seed-defaults",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const defaultPolicies = [
          {
            orgId,
            name: "Critical Alert Auto-Escalation",
            description: "Automatically escalate critical severity alerts to priority 1 incidents",
            enabled: true,
            triggerCondition: { severity: ["critical"] },
            actions: [
              { actionType: "escalate", config: {}, requireApproval: false },
              { actionType: "notify_slack", config: { channel: "#security-critical" }, requireApproval: false },
            ],
            cooldownMinutes: 30,
            maxExecutionsPerDay: 50,
          },
          {
            orgId,
            name: "Malware Auto-Isolation",
            description: "Automatically isolate hosts with confirmed malware detections",
            enabled: false, // Disabled by default - requires approval
            triggerCondition: { category: ["malware"], severity: ["critical", "high"] },
            actions: [
              { actionType: "isolate_host", config: {}, requireApproval: true },
              { actionType: "notify_pagerduty", config: {}, requireApproval: false },
            ],
            cooldownMinutes: 60,
            maxExecutionsPerDay: 20,
          },
          {
            orgId,
            name: "Data Exfiltration Response",
            description: "Block suspicious IPs and domains during data exfiltration attempts",
            enabled: false,
            triggerCondition: { category: ["data_exfiltration"] },
            actions: [
              { actionType: "block_ip", config: {}, requireApproval: true },
              { actionType: "block_domain", config: {}, requireApproval: true },
              {
                actionType: "create_jira_ticket",
                config: { project: "SEC", priority: "critical" },
                requireApproval: false,
              },
            ],
            cooldownMinutes: 15,
            maxExecutionsPerDay: 10,
          },
          {
            orgId,
            name: "Credential Compromise Response",
            description: "Disable compromised user accounts and notify security team",
            enabled: false,
            triggerCondition: { category: ["credential_access", "privilege_escalation"] },
            actions: [
              { actionType: "disable_user", config: {}, requireApproval: true },
              {
                actionType: "notify_email",
                config: { recipient: "security-team@company.com" },
                requireApproval: false,
              },
            ],
            cooldownMinutes: 120,
            maxExecutionsPerDay: 5,
          },
          {
            orgId,
            name: "Lateral Movement Containment",
            description: "Isolate hosts showing lateral movement to contain spread",
            enabled: false,
            triggerCondition: { category: ["lateral_movement"] },
            actions: [
              { actionType: "isolate_host", config: {}, requireApproval: true },
              { actionType: "escalate", config: {}, requireApproval: false },
            ],
            cooldownMinutes: 45,
            maxExecutionsPerDay: 15,
          },
          {
            orgId,
            name: "Auto-Triage Low Severity Alerts",
            description: "Automatically triage and categorize low severity alerts",
            enabled: true,
            triggerCondition: { severity: ["low", "informational"] },
            actions: [
              { actionType: "auto_triage", config: {}, requireApproval: false },
              { actionType: "add_tag", config: { tag: "auto-triaged" }, requireApproval: false },
            ],
            cooldownMinutes: 5,
            maxExecutionsPerDay: 500,
          },
        ];

        const created = [];
        for (const policy of defaultPolicies) {
          const created_policy = await storage.createAutoResponsePolicy({
            ...policy,
            triggerType: "incident_created",
            conditions: policy.triggerCondition,
            severityFilter: policy.triggerCondition.severity,
            confidenceThreshold: 0.85,
            maxActionsPerHour: policy.maxExecutionsPerDay,
            status: policy.enabled ? "active" : "inactive",
          } as any);
          created.push({ ...policy, id: created_policy.id });
        }

        log.info("Seeded default autonomous policies", { orgId, count: created.length });

        return reply(res, created);
      } catch (error: any) {
        log.error("Failed to seed default policies", { error: error.message });
        return replyInternal(res, "Failed to seed default policies");
      }
    },
  );

  /**
   * POST /api/autonomous/policies
   * Create a new autonomous response policy
   */
  app.post(
    "/api/autonomous/policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    enforcePlanLimit("response_policies"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const validated = policySchema.parse(req.body);

        const policy = await storage.createAutoResponsePolicy({
          orgId,
          ...validated,
          confidenceThreshold: validated.confidenceThreshold ?? 0,
        } as any);

        log.info("Created autonomous policy", { orgId, policyId: policy.id, name: validated.name });

        return reply(res, policy, {}, 201);
      } catch (error: any) {
        if (error.name === "ZodError") {
          return replyValidation(
            res,
            error.errors.map((issue: { message: string; path: (string | number)[] }) => ({
              message: issue.message,
              field: issue.path.join("."),
            })),
          );
        }
        log.error("Failed to create autonomous policy", { error: error.message });
        return replyInternal(res, "Failed to create autonomous policy");
      }
    },
  );

  /**
   * PATCH /api/autonomous/policies/:id
   * Update an autonomous response policy
   */
  app.patch(
    "/api/autonomous/policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const policyId = String(req.params.id);
        const existing = await storage.getAutoResponsePolicy(policyId);

        if (!existing || existing.orgId !== orgId) {
          return replyNotFound(res, "Policy not found");
        }

        const updates = policySchema.partial().parse(req.body);

        const updated = await storage.updateAutoResponsePolicy(policyId, updates as any);

        log.info("Updated autonomous policy", { orgId, policyId });

        return reply(res, updated);
      } catch (error: any) {
        if (error.name === "ZodError") {
          return replyValidation(
            res,
            error.errors.map((issue: { message: string; path: (string | number)[] }) => ({
              message: issue.message,
              field: issue.path.join("."),
            })),
          );
        }
        log.error("Failed to update autonomous policy", { error: error.message });
        return replyInternal(res, "Failed to update autonomous policy");
      }
    },
  );

  /**
   * DELETE /api/autonomous/policies/:id
   * Delete an autonomous response policy
   */
  app.delete(
    "/api/autonomous/policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const policyId = String(req.params.id);
        const existing = await storage.getAutoResponsePolicy(policyId);

        if (!existing || existing.orgId !== orgId) {
          return replyNotFound(res, "Policy not found");
        }

        await storage.deleteAutoResponsePolicy(policyId);

        log.info("Deleted autonomous policy", { orgId, policyId });

        return reply(res, { deleted: true });
      } catch (error: any) {
        log.error("Failed to delete autonomous policy", { error: error.message });
        return replyInternal(res, "Failed to delete autonomous policy");
      }
    },
  );

  // =============================
  // RESPONSE ACTIONS
  // =============================

  /**
   * GET /api/response-actions
   * Get response action timeline for the organization
   */
  app.get(
    "/api/response-actions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const incidentId = req.query.incidentId as string | undefined;

        const actions = await storage.getResponseActions(orgId, incidentId);

        return reply(res, actions || [], { total: actions?.length || 0 });
      } catch (error: any) {
        log.error("Failed to fetch response actions", { error: error.message });
        return replyInternal(res, "Failed to fetch response actions");
      }
    },
  );

  /**
   * POST /api/response-actions/execute
   * Manually execute a response action
   */
  app.post(
    "/api/response-actions/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const { actionType, config, incidentId, alertId } = req.body;

        if (!actionType) return replyBadRequest(res, "actionType is required");
        const user = req.user as SessionUser;
        const autonomyMode = (await getAiSecuritySettings(orgId)).autonomyMode ?? undefined;

        const result = await dispatchAction(actionType, config || {}, {
          orgId,
          incidentId,
          alertId,
          userId: user.id,
          userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : (user.email ?? user.id),
          callerRole: user.orgRole ?? undefined,
          storage,
          autonomyMode,
        });

        log.info("Manually executed response action", { orgId, actionType, status: result.status });

        return reply(res, { result });
      } catch (error: any) {
        log.error("Failed to execute response action", { error: error.message });
        return replyInternal(res, "Failed to execute response action");
      }
    },
  );

  // =============================
  // INVESTIGATIONS
  // =============================

  /**
   * GET /api/autonomous/investigations
   * List all investigation runs
   */
  app.get(
    "/api/autonomous/investigations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const runs = await storage.getInvestigationRuns(orgId);

        return res.json({
          investigations: runs || [],
          summary: {
            total: runs?.length || 0,
            completed: runs?.filter((r: any) => r.status === "completed").length || 0,
            running: runs?.filter((r: any) => r.status === "running").length || 0,
            failed: runs?.filter((r: any) => r.status === "failed").length || 0,
          },
        });
      } catch (error: any) {
        log.error("Failed to fetch investigation runs", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch investigation runs" });
      }
    },
  );

  /**
   * POST /api/autonomous/investigations
   * Trigger a new investigation run for an incident
   */
  app.post(
    "/api/autonomous/investigations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const { incidentId } = req.body;

        if (!incidentId) {
          return res.status(400).json({ error: "incidentId is required" });
        }

        // Verify incident exists and belongs to org
        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ error: "Incident not found" });
        }

        const run = await storage.createInvestigationRun({
          orgId,
          incidentId,
          status: "pending",
          triggeredBy: (req as any).user?.id || "system",
        });

        // Run investigation asynchronously
        runInvestigation(run.id).catch((error: any) => {
          log.error("Investigation run failed", { runId: run.id, error: error.message });
        });

        log.info("Started investigation run", { orgId, incidentId, runId: run.id });

        return res.status(201).json({
          runId: run.id,
          message: "Investigation started",
          incidentId,
        });
      } catch (error: any) {
        log.error("Failed to start investigation", { error: error.message });
        return res.status(500).json({ error: "Failed to start investigation" });
      }
    },
  );

  /**
   * GET /api/autonomous/investigations/:id
   * Get investigation run details including steps
   */
  app.get(
    "/api/autonomous/investigations/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const runId = String(req.params.id);
        const run = await storage.getInvestigationRun(runId);

        if (!run || run.orgId !== orgId) {
          return res.status(404).json({ error: "Investigation run not found" });
        }

        const steps = await storage.getInvestigationSteps(runId);

        return res.json({
          investigation: run,
          steps: steps || [],
        });
      } catch (error: any) {
        log.error("Failed to fetch investigation run", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch investigation run" });
      }
    },
  );

  // =============================
  // ROLLBACKS
  // =============================

  /**
   * GET /api/autonomous/rollbacks
   * Get rollback history
   */
  app.get(
    "/api/autonomous/rollbacks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const rollbacks = await storage.getResponseActionRollbacks(orgId);

        return res.json({
          rollbacks: rollbacks || [],
          count: rollbacks?.length || 0,
        });
      } catch (error: any) {
        log.error("Failed to fetch rollbacks", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch rollbacks" });
      }
    },
  );

  /**
   * POST /api/autonomous/rollbacks
   * Create a rollback request for a response action
   */
  app.post(
    "/api/autonomous/rollbacks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const validated = rollbackSchema.parse(req.body);

        // Verify action exists and belongs to org
        const action = await storage.getResponseAction(validated.responseActionId);
        if (!action || action.orgId !== orgId) {
          return res.status(404).json({ error: "Response action not found" });
        }

        return res.status(503).json({
          code: "ROLLBACK_EXECUTION_UNAVAILABLE",
          error: "Rollback execution is unavailable until the original action is linked to a native sensor action.",
        });
      } catch (error: any) {
        if (error.name === "ZodError") {
          return res.status(400).json({ error: "Invalid rollback data", details: error.errors });
        }
        log.error("Failed to create rollback", { error: error.message });
        return res.status(500).json({ error: "Failed to create rollback" });
      }
    },
  );

  /**
   * POST /api/autonomous/rollbacks/:id/execute
   * Execute a rollback
   */
  app.post(
    "/api/autonomous/rollbacks/:id/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const rollbackId = String(req.params.id);
        const rollback = await storage.getResponseActionRollback(rollbackId);

        if (!rollback || rollback.orgId !== orgId) {
          return res.status(404).json({ error: "Rollback not found" });
        }

        if (rollback.status !== "pending") {
          return res.status(400).json({ error: `Rollback already ${rollback.status}` });
        }

        // Get the original action
        const action = await storage.getResponseAction(rollback.originalActionId || "");
        if (!action) {
          return res.status(404).json({ error: "Original action not found" });
        }

        log.warn("Rollback execution unavailable: native sensor dispatch is required", {
          orgId,
          rollbackId,
          actionType: action.actionType,
        });

        return res.status(503).json({
          code: "ROLLBACK_EXECUTION_UNAVAILABLE",
          message: "Rollback execution is unavailable until a native sensor dispatch is configured.",
          rollback,
        });
      } catch (error: any) {
        log.error("Failed to execute rollback", { error: error.message });
        return res.status(500).json({ error: "Failed to execute rollback" });
      }
    },
  );

  // =============================
  // 22.1 — ROLLBACK DETAIL VIEW
  // =============================

  app.get(
    "/api/autonomous/rollbacks/:id/detail",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rollbackId = String(req.params.id);
        const rollback = await storage.getResponseActionRollback(rollbackId);

        if (!rollback || rollback.orgId !== orgId) {
          return res.status(404).json({ error: "Rollback not found" });
        }

        // Fetch original action details
        const originalAction = rollback.originalActionId
          ? await storage.getResponseAction(rollback.originalActionId)
          : null;

        const resultOutput =
          rollback.result && typeof rollback.result === "object" && "resultOutput" in rollback.result
            ? String((rollback.result as Record<string, unknown>).resultOutput)
            : null;
        const verificationChecks = [
          {
            check: "agent_report",
            status:
              rollback.status === "completed" && resultOutput
                ? "pass"
                : rollback.status === "failed"
                  ? "fail"
                  : "unknown",
            detail: resultOutput
              ? `Sensor reported: ${resultOutput}`
              : "No agent-reported rollback output is available.",
          },
          {
            check: "external_state",
            status: "unknown",
            detail: "External rollback state cannot be independently verified by SecureNexus.",
          },
        ];
        const verificationStatus = verificationChecks.some((c) => c.status === "fail")
          ? "failed"
          : verificationChecks.every((c) => c.status === "pass")
            ? "agent_reported"
            : "unverified";

        return res.json({
          rollback,
          originalAction: originalAction
            ? {
                id: originalAction.id,
                actionType: originalAction.actionType,
                targetType: originalAction.targetType,
                targetValue: originalAction.targetValue,
                status: originalAction.status,
                createdAt: originalAction.createdAt,
                executedAt: originalAction.executedAt,
              }
            : null,
          initiatedBy: rollback.executedBy || "unknown",
          reason: (rollback.rollbackAction as any)?.reason || "No reason provided",
          beforeState: {},
          afterState: {},
          verificationStatus,
          verificationChecks,
        });
      } catch (error: any) {
        log.error("Failed to fetch rollback detail", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch rollback detail" });
      }
    },
  );

  // =============================
  // 22.2 — ROLLBACK IMPACT ANALYSIS
  // =============================

  app.get(
    "/api/autonomous/rollbacks/:id/impact",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rollbackId = String(req.params.id);
        const rollback = await storage.getResponseActionRollback(rollbackId);

        if (!rollback || rollback.orgId !== orgId) {
          return res.status(404).json({ error: "Rollback not found" });
        }

        const originalAction = rollback.originalActionId
          ? await storage.getResponseAction(rollback.originalActionId)
          : null;

        const actionType = originalAction?.actionType || rollback.actionType;
        const target = originalAction?.targetValue || rollback.target;
        const impactSummary: Record<string, unknown> = {
          actionType,
          target,
          status: "unverified",
          durationMinutes: null,
          durationFormatted: "Unknown",
          description: "Impact cannot be determined without agent and endpoint telemetry.",
          businessImpact: "unknown",
        };

        return res.json({
          rollbackId,
          impact: impactSummary,
          timeline: [
            {
              event: "Original action recorded",
              timestamp: originalAction?.createdAt || null,
              detail: `${actionType} on ${target}; external state unverified`,
            },
            {
              event: "Rollback requested",
              timestamp: rollback.createdAt,
              detail: (rollback.rollbackAction as any)?.reason || "Manual rollback",
            },
            ...(rollback.executedAt
              ? [
                  {
                    event: "Rollback result recorded",
                    timestamp: rollback.executedAt,
                    detail: `Status: ${rollback.status}; external state unverified`,
                  },
                ]
              : []),
          ],
        });
      } catch (error: any) {
        log.error("Failed to compute rollback impact", { error: error.message });
        return res.status(500).json({ error: "Failed to compute rollback impact" });
      }
    },
  );

  // =============================
  // 22.3 — AUTOMATIC ROLLBACK TRIGGERS
  // =============================

  const autoRollbackTriggers = new Map<
    string,
    {
      orgId: string;
      id: string;
      name: string;
      description: string;
      enabled: boolean;
      actionType: string;
      condition: {
        metric: string;
        threshold: number;
        windowMinutes: number;
        comparison: "gt" | "lt" | "gte" | "lte" | "eq";
      };
      createdAt: string;
      updatedAt: string;
    }
  >();

  app.get(
    "/api/autonomous/rollback-triggers",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const triggers = Array.from(autoRollbackTriggers.values()).filter((t) => t.orgId === orgId);
        return res.json({ triggers, count: triggers.length });
      } catch (error: any) {
        log.error("Failed to fetch rollback triggers", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch rollback triggers" });
      }
    },
  );

  app.post(
    "/api/autonomous/rollback-triggers",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, description, actionType, condition, enabled } = req.body;

        if (!name || !actionType || !condition) {
          return res.status(400).json({ error: "name, actionType, and condition are required" });
        }

        if (
          !condition.metric ||
          typeof condition.threshold !== "number" ||
          typeof condition.windowMinutes !== "number" ||
          !["gt", "lt", "gte", "lte", "eq"].includes(condition.comparison)
        ) {
          return res
            .status(400)
            .json({ error: "condition must have metric, threshold, windowMinutes, and comparison (gt|lt|gte|lte|eq)" });
        }

        const id = `art-${Date.now().toString(36)}-${randomBytes(3).toString("hex")}`;
        const trigger = {
          orgId,
          id,
          name,
          description: description || "",
          enabled: enabled !== false,
          actionType,
          condition,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        autoRollbackTriggers.set(id, trigger);
        log.info("Created auto-rollback trigger", { orgId, triggerId: id, name });

        return res.status(201).json({ trigger });
      } catch (error: any) {
        log.error("Failed to create rollback trigger", { error: error.message });
        return res.status(500).json({ error: "Failed to create rollback trigger" });
      }
    },
  );

  app.patch(
    "/api/autonomous/rollback-triggers/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const triggerId = String(req.params.id);
        const trigger = autoRollbackTriggers.get(triggerId);

        if (!trigger || trigger.orgId !== orgId) {
          return res.status(404).json({ error: "Trigger not found" });
        }

        const { name, description, actionType, condition, enabled } = req.body;
        if (name !== undefined) trigger.name = name;
        if (description !== undefined) trigger.description = description;
        if (actionType !== undefined) trigger.actionType = actionType;
        if (condition !== undefined) trigger.condition = condition;
        if (enabled !== undefined) trigger.enabled = enabled;
        trigger.updatedAt = new Date().toISOString();

        log.info("Updated auto-rollback trigger", { orgId, triggerId });
        return res.json({ trigger });
      } catch (error: any) {
        log.error("Failed to update rollback trigger", { error: error.message });
        return res.status(500).json({ error: "Failed to update rollback trigger" });
      }
    },
  );

  app.delete(
    "/api/autonomous/rollback-triggers/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const triggerId = String(req.params.id);
        const trigger = autoRollbackTriggers.get(triggerId);

        if (!trigger || trigger.orgId !== orgId) {
          return res.status(404).json({ error: "Trigger not found" });
        }

        autoRollbackTriggers.delete(triggerId);
        log.info("Deleted auto-rollback trigger", { orgId, triggerId });
        return res.json({ message: "Trigger deleted" });
      } catch (error: any) {
        log.error("Failed to delete rollback trigger", { error: error.message });
        return res.status(500).json({ error: "Failed to delete rollback trigger" });
      }
    },
  );

  // =============================
  // 22.4 — ROLLBACK AUDIT TRAIL
  // =============================

  app.get(
    "/api/autonomous/rollbacks/:id/audit-trail",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rollbackId = String(req.params.id);
        const rollback = await storage.getResponseActionRollback(rollbackId);

        if (!rollback || rollback.orgId !== orgId) {
          return res.status(404).json({ error: "Rollback not found" });
        }

        const originalAction = rollback.originalActionId
          ? await storage.getResponseAction(rollback.originalActionId)
          : null;

        // Build comprehensive audit trail
        const auditEntries: {
          timestamp: string | null;
          actor: string;
          action: string;
          detail: string;
          category: string;
        }[] = [];

        // 1. Original action record
        if (originalAction) {
          auditEntries.push({
            timestamp: originalAction.createdAt ? new Date(originalAction.createdAt).toISOString() : null,
            actor: "system",
            action: "original_action_created",
            detail: `${originalAction.actionType} on ${originalAction.targetValue}`,
            category: "action",
          });

          if (originalAction.executedAt) {
            auditEntries.push({
              timestamp: new Date(originalAction.executedAt).toISOString(),
              actor: "system",
              action: "original_action_status_recorded",
              detail: `Recorded status: ${originalAction.status}; external state unverified`,
              category: "action",
            });
          }
        }

        // 2. Rollback requested
        auditEntries.push({
          timestamp: rollback.createdAt ? new Date(rollback.createdAt).toISOString() : null,
          actor: rollback.executedBy || "unknown",
          action: "rollback_requested",
          detail: (rollback.rollbackAction as any)?.reason || "No reason provided",
          category: "rollback",
        });

        // 3. Rollback result
        if (rollback.executedAt) {
          auditEntries.push({
            timestamp: new Date(rollback.executedAt).toISOString(),
            actor: rollback.executedBy || "system",
            action: "rollback_result_recorded",
            detail: `Rollback status: ${rollback.status}; external state unverified`,
            category: "rollback",
          });
        }

        // 4. Result recorded
        if (rollback.result && Object.keys(rollback.result).length > 0) {
          auditEntries.push({
            timestamp: rollback.executedAt ? new Date(rollback.executedAt).toISOString() : null,
            actor: "system",
            action: "result_recorded",
            detail: JSON.stringify(rollback.result),
            category: "verification",
          });
        }

        // 5. Error recorded
        if (rollback.error) {
          auditEntries.push({
            timestamp: rollback.executedAt ? new Date(rollback.executedAt).toISOString() : null,
            actor: "system",
            action: "error_recorded",
            detail: rollback.error,
            category: "error",
          });
        }

        auditEntries.sort((a, b) => {
          if (!a.timestamp) return -1;
          if (!b.timestamp) return 1;
          return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
        });

        return res.json({
          rollbackId,
          auditTrail: auditEntries,
          summary: {
            totalEntries: auditEntries.length,
            requestedBy: rollback.executedBy || "unknown",
            reason: (rollback.rollbackAction as any)?.reason || "No reason provided",
            originalActionType: originalAction?.actionType || rollback.actionType,
            originalTarget: originalAction?.targetValue || rollback.target,
            finalStatus: rollback.status,
            complianceNote: "Full audit trail preserved for regulatory compliance. All entries are immutable.",
          },
        });
      } catch (error: any) {
        log.error("Failed to fetch rollback audit trail", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch rollback audit trail" });
      }
    },
  );
}
