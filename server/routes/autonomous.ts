import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { storage } from "../storage";
import { dispatchAction } from "../action-dispatcher";
import { runInvestigation } from "../investigation-agent";
import { logger } from "../logger";
import { z } from "zod";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";

const log = logger.child("autonomous-routes");

// Validation Schemas
const policySchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  enabled: z.boolean().default(true),
  triggerCondition: z.object({
    severity: z.array(z.string()).optional(),
    category: z.array(z.string()).optional(),
    source: z.array(z.string()).optional(),
    mitreTactic: z.array(z.string()).optional(),
  }),
  actions: z.array(
    z.object({
      actionType: z.string(),
      config: z.record(z.unknown()),
      requireApproval: z.boolean().default(false),
    }),
  ),
  cooldownMinutes: z.number().min(0).max(10080).default(60),
  maxExecutionsPerDay: z.number().min(1).max(1000).default(100),
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const policies = await storage.getAutonomousPolicies(orgId);

        return res.json({
          policies: policies || [],
          summary: {
            total: policies?.length || 0,
            enabled: policies?.filter((p: any) => p.enabled).length || 0,
            disabled: policies?.filter((p: any) => !p.enabled).length || 0,
          },
        });
      } catch (error: any) {
        log.error("Failed to fetch autonomous policies", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch autonomous policies" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

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
          const policyId = await storage.createAutonomousPolicy(policy);
          created.push({ ...policy, id: policyId });
        }

        log.info("Seeded default autonomous policies", { orgId, count: created.length });

        return res.json({
          message: `Created ${created.length} default autonomous response policies`,
          policies: created,
        });
      } catch (error: any) {
        log.error("Failed to seed default policies", { error: error.message });
        return res.status(500).json({ error: "Failed to seed default policies" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const validated = policySchema.parse(req.body);

        const policyId = await storage.createAutonomousPolicy({
          orgId,
          ...validated,
        });

        const policy = await storage.getAutonomousPolicy(policyId);

        log.info("Created autonomous policy", { orgId, policyId, name: validated.name });

        return res.status(201).json({ policy });
      } catch (error: any) {
        if (error.name === "ZodError") {
          return res.status(400).json({ error: "Invalid policy data", details: error.errors });
        }
        log.error("Failed to create autonomous policy", { error: error.message });
        return res.status(500).json({ error: "Failed to create autonomous policy" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const policyId = req.params.id;
        const existing = await storage.getAutonomousPolicy(policyId);

        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ error: "Policy not found" });
        }

        const updates = policySchema.partial().parse(req.body);

        await storage.updateAutonomousPolicy(policyId, updates);
        const updated = await storage.getAutonomousPolicy(policyId);

        log.info("Updated autonomous policy", { orgId, policyId });

        return res.json({ policy: updated });
      } catch (error: any) {
        if (error.name === "ZodError") {
          return res.status(400).json({ error: "Invalid policy data", details: error.errors });
        }
        log.error("Failed to update autonomous policy", { error: error.message });
        return res.status(500).json({ error: "Failed to update autonomous policy" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const policyId = req.params.id;
        const existing = await storage.getAutonomousPolicy(policyId);

        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ error: "Policy not found" });
        }

        await storage.deleteAutonomousPolicy(policyId);

        log.info("Deleted autonomous policy", { orgId, policyId });

        return res.json({ message: "Policy deleted successfully" });
      } catch (error: any) {
        log.error("Failed to delete autonomous policy", { error: error.message });
        return res.status(500).json({ error: "Failed to delete autonomous policy" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const limit = parseInt(req.query.limit as string) || 100;
        const incidentId = req.query.incidentId as string | undefined;
        const alertId = req.query.alertId as string | undefined;

        const actions = await storage.getResponseActions(orgId, { limit, incidentId, alertId });

        return res.json({
          actions: actions || [],
          count: actions?.length || 0,
        });
      } catch (error: any) {
        log.error("Failed to fetch response actions", { error: error.message });
        return res.status(500).json({ error: "Failed to fetch response actions" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const { actionType, config, incidentId, alertId } = req.body;

        if (!actionType) {
          return res.status(400).json({ error: "actionType is required" });
        }

        const result = await dispatchAction(actionType, config || {}, {
          orgId,
          incidentId,
          alertId,
          userId: req.user?.id,
          userName: req.user?.name || req.user?.email,
          storage,
        });

        log.info("Manually executed response action", { orgId, actionType, status: result.status });

        return res.json({ result });
      } catch (error: any) {
        log.error("Failed to execute response action", { error: error.message });
        return res.status(500).json({ error: "Failed to execute response action" });
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const { incidentId } = req.body;

        if (!incidentId) {
          return res.status(400).json({ error: "incidentId is required" });
        }

        // Verify incident exists and belongs to org
        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ error: "Incident not found" });
        }

        const runId = await storage.createInvestigationRun({
          orgId,
          incidentId,
          status: "pending",
          triggeredBy: req.user?.id || "system",
        });

        // Run investigation asynchronously
        runInvestigation(runId).catch((error: any) => {
          log.error("Investigation run failed", { runId, error: error.message });
        });

        log.info("Started investigation run", { orgId, incidentId, runId });

        return res.status(201).json({
          runId,
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const runId = req.params.id;
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const rollbacks = await storage.getRollbacks(orgId);

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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const validated = rollbackSchema.parse(req.body);

        // Verify action exists and belongs to org
        const action = await storage.getResponseAction(validated.responseActionId);
        if (!action || action.orgId !== orgId) {
          return res.status(404).json({ error: "Response action not found" });
        }

        const rollbackId = await storage.createRollback({
          orgId,
          responseActionId: validated.responseActionId,
          reason: validated.reason || "Manual rollback request",
          status: "pending",
          requestedBy: req.user?.id || "unknown",
        });

        log.info("Created rollback request", { orgId, rollbackId, actionId: validated.responseActionId });

        return res.status(201).json({
          rollbackId,
          message: "Rollback request created",
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
        const orgId = req.user?.orgId;
        if (!orgId) return res.status(403).json({ error: "No organization context" });

        const rollbackId = req.params.id;
        const rollback = await storage.getRollback(rollbackId);

        if (!rollback || rollback.orgId !== orgId) {
          return res.status(404).json({ error: "Rollback not found" });
        }

        if (rollback.status !== "pending") {
          return res.status(400).json({ error: `Rollback already ${rollback.status}` });
        }

        // Get the original action
        const action = await storage.getResponseAction(rollback.responseActionId);
        if (!action) {
          return res.status(404).json({ error: "Original action not found" });
        }

        // Update rollback status
        await storage.updateRollback(rollbackId, {
          status: "completed",
          executedAt: new Date(),
          executedBy: req.user?.id || "unknown",
          result: {
            message: `[Simulated] Rolled back ${action.actionType} on ${action.targetValue}`,
            originalAction: {
              actionType: action.actionType,
              targetType: action.targetType,
              targetValue: action.targetValue,
            },
          },
        });

        log.info("Executed rollback", { orgId, rollbackId, actionType: action.actionType });

        return res.json({
          message: "Rollback executed successfully",
          rollback: await storage.getRollback(rollbackId),
        });
      } catch (error: any) {
        log.error("Failed to execute rollback", { error: error.message });
        return res.status(500).json({ error: "Failed to execute rollback" });
      }
    },
  );
}
