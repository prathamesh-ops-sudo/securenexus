import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or } from "drizzle-orm";
import {
  agentResponseActions,
  nativeSensors,
  AGENT_ACTION_TYPES,
  AGENT_ACTION_RISK_LEVELS,
  AGENT_ACTION_STATUSES,
} from "../../shared/schema";

const log = logger.child("agent-response");

// High-risk actions require approval before dispatch
const HIGH_RISK_ACTIONS = ["delete_file", "isolate_host", "run_script", "disable_user"];
const MEDIUM_RISK_ACTIONS = ["kill_process", "block_ip", "quarantine_file", "block_domain"];

function determineRiskLevel(actionType: string): string {
  if (HIGH_RISK_ACTIONS.includes(actionType)) return "high";
  if (MEDIUM_RISK_ACTIONS.includes(actionType)) return "medium";
  return "low";
}

function determineInitialStatus(riskLevel: string): string {
  // High and medium risk actions require approval
  if (riskLevel === "high" || riskLevel === "medium") return "pending_approval";
  return "approved";
}

export function registerAgentResponseRoutes(app: Express): void {
  // ==========================================================================
  // CREATE ACTION — auto-queues high-risk for approval
  // ==========================================================================

  app.post(
    "/api/native/response/actions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          sensorId,
          actionType,
          targetPid,
          targetProcessName,
          targetIp,
          targetFilePath,
          targetUserName,
          targetDomain,
          targetServiceName,
          scriptContent,
          scriptType,
          parameters,
          reason,
          incidentId,
          timeoutSeconds,
        } = req.body;

        if (!sensorId || typeof sensorId !== "string") {
          return res.status(400).json({ message: "sensorId is required" });
        }

        if (!actionType || !AGENT_ACTION_TYPES.includes(actionType as any)) {
          return res.status(400).json({
            message: `actionType must be one of: ${AGENT_ACTION_TYPES.join(", ")}`,
          });
        }

        // Verify sensor belongs to org
        const [sensor] = await db
          .select()
          .from(nativeSensors)
          .where(and(eq(nativeSensors.id, sensorId), eq(nativeSensors.orgId, orgId)))
          .limit(1);

        if (!sensor) {
          return res.status(404).json({ message: "Sensor not found" });
        }

        const riskLevelVal = determineRiskLevel(actionType);
        const initialStatus = determineInitialStatus(riskLevelVal);

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName || (req as any).user?.email || "Unknown";

        const timeout = typeof timeoutSeconds === "number" ? Math.min(timeoutSeconds, 3600) : 300;

        const [action] = await db
          .insert(agentResponseActions)
          .values({
            orgId,
            sensorId,
            actionType,
            riskLevel: riskLevelVal,
            status: initialStatus,
            targetPid: typeof targetPid === "number" ? targetPid : null,
            targetProcessName: targetProcessName || null,
            targetIp: targetIp || null,
            targetFilePath: targetFilePath || null,
            targetUserName: targetUserName || null,
            targetDomain: targetDomain || null,
            targetServiceName: targetServiceName || null,
            scriptContent: scriptContent || null,
            scriptType: scriptType || null,
            parameters: parameters || null,
            requestedBy: userId,
            requestedByName: userName,
            reason: reason || null,
            incidentId: incidentId || null,
            timeoutSeconds: timeout,
            expiresAt: new Date(Date.now() + timeout * 1000),
            // Auto-approve low-risk actions
            ...(initialStatus === "approved"
              ? { approvedBy: "system", approvedByName: "Auto-approved (low risk)", approvedAt: new Date() }
              : {}),
          })
          .returning();

        log.info(`Response action created: ${actionType} on sensor ${sensor.hostname}`, {
          actionId: action.id,
          riskLevel: riskLevelVal,
          status: initialStatus,
          orgId,
        });

        res.status(201).json({
          action,
          needsApproval: initialStatus === "pending_approval",
          message:
            initialStatus === "pending_approval"
              ? `Action queued for approval (${riskLevelVal} risk)`
              : "Action approved and ready for dispatch",
        });
      } catch (error) {
        log.error("Failed to create response action", { error: String(error) });
        res.status(500).json({ message: "Failed to create response action" });
      }
    },
  );

  // ==========================================================================
  // LIST ACTIONS — pending approvals + history
  // ==========================================================================

  app.get("/api/native/response/actions", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const actionType = req.query.actionType as string | undefined;
      const sensorId = req.query.sensorId as string | undefined;
      const riskLevelFilter = req.query.riskLevel as string | undefined;
      const q = (req.query.q as string) || "";
      const limitParam = parseInt(String(req.query.limit || "100"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
      const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

      const conditions: unknown[] = [eq(agentResponseActions.orgId, orgId)];
      if (status && status !== "all") conditions.push(eq(agentResponseActions.status, status));
      if (actionType && actionType !== "all") conditions.push(eq(agentResponseActions.actionType, actionType));
      if (sensorId) conditions.push(eq(agentResponseActions.sensorId, sensorId));
      if (riskLevelFilter && riskLevelFilter !== "all")
        conditions.push(eq(agentResponseActions.riskLevel, riskLevelFilter));
      if (q) {
        conditions.push(
          or(
            ilike(agentResponseActions.targetProcessName, `%${q}%`),
            ilike(agentResponseActions.targetIp, `%${q}%`),
            ilike(agentResponseActions.targetFilePath, `%${q}%`),
          ),
        );
      }

      const actions = await db
        .select()
        .from(agentResponseActions)
        .where(and(...(conditions as any[])))
        .orderBy(desc(agentResponseActions.createdAt))
        .limit(limit)
        .offset(offset);

      // Get stats
      const statsResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'pending_approval') AS pending_count,
            COUNT(*) FILTER (WHERE status = 'approved') AS approved_count,
            COUNT(*) FILTER (WHERE status = 'executing') AS executing_count,
            COUNT(*) FILTER (WHERE status = 'completed') AS completed_count,
            COUNT(*) FILTER (WHERE status = 'failed') AS failed_count,
            COUNT(*) FILTER (WHERE status = 'rejected') AS rejected_count,
            COUNT(*) FILTER (WHERE risk_level = 'high') AS high_risk_count,
            COUNT(*) FILTER (WHERE risk_level = 'medium') AS medium_risk_count,
            COUNT(*) FILTER (WHERE risk_level = 'low') AS low_risk_count
          FROM agent_response_actions
          WHERE org_id = ${orgId}
        `);
      const s = (statsResult as any).rows?.[0] || {};

      res.json({
        actions,
        stats: {
          total: parseInt(s.total || "0"),
          pendingCount: parseInt(s.pending_count || "0"),
          approvedCount: parseInt(s.approved_count || "0"),
          executingCount: parseInt(s.executing_count || "0"),
          completedCount: parseInt(s.completed_count || "0"),
          failedCount: parseInt(s.failed_count || "0"),
          rejectedCount: parseInt(s.rejected_count || "0"),
          highRiskCount: parseInt(s.high_risk_count || "0"),
          mediumRiskCount: parseInt(s.medium_risk_count || "0"),
          lowRiskCount: parseInt(s.low_risk_count || "0"),
        },
      });
    } catch (error) {
      log.error("Failed to list response actions", { error: String(error) });
      res.status(500).json({ message: "Failed to list response actions" });
    }
  });

  // ==========================================================================
  // APPROVE ACTION — admin only
  // ==========================================================================

  app.post(
    "/api/native/response/actions/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.id);

        const [action] = await db
          .select()
          .from(agentResponseActions)
          .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
          .limit(1);

        if (!action) {
          return res.status(404).json({ message: "Action not found" });
        }

        if (action.status !== "pending_approval") {
          return res.status(400).json({ message: `Cannot approve action in status: ${action.status}` });
        }

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName || (req as any).user?.email || "Unknown";

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "approved",
            approvedBy: userId,
            approvedByName: userName,
            approvedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, actionId))
          .returning();

        log.info(`Action approved: ${action.actionType}`, { actionId, approvedBy: userId, orgId });

        res.json({ action: updated, message: "Action approved" });
      } catch (error) {
        log.error("Failed to approve action", { error: String(error) });
        res.status(500).json({ message: "Failed to approve action" });
      }
    },
  );

  // ==========================================================================
  // REJECT ACTION — admin only
  // ==========================================================================

  app.post(
    "/api/native/response/actions/:id/reject",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.id);
        const { reason } = req.body;

        const [action] = await db
          .select()
          .from(agentResponseActions)
          .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
          .limit(1);

        if (!action) {
          return res.status(404).json({ message: "Action not found" });
        }

        if (action.status !== "pending_approval") {
          return res.status(400).json({ message: `Cannot reject action in status: ${action.status}` });
        }

        const userId = (req as any).user?.id;

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "rejected",
            rejectedBy: userId,
            rejectedReason: reason || null,
            rejectedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, actionId))
          .returning();

        log.info(`Action rejected: ${action.actionType}`, { actionId, rejectedBy: userId, orgId });

        res.json({ action: updated, message: "Action rejected" });
      } catch (error) {
        log.error("Failed to reject action", { error: String(error) });
        res.status(500).json({ message: "Failed to reject action" });
      }
    },
  );

  // ==========================================================================
  // GET ACTION STATUS — poll for execution result
  // ==========================================================================

  app.get("/api/native/response/actions/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const actionId = String(req.params.id);

      const [action] = await db
        .select()
        .from(agentResponseActions)
        .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
        .limit(1);

      if (!action) {
        return res.status(404).json({ message: "Action not found" });
      }

      // Get sensor info
      const [sensor] = await db.select().from(nativeSensors).where(eq(nativeSensors.id, action.sensorId)).limit(1);

      res.json({
        action,
        sensor: sensor
          ? { id: sensor.id, hostname: sensor.hostname, platform: sensor.platform, status: sensor.status }
          : null,
      });
    } catch (error) {
      log.error("Failed to get action status", { error: String(error) });
      res.status(500).json({ message: "Failed to get action status" });
    }
  });

  // ==========================================================================
  // CANCEL ACTION — cancel pending or approved action
  // ==========================================================================

  app.post(
    "/api/native/response/actions/:id/cancel",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.id);

        const [action] = await db
          .select()
          .from(agentResponseActions)
          .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
          .limit(1);

        if (!action) {
          return res.status(404).json({ message: "Action not found" });
        }

        if (!["pending_approval", "approved"].includes(action.status)) {
          return res.status(400).json({ message: `Cannot cancel action in status: ${action.status}` });
        }

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "cancelled",
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, actionId))
          .returning();

        res.json({ action: updated, message: "Action cancelled" });
      } catch (error) {
        log.error("Failed to cancel action", { error: String(error) });
        res.status(500).json({ message: "Failed to cancel action" });
      }
    },
  );

  // ==========================================================================
  // SIMULATE EXECUTION — mark action as completed (for demo/testing)
  // ==========================================================================

  app.post(
    "/api/native/response/actions/:id/execute",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.id);

        const [action] = await db
          .select()
          .from(agentResponseActions)
          .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
          .limit(1);

        if (!action) {
          return res.status(404).json({ message: "Action not found" });
        }

        if (action.status !== "approved") {
          return res
            .status(400)
            .json({ message: `Action must be approved before execution. Current status: ${action.status}` });
        }

        // Mark as executing then completed
        await db
          .update(agentResponseActions)
          .set({
            status: "executing",
            dispatchedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, actionId));

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "completed",
            completedAt: new Date(),
            resultOutput: `Action ${action.actionType} executed successfully on sensor ${action.sensorId}`,
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, actionId))
          .returning();

        log.info(`Action executed: ${action.actionType}`, { actionId, orgId });

        res.json({ action: updated, message: "Action executed successfully" });
      } catch (error) {
        log.error("Failed to execute action", { error: String(error) });
        res.status(500).json({ message: "Failed to execute action" });
      }
    },
  );

  // ==========================================================================
  // ACTION TYPE REFERENCE — for the UI action creation modal
  // ==========================================================================

  app.get("/api/native/response/action-types", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    const actionTypes = [
      {
        type: "kill_process",
        label: "Kill Process",
        description: "Terminate a running process by PID or name",
        riskLevel: "medium",
        requiredFields: ["targetPid or targetProcessName"],
        icon: "Crosshair",
      },
      {
        type: "isolate_host",
        label: "Isolate Host",
        description: "Network-isolate the host — blocks all traffic except management channel",
        riskLevel: "high",
        requiredFields: [],
        icon: "ShieldOff",
      },
      {
        type: "block_ip",
        label: "Block IP",
        description: "Add an IP to the host firewall deny list",
        riskLevel: "medium",
        requiredFields: ["targetIp"],
        icon: "Ban",
      },
      {
        type: "quarantine_file",
        label: "Quarantine File",
        description: "Move a file to quarantine vault and strip execute permissions",
        riskLevel: "medium",
        requiredFields: ["targetFilePath"],
        icon: "FileWarning",
      },
      {
        type: "delete_file",
        label: "Delete File",
        description: "Permanently delete a file from the filesystem",
        riskLevel: "high",
        requiredFields: ["targetFilePath"],
        icon: "Trash2",
      },
      {
        type: "disable_user",
        label: "Disable User Account",
        description: "Lock a local user account to prevent further logins",
        riskLevel: "high",
        requiredFields: ["targetUserName"],
        icon: "UserX",
      },
      {
        type: "collect_forensics",
        label: "Collect Forensics",
        description: "Gather memory dump, running processes, open files, and network connections",
        riskLevel: "low",
        requiredFields: [],
        icon: "Search",
      },
      {
        type: "run_script",
        label: "Run Script",
        description: "Execute a custom script on the endpoint (bash/powershell)",
        riskLevel: "high",
        requiredFields: ["scriptContent", "scriptType"],
        icon: "Terminal",
      },
      {
        type: "block_domain",
        label: "Block Domain",
        description: "Add a domain to the DNS sinkhole / hosts file",
        riskLevel: "medium",
        requiredFields: ["targetDomain"],
        icon: "Globe",
      },
      {
        type: "enable_logging",
        label: "Enable Enhanced Logging",
        description: "Turn on verbose audit logging for the host",
        riskLevel: "low",
        requiredFields: [],
        icon: "FileText",
      },
      {
        type: "restart_service",
        label: "Restart Service",
        description: "Restart a system service by name",
        riskLevel: "low",
        requiredFields: ["targetServiceName"],
        icon: "RefreshCw",
      },
    ];

    res.json({ actionTypes });
  });
}
