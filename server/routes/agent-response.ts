/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or } from "drizzle-orm";
import { agentResponseActions, nativeSensors, integrationConfigs, AGENT_ACTION_TYPES } from "../../shared/schema";
import { expireTimedOutResponseActions, validateResponseActionTimeout } from "../response-action-timeouts";

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

        const timeoutResult = validateResponseActionTimeout(timeoutSeconds);
        if (!timeoutResult.valid) {
          return res.status(400).json({ message: timeoutResult.message });
        }
        const timeout = timeoutResult.timeoutSeconds;

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
            COUNT(*) FILTER (WHERE status = 'timed_out') AS timed_out_count,
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
          timedOutCount: parseInt(s.timed_out_count || "0"),
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
  // DISPATCH ACTION — leave approved action available for sensor pickup
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

        log.info(`Action made available for sensor pickup: ${action.actionType}`, { actionId, orgId });

        res.json({
          action,
          message: "Action is awaiting sensor pickup. Completion requires an agent-reported result.",
        });
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

  // ==========================================================================
  // 21.1 — APPROVAL QUEUE — pending actions with details + risk assessment
  // ==========================================================================

  app.get("/api/native/response/approval-queue", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const pending = await db
        .select()
        .from(agentResponseActions)
        .where(and(eq(agentResponseActions.orgId, orgId), eq(agentResponseActions.status, "pending_approval")))
        .orderBy(desc(agentResponseActions.createdAt))
        .limit(100);

      // Enrich with sensor info
      const enriched = await Promise.all(
        pending.map(async (action) => {
          const [sensor] = await db
            .select({
              id: nativeSensors.id,
              hostname: nativeSensors.hostname,
              platform: nativeSensors.platform,
              ipAddress: nativeSensors.ipAddress,
            })
            .from(nativeSensors)
            .where(eq(nativeSensors.id, action.sensorId))
            .limit(1);

          const targetSummary =
            action.targetIp ||
            action.targetProcessName ||
            action.targetFilePath ||
            action.targetUserName ||
            action.targetDomain ||
            action.targetServiceName ||
            "N/A";

          return {
            ...action,
            sensor: sensor || null,
            targetSummary,
            riskAssessment: {
              level: action.riskLevel,
              description:
                action.riskLevel === "high"
                  ? "This action may cause service disruption. Review carefully before approving."
                  : action.riskLevel === "medium"
                    ? "This action has moderate impact. Verify the target before approving."
                    : "Low-risk action. Safe to approve in most cases.",
              affectedScope:
                action.actionType === "isolate_host"
                  ? "Full network isolation — all connections will be severed except management channel"
                  : action.actionType === "disable_user"
                    ? "User will be locked out of all sessions immediately"
                    : action.actionType === "block_ip"
                      ? "All inbound/outbound traffic from this IP will be blocked"
                      : action.actionType === "kill_process"
                        ? "Process will be forcefully terminated — unsaved data may be lost"
                        : action.actionType === "quarantine_file"
                          ? "File will be moved to quarantine vault and stripped of execute permissions"
                          : action.actionType === "block_domain"
                            ? "DNS resolution for this domain will be sinkholed"
                            : "Action will be executed on the target endpoint",
            },
            waitingDuration: action.createdAt ? Date.now() - new Date(String(action.createdAt)).getTime() : 0,
          };
        }),
      );

      // Stats
      const statsResult = await db.execute(sql`
          SELECT
            COUNT(*) FILTER (WHERE status = 'pending_approval') AS pending_count,
            COUNT(*) FILTER (WHERE status = 'pending_approval' AND risk_level = 'high') AS high_risk_pending,
            COUNT(*) FILTER (WHERE status = 'pending_approval' AND risk_level = 'medium') AS medium_risk_pending,
            AVG(EXTRACT(EPOCH FROM (NOW() - created_at))) FILTER (WHERE status = 'pending_approval') AS avg_wait_seconds
          FROM agent_response_actions
          WHERE org_id = ${orgId}
        `);
      const s = (statsResult as any).rows?.[0] || {};

      res.json({
        queue: enriched,
        stats: {
          pendingCount: parseInt(s.pending_count || "0"),
          highRiskPending: parseInt(s.high_risk_pending || "0"),
          mediumRiskPending: parseInt(s.medium_risk_pending || "0"),
          avgWaitSeconds: Math.round(parseFloat(s.avg_wait_seconds || "0")),
        },
      });
    } catch (error) {
      log.error("Failed to fetch approval queue", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch approval queue" });
    }
  });

  // Batch approve/reject
  app.post(
    "/api/native/response/approval-queue/batch",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { actionIds, decision } = req.body;

        if (!Array.isArray(actionIds) || !actionIds.length) {
          return res.status(400).json({ message: "actionIds array is required" });
        }
        if (!["approved", "rejected"].includes(decision)) {
          return res.status(400).json({ message: "decision must be 'approved' or 'rejected'" });
        }

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName || (req as any).user?.email || "Unknown";
        const results: Array<{ id: string; status: string; success: boolean }> = [];

        for (const actionId of actionIds) {
          try {
            const [action] = await db
              .select()
              .from(agentResponseActions)
              .where(
                and(
                  eq(agentResponseActions.id, String(actionId)),
                  eq(agentResponseActions.orgId, orgId),
                  eq(agentResponseActions.status, "pending_approval"),
                ),
              )
              .limit(1);

            if (!action) {
              results.push({ id: String(actionId), status: "not_found", success: false });
              continue;
            }

            if (decision === "approved") {
              await db
                .update(agentResponseActions)
                .set({
                  status: "approved",
                  approvedBy: userId,
                  approvedByName: userName,
                  approvedAt: new Date(),
                  updatedAt: new Date(),
                })
                .where(eq(agentResponseActions.id, String(actionId)));
            } else {
              await db
                .update(agentResponseActions)
                .set({
                  status: "rejected",
                  rejectedBy: userId,
                  rejectedReason: req.body.reason || null,
                  rejectedAt: new Date(),
                  updatedAt: new Date(),
                })
                .where(eq(agentResponseActions.id, String(actionId)));
            }

            results.push({ id: String(actionId), status: decision, success: true });
          } catch (err) {
            results.push({ id: String(actionId), status: "error", success: false });
          }
        }

        const successCount = results.filter((r) => r.success).length;
        log.info(`Batch ${decision}: ${successCount}/${actionIds.length} actions`, { orgId });

        res.json({
          results,
          summary: { total: actionIds.length, succeeded: successCount, failed: actionIds.length - successCount },
        });
      } catch (error) {
        log.error("Batch approval/rejection failed", { error: String(error) });
        res.status(500).json({ message: "Batch operation failed" });
      }
    },
  );

  // ==========================================================================
  // 21.2 — IMPACT PREVIEW — show predicted impact before executing
  // ==========================================================================

  app.get(
    "/api/native/response/actions/:id/impact-preview",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
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

        const [sensor] = await db.select().from(nativeSensors).where(eq(nativeSensors.id, action.sensorId)).limit(1);

        // Build impact assessment based on action type
        const impactByType: Record<string, any> = {
          isolate_host: {
            severity: "critical",
            summary: `Isolating ${sensor?.hostname || "host"} (${sensor?.ipAddress || action.targetIp || "unknown IP"}) will sever all network connections except the management channel.`,
            affectedSessions: 2, // Estimated based on typical endpoint usage
            affectedServices: ["RDP", "SSH", "HTTP"],
            estimatedDowntime: "Until manual un-isolation",
            reversible: true,
            rollbackAction: "un-isolate host",
            warnings: [
              "All active user sessions will be disconnected immediately",
              "Running downloads and file transfers will be interrupted",
              "Scheduled tasks requiring network access will fail",
            ],
          },
          block_ip: {
            severity: "high",
            summary: `Blocking IP ${action.targetIp || "unknown"} will prevent all inbound and outbound traffic to/from this address.`,
            affectedSessions: 0,
            affectedServices: [],
            estimatedDowntime: "N/A — only affects traffic to/from blocked IP",
            reversible: true,
            rollbackAction: "unblock IP",
            warnings: [
              "Any legitimate services communicating with this IP will be disrupted",
              "If this is a shared IP (NAT/proxy), multiple users may be affected",
            ],
          },
          block_domain: {
            severity: "high",
            summary: `Blocking domain ${action.targetDomain || "unknown"} will sinkhole DNS resolution for this domain.`,
            affectedSessions: 0,
            affectedServices: [],
            estimatedDowntime: "N/A — only affects DNS resolution for blocked domain",
            reversible: true,
            rollbackAction: "unblock domain",
            warnings: ["All subdomains will also be affected", "DNS cache may delay the effect by up to TTL seconds"],
          },
          disable_user: {
            severity: "critical",
            summary: `Disabling user "${action.targetUserName || "unknown"}" will lock the account and terminate all active sessions.`,
            affectedSessions: 1,
            affectedServices: ["Login", "SSO", "VPN", "Email"],
            estimatedDowntime: "Until account is manually re-enabled",
            reversible: true,
            rollbackAction: "re-enable user account",
            warnings: [
              "User will be immediately locked out of all systems",
              "MFA tokens will be invalidated",
              "Ongoing file operations may be interrupted",
            ],
          },
          kill_process: {
            severity: "medium",
            summary: `Terminating process "${action.targetProcessName || action.targetPid || "unknown"}" on ${sensor?.hostname || "host"}.`,
            affectedSessions: 0,
            affectedServices: [action.targetProcessName || "target process"],
            estimatedDowntime: "Process will need to be manually restarted if legitimate",
            reversible: false,
            rollbackAction: "restart process manually",
            warnings: ["Unsaved data in the process will be lost", "Child processes may become orphaned"],
          },
          quarantine_file: {
            severity: "medium",
            summary: `Quarantining file "${action.targetFilePath || "unknown"}" — moving to secure vault and removing execute permissions.`,
            affectedSessions: 0,
            affectedServices: [],
            estimatedDowntime: "N/A",
            reversible: true,
            rollbackAction: "restore file from quarantine",
            warnings: [
              "File will no longer be accessible at its original path",
              "Any processes using this file may crash",
            ],
          },
        };

        const impact = impactByType[action.actionType] || {
          severity: "low",
          summary: `Executing ${action.actionType} on ${sensor?.hostname || "target"}.`,
          affectedSessions: 0,
          affectedServices: [],
          estimatedDowntime: "Minimal",
          reversible: true,
          rollbackAction: "undo action",
          warnings: [],
        };

        // Check for similar past actions
        const pastActions = await db
          .select({
            id: agentResponseActions.id,
            status: agentResponseActions.status,
            completedAt: agentResponseActions.completedAt,
          })
          .from(agentResponseActions)
          .where(
            and(
              eq(agentResponseActions.orgId, orgId),
              eq(agentResponseActions.actionType, action.actionType),
              eq(agentResponseActions.sensorId, action.sensorId),
            ),
          )
          .orderBy(desc(agentResponseActions.createdAt))
          .limit(5);

        const pastSuccessRate = pastActions.length
          ? Math.round((pastActions.filter((a) => a.status === "completed").length / pastActions.length) * 100)
          : null;

        res.json({
          actionId: action.id,
          actionType: action.actionType,
          target: {
            sensor: sensor
              ? { id: sensor.id, hostname: sensor.hostname, platform: sensor.platform, ipAddress: sensor.ipAddress }
              : null,
            value:
              action.targetIp ||
              action.targetProcessName ||
              action.targetFilePath ||
              action.targetUserName ||
              action.targetDomain ||
              "N/A",
          },
          impact,
          history: {
            pastActionsOnSameTarget: pastActions.length,
            pastSuccessRate,
          },
        });
      } catch (error) {
        log.error("Failed to generate impact preview", { error: String(error) });
        res.status(500).json({ message: "Failed to generate impact preview" });
      }
    },
  );

  // ==========================================================================
  // 21.3 — TIMELINE — all response actions with filters
  // ==========================================================================

  app.get("/api/native/response/timeline", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const actionTypeFilter = req.query.actionType as string | undefined;
      const statusFilter = req.query.status as string | undefined;
      const targetFilter = (req.query.target as string) || "";
      const sinceParam = req.query.since as string | undefined;
      const limitParam = parseInt(String(req.query.limit || "50"));
      const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);

      const conditions: unknown[] = [eq(agentResponseActions.orgId, orgId)];
      if (actionTypeFilter && actionTypeFilter !== "all") {
        conditions.push(eq(agentResponseActions.actionType, actionTypeFilter));
      }
      if (statusFilter && statusFilter !== "all") {
        conditions.push(eq(agentResponseActions.status, statusFilter));
      }
      if (targetFilter) {
        conditions.push(
          or(
            ilike(agentResponseActions.targetIp, `%${targetFilter}%`),
            ilike(agentResponseActions.targetProcessName, `%${targetFilter}%`),
            ilike(agentResponseActions.targetFilePath, `%${targetFilter}%`),
            ilike(agentResponseActions.targetUserName, `%${targetFilter}%`),
            ilike(agentResponseActions.targetDomain, `%${targetFilter}%`),
          ),
        );
      }
      if (sinceParam) {
        const sinceDate = new Date(sinceParam);
        if (!isNaN(sinceDate.getTime())) {
          conditions.push(sql`${agentResponseActions.createdAt} >= ${sinceDate}`);
        }
      }

      const actions = await db
        .select()
        .from(agentResponseActions)
        .where(and(...(conditions as any[])))
        .orderBy(desc(agentResponseActions.createdAt))
        .limit(limit);

      // Build timeline entries
      const timeline = await Promise.all(
        actions.map(async (action) => {
          const [sensor] = await db
            .select({ hostname: nativeSensors.hostname, platform: nativeSensors.platform })
            .from(nativeSensors)
            .where(eq(nativeSensors.id, action.sensorId))
            .limit(1);

          const durationMs =
            action.completedAt && action.dispatchedAt
              ? new Date(String(action.completedAt)).getTime() - new Date(String(action.dispatchedAt)).getTime()
              : null;

          return {
            id: action.id,
            actionType: action.actionType,
            status: action.status,
            riskLevel: action.riskLevel,
            target:
              action.targetIp ||
              action.targetProcessName ||
              action.targetFilePath ||
              action.targetUserName ||
              action.targetDomain ||
              "N/A",
            sensorHostname: sensor?.hostname || "Unknown",
            sensorPlatform: sensor?.platform || "unknown",
            requestedBy: action.requestedByName || "System",
            requestedAt: action.createdAt,
            approvedBy: action.approvedByName || null,
            approvedAt: action.approvedAt,
            dispatchedAt: action.dispatchedAt,
            completedAt: action.completedAt,
            durationMs,
            reason: action.reason,
            incidentId: action.incidentId,
            outcome: action.resultOutput || action.resultError || null,
          };
        }),
      );

      res.json({ timeline, total: timeline.length });
    } catch (error) {
      log.error("Failed to fetch response action timeline", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch timeline" });
    }
  });

  // ==========================================================================
  // 21.4 — IDEMPOTENCY — prevent duplicate action execution
  // ==========================================================================

  app.post(
    "/api/native/response/actions/check-duplicate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { actionType, sensorId, targetIp, targetProcessName, targetFilePath, targetUserName, targetDomain } =
          req.body;

        if (!actionType) {
          return res.status(400).json({ message: "actionType is required" });
        }

        // Look for active (non-terminal) actions of the same type on the same target
        const conditions: unknown[] = [
          eq(agentResponseActions.orgId, orgId),
          eq(agentResponseActions.actionType, actionType),
          sql`${agentResponseActions.status} IN ('pending_approval', 'approved', 'executing')`,
        ];

        if (sensorId) conditions.push(eq(agentResponseActions.sensorId, sensorId));
        if (targetIp) conditions.push(eq(agentResponseActions.targetIp, targetIp));
        if (targetProcessName) conditions.push(eq(agentResponseActions.targetProcessName, targetProcessName));
        if (targetFilePath) conditions.push(eq(agentResponseActions.targetFilePath, targetFilePath));
        if (targetUserName) conditions.push(eq(agentResponseActions.targetUserName, targetUserName));
        if (targetDomain) conditions.push(eq(agentResponseActions.targetDomain, targetDomain));

        const existing = await db
          .select()
          .from(agentResponseActions)
          .where(and(...(conditions as any[])))
          .orderBy(desc(agentResponseActions.createdAt))
          .limit(5);

        const isDuplicate = existing.length > 0;

        res.json({
          isDuplicate,
          existingActions: existing.map((a) => ({
            id: a.id,
            status: a.status,
            createdAt: a.createdAt,
            requestedBy: a.requestedByName,
          })),
          recommendation: isDuplicate
            ? `An active ${actionType} action already exists for this target. Creating another would be a duplicate.`
            : `No active ${actionType} action found for this target. Safe to proceed.`,
        });
      } catch (error) {
        log.error("Duplicate check failed", { error: String(error) });
        res.status(500).json({ message: "Failed to check for duplicates" });
      }
    },
  );

  // Idempotent create — wraps the check + create in one call
  app.post(
    "/api/native/response/actions/idempotent-create",
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
          targetIp,
          targetProcessName,
          targetFilePath,
          targetUserName,
          targetDomain,
          reason,
          incidentId,
          timeoutSeconds,
          force,
        } = req.body;

        if (!sensorId || !actionType) {
          return res.status(400).json({ message: "sensorId and actionType are required" });
        }

        // Check for duplicates (unless force=true)
        if (!force) {
          const dupeConditions: unknown[] = [
            eq(agentResponseActions.orgId, orgId),
            eq(agentResponseActions.actionType, actionType),
            eq(agentResponseActions.sensorId, sensorId),
            sql`${agentResponseActions.status} IN ('pending_approval', 'approved', 'executing')`,
          ];
          if (targetIp) dupeConditions.push(eq(agentResponseActions.targetIp, targetIp));
          if (targetUserName) dupeConditions.push(eq(agentResponseActions.targetUserName, targetUserName));
          if (targetDomain) dupeConditions.push(eq(agentResponseActions.targetDomain, targetDomain));

          const [existing] = await db
            .select({ id: agentResponseActions.id, status: agentResponseActions.status })
            .from(agentResponseActions)
            .where(and(...(dupeConditions as any[])))
            .limit(1);

          if (existing) {
            return res.status(409).json({
              message: `Duplicate action detected: ${actionType} already ${existing.status} (ID: ${existing.id}). Use force=true to override.`,
              existingActionId: existing.id,
              existingStatus: existing.status,
            });
          }
        }

        // Verify sensor
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
        const timeoutResult = validateResponseActionTimeout(timeoutSeconds);
        if (!timeoutResult.valid) {
          return res.status(400).json({ message: timeoutResult.message });
        }
        const timeout = timeoutResult.timeoutSeconds;

        const [action] = await db
          .insert(agentResponseActions)
          .values({
            orgId,
            sensorId,
            actionType,
            riskLevel: riskLevelVal,
            status: initialStatus,
            targetIp: targetIp || null,
            targetProcessName: targetProcessName || null,
            targetFilePath: targetFilePath || null,
            targetUserName: targetUserName || null,
            targetDomain: targetDomain || null,
            requestedBy: userId,
            requestedByName: userName,
            reason: reason || null,
            incidentId: incidentId || null,
            timeoutSeconds: timeout,
            expiresAt: new Date(Date.now() + timeout * 1000),
            ...(initialStatus === "approved"
              ? { approvedBy: "system", approvedByName: "Auto-approved (low risk)", approvedAt: new Date() }
              : {}),
          })
          .returning();

        res.status(201).json({ action, needsApproval: initialStatus === "pending_approval", isDuplicate: false });
      } catch (error) {
        log.error("Idempotent create failed", { error: String(error) });
        res.status(500).json({ message: "Failed to create action" });
      }
    },
  );

  // ==========================================================================
  // 21.5 — HEALTH CHECKS — verify action actually succeeded
  // ==========================================================================

  app.post(
    "/api/native/response/actions/:id/verify",
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

        if (!["completed", "executing"].includes(action.status)) {
          return res
            .status(400)
            .json({ message: `Cannot verify action in status: ${action.status}. Must be completed or executing.` });
        }

        const checks: Array<{ check: string; status: "pass" | "fail" | "unknown"; detail: string }> = [];
        checks.push({
          check: "agent_report",
          status:
            action.status === "completed" && action.resultOutput
              ? "pass"
              : action.status === "failed"
                ? "fail"
                : "unknown",
          detail: action.resultOutput
            ? `Sensor reported: ${action.resultOutput}`
            : "No agent-reported output is available for this action.",
        });
        checks.push({
          check: "external_state",
          status: "unknown",
          detail: "External provider or endpoint state cannot be independently verified by SecureNexus.",
        });

        const allPassed = checks.every((c) => c.status === "pass");
        const anyFailed = checks.some((c) => c.status === "fail");

        // Update the action with verification result
        await db
          .update(agentResponseActions)
          .set({
            parameters: {
              ...(typeof action.parameters === "object" && action.parameters ? action.parameters : {}),
              verificationResult: {
                verified: allPassed,
                checks,
                verifiedAt: new Date().toISOString(),
                verifiedBy: (req as any).user?.id,
              },
            } as any,
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, actionId));

        res.json({
          actionId: action.id,
          actionType: action.actionType,
          verificationStatus: anyFailed ? "failed" : allPassed ? "agent_reported" : "unverified",
          checks,
          verifiedAt: new Date().toISOString(),
        });
      } catch (error) {
        log.error("Health check verification failed", { error: String(error) });
        res.status(500).json({ message: "Failed to verify action" });
      }
    },
  );

  // ==========================================================================
  // 21.6 — GRADUATED AUTONOMOUS RESPONSE — confidence-based automation
  // ==========================================================================

  // In-memory threshold config (per-org)
  const autonomousThresholds = new Map<
    string,
    Record<string, { autoExecute: number; requireApproval: number; suggestOnly: number }>
  >();

  const DEFAULT_THRESHOLDS: Record<string, { autoExecute: number; requireApproval: number; suggestOnly: number }> = {
    isolate_host: { autoExecute: 98, requireApproval: 80, suggestOnly: 0 },
    block_ip: { autoExecute: 95, requireApproval: 70, suggestOnly: 0 },
    block_domain: { autoExecute: 95, requireApproval: 70, suggestOnly: 0 },
    disable_user: { autoExecute: 98, requireApproval: 85, suggestOnly: 0 },
    kill_process: { autoExecute: 90, requireApproval: 70, suggestOnly: 0 },
    quarantine_file: { autoExecute: 90, requireApproval: 65, suggestOnly: 0 },
    delete_file: { autoExecute: 99, requireApproval: 90, suggestOnly: 0 },
    collect_forensics: { autoExecute: 50, requireApproval: 20, suggestOnly: 0 },
    enable_logging: { autoExecute: 50, requireApproval: 20, suggestOnly: 0 },
    run_script: { autoExecute: 99, requireApproval: 90, suggestOnly: 0 },
    restart_service: { autoExecute: 90, requireApproval: 60, suggestOnly: 0 },
  };

  app.get(
    "/api/native/response/autonomous-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const orgConfig = autonomousThresholds.get(orgId) || {};
        const merged: Record<string, any> = {};

        for (const [actionType, defaults] of Object.entries(DEFAULT_THRESHOLDS)) {
          merged[actionType] = orgConfig[actionType] || defaults;
        }

        res.json({
          thresholds: merged,
          description: {
            autoExecute: "Confidence >= this threshold: action is auto-executed without human review",
            requireApproval: "Confidence >= this threshold but < autoExecute: action queued for approval",
            suggestOnly: "Confidence < requireApproval: action is suggested only, no automatic creation",
          },
        });
      } catch (error) {
        log.error("Failed to fetch autonomous config", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch autonomous config" });
      }
    },
  );

  app.patch(
    "/api/native/response/autonomous-config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { thresholds } = req.body;

        if (!thresholds || typeof thresholds !== "object") {
          return res.status(400).json({ message: "thresholds object is required" });
        }

        const existing = autonomousThresholds.get(orgId) || {};

        for (const [actionType, values] of Object.entries(thresholds as Record<string, any>)) {
          if (!DEFAULT_THRESHOLDS[actionType]) continue;
          const autoExec =
            typeof values.autoExecute === "number"
              ? Math.min(100, Math.max(0, values.autoExecute))
              : (existing[actionType]?.autoExecute ?? DEFAULT_THRESHOLDS[actionType].autoExecute);
          const reqApproval =
            typeof values.requireApproval === "number"
              ? Math.min(100, Math.max(0, values.requireApproval))
              : (existing[actionType]?.requireApproval ?? DEFAULT_THRESHOLDS[actionType].requireApproval);

          // Ensure autoExecute >= requireApproval
          existing[actionType] = {
            autoExecute: Math.max(autoExec, reqApproval),
            requireApproval: reqApproval,
            suggestOnly: 0,
          };
        }

        autonomousThresholds.set(orgId, existing);

        log.info("Autonomous response thresholds updated", { orgId });
        res.json({ thresholds: existing, message: "Thresholds updated" });
      } catch (error) {
        log.error("Failed to update autonomous config", { error: String(error) });
        res.status(500).json({ message: "Failed to update autonomous config" });
      }
    },
  );

  // Evaluate confidence and determine action disposition
  app.post(
    "/api/native/response/evaluate-confidence",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { actionType, confidenceScore, detectionSource, detectionId } = req.body;

        if (!actionType || typeof confidenceScore !== "number") {
          return res.status(400).json({ message: "actionType and confidenceScore (number 0-100) are required" });
        }

        const score = Math.min(100, Math.max(0, confidenceScore));
        const orgConfig = autonomousThresholds.get(orgId) || {};
        const thresholds = orgConfig[actionType] ||
          DEFAULT_THRESHOLDS[actionType] || { autoExecute: 95, requireApproval: 70, suggestOnly: 0 };

        let disposition: "auto_execute" | "require_approval" | "suggest_only";
        let explanation: string;

        if (score >= thresholds.autoExecute) {
          disposition = "auto_execute";
          explanation = `Confidence ${score}% >= auto-execute threshold ${thresholds.autoExecute}%. Action will be executed automatically.`;
        } else if (score >= thresholds.requireApproval) {
          disposition = "require_approval";
          explanation = `Confidence ${score}% is between approval threshold ${thresholds.requireApproval}% and auto-execute ${thresholds.autoExecute}%. Action queued for human approval.`;
        } else {
          disposition = "suggest_only";
          explanation = `Confidence ${score}% < approval threshold ${thresholds.requireApproval}%. Action will be suggested but not automatically created.`;
        }

        res.json({
          actionType,
          confidenceScore: score,
          disposition,
          explanation,
          thresholds,
          detectionSource: detectionSource || null,
          detectionId: detectionId || null,
        });
      } catch (error) {
        log.error("Confidence evaluation failed", { error: String(error) });
        res.status(500).json({ message: "Failed to evaluate confidence" });
      }
    },
  );

  // ==========================================================================
  // 21.7 — CONNECTOR EXECUTION — verify actions execute through connectors
  // ==========================================================================

  const CONNECTOR_REGISTRY: Record<
    string,
    { platforms: string[]; executionMethod: string; verificationMethod: string }
  > = {
    isolate_host: {
      platforms: ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender for Endpoint", "Carbon Black"],
      executionMethod: "API call to EDR platform → contain/isolate endpoint",
      verificationMethod: "Poll EDR platform API for isolation status confirmation",
    },
    block_ip: {
      platforms: ["Palo Alto Networks", "FortiGate", "Cisco ASA", "Check Point", "AWS Security Groups"],
      executionMethod: "API call to firewall → create deny rule for IP",
      verificationMethod: "Query firewall rule table to confirm rule exists",
    },
    block_domain: {
      platforms: ["Infoblox", "BlueCat DNS", "Cisco Umbrella", "Zscaler"],
      executionMethod: "API call to DNS/proxy → add domain to block list",
      verificationMethod: "DNS lookup to confirm sinkhole response",
    },
    disable_user: {
      platforms: ["Okta", "Azure Active Directory", "Google Workspace", "CyberArk"],
      executionMethod: "API call to IdP → suspend/disable user account",
      verificationMethod: "Query IdP API to confirm account status is disabled",
    },
    quarantine_file: {
      platforms: ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender", "Carbon Black"],
      executionMethod: "API call to EDR → quarantine file by hash/path",
      verificationMethod: "Query EDR quarantine vault for file entry",
    },
    kill_process: {
      platforms: ["CrowdStrike Falcon RTR", "SentinelOne Remote Shell", "Microsoft Defender Live Response"],
      executionMethod: "API call to EDR → remote kill process by PID",
      verificationMethod: "Query process list on endpoint to confirm termination",
    },
  };

  app.get(
    "/api/native/response/connector-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        // Check which integrations the org has configured
        const activeIntegrations = await db
          .select({
            id: integrationConfigs.id,
            type: integrationConfigs.type,
            name: integrationConfigs.name,
            status: integrationConfigs.status,
          })
          .from(integrationConfigs)
          .where(and(eq(integrationConfigs.orgId, orgId), eq(integrationConfigs.status, "active")));

        // Map action types to their connector status
        const connectorStatus = Object.entries(CONNECTOR_REGISTRY).map(([actionType, info]) => {
          const matchingIntegrations = activeIntegrations.filter((i) =>
            info.platforms.some(
              (p) =>
                i.name?.toLowerCase().includes(p.toLowerCase().split(" ")[0]) ||
                i.type?.toLowerCase().includes(p.toLowerCase().split(" ")[0]),
            ),
          );

          return {
            actionType,
            supportedPlatforms: info.platforms,
            executionMethod: info.executionMethod,
            verificationMethod: info.verificationMethod,
            connectedPlatforms: matchingIntegrations.map((i) => ({ id: i.id, name: i.name, type: i.type })),
            hasMatchingIntegration: matchingIntegrations.length > 0,
            isAvailable: false,
            executionMode: "unavailable",
          };
        });

        const configuredCount = connectorStatus.filter((c) => c.hasMatchingIntegration).length;

        res.json({
          connectorStatus,
          summary: {
            totalActionTypes: connectorStatus.length,
            configuredActionTypes: configuredCount,
            availableActionTypes: 0,
            unavailableActionTypes: connectorStatus.length,
            activeIntegrations: activeIntegrations.length,
          },
        });
      } catch (error) {
        log.error("Failed to fetch connector status", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch connector status" });
      }
    },
  );

  // Connector execution is not implemented until provider adapters and credentials exist.
  app.post(
    "/api/native/response/actions/:id/execute-via-connector",
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

        if (!action) return res.status(404).json({ message: "Action not found" });
        if (action.status !== "approved") {
          return res.status(400).json({ message: `Action must be approved. Current: ${action.status}` });
        }

        res.status(503).json({
          action,
          code: "CONNECTOR_EXECUTION_UNAVAILABLE",
          message: "Connector execution is unavailable: no provider adapter is configured.",
          executionDetails: {
            connectorUsed: null,
            isLiveExecution: false,
            executionLog: [],
          },
        });
      } catch (error) {
        log.error("Connector execution failed", { error: String(error) });
        res.status(500).json({ message: "Failed to execute via connector" });
      }
    },
  );

  // ==========================================================================
  // 21.8 — ROLLBACK VERIFICATION — verify rollback succeeded
  // ==========================================================================

  const ROLLBACK_ACTION_MAP: Record<string, string> = {
    isolate_host: "unisolate_host",
    block_ip: "unblock_ip",
    block_domain: "unblock_domain",
    disable_user: "enable_user",
    quarantine_file: "restore_file",
    kill_process: "N/A — process cannot be un-killed",
  };

  app.post(
    "/api/native/response/actions/:id/rollback",
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

        if (!action) return res.status(404).json({ message: "Action not found" });
        if (action.status !== "completed") {
          return res.status(400).json({ message: `Can only rollback completed actions. Current: ${action.status}` });
        }

        const rollbackAction = ROLLBACK_ACTION_MAP[action.actionType];
        if (!rollbackAction || rollbackAction.startsWith("N/A")) {
          return res.status(400).json({
            message: `Action type ${action.actionType} cannot be rolled back: ${rollbackAction || "no rollback defined"}`,
          });
        }

        const userId = (req as any).user?.id;
        const userName = (req as any).user?.firstName || (req as any).user?.email || "Unknown";

        // Create rollback action record
        const [rollback] = await db
          .insert(agentResponseActions)
          .values({
            orgId,
            sensorId: action.sensorId,
            actionType: rollbackAction,
            riskLevel: action.riskLevel,
            status: "approved",
            targetIp: action.targetIp,
            targetProcessName: action.targetProcessName,
            targetFilePath: action.targetFilePath,
            targetUserName: action.targetUserName,
            targetDomain: action.targetDomain,
            targetServiceName: action.targetServiceName,
            requestedBy: userId,
            requestedByName: userName,
            reason: `Rollback of action ${actionId}: ${rollbackAction}`,
            incidentId: action.incidentId,
            approvedBy: userId,
            approvedByName: userName,
            approvedAt: new Date(),
            timeoutSeconds: 300,
            expiresAt: new Date(Date.now() + 300_000),
            parameters: { originalActionId: actionId, rollbackType: rollbackAction } as any,
          })
          .returning();

        log.info(`Rollback action made available for sensor pickup: ${action.actionType} → ${rollbackAction}`, {
          actionId,
          rollbackId: rollback.id,
          orgId,
        });

        res.json({
          rollbackAction: rollback,
          originalActionId: actionId,
          rollbackType: rollbackAction,
          message: `Rollback is awaiting sensor pickup. Completion requires an agent-reported result.`,
        });
      } catch (error) {
        log.error("Rollback failed", { error: String(error) });
        res.status(500).json({ message: "Failed to rollback action" });
      }
    },
  );

  // Verify rollback succeeded
  app.post(
    "/api/native/response/actions/:id/verify-rollback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.id);

        // Find rollback actions for this original action
        const rollbacks = await db
          .select()
          .from(agentResponseActions)
          .where(
            and(
              eq(agentResponseActions.orgId, orgId),
              sql`${agentResponseActions.parameters}->>'originalActionId' = ${actionId}`,
            ),
          )
          .orderBy(desc(agentResponseActions.createdAt))
          .limit(5);

        if (!rollbacks.length) {
          return res.status(404).json({ message: "No rollback actions found for this action" });
        }

        const [originalAction] = await db
          .select()
          .from(agentResponseActions)
          .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
          .limit(1);

        const latestRollback = rollbacks[0];
        const verificationChecks: Array<{ check: string; status: "pass" | "fail" | "unknown"; detail: string }> = [];

        if (originalAction) {
          const rollbackType = ROLLBACK_ACTION_MAP[originalAction.actionType] || "unknown";
          const hasAgentCompletion = latestRollback.status === "completed" && Boolean(latestRollback.resultOutput);
          const agentDetail = latestRollback.resultOutput
            ? `Agent reported: ${latestRollback.resultOutput}`
            : `No agent completion evidence is available (status: ${latestRollback.status}).`;

          if (originalAction.actionType === "isolate_host") {
            verificationChecks.push({
              check: "agent_reported_rollback",
              status: hasAgentCompletion ? "pass" : latestRollback.status === "failed" ? "fail" : "unknown",
              detail: agentDetail,
            });
            verificationChecks.push({
              check: "external_state",
              status: "unknown",
              detail: "External host isolation state cannot be verified by SecureNexus without provider evidence.",
            });
          } else if (originalAction.actionType === "block_ip") {
            verificationChecks.push({
              check: "agent_reported_rollback",
              status: hasAgentCompletion ? "pass" : latestRollback.status === "failed" ? "fail" : "unknown",
              detail: agentDetail,
            });
            verificationChecks.push({
              check: "external_state",
              status: "unknown",
              detail: "External firewall state cannot be verified by SecureNexus without provider evidence.",
            });
          } else if (originalAction.actionType === "block_domain") {
            verificationChecks.push({
              check: "agent_reported_rollback",
              status: hasAgentCompletion ? "pass" : latestRollback.status === "failed" ? "fail" : "unknown",
              detail: agentDetail,
            });
            verificationChecks.push({
              check: "external_state",
              status: "unknown",
              detail: "External DNS/proxy state cannot be verified by SecureNexus without provider evidence.",
            });
          } else if (originalAction.actionType === "disable_user") {
            verificationChecks.push({
              check: "agent_reported_rollback",
              status: hasAgentCompletion ? "pass" : latestRollback.status === "failed" ? "fail" : "unknown",
              detail: agentDetail,
            });
            verificationChecks.push({
              check: "external_state",
              status: "unknown",
              detail: "External identity-provider state cannot be verified by SecureNexus without provider evidence.",
            });
          } else if (originalAction.actionType === "quarantine_file") {
            verificationChecks.push({
              check: "agent_reported_rollback",
              status: hasAgentCompletion ? "pass" : latestRollback.status === "failed" ? "fail" : "unknown",
              detail: agentDetail,
            });
            verificationChecks.push({
              check: "external_state",
              status: "unknown",
              detail: "External endpoint file state cannot be verified by SecureNexus without provider evidence.",
            });
          } else {
            verificationChecks.push({
              check: "rollback_completed",
              status: hasAgentCompletion ? "pass" : latestRollback.status === "failed" ? "fail" : "unknown",
              detail: `Rollback action (${rollbackType}) status: ${latestRollback.status}. ${agentDetail}`,
            });
          }
        }

        const allPassed = verificationChecks.every((c) => c.status === "pass");
        const anyFailed = verificationChecks.some((c) => c.status === "fail");

        res.json({
          originalActionId: actionId,
          latestRollbackId: latestRollback.id,
          rollbackStatus: latestRollback.status,
          verificationStatus: anyFailed ? "failed" : allPassed ? "agent_reported" : "unverified",
          checks: verificationChecks,
          rollbackHistory: rollbacks.map((r) => ({
            id: r.id,
            status: r.status,
            createdAt: r.createdAt,
            completedAt: r.completedAt,
          })),
        });
      } catch (error) {
        log.error("Rollback verification failed", { error: String(error) });
        res.status(500).json({ message: "Failed to verify rollback" });
      }
    },
  );

  // ==========================================================================
  // 50.5: COMMAND TIMEOUT — configurable timeouts, alerts, cancellation
  // ==========================================================================

  app.post(
    "/api/native/response/actions/:id/cancel",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actionId = String(req.params.id);
        const { reason } = req.body as { reason?: string };

        const [action] = await db
          .select()
          .from(agentResponseActions)
          .where(and(eq(agentResponseActions.id, actionId), eq(agentResponseActions.orgId, orgId)))
          .limit(1);

        if (!action) {
          res.status(404).json({ message: "Action not found" });
          return;
        }

        // Only allow cancellation of pending/approved/executing actions
        const cancellableStatuses = ["pending_approval", "approved", "executing"];
        if (!cancellableStatuses.includes(action.status)) {
          res.status(400).json({
            message: `Cannot cancel action in '${action.status}' status. Only pending_approval, approved, or executing actions can be cancelled.`,
          });
          return;
        }

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "failed",
            completedAt: new Date(),
            resultOutput: JSON.stringify({
              cancelled: true,
              cancelledAt: new Date().toISOString(),
              cancelledBy: (req.user as Record<string, unknown>)?.id || "unknown",
              cancelReason: reason || "Manually cancelled by operator",
            }),
          })
          .where(eq(agentResponseActions.id, actionId))
          .returning();

        log.info("Action cancelled", {
          actionId,
          previousStatus: action.status,
          cancelledBy: (req.user as Record<string, unknown>)?.id,
          reason,
        });

        res.json({ action: updated, message: "Action cancelled successfully" });
      } catch (error) {
        log.error("Cancel action failed", { error: String(error) });
        res.status(500).json({ message: "Failed to cancel action" });
      }
    },
  );

  // Check for timed-out actions
  app.post(
    "/api/native/response/actions/check-timeouts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const timedOutActions = await expireTimedOutResponseActions(orgId);

        res.json({
          checked: timedOutActions.length,
          timedOut: timedOutActions.length,
          timedOutActionIds: timedOutActions.map((action) => action.id),
        });
      } catch (error) {
        log.error("Timeout check failed", { error: String(error) });
        res.status(500).json({ message: "Failed to check timeouts" });
      }
    },
  );

  // ==========================================================================
  // 50.6: COMMAND AUDIT TRAIL — comprehensive forensic logging
  // ==========================================================================

  app.get("/api/native/response/audit-trail", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(parseInt(String(req.query.limit)) || 50, 200);
      const offset = parseInt(String(req.query.offset)) || 0;
      const actionType = req.query.actionType as string | undefined;
      const status = req.query.status as string | undefined;
      const sensorId = req.query.sensorId as string | undefined;

      const conditions = [eq(agentResponseActions.orgId, orgId)];
      if (actionType) conditions.push(eq(agentResponseActions.actionType, actionType));
      if (status) conditions.push(eq(agentResponseActions.status, status));
      if (sensorId) conditions.push(eq(agentResponseActions.sensorId, sensorId));

      const actions = await db
        .select()
        .from(agentResponseActions)
        .where(and(...conditions))
        .orderBy(desc(agentResponseActions.createdAt))
        .limit(limit)
        .offset(offset);

      // Enrich with sensor info for each action
      const auditEntries = await Promise.all(
        actions.map(async (action) => {
          const [sensor] = await db
            .select({
              hostname: nativeSensors.hostname,
              ipAddress: nativeSensors.ipAddress,
              platform: nativeSensors.platform,
            })
            .from(nativeSensors)
            .where(eq(nativeSensors.id, action.sensorId))
            .limit(1);

          const durationMs =
            action.completedAt && action.dispatchedAt
              ? new Date(action.completedAt).getTime() - new Date(action.dispatchedAt).getTime()
              : null;

          return {
            id: action.id,
            actionType: action.actionType,
            status: action.status,
            riskLevel: action.riskLevel,
            sensorId: action.sensorId,
            sensorHostname: sensor?.hostname || "Unknown",
            sensorIp: sensor?.ipAddress || null,
            sensorPlatform: sensor?.platform || null,
            requestedBy: action.requestedByName || action.requestedBy,
            approvedBy: action.approvedByName || action.approvedBy,
            reason: action.reason,
            incidentId: action.incidentId,
            targetPid: action.targetPid,
            targetProcessName: action.targetProcessName,
            targetIp: action.targetIp,
            targetFilePath: action.targetFilePath,
            targetUserName: action.targetUserName,
            targetDomain: action.targetDomain,
            scriptType: action.scriptType,
            timeoutSeconds: action.timeoutSeconds,
            resultOutput: action.resultOutput,
            resultError: action.resultError,
            durationMs,
            createdAt: action.createdAt,
            dispatchedAt: action.dispatchedAt,
            completedAt: action.completedAt,
            approvedAt: action.approvedAt,
          };
        }),
      );

      // Aggregate stats for the audit trail
      const totalResult = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(agentResponseActions)
        .where(and(...conditions));

      const statusBreakdown = await db
        .select({
          status: agentResponseActions.status,
          count: sql<number>`count(*)::int`,
        })
        .from(agentResponseActions)
        .where(eq(agentResponseActions.orgId, orgId))
        .groupBy(agentResponseActions.status);

      res.json({
        entries: auditEntries,
        total: totalResult[0]?.count || 0,
        offset,
        limit,
        statusBreakdown: Object.fromEntries(statusBreakdown.map((s) => [s.status, s.count])),
      });
    } catch (error) {
      log.error("Audit trail query failed", { error: String(error) });
      res.status(500).json({ message: "Failed to retrieve audit trail" });
    }
  });

  // Reject an action (counterpart to approve)
  app.post(
    "/api/native/response/actions/:id/reject",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
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
          res.status(404).json({ message: "Action not found" });
          return;
        }

        if (action.status !== "pending_approval") {
          res.status(400).json({ message: "Only pending_approval actions can be rejected" });
          return;
        }

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "failed",
            completedAt: new Date(),
            rejectedBy: String((req.user as Record<string, unknown>)?.id || ""),
            rejectedAt: new Date(),
            rejectedReason: String(req.body?.reason || "Rejected by approver"),
          })
          .where(eq(agentResponseActions.id, actionId))
          .returning();

        log.info("Action rejected", { actionId, rejectedBy: (req.user as Record<string, unknown>)?.id });
        res.json({ action: updated, message: "Action rejected" });
      } catch (error) {
        log.error("Reject action failed", { error: String(error) });
        res.status(500).json({ message: "Failed to reject action" });
      }
    },
  );
}
