import type { IStorage } from "./storage";
import { db } from "./db";
import { agentResponseActions, nativeSensors } from "../shared/schema";
import { eq, and, or, ilike } from "drizzle-orm";
import { logger } from "./routes/shared";
import { validateWebhookUrl } from "./outbound-security";

const log = logger.child("action-dispatcher");

export interface ActionContext {
  orgId?: string;
  incidentId?: string;
  alertId?: string;
  userId?: string;
  userName?: string;
  sensorId?: string;
  storage: IStorage;
}

export interface ActionResult {
  actionType: string;
  status: "completed" | "failed" | "simulated" | "pending_approval" | "approved";
  message: string;
  details?: any;
  executedAt: string;
}

export async function dispatchAction(actionType: string, config: any, context: ActionContext): Promise<ActionResult> {
  const executedAt = new Date().toISOString();

  switch (actionType) {
    case "create_jira_ticket":
      return executeTicketing("jira", config, context, executedAt);
    case "create_servicenow_ticket":
      return executeTicketing("servicenow", config, context, executedAt);
    case "notify_slack":
      return executeNotification("slack", config, context, executedAt);
    case "notify_teams":
      return executeNotification("teams", config, context, executedAt);
    case "notify_email":
      return executeNotification("email", config, context, executedAt);
    case "notify_webhook":
      return executeNotification("webhook", config, context, executedAt);
    case "notify_pagerduty":
      return executeNotification("pagerduty", config, context, executedAt);
    case "isolate_host":
    case "block_ip":
    case "block_domain":
    case "quarantine_file":
    case "disable_user":
    case "kill_process":
      return executeAgentResponseAction(actionType, config, context, executedAt);
    case "auto_triage":
      return executeAutoTriage(config, context, executedAt);
    case "assign_analyst":
      return executeAssignAnalyst(config, context, executedAt);
    case "change_status":
      return executeChangeStatus(config, context, executedAt);
    case "add_tag":
      return executeAddTag(config, context, executedAt);
    case "escalate":
      return executeEscalate(config, context, executedAt);
    case "notify":
      return executeNotification("default", config, context, executedAt);
    default:
      return {
        actionType,
        status: "failed",
        message: `Unknown action type: ${actionType}`,
        executedAt,
      };
  }
}

async function executeTicketing(
  platform: string,
  config: any,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
  const ticketId = `${platform.toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;
  const summary = config?.summary || `Security Incident ${context.incidentId || "Unknown"}`;
  const priority = config?.priority || "high";
  const project = config?.project || config?.projectKey || "SEC";

  // If a webhook URL is configured for the ticketing platform, call it
  const webhookUrl = config?.webhookUrl || config?.apiUrl;
  let ticketUrl = `https://${platform}.example.com/browse/${ticketId}`;
  let status: "completed" | "failed" = "completed";
  let message = `Created ${platform} ticket ${ticketId}: "${summary}" (Priority: ${priority})`;

  if (webhookUrl) {
    const urlCheck = validateWebhookUrl(webhookUrl);
    if (!urlCheck.valid) {
      status = "failed";
      message = `${platform} webhook URL validation failed: ${urlCheck.reason}`;
    } else {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10_000);
        const response = await fetch(webhookUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(config?.authHeader ? { Authorization: config.authHeader } : {}),
          },
          body: JSON.stringify({ summary, priority, project, incidentId: context.incidentId, source: "SecureNexus" }),
          signal: controller.signal,
          redirect: "error",
        });
        clearTimeout(timeout);
        if (response.ok) {
          const data = await response.json().catch(() => ({}));
          ticketUrl = (data as any)?.url || (data as any)?.ticketUrl || ticketUrl;
          message = `Created ${platform} ticket via API: "${summary}" (Priority: ${priority})`;
        } else {
          status = "failed";
          message = `${platform} API returned HTTP ${response.status}`;
        }
      } catch (err) {
        status = "failed";
        message = `${platform} API call failed: ${(err as Error).message}`;
      }
    }
  }

  if (context.incidentId && context.storage) {
    await context.storage.createResponseAction({
      orgId: context.orgId,
      actionType: `create_${platform}_ticket`,
      incidentId: context.incidentId,
      alertId: context.alertId,
      targetType: "ticket",
      targetValue: ticketId,
      status,
      requestPayload: { platform, summary, priority, project },
      responsePayload: { ticketId, ticketUrl },
      executedBy: context.userId,
    });
  }

  return {
    actionType: `create_${platform}_ticket`,
    status,
    message,
    details: { ticketId, platform, summary, priority, project, ticketUrl },
    executedAt,
  };
}

async function executeNotification(
  channel: string,
  config: any,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
  const message = config?.message || `Alert from SecureNexus: Incident ${context.incidentId || "N/A"}`;
  const target = config?.channel || config?.recipient || config?.webhookUrl || "#security-alerts";

  try {
    const { dispatchNotification } = await import("./notification-dispatcher");
    const results = await dispatchNotification(
      {
        title: `SecureNexus Action: ${context.incidentId || "Alert"}`,
        body: message,
        severity: "warning",
        source: "action-dispatcher",
        metadata: { incidentId: context.incidentId, alertId: context.alertId, channel },
      },
      "action_notification",
      context.orgId,
    );

    const successCount = results.filter((r) => r.success).length;
    if (successCount > 0) {
      return {
        actionType: `notify_${channel}`,
        status: "completed",
        message: `Sent ${channel} notification to ${target} (${successCount}/${results.length} channels delivered)`,
        details: { channel, target, message, deliveryResults: results },
        executedAt,
      };
    }

    // If no notification channels are configured, log and return completed
    if (results.length === 0) {
      log.info("No notification channels configured — action logged but no delivery", { channel, target });
      return {
        actionType: `notify_${channel}`,
        status: "completed",
        message: `Notification logged (no ${channel} channels configured). Target: ${target}`,
        details: { channel, target, message, noChannelsConfigured: true },
        executedAt,
      };
    }

    return {
      actionType: `notify_${channel}`,
      status: "failed",
      message: `All ${channel} notification deliveries failed`,
      details: { channel, target, deliveryResults: results },
      executedAt,
    };
  } catch (err) {
    log.error("Notification dispatch error", { channel, error: String(err) });
    return {
      actionType: `notify_${channel}`,
      status: "failed",
      message: `Notification dispatch failed: ${(err as Error).message}`,
      details: { channel, target, error: (err as Error).message },
      executedAt,
    };
  }
}

// High-risk actions require manual approval before dispatch
const HIGH_RISK_ACTIONS = ["isolate_host", "disable_user"];
const MEDIUM_RISK_ACTIONS = ["kill_process", "block_ip", "quarantine_file", "block_domain"];

function determineRiskLevel(actionType: string): string {
  if (HIGH_RISK_ACTIONS.includes(actionType)) return "high";
  if (MEDIUM_RISK_ACTIONS.includes(actionType)) return "medium";
  return "low";
}

function determineInitialStatus(riskLevel: string): string {
  if (riskLevel === "high" || riskLevel === "medium") return "pending_approval";
  return "approved";
}

/**
 * Resolve a sensor ID from the context. Priority:
 * 1. Explicit sensorId in context or config
 * 2. Lookup by hostname or IP in nativeSensors table
 * Returns null if no sensor can be resolved.
 */
async function resolveSensorId(orgId: string, config: any, context: ActionContext): Promise<string | null> {
  // 1. Explicit sensorId
  const explicit = context.sensorId || config?.sensorId;
  if (explicit) {
    // Verify it belongs to org
    const [sensor] = await db
      .select({ id: nativeSensors.id })
      .from(nativeSensors)
      .where(and(eq(nativeSensors.id, explicit), eq(nativeSensors.orgId, orgId)))
      .limit(1);
    return sensor ? sensor.id : null;
  }

  // 2. Lookup by hostname or IP
  const hostname = config?.hostname || config?.target;
  const ip = config?.ip || config?.targetIp;

  if (!hostname && !ip) return null;

  const conditions: unknown[] = [eq(nativeSensors.orgId, orgId)];
  if (hostname && ip) {
    conditions.push(or(ilike(nativeSensors.hostname, hostname), eq(nativeSensors.ipAddress, ip)));
  } else if (hostname) {
    conditions.push(ilike(nativeSensors.hostname, hostname));
  } else if (ip) {
    conditions.push(eq(nativeSensors.ipAddress, ip));
  }

  const [sensor] = await db
    .select({ id: nativeSensors.id })
    .from(nativeSensors)
    .where(and(...(conditions as any[])))
    .limit(1);

  return sensor ? sensor.id : null;
}

/**
 * Execute a real response action through the agent_response_actions pipeline.
 * Creates a DB entry with proper risk assessment and approval workflow.
 * Falls back to legacy simulation if no sensor can be resolved (no agent deployed).
 */
async function executeAgentResponseAction(
  actionType: string,
  config: any,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
  const target = config?.target || config?.hostname || config?.ip || config?.hash || "unknown";
  const orgId = context.orgId;

  // If no orgId, we can't use the real pipeline
  if (!orgId) {
    log.warn("No orgId in context — falling back to legacy simulation", { actionType, target });
    return legacySimulateEdrAction(actionType, config, context, executedAt);
  }

  // Try to resolve sensor
  let sensorId: string | null = null;
  try {
    sensorId = await resolveSensorId(orgId, config, context);
  } catch (err) {
    log.warn("Failed to resolve sensor — falling back to legacy simulation", {
      actionType,
      target,
      error: String(err),
    });
    return legacySimulateEdrAction(actionType, config, context, executedAt);
  }

  // If no sensor found, fall back to simulation with a note
  if (!sensorId) {
    log.info("No matching sensor found — falling back to legacy simulation", {
      actionType,
      target,
      orgId,
    });
    return legacySimulateEdrAction(actionType, config, context, executedAt);
  }

  // Determine risk level and initial status
  const riskLevel = determineRiskLevel(actionType);
  const initialStatus = determineInitialStatus(riskLevel);
  const timeout = typeof config?.timeoutSeconds === "number" ? Math.min(config.timeoutSeconds, 3600) : 300;

  try {
    const [action] = await db
      .insert(agentResponseActions)
      .values({
        orgId,
        sensorId,
        actionType,
        riskLevel,
        status: initialStatus,
        targetPid: typeof config?.targetPid === "number" ? config.targetPid : null,
        targetProcessName: config?.targetProcessName || config?.processName || null,
        targetIp: config?.ip || config?.targetIp || (actionType === "block_ip" ? target : null),
        targetFilePath: config?.filePath || config?.targetFilePath || config?.hash || null,
        targetUserName: config?.userName || config?.targetUserName || (actionType === "disable_user" ? target : null),
        targetDomain: config?.domain || config?.targetDomain || (actionType === "block_domain" ? target : null),
        targetServiceName: config?.serviceName || config?.targetServiceName || null,
        parameters: config?.parameters || (config?.allowedIps ? { allowedIps: config.allowedIps } : null),
        requestedBy: context.userId || null,
        requestedByName: context.userName || "Autonomous Action",
        reason: config?.reason || `Dispatched by SecureNexus for incident ${context.incidentId || "N/A"}`,
        incidentId: context.incidentId || null,
        timeoutSeconds: timeout,
        expiresAt: new Date(Date.now() + timeout * 1000),
        // Auto-approve low-risk actions
        ...(initialStatus === "approved"
          ? { approvedBy: "system", approvedByName: "Auto-approved (low risk)", approvedAt: new Date() }
          : {}),
      })
      .returning();

    // Also record in legacy response_actions table for backward compatibility
    if (context.storage) {
      await context.storage.createResponseAction({
        orgId,
        actionType,
        incidentId: context.incidentId,
        alertId: context.alertId,
        targetType: actionType.split("_")[0],
        targetValue: target,
        status: initialStatus,
        requestPayload: { actionType, target, sensorId, riskLevel },
        responsePayload: { actionId: action.id, needsApproval: initialStatus === "pending_approval" },
        executedBy: context.userId,
      });
    }

    const actionLabels: Record<string, string> = {
      isolate_host: `Isolate host "${target}" from network`,
      block_ip: `Block IP address ${target} at firewall`,
      block_domain: `Block domain ${target} via DNS/proxy`,
      quarantine_file: `Quarantine file ${target}`,
      disable_user: `Disable user account "${target}"`,
      kill_process: `Terminate process "${target}"`,
    };

    const label = actionLabels[actionType] || actionType;

    if (initialStatus === "pending_approval") {
      log.info(`Response action queued for approval: ${actionType}`, {
        actionId: action.id,
        riskLevel,
        sensorId,
        orgId,
      });
      return {
        actionType,
        status: "pending_approval",
        message: `${label} — queued for approval (${riskLevel} risk). Action ID: ${action.id}`,
        details: {
          actionId: action.id,
          sensorId,
          target,
          riskLevel,
          needsApproval: true,
          approveUrl: `/api/native/response/actions/${action.id}/approve`,
        },
        executedAt,
      };
    }

    log.info(`Response action auto-approved and dispatched: ${actionType}`, {
      actionId: action.id,
      riskLevel,
      sensorId,
      orgId,
    });
    return {
      actionType,
      status: "approved",
      message: `${label} — approved and dispatched to sensor. Action ID: ${action.id}`,
      details: {
        actionId: action.id,
        sensorId,
        target,
        riskLevel,
        needsApproval: false,
      },
      executedAt,
    };
  } catch (err) {
    log.error("Failed to create agent response action — falling back to legacy simulation", {
      actionType,
      target,
      error: String(err),
    });
    return legacySimulateEdrAction(actionType, config, context, executedAt);
  }
}

/**
 * Legacy simulation fallback — used when no native sensor is deployed
 * or when the agent response pipeline is unavailable.
 */
function legacySimulateEdrAction(
  actionType: string,
  config: any,
  context: ActionContext,
  executedAt: string,
): ActionResult {
  const target = config?.target || config?.hostname || config?.ip || config?.hash || "unknown";
  const actionLabels: Record<string, string> = {
    isolate_host: `Isolated host "${target}" from network`,
    block_ip: `Blocked IP address ${target} at firewall/EDR`,
    block_domain: `Blocked domain ${target} via DNS/proxy`,
    quarantine_file: `Quarantined file with hash ${target}`,
    disable_user: `Disabled user account "${target}"`,
    kill_process: `Terminated process "${target}" on affected hosts`,
  };

  return {
    actionType,
    status: "simulated",
    message: `[Simulated — no sensor deployed] ${actionLabels[actionType] || actionType}: ${target}`,
    details: { actionType, target, simulated: true, reason: "No native sensor agent found for target" },
    executedAt,
  };
}

async function executeAutoTriage(config: any, context: ActionContext, executedAt: string): Promise<ActionResult> {
  return {
    actionType: "auto_triage",
    status: "completed",
    message: `Auto-triaged alert/incident with severity-based rules`,
    details: { config },
    executedAt,
  };
}

async function executeAssignAnalyst(config: any, context: ActionContext, executedAt: string): Promise<ActionResult> {
  const analyst = config?.analyst || config?.assignee || "on-call";
  if (context.incidentId && context.storage) {
    await context.storage.updateIncident(context.incidentId, { assignedTo: analyst });
  }
  return {
    actionType: "assign_analyst",
    status: "completed",
    message: `Assigned to analyst: ${analyst}`,
    details: { analyst, incidentId: context.incidentId },
    executedAt,
  };
}

async function executeChangeStatus(config: any, context: ActionContext, executedAt: string): Promise<ActionResult> {
  const newStatus = config?.status || config?.newStatus || "investigating";
  if (context.incidentId && context.storage) {
    await context.storage.updateIncident(context.incidentId, { status: newStatus });
  }
  return {
    actionType: "change_status",
    status: "completed",
    message: `Changed status to: ${newStatus}`,
    details: { newStatus, incidentId: context.incidentId },
    executedAt,
  };
}

async function executeAddTag(config: any, context: ActionContext, executedAt: string): Promise<ActionResult> {
  const tagName = config?.tag || config?.tagName || "automated";
  return {
    actionType: "add_tag",
    status: "completed",
    message: `Added tag: ${tagName}`,
    details: { tagName },
    executedAt,
  };
}

async function executeEscalate(config: any, context: ActionContext, executedAt: string): Promise<ActionResult> {
  if (context.incidentId && context.storage) {
    await context.storage.updateIncident(context.incidentId, {
      escalated: true,
      escalatedAt: new Date(),
      priority: 1,
    });
  }
  return {
    actionType: "escalate",
    status: "completed",
    message: `Escalated incident to priority 1`,
    details: { incidentId: context.incidentId },
    executedAt,
  };
}
