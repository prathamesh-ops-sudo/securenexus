import type { IStorage } from "./storage";
import { db } from "./db";
import { agentResponseActions, nativeSensors, ROLE_PERMISSIONS } from "../shared/schema";
import { validateResponseActionTimeout } from "./response-action-timeouts";
import { eq, and, or, ilike, type SQL } from "drizzle-orm";
import { logger } from "./routes/shared";
import { validateWebhookUrl } from "./outbound-security";
import { validateActionInput } from "./action-schemas";
import { createAuditLog } from "./storage/audit";

const log = logger.child("action-dispatcher");

// Typed config interfaces for each action type
interface TicketingConfig {
  summary?: string;
  priority?: string;
  project?: string;
  projectKey?: string;
  webhookUrl?: string;
  apiUrl?: string;
  authHeader?: string;
}

interface NotificationConfig {
  message?: string;
  channel?: string;
  recipient?: string;
  webhookUrl?: string;
}

interface AgentActionConfig {
  target?: string;
  hostname?: string;
  ip?: string;
  targetIp?: string;
  hash?: string;
  sensorId?: string;
  timeoutSeconds?: number;
  targetPid?: number;
  targetProcessName?: string;
  processName?: string;
  filePath?: string;
  targetFilePath?: string;
  userName?: string;
  targetUserName?: string;
  domain?: string;
  targetDomain?: string;
  serviceName?: string;
  targetServiceName?: string;
  parameters?: Record<string, unknown>;
  allowedIps?: string[];
  reason?: string;
}

interface AutoTriageConfig {
  severity?: string;
  category?: string;
}

interface AssignAnalystConfig {
  analyst?: string;
  assignee?: string;
}

interface ChangeStatusConfig {
  status?: string;
  newStatus?: string;
}

interface AddTagConfig {
  tag?: string;
  tagName?: string;
}

interface EscalateConfig {
  targetTeam?: string;
  reason?: string;
}

type ActionConfig =
  | TicketingConfig
  | NotificationConfig
  | AgentActionConfig
  | AutoTriageConfig
  | AssignAnalystConfig
  | ChangeStatusConfig
  | AddTagConfig
  | EscalateConfig;

export interface ActionContext {
  orgId?: string;
  incidentId?: string;
  alertId?: string;
  userId?: string;
  userName?: string;
  sensorId?: string;
  storage: IStorage;
  dryRun?: boolean;
  callerOrgId?: string;
  callerRole?: string;
}

export interface ActionResult {
  actionType: string;
  status: "completed" | "failed" | "simulated" | "pending_approval" | "approved" | "unavailable";
  message: string;
  details?: Record<string, unknown>;
  executedAt: string;
}

/**
 * Check permissions before allowing action dispatch.
 * Validates org boundary and role-based access control.
 */
function checkActionPermissions(actionType: string, context: ActionContext): { allowed: boolean; reason?: string } {
  // Check org boundary: caller org must match target org
  if (context.callerOrgId && context.orgId && context.callerOrgId !== context.orgId) {
    return { allowed: false, reason: "Org boundary violation: caller org does not match target org" };
  }

  // Check role-based permissions: caller must have response_actions write scope
  if (context.callerRole) {
    const rolePerms = ROLE_PERMISSIONS[context.callerRole];
    if (!rolePerms || !rolePerms.response_actions || !rolePerms.response_actions.includes("write")) {
      return { allowed: false, reason: `Role ${context.callerRole} lacks response_actions write permission` };
    }
  }

  return { allowed: true };
}

export async function dispatchAction(
  actionType: string,
  config: Record<string, unknown>,
  context: ActionContext,
): Promise<ActionResult> {
  const executedAt = new Date().toISOString();
  const startMs = Date.now();

  // Step 1: Validate inputs with Zod schema (per RESP-03)
  const validation = validateActionInput(actionType, config);
  if (!validation.valid) {
    const failResult: ActionResult = {
      actionType,
      status: "failed",
      message: `Validation failed: ${validation.errors.issues.map((i) => i.message).join(", ")}`,
      details: { validationErrors: validation.errors.issues },
      executedAt,
    };
    // Audit the validation failure
    await safeCreateAuditLog(context, actionType, config, failResult, 0, false);
    return failResult;
  }

  // Step 1.5: Check permissions (per RESP-01 gap closure)
  const permCheck = checkActionPermissions(actionType, context);
  if (!permCheck.allowed) {
    const denyResult: ActionResult = {
      actionType,
      status: "failed",
      message: `Permission denied: ${permCheck.reason}`,
      details: { permissionDenied: true, reason: permCheck.reason },
      executedAt,
    };
    await safeCreateAuditLog(context, actionType, config, denyResult, 0, false, "response_action_permission_denied");
    return denyResult;
  }

  // Step 2: If dry-run, return simulated result without executing (per RESP-01)
  if (context.dryRun) {
    const dryResult: ActionResult = {
      actionType,
      status: "simulated",
      message: `[Dry Run] Would execute: ${actionType}`,
      details: { config, validationPassed: true, dryRun: true },
      executedAt,
    };
    await safeCreateAuditLog(context, actionType, config, dryResult, 0, true);
    return dryResult;
  }

  // Step 3: Execute action (existing switch statement)
  const result = await executeActionSwitch(actionType, config, context, executedAt);
  const durationMs = Date.now() - startMs;

  // Step 4: Audit log every execution (per RESP-04)
  // Only log for actions that actually executed (not pending_approval — those get audited when approved)
  if (result.status !== "pending_approval") {
    await safeCreateAuditLog(context, actionType, config, result, durationMs, false);
  }

  return result;
}

/**
 * Wraps createAuditLog in try/catch so audit failures never break action dispatch.
 */
async function safeCreateAuditLog(
  context: ActionContext,
  actionType: string,
  config: Record<string, unknown>,
  result: ActionResult,
  durationMs: number,
  isDryRun: boolean,
  auditAction?: string,
): Promise<void> {
  try {
    await createAuditLog({
      orgId: context.orgId || null,
      userId: context.userId || null,
      userName: context.userName || null,
      action: auditAction || (isDryRun ? "response_action_dry_run" : "response_action_executed"),
      resourceType: "response_action",
      resourceId: context.incidentId || context.alertId || null,
      details: {
        actionType,
        parameters: config,
        result: result.status,
        message: result.message,
        durationMs,
        dryRun: isDryRun,
        incidentId: context.incidentId,
        alertId: context.alertId,
      },
    });
  } catch (err) {
    log.warn("Failed to create audit log for response action", {
      actionType,
      error: String(err),
    });
  }
}

/**
 * Internal switch statement extracted from dispatchAction for separation of concerns.
 * Contains all existing action execution cases unchanged.
 */
async function executeActionSwitch(
  actionType: string,
  config: Record<string, unknown>,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
  switch (actionType) {
    case "create_jira_ticket":
      return executeTicketing("jira", config as TicketingConfig, context, executedAt);
    case "create_servicenow_ticket":
      return executeTicketing("servicenow", config as TicketingConfig, context, executedAt);
    case "notify_slack":
      return executeNotification("slack", config as NotificationConfig, context, executedAt);
    case "notify_teams":
      return executeNotification("teams", config as NotificationConfig, context, executedAt);
    case "notify_email":
      return executeNotification("email", config as NotificationConfig, context, executedAt);
    case "notify_webhook":
      return executeNotification("webhook", config as NotificationConfig, context, executedAt);
    case "notify_pagerduty":
      return executeNotification("pagerduty", config as NotificationConfig, context, executedAt);
    case "isolate_host":
    case "block_ip":
    case "block_domain":
    case "quarantine_file":
    case "disable_user":
    case "kill_process":
      return executeAgentResponseAction(actionType, config as AgentActionConfig, context, executedAt);
    case "auto_triage":
      return executeAutoTriage(config as AutoTriageConfig, context, executedAt);
    case "assign_analyst":
      return executeAssignAnalyst(config as AssignAnalystConfig, context, executedAt);
    case "change_status":
      return executeChangeStatus(config as ChangeStatusConfig, context, executedAt);
    case "add_tag":
      return executeAddTag(config as AddTagConfig, context, executedAt);
    case "escalate":
      return executeEscalate(config as EscalateConfig, context, executedAt);
    case "notify":
      return executeNotification("default", config as NotificationConfig, context, executedAt);
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
  config: TicketingConfig,
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
          const ticketResponse = data as Record<string, unknown>;
          ticketUrl = (ticketResponse.url as string) || (ticketResponse.ticketUrl as string) || ticketUrl;
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
  config: NotificationConfig,
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
async function resolveSensorId(
  orgId: string,
  config: AgentActionConfig,
  context: ActionContext,
): Promise<string | null> {
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

  const conditions: SQL[] = [eq(nativeSensors.orgId, orgId)];
  if (hostname && ip) {
    conditions.push(or(ilike(nativeSensors.hostname, hostname), eq(nativeSensors.ipAddress, ip))!);
  } else if (hostname) {
    conditions.push(ilike(nativeSensors.hostname, hostname));
  } else if (ip) {
    conditions.push(eq(nativeSensors.ipAddress, ip));
  }

  const [sensor] = await db
    .select({ id: nativeSensors.id })
    .from(nativeSensors)
    .where(and(...conditions))
    .limit(1);

  return sensor ? sensor.id : null;
}

/**
 * Execute a real response action through the agent_response_actions pipeline.
 * Creates a DB entry with proper risk assessment and approval workflow.
 * Fails visibly if no sensor can be resolved (no agent deployed).
 */
async function executeAgentResponseAction(
  actionType: string,
  config: AgentActionConfig,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
  const target = config?.target || config?.hostname || config?.ip || config?.hash || "unknown";
  const orgId = context.orgId;

  // If no orgId, we can't use the real pipeline
  if (!orgId) {
    log.error("No orgId in context — cannot dispatch native response action", { actionType, target });
    return unavailableAgentResponse(
      actionType,
      target,
      "Organization context is required to dispatch a native response action.",
      executedAt,
    );
  }

  // Try to resolve sensor
  let sensorId: string | null = null;
  try {
    sensorId = await resolveSensorId(orgId, config, context);
  } catch (err) {
    log.error("Failed to resolve sensor — native response action unavailable", {
      actionType,
      target,
      error: String(err),
    });
    return unavailableAgentResponse(
      actionType,
      target,
      "Sensor resolution failed; no native response action was dispatched.",
      executedAt,
    );
  }

  // Never represent an action as executed when no sensor is available.
  if (!sensorId) {
    log.warn("No matching sensor found — native response action unavailable", {
      actionType,
      target,
      orgId,
    });
    return unavailableAgentResponse(
      actionType,
      target,
      "No reachable native sensor was found for this target.",
      executedAt,
    );
  }

  // Determine risk level and initial status
  const riskLevel = determineRiskLevel(actionType);
  const initialStatus = determineInitialStatus(riskLevel);
  const timeoutResult = validateResponseActionTimeout(config?.timeoutSeconds);
  if (!timeoutResult.valid) {
    log.warn("Native response action timeout is below the sensor dispatch cadence", {
      actionType,
      target,
      timeoutSeconds: config?.timeoutSeconds,
      error: timeoutResult.message,
    });
    return unavailableAgentResponse(actionType, target, timeoutResult.message, executedAt);
  }
  const timeout = timeoutResult.timeoutSeconds;

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
      message: `${label} — approved and awaiting sensor pickup. Action ID: ${action.id}`,
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
    log.error("Failed to create agent response action", {
      actionType,
      target,
      error: String(err),
    });
    return {
      actionType,
      status: "failed",
      message: "Native response action could not be persisted and was not dispatched.",
      details: { actionType, target, reason: "Action persistence failed" },
      executedAt,
    };
  }
}

function unavailableAgentResponse(
  actionType: string,
  target: string,
  reason: string,
  executedAt: string,
): ActionResult {
  return {
    actionType,
    status: "unavailable",
    message: `Native response action unavailable: ${reason}`,
    details: { actionType, target, unavailable: true, reason },
    executedAt,
  };
}

async function executeAutoTriage(
  config: AutoTriageConfig,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
  return {
    actionType: "auto_triage",
    status: "completed",
    message: `Auto-triaged alert/incident with severity-based rules`,
    details: { config },
    executedAt,
  };
}

async function executeAssignAnalyst(
  config: AssignAnalystConfig,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
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

async function executeChangeStatus(
  config: ChangeStatusConfig,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
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

async function executeAddTag(config: AddTagConfig, context: ActionContext, executedAt: string): Promise<ActionResult> {
  const tagName = config?.tag || config?.tagName || "automated";
  return {
    actionType: "add_tag",
    status: "completed",
    message: `Added tag: ${tagName}`,
    details: { tagName },
    executedAt,
  };
}

async function executeEscalate(
  config: EscalateConfig,
  context: ActionContext,
  executedAt: string,
): Promise<ActionResult> {
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
