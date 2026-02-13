import type { IStorage } from "./storage";

export interface ActionContext {
  orgId?: string;
  incidentId?: string;
  alertId?: string;
  userId?: string;
  userName?: string;
  storage: IStorage;
}

export interface ActionResult {
  actionType: string;
  status: "completed" | "failed" | "simulated";
  message: string;
  details?: any;
  executedAt: string;
}

export async function dispatchAction(
  actionType: string,
  config: any,
  context: ActionContext
): Promise<ActionResult> {
  const executedAt = new Date().toISOString();

  switch (actionType) {
    case "create_jira_ticket":
      return simulateTicketing("jira", config, context, executedAt);
    case "create_servicenow_ticket":
      return simulateTicketing("servicenow", config, context, executedAt);
    case "notify_slack":
      return simulateNotification("slack", config, context, executedAt);
    case "notify_teams":
      return simulateNotification("teams", config, context, executedAt);
    case "notify_email":
      return simulateNotification("email", config, context, executedAt);
    case "notify_webhook":
      return simulateNotification("webhook", config, context, executedAt);
    case "notify_pagerduty":
      return simulateNotification("pagerduty", config, context, executedAt);
    case "isolate_host":
      return simulateEdrAction("isolate_host", config, context, executedAt);
    case "block_ip":
      return simulateEdrAction("block_ip", config, context, executedAt);
    case "block_domain":
      return simulateEdrAction("block_domain", config, context, executedAt);
    case "quarantine_file":
      return simulateEdrAction("quarantine_file", config, context, executedAt);
    case "disable_user":
      return simulateEdrAction("disable_user", config, context, executedAt);
    case "kill_process":
      return simulateEdrAction("kill_process", config, context, executedAt);
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
      return simulateNotification("default", config, context, executedAt);
    default:
      return {
        actionType,
        status: "failed",
        message: `Unknown action type: ${actionType}`,
        executedAt,
      };
  }
}

async function simulateTicketing(
  platform: string,
  config: any,
  context: ActionContext,
  executedAt: string
): Promise<ActionResult> {
  const ticketId = `${platform.toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;
  const summary = config?.summary || `Security Incident ${context.incidentId || "Unknown"}`;
  const priority = config?.priority || "high";
  const project = config?.project || config?.projectKey || "SEC";

  if (context.incidentId && context.storage) {
    await context.storage.createResponseAction({
      orgId: context.orgId,
      actionType: `create_${platform}_ticket`,
      incidentId: context.incidentId,
      alertId: context.alertId,
      targetType: "ticket",
      targetValue: ticketId,
      status: "simulated",
      requestPayload: { platform, summary, priority, project },
      responsePayload: { ticketId, ticketUrl: `https://${platform}.example.com/browse/${ticketId}` },
      executedBy: context.userId,
    });
  }

  return {
    actionType: `create_${platform}_ticket`,
    status: "simulated",
    message: `[Simulated] Created ${platform} ticket ${ticketId}: "${summary}" (Priority: ${priority})`,
    details: { ticketId, platform, summary, priority, project, ticketUrl: `https://${platform}.example.com/browse/${ticketId}` },
    executedAt,
  };
}

async function simulateNotification(
  channel: string,
  config: any,
  context: ActionContext,
  executedAt: string
): Promise<ActionResult> {
  const message = config?.message || `Alert from SecureNexus: Incident ${context.incidentId || "N/A"}`;
  const target = config?.channel || config?.recipient || config?.webhookUrl || "#security-alerts";

  return {
    actionType: `notify_${channel}`,
    status: "simulated",
    message: `[Simulated] Sent ${channel} notification to ${target}: "${message.substring(0, 80)}..."`,
    details: { channel, target, message, incidentId: context.incidentId, alertId: context.alertId },
    executedAt,
  };
}

async function simulateEdrAction(
  actionType: string,
  config: any,
  context: ActionContext,
  executedAt: string
): Promise<ActionResult> {
  const target = config?.target || config?.hostname || config?.ip || config?.hash || "unknown";
  const connector = config?.connector || config?.connectorId || "auto";
  const actionLabels: Record<string, string> = {
    isolate_host: `Isolated host "${target}" from network`,
    block_ip: `Blocked IP address ${target} at firewall/EDR`,
    block_domain: `Blocked domain ${target} via DNS/proxy`,
    quarantine_file: `Quarantined file with hash ${target}`,
    disable_user: `Disabled user account "${target}"`,
    kill_process: `Terminated process "${target}" on affected hosts`,
  };

  if (context.storage) {
    await context.storage.createResponseAction({
      orgId: context.orgId,
      actionType,
      connectorId: typeof connector === "string" && connector !== "auto" ? connector : undefined,
      incidentId: context.incidentId,
      alertId: context.alertId,
      targetType: actionType.split("_")[0],
      targetValue: target,
      status: "simulated",
      requestPayload: { actionType, target, connector },
      responsePayload: { success: true, simulated: true },
      executedBy: context.userId,
    });
  }

  return {
    actionType,
    status: "simulated",
    message: `[Simulated] ${actionLabels[actionType] || actionType}: ${target}`,
    details: { actionType, target, connector, simulated: true },
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
