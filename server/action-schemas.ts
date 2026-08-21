import { z } from "zod";
import { logger } from "./routes/shared";
import { MIN_RESPONSE_ACTION_TIMEOUT_SECONDS } from "../shared/schema";

const log = logger.child("action-schemas");

// Agent action schemas (high/medium risk)
export const isolateHostSchema = z
  .object({
    hostname: z.string().min(1).optional(),
    ip: z.string().ip().optional(),
    target: z.string().min(1).optional(),
    sensorId: z.string().uuid().optional(),
    reason: z.string().optional(),
    timeoutSeconds: z.number().int().min(MIN_RESPONSE_ACTION_TIMEOUT_SECONDS).max(3600).optional(),
  })
  .refine((d) => d.hostname || d.ip || d.target || d.sensorId, {
    message: "At least one of hostname, ip, target, or sensorId is required",
  });

export const blockIpSchema = z
  .object({
    ip: z.string().ip().optional(),
    targetIp: z.string().ip().optional(),
    target: z.string().min(1).optional(),
    reason: z.string().optional(),
  })
  .refine((d) => d.ip || d.targetIp || d.target, {
    message: "At least one of ip, targetIp, or target is required",
  });

export const blockDomainSchema = z
  .object({
    domain: z.string().min(1).optional(),
    targetDomain: z.string().min(1).optional(),
    target: z.string().min(1).optional(),
    reason: z.string().optional(),
  })
  .refine((d) => d.domain || d.targetDomain || d.target, {
    message: "At least one of domain, targetDomain, or target is required",
  });

export const quarantineFileSchema = z
  .object({
    hash: z.string().min(1).optional(),
    filePath: z.string().min(1).optional(),
    targetFilePath: z.string().min(1).optional(),
    target: z.string().min(1).optional(),
    reason: z.string().optional(),
  })
  .refine((d) => d.hash || d.filePath || d.targetFilePath || d.target, {
    message: "At least one of hash, filePath, targetFilePath, or target is required",
  });

export const disableUserSchema = z
  .object({
    userName: z.string().min(1).optional(),
    targetUserName: z.string().min(1).optional(),
    target: z.string().min(1).optional(),
    reason: z.string().optional(),
  })
  .refine((d) => d.userName || d.targetUserName || d.target, {
    message: "At least one of userName, targetUserName, or target is required",
  });

export const killProcessSchema = z
  .object({
    targetPid: z.number().int().positive().optional(),
    targetProcessName: z.string().min(1).optional(),
    processName: z.string().min(1).optional(),
    target: z.string().min(1).optional(),
    reason: z.string().optional(),
  })
  .refine((d) => d.targetPid || d.targetProcessName || d.processName || d.target, {
    message: "At least one of targetPid, targetProcessName, processName, or target is required",
  });

// Ticketing schemas
export const ticketingSchema = z.object({
  summary: z.string().optional(),
  priority: z.string().optional(),
  project: z.string().optional(),
  projectKey: z.string().optional(),
  webhookUrl: z.string().url().optional(),
  apiUrl: z.string().url().optional(),
  authHeader: z.string().optional(),
});

// Notification schemas
export const notificationSchema = z.object({
  message: z.string().optional(),
  channel: z.string().optional(),
  recipient: z.string().optional(),
  webhookUrl: z.string().url().optional(),
});

// Workflow action schemas
export const autoTriageSchema = z.object({
  severity: z.string().optional(),
  category: z.string().optional(),
});

export const assignAnalystSchema = z.object({
  analyst: z.string().optional(),
  assignee: z.string().optional(),
});

export const changeStatusSchema = z.object({
  status: z.string().optional(),
  newStatus: z.string().optional(),
});

export const addTagSchema = z.object({
  tag: z.string().optional(),
  tagName: z.string().optional(),
});

export const escalateSchema = z.object({
  targetTeam: z.string().optional(),
  reason: z.string().optional(),
});

/**
 * Registry mapping action type strings to their Zod validation schemas.
 * Every action type in the dispatcher's switch statement has a corresponding entry.
 */
export const ACTION_SCHEMAS: Record<string, z.ZodType> = {
  isolate_host: isolateHostSchema,
  block_ip: blockIpSchema,
  block_domain: blockDomainSchema,
  quarantine_file: quarantineFileSchema,
  disable_user: disableUserSchema,
  kill_process: killProcessSchema,
  create_jira_ticket: ticketingSchema,
  create_servicenow_ticket: ticketingSchema,
  notify_slack: notificationSchema,
  notify_teams: notificationSchema,
  notify_email: notificationSchema,
  notify_webhook: notificationSchema,
  notify_pagerduty: notificationSchema,
  notify: notificationSchema,
  auto_triage: autoTriageSchema,
  assign_analyst: assignAnalystSchema,
  change_status: changeStatusSchema,
  add_tag: addTagSchema,
  escalate: escalateSchema,
};

/**
 * Validate action input against the registered Zod schema for the given action type.
 * Unknown action types pass through without validation (handled by dispatcher's default case).
 */
export function validateActionInput(
  actionType: string,
  config: Record<string, unknown>,
): { valid: true; data: unknown } | { valid: false; errors: z.ZodError } {
  const schema = ACTION_SCHEMAS[actionType];
  if (!schema) {
    log.debug("No schema registered for action type, passing through", { actionType });
    return { valid: true, data: config };
  }
  const result = schema.safeParse(config);
  if (result.success) return { valid: true, data: result.data };
  return { valid: false, errors: result.error };
}
