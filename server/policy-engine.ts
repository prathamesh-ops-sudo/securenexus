import type { Alert, AutoResponsePolicy, Incident } from "@shared/schema";
import { dispatchAction, type ActionResult } from "./action-dispatcher";
import { logger } from "./logger";
import { storage } from "./storage";

export type PolicyEvalContext =
  | { kind: "incident"; incident: Incident; alerts: Alert[]; confidenceScore?: number; orgId: string }
  | { kind: "alert"; alert: Alert; orgId: string };

export interface PolicyMatch {
  policy: AutoResponsePolicy;
  matchedConditions: string[];
  suggestedActions: Array<Record<string, unknown>>;
  requiresApproval: boolean;
}

export async function evaluatePolicies(context: PolicyEvalContext): Promise<PolicyMatch[]> {
  const policies = await storage.getAutoResponsePolicies(context.orgId);
  const matches: PolicyMatch[] = [];
  for (const policy of policies.filter((candidate) => candidate.status === "active")) {
    const match = evaluatePolicy(policy, context);
    if (!match) continue;
    storage
      .updateAutoResponsePolicy(policy.id, {
        lastTriggeredAt: new Date(),
        executionCount: (policy.executionCount || 0) + 1,
      })
      .catch((error: unknown) =>
        logger.child("policy-engine").warn("Failed to update policy tracking", {
          policyId: policy.id,
          error: String(error),
        }),
      );
    matches.push(match);
  }
  return matches;
}

function evaluatePolicy(policy: AutoResponsePolicy, context: PolicyEvalContext): PolicyMatch | null {
  const matchedConditions: string[] = [];
  const conditions = (policy.conditions || {}) as Record<string, unknown>;
  if (
    context.kind === "incident" &&
    (policy.triggerType === "incident_created" || policy.triggerType === "incident_severity_change")
  ) {
    if (policy.severityFilter?.length && !policy.severityFilter.includes(context.incident.severity)) return null;
    if (policy.severityFilter?.length) matchedConditions.push(`severity: ${context.incident.severity}`);
    const confidence = context.confidenceScore || 0;
    const threshold = policy.confidenceThreshold || 0.85;
    if (confidence < threshold) return null;
    matchedConditions.push(`confidence: ${(confidence * 100).toFixed(0)}% >= ${(threshold * 100).toFixed(0)}%`);
    const minAlertCount = typeof conditions.minAlertCount === "number" ? conditions.minAlertCount : 0;
    if (minAlertCount && context.alerts.length < minAlertCount) return null;
    if (minAlertCount) matchedConditions.push(`alerts: ${context.alerts.length} >= ${minAlertCount}`);
    const minSources = typeof conditions.minSources === "number" ? conditions.minSources : 0;
    if (minSources) {
      const sources = new Set(context.alerts.map((alert) => alert.source));
      if (sources.size < minSources) return null;
      matchedConditions.push(`sources: ${sources.size} >= ${minSources}`);
    }
    const categories = stringArray(conditions.categories ?? conditions.category);
    if (
      categories.length &&
      !categories.some((category) => context.alerts.some((alert) => alert.category === category))
    ) {
      return null;
    }
    if (categories.length) matchedConditions.push("category match");
    if (isCoolingDown(policy) || isRateLimited(policy)) return null;
  } else if (context.kind === "alert" && policy.triggerType === "alert_created") {
    matchedConditions.push("alert_created");
    if (policy.severityFilter?.length && !policy.severityFilter.includes(context.alert.severity)) return null;
    if (policy.severityFilter?.length) matchedConditions.push(`severity: ${context.alert.severity}`);
    const categories = stringArray(conditions.categories ?? conditions.category);
    if (categories.length && !categories.includes(context.alert.category || "")) return null;
    if (categories.length) matchedConditions.push(`category: ${context.alert.category}`);
    const sources = stringArray(conditions.sources);
    if (sources.length && !sources.includes(context.alert.source)) return null;
    if (sources.length) matchedConditions.push(`source: ${context.alert.source}`);
    if (isCoolingDown(policy) || isRateLimited(policy)) return null;
  }
  if (!matchedConditions.length) return null;
  return {
    policy,
    matchedConditions,
    suggestedActions: Array.isArray(policy.actions) ? (policy.actions as Array<Record<string, unknown>>) : [],
    requiresApproval: policy.requiresApproval ?? true,
  };
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function isCoolingDown(policy: AutoResponsePolicy): boolean {
  if (!policy.lastTriggeredAt || !policy.cooldownMinutes) return false;
  return (Date.now() - new Date(policy.lastTriggeredAt).getTime()) / 60000 < policy.cooldownMinutes;
}

function isRateLimited(policy: AutoResponsePolicy): boolean {
  return Boolean(policy.maxActionsPerHour && (policy.executionCount || 0) >= policy.maxActionsPerHour);
}

export async function dispatchPolicyMatches(
  matches: PolicyMatch[],
  context: PolicyEvalContext,
): Promise<ActionResult[]> {
  const results: ActionResult[] = [];
  for (const match of matches) {
    for (const action of match.suggestedActions) {
      const actionType =
        typeof action.actionType === "string" ? action.actionType : typeof action.type === "string" ? action.type : "";
      if (!actionType) continue;
      const config =
        action.config && typeof action.config === "object" ? (action.config as Record<string, unknown>) : {};
      results.push(
        await dispatchAction(actionType, config, {
          orgId: context.orgId,
          incidentId: context.kind === "incident" ? context.incident.id : undefined,
          alertId: context.kind === "alert" ? context.alert.id : undefined,
          storage,
        }),
      );
    }
  }
  return results;
}

export async function evaluateAndDispatchAlertPolicies(alert: Alert): Promise<ActionResult[]> {
  if (!alert.orgId || alert.suppressed || alert.status === "deduped") return [];
  const context: PolicyEvalContext = { kind: "alert", alert, orgId: alert.orgId };
  return dispatchPolicyMatches(await evaluatePolicies(context), context);
}

export function generateDefaultPolicies(orgId: string): Partial<AutoResponsePolicy>[] {
  return [
    {
      orgId,
      name: "Auto-Contain Critical Malware",
      description:
        "Automatically isolate hosts and block IPs when critical malware incidents are detected with high confidence",
      triggerType: "incident_created",
      conditions: { minAlertCount: 3, categories: ["malware"], minSources: 2 },
      actions: [
        { type: "isolate_host", config: { reason: "Critical malware detected - automated containment" } },
        { type: "block_ip", config: { reason: "Malicious IP associated with malware campaign" } },
      ],
      confidenceThreshold: 0.9,
      severityFilter: ["critical"],
      requiresApproval: true,
      maxActionsPerHour: 5,
      cooldownMinutes: 60,
      status: "inactive",
    },
    {
      orgId,
      name: "Block Exfiltration Attempts",
      description: "Block suspicious domains and IPs when data exfiltration patterns are detected",
      triggerType: "incident_created",
      conditions: { minAlertCount: 2, categories: ["data_exfiltration"] },
      actions: [
        { type: "block_domain", config: { reason: "Suspected data exfiltration endpoint" } },
        { type: "block_ip", config: { reason: "Exfiltration destination IP" } },
      ],
      confidenceThreshold: 0.85,
      severityFilter: ["critical", "high"],
      requiresApproval: true,
      maxActionsPerHour: 10,
      cooldownMinutes: 30,
      status: "inactive",
    },
    {
      orgId,
      name: "Disable Compromised Accounts",
      description: "Disable user accounts when credential access or privilege escalation is detected",
      triggerType: "incident_created",
      conditions: { categories: ["credential_access", "privilege_escalation"] },
      actions: [{ type: "disable_user", config: { reason: "Account compromise detected - automated lockout" } }],
      confidenceThreshold: 0.92,
      severityFilter: ["critical"],
      requiresApproval: true,
      maxActionsPerHour: 3,
      cooldownMinutes: 120,
      status: "inactive",
    },
  ];
}
