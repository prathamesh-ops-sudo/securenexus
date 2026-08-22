import { randomUUID } from "crypto";
import type { RuntimeGuardrailPolicy } from "@shared/schema";

export type PolicyAction =
  | "ai_agent_invoke"
  | "ai_agent_tool_call"
  | "api_outbound_call"
  | "browser_navigation"
  | "secret_access"
  | "data_egress"
  | "file_write"
  | "shell_exec"
  | "db_query"
  | "webhook_dispatch";

export type PolicyDecisionVerdict = "allow" | "deny" | "quarantine";
export type PolicyMode = "enforce" | "dry_run" | "audit_only" | "disabled";
export type PolicyScope = "ai_agent" | "tool_api" | "browser_workflow" | "secret_egress" | "data_pipeline" | "global";

export interface PolicyCondition {
  field: string;
  operator: "equals" | "not_equals" | "contains" | "matches_regex" | "gt" | "lt" | "in" | "not_in";
  value: string | number | string[];
}

export interface PolicyRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  scope: PolicyScope;
  actions: PolicyAction[];
  mode: PolicyMode;
  priority: number;
  conditions: PolicyCondition[];
  verdict: PolicyDecisionVerdict;
  rateLimit: { maxRequests: number; windowSeconds: number } | null;
  tags: string[];
  version: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface PolicyDecision {
  id: string;
  orgId: string;
  policyId: string;
  policyName: string;
  policyVersion: number;
  action: PolicyAction;
  verdict: PolicyDecisionVerdict;
  mode: PolicyMode;
  latencyMs: number;
  requestContext: Record<string, unknown>;
  matchedConditions: string[];
  timestamp: string;
  actorId: string;
  actorType: "user" | "agent" | "service";
  resourceId: string;
  resourceType: string;
  reason: string;
}

export interface PolicySimulation {
  id: string;
  orgId: string;
  policyId: string;
  policyName: string;
  simulatedAction: PolicyAction;
  inputContext: Record<string, unknown>;
  expectedVerdict: PolicyDecisionVerdict;
  actualVerdict: PolicyDecisionVerdict;
  blastRadius: BlastRadius;
  dryRunAt: string;
  runBy: string;
}

export interface BlastRadius {
  affectedAgents: number;
  affectedWorkflows: number;
  affectedApiCalls: number;
  estimatedBlockRate: number;
  impactedScopes: PolicyScope[];
  riskLevel: "low" | "medium" | "high" | "critical";
}

export interface EvaluateRequest {
  action: PolicyAction;
  actorId: string;
  actorType: "user" | "agent" | "service";
  resourceId: string;
  resourceType: string;
  context: Record<string, unknown>;
}

export interface SimulateRequest {
  policyId: string;
  action: PolicyAction;
  context: Record<string, unknown>;
}

const VALID_POLICY_ACTIONS = new Set<PolicyAction>([
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
]);

function isPolicyAction(value: unknown): value is PolicyAction {
  return typeof value === "string" && VALID_POLICY_ACTIONS.has(value as PolicyAction);
}

export function getPolicies(orgId: string): PolicyRule[] {
  void orgId;
  return [];
}

export function toPolicyRule(policy: RuntimeGuardrailPolicy): PolicyRule {
  const metadata =
    typeof policy.metadata === "object" && policy.metadata !== null ? (policy.metadata as Record<string, unknown>) : {};
  const metadataActions = Array.isArray(metadata.actions) ? metadata.actions.filter(isPolicyAction) : [];
  const actions = metadataActions.length > 0 ? metadataActions : [policy.action as PolicyAction];
  const conditions = Array.isArray(policy.conditions) ? (policy.conditions as PolicyCondition[]) : [];
  const tags = Array.isArray(metadata.tags)
    ? metadata.tags.filter((tag): tag is string => typeof tag === "string")
    : [];
  const verdict = metadata.verdict === "deny" || metadata.verdict === "quarantine" ? metadata.verdict : "allow";
  const mode: PolicyMode =
    policy.enabled === false
      ? "disabled"
      : policy.mode === "dry_run" || policy.mode === "audit_only" || policy.mode === "disabled"
        ? policy.mode
        : "enforce";

  return {
    id: policy.id,
    orgId: policy.orgId,
    name: policy.name,
    description: policy.description || "",
    scope: policy.scope as PolicyScope,
    actions,
    mode,
    priority: policy.priority,
    conditions,
    verdict,
    rateLimit:
      typeof metadata.rateLimit === "object" && metadata.rateLimit !== null
        ? (metadata.rateLimit as { maxRequests: number; windowSeconds: number })
        : null,
    tags,
    version: typeof metadata.version === "number" ? metadata.version : 1,
    createdAt: policy.createdAt?.toISOString() || new Date(0).toISOString(),
    updatedAt: policy.updatedAt?.toISOString() || new Date(0).toISOString(),
    createdBy: typeof metadata.createdBy === "string" ? metadata.createdBy : "api",
  };
}

export function evaluateAction(
  orgId: string,
  request: EvaluateRequest,
  options?: { skipLog?: boolean },
  policySource: PolicyRule[] = [],
): PolicyDecision {
  const startTime = Date.now();
  const policies = policySource.filter((policy) => policy.mode !== "disabled");
  let matchedPolicy: PolicyRule | null = null;
  let matchedConditionNames: string[] = [];

  for (const policy of policies) {
    if (!policy.actions.includes(request.action)) continue;

    const conditionMatches: string[] = [];
    let allMatch = true;
    for (const condition of policy.conditions) {
      const fieldValue = getNestedValue(request.context, condition.field);
      if (evaluateCondition(fieldValue, condition)) {
        conditionMatches.push(`${condition.field} ${condition.operator} ${JSON.stringify(condition.value)}`);
      } else {
        allMatch = false;
        break;
      }
    }

    if (allMatch) {
      matchedPolicy = policy;
      matchedConditionNames = conditionMatches;
      break;
    }
  }

  const verdict: PolicyDecisionVerdict = matchedPolicy
    ? matchedPolicy.mode === "dry_run" || matchedPolicy.mode === "audit_only"
      ? "allow"
      : matchedPolicy.verdict
    : "allow";

  void options;
  return {
    id: `gd-${randomUUID().slice(0, 8)}`,
    orgId,
    policyId: matchedPolicy?.id || "none",
    policyName: matchedPolicy?.name || "No matching policy",
    policyVersion: matchedPolicy?.version || 0,
    action: request.action,
    verdict,
    mode: matchedPolicy?.mode || "enforce",
    latencyMs: Math.max(Date.now() - startTime, 1),
    requestContext: request.context,
    matchedConditions: matchedConditionNames,
    timestamp: new Date().toISOString(),
    actorId: request.actorId,
    actorType: request.actorType,
    resourceId: request.resourceId,
    resourceType: request.resourceType,
    reason: matchedPolicy
      ? `Policy "${matchedPolicy.name}" matched: ${matchedConditionNames.join(", ") || "unconditional"}`
      : "No policy matched; default allow",
  };
}

function getNestedValue(object: Record<string, unknown>, path: string): unknown {
  let current: unknown = object;
  for (const part of path.split(".")) {
    if (current === null || current === undefined || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function evaluateCondition(fieldValue: unknown, condition: PolicyCondition): boolean {
  const { operator, value } = condition;
  switch (operator) {
    case "equals":
      return fieldValue === value;
    case "not_equals":
      return fieldValue !== value;
    case "contains":
      return typeof fieldValue === "string" && typeof value === "string" && fieldValue.includes(value);
    case "matches_regex":
      if (typeof fieldValue !== "string" || typeof value !== "string" || value.length > 200) return false;
      try {
        return new RegExp(value).test(fieldValue.length > 10000 ? fieldValue.slice(0, 10000) : fieldValue);
      } catch {
        return false;
      }
    case "gt":
      return typeof fieldValue === "number" && typeof value === "number" && fieldValue > value;
    case "lt":
      return typeof fieldValue === "number" && typeof value === "number" && fieldValue < value;
    case "in":
      return Array.isArray(value) && value.includes(fieldValue as string);
    case "not_in":
      return Array.isArray(value) && !value.includes(fieldValue as string);
    default:
      return false;
  }
}

export function simulatePolicy(
  orgId: string,
  request: SimulateRequest,
  policySource: PolicyRule[] = [],
): PolicySimulation {
  const policy = policySource.find((candidate) => candidate.id === request.policyId);
  if (!policy) throw new Error("POLICY_NOT_FOUND");

  const evaluation = evaluateAction(
    orgId,
    {
      action: request.action,
      actorId: "simulation",
      actorType: "service",
      resourceId: "sim-resource",
      resourceType: "simulation",
      context: request.context,
    },
    { skipLog: true },
    policySource,
  );
  const scopedPolicies = policySource.filter(
    (candidate) => candidate.scope === policy.scope || candidate.scope === "global",
  );
  const blastRadius: BlastRadius = {
    affectedAgents:
      policy.scope === "ai_agent" ? scopedPolicies.filter((candidate) => candidate.scope === "ai_agent").length * 2 : 0,
    affectedWorkflows: scopedPolicies.length * 3,
    affectedApiCalls: policy.actions.includes("api_outbound_call") ? scopedPolicies.length * 5 : 0,
    estimatedBlockRate:
      scopedPolicies.length > 0
        ? Math.round(
            (scopedPolicies.filter((candidate) => candidate.verdict === "deny").length / scopedPolicies.length) * 100,
          ) / 100
        : 0,
    impactedScopes: Array.from(new Set(scopedPolicies.map((candidate) => candidate.scope))),
    riskLevel:
      policy.priority >= 90 ? "critical" : policy.priority >= 70 ? "high" : policy.priority >= 50 ? "medium" : "low",
  };

  return {
    id: `gs-${randomUUID().slice(0, 8)}`,
    orgId,
    policyId: policy.id,
    policyName: policy.name,
    simulatedAction: request.action,
    inputContext: request.context,
    expectedVerdict: policy.verdict,
    actualVerdict: evaluation.verdict,
    blastRadius,
    dryRunAt: new Date().toISOString(),
    runBy: "request",
  };
}
