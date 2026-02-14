import { storage } from "./storage";
import type { AutoResponsePolicy, Alert, Incident } from "@shared/schema";

interface PolicyEvalContext {
  incident: Incident;
  alerts: Alert[];
  confidenceScore?: number;
  orgId: string;
}

interface PolicyMatch {
  policy: AutoResponsePolicy;
  matchedConditions: string[];
  suggestedActions: any[];
  requiresApproval: boolean;
}

export async function evaluatePolicies(context: PolicyEvalContext): Promise<PolicyMatch[]> {
  const policies = await storage.getAutoResponsePolicies(context.orgId);
  const activePolicies = policies.filter(p => p.status === "active");

  const matches: PolicyMatch[] = [];

  for (const policy of activePolicies) {
    const match = evaluatePolicy(policy, context);
    if (match) {
      // Update policy tracking
      storage.updateAutoResponsePolicy(policy.id, {
        lastTriggeredAt: new Date(),
        executionCount: (policy.executionCount || 0) + 1,
      }).catch(() => {}); // fire and forget
      matches.push(match);
    }
  }

  return matches;
}

function evaluatePolicy(policy: AutoResponsePolicy, context: PolicyEvalContext): PolicyMatch | null {
  const matchedConditions: string[] = [];
  const conditions = policy.conditions as any;

  if (policy.triggerType === "incident_created" || policy.triggerType === "incident_severity_change") {
    if (policy.severityFilter && policy.severityFilter.length > 0) {
      if (!policy.severityFilter.includes(context.incident.severity)) return null;
      matchedConditions.push(`severity: ${context.incident.severity}`);
    }

    const confidence = context.confidenceScore || 0;
    if (confidence < (policy.confidenceThreshold || 0.85)) return null;
    matchedConditions.push(`confidence: ${(confidence * 100).toFixed(0)}% >= ${((policy.confidenceThreshold || 0.85) * 100).toFixed(0)}%`);

    if (conditions?.minAlertCount && context.alerts.length < conditions.minAlertCount) return null;
    if (conditions?.minAlertCount) matchedConditions.push(`alerts: ${context.alerts.length} >= ${conditions.minAlertCount}`);

    if (conditions?.minSources) {
      const sources = new Set(context.alerts.map(a => a.source));
      if (sources.size < conditions.minSources) return null;
      matchedConditions.push(`sources: ${sources.size} >= ${conditions.minSources}`);
    }

    if (conditions?.categories && conditions.categories.length > 0) {
      const alertCategories = context.alerts.map(a => a.category).filter(Boolean);
      const hasMatch = conditions.categories.some((c: string) => alertCategories.includes(c));
      if (!hasMatch) return null;
      matchedConditions.push(`category match`);
    }

    if (policy.lastTriggeredAt && policy.cooldownMinutes) {
      const elapsed = (Date.now() - new Date(policy.lastTriggeredAt).getTime()) / 60000;
      if (elapsed < policy.cooldownMinutes) return null;
    }

    if (policy.maxActionsPerHour && (policy.executionCount || 0) >= policy.maxActionsPerHour) {
      return null;
    }
  }

  if (matchedConditions.length === 0) return null;

  return {
    policy,
    matchedConditions,
    suggestedActions: (policy.actions as any[]) || [],
    requiresApproval: policy.requiresApproval ?? true,
  };
}

export function generateDefaultPolicies(orgId: string): Partial<AutoResponsePolicy>[] {
  return [
    {
      orgId,
      name: "Auto-Contain Critical Malware",
      description: "Automatically isolate hosts and block IPs when critical malware incidents are detected with high confidence",
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
      actions: [
        { type: "disable_user", config: { reason: "Account compromise detected - automated lockout" } },
      ],
      confidenceThreshold: 0.92,
      severityFilter: ["critical"],
      requiresApproval: true,
      maxActionsPerHour: 3,
      cooldownMinutes: 120,
      status: "inactive",
    },
  ];
}
