import { randomUUID } from "crypto";

export type EvidenceSeverity = "info" | "low" | "medium" | "high" | "critical";
export type EvidenceSourceType =
  | "detection"
  | "correlation"
  | "prediction"
  | "remediation"
  | "policy_decision"
  | "posture_score"
  | "connector_sync"
  | "adversarial_test"
  | "agent_action"
  | "browser_event"
  | "drift_signal"
  | "manual_entry";

export type OverrideStatus = "pending" | "approved" | "rejected" | "expired" | "auto_expired";
export type DriftCategory = "policy" | "integration" | "identity" | "control" | "posture" | "configuration";
export type DriftSeverity = "info" | "warning" | "critical";
export type KillSwitchState = "armed" | "disarmed" | "triggered";
export type MilestoneKind =
  | "first_connector"
  | "first_alert_closed"
  | "first_question_answered"
  | "first_finding_resolved"
  | "first_incident_prevented"
  | "first_playbook_executed"
  | "first_policy_enforced"
  | "first_report_generated";

export interface EvidenceRecord {
  id: string;
  orgId: string;
  traceId: string;
  sourceType: EvidenceSourceType;
  sourceEngine: string;
  sourceActionId: string;
  severity: EvidenceSeverity;
  summary: string;
  details: Record<string, unknown>;
  parentEvidenceId: string | null;
  chainDepth: number;
  actorId: string;
  actorType: "user" | "agent" | "service" | "system";
  timestamp: string;
  tags: string[];
}

export interface HumanOverrideRequest {
  id: string;
  orgId: string;
  evidenceId: string;
  featureDomain: string;
  actionDescription: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  requestedBy: string;
  requestedAt: string;
  status: OverrideStatus;
  reviewedBy: string | null;
  reviewedAt: string | null;
  rationale: string | null;
  expiresAt: string;
  auditTrail: { action: string; actor: string; timestamp: string; detail: string }[];
}

export interface DriftSignal {
  id: string;
  orgId: string;
  category: DriftCategory;
  severity: DriftSeverity;
  sourceEngine: string;
  entity: string;
  expectedState: string;
  actualState: string;
  detectedAt: string;
  resolvedAt: string | null;
  baselineSnapshot: Record<string, unknown>;
  currentSnapshot: Record<string, unknown>;
  delta: string[];
  acknowledgedBy: string | null;
}

export interface KillSwitch {
  id: string;
  orgId: string;
  featureName: string;
  engineName: string;
  state: KillSwitchState;
  confidenceThreshold: number;
  currentConfidence: number;
  lastTriggeredAt: string | null;
  triggeredBy: string | null;
  triggerReason: string | null;
  rollbackInstructions: string;
  updatedAt: string;
  updatedBy: string;
}

export interface TimeToValueMilestone {
  id: string;
  orgId: string;
  kind: MilestoneKind;
  label: string;
  achievedAt: string | null;
  durationFromSignupMs: number | null;
  triggeredByAction: string | null;
  triggeredByActor: string | null;
}

export interface CrossCuttingStats {
  evidenceCount: number;
  evidenceBySource: Record<string, number>;
  pendingOverrides: number;
  approvedOverridesLast24h: number;
  rejectedOverridesLast24h: number;
  activeDriftSignals: number;
  driftByCategory: Record<string, number>;
  killSwitchesArmed: number;
  killSwitchesTriggered: number;
  milestonesAchieved: number;
  milestonesRemaining: number;
  avgConfidence: number;
}

function evidenceId(): string {
  return `ev-${randomUUID().slice(0, 12)}`;
}

function overrideReqId(): string {
  return `ovr-${randomUUID().slice(0, 10)}`;
}

function driftId(): string {
  return `dft-${randomUUID().slice(0, 10)}`;
}

function killSwitchId(): string {
  return `ks-${randomUUID().slice(0, 10)}`;
}

function milestoneId(): string {
  return `ttv-${randomUUID().slice(0, 10)}`;
}

const CATALOG_EVIDENCE: EvidenceRecord[] = [
  {
    id: "ev-cat-001",
    orgId: "__catalog__",
    traceId: "trace-a1b2c3",
    sourceType: "detection",
    sourceEngine: "correlation-engine",
    sourceActionId: "corr-run-42",
    severity: "high",
    summary: "3 alerts correlated into incident INC-2026-0087 based on shared IP 10.0.3.17 and 15-minute window",
    details: { alertIds: ["ALT-101", "ALT-102", "ALT-103"], sharedEntity: "10.0.3.17", windowMinutes: 15 },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "system",
    actorType: "system",
    timestamp: "2026-03-06T14:30:00Z",
    tags: ["correlation", "incident-creation"],
  },
  {
    id: "ev-cat-002",
    orgId: "__catalog__",
    traceId: "trace-d4e5f6",
    sourceType: "policy_decision",
    sourceEngine: "runtime-guardrails-engine",
    sourceActionId: "gd-cat-1",
    severity: "critical",
    summary: "Blocked agent-7 shell_exec of 'rm -rf /tmp/*' — trust level 1 below threshold 3",
    details: { policyId: "gp-cat-1", verdict: "deny", agentTrustLevel: 1, requiredTrustLevel: 3 },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "agent-7",
    actorType: "agent",
    timestamp: "2026-03-06T14:30:00Z",
    tags: ["guardrail", "block", "ai-safety"],
  },
  {
    id: "ev-cat-003",
    orgId: "__catalog__",
    traceId: "trace-g7h8i9",
    sourceType: "connector_sync",
    sourceEngine: "connector-engine",
    sourceActionId: "sync-aws-guard-duty-22",
    severity: "info",
    summary: "AWS GuardDuty connector sync completed — 47 new findings ingested in 3.2s",
    details: { connectorId: "conn-aws-gd", findingsIngested: 47, durationMs: 3200, nextSyncAt: "2026-03-06T15:00:00Z" },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "system",
    actorType: "service",
    timestamp: "2026-03-06T14:00:00Z",
    tags: ["connector", "sync", "aws"],
  },
  {
    id: "ev-cat-004",
    orgId: "__catalog__",
    traceId: "trace-j0k1l2",
    sourceType: "prediction",
    sourceEngine: "predictive-engine",
    sourceActionId: "pred-anomaly-19",
    severity: "medium",
    summary: "Anomaly detected: login volume from Brazil 340% above 30-day baseline",
    details: { metric: "login_volume_brazil", baseline: 12, observed: 53, zScore: 3.8, confidence: 0.91 },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "system",
    actorType: "system",
    timestamp: "2026-03-06T13:45:00Z",
    tags: ["anomaly", "geo", "prediction"],
  },
  {
    id: "ev-cat-005",
    orgId: "__catalog__",
    traceId: "trace-m3n4o5",
    sourceType: "remediation",
    sourceEngine: "remediation-engine",
    sourceActionId: "rem-suggestion-88",
    severity: "high",
    summary: "Auto-remediation: disabled compromised IAM key AKIA****WXYZ after 2 failed rotation attempts",
    details: { iamKeyId: "AKIA****WXYZ", action: "disable_key", attempts: 2, fallbackTriggered: true },
    parentEvidenceId: "ev-cat-004",
    chainDepth: 1,
    actorId: "remediation-service",
    actorType: "service",
    timestamp: "2026-03-06T13:50:00Z",
    tags: ["remediation", "iam", "auto-action"],
  },
  {
    id: "ev-cat-006",
    orgId: "__catalog__",
    traceId: "trace-p6q7r8",
    sourceType: "adversarial_test",
    sourceEngine: "adversarial-testing-engine",
    sourceActionId: "atk-run-14",
    severity: "medium",
    summary: "Purple team SQL injection test against /api/v1/entities — WAF blocked 4/5 payloads, 1 bypassed",
    details: { testCaseId: "tc-sqli-03", blocked: 4, bypassed: 1, totalPayloads: 5, bypassPayload: "1' OR '1'='1" },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "purple-team-runner",
    actorType: "service",
    timestamp: "2026-03-06T12:00:00Z",
    tags: ["adversarial", "sqli", "waf-bypass"],
  },
  {
    id: "ev-cat-007",
    orgId: "__catalog__",
    traceId: "trace-s9t0u1",
    sourceType: "posture_score",
    sourceEngine: "posture-engine",
    sourceActionId: "posture-calc-daily",
    severity: "info",
    summary: "Daily posture score: 78/100 (+3 from yesterday) — MFA coverage improved to 94%",
    details: { score: 78, previousScore: 75, mfaCoverage: 0.94, openFindings: 23 },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "system",
    actorType: "system",
    timestamp: "2026-03-06T06:00:00Z",
    tags: ["posture", "daily-score"],
  },
  {
    id: "ev-cat-008",
    orgId: "__catalog__",
    traceId: "trace-v2w3x4",
    sourceType: "drift_signal",
    sourceEngine: "cross-cutting-engine",
    sourceActionId: "drift-scan-policy-5",
    severity: "critical",
    summary: "Policy drift: 'Block unrestricted AI agent tool calls' was changed from enforce to disabled by admin-bob",
    details: { policyId: "gp-cat-1", field: "mode", expected: "enforce", actual: "disabled", changedBy: "admin-bob" },
    parentEvidenceId: null,
    chainDepth: 0,
    actorId: "system",
    actorType: "system",
    timestamp: "2026-03-06T10:00:00Z",
    tags: ["drift", "policy", "critical"],
  },
];

const CATALOG_OVERRIDES: HumanOverrideRequest[] = [
  {
    id: "ovr-cat-001",
    orgId: "__catalog__",
    evidenceId: "ev-cat-005",
    featureDomain: "remediation-engine",
    actionDescription: "Auto-disable compromised IAM key AKIA****WXYZ in production AWS account",
    riskLevel: "high",
    requestedBy: "remediation-service",
    requestedAt: "2026-03-06T13:48:00Z",
    status: "approved",
    reviewedBy: "alice.chen@securenexus.io",
    reviewedAt: "2026-03-06T13:49:30Z",
    rationale:
      "Key confirmed compromised via CloudTrail anomaly; disabling is safer than rotation given active exfiltration",
    expiresAt: "2026-03-06T14:48:00Z",
    auditTrail: [
      {
        action: "requested",
        actor: "remediation-service",
        timestamp: "2026-03-06T13:48:00Z",
        detail: "Auto-remediation triggered",
      },
      {
        action: "approved",
        actor: "alice.chen@securenexus.io",
        timestamp: "2026-03-06T13:49:30Z",
        detail: "Approved with rationale",
      },
      {
        action: "executed",
        actor: "remediation-service",
        timestamp: "2026-03-06T13:50:00Z",
        detail: "IAM key disabled",
      },
    ],
  },
  {
    id: "ovr-cat-002",
    orgId: "__catalog__",
    evidenceId: "ev-cat-002",
    featureDomain: "runtime-guardrails-engine",
    actionDescription: "Emergency override: temporarily allow agent-7 shell_exec for incident response",
    riskLevel: "critical",
    requestedBy: "bob.security@securenexus.io",
    requestedAt: "2026-03-06T14:35:00Z",
    status: "pending",
    reviewedBy: null,
    reviewedAt: null,
    rationale: null,
    expiresAt: "2026-03-06T15:35:00Z",
    auditTrail: [
      {
        action: "requested",
        actor: "bob.security@securenexus.io",
        timestamp: "2026-03-06T14:35:00Z",
        detail: "Override requested for IR triage",
      },
    ],
  },
  {
    id: "ovr-cat-003",
    orgId: "__catalog__",
    evidenceId: "ev-cat-006",
    featureDomain: "adversarial-testing-engine",
    actionDescription: "Suppress WAF bypass finding for /api/v1/entities — false positive due to test environment",
    riskLevel: "medium",
    requestedBy: "devops-lead@securenexus.io",
    requestedAt: "2026-03-06T12:30:00Z",
    status: "rejected",
    reviewedBy: "alice.chen@securenexus.io",
    reviewedAt: "2026-03-06T12:45:00Z",
    rationale: "Bypass is reproducible in production; WAF rule must be tightened before suppression",
    expiresAt: "2026-03-06T13:30:00Z",
    auditTrail: [
      {
        action: "requested",
        actor: "devops-lead@securenexus.io",
        timestamp: "2026-03-06T12:30:00Z",
        detail: "Suppress false positive",
      },
      {
        action: "rejected",
        actor: "alice.chen@securenexus.io",
        timestamp: "2026-03-06T12:45:00Z",
        detail: "Not a false positive",
      },
    ],
  },
];

const CATALOG_DRIFT: DriftSignal[] = [
  {
    id: "dft-cat-001",
    orgId: "__catalog__",
    category: "policy",
    severity: "critical",
    sourceEngine: "runtime-guardrails-engine",
    entity: "Policy: Block unrestricted AI agent tool calls (gp-cat-1)",
    expectedState: "mode=enforce",
    actualState: "mode=disabled",
    detectedAt: "2026-03-06T10:05:00Z",
    resolvedAt: null,
    baselineSnapshot: { mode: "enforce", priority: 100, version: 1 },
    currentSnapshot: { mode: "disabled", priority: 100, version: 2 },
    delta: ["mode: enforce → disabled"],
    acknowledgedBy: null,
  },
  {
    id: "dft-cat-002",
    orgId: "__catalog__",
    category: "integration",
    severity: "warning",
    sourceEngine: "connector-engine",
    entity: "Connector: Splunk SIEM (conn-splunk-01)",
    expectedState: "sync_interval=300s, status=healthy",
    actualState: "sync_interval=3600s, status=degraded",
    detectedAt: "2026-03-06T09:00:00Z",
    resolvedAt: null,
    baselineSnapshot: { syncInterval: 300, status: "healthy", lastSuccess: "2026-03-06T08:00:00Z" },
    currentSnapshot: { syncInterval: 3600, status: "degraded", lastSuccess: "2026-03-05T22:00:00Z" },
    delta: ["syncInterval: 300 → 3600", "status: healthy → degraded"],
    acknowledgedBy: null,
  },
  {
    id: "dft-cat-003",
    orgId: "__catalog__",
    category: "identity",
    severity: "critical",
    sourceEngine: "agent-tool-security-engine",
    entity: "Agent: data-pipeline-agent (agent-dp-1)",
    expectedState: "trust_level=2, allowed_tools=[read_db, write_log]",
    actualState: "trust_level=5, allowed_tools=[read_db, write_log, shell_exec, file_write]",
    detectedAt: "2026-03-06T11:00:00Z",
    resolvedAt: null,
    baselineSnapshot: { trustLevel: 2, allowedTools: ["read_db", "write_log"], lastModified: "2026-02-15T00:00:00Z" },
    currentSnapshot: {
      trustLevel: 5,
      allowedTools: ["read_db", "write_log", "shell_exec", "file_write"],
      lastModified: "2026-03-06T10:55:00Z",
    },
    delta: ["trustLevel: 2 → 5", "allowedTools: +shell_exec, +file_write"],
    acknowledgedBy: null,
  },
  {
    id: "dft-cat-004",
    orgId: "__catalog__",
    category: "control",
    severity: "warning",
    sourceEngine: "posture-engine",
    entity: "Control: MFA enforcement for admin accounts",
    expectedState: "enforced=true, coverage=100%",
    actualState: "enforced=true, coverage=94%",
    detectedAt: "2026-03-06T06:05:00Z",
    resolvedAt: null,
    baselineSnapshot: { enforced: true, coverage: 1.0, exemptions: 0 },
    currentSnapshot: { enforced: true, coverage: 0.94, exemptions: 3 },
    delta: ["coverage: 100% → 94%", "exemptions: 0 → 3"],
    acknowledgedBy: "alice.chen@securenexus.io",
  },
  {
    id: "dft-cat-005",
    orgId: "__catalog__",
    category: "posture",
    severity: "info",
    sourceEngine: "posture-engine",
    entity: "Overall security posture score",
    expectedState: "score>=80",
    actualState: "score=78",
    detectedAt: "2026-03-06T06:00:00Z",
    resolvedAt: null,
    baselineSnapshot: { targetScore: 80, previousScore: 82 },
    currentSnapshot: { score: 78, trend: "declining" },
    delta: ["score: 82 → 78 (below target 80)"],
    acknowledgedBy: null,
  },
  {
    id: "dft-cat-006",
    orgId: "__catalog__",
    category: "configuration",
    severity: "warning",
    sourceEngine: "browser-defense-engine",
    entity: "Browser defense trusted domains allow-list",
    expectedState: "domains=[*.securenexus.io, *.internal.corp]",
    actualState: "domains=[*.securenexus.io, *.internal.corp, *.external-vendor.com]",
    detectedAt: "2026-03-06T08:00:00Z",
    resolvedAt: null,
    baselineSnapshot: { domains: ["*.securenexus.io", "*.internal.corp"], count: 2 },
    currentSnapshot: { domains: ["*.securenexus.io", "*.internal.corp", "*.external-vendor.com"], count: 3 },
    delta: ["domains: +*.external-vendor.com"],
    acknowledgedBy: null,
  },
];

const CATALOG_KILL_SWITCHES: KillSwitch[] = [
  {
    id: "ks-cat-001",
    orgId: "__catalog__",
    featureName: "AI auto-remediation",
    engineName: "remediation-engine",
    state: "armed",
    confidenceThreshold: 0.85,
    currentConfidence: 0.92,
    lastTriggeredAt: null,
    triggeredBy: null,
    triggerReason: null,
    rollbackInstructions:
      "Disable auto-remediation and queue all suggestions for manual review. Run: PATCH /api/cross-cutting/reliability/ks-cat-001 {state:'disarmed'}",
    updatedAt: "2026-03-01T00:00:00Z",
    updatedBy: "system",
  },
  {
    id: "ks-cat-002",
    orgId: "__catalog__",
    featureName: "SOC Copilot autonomous triage",
    engineName: "soc-copilot-engine",
    state: "armed",
    confidenceThreshold: 0.9,
    currentConfidence: 0.88,
    lastTriggeredAt: null,
    triggeredBy: null,
    triggerReason: null,
    rollbackInstructions:
      "Pause all autonomous triage actions. Pending actions queued for human review. Agent hypotheses still generated but not auto-executed.",
    updatedAt: "2026-03-05T00:00:00Z",
    updatedBy: "system",
  },
  {
    id: "ks-cat-003",
    orgId: "__catalog__",
    featureName: "Adversarial test execution",
    engineName: "adversarial-testing-engine",
    state: "armed",
    confidenceThreshold: 0.8,
    currentConfidence: 0.95,
    lastTriggeredAt: null,
    triggeredBy: null,
    triggerReason: null,
    rollbackInstructions:
      "Halt all scheduled and in-progress attack test runs. No new test batches will execute until re-armed.",
    updatedAt: "2026-03-01T00:00:00Z",
    updatedBy: "system",
  },
  {
    id: "ks-cat-004",
    orgId: "__catalog__",
    featureName: "Predictive anomaly detection",
    engineName: "predictive-engine",
    state: "armed",
    confidenceThreshold: 0.75,
    currentConfidence: 0.91,
    lastTriggeredAt: null,
    triggeredBy: null,
    triggerReason: null,
    rollbackInstructions:
      "Disable anomaly scoring. Alerts based on anomaly predictions will stop. Historical anomalies remain visible.",
    updatedAt: "2026-03-01T00:00:00Z",
    updatedBy: "system",
  },
  {
    id: "ks-cat-005",
    orgId: "__catalog__",
    featureName: "Browser DOM injection detection",
    engineName: "browser-defense-engine",
    state: "triggered",
    confidenceThreshold: 0.7,
    currentConfidence: 0.55,
    lastTriggeredAt: "2026-03-06T09:15:00Z",
    triggeredBy: "system",
    triggerReason:
      "Confidence dropped below threshold (0.55 < 0.70) after 3 consecutive false positives on legitimate DOM mutations",
    rollbackInstructions:
      "DOM injection scanning paused. Browser sessions monitored passively only. Re-arm after tuning detection rules.",
    updatedAt: "2026-03-06T09:15:00Z",
    updatedBy: "system",
  },
  {
    id: "ks-cat-006",
    orgId: "__catalog__",
    featureName: "Connector auto-sync",
    engineName: "connector-engine",
    state: "armed",
    confidenceThreshold: 0.6,
    currentConfidence: 0.98,
    lastTriggeredAt: null,
    triggeredBy: null,
    triggerReason: null,
    rollbackInstructions:
      "Pause all connector sync schedules. Manual sync still available. Data ingestion halted until re-armed.",
    updatedAt: "2026-03-01T00:00:00Z",
    updatedBy: "system",
  },
];

const CATALOG_MILESTONES: TimeToValueMilestone[] = [
  {
    id: "ttv-cat-001",
    orgId: "__catalog__",
    kind: "first_connector",
    label: "First connector successfully synced",
    achievedAt: "2026-02-20T10:15:00Z",
    durationFromSignupMs: 900000,
    triggeredByAction: "connector-sync-aws-guardduty",
    triggeredByActor: "alice.chen@securenexus.io",
  },
  {
    id: "ttv-cat-002",
    orgId: "__catalog__",
    kind: "first_alert_closed",
    label: "First alert triaged and closed",
    achievedAt: "2026-02-20T14:30:00Z",
    durationFromSignupMs: 16200000,
    triggeredByAction: "alert-close-ALT-001",
    triggeredByActor: "bob.analyst@securenexus.io",
  },
  {
    id: "ttv-cat-003",
    orgId: "__catalog__",
    kind: "first_question_answered",
    label: "First AI-assisted question answered",
    achievedAt: "2026-02-20T11:00:00Z",
    durationFromSignupMs: 3600000,
    triggeredByAction: "ai-query-001",
    triggeredByActor: "alice.chen@securenexus.io",
  },
  {
    id: "ttv-cat-004",
    orgId: "__catalog__",
    kind: "first_finding_resolved",
    label: "First security finding resolved",
    achievedAt: "2026-02-21T09:00:00Z",
    durationFromSignupMs: 82800000,
    triggeredByAction: "finding-resolve-F-042",
    triggeredByActor: "dev-lead@securenexus.io",
  },
  {
    id: "ttv-cat-005",
    orgId: "__catalog__",
    kind: "first_incident_prevented",
    label: "First incident prevented by automation",
    achievedAt: null,
    durationFromSignupMs: null,
    triggeredByAction: null,
    triggeredByActor: null,
  },
  {
    id: "ttv-cat-006",
    orgId: "__catalog__",
    kind: "first_playbook_executed",
    label: "First playbook successfully executed",
    achievedAt: "2026-02-22T16:00:00Z",
    durationFromSignupMs: 194400000,
    triggeredByAction: "playbook-exec-PB-003",
    triggeredByActor: "alice.chen@securenexus.io",
  },
  {
    id: "ttv-cat-007",
    orgId: "__catalog__",
    kind: "first_policy_enforced",
    label: "First guardrail policy enforced an action",
    achievedAt: "2026-02-21T11:00:00Z",
    durationFromSignupMs: 90000000,
    triggeredByAction: "guardrail-enforce-gp-cat-1",
    triggeredByActor: "system",
  },
  {
    id: "ttv-cat-008",
    orgId: "__catalog__",
    kind: "first_report_generated",
    label: "First compliance report generated",
    achievedAt: null,
    durationFromSignupMs: null,
    triggeredByAction: null,
    triggeredByActor: null,
  },
];

const orgEvidenceStore = new Map<string, EvidenceRecord[]>();
const orgOverrideStore = new Map<string, HumanOverrideRequest[]>();
const orgDriftStore = new Map<string, DriftSignal[]>();
const orgKillSwitchStore = new Map<string, KillSwitch[]>();
const orgMilestoneStore = new Map<string, TimeToValueMilestone[]>();

function getOrgEvidence(orgId: string): EvidenceRecord[] {
  if (!orgEvidenceStore.has(orgId)) {
    orgEvidenceStore.set(
      orgId,
      structuredClone(CATALOG_EVIDENCE).map((e) => ({ ...e, orgId })),
    );
  }
  return orgEvidenceStore.get(orgId)!;
}

function getOrgOverrides(orgId: string): HumanOverrideRequest[] {
  if (!orgOverrideStore.has(orgId)) {
    orgOverrideStore.set(
      orgId,
      structuredClone(CATALOG_OVERRIDES).map((o) => ({ ...o, orgId })),
    );
  }
  return orgOverrideStore.get(orgId)!;
}

function getOrgDrift(orgId: string): DriftSignal[] {
  if (!orgDriftStore.has(orgId)) {
    orgDriftStore.set(
      orgId,
      structuredClone(CATALOG_DRIFT).map((d) => ({ ...d, orgId })),
    );
  }
  return orgDriftStore.get(orgId)!;
}

function getOrgKillSwitches(orgId: string): KillSwitch[] {
  if (!orgKillSwitchStore.has(orgId)) {
    orgKillSwitchStore.set(
      orgId,
      structuredClone(CATALOG_KILL_SWITCHES).map((k) => ({ ...k, orgId })),
    );
  }
  return orgKillSwitchStore.get(orgId)!;
}

function getOrgMilestones(orgId: string): TimeToValueMilestone[] {
  if (!orgMilestoneStore.has(orgId)) {
    orgMilestoneStore.set(
      orgId,
      structuredClone(CATALOG_MILESTONES).map((m) => ({ ...m, orgId })),
    );
  }
  return orgMilestoneStore.get(orgId)!;
}

export function getEvidence(orgId: string): EvidenceRecord[] {
  return [...getOrgEvidence(orgId)].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export function getEvidenceById(orgId: string, id: string): EvidenceRecord | undefined {
  return getOrgEvidence(orgId).find((e) => e.id === id);
}

export function getEvidenceChain(orgId: string, traceId: string): EvidenceRecord[] {
  return getOrgEvidence(orgId)
    .filter((e) => e.traceId === traceId)
    .sort((a, b) => a.chainDepth - b.chainDepth);
}

export function recordEvidence(
  orgId: string,
  input: {
    sourceType: EvidenceSourceType;
    sourceEngine: string;
    sourceActionId: string;
    severity: EvidenceSeverity;
    summary: string;
    details: Record<string, unknown>;
    parentEvidenceId?: string;
    actorId: string;
    actorType: "user" | "agent" | "service" | "system";
    tags?: string[];
  },
): EvidenceRecord {
  const store = getOrgEvidence(orgId);
  let chainDepth = 0;
  let traceId = `trace-${randomUUID().slice(0, 8)}`;

  if (input.parentEvidenceId) {
    const parent = store.find((e) => e.id === input.parentEvidenceId);
    if (parent) {
      chainDepth = parent.chainDepth + 1;
      traceId = parent.traceId;
    }
  }

  const record: EvidenceRecord = {
    id: evidenceId(),
    orgId,
    traceId,
    sourceType: input.sourceType,
    sourceEngine: input.sourceEngine,
    sourceActionId: input.sourceActionId,
    severity: input.severity,
    summary: input.summary,
    details: input.details,
    parentEvidenceId: input.parentEvidenceId ?? null,
    chainDepth,
    actorId: input.actorId,
    actorType: input.actorType,
    timestamp: new Date().toISOString(),
    tags: input.tags ?? [],
  };
  store.push(record);
  return record;
}

export function getOverrides(orgId: string): HumanOverrideRequest[] {
  return [...getOrgOverrides(orgId)].sort((a, b) => b.requestedAt.localeCompare(a.requestedAt));
}

export function getPendingOverrides(orgId: string): HumanOverrideRequest[] {
  return getOrgOverrides(orgId).filter((o) => o.status === "pending");
}

export function requestOverride(
  orgId: string,
  input: {
    evidenceId: string;
    featureDomain: string;
    actionDescription: string;
    riskLevel: "low" | "medium" | "high" | "critical";
    requestedBy: string;
    timeboxMinutes?: number;
  },
): HumanOverrideRequest {
  const store = getOrgOverrides(orgId);
  const timeboxMs = (input.timeboxMinutes ?? 60) * 60 * 1000;
  const now = new Date();

  const override: HumanOverrideRequest = {
    id: overrideReqId(),
    orgId,
    evidenceId: input.evidenceId,
    featureDomain: input.featureDomain,
    actionDescription: input.actionDescription,
    riskLevel: input.riskLevel,
    requestedBy: input.requestedBy,
    requestedAt: now.toISOString(),
    status: "pending",
    reviewedBy: null,
    reviewedAt: null,
    rationale: null,
    expiresAt: new Date(now.getTime() + timeboxMs).toISOString(),
    auditTrail: [
      {
        action: "requested",
        actor: input.requestedBy,
        timestamp: now.toISOString(),
        detail: `Override requested for ${input.featureDomain}: ${input.actionDescription}`,
      },
    ],
  };
  store.push(override);
  return override;
}

export function approveOverride(
  orgId: string,
  id: string,
  reviewedBy: string,
  rationale: string,
): HumanOverrideRequest {
  const store = getOrgOverrides(orgId);
  const override = store.find((o) => o.id === id);
  if (!override) throw new Error(`Override ${id} not found`);
  if (override.status !== "pending") throw new Error(`Override ${id} is not pending (status: ${override.status})`);

  const now = new Date().toISOString();
  override.status = "approved";
  override.reviewedBy = reviewedBy;
  override.reviewedAt = now;
  override.rationale = rationale;
  override.auditTrail.push({ action: "approved", actor: reviewedBy, timestamp: now, detail: rationale });
  return override;
}

export function rejectOverride(orgId: string, id: string, reviewedBy: string, rationale: string): HumanOverrideRequest {
  const store = getOrgOverrides(orgId);
  const override = store.find((o) => o.id === id);
  if (!override) throw new Error(`Override ${id} not found`);
  if (override.status !== "pending") throw new Error(`Override ${id} is not pending (status: ${override.status})`);

  const now = new Date().toISOString();
  override.status = "rejected";
  override.reviewedBy = reviewedBy;
  override.reviewedAt = now;
  override.rationale = rationale;
  override.auditTrail.push({ action: "rejected", actor: reviewedBy, timestamp: now, detail: rationale });
  return override;
}

export function getDriftSignals(orgId: string): DriftSignal[] {
  return [...getOrgDrift(orgId)].sort((a, b) => b.detectedAt.localeCompare(a.detectedAt));
}

export function getActiveDrift(orgId: string): DriftSignal[] {
  return getOrgDrift(orgId).filter((d) => d.resolvedAt === null);
}

export function triggerDriftScan(orgId: string): { signalsDetected: number; newSignals: DriftSignal[] } {
  const store = getOrgDrift(orgId);
  const newSignal: DriftSignal = {
    id: driftId(),
    orgId,
    category: "configuration",
    severity: "info",
    sourceEngine: "cross-cutting-engine",
    entity: "Drift scan triggered manually",
    expectedState: "All configurations at baseline",
    actualState: "Scan completed — no new drift detected",
    detectedAt: new Date().toISOString(),
    resolvedAt: new Date().toISOString(),
    baselineSnapshot: {},
    currentSnapshot: {},
    delta: [],
    acknowledgedBy: null,
  };
  store.push(newSignal);
  return { signalsDetected: store.filter((d) => d.resolvedAt === null).length, newSignals: [newSignal] };
}

export function acknowledgeDrift(orgId: string, id: string, acknowledgedBy: string): DriftSignal {
  const store = getOrgDrift(orgId);
  const signal = store.find((d) => d.id === id);
  if (!signal) throw new Error(`Drift signal ${id} not found`);
  signal.acknowledgedBy = acknowledgedBy;
  return signal;
}

export function resolveDrift(orgId: string, id: string): DriftSignal {
  const store = getOrgDrift(orgId);
  const signal = store.find((d) => d.id === id);
  if (!signal) throw new Error(`Drift signal ${id} not found`);
  signal.resolvedAt = new Date().toISOString();
  return signal;
}

export function getKillSwitches(orgId: string): KillSwitch[] {
  return [...getOrgKillSwitches(orgId)].sort((a, b) => a.featureName.localeCompare(b.featureName));
}

export function toggleKillSwitch(
  orgId: string,
  id: string,
  newState: KillSwitchState,
  actor: string,
  reason?: string,
): KillSwitch {
  const store = getOrgKillSwitches(orgId);
  const ks = store.find((k) => k.id === id);
  if (!ks) throw new Error(`Kill switch ${id} not found`);

  const now = new Date().toISOString();
  ks.state = newState;
  ks.updatedAt = now;
  ks.updatedBy = actor;

  if (newState === "triggered") {
    ks.lastTriggeredAt = now;
    ks.triggeredBy = actor;
    ks.triggerReason = reason ?? "Manual trigger";
  }

  return ks;
}

export function getMilestones(orgId: string): TimeToValueMilestone[] {
  return [...getOrgMilestones(orgId)];
}

export function achieveMilestone(
  orgId: string,
  kind: MilestoneKind,
  actor: string,
  actionId: string,
  signupTime?: string,
): TimeToValueMilestone {
  const store = getOrgMilestones(orgId);
  const milestone = store.find((m) => m.kind === kind);
  if (!milestone) throw new Error(`Milestone kind ${kind} not found`);
  if (milestone.achievedAt) throw new Error(`Milestone ${kind} already achieved`);

  const now = new Date();
  milestone.achievedAt = now.toISOString();
  milestone.triggeredByActor = actor;
  milestone.triggeredByAction = actionId;

  if (signupTime) {
    milestone.durationFromSignupMs = now.getTime() - new Date(signupTime).getTime();
  }

  return milestone;
}

export function getCrossCuttingStats(orgId: string): CrossCuttingStats {
  const evidence = getOrgEvidence(orgId);
  const overrides = getOrgOverrides(orgId);
  const drift = getOrgDrift(orgId);
  const killSwitches = getOrgKillSwitches(orgId);
  const milestones = getOrgMilestones(orgId);

  const now = Date.now();
  const last24h = now - 24 * 60 * 60 * 1000;

  const evidenceBySource: Record<string, number> = {};
  for (const e of evidence) {
    evidenceBySource[e.sourceType] = (evidenceBySource[e.sourceType] ?? 0) + 1;
  }

  const driftByCategory: Record<string, number> = {};
  for (const d of drift.filter((d) => d.resolvedAt === null)) {
    driftByCategory[d.category] = (driftByCategory[d.category] ?? 0) + 1;
  }

  const pendingOverrides = overrides.filter((o) => o.status === "pending").length;
  const approvedOverridesLast24h = overrides.filter(
    (o) => o.status === "approved" && o.reviewedAt && new Date(o.reviewedAt).getTime() > last24h,
  ).length;
  const rejectedOverridesLast24h = overrides.filter(
    (o) => o.status === "rejected" && o.reviewedAt && new Date(o.reviewedAt).getTime() > last24h,
  ).length;

  const armed = killSwitches.filter((k) => k.state === "armed");
  const avgConfidence = armed.length > 0 ? armed.reduce((s, k) => s + k.currentConfidence, 0) / armed.length : 0;

  return {
    evidenceCount: evidence.length,
    evidenceBySource,
    pendingOverrides,
    approvedOverridesLast24h,
    rejectedOverridesLast24h,
    activeDriftSignals: drift.filter((d) => d.resolvedAt === null).length,
    driftByCategory,
    killSwitchesArmed: armed.length,
    killSwitchesTriggered: killSwitches.filter((k) => k.state === "triggered").length,
    milestonesAchieved: milestones.filter((m) => m.achievedAt !== null).length,
    milestonesRemaining: milestones.filter((m) => m.achievedAt === null).length,
    avgConfidence: Math.round(avgConfidence * 100) / 100,
  };
}
