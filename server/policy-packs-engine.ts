import { storage } from "./storage";
import { logger } from "./logger";

const log = logger.child("policy-packs");

export type PolicyDomain = "cloud_posture" | "identity_risk" | "appsec" | "ai_runtime_safety" | "regulated_workflows";

export type StrictnessPreset = "starter" | "balanced" | "regulated" | "zero_trust";

export type PolicyStatus = "active" | "draft" | "deprecated" | "archived";

export interface PolicyRule {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  enabled: boolean;
  autoRemediate: boolean;
  parameters: Record<string, string | number | boolean>;
}

export interface DashboardWidget {
  id: string;
  title: string;
  type: "metric" | "chart" | "table" | "status";
  dataSource: string;
  config: Record<string, string | number | boolean>;
}

export interface AlertTemplate {
  id: string;
  name: string;
  condition: string;
  severity: "critical" | "high" | "medium" | "low";
  channels: string[];
  cooldownMinutes: number;
}

export interface OwnershipMapping {
  domain: PolicyDomain;
  defaultOwnerRole: string;
  escalationPath: string[];
  reviewCadenceDays: number;
}

export interface ChangeLogEntry {
  version: string;
  date: string;
  author: string;
  summary: string;
  changes: string[];
  migrationNotes: string | null;
  breaking: boolean;
}

export interface PolicyPack {
  id: string;
  name: string;
  domain: PolicyDomain;
  description: string;
  version: string;
  status: PolicyStatus;
  strictnessPreset: StrictnessPreset;
  rules: PolicyRule[];
  dashboards: DashboardWidget[];
  alerts: AlertTemplate[];
  ownership: OwnershipMapping;
  changelog: ChangeLogEntry[];
  createdAt: string;
  updatedAt: string;
  appliedByOrgs: string[];
  tags: string[];
}

export interface PolicyPackSummary {
  totalPacks: number;
  byDomain: Record<string, number>;
  byStrictness: Record<string, number>;
  byStatus: Record<string, number>;
  totalRules: number;
  totalAlerts: number;
}

export interface OrgPolicyPackActivation {
  orgId: string;
  packId: string;
  activatedAt: string;
  activatedBy: string;
  strictnessOverride: StrictnessPreset | null;
  ruleOverrides: Record<string, { enabled?: boolean; parameters?: Record<string, string | number | boolean> }>;
  status: "active" | "paused" | "pending_review";
}

const DOMAIN_LABELS: Record<PolicyDomain, string> = {
  cloud_posture: "Cloud Posture",
  identity_risk: "Identity Risk",
  appsec: "Application Security",
  ai_runtime_safety: "AI Runtime Safety",
  regulated_workflows: "Regulated Workflows",
};

const STRICTNESS_LABELS: Record<StrictnessPreset, string> = {
  starter: "Starter",
  balanced: "Balanced",
  regulated: "Regulated",
  zero_trust: "Zero Trust",
};

const STRICTNESS_DESCRIPTIONS: Record<StrictnessPreset, string> = {
  starter:
    "Lightweight baseline for teams starting their security journey. Focuses on high-impact, low-friction controls.",
  balanced:
    "Production-grade defaults balancing security coverage with operational overhead. Recommended for most teams.",
  regulated: "Strict controls aligned with SOC 2, ISO 27001, HIPAA, and GDPR requirements. Mandatory audit trails.",
  zero_trust:
    "Maximum enforcement with no implicit trust. Every access verified, every action logged, every anomaly flagged.",
};

export function getDomainLabels(): Record<PolicyDomain, string> {
  return { ...DOMAIN_LABELS };
}

export function getStrictnessPresets(): Array<{
  id: StrictnessPreset;
  label: string;
  description: string;
}> {
  return (Object.keys(STRICTNESS_LABELS) as StrictnessPreset[]).map((id) => ({
    id,
    label: STRICTNESS_LABELS[id],
    description: STRICTNESS_DESCRIPTIONS[id],
  }));
}

const catalogPacks: PolicyPack[] = [
  {
    id: "cloud-posture-pack",
    name: "Cloud Posture Baseline",
    domain: "cloud_posture",
    description:
      "Comprehensive cloud security posture policies covering AWS, Azure, and GCP. Enforces encryption, network segmentation, IAM hygiene, and resource tagging.",
    version: "2.3.0",
    status: "active",
    strictnessPreset: "balanced",
    rules: [
      {
        id: "cp-001",
        title: "Enforce S3 Bucket Encryption",
        description: "All S3 buckets must have server-side encryption enabled with AES-256 or AWS KMS.",
        severity: "critical",
        enabled: true,
        autoRemediate: true,
        parameters: { encryptionType: "aws:kms", blockPublicAccess: true },
      },
      {
        id: "cp-002",
        title: "Block Public Security Groups",
        description: "Security groups must not allow unrestricted inbound access (0.0.0.0/0) on sensitive ports.",
        severity: "critical",
        enabled: true,
        autoRemediate: false,
        parameters: { blockedPorts: "22,3389,3306,5432,27017", allowHttps: true },
      },
      {
        id: "cp-003",
        title: "Enforce Resource Tagging",
        description:
          "All cloud resources must have mandatory tags: Owner, Environment, CostCenter, DataClassification.",
        severity: "medium",
        enabled: true,
        autoRemediate: false,
        parameters: { requiredTags: "Owner,Environment,CostCenter,DataClassification" },
      },
      {
        id: "cp-004",
        title: "Enable CloudTrail Logging",
        description: "AWS CloudTrail must be enabled in all regions with log file validation.",
        severity: "high",
        enabled: true,
        autoRemediate: true,
        parameters: { multiRegion: true, logValidation: true, s3Encryption: true },
      },
      {
        id: "cp-005",
        title: "Restrict Root Account Usage",
        description: "Root account usage triggers immediate alert. MFA must be enabled on root.",
        severity: "critical",
        enabled: true,
        autoRemediate: false,
        parameters: { alertOnRootLogin: true, requireRootMFA: true },
      },
    ],
    dashboards: [
      {
        id: "cp-dash-1",
        title: "Cloud Compliance Score",
        type: "metric",
        dataSource: "cspm.complianceScore",
        config: { threshold: 90 },
      },
      {
        id: "cp-dash-2",
        title: "Misconfiguration Trend",
        type: "chart",
        dataSource: "cspm.misconfigTrend",
        config: { period: "30d" },
      },
      {
        id: "cp-dash-3",
        title: "Top Violations",
        type: "table",
        dataSource: "cspm.topViolations",
        config: { limit: 10 },
      },
    ],
    alerts: [
      {
        id: "cp-alert-1",
        name: "Public S3 Bucket Detected",
        condition: "s3.publicAccess == true",
        severity: "critical",
        channels: ["slack", "email", "pagerduty"],
        cooldownMinutes: 5,
      },
      {
        id: "cp-alert-2",
        name: "Root Account Login",
        condition: "iam.rootLogin == true",
        severity: "critical",
        channels: ["slack", "pagerduty"],
        cooldownMinutes: 0,
      },
      {
        id: "cp-alert-3",
        name: "Unencrypted Resource Created",
        condition: "resource.encryption == false",
        severity: "high",
        channels: ["slack", "email"],
        cooldownMinutes: 15,
      },
    ],
    ownership: {
      domain: "cloud_posture",
      defaultOwnerRole: "Cloud Security Engineer",
      escalationPath: ["Cloud Team Lead", "CISO"],
      reviewCadenceDays: 30,
    },
    changelog: [
      {
        version: "2.3.0",
        date: "2026-02-15",
        author: "security-team",
        summary: "Added GCP resource tagging enforcement",
        changes: [
          "Added cp-003 resource tagging rule for GCP",
          "Updated dashboard with GCP compliance metrics",
          "Fixed false positive on internal load balancer rules",
        ],
        migrationNotes: "New required tag 'DataClassification' added. Existing resources need tagging within 30 days.",
        breaking: false,
      },
      {
        version: "2.2.0",
        date: "2026-01-10",
        author: "security-team",
        summary: "Enhanced network segmentation controls",
        changes: [
          "Added cp-002 public security group blocking",
          "Added PagerDuty alert channel",
          "Increased CloudTrail log retention to 365 days",
        ],
        migrationNotes: null,
        breaking: false,
      },
      {
        version: "2.0.0",
        date: "2025-11-01",
        author: "security-team",
        summary: "Major rewrite for multi-cloud support",
        changes: [
          "Refactored rules engine for AWS+Azure+GCP",
          "Added auto-remediation for encryption rules",
          "Breaking: rule ID format changed from numeric to cp-XXX",
        ],
        migrationNotes: "Rule IDs changed format. Update any external integrations referencing old numeric IDs.",
        breaking: true,
      },
    ],
    createdAt: "2025-06-15T00:00:00Z",
    updatedAt: "2026-02-15T00:00:00Z",
    appliedByOrgs: [],
    tags: ["aws", "azure", "gcp", "cspm", "encryption", "iam"],
  },
  {
    id: "identity-risk-pack",
    name: "Identity & Access Risk Controls",
    domain: "identity_risk",
    description:
      "Identity-centric risk policies covering privilege escalation detection, dormant account cleanup, MFA enforcement, and anomalous access pattern detection.",
    version: "1.5.0",
    status: "active",
    strictnessPreset: "regulated",
    rules: [
      {
        id: "ir-001",
        title: "Enforce MFA on All Accounts",
        description:
          "Multi-factor authentication must be enabled for all user accounts. No exceptions for service accounts with interactive login.",
        severity: "critical",
        enabled: true,
        autoRemediate: false,
        parameters: { gracePeriodDays: 7, exemptServiceAccounts: false },
      },
      {
        id: "ir-002",
        title: "Dormant Account Detection",
        description:
          "Accounts inactive for more than the configured threshold are flagged for review and eventual deactivation.",
        severity: "medium",
        enabled: true,
        autoRemediate: true,
        parameters: { inactiveDaysThreshold: 90, autoDisableDays: 120 },
      },
      {
        id: "ir-003",
        title: "Privilege Escalation Alert",
        description: "Detect and alert on unauthorized privilege escalation attempts or suspicious role changes.",
        severity: "critical",
        enabled: true,
        autoRemediate: false,
        parameters: { monitorRoleChanges: true, alertOnSudoUsage: true },
      },
      {
        id: "ir-004",
        title: "Impossible Travel Detection",
        description: "Flag logins from geographically impossible locations within a short time window.",
        severity: "high",
        enabled: true,
        autoRemediate: false,
        parameters: { maxTravelSpeedKmh: 900, windowMinutes: 60 },
      },
    ],
    dashboards: [
      {
        id: "ir-dash-1",
        title: "MFA Adoption Rate",
        type: "metric",
        dataSource: "identity.mfaRate",
        config: { target: 100 },
      },
      {
        id: "ir-dash-2",
        title: "Dormant Accounts",
        type: "metric",
        dataSource: "identity.dormantCount",
        config: { warnThreshold: 5 },
      },
      {
        id: "ir-dash-3",
        title: "Access Anomalies",
        type: "chart",
        dataSource: "identity.anomalyTrend",
        config: { period: "7d" },
      },
    ],
    alerts: [
      {
        id: "ir-alert-1",
        name: "Privilege Escalation Detected",
        condition: "identity.privEscalation == true",
        severity: "critical",
        channels: ["slack", "pagerduty"],
        cooldownMinutes: 0,
      },
      {
        id: "ir-alert-2",
        name: "Impossible Travel Login",
        condition: "identity.impossibleTravel == true",
        severity: "high",
        channels: ["slack", "email"],
        cooldownMinutes: 10,
      },
    ],
    ownership: {
      domain: "identity_risk",
      defaultOwnerRole: "IAM Security Engineer",
      escalationPath: ["Identity Team Lead", "CISO"],
      reviewCadenceDays: 14,
    },
    changelog: [
      {
        version: "1.5.0",
        date: "2026-02-01",
        author: "identity-team",
        summary: "Added impossible travel detection",
        changes: [
          "Added ir-004 impossible travel rule",
          "Added access anomaly trend dashboard",
          "Tuned dormant account threshold from 60 to 90 days",
        ],
        migrationNotes: "Dormant account threshold changed. Existing flagged accounts will be re-evaluated.",
        breaking: false,
      },
      {
        version: "1.0.0",
        date: "2025-08-01",
        author: "identity-team",
        summary: "Initial identity risk pack",
        changes: ["MFA enforcement rule", "Dormant account detection", "Privilege escalation alerting"],
        migrationNotes: null,
        breaking: false,
      },
    ],
    createdAt: "2025-08-01T00:00:00Z",
    updatedAt: "2026-02-01T00:00:00Z",
    appliedByOrgs: [],
    tags: ["iam", "mfa", "privilege", "access-review", "identity"],
  },
  {
    id: "appsec-pack",
    name: "Application Security Controls",
    domain: "appsec",
    description:
      "End-to-end application security policies covering SAST/DAST integration gates, dependency vulnerability management, secret scanning, and secure SDLC enforcement.",
    version: "3.1.0",
    status: "active",
    strictnessPreset: "balanced",
    rules: [
      {
        id: "as-001",
        title: "Block Critical Dependency Vulnerabilities",
        description: "CI/CD pipeline must fail if critical or high-severity vulnerabilities are found in dependencies.",
        severity: "critical",
        enabled: true,
        autoRemediate: false,
        parameters: { blockSeverities: "critical,high", graceWindowDays: 3, exemptDevDeps: false },
      },
      {
        id: "as-002",
        title: "Secret Scanning Gate",
        description: "All commits must pass secret scanning before merge. Detected secrets block the pipeline.",
        severity: "critical",
        enabled: true,
        autoRemediate: false,
        parameters: { scanPreCommit: true, scanPR: true, allowOverride: false },
      },
      {
        id: "as-003",
        title: "SAST Quality Gate",
        description: "Static analysis must pass with zero critical findings before code can be merged to main.",
        severity: "high",
        enabled: true,
        autoRemediate: false,
        parameters: { maxCritical: 0, maxHigh: 3, toolIntegration: "semgrep" },
      },
      {
        id: "as-004",
        title: "Container Image Scanning",
        description:
          "Container images must be scanned for vulnerabilities before deployment. Images with critical CVEs are blocked.",
        severity: "high",
        enabled: true,
        autoRemediate: false,
        parameters: { maxCriticalCVEs: 0, scanOnPush: true, enforceBaseImagePolicy: true },
      },
      {
        id: "as-005",
        title: "SBOM Generation Requirement",
        description: "Software Bill of Materials must be generated and stored for every production release.",
        severity: "medium",
        enabled: true,
        autoRemediate: true,
        parameters: { format: "cyclonedx", includeTransitive: true },
      },
    ],
    dashboards: [
      {
        id: "as-dash-1",
        title: "Vulnerability Backlog",
        type: "metric",
        dataSource: "appsec.vulnCount",
        config: { warnThreshold: 10 },
      },
      {
        id: "as-dash-2",
        title: "MTTR by Severity",
        type: "chart",
        dataSource: "appsec.mttrBySeverity",
        config: { period: "90d" },
      },
      {
        id: "as-dash-3",
        title: "Pipeline Gate Pass Rate",
        type: "metric",
        dataSource: "appsec.gatePassRate",
        config: { target: 95 },
      },
    ],
    alerts: [
      {
        id: "as-alert-1",
        name: "Critical CVE in Production",
        condition: "appsec.criticalCVE.production == true",
        severity: "critical",
        channels: ["slack", "pagerduty", "email"],
        cooldownMinutes: 0,
      },
      {
        id: "as-alert-2",
        name: "Secret Detected in Commit",
        condition: "appsec.secretDetected == true",
        severity: "critical",
        channels: ["slack"],
        cooldownMinutes: 0,
      },
      {
        id: "as-alert-3",
        name: "SAST Gate Failure Spike",
        condition: "appsec.gateFailRate > 30",
        severity: "medium",
        channels: ["slack"],
        cooldownMinutes: 60,
      },
    ],
    ownership: {
      domain: "appsec",
      defaultOwnerRole: "AppSec Engineer",
      escalationPath: ["Engineering Manager", "VP Engineering", "CISO"],
      reviewCadenceDays: 14,
    },
    changelog: [
      {
        version: "3.1.0",
        date: "2026-02-20",
        author: "appsec-team",
        summary: "Added SBOM generation requirement",
        changes: [
          "Added as-005 SBOM rule",
          "Added CycloneDX format support",
          "Updated pipeline gate to include SBOM step",
        ],
        migrationNotes: "SBOM generation adds ~30s to CI pipeline. Ensure CycloneDX CLI is installed in build images.",
        breaking: false,
      },
      {
        version: "3.0.0",
        date: "2026-01-05",
        author: "appsec-team",
        summary: "Major upgrade with container scanning",
        changes: [
          "Added as-004 container image scanning",
          "Switched default SAST tool from CodeQL to Semgrep",
          "Breaking: removed legacy vulnerability threshold format",
        ],
        migrationNotes: "Threshold format changed from numeric to severity-based. Update CI config files.",
        breaking: true,
      },
      {
        version: "2.0.0",
        date: "2025-09-15",
        author: "appsec-team",
        summary: "SAST and secret scanning gates",
        changes: ["Added as-002 secret scanning", "Added as-003 SAST gate", "Integrated with GitHub Advanced Security"],
        migrationNotes: null,
        breaking: false,
      },
    ],
    createdAt: "2025-05-01T00:00:00Z",
    updatedAt: "2026-02-20T00:00:00Z",
    appliedByOrgs: [],
    tags: ["sast", "dast", "dependencies", "secrets", "containers", "sbom", "sdlc"],
  },
  {
    id: "ai-runtime-safety-pack",
    name: "AI Runtime Safety Controls",
    domain: "ai_runtime_safety",
    description:
      "Policies governing AI model deployment safety: prompt injection defense, output filtering, model drift detection, budget controls, and bias monitoring.",
    version: "1.2.0",
    status: "active",
    strictnessPreset: "regulated",
    rules: [
      {
        id: "ai-001",
        title: "Prompt Injection Defense",
        description:
          "All LLM inputs must pass prompt injection detection before processing. Blocked inputs are logged and alerted.",
        severity: "critical",
        enabled: true,
        autoRemediate: true,
        parameters: { detectionModel: "ensemble", blockThreshold: 0.85, logAllInputs: true },
      },
      {
        id: "ai-002",
        title: "Output Content Filtering",
        description: "All LLM outputs must pass content safety filtering before being returned to users.",
        severity: "high",
        enabled: true,
        autoRemediate: true,
        parameters: { filterPII: true, filterHarmful: true, filterConfidential: true },
      },
      {
        id: "ai-003",
        title: "Model Inference Budget",
        description: "Per-org daily inference budget limits. Exceeding triggers throttling and alerts.",
        severity: "medium",
        enabled: true,
        autoRemediate: true,
        parameters: { dailyBudgetUSD: 500, throttleAt: 80, hardStopAt: 100 },
      },
      {
        id: "ai-004",
        title: "Model Drift Monitoring",
        description:
          "Monitor model output distributions for drift. Alert when statistical divergence exceeds threshold.",
        severity: "high",
        enabled: true,
        autoRemediate: false,
        parameters: { driftMetric: "psi", alertThreshold: 0.2, windowHours: 24 },
      },
    ],
    dashboards: [
      {
        id: "ai-dash-1",
        title: "Prompt Injection Attempts",
        type: "chart",
        dataSource: "ai.promptInjectionTrend",
        config: { period: "7d" },
      },
      {
        id: "ai-dash-2",
        title: "Inference Budget Usage",
        type: "metric",
        dataSource: "ai.budgetUsage",
        config: { threshold: 80 },
      },
      {
        id: "ai-dash-3",
        title: "Model Drift Score",
        type: "metric",
        dataSource: "ai.driftScore",
        config: { warnThreshold: 0.15 },
      },
    ],
    alerts: [
      {
        id: "ai-alert-1",
        name: "Prompt Injection Blocked",
        condition: "ai.promptInjection.blocked == true",
        severity: "high",
        channels: ["slack"],
        cooldownMinutes: 5,
      },
      {
        id: "ai-alert-2",
        name: "Budget Threshold Exceeded",
        condition: "ai.budget.percentUsed > 80",
        severity: "medium",
        channels: ["slack", "email"],
        cooldownMinutes: 60,
      },
      {
        id: "ai-alert-3",
        name: "Model Drift Detected",
        condition: "ai.drift.psi > 0.2",
        severity: "high",
        channels: ["slack", "email"],
        cooldownMinutes: 120,
      },
    ],
    ownership: {
      domain: "ai_runtime_safety",
      defaultOwnerRole: "ML Security Engineer",
      escalationPath: ["AI Team Lead", "VP Engineering", "CISO"],
      reviewCadenceDays: 7,
    },
    changelog: [
      {
        version: "1.2.0",
        date: "2026-02-10",
        author: "ai-team",
        summary: "Added model drift monitoring",
        changes: [
          "Added ai-004 drift monitoring rule",
          "Added PSI-based drift metric",
          "Added drift score dashboard widget",
        ],
        migrationNotes: "Drift monitoring requires model output logging to be enabled. Enable via AI Engine settings.",
        breaking: false,
      },
      {
        version: "1.0.0",
        date: "2025-12-01",
        author: "ai-team",
        summary: "Initial AI safety pack",
        changes: ["Prompt injection defense", "Output content filtering", "Inference budget controls"],
        migrationNotes: null,
        breaking: false,
      },
    ],
    createdAt: "2025-12-01T00:00:00Z",
    updatedAt: "2026-02-10T00:00:00Z",
    appliedByOrgs: [],
    tags: ["ai", "llm", "prompt-injection", "content-safety", "budget", "drift"],
  },
  {
    id: "regulated-workflows-pack",
    name: "Regulated Industry Workflows",
    domain: "regulated_workflows",
    description:
      "Compliance-driven workflow policies for regulated industries: SOX change controls, HIPAA access logging, PCI-DSS cardholder data protection, and evidence collection automation.",
    version: "2.0.0",
    status: "active",
    strictnessPreset: "regulated",
    rules: [
      {
        id: "rw-001",
        title: "Change Advisory Board Approval",
        description: "All production changes require CAB approval with documented risk assessment and rollback plan.",
        severity: "high",
        enabled: true,
        autoRemediate: false,
        parameters: { minApprovers: 2, requireRiskAssessment: true, requireRollbackPlan: true },
      },
      {
        id: "rw-002",
        title: "PHI Access Audit Trail",
        description:
          "All access to Protected Health Information must be logged with user identity, timestamp, and justification.",
        severity: "critical",
        enabled: true,
        autoRemediate: true,
        parameters: { logRetentionDays: 2190, requireJustification: true, alertOnBulkAccess: true },
      },
      {
        id: "rw-003",
        title: "Evidence Collection Automation",
        description:
          "Compliance evidence must be automatically collected and stored for audit periods. Manual evidence requires attestation.",
        severity: "medium",
        enabled: true,
        autoRemediate: true,
        parameters: { autoCollectFrequencyHours: 24, retentionDays: 365, requireAttestation: true },
      },
      {
        id: "rw-004",
        title: "Segregation of Duties",
        description: "Critical operations require different individuals for request, approval, and execution phases.",
        severity: "high",
        enabled: true,
        autoRemediate: false,
        parameters: { enforceThreePhase: true, exemptEmergencyChanges: false },
      },
    ],
    dashboards: [
      {
        id: "rw-dash-1",
        title: "CAB Approval Status",
        type: "status",
        dataSource: "regulated.cabStatus",
        config: { showPending: true },
      },
      {
        id: "rw-dash-2",
        title: "Evidence Collection Rate",
        type: "metric",
        dataSource: "regulated.evidenceRate",
        config: { target: 100 },
      },
      {
        id: "rw-dash-3",
        title: "Compliance Gaps",
        type: "table",
        dataSource: "regulated.complianceGaps",
        config: { limit: 20 },
      },
    ],
    alerts: [
      {
        id: "rw-alert-1",
        name: "Unapproved Production Change",
        condition: "regulated.unapprovedChange == true",
        severity: "critical",
        channels: ["slack", "pagerduty", "email"],
        cooldownMinutes: 0,
      },
      {
        id: "rw-alert-2",
        name: "PHI Bulk Access Detected",
        condition: "regulated.phiBulkAccess == true",
        severity: "high",
        channels: ["slack", "email"],
        cooldownMinutes: 10,
      },
      {
        id: "rw-alert-3",
        name: "Evidence Collection Failed",
        condition: "regulated.evidenceCollectionFailed == true",
        severity: "medium",
        channels: ["slack"],
        cooldownMinutes: 60,
      },
    ],
    ownership: {
      domain: "regulated_workflows",
      defaultOwnerRole: "Compliance Manager",
      escalationPath: ["Compliance Director", "GRC Lead", "CISO"],
      reviewCadenceDays: 7,
    },
    changelog: [
      {
        version: "2.0.0",
        date: "2026-01-20",
        author: "compliance-team",
        summary: "Major upgrade with segregation of duties",
        changes: [
          "Added rw-004 segregation of duties rule",
          "Breaking: CAB approval now requires risk assessment field",
          "Added compliance gaps dashboard",
          "Increased PHI log retention to 6 years",
        ],
        migrationNotes:
          "CAB approval form now requires mandatory risk_assessment field. Update all change request templates.",
        breaking: true,
      },
      {
        version: "1.0.0",
        date: "2025-10-01",
        author: "compliance-team",
        summary: "Initial regulated workflows pack",
        changes: ["CAB approval requirement", "PHI access audit trail", "Evidence collection automation"],
        migrationNotes: null,
        breaking: false,
      },
    ],
    createdAt: "2025-10-01T00:00:00Z",
    updatedAt: "2026-01-20T00:00:00Z",
    appliedByOrgs: [],
    tags: ["sox", "hipaa", "pci-dss", "cab", "evidence", "compliance", "segregation-of-duties"],
  },
];

const orgActivations = new Map<string, OrgPolicyPackActivation[]>();

function getOrgActivations(orgId: string): OrgPolicyPackActivation[] {
  if (!orgActivations.has(orgId)) {
    orgActivations.set(orgId, []);
  }
  return orgActivations.get(orgId)!;
}

export function getAllPolicyPacks(): PolicyPack[] {
  return catalogPacks;
}

export function getPolicyPackById(id: string): PolicyPack | undefined {
  return catalogPacks.find((p) => p.id === id);
}

export function getPolicyPacksByDomain(domain: PolicyDomain): PolicyPack[] {
  return catalogPacks.filter((p) => p.domain === domain);
}

export function getPolicyPacksByStrictness(preset: StrictnessPreset): PolicyPack[] {
  return catalogPacks.filter((p) => p.strictnessPreset === preset);
}

export function getPolicyPackSummary(): PolicyPackSummary {
  const byDomain: Record<string, number> = {};
  const byStrictness: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  let totalRules = 0;
  let totalAlerts = 0;

  for (const pack of catalogPacks) {
    byDomain[pack.domain] = (byDomain[pack.domain] || 0) + 1;
    byStrictness[pack.strictnessPreset] = (byStrictness[pack.strictnessPreset] || 0) + 1;
    byStatus[pack.status] = (byStatus[pack.status] || 0) + 1;
    totalRules += pack.rules.length;
    totalAlerts += pack.alerts.length;
  }

  return {
    totalPacks: catalogPacks.length,
    byDomain,
    byStrictness,
    byStatus,
    totalRules,
    totalAlerts,
  };
}

export function getPackChangelog(packId: string): ChangeLogEntry[] {
  const pack = catalogPacks.find((p) => p.id === packId);
  if (!pack) return [];
  return pack.changelog;
}

export function activatePackForOrg(
  orgId: string,
  packId: string,
  activatedBy: string,
  strictnessOverride?: StrictnessPreset,
): OrgPolicyPackActivation | { error: string } {
  const pack = catalogPacks.find((p) => p.id === packId);
  if (!pack) {
    return { error: "Policy pack not found" };
  }

  const activations = getOrgActivations(orgId);
  const existing = activations.find((a) => a.packId === packId);
  if (existing) {
    return { error: "Policy pack already activated for this organization" };
  }

  const activation: OrgPolicyPackActivation = {
    orgId,
    packId,
    activatedAt: new Date().toISOString(),
    activatedBy,
    strictnessOverride: strictnessOverride || null,
    ruleOverrides: {},
    status: "active",
  };

  activations.push(activation);

  if (!pack.appliedByOrgs.includes(orgId)) {
    pack.appliedByOrgs.push(orgId);
  }

  log.info("Policy pack activated", { orgId, packId, strictnessOverride });

  storage
    .createAuditLog({
      orgId,
      userId: activatedBy,
      action: "policy_pack.activated",
      resourceType: "policy_pack",
      resourceId: packId,
      details: { packName: pack.name, strictnessOverride: strictnessOverride || pack.strictnessPreset },
    })
    .catch((err: unknown) => {
      log.warn("Failed to persist audit log for pack activation", { error: String(err) });
    });

  return activation;
}

export function deactivatePackForOrg(orgId: string, packId: string): boolean {
  const activations = getOrgActivations(orgId);
  const idx = activations.findIndex((a) => a.packId === packId);
  if (idx === -1) return false;

  activations.splice(idx, 1);

  const pack = catalogPacks.find((p) => p.id === packId);
  if (pack) {
    const orgIdx = pack.appliedByOrgs.indexOf(orgId);
    if (orgIdx !== -1) pack.appliedByOrgs.splice(orgIdx, 1);
  }

  log.info("Policy pack deactivated", { orgId, packId });
  return true;
}

export function getOrgActivatedPacks(orgId: string): OrgPolicyPackActivation[] {
  return getOrgActivations(orgId);
}

export function updatePackActivation(
  orgId: string,
  packId: string,
  updates: {
    strictnessOverride?: StrictnessPreset | null;
    status?: "active" | "paused" | "pending_review";
    ruleOverrides?: Record<string, { enabled?: boolean; parameters?: Record<string, string | number | boolean> }>;
  },
): OrgPolicyPackActivation | null {
  const activations = getOrgActivations(orgId);
  const activation = activations.find((a) => a.packId === packId);
  if (!activation) return null;

  if (updates.strictnessOverride !== undefined) {
    activation.strictnessOverride = updates.strictnessOverride;
  }
  if (updates.status !== undefined) {
    activation.status = updates.status;
  }
  if (updates.ruleOverrides !== undefined) {
    activation.ruleOverrides = { ...activation.ruleOverrides, ...updates.ruleOverrides };
  }

  log.info("Policy pack activation updated", { orgId, packId, updates });
  return activation;
}

export function getEffectiveRules(orgId: string, packId: string): PolicyRule[] | null {
  const pack = catalogPacks.find((p) => p.id === packId);
  if (!pack) return null;

  const activation = getOrgActivations(orgId).find((a) => a.packId === packId);

  return pack.rules.map((rule) => {
    const override = activation?.ruleOverrides[rule.id];
    if (!override) return { ...rule };

    return {
      ...rule,
      enabled: override.enabled !== undefined ? override.enabled : rule.enabled,
      parameters: override.parameters ? { ...rule.parameters, ...override.parameters } : rule.parameters,
    };
  });
}
