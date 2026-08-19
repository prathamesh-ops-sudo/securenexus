import { randomUUID, createHash } from "crypto";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type FindingSource =
  | "sast"
  | "dast"
  | "sca"
  | "container_scan"
  | "iac_scan"
  | "secret_scan"
  | "cloud_config"
  | "runtime"
  | "pentest"
  | "manual";

export type FindingStatus = "open" | "in_progress" | "remediated" | "suppressed" | "false_positive";

export type ConfidenceLevel = "confirmed" | "high" | "medium" | "low" | "unknown";

export interface SourceLocation {
  repo: string;
  branch: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  rule: string;
  language: string;
  commitSha: string;
}

export interface BuildContext {
  pipelineName: string;
  pipelineId: string;
  jobName: string;
  jobId: string;
  buildNumber: number;
  artifactHash: string;
  registry: string;
  imageTag: string;
  triggeredAt: string;
}

export interface DeployedAsset {
  assetId: string;
  assetName: string;
  assetType: "service" | "function" | "container" | "vm" | "bucket" | "database" | "api_gateway";
  environment: "production" | "staging" | "development" | "shared";
  region: string;
  namespace: string;
  lastDeployedAt: string;
  infraProvider: "aws" | "gcp" | "azure" | "on_prem";
}

export interface OwnerInfo {
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  team: string;
  escalationPath: string[];
  slackChannel: string;
  oncallSchedule: string;
}

export interface EvidenceBundle {
  id: string;
  findingId: string;
  evidenceType: "code_snippet" | "log_trace" | "network_capture" | "config_snapshot" | "scan_report";
  title: string;
  content: string;
  collectedAt: string;
  sourceUrl: string;
}

export interface RemediationSuggestion {
  id: string;
  findingId: string;
  title: string;
  description: string;
  patchDiff: string;
  filePath: string;
  language: string;
  confidenceScore: number;
  effort: "trivial" | "small" | "medium" | "large";
  prReady: boolean;
  cweIds: string[];
  references: string[];
  createdAt: string;
}

export interface FindingLineage {
  id: string;
  orgId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  source: FindingSource;
  status: FindingStatus;
  confidence: ConfidenceLevel;
  riskScore: number;
  sourceLocation: SourceLocation;
  buildContext: BuildContext | null;
  deployedAsset: DeployedAsset;
  owner: OwnerInfo;
  evidenceBundles: EvidenceBundle[];
  remediationSuggestions: RemediationSuggestion[];
  correlationHash: string;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  slaDeadline: string;
  cveIds: string[];
  cweIds: string[];
  mitreTactics: string[];
}

export interface LineageStats {
  totalFindings: number;
  openFindings: number;
  remediatedFindings: number;
  suppressedFindings: number;
  bySeverity: Record<FindingSeverity, number>;
  bySource: Record<string, number>;
  byEnvironment: Record<string, number>;
  meanTimeToRemediate: string;
  slaBreaches: number;
  patchReadySuggestions: number;
  avgConfidenceScore: number;
  topOwners: { owner: OwnerInfo; findingCount: number }[];
}

export interface LineageFilter {
  severity?: FindingSeverity[];
  source?: FindingSource[];
  status?: FindingStatus[];
  environment?: string[];
  owner?: string;
  repo?: string;
  minRiskScore?: number;
  maxRiskScore?: number;
  searchTerm?: string;
}

function computeCorrelationHash(repo: string, filePath: string, rule: string, lineStart: number): string {
  return createHash("sha256").update(`${repo}:${filePath}:${rule}:${lineStart}`).digest("hex").slice(0, 16);
}

const OWNERS: OwnerInfo[] = [
  {
    ownerId: "own-1",
    ownerName: "Alice Chen",
    ownerEmail: "alice.chen@securenexus.io",
    team: "Platform Security",
    escalationPath: ["Alice Chen", "VP Engineering", "CTO"],
    slackChannel: "#platform-security",
    oncallSchedule: "Mon-Fri 09:00-18:00 UTC",
  },
  {
    ownerId: "own-2",
    ownerName: "Bob Martinez",
    ownerEmail: "bob.martinez@securenexus.io",
    team: "Backend Engineering",
    escalationPath: ["Bob Martinez", "Tech Lead", "VP Engineering"],
    slackChannel: "#backend-eng",
    oncallSchedule: "24/7 rotation",
  },
  {
    ownerId: "own-3",
    ownerName: "Carol Davis",
    ownerEmail: "carol.davis@securenexus.io",
    team: "Frontend Engineering",
    escalationPath: ["Carol Davis", "Frontend Lead", "VP Engineering"],
    slackChannel: "#frontend-eng",
    oncallSchedule: "Mon-Fri 09:00-18:00 UTC",
  },
  {
    ownerId: "own-4",
    ownerName: "Dan Wilson",
    ownerEmail: "dan.wilson@securenexus.io",
    team: "DevOps / SRE",
    escalationPath: ["Dan Wilson", "SRE Lead", "VP Infrastructure"],
    slackChannel: "#devops-sre",
    oncallSchedule: "24/7 rotation",
  },
  {
    ownerId: "own-5",
    ownerName: "Eve Thompson",
    ownerEmail: "eve.thompson@securenexus.io",
    team: "Cloud Security",
    escalationPath: ["Eve Thompson", "Cloud Sec Lead", "CISO"],
    slackChannel: "#cloud-security",
    oncallSchedule: "Mon-Fri 06:00-22:00 UTC",
  },
];

const CATALOG_FINDINGS: FindingLineage[] = [
  {
    id: "fl-1",
    orgId: "__catalog__",
    title: "SQL injection in alert search endpoint",
    description:
      "User-controlled search parameter is concatenated directly into a SQL query in the alerts route handler. An attacker can inject arbitrary SQL to exfiltrate data or modify records.",
    severity: "critical",
    source: "sast",
    status: "open",
    confidence: "confirmed",
    riskScore: 0.95,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "server/routes/alerts.ts",
      lineStart: 142,
      lineEnd: 148,
      rule: "js/sql-injection",
      language: "typescript",
      commitSha: "a1b2c3d4e5f6",
    },
    buildContext: {
      pipelineName: "backend-ci",
      pipelineId: "pipe-1001",
      jobName: "sast-scan",
      jobId: "job-2001",
      buildNumber: 847,
      artifactHash: "sha256:abc123def456",
      registry: "ecr.aws/securenexus",
      imageTag: "backend:v2.14.3",
      triggeredAt: "2026-03-05T08:30:00Z",
    },
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "service",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-05T10:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[1],
    evidenceBundles: [
      {
        id: "ev-1",
        findingId: "fl-1",
        evidenceType: "code_snippet",
        title: "Vulnerable SQL query construction",
        content: "const query = `SELECT * FROM alerts WHERE title LIKE '%${searchTerm}%'`;",
        collectedAt: "2026-03-05T08:30:00Z",
        sourceUrl: "https://github.com/securenexus/backend/blob/main/server/routes/alerts.ts#L142",
      },
      {
        id: "ev-2",
        findingId: "fl-1",
        evidenceType: "scan_report",
        title: "CodeQL SAST scan result",
        content:
          "Finding: js/sql-injection\nSeverity: critical\nMessage: User-controlled data flows into a SQL query without sanitization.\nData flow: req.query.search -> searchTerm -> query template literal",
        collectedAt: "2026-03-05T08:32:00Z",
        sourceUrl: "https://github.com/securenexus/backend/security/code-scanning/1",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-1",
        findingId: "fl-1",
        title: "Use parameterized query",
        description: "Replace string concatenation with parameterized queries to prevent SQL injection.",
        patchDiff: `--- a/server/routes/alerts.ts
+++ b/server/routes/alerts.ts
@@ -142,1 +142,1 @@
-  const query = \`SELECT * FROM alerts WHERE title LIKE '%\${searchTerm}%'\`;
+  const query = db.prepare("SELECT * FROM alerts WHERE title LIKE ?").bind(\`%\${searchTerm}%\`);`,
        filePath: "server/routes/alerts.ts",
        language: "typescript",
        confidenceScore: 0.97,
        effort: "trivial",
        prReady: true,
        cweIds: ["CWE-89"],
        references: [
          "https://owasp.org/Top10/A03_2021-Injection/",
          "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
        ],
        createdAt: "2026-03-05T08:35:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/backend", "server/routes/alerts.ts", "js/sql-injection", 142),
    firstSeenAt: "2026-02-28T10:00:00Z",
    lastSeenAt: "2026-03-05T08:30:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-07T10:00:00Z",
    cveIds: [],
    cweIds: ["CWE-89"],
    mitreTactics: ["initial-access", "execution"],
  },
  {
    id: "fl-2",
    orgId: "__catalog__",
    title: "XSS via unsanitized HTML rendering in incident detail",
    description:
      "User-supplied description field is rendered with dangerouslySetInnerHTML without sanitization, enabling stored XSS attacks.",
    severity: "critical",
    source: "sast",
    status: "in_progress",
    confidence: "confirmed",
    riskScore: 0.92,
    sourceLocation: {
      repo: "securenexus/frontend",
      branch: "main",
      filePath: "client/src/pages/incident-detail.tsx",
      lineStart: 156,
      lineEnd: 158,
      rule: "js/xss",
      language: "tsx",
      commitSha: "f6e5d4c3b2a1",
    },
    buildContext: {
      pipelineName: "frontend-ci",
      pipelineId: "pipe-1002",
      jobName: "sast-scan",
      jobId: "job-2002",
      buildNumber: 412,
      artifactHash: "sha256:def456ghi789",
      registry: "ecr.aws/securenexus",
      imageTag: "frontend:v2.14.3",
      triggeredAt: "2026-03-05T09:00:00Z",
    },
    deployedAsset: {
      assetId: "asset-web-1",
      assetName: "securenexus-webapp",
      assetType: "container",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-05T10:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[2],
    evidenceBundles: [
      {
        id: "ev-3",
        findingId: "fl-2",
        evidenceType: "code_snippet",
        title: "Unsanitized HTML rendering",
        content: "<div dangerouslySetInnerHTML={{ __html: incident.description }} />",
        collectedAt: "2026-03-05T09:00:00Z",
        sourceUrl: "https://github.com/securenexus/frontend/blob/main/client/src/pages/incident-detail.tsx#L156",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-2",
        findingId: "fl-2",
        title: "Sanitize HTML with DOMPurify",
        description: "Use DOMPurify to sanitize user-supplied HTML before rendering to prevent XSS.",
        patchDiff: `--- a/client/src/pages/incident-detail.tsx
+++ b/client/src/pages/incident-detail.tsx
@@ -1,0 +1,1 @@
+import DOMPurify from 'dompurify';
@@ -156,1 +157,1 @@
-  <div dangerouslySetInnerHTML={{ __html: incident.description }} />
+  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(incident.description) }} />`,
        filePath: "client/src/pages/incident-detail.tsx",
        language: "tsx",
        confidenceScore: 0.95,
        effort: "trivial",
        prReady: true,
        cweIds: ["CWE-79"],
        references: ["https://owasp.org/Top10/A07_2021-Cross-Site_Scripting_XSS/"],
        createdAt: "2026-03-05T09:05:00Z",
      },
    ],
    correlationHash: computeCorrelationHash(
      "securenexus/frontend",
      "client/src/pages/incident-detail.tsx",
      "js/xss",
      156,
    ),
    firstSeenAt: "2026-03-01T14:00:00Z",
    lastSeenAt: "2026-03-05T09:00:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-08T14:00:00Z",
    cveIds: [],
    cweIds: ["CWE-79"],
    mitreTactics: ["initial-access", "execution"],
  },
  {
    id: "fl-3",
    orgId: "__catalog__",
    title: "Overprivileged IAM role on Lambda function",
    description: "Lambda execution role uses AdministratorAccess policy instead of least-privilege scoped permissions.",
    severity: "critical",
    source: "iac_scan",
    status: "open",
    confidence: "high",
    riskScore: 0.9,
    sourceLocation: {
      repo: "securenexus/infra",
      branch: "main",
      filePath: "k8s/iam-roles.yaml",
      lineStart: 22,
      lineEnd: 28,
      rule: "iam-role-overprivileged",
      language: "yaml",
      commitSha: "1a2b3c4d5e6f",
    },
    buildContext: {
      pipelineName: "infra-ci",
      pipelineId: "pipe-1003",
      jobName: "iac-scan",
      jobId: "job-2003",
      buildNumber: 205,
      artifactHash: "sha256:iac123abc456",
      registry: "N/A",
      imageTag: "N/A",
      triggeredAt: "2026-03-04T16:00:00Z",
    },
    deployedAsset: {
      assetId: "asset-lambda-1",
      assetName: "connector-sync-fn",
      assetType: "function",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-lambdas",
      lastDeployedAt: "2026-03-04T17:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[3],
    evidenceBundles: [
      {
        id: "ev-4",
        findingId: "fl-3",
        evidenceType: "config_snapshot",
        title: "IAM role policy attachment",
        content: "PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess\nAttachedTo: connector-sync-fn-role",
        collectedAt: "2026-03-04T16:00:00Z",
        sourceUrl: "https://github.com/securenexus/infra/blob/main/k8s/iam-roles.yaml#L22",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-3",
        findingId: "fl-3",
        title: "Scope IAM to minimum permissions",
        description:
          "Replace AdministratorAccess with a custom policy granting only logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, and specific S3/DynamoDB actions.",
        patchDiff: `--- a/k8s/iam-roles.yaml
+++ b/k8s/iam-roles.yaml
@@ -22,1 +22,8 @@
-  PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess
+  PolicyDocument:
+    Statement:
+      - Effect: Allow
+        Action:
+          - logs:CreateLogGroup
+          - logs:CreateLogStream
+          - logs:PutLogEvents
+        Resource: "arn:aws:logs:*:*:*"`,
        filePath: "k8s/iam-roles.yaml",
        language: "yaml",
        confidenceScore: 0.88,
        effort: "medium",
        prReady: true,
        cweIds: ["CWE-250"],
        references: ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        createdAt: "2026-03-04T16:10:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/infra", "k8s/iam-roles.yaml", "iam-role-overprivileged", 22),
    firstSeenAt: "2026-02-20T08:00:00Z",
    lastSeenAt: "2026-03-04T16:00:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-06T08:00:00Z",
    cveIds: [],
    cweIds: ["CWE-250"],
    mitreTactics: ["privilege-escalation", "lateral-movement"],
  },
  {
    id: "fl-4",
    orgId: "__catalog__",
    title: "Vulnerable dependency: lodash < 4.17.21 (CVE-2021-23337)",
    description:
      "The project depends on lodash 4.17.15 which is vulnerable to command injection via the template function.",
    severity: "high",
    source: "sca",
    status: "open",
    confidence: "confirmed",
    riskScore: 0.78,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "package.json",
      lineStart: 45,
      lineEnd: 45,
      rule: "npm-audit-high",
      language: "json",
      commitSha: "a1b2c3d4e5f6",
    },
    buildContext: {
      pipelineName: "backend-ci",
      pipelineId: "pipe-1001",
      jobName: "sca-scan",
      jobId: "job-2004",
      buildNumber: 847,
      artifactHash: "sha256:abc123def456",
      registry: "ecr.aws/securenexus",
      imageTag: "backend:v2.14.3",
      triggeredAt: "2026-03-05T08:30:00Z",
    },
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "service",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-05T10:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[1],
    evidenceBundles: [
      {
        id: "ev-5",
        findingId: "fl-4",
        evidenceType: "scan_report",
        title: "npm audit report",
        content:
          "lodash  <4.17.21\nSeverity: high\nCommand Injection - https://github.com/advisories/GHSA-35jh-r3h4-6jhm\nfix: npm audit fix --force",
        collectedAt: "2026-03-05T08:31:00Z",
        sourceUrl: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-4",
        findingId: "fl-4",
        title: "Upgrade lodash to 4.17.21",
        description: "Update lodash to the patched version that fixes the command injection vulnerability.",
        patchDiff: `--- a/package.json
+++ b/package.json
@@ -45,1 +45,1 @@
-    "lodash": "^4.17.15",
+    "lodash": "^4.17.21",`,
        filePath: "package.json",
        language: "json",
        confidenceScore: 0.99,
        effort: "trivial",
        prReady: true,
        cweIds: ["CWE-77"],
        references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
        createdAt: "2026-03-05T08:35:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/backend", "package.json", "npm-audit-high", 45),
    firstSeenAt: "2026-01-15T10:00:00Z",
    lastSeenAt: "2026-03-05T08:30:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-12T10:00:00Z",
    cveIds: ["CVE-2021-23337"],
    cweIds: ["CWE-77"],
    mitreTactics: ["execution"],
  },
  {
    id: "fl-5",
    orgId: "__catalog__",
    title: "Container image running as root",
    description: "The production Docker image runs processes as root user, violating least-privilege principle.",
    severity: "high",
    source: "container_scan",
    status: "open",
    confidence: "confirmed",
    riskScore: 0.75,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "Dockerfile",
      lineStart: 1,
      lineEnd: 25,
      rule: "container-root-user",
      language: "dockerfile",
      commitSha: "a1b2c3d4e5f6",
    },
    buildContext: {
      pipelineName: "backend-ci",
      pipelineId: "pipe-1001",
      jobName: "container-scan",
      jobId: "job-2005",
      buildNumber: 847,
      artifactHash: "sha256:abc123def456",
      registry: "ecr.aws/securenexus",
      imageTag: "backend:v2.14.3",
      triggeredAt: "2026-03-05T08:30:00Z",
    },
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "container",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-05T10:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[3],
    evidenceBundles: [
      {
        id: "ev-6",
        findingId: "fl-5",
        evidenceType: "scan_report",
        title: "Trivy container scan",
        content: "WARN: Running as root user detected.\nRecommendation: Add USER directive to Dockerfile.",
        collectedAt: "2026-03-05T08:33:00Z",
        sourceUrl: "",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-5",
        findingId: "fl-5",
        title: "Add non-root USER directive",
        description: "Add a non-root user to the Dockerfile and switch to it before the CMD instruction.",
        patchDiff: `--- a/Dockerfile
+++ b/Dockerfile
@@ -20,0 +20,3 @@
+RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
+USER appuser
+`,
        filePath: "Dockerfile",
        language: "dockerfile",
        confidenceScore: 0.93,
        effort: "small",
        prReady: true,
        cweIds: ["CWE-250"],
        references: ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"],
        createdAt: "2026-03-05T08:36:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/backend", "Dockerfile", "container-root-user", 1),
    firstSeenAt: "2026-02-01T12:00:00Z",
    lastSeenAt: "2026-03-05T08:30:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-15T12:00:00Z",
    cveIds: [],
    cweIds: ["CWE-250"],
    mitreTactics: ["privilege-escalation"],
  },
  {
    id: "fl-6",
    orgId: "__catalog__",
    title: "Hardcoded AWS secret key in configuration",
    description: "An AWS secret access key is hardcoded in a configuration file committed to the repository.",
    severity: "critical",
    source: "secret_scan",
    status: "remediated",
    confidence: "confirmed",
    riskScore: 0.98,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "server/config.ts",
      lineStart: 32,
      lineEnd: 32,
      rule: "aws-secret-key",
      language: "typescript",
      commitSha: "c3d4e5f6a1b2",
    },
    buildContext: {
      pipelineName: "backend-ci",
      pipelineId: "pipe-1001",
      jobName: "secret-scan",
      jobId: "job-2006",
      buildNumber: 840,
      artifactHash: "sha256:old789abc123",
      registry: "ecr.aws/securenexus",
      imageTag: "backend:v2.14.0",
      triggeredAt: "2026-03-01T14:00:00Z",
    },
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "service",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-01T15:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[0],
    evidenceBundles: [
      {
        id: "ev-7",
        findingId: "fl-6",
        evidenceType: "code_snippet",
        title: "Hardcoded secret in config",
        content: 'const AWS_SECRET = "AKIA••••••••••••••••";',
        collectedAt: "2026-03-01T14:00:00Z",
        sourceUrl: "",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-6",
        findingId: "fl-6",
        title: "Move secret to AWS Secrets Manager",
        description: "Remove the hardcoded secret and fetch it from AWS Secrets Manager at runtime.",
        patchDiff: `--- a/server/config.ts
+++ b/server/config.ts
@@ -32,1 +32,1 @@
-const AWS_SECRET = "AKIA••••••••••••••••";
+const AWS_SECRET = await getSecretFromSecretsManager("securenexus/aws-secret-key");`,
        filePath: "server/config.ts",
        language: "typescript",
        confidenceScore: 0.96,
        effort: "small",
        prReady: true,
        cweIds: ["CWE-798"],
        references: ["https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"],
        createdAt: "2026-03-01T14:05:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/backend", "server/config.ts", "aws-secret-key", 32),
    firstSeenAt: "2026-03-01T14:00:00Z",
    lastSeenAt: "2026-03-01T14:00:00Z",
    resolvedAt: "2026-03-02T09:00:00Z",
    slaDeadline: "2026-03-02T14:00:00Z",
    cveIds: [],
    cweIds: ["CWE-798"],
    mitreTactics: ["credential-access"],
  },
  {
    id: "fl-7",
    orgId: "__catalog__",
    title: "Missing rate limiting on authentication endpoints",
    description: "Login and password reset endpoints have no rate limiting, enabling brute-force credential attacks.",
    severity: "high",
    source: "dast",
    status: "open",
    confidence: "high",
    riskScore: 0.8,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "server/auth.ts",
      lineStart: 30,
      lineEnd: 35,
      rule: "brute-force-possible",
      language: "typescript",
      commitSha: "a1b2c3d4e5f6",
    },
    buildContext: {
      pipelineName: "security-scan",
      pipelineId: "pipe-1004",
      jobName: "dast-scan",
      jobId: "job-2007",
      buildNumber: 98,
      artifactHash: "N/A",
      registry: "N/A",
      imageTag: "N/A",
      triggeredAt: "2026-03-05T02:00:00Z",
    },
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "service",
      environment: "staging",
      region: "us-east-1",
      namespace: "securenexus-staging",
      lastDeployedAt: "2026-03-04T22:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[0],
    evidenceBundles: [
      {
        id: "ev-8",
        findingId: "fl-7",
        evidenceType: "network_capture",
        title: "Brute force test - 1000 attempts in 60s",
        content:
          "POST /api/auth/login - 1000 requests in 60 seconds\nAll returned 401 (no lockout)\nNo rate limiting header observed",
        collectedAt: "2026-03-05T02:05:00Z",
        sourceUrl: "",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-7",
        findingId: "fl-7",
        title: "Add auth-specific rate limiter",
        description:
          "Apply a dedicated rate limiter (10 attempts per 5 minutes) to login and password reset endpoints.",
        patchDiff: `--- a/server/auth.ts
+++ b/server/auth.ts
@@ -30,1 +30,6 @@
-app.post("/api/auth/login", async (req, res) => {
+const authLimiter = rateLimit({
+  windowMs: 5 * 60 * 1000,
+  max: 10,
+  message: { message: "Too many login attempts" },
+});
+app.post("/api/auth/login", authLimiter, async (req, res) => {`,
        filePath: "server/auth.ts",
        language: "typescript",
        confidenceScore: 0.91,
        effort: "small",
        prReady: true,
        cweIds: ["CWE-307"],
        references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        createdAt: "2026-03-05T02:10:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/backend", "server/auth.ts", "brute-force-possible", 30),
    firstSeenAt: "2026-02-25T02:00:00Z",
    lastSeenAt: "2026-03-05T02:00:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-11T02:00:00Z",
    cveIds: [],
    cweIds: ["CWE-307"],
    mitreTactics: ["credential-access", "initial-access"],
  },
  {
    id: "fl-8",
    orgId: "__catalog__",
    title: "S3 bucket public read access enabled",
    description:
      "The report-exports S3 bucket has public read access enabled, potentially exposing sensitive compliance reports.",
    severity: "high",
    source: "cloud_config",
    status: "open",
    confidence: "confirmed",
    riskScore: 0.85,
    sourceLocation: {
      repo: "securenexus/infra",
      branch: "main",
      filePath: "terraform/s3.tf",
      lineStart: 18,
      lineEnd: 22,
      rule: "s3-bucket-public-read",
      language: "hcl",
      commitSha: "7f8g9h0i1j2k",
    },
    buildContext: null,
    deployedAsset: {
      assetId: "asset-s3-1",
      assetName: "securenexus-report-exports",
      assetType: "bucket",
      environment: "production",
      region: "us-east-1",
      namespace: "N/A",
      lastDeployedAt: "2026-02-15T08:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[4],
    evidenceBundles: [
      {
        id: "ev-9",
        findingId: "fl-8",
        evidenceType: "config_snapshot",
        title: "S3 bucket policy",
        content:
          '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::securenexus-report-exports/*"}',
        collectedAt: "2026-03-04T20:00:00Z",
        sourceUrl: "",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-8",
        findingId: "fl-8",
        title: "Remove public access and enable block public access",
        description: "Delete the permissive bucket policy and enable S3 Block Public Access settings.",
        patchDiff: `--- a/terraform/s3.tf
+++ b/terraform/s3.tf
@@ -18,5 +18,9 @@
-  acl    = "public-read"
-  policy = data.aws_iam_policy_document.public_read.json
+  acl    = "private"
+
+  block_public_access {
+    block_public_acls       = true
+    block_public_policy     = true
+    ignore_public_acls      = true
+    restrict_public_buckets = true
+  }`,
        filePath: "terraform/s3.tf",
        language: "hcl",
        confidenceScore: 0.94,
        effort: "small",
        prReady: true,
        cweIds: ["CWE-284"],
        references: ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        createdAt: "2026-03-04T20:10:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/infra", "terraform/s3.tf", "s3-bucket-public-read", 18),
    firstSeenAt: "2026-02-15T10:00:00Z",
    lastSeenAt: "2026-03-04T20:00:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-09T10:00:00Z",
    cveIds: [],
    cweIds: ["CWE-284"],
    mitreTactics: ["collection", "exfiltration"],
  },
  {
    id: "fl-9",
    orgId: "__catalog__",
    title: "Missing CSRF token validation on state-changing endpoints",
    description: "POST/PUT/DELETE endpoints lack CSRF token validation, enabling cross-site request forgery attacks.",
    severity: "medium",
    source: "pentest",
    status: "suppressed",
    confidence: "medium",
    riskScore: 0.55,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "server/routes/incidents.ts",
      lineStart: 45,
      lineEnd: 52,
      rule: "csrf-missing",
      language: "typescript",
      commitSha: "a1b2c3d4e5f6",
    },
    buildContext: null,
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "service",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-05T10:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[0],
    evidenceBundles: [],
    remediationSuggestions: [
      {
        id: "rem-9",
        findingId: "fl-9",
        title: "Add CSRF middleware to state-changing routes",
        description: "Add csrfProtection middleware before state-changing route handlers.",
        patchDiff: `--- a/server/routes/incidents.ts
+++ b/server/routes/incidents.ts
@@ -45,1 +45,1 @@
-  app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), async (req, res) => {
+  app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), csrfProtection, async (req, res) => {`,
        filePath: "server/routes/incidents.ts",
        language: "typescript",
        confidenceScore: 0.82,
        effort: "medium",
        prReady: false,
        cweIds: ["CWE-352"],
        references: ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        createdAt: "2026-03-03T11:00:00Z",
      },
    ],
    correlationHash: computeCorrelationHash("securenexus/backend", "server/routes/incidents.ts", "csrf-missing", 45),
    firstSeenAt: "2026-02-10T11:00:00Z",
    lastSeenAt: "2026-03-03T11:00:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-20T11:00:00Z",
    cveIds: [],
    cweIds: ["CWE-352"],
    mitreTactics: ["initial-access"],
  },
  {
    id: "fl-10",
    orgId: "__catalog__",
    title: "Runtime anomaly: excessive outbound DNS queries from API pod",
    description:
      "Kubernetes pod securenexus-api-7b8c9d is generating 5x the baseline outbound DNS queries, possible data exfiltration via DNS tunneling.",
    severity: "medium",
    source: "runtime",
    status: "open",
    confidence: "low",
    riskScore: 0.6,
    sourceLocation: {
      repo: "securenexus/backend",
      branch: "main",
      filePath: "server/connectors/dns-resolver.ts",
      lineStart: 1,
      lineEnd: 50,
      rule: "runtime-dns-anomaly",
      language: "typescript",
      commitSha: "a1b2c3d4e5f6",
    },
    buildContext: {
      pipelineName: "backend-ci",
      pipelineId: "pipe-1001",
      jobName: "build",
      jobId: "job-2010",
      buildNumber: 847,
      artifactHash: "sha256:abc123def456",
      registry: "ecr.aws/securenexus",
      imageTag: "backend:v2.14.3",
      triggeredAt: "2026-03-05T08:30:00Z",
    },
    deployedAsset: {
      assetId: "asset-api-1",
      assetName: "securenexus-api",
      assetType: "container",
      environment: "production",
      region: "us-east-1",
      namespace: "securenexus-prod",
      lastDeployedAt: "2026-03-05T10:00:00Z",
      infraProvider: "aws",
    },
    owner: OWNERS[3],
    evidenceBundles: [
      {
        id: "ev-10",
        findingId: "fl-10",
        evidenceType: "log_trace",
        title: "DNS query spike log",
        content:
          "2026-03-05T14:00:00Z pod/securenexus-api-7b8c9d DNS queries: 12,340 in 1hr (baseline: 2,500)\nTop queried domains: *.data-exfil-test.example.com",
        collectedAt: "2026-03-05T15:00:00Z",
        sourceUrl: "",
      },
    ],
    remediationSuggestions: [
      {
        id: "rem-10",
        findingId: "fl-10",
        title: "Restrict outbound DNS with NetworkPolicy",
        description: "Apply a Kubernetes NetworkPolicy to restrict DNS queries to the cluster DNS service only.",
        patchDiff: `--- /dev/null
+++ b/k8s/network-policy-dns.yaml
@@ -0,0 +1,15 @@
+apiVersion: networking.k8s.io/v1
+kind: NetworkPolicy
+metadata:
+  name: restrict-dns-egress
+  namespace: securenexus-prod
+spec:
+  podSelector:
+    matchLabels:
+      app: securenexus-api
+  policyTypes:
+    - Egress
+  egress:
+    - to:
+        - namespaceSelector: {}
+      ports:
+        - port: 53
+          protocol: UDP`,
        filePath: "k8s/network-policy-dns.yaml",
        language: "yaml",
        confidenceScore: 0.65,
        effort: "medium",
        prReady: false,
        cweIds: ["CWE-200"],
        references: ["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
        createdAt: "2026-03-05T15:10:00Z",
      },
    ],
    correlationHash: computeCorrelationHash(
      "securenexus/backend",
      "server/connectors/dns-resolver.ts",
      "runtime-dns-anomaly",
      1,
    ),
    firstSeenAt: "2026-03-05T14:00:00Z",
    lastSeenAt: "2026-03-05T15:00:00Z",
    resolvedAt: null,
    slaDeadline: "2026-03-12T14:00:00Z",
    cveIds: [],
    cweIds: ["CWE-200"],
    mitreTactics: ["exfiltration", "command-and-control"],
  },
];

const orgFindingStores = new Map<string, Map<string, FindingLineage>>();

function getOrgStore(orgId: string): Map<string, FindingLineage> {
  let store = orgFindingStores.get(orgId);
  if (!store) {
    store = new Map();
    orgFindingStores.set(orgId, store);
  }
  return store;
}

export function getFindings(orgId?: string): FindingLineage[] {
  const orgStore = orgId ? getOrgStore(orgId) : new Map<string, FindingLineage>();
  const merged = [...CATALOG_FINDINGS, ...Array.from(orgStore.values())];
  return merged.sort((a, b) => b.riskScore - a.riskScore);
}

export function getFindingById(findingId: string, orgId?: string): FindingLineage | null {
  if (orgId) {
    const orgStore = getOrgStore(orgId);
    const orgFinding = orgStore.get(findingId);
    if (orgFinding) return orgFinding;
  }
  return CATALOG_FINDINGS.find((f) => f.id === findingId) || null;
}

export function filterFindings(filter: LineageFilter, orgId?: string): FindingLineage[] {
  let results = getFindings(orgId);

  if (filter.severity && filter.severity.length > 0) {
    results = results.filter((f) => filter.severity!.includes(f.severity));
  }
  if (filter.source && filter.source.length > 0) {
    results = results.filter((f) => filter.source!.includes(f.source));
  }
  if (filter.status && filter.status.length > 0) {
    results = results.filter((f) => filter.status!.includes(f.status));
  }
  if (filter.environment && filter.environment.length > 0) {
    results = results.filter((f) => filter.environment!.includes(f.deployedAsset.environment));
  }
  if (filter.owner) {
    const ownerLower = filter.owner.toLowerCase();
    results = results.filter(
      (f) => f.owner.ownerName.toLowerCase().includes(ownerLower) || f.owner.team.toLowerCase().includes(ownerLower),
    );
  }
  if (filter.repo) {
    const repoLower = filter.repo.toLowerCase();
    results = results.filter((f) => f.sourceLocation.repo.toLowerCase().includes(repoLower));
  }
  if (filter.minRiskScore !== undefined) {
    results = results.filter((f) => f.riskScore >= filter.minRiskScore!);
  }
  if (filter.maxRiskScore !== undefined) {
    results = results.filter((f) => f.riskScore <= filter.maxRiskScore!);
  }
  if (filter.searchTerm) {
    const term = filter.searchTerm.toLowerCase();
    results = results.filter(
      (f) =>
        f.title.toLowerCase().includes(term) ||
        f.description.toLowerCase().includes(term) ||
        f.sourceLocation.filePath.toLowerCase().includes(term) ||
        f.sourceLocation.rule.toLowerCase().includes(term) ||
        f.cweIds.some((c) => c.toLowerCase().includes(term)) ||
        f.cveIds.some((c) => c.toLowerCase().includes(term)),
    );
  }

  return results;
}

export function getLineageStats(orgId?: string): LineageStats {
  const findings = getFindings(orgId);

  const bySeverity: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const bySource: Record<string, number> = {};
  const byEnvironment: Record<string, number> = {};
  const ownerCounts: Record<string, { owner: OwnerInfo; count: number }> = {};

  let openCount = 0;
  let remediatedCount = 0;
  let suppressedCount = 0;
  let totalRemediationMs = 0;
  let remediatedWithTime = 0;
  let patchReady = 0;
  let totalConfidence = 0;

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    bySource[f.source] = (bySource[f.source] || 0) + 1;
    byEnvironment[f.deployedAsset.environment] = (byEnvironment[f.deployedAsset.environment] || 0) + 1;

    if (f.status === "open" || f.status === "in_progress") openCount++;
    if (f.status === "remediated") remediatedCount++;
    if (f.status === "suppressed") suppressedCount++;

    if (f.resolvedAt) {
      const delta = new Date(f.resolvedAt).getTime() - new Date(f.firstSeenAt).getTime();
      totalRemediationMs += delta;
      remediatedWithTime++;
    }

    for (const s of f.remediationSuggestions) {
      if (s.prReady) patchReady++;
      totalConfidence += s.confidenceScore;
    }

    const key = f.owner.ownerId;
    if (!ownerCounts[key]) {
      ownerCounts[key] = { owner: f.owner, count: 0 };
    }
    ownerCounts[key].count++;
  }

  const now = new Date();
  let slaBreaches = 0;
  for (const f of findings) {
    if (f.status !== "remediated" && f.status !== "false_positive" && new Date(f.slaDeadline) < now) {
      slaBreaches++;
    }
  }

  const avgMs = remediatedWithTime > 0 ? totalRemediationMs / remediatedWithTime : 0;
  const avgHours = Math.round(avgMs / (1000 * 60 * 60));
  const meanTimeToRemediate = avgHours >= 24 ? `${Math.round(avgHours / 24)}d` : `${avgHours}h`;

  const totalSuggestions = findings.reduce((s, f) => s + f.remediationSuggestions.length, 0);
  const avgConfidenceScore = totalSuggestions > 0 ? Math.round((totalConfidence / totalSuggestions) * 100) / 100 : 0;

  const topOwners = Object.values(ownerCounts)
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map((o) => ({ owner: o.owner, findingCount: o.count }));

  return {
    totalFindings: findings.length,
    openFindings: openCount,
    remediatedFindings: remediatedCount,
    suppressedFindings: suppressedCount,
    bySeverity,
    bySource,
    byEnvironment,
    meanTimeToRemediate,
    slaBreaches,
    patchReadySuggestions: patchReady,
    avgConfidenceScore,
    topOwners,
  };
}

export function ingestFinding(
  orgId: string,
  data: Omit<FindingLineage, "id" | "orgId" | "correlationHash">,
): FindingLineage {
  const store = getOrgStore(orgId);
  const correlationHash = computeCorrelationHash(
    data.sourceLocation.repo,
    data.sourceLocation.filePath,
    data.sourceLocation.rule,
    data.sourceLocation.lineStart,
  );

  for (const existing of Array.from(store.values())) {
    if (existing.correlationHash === correlationHash) {
      existing.lastSeenAt = data.lastSeenAt || new Date().toISOString();
      existing.riskScore = data.riskScore;
      existing.status = data.status;
      if (data.evidenceBundles.length > 0) {
        existing.evidenceBundles = [...existing.evidenceBundles, ...data.evidenceBundles];
      }
      if (data.remediationSuggestions.length > 0) {
        existing.remediationSuggestions = [...existing.remediationSuggestions, ...data.remediationSuggestions];
      }
      return existing;
    }
  }

  const finding: FindingLineage = {
    ...data,
    id: `fl-${randomUUID().slice(0, 8)}`,
    orgId,
    correlationHash,
  };
  store.set(finding.id, finding);
  return finding;
}

export function updateFindingStatus(findingId: string, status: FindingStatus, orgId?: string): FindingLineage | null {
  if (orgId) {
    const store = getOrgStore(orgId);
    const existing = store.get(findingId);
    if (existing) {
      existing.status = status;
      if (status === "remediated") {
        existing.resolvedAt = new Date().toISOString();
      }
      return existing;
    }
    const catalogFinding = CATALOG_FINDINGS.find((f) => f.id === findingId);
    if (catalogFinding) {
      const cloned: FindingLineage = {
        ...catalogFinding,
        orgId,
        owner: { ...catalogFinding.owner },
        sourceLocation: { ...catalogFinding.sourceLocation },
        deployedAsset: { ...catalogFinding.deployedAsset },
        buildContext: catalogFinding.buildContext ? { ...catalogFinding.buildContext } : null,
        evidenceBundles: catalogFinding.evidenceBundles.map((e) => ({ ...e })),
        remediationSuggestions: catalogFinding.remediationSuggestions.map((r) => ({ ...r })),
        cveIds: [...catalogFinding.cveIds],
        cweIds: [...catalogFinding.cweIds],
        mitreTactics: [...catalogFinding.mitreTactics],
        status,
        resolvedAt: status === "remediated" ? new Date().toISOString() : catalogFinding.resolvedAt,
      };
      store.set(cloned.id, cloned);
      return cloned;
    }
  }
  return null;
}

export function getOwners(): OwnerInfo[] {
  return [...OWNERS];
}

export function getEvidenceForFinding(findingId: string, orgId?: string): EvidenceBundle[] {
  const finding = getFindingById(findingId, orgId);
  if (!finding) return [];
  return finding.evidenceBundles;
}

export function getRemediationsForFinding(findingId: string, orgId?: string): RemediationSuggestion[] {
  const finding = getFindingById(findingId, orgId);
  if (!finding) return [];
  return finding.remediationSuggestions;
}
