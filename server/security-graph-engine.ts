export interface SecurityAsset {
  id: string;
  orgId: string | null;
  name: string;
  type: AssetType;
  subType: string;
  environment: "production" | "staging" | "development" | "shared";
  riskScore: number;
  metadata: Record<string, unknown>;
  tags: string[];
  owner: string | null;
  lastScannedAt: string | null;
  createdAt: string;
}

export type AssetType = "code" | "cloud" | "identity" | "data" | "network" | "compute" | "container";

export interface SecurityRelationship {
  id: string;
  sourceId: string;
  targetId: string;
  relationship: RelationshipType;
  weight: number;
  metadata: Record<string, unknown>;
  bidirectional: boolean;
}

export type RelationshipType =
  | "accesses"
  | "authenticates_with"
  | "contains"
  | "deploys_to"
  | "exposes"
  | "has_permission"
  | "reads_from"
  | "writes_to"
  | "connects_to"
  | "inherits_from"
  | "manages"
  | "depends_on"
  | "runs_on";

export interface RankedAttackPath {
  id: string;
  name: string;
  description: string;
  nodes: SecurityAsset[];
  edges: SecurityRelationship[];
  riskScore: number;
  blastRadius: number;
  exploitability: number;
  hopCount: number;
  entryPoint: SecurityAsset;
  target: SecurityAsset;
  mitigations: string[];
  mitreTactics: string[];
}

export interface SecurityGraphData {
  assets: SecurityAsset[];
  relationships: SecurityRelationship[];
  attackPaths: RankedAttackPath[];
  stats: GraphStats;
}

export interface GraphStats {
  totalAssets: number;
  totalRelationships: number;
  criticalPaths: number;
  highRiskAssets: number;
  avgRiskScore: number;
  byType: Record<string, number>;
  byEnvironment: Record<string, number>;
  internetExposed: number;
  overPrivileged: number;
}

const ASSET_CATALOG: Omit<SecurityAsset, "orgId">[] = [
  {
    id: "asset-repo-backend",
    name: "securenexus-api",
    type: "code",
    subType: "repository",
    environment: "production",
    riskScore: 0.35,
    metadata: {
      language: "TypeScript",
      branch: "main",
      commits: 847,
      contributors: 4,
      lastCommit: "2026-03-05T18:30:00Z",
      hasSecrets: false,
      ciEnabled: true,
    },
    tags: ["backend", "api", "nodejs"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-06-15T10:00:00Z",
  },
  {
    id: "asset-repo-frontend",
    name: "securenexus-web",
    type: "code",
    subType: "repository",
    environment: "production",
    riskScore: 0.25,
    metadata: {
      language: "TypeScript/React",
      branch: "main",
      commits: 1203,
      contributors: 3,
      lastCommit: "2026-03-06T01:45:00Z",
      hasSecrets: false,
      ciEnabled: true,
    },
    tags: ["frontend", "react", "spa"],
    owner: "frontend-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-06-15T10:00:00Z",
  },
  {
    id: "asset-repo-infra",
    name: "securenexus-infra",
    type: "code",
    subType: "iac_repository",
    environment: "shared",
    riskScore: 0.55,
    metadata: {
      language: "Terraform/YAML",
      branch: "main",
      commits: 312,
      hasSecrets: false,
      ciEnabled: true,
      containsIAMPolicies: true,
    },
    tags: ["infrastructure", "terraform", "k8s"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T01:30:00Z",
    createdAt: "2025-07-01T08:00:00Z",
  },
  {
    id: "asset-eks-cluster",
    name: "securenexus-eks-prod",
    type: "compute",
    subType: "kubernetes_cluster",
    environment: "production",
    riskScore: 0.45,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      version: "1.29",
      nodeCount: 6,
      namespaces: ["production", "staging", "monitoring"],
      publicEndpoint: false,
    },
    tags: ["kubernetes", "eks", "container-orchestration"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T03:00:00Z",
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    id: "asset-rds-primary",
    name: "securenexus-db-prod",
    type: "data",
    subType: "rds_postgresql",
    environment: "production",
    riskScore: 0.7,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      engine: "PostgreSQL 15",
      multiAz: true,
      encrypted: true,
      publiclyAccessible: false,
      backupRetention: 30,
      dataClassification: "confidential",
      recordCount: 2450000,
    },
    tags: ["database", "postgresql", "primary"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:30:00Z",
    createdAt: "2025-06-20T09:00:00Z",
  },
  {
    id: "asset-rds-replica",
    name: "securenexus-db-replica",
    type: "data",
    subType: "rds_postgresql",
    environment: "production",
    riskScore: 0.55,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      engine: "PostgreSQL 15",
      readReplica: true,
      encrypted: true,
      publiclyAccessible: false,
    },
    tags: ["database", "postgresql", "replica"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:30:00Z",
    createdAt: "2025-09-01T11:00:00Z",
  },
  {
    id: "asset-s3-evidence",
    name: "securenexus-evidence-prod",
    type: "data",
    subType: "s3_bucket",
    environment: "production",
    riskScore: 0.6,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      versioning: true,
      encryption: "AES-256",
      publicAccess: false,
      objectCount: 48200,
      dataClassification: "restricted",
      lifecycleRules: true,
    },
    tags: ["storage", "evidence", "compliance"],
    owner: "security-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-07-15T10:00:00Z",
  },
  {
    id: "asset-s3-logs",
    name: "securenexus-audit-logs",
    type: "data",
    subType: "s3_bucket",
    environment: "production",
    riskScore: 0.4,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      versioning: true,
      encryption: "AES-256",
      publicAccess: false,
      objectCount: 890000,
      retentionDays: 365,
      dataClassification: "internal",
    },
    tags: ["storage", "audit", "logs"],
    owner: "security-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-07-15T10:00:00Z",
  },
  {
    id: "asset-ecr-registry",
    name: "securenexus-ecr",
    type: "container",
    subType: "container_registry",
    environment: "shared",
    riskScore: 0.5,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      imageCount: 34,
      scanOnPush: true,
      immutableTags: true,
      criticalVulns: 0,
      highVulns: 2,
    },
    tags: ["container", "registry", "docker"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T03:15:00Z",
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    id: "asset-alb-public",
    name: "securenexus-alb-prod",
    type: "network",
    subType: "load_balancer",
    environment: "production",
    riskScore: 0.5,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      scheme: "internet-facing",
      protocol: "HTTPS",
      wafEnabled: true,
      sslPolicy: "TLS1.3",
      targetGroups: 2,
      internetExposed: true,
    },
    tags: ["network", "load-balancer", "internet-facing"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T03:00:00Z",
    createdAt: "2025-08-15T09:00:00Z",
  },
  {
    id: "asset-vpc-prod",
    name: "securenexus-vpc-prod",
    type: "network",
    subType: "vpc",
    environment: "production",
    riskScore: 0.3,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      cidr: "10.0.0.0/16",
      subnets: 6,
      natGateways: 2,
      flowLogsEnabled: true,
      privateSubnetsOnly: false,
    },
    tags: ["network", "vpc", "production"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T03:00:00Z",
    createdAt: "2025-06-15T08:00:00Z",
  },
  {
    id: "asset-cloudfront-cdn",
    name: "securenexus-cdn",
    type: "network",
    subType: "cdn",
    environment: "production",
    riskScore: 0.35,
    metadata: {
      provider: "AWS",
      distribution: "E1ABCDEF12345",
      origins: 2,
      wafAssociated: true,
      sslCertificate: "ACM",
      priceClass: "PriceClass_100",
      internetExposed: true,
    },
    tags: ["network", "cdn", "cloudfront"],
    owner: "frontend-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-09-01T10:00:00Z",
  },
  {
    id: "asset-cognito-pool",
    name: "securenexus-auth-pool",
    type: "identity",
    subType: "cognito_user_pool",
    environment: "production",
    riskScore: 0.65,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      userCount: 2840,
      mfaEnabled: true,
      oauthProviders: ["Google", "GitHub"],
      passwordPolicy: "strong",
      advancedSecurity: true,
    },
    tags: ["identity", "auth", "cognito"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-07-01T10:00:00Z",
  },
  {
    id: "asset-iam-deploy-role",
    name: "securenexus-deploy-role",
    type: "identity",
    subType: "iam_role",
    environment: "shared",
    riskScore: 0.75,
    metadata: {
      provider: "AWS",
      policies: ["AmazonEKSClusterPolicy", "AmazonECRFullAccess", "SecretsManagerReadWrite"],
      assumableBy: ["github-actions", "codebuild"],
      lastUsed: "2026-03-06T04:00:00Z",
      isOverPrivileged: true,
    },
    tags: ["identity", "iam", "deployment"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-08-01T10:00:00Z",
  },
  {
    id: "asset-iam-app-role",
    name: "securenexus-app-role",
    type: "identity",
    subType: "iam_role",
    environment: "production",
    riskScore: 0.5,
    metadata: {
      provider: "AWS",
      policies: ["AmazonS3ReadOnlyAccess", "AmazonRDSDataFullAccess", "SecretsManagerReadWrite"],
      assumableBy: ["eks-service-account"],
      lastUsed: "2026-03-06T04:30:00Z",
      isOverPrivileged: false,
    },
    tags: ["identity", "iam", "application"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    id: "asset-secrets-manager",
    name: "securenexus-secrets",
    type: "data",
    subType: "secrets_manager",
    environment: "production",
    riskScore: 0.8,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      secretCount: 12,
      rotationEnabled: true,
      kmsEncrypted: true,
      dataClassification: "secret",
      lastRotated: "2026-02-28T00:00:00Z",
    },
    tags: ["secrets", "credentials", "kms"],
    owner: "security-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-07-01T10:00:00Z",
  },
  {
    id: "asset-lambda-processor",
    name: "securenexus-event-processor",
    type: "compute",
    subType: "lambda_function",
    environment: "production",
    riskScore: 0.4,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      runtime: "nodejs20.x",
      memoryMB: 512,
      timeoutSec: 30,
      vpcAttached: true,
      triggers: ["SQS", "EventBridge"],
      lastInvoked: "2026-03-06T04:35:00Z",
    },
    tags: ["compute", "serverless", "event-processing"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-10-15T10:00:00Z",
  },
  {
    id: "asset-sqs-alerts",
    name: "securenexus-alert-queue",
    type: "cloud",
    subType: "sqs_queue",
    environment: "production",
    riskScore: 0.3,
    metadata: {
      provider: "AWS",
      region: "us-east-1",
      type: "FIFO",
      visibilityTimeout: 30,
      retentionDays: 14,
      dlqEnabled: true,
      encrypted: true,
    },
    tags: ["messaging", "queue", "alerts"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-10-15T10:00:00Z",
  },
  {
    id: "asset-github-actions",
    name: "github-actions-ci",
    type: "cloud",
    subType: "ci_cd_pipeline",
    environment: "shared",
    riskScore: 0.55,
    metadata: {
      provider: "GitHub",
      workflows: 3,
      secretsCount: 8,
      oidcEnabled: true,
      selfHostedRunners: false,
      lastRun: "2026-03-06T04:10:00Z",
    },
    tags: ["ci-cd", "github", "automation"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-06-20T10:00:00Z",
  },
  {
    id: "asset-waf-rules",
    name: "securenexus-waf",
    type: "network",
    subType: "waf",
    environment: "production",
    riskScore: 0.25,
    metadata: {
      provider: "AWS",
      ruleGroups: 4,
      managedRules: [
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesSQLiRuleSet",
      ],
      customRules: 3,
      blockedRequests24h: 1247,
    },
    tags: ["security", "waf", "firewall"],
    owner: "security-team",
    lastScannedAt: "2026-03-06T03:00:00Z",
    createdAt: "2025-09-01T10:00:00Z",
  },
];

const RELATIONSHIP_CATALOG: Omit<SecurityRelationship, "id">[] = [
  {
    sourceId: "asset-repo-backend",
    targetId: "asset-ecr-registry",
    relationship: "deploys_to",
    weight: 0.8,
    metadata: { pipeline: "github-actions", trigger: "push-to-main" },
    bidirectional: false,
  },
  {
    sourceId: "asset-repo-frontend",
    targetId: "asset-cloudfront-cdn",
    relationship: "deploys_to",
    weight: 0.7,
    metadata: { pipeline: "github-actions", trigger: "push-to-main" },
    bidirectional: false,
  },
  {
    sourceId: "asset-repo-infra",
    targetId: "asset-eks-cluster",
    relationship: "manages",
    weight: 0.9,
    metadata: { tool: "terraform", approach: "gitops" },
    bidirectional: false,
  },
  {
    sourceId: "asset-ecr-registry",
    targetId: "asset-eks-cluster",
    relationship: "deploys_to",
    weight: 0.9,
    metadata: { method: "kubectl-apply", namespace: "production" },
    bidirectional: false,
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-rds-primary",
    relationship: "connects_to",
    weight: 0.95,
    metadata: { port: 5432, encrypted: true, vpcInternal: true },
    bidirectional: false,
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-s3-evidence",
    relationship: "writes_to",
    weight: 0.7,
    metadata: { accessPattern: "write-heavy", encryption: "AES-256" },
    bidirectional: false,
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-s3-logs",
    relationship: "writes_to",
    weight: 0.6,
    metadata: { accessPattern: "append-only", retention: "365d" },
    bidirectional: false,
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-secrets-manager",
    relationship: "reads_from",
    weight: 0.95,
    metadata: { method: "IRSA", secretNames: ["database-url", "session-secret", "api-keys"] },
    bidirectional: false,
  },
  {
    sourceId: "asset-alb-public",
    targetId: "asset-eks-cluster",
    relationship: "connects_to",
    weight: 0.9,
    metadata: { protocol: "HTTPS", targetPort: 5000, healthCheck: "/ops/health" },
    bidirectional: false,
  },
  {
    sourceId: "asset-cloudfront-cdn",
    targetId: "asset-alb-public",
    relationship: "connects_to",
    weight: 0.8,
    metadata: { origin: "alb", protocol: "HTTPS", cachePolicy: "optimized" },
    bidirectional: false,
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-eks-cluster",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "private" },
    bidirectional: false,
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-rds-primary",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "private-data" },
    bidirectional: false,
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-rds-replica",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "private-data" },
    bidirectional: false,
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-alb-public",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "public" },
    bidirectional: false,
  },
  {
    sourceId: "asset-iam-deploy-role",
    targetId: "asset-eks-cluster",
    relationship: "has_permission",
    weight: 0.9,
    metadata: { access: "cluster-admin", scope: "full" },
    bidirectional: false,
  },
  {
    sourceId: "asset-iam-deploy-role",
    targetId: "asset-ecr-registry",
    relationship: "has_permission",
    weight: 0.85,
    metadata: { access: "push-pull", scope: "full" },
    bidirectional: false,
  },
  {
    sourceId: "asset-iam-deploy-role",
    targetId: "asset-secrets-manager",
    relationship: "has_permission",
    weight: 0.9,
    metadata: { access: "read-write", scope: "full" },
    bidirectional: false,
  },
  {
    sourceId: "asset-iam-app-role",
    targetId: "asset-rds-primary",
    relationship: "has_permission",
    weight: 0.85,
    metadata: { access: "data-full", scope: "application" },
    bidirectional: false,
  },
  {
    sourceId: "asset-iam-app-role",
    targetId: "asset-s3-evidence",
    relationship: "has_permission",
    weight: 0.7,
    metadata: { access: "read-write", scope: "bucket" },
    bidirectional: false,
  },
  {
    sourceId: "asset-iam-app-role",
    targetId: "asset-secrets-manager",
    relationship: "has_permission",
    weight: 0.8,
    metadata: { access: "read", scope: "application-secrets" },
    bidirectional: false,
  },
  {
    sourceId: "asset-cognito-pool",
    targetId: "asset-eks-cluster",
    relationship: "authenticates_with",
    weight: 0.9,
    metadata: { protocol: "OAuth2/OIDC", tokenType: "JWT" },
    bidirectional: false,
  },
  {
    sourceId: "asset-github-actions",
    targetId: "asset-iam-deploy-role",
    relationship: "authenticates_with",
    weight: 0.85,
    metadata: { method: "OIDC", trustPolicy: "github-actions" },
    bidirectional: false,
  },
  {
    sourceId: "asset-github-actions",
    targetId: "asset-repo-backend",
    relationship: "reads_from",
    weight: 0.7,
    metadata: { trigger: "pull_request", access: "checkout" },
    bidirectional: false,
  },
  {
    sourceId: "asset-github-actions",
    targetId: "asset-repo-frontend",
    relationship: "reads_from",
    weight: 0.7,
    metadata: { trigger: "pull_request", access: "checkout" },
    bidirectional: false,
  },
  {
    sourceId: "asset-rds-primary",
    targetId: "asset-rds-replica",
    relationship: "connects_to",
    weight: 0.9,
    metadata: { replicationType: "async", lag: "< 1s" },
    bidirectional: false,
  },
  {
    sourceId: "asset-lambda-processor",
    targetId: "asset-rds-primary",
    relationship: "writes_to",
    weight: 0.7,
    metadata: { accessPattern: "event-driven", connection: "rds-proxy" },
    bidirectional: false,
  },
  {
    sourceId: "asset-sqs-alerts",
    targetId: "asset-lambda-processor",
    relationship: "connects_to",
    weight: 0.8,
    metadata: { trigger: "event-source-mapping", batchSize: 10 },
    bidirectional: false,
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-sqs-alerts",
    relationship: "writes_to",
    weight: 0.6,
    metadata: { pattern: "async-publish", messageType: "alert-events" },
    bidirectional: false,
  },
  {
    sourceId: "asset-waf-rules",
    targetId: "asset-alb-public",
    relationship: "manages",
    weight: 0.95,
    metadata: { association: "web-acl", mode: "block" },
    bidirectional: false,
  },
  {
    sourceId: "asset-waf-rules",
    targetId: "asset-cloudfront-cdn",
    relationship: "manages",
    weight: 0.95,
    metadata: { association: "web-acl", mode: "block" },
    bidirectional: false,
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-iam-app-role",
    relationship: "authenticates_with",
    weight: 0.85,
    metadata: { method: "IRSA", serviceAccount: "securenexus-sa" },
    bidirectional: false,
  },
];

function buildAttackPaths(assets: SecurityAsset[], relationships: SecurityRelationship[]): RankedAttackPath[] {
  const adjacency = new Map<string, { targetId: string; rel: SecurityRelationship }[]>();
  for (const rel of relationships) {
    const existing = adjacency.get(rel.sourceId) || [];
    existing.push({ targetId: rel.targetId, rel });
    adjacency.set(rel.sourceId, existing);
  }

  const assetMap = new Map<string, SecurityAsset>();
  for (const asset of assets) {
    assetMap.set(asset.id, asset);
  }

  const internetFacing = assets.filter(
    (a) =>
      (a.metadata as Record<string, unknown>).internetExposed === true ||
      a.subType === "load_balancer" ||
      a.subType === "cdn",
  );

  const sensitiveTargets = assets.filter(
    (a) =>
      (a.metadata as Record<string, unknown>).dataClassification === "secret" ||
      (a.metadata as Record<string, unknown>).dataClassification === "confidential" ||
      (a.metadata as Record<string, unknown>).dataClassification === "restricted" ||
      a.subType === "secrets_manager",
  );

  const paths: RankedAttackPath[] = [];
  let pathId = 0;

  for (const entry of internetFacing) {
    for (const target of sensitiveTargets) {
      const found = bfsPath(entry.id, target.id, adjacency, assetMap);
      if (found && found.length > 1) {
        const pathNodes = found.map((id) => assetMap.get(id)).filter(Boolean) as SecurityAsset[];
        const pathEdges: SecurityRelationship[] = [];
        for (let i = 0; i < found.length - 1; i++) {
          const neighbors = adjacency.get(found[i]) || [];
          const edge = neighbors.find((n) => n.targetId === found[i + 1]);
          if (edge) pathEdges.push(edge.rel);
        }

        const hopCount = found.length - 1;
        const avgRisk = pathNodes.reduce((sum, n) => sum + n.riskScore, 0) / pathNodes.length;
        const maxRisk = Math.max(...pathNodes.map((n) => n.riskScore));
        const exploitability = calculateExploitability(pathNodes, pathEdges);
        const blastRadius = calculateBlastRadius(target, adjacency, assetMap);
        const riskScore = Math.min(
          1,
          avgRisk * 0.3 + maxRisk * 0.2 + exploitability * 0.25 + blastRadius * 0.15 + (1 / hopCount) * 0.1,
        );

        pathId++;
        paths.push({
          id: `apath-${String(pathId).padStart(3, "0")}`,
          name: `${entry.name} → ${target.name}`,
          description: `Attack path from ${entry.subType} to ${target.subType} via ${hopCount} hops`,
          nodes: pathNodes,
          edges: pathEdges,
          riskScore: Math.round(riskScore * 100) / 100,
          blastRadius: Math.round(blastRadius * 100) / 100,
          exploitability: Math.round(exploitability * 100) / 100,
          hopCount,
          entryPoint: entry,
          target,
          mitigations: generateMitigations(pathNodes, pathEdges),
          mitreTactics: inferMitreTactics(pathNodes),
        });
      }
    }
  }

  paths.sort((a, b) => b.riskScore - a.riskScore);
  return paths;
}

function bfsPath(
  startId: string,
  endId: string,
  adjacency: Map<string, { targetId: string; rel: SecurityRelationship }[]>,
  assetMap: Map<string, SecurityAsset>,
): string[] | null {
  if (startId === endId) return null;
  const visited = new Set<string>();
  const queue: { id: string; path: string[] }[] = [{ id: startId, path: [startId] }];
  visited.add(startId);

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;

    const neighbors = adjacency.get(current.id) || [];
    for (const { targetId } of neighbors) {
      if (visited.has(targetId)) continue;
      if (!assetMap.has(targetId)) continue;

      const newPath = [...current.path, targetId];
      if (targetId === endId) return newPath;

      if (newPath.length < 8) {
        visited.add(targetId);
        queue.push({ id: targetId, path: newPath });
      }
    }
  }
  return null;
}

function calculateExploitability(nodes: SecurityAsset[], edges: SecurityRelationship[]): number {
  let score = 0;
  let factors = 0;

  for (const node of nodes) {
    const meta = node.metadata as Record<string, unknown>;
    if (meta.isOverPrivileged) {
      score += 0.9;
      factors++;
    }
    if (meta.publiclyAccessible || meta.internetExposed) {
      score += 0.8;
      factors++;
    }
    if (meta.mfaEnabled === false) {
      score += 0.7;
      factors++;
    }
    if (typeof meta.criticalVulns === "number" && meta.criticalVulns > 0) {
      score += 0.95;
      factors++;
    }
    if (typeof meta.highVulns === "number" && meta.highVulns > 0) {
      score += 0.6;
      factors++;
    }
  }

  for (const edge of edges) {
    const meta = edge.metadata as Record<string, unknown>;
    if (meta.encrypted === false) {
      score += 0.7;
      factors++;
    }
    if (meta.access === "full" || meta.scope === "full") {
      score += 0.6;
      factors++;
    }
  }

  return factors > 0 ? Math.min(1, score / factors) : 0.3;
}

function calculateBlastRadius(
  target: SecurityAsset,
  adjacency: Map<string, { targetId: string; rel: SecurityRelationship }[]>,
  assetMap: Map<string, SecurityAsset>,
): number {
  const visited = new Set<string>();
  const queue = [target.id];
  visited.add(target.id);

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;
    const neighbors = adjacency.get(current) || [];
    for (const { targetId } of neighbors) {
      if (!visited.has(targetId) && assetMap.has(targetId)) {
        visited.add(targetId);
        queue.push(targetId);
      }
    }
  }

  const totalAssets = assetMap.size;
  return totalAssets > 0 ? Math.min(1, visited.size / totalAssets) : 0;
}

function generateMitigations(nodes: SecurityAsset[], edges: SecurityRelationship[]): string[] {
  const mitigations: string[] = [];

  for (const node of nodes) {
    const meta = node.metadata as Record<string, unknown>;
    if (meta.isOverPrivileged) {
      mitigations.push(`Reduce permissions on ${node.name} — apply least-privilege IAM policy`);
    }
    if (meta.publiclyAccessible) {
      mitigations.push(`Restrict public access on ${node.name} — move to private subnet`);
    }
    if (meta.mfaEnabled === false) {
      mitigations.push(`Enable MFA on ${node.name}`);
    }
    if (typeof meta.highVulns === "number" && meta.highVulns > 0) {
      mitigations.push(`Patch ${meta.highVulns} high-severity vulnerabilities in ${node.name}`);
    }
  }

  for (const edge of edges) {
    const meta = edge.metadata as Record<string, unknown>;
    if (meta.encrypted === false) {
      mitigations.push(`Enable encryption in transit for connection from ${edge.sourceId} to ${edge.targetId}`);
    }
  }

  if (mitigations.length === 0) {
    mitigations.push("Implement network segmentation between entry point and sensitive data");
    mitigations.push("Add additional authentication gates at critical path junctions");
  }

  return mitigations;
}

function inferMitreTactics(nodes: SecurityAsset[]): string[] {
  const tactics = new Set<string>();
  tactics.add("initial-access");

  for (const node of nodes) {
    if (node.type === "identity") {
      tactics.add("credential-access");
      if ((node.metadata as Record<string, unknown>).isOverPrivileged) {
        tactics.add("privilege-escalation");
      }
    }
    if (node.type === "network" && node.subType === "load_balancer") {
      tactics.add("discovery");
    }
    if (node.type === "compute") {
      tactics.add("execution");
      tactics.add("lateral-movement");
    }
    if (node.type === "data") {
      tactics.add("collection");
      const classification = (node.metadata as Record<string, unknown>).dataClassification;
      if (classification === "secret" || classification === "confidential") {
        tactics.add("exfiltration");
      }
    }
  }

  return Array.from(tactics);
}

export function getSecurityGraph(orgId?: string): SecurityGraphData {
  const assets: SecurityAsset[] = ASSET_CATALOG.map((a) => ({
    ...a,
    orgId: orgId || null,
  }));

  const relationships: SecurityRelationship[] = RELATIONSHIP_CATALOG.map((r, i) => ({
    ...r,
    id: `rel-${String(i + 1).padStart(3, "0")}`,
  }));

  const attackPaths = buildAttackPaths(assets, relationships);

  const highRiskAssets = assets.filter((a) => a.riskScore >= 0.7).length;
  const avgRiskScore =
    assets.length > 0 ? Math.round((assets.reduce((sum, a) => sum + a.riskScore, 0) / assets.length) * 100) / 100 : 0;

  const byType: Record<string, number> = {};
  const byEnvironment: Record<string, number> = {};
  let internetExposed = 0;
  let overPrivileged = 0;

  for (const asset of assets) {
    byType[asset.type] = (byType[asset.type] || 0) + 1;
    byEnvironment[asset.environment] = (byEnvironment[asset.environment] || 0) + 1;
    if ((asset.metadata as Record<string, unknown>).internetExposed) internetExposed++;
    if ((asset.metadata as Record<string, unknown>).isOverPrivileged) overPrivileged++;
  }

  const stats: GraphStats = {
    totalAssets: assets.length,
    totalRelationships: relationships.length,
    criticalPaths: attackPaths.filter((p) => p.riskScore >= 0.7).length,
    highRiskAssets,
    avgRiskScore,
    byType,
    byEnvironment,
    internetExposed,
    overPrivileged,
  };

  return { assets, relationships, attackPaths, stats };
}

export function getAttackPathById(pathId: string, orgId?: string): RankedAttackPath | null {
  const graph = getSecurityGraph(orgId);
  return graph.attackPaths.find((p) => p.id === pathId) || null;
}

export function getAssetById(assetId: string, orgId?: string): SecurityAsset | null {
  const graph = getSecurityGraph(orgId);
  return graph.assets.find((a) => a.id === assetId) || null;
}

export function getAssetNeighbors(
  assetId: string,
  orgId?: string,
): { asset: SecurityAsset; relationship: SecurityRelationship; direction: "inbound" | "outbound" }[] {
  const graph = getSecurityGraph(orgId);
  const assetMap = new Map(graph.assets.map((a) => [a.id, a]));
  const neighbors: { asset: SecurityAsset; relationship: SecurityRelationship; direction: "inbound" | "outbound" }[] =
    [];

  for (const rel of graph.relationships) {
    if (rel.sourceId === assetId) {
      const target = assetMap.get(rel.targetId);
      if (target) neighbors.push({ asset: target, relationship: rel, direction: "outbound" });
    }
    if (rel.targetId === assetId) {
      const source = assetMap.get(rel.sourceId);
      if (source) neighbors.push({ asset: source, relationship: rel, direction: "inbound" });
    }
  }

  return neighbors;
}
