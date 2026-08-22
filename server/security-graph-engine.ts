import { createHash } from "crypto";

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
  resolutionKey: string;
}

export type AssetType =
  | "code"
  | "cloud"
  | "identity"
  | "data"
  | "network"
  | "compute"
  | "container"
  | "endpoint"
  | "saas"
  | "runtime"
  | "remediation"
  | "vulnerability";

export interface SecurityRelationship {
  id: string;
  sourceId: string;
  targetId: string;
  relationship: RelationshipType;
  weight: number;
  metadata: Record<string, unknown>;
  bidirectional: boolean;
  createdAt: string;
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
  | "runs_on"
  | "can_access"
  | "exposed_to"
  | "owned_by"
  | "fixed_by"
  | "triggers"
  | "mitigates"
  | "scans";

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

export interface IngestionPayload {
  assets?: AssetUpsert[];
  relationships?: RelationshipUpsert[];
}

export interface AssetUpsert {
  name: string;
  type: AssetType;
  subType: string;
  environment: "production" | "staging" | "development" | "shared";
  riskScore: number;
  metadata?: Record<string, unknown>;
  tags?: string[];
  owner?: string | null;
  resolutionKey?: string;
}

export interface RelationshipUpsert {
  sourceResolutionKey: string;
  targetResolutionKey: string;
  relationship: RelationshipType;
  weight?: number;
  metadata?: Record<string, unknown>;
  bidirectional?: boolean;
}

export interface GraphQuery {
  assetTypes?: AssetType[];
  relationshipTypes?: RelationshipType[];
  environments?: string[];
  minRiskScore?: number;
  maxRiskScore?: number;
  tags?: string[];
  ownerFilter?: string;
  searchTerm?: string;
  sourceId?: string;
  targetId?: string;
  maxDepth?: number;
}

export interface IngestionResult {
  assetsUpserted: number;
  relationshipsUpserted: number;
  assetsSkipped: number;
  relationshipsSkipped: number;
  errors: string[];
}

function computeResolutionKey(asset: AssetUpsert): string {
  const keyParts: string[] = [asset.type, asset.subType, asset.name];
  const meta = asset.metadata || {};
  if (meta.arn && typeof meta.arn === "string") keyParts.push(meta.arn);
  else if (meta.resourceId && typeof meta.resourceId === "string") keyParts.push(meta.resourceId);
  if (meta.provider && typeof meta.provider === "string") keyParts.push(meta.provider);
  if (meta.region && typeof meta.region === "string") keyParts.push(meta.region);
  if (asset.type === "code" && meta.branch && typeof meta.branch === "string") keyParts.push(meta.branch);
  if (asset.type === "identity" && meta.principalId && typeof meta.principalId === "string")
    keyParts.push(meta.principalId);
  if (asset.type === "endpoint" && meta.hostname && typeof meta.hostname === "string") keyParts.push(meta.hostname);
  if (asset.type === "vulnerability" && meta.cveId && typeof meta.cveId === "string") keyParts.push(meta.cveId);
  if (asset.type === "remediation" && meta.ticketId && typeof meta.ticketId === "string") keyParts.push(meta.ticketId);
  const raw = keyParts.join(":").toLowerCase();
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

function deriveAssetId(resolutionKey: string): string {
  return "asset-" + resolutionKey;
}

const orgGraphStores = new Map<
  string,
  { assets: Map<string, SecurityAsset>; relationships: Map<string, SecurityRelationship> }
>();

function getOrgStore(orgId: string): {
  assets: Map<string, SecurityAsset>;
  relationships: Map<string, SecurityRelationship>;
} {
  let store = orgGraphStores.get(orgId);
  if (!store) {
    store = { assets: new Map(), relationships: new Map() };
    orgGraphStores.set(orgId, store);
  }
  return store;
}

export function ingestEntities(orgId: string, payload: IngestionPayload): IngestionResult {
  const store = getOrgStore(orgId);
  const result: IngestionResult = {
    assetsUpserted: 0,
    relationshipsUpserted: 0,
    assetsSkipped: 0,
    relationshipsSkipped: 0,
    errors: [],
  };

  if (payload.assets) {
    for (const assetInput of payload.assets) {
      try {
        const resKey = assetInput.resolutionKey || computeResolutionKey(assetInput);
        const assetId = deriveAssetId(resKey);
        const existing = store.assets.get(assetId);
        const now = new Date().toISOString();
        const merged: SecurityAsset = {
          id: assetId,
          orgId,
          name: assetInput.name,
          type: assetInput.type,
          subType: assetInput.subType,
          environment: assetInput.environment,
          riskScore: assetInput.riskScore,
          metadata: { ...(existing?.metadata || {}), ...(assetInput.metadata || {}) },
          tags: assetInput.tags || existing?.tags || [],
          owner: assetInput.owner !== undefined ? assetInput.owner : (existing?.owner ?? null),
          lastScannedAt: now,
          createdAt: existing?.createdAt || now,
          resolutionKey: resKey,
        };
        store.assets.set(assetId, merged);
        result.assetsUpserted++;
      } catch (err) {
        result.assetsSkipped++;
        result.errors.push('Asset "' + assetInput.name + '": ' + String(err));
      }
    }
  }

  if (payload.relationships) {
    for (const relInput of payload.relationships) {
      try {
        const sourceAsset = findAssetByResolutionKey(store.assets, relInput.sourceResolutionKey);
        const targetAsset = findAssetByResolutionKey(store.assets, relInput.targetResolutionKey);
        if (!sourceAsset) {
          result.relationshipsSkipped++;
          result.errors.push('Relationship: source key "' + relInput.sourceResolutionKey + '" not found');
          continue;
        }
        if (!targetAsset) {
          result.relationshipsSkipped++;
          result.errors.push('Relationship: target key "' + relInput.targetResolutionKey + '" not found');
          continue;
        }
        const relId = "rel-" + sourceAsset.id + "-" + relInput.relationship + "-" + targetAsset.id;
        const existing = store.relationships.get(relId);
        const merged: SecurityRelationship = {
          id: relId,
          sourceId: sourceAsset.id,
          targetId: targetAsset.id,
          relationship: relInput.relationship,
          weight: relInput.weight ?? existing?.weight ?? 0.5,
          metadata: { ...(existing?.metadata || {}), ...(relInput.metadata || {}) },
          bidirectional: relInput.bidirectional ?? existing?.bidirectional ?? false,
          createdAt: existing?.createdAt || new Date().toISOString(),
        };
        store.relationships.set(relId, merged);
        result.relationshipsUpserted++;
      } catch (err) {
        result.relationshipsSkipped++;
        result.errors.push("Relationship: " + String(err));
      }
    }
  }
  return result;
}

function findAssetByResolutionKey(
  assets: Map<string, SecurityAsset>,
  resolutionKeyOrId: string,
): SecurityAsset | undefined {
  const byId = assets.get(resolutionKeyOrId);
  if (byId) return byId;
  const derived = deriveAssetId(resolutionKeyOrId);
  const byDerived = assets.get(derived);
  if (byDerived) return byDerived;
  for (const asset of Array.from(assets.values())) {
    if (asset.resolutionKey === resolutionKeyOrId) return asset;
  }
  return undefined;
}

export function deleteAsset(orgId: string, assetId: string): boolean {
  const store = getOrgStore(orgId);
  const deleted = store.assets.delete(assetId);
  if (deleted) {
    for (const [, rel] of Array.from(store.relationships.entries())) {
      if (rel.sourceId === assetId || rel.targetId === assetId) {
        store.relationships.delete(rel.id);
      }
    }
  }
  return deleted;
}

export function deleteRelationship(orgId: string, relationshipId: string): boolean {
  const store = getOrgStore(orgId);
  return store.relationships.delete(relationshipId);
}

export function queryGraph(orgId: string, query: GraphQuery): SecurityGraphData {
  const fullGraph = getSecurityGraph(orgId);
  let filteredAssets = fullGraph.assets;
  if (query.assetTypes && query.assetTypes.length > 0) {
    const typeSet = new Set(query.assetTypes);
    filteredAssets = filteredAssets.filter((a) => typeSet.has(a.type));
  }
  if (query.environments && query.environments.length > 0) {
    const envSet = new Set(query.environments);
    filteredAssets = filteredAssets.filter((a) => envSet.has(a.environment));
  }
  if (typeof query.minRiskScore === "number") {
    filteredAssets = filteredAssets.filter((a) => a.riskScore >= (query.minRiskScore as number));
  }
  if (typeof query.maxRiskScore === "number") {
    filteredAssets = filteredAssets.filter((a) => a.riskScore <= (query.maxRiskScore as number));
  }
  if (query.tags && query.tags.length > 0) {
    const tagSet = new Set(query.tags.map((t) => t.toLowerCase()));
    filteredAssets = filteredAssets.filter((a) => a.tags.some((t) => tagSet.has(t.toLowerCase())));
  }
  if (query.ownerFilter) {
    const ownerLower = query.ownerFilter.toLowerCase();
    filteredAssets = filteredAssets.filter((a) => a.owner && a.owner.toLowerCase().includes(ownerLower));
  }
  if (query.searchTerm) {
    const term = query.searchTerm.toLowerCase();
    filteredAssets = filteredAssets.filter(
      (a) =>
        a.name.toLowerCase().includes(term) ||
        a.subType.toLowerCase().includes(term) ||
        a.tags.some((t) => t.toLowerCase().includes(term)),
    );
  }
  const assetIds = new Set(filteredAssets.map((a) => a.id));
  let filteredRels = fullGraph.relationships.filter((r) => assetIds.has(r.sourceId) && assetIds.has(r.targetId));
  if (query.relationshipTypes && query.relationshipTypes.length > 0) {
    const relTypeSet = new Set(query.relationshipTypes);
    filteredRels = filteredRels.filter((r) => relTypeSet.has(r.relationship));
  }
  const attackPaths = buildAttackPaths(filteredAssets, filteredRels);
  const stats = computeStats(filteredAssets, filteredRels, attackPaths);
  return { assets: filteredAssets, relationships: filteredRels, attackPaths, stats };
}

export function findPaths(orgId: string, sourceId: string, targetId: string, maxDepth: number = 6): RankedAttackPath[] {
  const graph = getSecurityGraph(orgId);
  const adjacency = buildAdjacency(graph.relationships);
  const assetMap = new Map(graph.assets.map((a) => [a.id, a]));
  const source = assetMap.get(sourceId);
  const target = assetMap.get(targetId);
  if (!source || !target) return [];
  const allPaths = bfsAllPaths(sourceId, targetId, adjacency, assetMap, maxDepth);
  const ranked: RankedAttackPath[] = [];
  for (let i = 0; i < allPaths.length; i++) {
    const nodeIds = allPaths[i];
    const pathNodes = nodeIds.map((nid) => assetMap.get(nid)).filter(Boolean) as SecurityAsset[];
    const pathEdges: SecurityRelationship[] = [];
    for (let j = 0; j < nodeIds.length - 1; j++) {
      const neighbors = adjacency.get(nodeIds[j]) || [];
      const edge = neighbors.find((n) => n.targetId === nodeIds[j + 1]);
      if (edge) pathEdges.push(edge.rel);
    }
    const hopCount = nodeIds.length - 1;
    const avgRisk = pathNodes.reduce((sum, n) => sum + n.riskScore, 0) / pathNodes.length;
    const maxRisk = Math.max(...pathNodes.map((n) => n.riskScore));
    const exploitability = calculateExploitability(pathNodes, pathEdges);
    const blastRadius = calculateBlastRadius(target, adjacency, assetMap);
    const riskScore = Math.min(
      1,
      avgRisk * 0.3 + maxRisk * 0.2 + exploitability * 0.25 + blastRadius * 0.15 + (1 / hopCount) * 0.1,
    );
    ranked.push({
      id: "path-" + String(i + 1).padStart(3, "0"),
      name: source.name + " -> " + target.name,
      description: "Path from " + source.subType + " to " + target.subType + " via " + hopCount + " hops",
      nodes: pathNodes,
      edges: pathEdges,
      riskScore: Math.round(riskScore * 100) / 100,
      blastRadius: Math.round(blastRadius * 100) / 100,
      exploitability: Math.round(exploitability * 100) / 100,
      hopCount,
      entryPoint: source,
      target,
      mitigations: generateMitigations(pathNodes, pathEdges),
      mitreTactics: inferMitreTactics(pathNodes),
    });
  }
  ranked.sort((a, b) => b.riskScore - a.riskScore);
  return ranked;
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
    resolutionKey: "code:repository:securenexus-api",
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
    resolutionKey: "code:repository:securenexus-web",
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
    resolutionKey: "code:iac_repository:securenexus-infra",
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
    resolutionKey: "compute:kubernetes_cluster:securenexus-eks-prod",
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
    resolutionKey: "data:rds_postgresql:securenexus-db-prod",
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
    resolutionKey: "data:rds_postgresql:securenexus-db-replica",
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
    resolutionKey: "data:s3_bucket:securenexus-evidence-prod",
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
    resolutionKey: "data:s3_bucket:securenexus-audit-logs",
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
    resolutionKey: "container:container_registry:securenexus-ecr",
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
    resolutionKey: "network:load_balancer:securenexus-alb-prod",
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
    resolutionKey: "network:vpc:securenexus-vpc-prod",
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
    resolutionKey: "network:cdn:securenexus-cdn",
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
    resolutionKey: "identity:cognito_user_pool:securenexus-auth-pool",
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
    resolutionKey: "identity:iam_role:securenexus-deploy-role",
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
    resolutionKey: "identity:iam_role:securenexus-app-role",
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
    resolutionKey: "data:secrets_manager:securenexus-secrets",
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
    resolutionKey: "compute:lambda_function:securenexus-event-processor",
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
    resolutionKey: "cloud:sqs_queue:securenexus-alert-queue",
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
    resolutionKey: "cloud:ci_cd_pipeline:github-actions-ci",
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
    resolutionKey: "network:waf:securenexus-waf",
  },
  {
    id: "asset-endpoint-api",
    name: "api.securenexus.io",
    type: "endpoint",
    subType: "api_endpoint",
    environment: "production",
    riskScore: 0.6,
    metadata: {
      hostname: "api.securenexus.io",
      protocol: "HTTPS",
      port: 443,
      authRequired: true,
      rateLimited: true,
      lastHealthCheck: "2026-03-06T04:30:00Z",
      responseTimeP99: 245,
      internetExposed: true,
    },
    tags: ["endpoint", "api", "public"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T04:00:00Z",
    createdAt: "2025-08-01T10:00:00Z",
    resolutionKey: "endpoint:api_endpoint:api.securenexus.io",
  },
  {
    id: "asset-endpoint-webhook",
    name: "webhooks.securenexus.io",
    type: "endpoint",
    subType: "webhook_endpoint",
    environment: "production",
    riskScore: 0.55,
    metadata: {
      hostname: "webhooks.securenexus.io",
      protocol: "HTTPS",
      port: 443,
      authRequired: true,
      hmacValidation: true,
      internetExposed: true,
    },
    tags: ["endpoint", "webhook", "integration"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T04:00:00Z",
    createdAt: "2025-10-01T10:00:00Z",
    resolutionKey: "endpoint:webhook_endpoint:webhooks.securenexus.io",
  },
  {
    id: "asset-saas-github",
    name: "GitHub Enterprise",
    type: "saas",
    subType: "scm_platform",
    environment: "shared",
    riskScore: 0.4,
    metadata: {
      provider: "GitHub",
      ssoEnabled: true,
      orgMembers: 12,
      repos: 8,
      branchProtection: true,
      secretScanning: true,
    },
    tags: ["saas", "scm", "github"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-06-01T10:00:00Z",
    resolutionKey: "saas:scm_platform:github-enterprise",
  },
  {
    id: "asset-saas-slack",
    name: "Slack Workspace",
    type: "saas",
    subType: "messaging_platform",
    environment: "shared",
    riskScore: 0.35,
    metadata: { provider: "Slack", ssoEnabled: true, channelCount: 24, botIntegrations: 3, dlpEnabled: false },
    tags: ["saas", "messaging", "collaboration"],
    owner: "it-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-06-01T10:00:00Z",
    resolutionKey: "saas:messaging_platform:slack-workspace",
  },
  {
    id: "asset-saas-jira",
    name: "Jira Cloud",
    type: "saas",
    subType: "project_management",
    environment: "shared",
    riskScore: 0.3,
    metadata: { provider: "Atlassian", ssoEnabled: true, projects: 6, activeUsers: 15 },
    tags: ["saas", "project-management", "ticketing"],
    owner: "engineering-lead",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2025-06-01T10:00:00Z",
    resolutionKey: "saas:project_management:jira-cloud",
  },
  {
    id: "asset-vuln-log4shell",
    name: "CVE-2021-44228 (Log4Shell)",
    type: "vulnerability",
    subType: "cve",
    environment: "production",
    riskScore: 0.95,
    metadata: {
      cveId: "CVE-2021-44228",
      cvss: 10.0,
      severity: "critical",
      affectedPackage: "log4j-core",
      affectedVersion: "<2.17.0",
      patchAvailable: true,
      exploitInWild: true,
    },
    tags: ["vulnerability", "critical", "rce"],
    owner: "security-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2021-12-09T00:00:00Z",
    resolutionKey: "vulnerability:cve:CVE-2021-44228",
  },
  {
    id: "asset-vuln-xss-frontend",
    name: "XSS in Search Input (SNX-2026-001)",
    type: "vulnerability",
    subType: "application_vuln",
    environment: "production",
    riskScore: 0.65,
    metadata: {
      internalId: "SNX-2026-001",
      severity: "high",
      component: "search-bar",
      discoveredBy: "pentest",
      patchAvailable: true,
    },
    tags: ["vulnerability", "xss", "frontend"],
    owner: "frontend-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2026-02-15T10:00:00Z",
    resolutionKey: "vulnerability:application_vuln:SNX-2026-001",
  },
  {
    id: "asset-runtime-k8s-pod",
    name: "securenexus-api-pod-7b4f2",
    type: "runtime",
    subType: "kubernetes_pod",
    environment: "production",
    riskScore: 0.4,
    metadata: {
      namespace: "production",
      image: "securenexus-ecr:latest",
      cpuLimitMilli: 1000,
      memoryLimitMB: 1024,
      restartCount: 0,
      startedAt: "2026-03-06T00:12:00Z",
    },
    tags: ["runtime", "pod", "api"],
    owner: "devops-team",
    lastScannedAt: "2026-03-06T04:30:00Z",
    createdAt: "2026-03-06T00:12:00Z",
    resolutionKey: "runtime:kubernetes_pod:securenexus-api-pod-7b4f2",
  },
  {
    id: "asset-runtime-guardduty",
    name: "GuardDuty: Unusual API Activity",
    type: "runtime",
    subType: "security_finding",
    environment: "production",
    riskScore: 0.72,
    metadata: {
      findingType: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
      severity: "high",
      firstSeen: "2026-03-05T22:00:00Z",
      lastSeen: "2026-03-06T02:00:00Z",
      resourceType: "AccessKey",
      acknowledged: false,
    },
    tags: ["runtime", "guardduty", "threat-detection"],
    owner: "security-team",
    lastScannedAt: "2026-03-06T04:00:00Z",
    createdAt: "2026-03-05T22:00:00Z",
    resolutionKey: "runtime:security_finding:guardduty-unusual-api",
  },
  {
    id: "asset-remediation-pr-xss",
    name: "PR #142: Fix XSS in search input",
    type: "remediation",
    subType: "pull_request",
    environment: "production",
    riskScore: 0.15,
    metadata: {
      ticketId: "SNX-2026-001-FIX",
      prNumber: 142,
      repo: "securenexus-web",
      status: "merged",
      author: "security-bot",
      mergedAt: "2026-02-20T14:00:00Z",
    },
    tags: ["remediation", "pr", "xss-fix"],
    owner: "frontend-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2026-02-18T10:00:00Z",
    resolutionKey: "remediation:pull_request:SNX-2026-001-FIX",
  },
  {
    id: "asset-remediation-ticket-log4j",
    name: "JIRA-SEC-456: Upgrade Log4j",
    type: "remediation",
    subType: "ticket",
    environment: "production",
    riskScore: 0.2,
    metadata: {
      ticketId: "SEC-456",
      platform: "Jira",
      status: "in_progress",
      assignee: "platform-team",
      priority: "P0",
      dueDate: "2026-03-10T00:00:00Z",
    },
    tags: ["remediation", "ticket", "log4j"],
    owner: "platform-team",
    lastScannedAt: "2026-03-06T02:00:00Z",
    createdAt: "2026-03-01T10:00:00Z",
    resolutionKey: "remediation:ticket:SEC-456",
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
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-repo-frontend",
    targetId: "asset-cloudfront-cdn",
    relationship: "deploys_to",
    weight: 0.7,
    metadata: { pipeline: "github-actions", trigger: "push-to-main" },
    bidirectional: false,
    createdAt: "2025-09-01T10:00:00Z",
  },
  {
    sourceId: "asset-repo-infra",
    targetId: "asset-eks-cluster",
    relationship: "manages",
    weight: 0.9,
    metadata: { tool: "terraform", approach: "gitops" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-ecr-registry",
    targetId: "asset-eks-cluster",
    relationship: "deploys_to",
    weight: 0.9,
    metadata: { method: "kubectl-apply", namespace: "production" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-rds-primary",
    relationship: "connects_to",
    weight: 0.95,
    metadata: { port: 5432, encrypted: true, vpcInternal: true },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-s3-evidence",
    relationship: "writes_to",
    weight: 0.7,
    metadata: { accessPattern: "write-heavy", encryption: "AES-256" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-s3-logs",
    relationship: "writes_to",
    weight: 0.6,
    metadata: { accessPattern: "append-only", retention: "365d" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-secrets-manager",
    relationship: "reads_from",
    weight: 0.95,
    metadata: { method: "IRSA", secretNames: ["database-url", "session-secret", "api-keys"] },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-alb-public",
    targetId: "asset-eks-cluster",
    relationship: "connects_to",
    weight: 0.9,
    metadata: { protocol: "HTTPS", targetPort: 5000, healthCheck: "/ops/health" },
    bidirectional: false,
    createdAt: "2025-08-15T09:00:00Z",
  },
  {
    sourceId: "asset-cloudfront-cdn",
    targetId: "asset-alb-public",
    relationship: "connects_to",
    weight: 0.8,
    metadata: { origin: "alb", protocol: "HTTPS", cachePolicy: "optimized" },
    bidirectional: false,
    createdAt: "2025-09-01T10:00:00Z",
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-eks-cluster",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "private" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-rds-primary",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "private-data" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-rds-replica",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "private-data" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-vpc-prod",
    targetId: "asset-alb-public",
    relationship: "contains",
    weight: 1.0,
    metadata: { subnet: "public" },
    bidirectional: false,
    createdAt: "2025-08-15T09:00:00Z",
  },
  {
    sourceId: "asset-iam-deploy-role",
    targetId: "asset-eks-cluster",
    relationship: "can_access",
    weight: 0.9,
    metadata: { access: "cluster-admin", scope: "full" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-iam-deploy-role",
    targetId: "asset-ecr-registry",
    relationship: "can_access",
    weight: 0.85,
    metadata: { access: "push-pull", scope: "full" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-iam-deploy-role",
    targetId: "asset-secrets-manager",
    relationship: "can_access",
    weight: 0.9,
    metadata: { access: "read-write", scope: "full" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-iam-app-role",
    targetId: "asset-rds-primary",
    relationship: "can_access",
    weight: 0.85,
    metadata: { access: "data-full", scope: "application" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-iam-app-role",
    targetId: "asset-s3-evidence",
    relationship: "can_access",
    weight: 0.7,
    metadata: { access: "read-write", scope: "bucket" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-iam-app-role",
    targetId: "asset-secrets-manager",
    relationship: "can_access",
    weight: 0.8,
    metadata: { access: "read", scope: "application-secrets" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-cognito-pool",
    targetId: "asset-eks-cluster",
    relationship: "authenticates_with",
    weight: 0.9,
    metadata: { protocol: "OAuth2/OIDC", tokenType: "JWT" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-github-actions",
    targetId: "asset-iam-deploy-role",
    relationship: "authenticates_with",
    weight: 0.85,
    metadata: { method: "OIDC", trustPolicy: "github-actions" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-github-actions",
    targetId: "asset-repo-backend",
    relationship: "reads_from",
    weight: 0.7,
    metadata: { trigger: "pull_request", access: "checkout" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-github-actions",
    targetId: "asset-repo-frontend",
    relationship: "reads_from",
    weight: 0.7,
    metadata: { trigger: "pull_request", access: "checkout" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-rds-primary",
    targetId: "asset-rds-replica",
    relationship: "connects_to",
    weight: 0.9,
    metadata: { replicationType: "async", lag: "< 1s" },
    bidirectional: false,
    createdAt: "2025-09-01T11:00:00Z",
  },
  {
    sourceId: "asset-lambda-processor",
    targetId: "asset-rds-primary",
    relationship: "writes_to",
    weight: 0.7,
    metadata: { accessPattern: "event-driven", connection: "rds-proxy" },
    bidirectional: false,
    createdAt: "2025-10-15T10:00:00Z",
  },
  {
    sourceId: "asset-sqs-alerts",
    targetId: "asset-lambda-processor",
    relationship: "triggers",
    weight: 0.8,
    metadata: { trigger: "event-source-mapping", batchSize: 10 },
    bidirectional: false,
    createdAt: "2025-10-15T10:00:00Z",
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-sqs-alerts",
    relationship: "writes_to",
    weight: 0.6,
    metadata: { pattern: "async-publish", messageType: "alert-events" },
    bidirectional: false,
    createdAt: "2025-10-15T10:00:00Z",
  },
  {
    sourceId: "asset-waf-rules",
    targetId: "asset-alb-public",
    relationship: "manages",
    weight: 0.95,
    metadata: { association: "web-acl", mode: "block" },
    bidirectional: false,
    createdAt: "2025-09-01T10:00:00Z",
  },
  {
    sourceId: "asset-waf-rules",
    targetId: "asset-cloudfront-cdn",
    relationship: "manages",
    weight: 0.95,
    metadata: { association: "web-acl", mode: "block" },
    bidirectional: false,
    createdAt: "2025-09-01T10:00:00Z",
  },
  {
    sourceId: "asset-eks-cluster",
    targetId: "asset-iam-app-role",
    relationship: "authenticates_with",
    weight: 0.85,
    metadata: { method: "IRSA", serviceAccount: "securenexus-sa" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-endpoint-api",
    targetId: "asset-alb-public",
    relationship: "connects_to",
    weight: 0.9,
    metadata: { protocol: "HTTPS", dnsResolves: true },
    bidirectional: false,
    createdAt: "2025-08-01T10:00:00Z",
  },
  {
    sourceId: "asset-endpoint-webhook",
    targetId: "asset-alb-public",
    relationship: "connects_to",
    weight: 0.85,
    metadata: { protocol: "HTTPS", hmacVerified: true },
    bidirectional: false,
    createdAt: "2025-10-01T10:00:00Z",
  },
  {
    sourceId: "asset-saas-github",
    targetId: "asset-repo-backend",
    relationship: "contains",
    weight: 0.9,
    metadata: { relationship: "org-owns-repo" },
    bidirectional: false,
    createdAt: "2025-06-15T10:00:00Z",
  },
  {
    sourceId: "asset-saas-github",
    targetId: "asset-repo-frontend",
    relationship: "contains",
    weight: 0.9,
    metadata: { relationship: "org-owns-repo" },
    bidirectional: false,
    createdAt: "2025-06-15T10:00:00Z",
  },
  {
    sourceId: "asset-saas-github",
    targetId: "asset-repo-infra",
    relationship: "contains",
    weight: 0.9,
    metadata: { relationship: "org-owns-repo" },
    bidirectional: false,
    createdAt: "2025-07-01T08:00:00Z",
  },
  {
    sourceId: "asset-saas-slack",
    targetId: "asset-eks-cluster",
    relationship: "connects_to",
    weight: 0.4,
    metadata: { integration: "alerting-bot", channel: "#security-alerts" },
    bidirectional: false,
    createdAt: "2025-09-01T10:00:00Z",
  },
  {
    sourceId: "asset-vuln-log4shell",
    targetId: "asset-lambda-processor",
    relationship: "exposed_to",
    weight: 0.9,
    metadata: { component: "log4j-core", version: "2.14.1" },
    bidirectional: false,
    createdAt: "2026-03-01T10:00:00Z",
  },
  {
    sourceId: "asset-vuln-xss-frontend",
    targetId: "asset-repo-frontend",
    relationship: "exposed_to",
    weight: 0.7,
    metadata: { file: "src/components/SearchBar.tsx", line: 42 },
    bidirectional: false,
    createdAt: "2026-02-15T10:00:00Z",
  },
  {
    sourceId: "asset-runtime-k8s-pod",
    targetId: "asset-eks-cluster",
    relationship: "runs_on",
    weight: 0.95,
    metadata: { namespace: "production", node: "ip-10-0-1-45" },
    bidirectional: false,
    createdAt: "2026-03-06T00:12:00Z",
  },
  {
    sourceId: "asset-runtime-guardduty",
    targetId: "asset-iam-deploy-role",
    relationship: "exposed_to",
    weight: 0.85,
    metadata: { findingType: "credential-exfiltration", actionRequired: true },
    bidirectional: false,
    createdAt: "2026-03-05T22:00:00Z",
  },
  {
    sourceId: "asset-remediation-pr-xss",
    targetId: "asset-vuln-xss-frontend",
    relationship: "fixed_by",
    weight: 0.95,
    metadata: { prStatus: "merged", fixVerified: true },
    bidirectional: false,
    createdAt: "2026-02-20T14:00:00Z",
  },
  {
    sourceId: "asset-remediation-ticket-log4j",
    targetId: "asset-vuln-log4shell",
    relationship: "mitigates",
    weight: 0.7,
    metadata: { status: "in_progress", eta: "2026-03-10" },
    bidirectional: false,
    createdAt: "2026-03-01T10:00:00Z",
  },
  {
    sourceId: "asset-saas-jira",
    targetId: "asset-remediation-ticket-log4j",
    relationship: "contains",
    weight: 0.8,
    metadata: { project: "SEC", ticketType: "bug" },
    bidirectional: false,
    createdAt: "2026-03-01T10:00:00Z",
  },
  {
    sourceId: "asset-rds-primary",
    targetId: "asset-iam-app-role",
    relationship: "owned_by",
    weight: 0.8,
    metadata: { ownership: "application-data-owner" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-s3-evidence",
    targetId: "asset-iam-app-role",
    relationship: "owned_by",
    weight: 0.7,
    metadata: { ownership: "evidence-store-owner" },
    bidirectional: false,
    createdAt: "2025-08-10T14:00:00Z",
  },
  {
    sourceId: "asset-endpoint-api",
    targetId: "asset-cognito-pool",
    relationship: "authenticates_with",
    weight: 0.9,
    metadata: { flow: "authorization-code", tokenValidation: "JWT" },
    bidirectional: false,
    createdAt: "2025-08-01T10:00:00Z",
  },
  {
    sourceId: "asset-repo-backend",
    targetId: "asset-vuln-log4shell",
    relationship: "depends_on",
    weight: 0.3,
    metadata: { dependency: "log4j-core", transitive: true, depth: 2 },
    bidirectional: false,
    createdAt: "2026-03-01T10:00:00Z",
  },
  {
    sourceId: "asset-waf-rules",
    targetId: "asset-vuln-xss-frontend",
    relationship: "mitigates",
    weight: 0.6,
    metadata: { rule: "XSS-protection", type: "runtime-mitigation" },
    bidirectional: false,
    createdAt: "2026-02-15T10:00:00Z",
  },
  {
    sourceId: "asset-runtime-guardduty",
    targetId: "asset-sqs-alerts",
    relationship: "triggers",
    weight: 0.8,
    metadata: { eventType: "security-finding", severity: "high" },
    bidirectional: false,
    createdAt: "2026-03-05T22:00:00Z",
  },
];

function buildAdjacency(
  relationships: SecurityRelationship[],
): Map<string, { targetId: string; rel: SecurityRelationship }[]> {
  const adjacency = new Map<string, { targetId: string; rel: SecurityRelationship }[]>();
  for (const rel of relationships) {
    const existing = adjacency.get(rel.sourceId) || [];
    existing.push({ targetId: rel.targetId, rel });
    adjacency.set(rel.sourceId, existing);
  }
  return adjacency;
}

function buildAttackPaths(assets: SecurityAsset[], relationships: SecurityRelationship[]): RankedAttackPath[] {
  const adjacency = buildAdjacency(relationships);
  const assetMap = new Map<string, SecurityAsset>();
  for (const asset of assets) assetMap.set(asset.id, asset);
  const internetFacing = assets.filter(
    (a) =>
      (a.metadata as Record<string, unknown>).internetExposed === true ||
      a.subType === "load_balancer" ||
      a.subType === "cdn" ||
      a.subType === "api_endpoint" ||
      a.subType === "webhook_endpoint",
  );
  const sensitiveTargets = assets.filter(
    (a) =>
      (a.metadata as Record<string, unknown>).dataClassification === "secret" ||
      (a.metadata as Record<string, unknown>).dataClassification === "confidential" ||
      (a.metadata as Record<string, unknown>).dataClassification === "restricted" ||
      a.subType === "secrets_manager" ||
      a.type === "vulnerability",
  );
  const paths: RankedAttackPath[] = [];
  let pathId = 0;
  for (const entry of internetFacing) {
    for (const target of sensitiveTargets) {
      const found = bfsPath(entry.id, target.id, adjacency, assetMap);
      if (found && found.length > 1) {
        const pathNodes = found.map((nid) => assetMap.get(nid)).filter(Boolean) as SecurityAsset[];
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
          id: "apath-" + String(pathId).padStart(3, "0"),
          name: entry.name + " -> " + target.name,
          description: "Attack path from " + entry.subType + " to " + target.subType + " via " + hopCount + " hops",
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

function bfsAllPaths(
  startId: string,
  endId: string,
  adjacency: Map<string, { targetId: string; rel: SecurityRelationship }[]>,
  assetMap: Map<string, SecurityAsset>,
  maxDepth: number,
): string[][] {
  if (startId === endId) return [];
  const results: string[][] = [];
  const queue: { id: string; path: string[] }[] = [{ id: startId, path: [startId] }];
  while (queue.length > 0 && results.length < 10) {
    const current = queue.shift();
    if (!current) break;
    const neighbors = adjacency.get(current.id) || [];
    for (const { targetId } of neighbors) {
      if (current.path.includes(targetId)) continue;
      if (!assetMap.has(targetId)) continue;
      const newPath = [...current.path, targetId];
      if (targetId === endId) {
        results.push(newPath);
        continue;
      }
      if (newPath.length <= maxDepth) queue.push({ id: targetId, path: newPath });
    }
  }
  return results;
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
    if (meta.exploitInWild === true) {
      score += 0.98;
      factors++;
    }
    if (typeof meta.cvss === "number" && meta.cvss >= 9.0) {
      score += 0.95;
      factors++;
    }
    if (typeof meta.epss === "number" && meta.epss >= 0.5) {
      score += 0.85;
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
    if (meta.isOverPrivileged)
      mitigations.push("Reduce permissions on " + node.name + " \u2014 apply least-privilege IAM policy");
    if (meta.publiclyAccessible)
      mitigations.push("Restrict public access on " + node.name + " \u2014 move to private subnet");
    if (meta.mfaEnabled === false) mitigations.push("Enable MFA on " + node.name);
    if (typeof meta.highVulns === "number" && meta.highVulns > 0)
      mitigations.push("Patch " + meta.highVulns + " high-severity vulnerabilities in " + node.name);
    if (meta.exploitInWild === true) mitigations.push("Urgent: patch actively exploited vulnerability in " + node.name);
    if (node.type === "vulnerability" && meta.patchAvailable === true)
      mitigations.push("Apply available patch for " + node.name);
  }
  for (const edge of edges) {
    const meta = edge.metadata as Record<string, unknown>;
    if (meta.encrypted === false)
      mitigations.push("Enable encryption in transit for connection from " + edge.sourceId + " to " + edge.targetId);
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
      if ((node.metadata as Record<string, unknown>).isOverPrivileged) tactics.add("privilege-escalation");
    }
    if (node.type === "network" && node.subType === "load_balancer") tactics.add("discovery");
    if (node.type === "compute") {
      tactics.add("execution");
      tactics.add("lateral-movement");
    }
    if (node.type === "data") {
      tactics.add("collection");
      const classification = (node.metadata as Record<string, unknown>).dataClassification;
      if (classification === "secret" || classification === "confidential") tactics.add("exfiltration");
    }
    if (node.type === "endpoint") tactics.add("command-and-control");
    if (node.type === "vulnerability") {
      tactics.add("exploitation");
      if ((node.metadata as Record<string, unknown>).severity === "critical") tactics.add("impact");
    }
    if (node.type === "runtime") {
      tactics.add("defense-evasion");
      tactics.add("persistence");
    }
  }
  return Array.from(tactics);
}

function computeStats(
  assets: SecurityAsset[],
  relationships: SecurityRelationship[],
  attackPaths: RankedAttackPath[],
): GraphStats {
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
  return {
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
}

export function getSecurityGraph(orgId?: string): SecurityGraphData {
  const effectiveOrgId = orgId || "__default__";
  const store = orgGraphStores.get(effectiveOrgId);
  const catalogAssets: SecurityAsset[] = ASSET_CATALOG.map((a) => ({
    ...a,
    orgId: orgId || null,
  }));
  const catalogRelationships: SecurityRelationship[] = RELATIONSHIP_CATALOG.map((r, i) => ({
    ...r,
    id: "rel-" + String(i + 1).padStart(3, "0"),
  }));
  let allAssets = catalogAssets;
  let allRelationships = catalogRelationships;
  if (store) {
    const ingestedAssets = Array.from(store.assets.values());
    const ingestedRels = Array.from(store.relationships.values());
    const assetIdSet = new Set(ingestedAssets.map((a) => a.id));
    const filteredCatalog = catalogAssets.filter((a) => !assetIdSet.has(a.id));
    allAssets = [...filteredCatalog, ...ingestedAssets];
    const relIdSet = new Set(ingestedRels.map((r) => r.id));
    const filteredCatalogRels = catalogRelationships.filter((r) => !relIdSet.has(r.id));
    allRelationships = [...filteredCatalogRels, ...ingestedRels];
  }
  const attackPaths = buildAttackPaths(allAssets, allRelationships);
  const stats = computeStats(allAssets, allRelationships, attackPaths);
  return { assets: allAssets, relationships: allRelationships, attackPaths, stats };
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
