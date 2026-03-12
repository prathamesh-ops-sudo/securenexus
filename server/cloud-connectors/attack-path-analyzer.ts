/**
 * Multi-Cloud Attack Path Analyzer
 * Identifies lateral movement opportunities across cloud providers
 * Maps trust relationships, federated identities, and cross-account pivots
 */

import type { CloudFinding } from "./aws";

export interface AttackPathNode {
  id: string;
  provider: "aws" | "azure" | "gcp";
  resourceType: string;
  resourceId: string;
  name: string;
  riskScore: number;
  vulnerabilities: string[];
  permissions: string[];
}

export interface AttackPathEdge {
  from: string;
  to: string;
  edgeType: "trust" | "federation" | "network" | "permission" | "credential" | "lateral_movement";
  description: string;
  riskScore: number;
}

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  riskScore: number;
  mitigations: string[];
  detectedAt: Date;
}

export interface AttackPathAnalysis {
  totalPaths: number;
  criticalPaths: number;
  highPaths: number;
  paths: AttackPath[];
  crossCloudPaths: AttackPath[];
  analyzedAt: Date;
}

/** Known cross-cloud trust patterns */
const CROSS_CLOUD_PATTERNS = [
  {
    name: "AWS-to-Azure Federated Identity",
    from: "aws",
    to: "azure",
    condition: (findings: CloudFinding[]) =>
      findings.some(
        (f) =>
          f.resourceType.includes("iam") &&
          (f.description.toLowerCase().includes("federat") || f.description.toLowerCase().includes("saml")),
      ),
    description: "AWS IAM federated identity can be used to pivot to Azure AD via SAML/OIDC trust",
  },
  {
    name: "Azure-to-GCP Service Account",
    from: "azure",
    to: "gcp",
    condition: (findings: CloudFinding[]) =>
      findings.some((f) => f.resourceType.includes("keyvault") || f.resourceType.includes("service-account")),
    description: "Azure Key Vault may store GCP service account keys, enabling cross-cloud pivot",
  },
  {
    name: "GCP-to-AWS Cross-Account Access",
    from: "gcp",
    to: "aws",
    condition: (findings: CloudFinding[]) =>
      findings.some(
        (f) =>
          f.resourceType.includes("iam") &&
          (f.description.toLowerCase().includes("cross-account") || f.description.toLowerCase().includes("assume")),
      ),
    description: "GCP workload identity federation can be configured to assume AWS IAM roles",
  },
];

export class AttackPathAnalyzer {
  /** Analyze findings across all cloud providers to identify attack paths */
  analyzeAttackPaths(findingsByProvider: Record<string, CloudFinding[]>): AttackPathAnalysis {
    const paths: AttackPath[] = [];
    const crossCloudPaths: AttackPath[] = [];
    let pathCounter = 0;

    // Analyze per-provider attack paths
    for (const [provider, findings] of Object.entries(findingsByProvider)) {
      const providerPaths = this.analyzeProviderPaths(provider, findings);
      paths.push(...providerPaths);
    }

    // Analyze cross-cloud attack paths
    const allFindings = Object.values(findingsByProvider).flat();

    for (const pattern of CROSS_CLOUD_PATTERNS) {
      const fromFindings = findingsByProvider[pattern.from] || [];
      const toFindings = findingsByProvider[pattern.to] || [];

      if (fromFindings.length > 0 && toFindings.length > 0) {
        if (pattern.condition(allFindings)) {
          pathCounter++;
          const crossPath = this.buildCrossCloudPath(`cross-${pathCounter}`, pattern, fromFindings, toFindings);
          crossCloudPaths.push(crossPath);
          paths.push(crossPath);
        }
      }
    }

    // Also analyze based on misconfiguration chains
    const misconfigPaths = this.analyzeMisconfigChains(findingsByProvider);
    paths.push(...misconfigPaths);

    const criticalPaths = paths.filter((p) => p.severity === "critical").length;
    const highPaths = paths.filter((p) => p.severity === "high").length;

    return {
      totalPaths: paths.length,
      criticalPaths,
      highPaths,
      paths,
      crossCloudPaths,
      analyzedAt: new Date(),
    };
  }

  /** Analyze attack paths within a single cloud provider */
  private analyzeProviderPaths(provider: string, findings: CloudFinding[]): AttackPath[] {
    const paths: AttackPath[] = [];

    // Group findings by resource
    const byResource = new Map<string, CloudFinding[]>();
    for (const f of findings) {
      const key = f.resourceId;
      const existing = byResource.get(key) || [];
      existing.push(f);
      byResource.set(key, existing);
    }

    // Look for privilege escalation paths: public access -> data exposure
    const publicAccessFindings = findings.filter(
      (f) =>
        f.description.toLowerCase().includes("public") ||
        f.description.toLowerCase().includes("unrestricted") ||
        f.description.toLowerCase().includes("0.0.0.0"),
    );

    const dataFindings = findings.filter(
      (f) =>
        f.resourceType.includes("s3") ||
        f.resourceType.includes("storage") ||
        f.resourceType.includes("rds") ||
        f.resourceType.includes("sql"),
    );

    if (publicAccessFindings.length > 0 && dataFindings.length > 0) {
      const nodes: AttackPathNode[] = [];
      const edges: AttackPathEdge[] = [];

      // Entry point: public-facing resource
      const entryFinding = publicAccessFindings[0];
      const entryNode: AttackPathNode = {
        id: `node-entry-${provider}`,
        provider: provider as "aws" | "azure" | "gcp",
        resourceType: entryFinding.resourceType,
        resourceId: entryFinding.resourceId,
        name: `Public ${entryFinding.resourceType}`,
        riskScore: 9,
        vulnerabilities: [entryFinding.ruleId],
        permissions: ["public_access"],
      };
      nodes.push(entryNode);

      // Target: data store
      const dataFinding = dataFindings[0];
      const dataNode: AttackPathNode = {
        id: `node-data-${provider}`,
        provider: provider as "aws" | "azure" | "gcp",
        resourceType: dataFinding.resourceType,
        resourceId: dataFinding.resourceId,
        name: `${dataFinding.resourceType} data store`,
        riskScore: 8,
        vulnerabilities: [dataFinding.ruleId],
        permissions: ["data_access"],
      };
      nodes.push(dataNode);

      edges.push({
        from: entryNode.id,
        to: dataNode.id,
        edgeType: "network",
        description: "Public network access can reach data resources via network connectivity",
        riskScore: 8,
      });

      paths.push({
        id: `path-${provider}-public-to-data`,
        name: `Public Access to Data Store (${provider.toUpperCase()})`,
        description: `An attacker can exploit public access on ${entryFinding.resourceType} to potentially reach ${dataFinding.resourceType} data stores via network or permission escalation.`,
        severity: "high",
        nodes,
        edges,
        riskScore: 85,
        mitigations: [
          "Remove public access from all cloud resources",
          "Enable encryption at rest and in transit",
          "Implement network segmentation with private subnets",
          "Enable audit logging for all data access",
        ],
        detectedAt: new Date(),
      });
    }

    // Look for IAM escalation paths
    const iamFindings = findings.filter((f) => f.resourceType.includes("iam"));
    const criticalPerms = iamFindings.filter(
      (f) =>
        f.description.toLowerCase().includes("admin") ||
        f.description.toLowerCase().includes("unrestricted") ||
        f.description.toLowerCase().includes("all"),
    );

    if (criticalPerms.length > 0) {
      const nodes: AttackPathNode[] = [];
      const edges: AttackPathEdge[] = [];

      const iamNode: AttackPathNode = {
        id: `node-iam-${provider}`,
        provider: provider as "aws" | "azure" | "gcp",
        resourceType: criticalPerms[0].resourceType,
        resourceId: criticalPerms[0].resourceId,
        name: "Over-privileged Identity",
        riskScore: 9,
        vulnerabilities: criticalPerms.map((f) => f.ruleId),
        permissions: ["admin_access"],
      };
      nodes.push(iamNode);

      const allResourcesNode: AttackPathNode = {
        id: `node-all-resources-${provider}`,
        provider: provider as "aws" | "azure" | "gcp",
        resourceType: `${provider}:all:resources`,
        resourceId: `all-resources-${provider}`,
        name: "All Cloud Resources",
        riskScore: 10,
        vulnerabilities: [],
        permissions: ["full_access"],
      };
      nodes.push(allResourcesNode);

      edges.push({
        from: iamNode.id,
        to: allResourcesNode.id,
        edgeType: "permission",
        description: "Admin-level permissions grant access to all resources in the account",
        riskScore: 10,
      });

      paths.push({
        id: `path-${provider}-iam-escalation`,
        name: `IAM Privilege Escalation (${provider.toUpperCase()})`,
        description: `Over-privileged IAM identity (${criticalPerms[0].resourceId}) has admin-level access that can be exploited to access all resources.`,
        severity: "critical",
        nodes,
        edges,
        riskScore: 95,
        mitigations: [
          "Apply principle of least privilege to all IAM identities",
          "Remove AdministratorAccess policies from users",
          "Enable MFA for all IAM users",
          "Use temporary credentials via IAM roles instead of long-lived access keys",
          "Implement SCPs/permission boundaries to limit blast radius",
        ],
        detectedAt: new Date(),
      });
    }

    return paths;
  }

  /** Build a cross-cloud attack path from a pattern match */
  private buildCrossCloudPath(
    id: string,
    pattern: (typeof CROSS_CLOUD_PATTERNS)[0],
    fromFindings: CloudFinding[],
    toFindings: CloudFinding[],
  ): AttackPath {
    const fromFinding = fromFindings[0];
    const toFinding = toFindings[0];

    const nodes: AttackPathNode[] = [
      {
        id: `node-from-${pattern.from}`,
        provider: pattern.from as "aws" | "azure" | "gcp",
        resourceType: fromFinding.resourceType,
        resourceId: fromFinding.resourceId,
        name: `${pattern.from.toUpperCase()} Resource`,
        riskScore: 8,
        vulnerabilities: [fromFinding.ruleId],
        permissions: [],
      },
      {
        id: `node-to-${pattern.to}`,
        provider: pattern.to as "aws" | "azure" | "gcp",
        resourceType: toFinding.resourceType,
        resourceId: toFinding.resourceId,
        name: `${pattern.to.toUpperCase()} Resource`,
        riskScore: 8,
        vulnerabilities: [toFinding.ruleId],
        permissions: [],
      },
    ];

    const edges: AttackPathEdge[] = [
      {
        from: nodes[0].id,
        to: nodes[1].id,
        edgeType: "federation",
        description: pattern.description,
        riskScore: 9,
      },
    ];

    return {
      id,
      name: pattern.name,
      description: `Cross-cloud attack path: ${pattern.description}. An attacker who compromises a ${pattern.from.toUpperCase()} resource can potentially pivot to ${pattern.to.toUpperCase()}.`,
      severity: "critical",
      nodes,
      edges,
      riskScore: 90,
      mitigations: [
        "Review and minimize cross-cloud trust relationships",
        "Implement conditional access policies for federated identities",
        "Enable MFA for all cross-cloud authentication",
        "Monitor cross-cloud API calls for anomalies",
        "Use short-lived tokens for cross-cloud access",
      ],
      detectedAt: new Date(),
    };
  }

  /** Analyze misconfiguration chains that create attack paths */
  private analyzeMisconfigChains(findingsByProvider: Record<string, CloudFinding[]>): AttackPath[] {
    const paths: AttackPath[] = [];
    const allFindings = Object.values(findingsByProvider).flat();

    // Check for encryption gaps across providers
    const encryptionFindings = allFindings.filter((f) => f.description.toLowerCase().includes("encrypt"));

    if (encryptionFindings.length >= 3) {
      const nodes = encryptionFindings.slice(0, 5).map((f, i) => ({
        id: `node-encrypt-${i}`,
        provider: (f.resourceType.startsWith("aws") ? "aws" : f.resourceType.startsWith("azure") ? "azure" : "gcp") as
          | "aws"
          | "azure"
          | "gcp",
        resourceType: f.resourceType,
        resourceId: f.resourceId,
        name: `Unencrypted: ${f.resourceType}`,
        riskScore: 7,
        vulnerabilities: [f.ruleId],
        permissions: [],
      }));

      const edges = nodes.slice(1).map((n, i) => ({
        from: nodes[i].id,
        to: n.id,
        edgeType: "lateral_movement" as const,
        description: "Data can flow between unencrypted resources without protection",
        riskScore: 7,
      }));

      paths.push({
        id: "path-encryption-gap",
        name: "Multi-Resource Encryption Gap",
        description: `${encryptionFindings.length} resources lack encryption across cloud providers, creating a data exposure chain.`,
        severity: "high",
        nodes,
        edges,
        riskScore: 75,
        mitigations: [
          "Enable encryption at rest for all storage resources",
          "Enable encryption in transit for all network communications",
          "Use customer-managed keys (CMK) for sensitive data",
          "Implement key rotation policies",
        ],
        detectedAt: new Date(),
      });
    }

    return paths;
  }
}
