/**
 * Drift Detection Engine
 * Compares current cloud resource configuration against approved baselines
 * Detects unauthorized changes, configuration drift, and compliance violations
 */

import type { CloudResource } from "./aws";

export interface DriftBaseline {
  id: string;
  orgId: string;
  accountId: string;
  resourceId: string;
  resourceType: string;
  region: string;
  approvedConfig: Record<string, unknown>;
  snapshotAt: Date;
}

export interface DriftResult {
  resourceId: string;
  resourceType: string;
  region: string;
  driftType: "added" | "removed" | "modified";
  field: string;
  baselineValue: unknown;
  currentValue: unknown;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  detectedAt: Date;
}

/** Critical fields that indicate high-severity drift when changed */
const CRITICAL_FIELDS: Record<string, string[]> = {
  "aws:ec2:security-group": ["IpPermissions", "IpPermissionsEgress"],
  "aws:s3:bucket": ["publicAccessBlock", "encryption", "policy"],
  "aws:iam:user": ["AttachedPolicies", "MFADevices"],
  "aws:rds:db-instance": ["PubliclyAccessible", "StorageEncrypted"],
  "aws:ec2:instance": ["SecurityGroups", "IamInstanceProfile"],
  "azure:network:nsg": ["securityRules"],
  "azure:storage:account": ["allowBlobPublicAccess", "networkAcls"],
  "gcp:compute:firewall": ["allowed", "sourceRanges"],
  "gcp:storage:bucket": ["iamConfiguration", "encryption"],
};

/** Severity classification for drift changes */
const HIGH_SEVERITY_PATTERNS = [
  /public/i,
  /encrypt/i,
  /security/i,
  /firewall/i,
  /access/i,
  /policy/i,
  /iam/i,
  /password/i,
  /mfa/i,
  /ssl/i,
  /tls/i,
];

export class DriftDetector {
  private baselines: Map<string, DriftBaseline> = new Map();

  /** Store a baseline snapshot for a resource */
  setBaseline(baseline: DriftBaseline): void {
    this.baselines.set(`${baseline.accountId}:${baseline.resourceId}`, baseline);
  }

  /** Load baselines from stored data */
  loadBaselines(baselines: DriftBaseline[]): void {
    for (const b of baselines) {
      this.baselines.set(`${b.accountId}:${b.resourceId}`, b);
    }
  }

  /** Get all baselines for an account */
  getBaselines(accountId: string): DriftBaseline[] {
    return Array.from(this.baselines.values()).filter((b) => b.accountId === accountId);
  }

  /** Compare current resources against baselines and detect drift */
  detectDrift(accountId: string, currentResources: CloudResource[]): DriftResult[] {
    const results: DriftResult[] = [];
    const currentById = new Map(currentResources.map((r) => [r.resourceId, r]));
    const accountBaselines = this.getBaselines(accountId);

    // Check for modified and removed resources
    for (const baseline of accountBaselines) {
      const current = currentById.get(baseline.resourceId);

      if (!current) {
        // Resource was removed
        results.push({
          resourceId: baseline.resourceId,
          resourceType: baseline.resourceType,
          region: baseline.region,
          driftType: "removed",
          field: "*",
          baselineValue: baseline.approvedConfig,
          currentValue: null,
          severity: "high",
          description: `Resource '${baseline.resourceId}' (${baseline.resourceType}) was removed or is no longer discoverable.`,
          detectedAt: new Date(),
        });
        continue;
      }

      // Compare configurations field by field
      const diffs = deepCompare(baseline.approvedConfig, current.configuration, "");

      for (const diff of diffs) {
        const severity = classifyDriftSeverity(baseline.resourceType, diff.field);

        results.push({
          resourceId: baseline.resourceId,
          resourceType: baseline.resourceType,
          region: baseline.region,
          driftType: "modified",
          field: diff.field,
          baselineValue: diff.baselineValue,
          currentValue: diff.currentValue,
          severity,
          description: `Configuration drift detected on '${baseline.resourceId}': field '${diff.field}' changed from ${JSON.stringify(diff.baselineValue)} to ${JSON.stringify(diff.currentValue)}.`,
          detectedAt: new Date(),
        });
      }
    }

    // Check for new resources not in baseline
    const baselineIds = new Set(accountBaselines.map((b) => b.resourceId));
    for (const resource of currentResources) {
      if (!baselineIds.has(resource.resourceId)) {
        results.push({
          resourceId: resource.resourceId,
          resourceType: resource.resourceType,
          region: resource.region,
          driftType: "added",
          field: "*",
          baselineValue: null,
          currentValue: resource.configuration,
          severity: "medium",
          description: `New resource '${resource.resourceId}' (${resource.resourceType}) discovered that is not in the approved baseline.`,
          detectedAt: new Date(),
        });
      }
    }

    return results;
  }

  /** Create baseline snapshots from current resources */
  createBaselines(orgId: string, accountId: string, resources: CloudResource[]): DriftBaseline[] {
    const baselines: DriftBaseline[] = [];
    for (const resource of resources) {
      const baseline: DriftBaseline = {
        id: `baseline-${accountId}-${resource.resourceId}-${Date.now()}`,
        orgId,
        accountId,
        resourceId: resource.resourceId,
        resourceType: resource.resourceType,
        region: resource.region,
        approvedConfig: resource.configuration,
        snapshotAt: new Date(),
      };
      this.setBaseline(baseline);
      baselines.push(baseline);
    }
    return baselines;
  }
}

interface FieldDiff {
  field: string;
  baselineValue: unknown;
  currentValue: unknown;
}

/** Deep compare two objects and return field-level differences */
function deepCompare(baseline: Record<string, unknown>, current: Record<string, unknown>, prefix: string): FieldDiff[] {
  const diffs: FieldDiff[] = [];
  const allKeys = Array.from(new Set([...Object.keys(baseline), ...Object.keys(current)]));

  for (const key of allKeys) {
    const fullPath = prefix ? `${prefix}.${key}` : key;
    const bVal = baseline[key];
    const cVal = current[key];

    if (bVal === undefined && cVal !== undefined) {
      diffs.push({ field: fullPath, baselineValue: undefined, currentValue: cVal });
    } else if (bVal !== undefined && cVal === undefined) {
      diffs.push({ field: fullPath, baselineValue: bVal, currentValue: undefined });
    } else if (
      typeof bVal === "object" &&
      bVal !== null &&
      typeof cVal === "object" &&
      cVal !== null &&
      !Array.isArray(bVal) &&
      !Array.isArray(cVal)
    ) {
      diffs.push(...deepCompare(bVal as Record<string, unknown>, cVal as Record<string, unknown>, fullPath));
    } else if (JSON.stringify(bVal) !== JSON.stringify(cVal)) {
      diffs.push({ field: fullPath, baselineValue: bVal, currentValue: cVal });
    }
  }

  return diffs;
}

/** Classify drift severity based on resource type and field */
function classifyDriftSeverity(resourceType: string, field: string): DriftResult["severity"] {
  const criticalFields = CRITICAL_FIELDS[resourceType] || [];
  const fieldLower = field.toLowerCase();

  // Check if the field is in the critical list for this resource type
  for (const cf of criticalFields) {
    if (fieldLower.includes(cf.toLowerCase())) return "critical";
  }

  // Check against high-severity patterns
  for (const pattern of HIGH_SEVERITY_PATTERNS) {
    if (pattern.test(field)) return "high";
  }

  return "medium";
}
