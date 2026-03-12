/**
 * CSPM Scanner — Real Cloud Connector Integration
 * Replaces mock finding generation with actual AWS/Azure/GCP API calls
 */

import { storage } from "./storage";
import type { InsertCspmScan, InsertCspmFinding } from "@shared/schema";
import { runAwsScan, validateAwsCredentials } from "./cloud-connectors/aws";
import { runAzureScan, validateAzureCredentials } from "./cloud-connectors/azure";
import { runGcpScan, validateGcpCredentials } from "./cloud-connectors/gcp";
import { DriftDetector } from "./cloud-connectors/drift-detector";
import { DspmScanner } from "./cloud-connectors/dspm-scanner";
import { AttackPathAnalyzer } from "./cloud-connectors/attack-path-analyzer";
import { RemediationEngine } from "./cloud-connectors/remediation-engine";
import type { CloudFinding } from "./cloud-connectors/aws";

// Shared instances for cross-scan state
const driftDetector = new DriftDetector();
const dspmScanner = new DspmScanner();
const attackPathAnalyzer = new AttackPathAnalyzer();
const remediationEngine = new RemediationEngine();

// Re-export engines for use in routes
export { driftDetector, dspmScanner, attackPathAnalyzer, remediationEngine };

/**
 * Run a CSPM scan using real cloud connectors.
 */
export async function runCspmScan(orgId: string, accountId: string): Promise<void> {
  const scanData: InsertCspmScan = {
    orgId,
    accountId,
    status: "running",
    findingsCount: 0,
    summary: {},
  };
  const scan = await storage.createCspmScan(scanData);

  const account = await storage.getCspmAccount(accountId);
  if (!account) {
    await storage.updateCspmScan(scan.id, {
      status: "failed",
      completedAt: new Date(),
      summary: { error: "Account not found" },
    });
    return;
  }

  const provider = account.cloudProvider;
  const config = (account.config || {}) as Record<string, unknown>;
  const regions =
    account.regions && account.regions.length > 0
      ? account.regions
      : provider === "aws"
        ? ["us-east-1"]
        : provider === "azure"
          ? ["eastus"]
          : ["us-central1"];

  try {
    let findings: CloudFinding[] = [];

    switch (provider) {
      case "aws": {
        const awsConfig = {
          accessKeyId: (config.accessKeyId as string) || process.env.AWS_ACCESS_KEY_ID || "",
          secretAccessKey: (config.secretAccessKey as string) || process.env.AWS_SECRET_ACCESS_KEY || "",
          regions: regions as string[],
        };

        const validResult = await validateAwsCredentials(awsConfig);
        if (!validResult.valid) {
          await storage.updateCspmScan(scan.id, {
            status: "failed",
            completedAt: new Date(),
            summary: {
              error: "AWS credentials invalid or insufficient permissions",
            },
          });
          return;
        }

        const awsResult = await runAwsScan(awsConfig, accountId);
        findings = awsResult.findings;
        break;
      }

      case "azure": {
        const azureConfig = {
          tenantId: (config.tenantId as string) || "",
          clientId: (config.clientId as string) || "",
          clientSecret: (config.clientSecret as string) || "",
          subscriptionId: (config.subscriptionId as string) || "",
        };

        if (!azureConfig.tenantId || !azureConfig.clientId || !azureConfig.clientSecret) {
          await storage.updateCspmScan(scan.id, {
            status: "failed",
            completedAt: new Date(),
            summary: {
              error: "Azure credentials not configured. Provide tenantId, clientId, clientSecret, subscriptionId.",
            },
          });
          return;
        }

        const validResult = await validateAzureCredentials(azureConfig);
        if (!validResult.valid) {
          await storage.updateCspmScan(scan.id, {
            status: "failed",
            completedAt: new Date(),
            summary: { error: "Azure credentials invalid" },
          });
          return;
        }

        const azureResult = await runAzureScan(azureConfig);
        findings = azureResult.findings;
        break;
      }

      case "gcp": {
        const gcpConfig = {
          projectId: (config.projectId as string) || "",
          serviceAccountKey: (config.serviceAccountKey as string) || "",
        };

        if (!gcpConfig.projectId || !gcpConfig.serviceAccountKey) {
          await storage.updateCspmScan(scan.id, {
            status: "failed",
            completedAt: new Date(),
            summary: {
              error: "GCP credentials not configured. Provide projectId and serviceAccountKey.",
            },
          });
          return;
        }

        const validResult = await validateGcpCredentials(gcpConfig);
        if (!validResult.valid) {
          await storage.updateCspmScan(scan.id, {
            status: "failed",
            completedAt: new Date(),
            summary: { error: "GCP credentials invalid" },
          });
          return;
        }

        const gcpResult = await runGcpScan(gcpConfig);
        findings = gcpResult.findings;
        break;
      }

      default:
        await storage.updateCspmScan(scan.id, {
          status: "failed",
          completedAt: new Date(),
          summary: { error: `Unsupported cloud provider: ${provider}` },
        });
        return;
    }

    // Store findings in the database
    const severityCounts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of findings) {
      const finding: InsertCspmFinding = {
        orgId,
        scanId: scan.id,
        accountId,
        ruleId: f.ruleId,
        ruleName: f.ruleName,
        severity: f.severity,
        resourceType: f.resourceType,
        resourceId: f.resourceId,
        resourceRegion: f.resourceRegion,
        description: f.description,
        remediation: f.remediation,
        complianceFrameworks: f.complianceFrameworks || [],
        status: "open",
      };

      await storage.createCspmFinding(finding);
      const sev = f.severity.toLowerCase();
      if (sev in severityCounts) {
        severityCounts[sev]++;
      }
    }

    // Run attack path analysis on the findings
    const findingsByProvider: Record<string, CloudFinding[]> = {
      [provider]: findings,
    };
    const attackPaths = attackPathAnalyzer.analyzeAttackPaths(findingsByProvider);

    // Store attack paths
    for (const path of attackPaths.paths) {
      await storage.createCspmAttackPath({
        orgId,
        name: path.name,
        description: path.description,
        severity: path.severity,
        riskScore: path.riskScore,
        nodes: path.nodes,
        edges: path.edges,
        mitigations: path.mitigations,
        isCrossCloud:
          path.nodes.length > 1 && path.nodes.some((n, _i, arr) => arr.some((other) => other.provider !== n.provider)),
      });
    }

    await storage.updateCspmScan(scan.id, {
      status: "completed",
      findingsCount: findings.length,
      completedAt: new Date(),
      summary: {
        severityCounts,
        totalFindings: findings.length,
        provider,
        regionsScanned: regions,
        attackPaths: {
          total: attackPaths.totalPaths,
          critical: attackPaths.criticalPaths,
          high: attackPaths.highPaths,
        },
      },
    });

    await storage.updateCspmAccount(accountId, {
      lastScanAt: new Date(),
    });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error(`[CSPM] Scan error for account ${accountId}:`, errorMessage);
    await storage.updateCspmScan(scan.id, {
      status: "failed",
      completedAt: new Date(),
      summary: { error: errorMessage },
    });
  }
}

/**
 * Run a DSPM scan on cloud storage buckets.
 */
export async function runDspmScan(
  orgId: string,
  accountId: string,
): Promise<{
  totalBuckets: number;
  totalObjects: number;
  sensitiveObjects: number;
  findingsCount: number;
}> {
  const account = await storage.getCspmAccount(accountId);
  if (!account) throw new Error("Account not found");
  if (account.orgId !== orgId) throw new Error("Account not found");

  const config = (account.config || {}) as Record<string, unknown>;
  const regions = account.regions && account.regions.length > 0 ? account.regions : ["us-east-1"];

  const awsConfig = {
    accessKeyId: (config.accessKeyId as string) || process.env.AWS_ACCESS_KEY_ID || "",
    secretAccessKey: (config.secretAccessKey as string) || process.env.AWS_SECRET_ACCESS_KEY || "",
    regions: regions as string[],
  };

  const result = await dspmScanner.scanAwsS3(awsConfig);

  for (const f of result.findings) {
    await storage.createCspmDspmFinding({
      orgId,
      accountId,
      resourceId: f.resourceId,
      resourceType: f.resourceType,
      region: f.region,
      dataClassification: f.dataClassification,
      sensitivityLevel: f.sensitivityLevel,
      dataCategories: f.dataCategories,
      objectCount: f.objectCount,
      sampleObjects: f.sampleObjects,
      description: f.description,
      remediation: f.remediation,
    });
  }

  return {
    totalBuckets: result.totalBuckets,
    totalObjects: result.totalObjects,
    sensitiveObjects: result.sensitiveObjects,
    findingsCount: result.findings.length,
  };
}

/**
 * Create a drift detection baseline from the current scan findings.
 */
export async function createDriftBaseline(orgId: string, accountId: string): Promise<number> {
  const account = await storage.getCspmAccount(accountId);
  if (!account) throw new Error("Account not found");
  if (account.orgId !== orgId) throw new Error("Account not found");

  const findings = await storage.getCspmFindings(orgId, undefined, undefined);
  const accountFindings = findings.filter((f) => f.accountId === accountId);

  await storage.deleteCspmDriftBaselines(orgId, accountId);

  let count = 0;
  for (const f of accountFindings) {
    await storage.createCspmDriftBaseline({
      orgId,
      accountId,
      resourceId: f.resourceId,
      resourceType: f.resourceType,
      region: f.resourceRegion || undefined,
      approvedConfig: {
        ruleId: f.ruleId,
        severity: f.severity,
        status: f.status,
        description: f.description,
      },
    });
    count++;
  }

  return count;
}

/**
 * Run drift detection by comparing current scan against baseline.
 */
export async function runDriftDetection(orgId: string, accountId: string): Promise<number> {
  const account = await storage.getCspmAccount(accountId);
  if (!account) throw new Error("Account not found");
  if (account.orgId !== orgId) throw new Error("Account not found");

  const baselines = await storage.getCspmDriftBaselines(orgId, accountId);
  if (baselines.length === 0) {
    throw new Error("No baseline exists for this account. Create a baseline first.");
  }

  const currentFindings = await storage.getCspmFindings(orgId, undefined, undefined);
  const accountFindings = currentFindings.filter((f) => f.accountId === accountId);

  const baselineMap = new Map(baselines.map((b) => [b.resourceId, b]));
  const currentMap = new Map(accountFindings.map((f) => [f.resourceId, f]));

  let driftCount = 0;

  // Check for removed or modified findings
  for (const baseline of baselines) {
    const current = currentMap.get(baseline.resourceId);
    const baseConfig = (baseline.approvedConfig || {}) as Record<string, unknown>;

    if (!current) {
      // Finding was resolved since baseline
      await storage.createCspmDriftEvent({
        orgId,
        accountId,
        resourceId: baseline.resourceId,
        resourceType: baseline.resourceType,
        region: baseline.region || undefined,
        driftType: "removed",
        field: "*",
        baselineValue: baseConfig,
        currentValue: null,
        severity: "medium",
        description: `Finding for resource '${baseline.resourceId}' was resolved since baseline.`,
      });
      driftCount++;
    } else {
      // Check for severity changes
      if (baseConfig.severity !== current.severity) {
        await storage.createCspmDriftEvent({
          orgId,
          accountId,
          resourceId: baseline.resourceId,
          resourceType: baseline.resourceType,
          region: baseline.region || undefined,
          driftType: "modified",
          field: "severity",
          baselineValue: baseConfig.severity as string,
          currentValue: current.severity as string,
          severity: current.severity === "critical" ? "critical" : "high",
          description: `Severity changed from '${baseConfig.severity}' to '${current.severity}'.`,
        });
        driftCount++;
      }

      // Check for status changes
      if (baseConfig.status !== current.status) {
        await storage.createCspmDriftEvent({
          orgId,
          accountId,
          resourceId: baseline.resourceId,
          resourceType: baseline.resourceType,
          region: baseline.region || undefined,
          driftType: "modified",
          field: "status",
          baselineValue: baseConfig.status as string,
          currentValue: current.status as string,
          severity: "medium",
          description: `Status changed from '${baseConfig.status}' to '${current.status}'.`,
        });
        driftCount++;
      }
    }
  }

  // Check for new findings not in baseline
  for (const finding of accountFindings) {
    if (!baselineMap.has(finding.resourceId)) {
      await storage.createCspmDriftEvent({
        orgId,
        accountId,
        resourceId: finding.resourceId,
        resourceType: finding.resourceType,
        region: finding.resourceRegion || undefined,
        driftType: "added",
        field: "*",
        baselineValue: null,
        currentValue: {
          ruleId: finding.ruleId,
          severity: finding.severity,
          status: finding.status,
        },
        severity: finding.severity === "critical" ? "critical" : "high",
        description: `New finding for '${finding.resourceId}' (${finding.ruleId}) not in baseline.`,
      });
      driftCount++;
    }
  }

  return driftCount;
}
