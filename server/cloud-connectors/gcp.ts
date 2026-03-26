/**
 * GCP Cloud Connector
 * REST API calls to Security Command Center, Cloud Audit Logs, Compute, Storage, IAM
 */

import type { CloudFinding, CloudResource } from "./aws";
import { logger } from "../logger";

const log = logger.child("cloud-connector-gcp");

export interface GcpConnectorConfig {
  projectId: string;
  serviceAccountKey: string; // JSON key file contents
}

interface GcpTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface ServiceAccountKey {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
}

const gcpTokenCache = new Map<string, { token: string; expiresAt: number }>();

function gcpCacheKey(config: GcpConnectorConfig): string {
  try {
    const parsed = JSON.parse(config.serviceAccountKey) as { client_email?: string };
    return `${config.projectId}:${parsed.client_email || "unknown"}`;
  } catch {
    return `${config.projectId}:unknown`;
  }
}

/** Create a JWT and exchange it for an access token */
async function getGcpToken(config: GcpConnectorConfig): Promise<string> {
  const key = gcpCacheKey(config);
  const cached = gcpTokenCache.get(key);
  if (cached && Date.now() < cached.expiresAt - 60_000) {
    return cached.token;
  }

  let keyData: ServiceAccountKey;
  try {
    keyData = JSON.parse(config.serviceAccountKey);
  } catch {
    throw new Error("Invalid GCP service account key JSON");
  }

  // Create JWT header and claims
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: keyData.client_email,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: keyData.token_uri || "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  // Use Node.js crypto to sign JWT
  const { createSign } = await import("crypto");

  const encodeBase64Url = (data: string) => Buffer.from(data).toString("base64url");

  const headerB64 = encodeBase64Url(JSON.stringify(header));
  const claimsB64 = encodeBase64Url(JSON.stringify(claims));
  const unsignedToken = `${headerB64}.${claimsB64}`;

  const sign = createSign("RSA-SHA256");
  sign.update(unsignedToken);
  const signature = sign.sign(keyData.private_key, "base64url");

  const jwt = `${unsignedToken}.${signature}`;

  const tokenUrl = keyData.token_uri || "https://oauth2.googleapis.com/token";
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: jwt,
  });

  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`GCP auth failed: ${resp.status} ${text}`);
  }

  const data: GcpTokenResponse = await resp.json();
  gcpTokenCache.set(key, {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  });
  return data.access_token;
}

async function gcpGet(config: GcpConnectorConfig, url: string): Promise<unknown> {
  const token = await getGcpToken(config);
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`GCP API error: ${resp.status} ${text}`);
  }

  return resp.json();
}

/** Validate GCP credentials */
export async function validateGcpCredentials(config: GcpConnectorConfig): Promise<{
  valid: boolean;
  projectId?: string;
  error?: string;
}> {
  try {
    const project = (await gcpGet(
      config,
      `https://cloudresourcemanager.googleapis.com/v1/projects/${config.projectId}`,
    )) as { projectId?: string; name?: string };
    return {
      valid: true,
      projectId: project.projectId || config.projectId,
    };
  } catch (err: unknown) {
    return { valid: false, error: err instanceof Error ? err.message : "Unknown error" };
  }
}

/** Fetch Security Command Center findings */
export async function scanGcpSCC(config: GcpConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await gcpGet(
      config,
      `https://securitycenter.googleapis.com/v1/projects/${config.projectId}/sources/-/findings?filter=state%3D%22ACTIVE%22&pageSize=100`,
    )) as {
      listFindingsResults?: Array<{
        finding?: {
          name?: string;
          category?: string;
          severity?: string;
          resourceName?: string;
          description?: string;
          sourceProperties?: Record<string, unknown>;
          state?: string;
          createTime?: string;
          findingClass?: string;
        };
      }>;
    };

    for (const result of resp.listFindingsResults || []) {
      const f = result.finding;
      if (!f) continue;

      const gcpSeverity = (f.severity || "MEDIUM").toUpperCase();
      let severity: CloudFinding["severity"] = "medium";
      if (gcpSeverity === "CRITICAL") severity = "critical";
      else if (gcpSeverity === "HIGH") severity = "high";
      else if (gcpSeverity === "LOW") severity = "low";

      findings.push({
        ruleId: `GCP-SCC-${f.category || "UNKNOWN"}`.substring(0, 50),
        ruleName: f.category || "GCP Security Finding",
        severity,
        resourceType: inferGcpResourceType(f.resourceName || ""),
        resourceId: f.resourceName || f.name || "unknown",
        resourceRegion: extractGcpRegion(f.resourceName || ""),
        description: f.description || `Security Command Center finding: ${f.category}`,
        remediation: `Review the ${f.category} finding in GCP Security Command Center and remediate the affected resource.`,
        complianceFrameworks: ["cis", "nist"],
        rawData: {
          findingClass: f.findingClass,
          createTime: f.createTime,
          state: f.state,
        },
      });
    }
  } catch (err: unknown) {
    log.error("SCC scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan GCP compute firewall rules */
export async function scanGcpFirewalls(config: GcpConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await gcpGet(
      config,
      `https://compute.googleapis.com/compute/v1/projects/${config.projectId}/global/firewalls`,
    )) as {
      items?: Array<{
        id?: string;
        name?: string;
        direction?: string;
        sourceRanges?: string[];
        allowed?: Array<{ IPProtocol?: string; ports?: string[] }>;
        disabled?: boolean;
        network?: string;
      }>;
    };

    for (const fw of resp.items || []) {
      if (fw.disabled) continue;
      if (fw.direction !== "INGRESS") continue;

      const hasOpenSource = fw.sourceRanges?.includes("0.0.0.0/0");
      if (!hasOpenSource) continue;

      const fwName = fw.name || "unknown";
      const fwId = `projects/${config.projectId}/global/firewalls/${fwName}`;

      for (const rule of fw.allowed || []) {
        const ports = rule.ports || [];
        const protocol = rule.IPProtocol || "all";

        if (protocol === "all" && ports.length === 0) {
          findings.push({
            ruleId: "GCP-FW-002",
            ruleName: "Firewall Rule Allows All Protocols and Ports",
            severity: "critical",
            resourceType: "gcp:compute:firewall",
            resourceId: fwId,
            resourceRegion: "global",
            description: `Firewall rule '${fwName}' allows all traffic from 0.0.0.0/0 on all ports and protocols.`,
            remediation: "Specify allowed protocols and port ranges. Follow the principle of least privilege.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          });
          continue;
        }

        for (const port of ports) {
          if (portMatchesTarget(port, 22)) {
            findings.push({
              ruleId: "GCP-FW-003",
              ruleName: "Firewall Rule Allows SSH from Internet",
              severity: "high",
              resourceType: "gcp:compute:firewall",
              resourceId: fwId,
              resourceRegion: "global",
              description: `Firewall rule '${fwName}' allows SSH (port 22) from 0.0.0.0/0.`,
              remediation: "Use Identity-Aware Proxy (IAP) for SSH access instead of direct internet exposure.",
              complianceFrameworks: ["cis", "nist", "soc2"],
            });
          }
          if (portMatchesTarget(port, 3389)) {
            findings.push({
              ruleId: "GCP-FW-004",
              ruleName: "Firewall Rule Allows RDP from Internet",
              severity: "critical",
              resourceType: "gcp:compute:firewall",
              resourceId: fwId,
              resourceRegion: "global",
              description: `Firewall rule '${fwName}' allows RDP (port 3389) from 0.0.0.0/0.`,
              remediation: "Remove the RDP rule. Use IAP or a VPN for remote desktop access.",
              complianceFrameworks: ["cis", "nist", "pci_dss"],
            });
          }
        }
      }
    }
  } catch (err: unknown) {
    log.error("Firewall scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan GCP storage buckets */
export async function scanGcpStorage(config: GcpConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await gcpGet(config, `https://storage.googleapis.com/storage/v1/b?project=${config.projectId}`)) as {
      items?: Array<{
        id?: string;
        name?: string;
        location?: string;
        iamConfiguration?: {
          uniformBucketLevelAccess?: { enabled?: boolean };
          publicAccessPrevention?: string;
        };
        encryption?: { defaultKmsKeyName?: string };
        versioning?: { enabled?: boolean };
        logging?: { logBucket?: string };
      }>;
    };

    for (const bucket of resp.items || []) {
      const name = bucket.name || "unknown";
      const region = bucket.location || "global";
      const bucketId = `projects/${config.projectId}/buckets/${name}`;

      if (!bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled) {
        findings.push({
          ruleId: "GCP-GCS-001",
          ruleName: "Cloud Storage Bucket Uniform Access Disabled",
          severity: "medium",
          resourceType: "gcp:storage:bucket",
          resourceId: bucketId,
          resourceRegion: region,
          description: `Bucket '${name}' does not have uniform bucket-level access enabled. Mixed ACL and IAM permissions create complexity.`,
          remediation: "Enable uniform bucket-level access to use IAM exclusively for access control.",
          complianceFrameworks: ["cis", "nist", "soc2"],
        });
      }

      if (bucket.iamConfiguration?.publicAccessPrevention !== "enforced") {
        findings.push({
          ruleId: "GCP-GCS-003",
          ruleName: "Cloud Storage Public Access Prevention Not Enforced",
          severity: "high",
          resourceType: "gcp:storage:bucket",
          resourceId: bucketId,
          resourceRegion: region,
          description: `Bucket '${name}' does not enforce public access prevention. Objects may be publicly accessible.`,
          remediation: "Set public access prevention to 'enforced' on the bucket to prevent public access.",
          complianceFrameworks: ["cis", "nist", "pci_dss"],
        });
      }

      if (!bucket.versioning?.enabled) {
        findings.push({
          ruleId: "GCP-GCS-004",
          ruleName: "Cloud Storage Versioning Not Enabled",
          severity: "medium",
          resourceType: "gcp:storage:bucket",
          resourceId: bucketId,
          resourceRegion: region,
          description: `Bucket '${name}' does not have object versioning enabled. Accidental deletion is irrecoverable.`,
          remediation: "Enable object versioning on the bucket to protect against accidental data loss.",
          complianceFrameworks: ["cis", "nist"],
        });
      }
    }
  } catch (err: unknown) {
    log.error("Storage scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan GCP Cloud SQL instances */
export async function scanGcpCloudSQL(config: GcpConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await gcpGet(
      config,
      `https://sqladmin.googleapis.com/v1/projects/${config.projectId}/instances`,
    )) as {
      items?: Array<{
        name?: string;
        connectionName?: string;
        region?: string;
        databaseVersion?: string;
        settings?: {
          ipConfiguration?: {
            ipv4Enabled?: boolean;
            requireSsl?: boolean;
            authorizedNetworks?: Array<{ value?: string; name?: string }>;
          };
          backupConfiguration?: { enabled?: boolean; pointInTimeRecoveryEnabled?: boolean };
          dataDiskSizeGb?: string;
        };
      }>;
    };

    for (const instance of resp.items || []) {
      const name = instance.name || "unknown";
      const region = instance.region || "global";
      const instanceId = `projects/${config.projectId}/instances/${name}`;

      if (instance.settings?.ipConfiguration?.ipv4Enabled) {
        findings.push({
          ruleId: "GCP-SQL-001",
          ruleName: "Cloud SQL Instance Has Public IP Address",
          severity: "high",
          resourceType: "gcp:sql:instance",
          resourceId: instanceId,
          resourceRegion: region,
          description: `Cloud SQL instance '${name}' has a public IP address. Direct internet access to databases is a security risk.`,
          remediation: "Use Private IP only. Connect via Cloud SQL Proxy or Private Service Connect.",
          complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
        });
      }

      if (!instance.settings?.ipConfiguration?.requireSsl) {
        findings.push({
          ruleId: "GCP-SQL-002",
          ruleName: "Cloud SQL SSL Not Required",
          severity: "high",
          resourceType: "gcp:sql:instance",
          resourceId: instanceId,
          resourceRegion: region,
          description: `Cloud SQL instance '${name}' does not require SSL for connections. Unencrypted connections are vulnerable to interception.`,
          remediation: "Enable 'Require SSL' on the Cloud SQL instance to enforce encrypted connections.",
          complianceFrameworks: ["cis", "nist", "pci_dss"],
        });
      }

      // Check for authorized networks with 0.0.0.0/0
      const networks = instance.settings?.ipConfiguration?.authorizedNetworks || [];
      for (const net of networks) {
        if (net.value === "0.0.0.0/0") {
          findings.push({
            ruleId: "GCP-SQL-003",
            ruleName: "Cloud SQL Allows Access from All IPs",
            severity: "critical",
            resourceType: "gcp:sql:instance",
            resourceId: instanceId,
            resourceRegion: region,
            description: `Cloud SQL instance '${name}' has authorized network 0.0.0.0/0, allowing access from any IP address.`,
            remediation: "Remove the 0.0.0.0/0 authorized network. Use specific IP ranges or Private IP.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          });
        }
      }

      if (!instance.settings?.backupConfiguration?.enabled) {
        findings.push({
          ruleId: "GCP-SQL-004",
          ruleName: "Cloud SQL Automated Backups Disabled",
          severity: "medium",
          resourceType: "gcp:sql:instance",
          resourceId: instanceId,
          resourceRegion: region,
          description: `Cloud SQL instance '${name}' does not have automated backups enabled.`,
          remediation: "Enable automated backups and point-in-time recovery for the Cloud SQL instance.",
          complianceFrameworks: ["nist", "soc2"],
        });
      }
    }
  } catch (err: unknown) {
    log.error("Cloud SQL scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Run a full GCP CSPM scan */
export async function runGcpScan(
  config: GcpConnectorConfig,
): Promise<{ findings: CloudFinding[]; resources: CloudResource[] }> {
  const [sccFindings, firewallFindings, storageFindings, sqlFindings] = await Promise.all([
    scanGcpSCC(config),
    scanGcpFirewalls(config),
    scanGcpStorage(config),
    scanGcpCloudSQL(config),
  ]);

  return {
    findings: [...sccFindings, ...firewallFindings, ...storageFindings, ...sqlFindings],
    resources: [],
  };
}

// Helper functions

/** Check if a port spec (e.g. "22", "20-25") matches a target port number */
function portMatchesTarget(portSpec: string, target: number): boolean {
  if (portSpec.includes("-")) {
    const [startStr, endStr] = portSpec.split("-");
    const start = parseInt(startStr, 10);
    const end = parseInt(endStr, 10);
    if (!isNaN(start) && !isNaN(end)) {
      return target >= start && target <= end;
    }
    return false;
  }
  return parseInt(portSpec, 10) === target;
}

function inferGcpResourceType(resourceName: string): string {
  if (resourceName.includes("/buckets/")) return "gcp:storage:bucket";
  if (resourceName.includes("/firewalls/")) return "gcp:compute:firewall";
  if (resourceName.includes("/instances/") && resourceName.includes("sqladmin")) return "gcp:sql:instance";
  if (resourceName.includes("/instances/")) return "gcp:compute:instance";
  if (resourceName.includes("/serviceAccounts/")) return "gcp:iam:service-account";
  return "gcp:unknown";
}

function extractGcpRegion(resourceName: string): string {
  const match = resourceName.match(/\/locations\/([^/]+)/);
  if (match) return match[1];
  const zoneMatch = resourceName.match(/\/zones\/([^/]+)/);
  if (zoneMatch) return zoneMatch[1];
  return "global";
}
