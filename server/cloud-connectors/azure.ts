/**
 * Azure Cloud Connector
 * REST API calls to Azure Defender, Azure Policy, Azure Monitor
 * Uses Azure Resource Manager (ARM) REST API with bearer token authentication
 */

import type { CloudFinding, CloudResource } from "./aws";
import { logger } from "../logger";

const log = logger.child("cloud-connector-azure");

export interface AzureConnectorConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
}

interface AzureTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

const azureTokenCache = new Map<string, { token: string; expiresAt: number }>();

function azureCacheKey(config: AzureConnectorConfig): string {
  return `${config.tenantId}:${config.clientId}:${config.subscriptionId}`;
}

/** Acquire an OAuth2 bearer token from Azure AD */
async function getAzureToken(config: AzureConnectorConfig): Promise<string> {
  const key = azureCacheKey(config);
  const cached = azureTokenCache.get(key);
  if (cached && Date.now() < cached.expiresAt - 60_000) {
    return cached.token;
  }

  const tokenUrl = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    scope: "https://management.azure.com/.default",
  });

  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Azure auth failed: ${resp.status} ${text}`);
  }

  const data: AzureTokenResponse = await resp.json();
  azureTokenCache.set(key, {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  });
  return data.access_token;
}

async function azureGet(config: AzureConnectorConfig, path: string): Promise<unknown> {
  const token = await getAzureToken(config);
  const baseUrl = "https://management.azure.com";
  const url = path.startsWith("https://") ? path : `${baseUrl}${path}`;
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Azure API error: ${resp.status} ${text}`);
  }

  return resp.json();
}

/** Validate Azure credentials */
export async function validateAzureCredentials(config: AzureConnectorConfig): Promise<{
  valid: boolean;
  subscriptionName?: string;
  error?: string;
}> {
  try {
    const sub = (await azureGet(config, `/subscriptions/${config.subscriptionId}?api-version=2022-12-01`)) as {
      displayName?: string;
      subscriptionId?: string;
    };
    return {
      valid: true,
      subscriptionName: sub.displayName || config.subscriptionId,
    };
  } catch (err: unknown) {
    return { valid: false, error: err instanceof Error ? err.message : "Unknown error" };
  }
}

/** Fetch Azure Security Center / Defender recommendations */
export async function scanAzureDefender(config: AzureConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await azureGet(
      config,
      `/subscriptions/${config.subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01`,
    )) as {
      value?: Array<{
        id?: string;
        name?: string;
        properties?: {
          displayName?: string;
          status?: { code?: string; cause?: string; description?: string };
          resourceDetails?: { Id?: string; Source?: string };
          metadata?: {
            severity?: string;
            description?: string;
            remediationDescription?: string;
            categories?: string[];
          };
        };
      }>;
    };

    for (const assessment of resp.value || []) {
      const props = assessment.properties;
      if (!props) continue;

      // Only include unhealthy assessments
      if (props.status?.code === "Healthy" || props.status?.code === "NotApplicable") continue;

      const azSeverity = props.metadata?.severity?.toLowerCase() || "medium";
      let severity: CloudFinding["severity"] = "medium";
      if (azSeverity === "high") severity = "high";
      else if (azSeverity === "low") severity = "low";
      else if (azSeverity === "medium") severity = "medium";

      const resourceId = props.resourceDetails?.Id || assessment.id || "unknown";
      const resourceType = inferAzureResourceType(resourceId);

      findings.push({
        ruleId: `AZ-DEF-${assessment.name || "unknown"}`.substring(0, 50),
        ruleName: props.displayName || "Azure Defender Assessment",
        severity,
        resourceType,
        resourceId,
        resourceRegion: extractAzureRegion(resourceId),
        description:
          props.metadata?.description || props.status?.description || "Azure Defender detected a security issue.",
        remediation: props.metadata?.remediationDescription || "Follow Azure Defender recommendations.",
        complianceFrameworks: mapAzureCategories(props.metadata?.categories || []),
        rawData: { statusCode: props.status?.code, cause: props.status?.cause },
      });
    }
  } catch (err: unknown) {
    log.error("Defender scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Fetch Azure Policy compliance results */
export async function scanAzurePolicy(config: AzureConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await azureGet(
      config,
      `/subscriptions/${config.subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&$filter=complianceState eq 'NonCompliant'&$top=100`,
    )) as {
      value?: Array<{
        policyAssignmentName?: string;
        policyDefinitionName?: string;
        policyDefinitionReferenceId?: string;
        resourceId?: string;
        resourceType?: string;
        resourceLocation?: string;
        complianceState?: string;
        policyDefinitionAction?: string;
      }>;
    };

    for (const state of resp.value || []) {
      findings.push({
        ruleId: `AZ-POL-${state.policyDefinitionName || "unknown"}`.substring(0, 50),
        ruleName: `Policy Violation: ${state.policyAssignmentName || state.policyDefinitionName || "Unknown"}`,
        severity: state.policyDefinitionAction === "deny" ? "high" : "medium",
        resourceType: `azure:${state.resourceType || "unknown"}`,
        resourceId: state.resourceId || "unknown",
        resourceRegion: state.resourceLocation || "global",
        description: `Resource is non-compliant with Azure Policy '${state.policyAssignmentName}'. Policy definition: ${state.policyDefinitionName}.`,
        remediation: "Review the Azure Policy definition and remediate the resource to meet compliance requirements.",
        complianceFrameworks: ["cis", "nist"],
        rawData: {
          complianceState: state.complianceState,
          action: state.policyDefinitionAction,
        },
      });
    }
  } catch (err: unknown) {
    log.error("Policy scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan Azure Storage accounts for misconfigurations */
export async function scanAzureStorage(config: AzureConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await azureGet(
      config,
      `/subscriptions/${config.subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`,
    )) as {
      value?: Array<{
        id?: string;
        name?: string;
        location?: string;
        properties?: {
          allowBlobPublicAccess?: boolean;
          supportsHttpsTrafficOnly?: boolean;
          minimumTlsVersion?: string;
          encryption?: { services?: { blob?: { enabled?: boolean }; file?: { enabled?: boolean } } };
          networkAcls?: { defaultAction?: string };
        };
      }>;
    };

    for (const account of resp.value || []) {
      const props = account.properties;
      const name = account.name || "unknown";
      const id = account.id || "unknown";
      const region = account.location || "global";

      if (props?.allowBlobPublicAccess) {
        findings.push({
          ruleId: "AZ-STOR-001",
          ruleName: "Storage Account Allows Public Blob Access",
          severity: "high",
          resourceType: "azure:storage:account",
          resourceId: id,
          resourceRegion: region,
          description: `Storage account '${name}' has public blob access enabled. Anonymous users can read blob data.`,
          remediation: "Set 'Allow Blob public access' to disabled on the storage account.",
          complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
        });
      }

      if (!props?.supportsHttpsTrafficOnly) {
        findings.push({
          ruleId: "AZ-STOR-002",
          ruleName: "Storage Account HTTPS-Only Not Enforced",
          severity: "high",
          resourceType: "azure:storage:account",
          resourceId: id,
          resourceRegion: region,
          description: `Storage account '${name}' allows HTTP traffic. Data is vulnerable to interception.`,
          remediation: "Enable 'Secure transfer required' to enforce HTTPS-only access.",
          complianceFrameworks: ["cis", "nist", "pci_dss"],
        });
      }

      if (props?.minimumTlsVersion && props.minimumTlsVersion !== "TLS1_2") {
        findings.push({
          ruleId: "AZ-STOR-003",
          ruleName: "Storage Account Using Outdated TLS Version",
          severity: "medium",
          resourceType: "azure:storage:account",
          resourceId: id,
          resourceRegion: region,
          description: `Storage account '${name}' minimum TLS version is ${props.minimumTlsVersion}. TLS 1.2 should be the minimum.`,
          remediation: "Set the minimum TLS version to TLS1_2 on the storage account.",
          complianceFrameworks: ["cis", "nist", "pci_dss"],
        });
      }

      if (props?.networkAcls?.defaultAction === "Allow") {
        findings.push({
          ruleId: "AZ-STOR-004",
          ruleName: "Storage Account Network Rules Allow All Traffic",
          severity: "medium",
          resourceType: "azure:storage:account",
          resourceId: id,
          resourceRegion: region,
          description: `Storage account '${name}' allows traffic from all networks. No network-level access control is enforced.`,
          remediation:
            "Configure network rules to deny access by default and allow only trusted virtual networks and IP addresses.",
          complianceFrameworks: ["cis", "nist", "soc2"],
        });
      }
    }
  } catch (err: unknown) {
    log.error("Storage scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan Azure NSGs for misconfigurations */
export async function scanAzureNSGs(config: AzureConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const resp = (await azureGet(
      config,
      `/subscriptions/${config.subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01`,
    )) as {
      value?: Array<{
        id?: string;
        name?: string;
        location?: string;
        properties?: {
          securityRules?: Array<{
            name?: string;
            properties?: {
              direction?: string;
              access?: string;
              sourceAddressPrefix?: string;
              destinationPortRange?: string;
              protocol?: string;
              priority?: number;
            };
          }>;
        };
      }>;
    };

    for (const nsg of resp.value || []) {
      const nsgName = nsg.name || "unknown";
      const nsgId = nsg.id || "unknown";
      const region = nsg.location || "global";

      for (const rule of nsg.properties?.securityRules || []) {
        const props = rule.properties;
        if (!props || props.direction !== "Inbound" || props.access !== "Allow") continue;

        const isOpenSource = props.sourceAddressPrefix === "*" || props.sourceAddressPrefix === "0.0.0.0/0";
        if (!isOpenSource) continue;

        const port = props.destinationPortRange;

        if (port === "22") {
          findings.push({
            ruleId: "AZ-NSG-002",
            ruleName: "NSG Allows SSH from Internet",
            severity: "high",
            resourceType: "azure:network:nsg",
            resourceId: nsgId,
            resourceRegion: region,
            description: `NSG '${nsgName}' allows inbound SSH (port 22) from any source.`,
            remediation: "Restrict SSH access to specific IP ranges. Use Azure Bastion for secure remote management.",
            complianceFrameworks: ["cis", "nist", "soc2"],
          });
        }

        if (port === "3389") {
          findings.push({
            ruleId: "AZ-NSG-003",
            ruleName: "NSG Allows RDP from Internet",
            severity: "critical",
            resourceType: "azure:network:nsg",
            resourceId: nsgId,
            resourceRegion: region,
            description: `NSG '${nsgName}' allows inbound RDP (port 3389) from any source.`,
            remediation: "Remove the allow-RDP rule. Use Azure Bastion or Just-In-Time VM access.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          });
        }

        if (port === "*") {
          findings.push({
            ruleId: "AZ-NSG-001",
            ruleName: "NSG Rule Allows All Inbound Traffic",
            severity: "critical",
            resourceType: "azure:network:nsg",
            resourceId: nsgId,
            resourceRegion: region,
            description: `NSG '${nsgName}' contains rule '${rule.name}' allowing all inbound traffic from any source on all ports.`,
            remediation:
              "Remove or restrict the allow-all inbound rule. Create specific NSG rules for required ports only.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          });
        }
      }
    }
  } catch (err: unknown) {
    log.error("NSG scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Run a full Azure CSPM scan */
export async function runAzureScan(
  config: AzureConnectorConfig,
): Promise<{ findings: CloudFinding[]; resources: CloudResource[] }> {
  const [defenderFindings, policyFindings, storageFindings, nsgFindings] = await Promise.all([
    scanAzureDefender(config),
    scanAzurePolicy(config),
    scanAzureStorage(config),
    scanAzureNSGs(config),
  ]);

  return {
    findings: [...defenderFindings, ...policyFindings, ...storageFindings, ...nsgFindings],
    resources: [],
  };
}

// Helper functions

function inferAzureResourceType(resourceId: string): string {
  if (resourceId.includes("Microsoft.Storage")) return "azure:storage:account";
  if (resourceId.includes("Microsoft.Network/networkSecurityGroups")) return "azure:network:nsg";
  if (resourceId.includes("Microsoft.Compute/virtualMachines")) return "azure:compute:vm";
  if (resourceId.includes("Microsoft.Sql")) return "azure:sql:database";
  if (resourceId.includes("Microsoft.KeyVault")) return "azure:keyvault:vault";
  if (resourceId.includes("Microsoft.Web")) return "azure:web:app";
  return "azure:unknown";
}

function extractAzureRegion(resourceId: string): string {
  // Azure resource IDs don't always include region; return global as fallback
  return "global";
}

function mapAzureCategories(categories: string[]): string[] {
  const frameworks: string[] = [];
  for (const cat of categories) {
    const lower = cat.toLowerCase();
    if (lower.includes("network")) frameworks.push("cis", "nist");
    if (lower.includes("data")) frameworks.push("pci_dss", "gdpr");
    if (lower.includes("identity")) frameworks.push("cis", "nist");
    if (lower.includes("compute")) frameworks.push("cis");
  }
  return frameworks.length > 0 ? Array.from(new Set(frameworks)) : ["cis", "nist"];
}
