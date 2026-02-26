import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

async function getToken(config: ConnectorConfig): Promise<string> {
  const tokenRes = await fetch(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=client_credentials&client_id=${encodeURIComponent(config.clientId!)}&client_secret=${encodeURIComponent(config.clientSecret!)}&scope=https://graph.microsoft.com/.default`,
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error("Defender OAuth2 failed: " + JSON.stringify(tokenData));
  return tokenData.access_token;
}

function mapCategory(cat?: string): string {
  if (!cat) return "other";
  const c = cat.toLowerCase();
  if (c.includes("malware")) return "malware";
  if (c.includes("phish")) return "phishing";
  if (c.includes("ransomware")) return "malware";
  if (c.includes("lateral")) return "lateral_movement";
  if (c.includes("credential")) return "credential_access";
  if (c.includes("command") || c.includes("c2")) return "command_and_control";
  return "other";
}

export const defenderPlugin: ConnectorPlugin = {
  type: "defender",
  alertSource: "Microsoft Defender",
  normalizerKey: "defender",
  metadata: {
    name: "Microsoft Defender",
    description: "Endpoint / Cloud Security - Pulls alerts from Microsoft Graph Security API",
    authType: "oauth2",
    requiredFields: [
      { key: "tenantId", label: "Azure Tenant ID", type: "text", placeholder: "Your Azure AD Tenant ID" },
      { key: "clientId", label: "App Client ID", type: "text", placeholder: "Azure AD App Registration Client ID" },
      { key: "clientSecret", label: "App Client Secret", type: "password", placeholder: "Azure AD App Registration Secret" },
    ],
    optionalFields: [],
    icon: "ShieldCheck",
    docsUrl: "https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      await getToken(config);
      return { success: true, message: "Successfully connected to defender", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const token = await getToken(config);
    let url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100&$orderby=createdDateTime desc";
    if (since) {
      url += `&$filter=createdDateTime ge ${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers: { Authorization: `Bearer ${token}` } });
    return (res.data as Record<string, any>)?.value || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Microsoft Defender",
      sourceEventId: r.id,
      title: r.title || "Defender Alert",
      description: r.description || "",
      severity: (r.severity || "medium").toLowerCase(),
      category: mapCategory(r.category),
      sourceIp: r.evidence?.[0]?.ipAddress,
      hostname: r.evidence?.[0]?.deviceDnsName,
      userId: r.evidence?.[0]?.userAccount?.accountName,
      fileHash: r.evidence?.[0]?.fileDetails?.sha256,
      mitreTactic: r.mitreTechniques?.[0]?.split(".")?.[0],
      mitreTechnique: r.mitreTechniques?.[0],
      detectedAt: r.createdDateTime ? new Date(r.createdDateTime) : new Date(),
      rawData: r,
    };
  },
};
