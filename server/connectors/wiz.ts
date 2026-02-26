import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

async function getToken(config: ConnectorConfig): Promise<string> {
  const authUrl = "https://auth.app.wiz.io/oauth/token";
  const tokenRes = await fetch(authUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: config.clientId!,
      client_secret: config.clientSecret!,
      audience: "wiz-api",
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error("Wiz OAuth2 failed: " + JSON.stringify(tokenData));
  return tokenData.access_token;
}

function mapCategory(type?: string): string {
  if (!type) return "cloud_misconfiguration";
  const t = type.toLowerCase();
  if (t.includes("network")) return "intrusion";
  if (t.includes("iam") || t.includes("identity")) return "privilege_escalation";
  if (t.includes("data")) return "data_exfiltration";
  if (t.includes("malware") || t.includes("runtime")) return "malware";
  return "cloud_misconfiguration";
}

export const wizPlugin: ConnectorPlugin = {
  type: "wiz",
  alertSource: "Wiz Cloud",
  normalizerKey: "wiz",
  metadata: {
    name: "Wiz",
    description: "Cloud Security - Pulls issues via Wiz GraphQL API with severity filtering",
    authType: "oauth2",
    requiredFields: [
      { key: "clientId", label: "Service Account Client ID", type: "text", placeholder: "53-character client ID" },
      { key: "clientSecret", label: "Service Account Secret", type: "password", placeholder: "64-character client secret" },
    ],
    optionalFields: [
      { key: "datacenter", label: "Data Center", type: "text", placeholder: "us1, us2, eu1, eu2" },
    ],
    icon: "Cloud",
    docsUrl: "https://docs.wiz.io",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      await getToken(config);
      return { success: true, message: "Successfully connected to wiz", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const token = await getToken(config);
    const dc = config.datacenter || "us1";
    const endpoint = `https://api.${dc}.app.wiz.io/graphql`;
    const afterFilter = since ? `createdAt: { after: "${since.toISOString()}" }` : "";
    const query = `query {
    issues(first: 100, filterBy: { status: [OPEN, IN_PROGRESS], severity: [CRITICAL, HIGH, MEDIUM] ${afterFilter ? ", " + afterFilter : ""} }) {
      nodes { id type status severity createdAt updatedAt notes { text } entitySnapshot { id type nativeType name cloudPlatform region subscriptionId } sourceRule { id name description } }
      pageInfo { hasNextPage endCursor }
    }
  }`;
    const res = await httpRequest(endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: { query },
    });
    return (res.data as Record<string, any>)?.data?.issues?.nodes || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Wiz Cloud",
      sourceEventId: r.id,
      title: r.sourceRule?.name || r.type || "Wiz Issue",
      description: r.sourceRule?.description || r.notes?.[0]?.text || "",
      severity: (r.severity || "medium").toLowerCase(),
      category: mapCategory(r.type),
      hostname: r.entitySnapshot?.name,
      detectedAt: r.createdAt ? new Date(r.createdAt) : new Date(),
      rawData: r,
      normalizedData: {
        cloudPlatform: r.entitySnapshot?.cloudPlatform,
        region: r.entitySnapshot?.region,
        resourceType: r.entitySnapshot?.nativeType,
        subscriptionId: r.entitySnapshot?.subscriptionId,
      },
    };
  },
};
