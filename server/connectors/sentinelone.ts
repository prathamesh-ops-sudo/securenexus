import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(level?: string): string {
  if (!level) return "medium";
  const l = level.toLowerCase();
  if (l === "malicious" || l === "suspicious") return "high";
  if (l === "true_positive") return "critical";
  return "medium";
}

function mapCategory(classification?: string): string {
  if (!classification) return "other";
  const c = classification.toLowerCase();
  if (c.includes("ransomware")) return "malware";
  if (c.includes("trojan")) return "malware";
  if (c.includes("exploit")) return "intrusion";
  if (c.includes("pup")) return "policy_violation";
  return "malware";
}

export const sentinelonePlugin: ConnectorPlugin = {
  type: "sentinelone",
  alertSource: "SentinelOne EDR",
  normalizerKey: "sentinelone",
  metadata: {
    name: "SentinelOne",
    description: "EDR - Pulls threats from SentinelOne Management API",
    authType: "token",
    requiredFields: [
      { key: "baseUrl", label: "Management Console URL", type: "url", placeholder: "https://your-instance.sentinelone.net" },
      { key: "apiKey", label: "API Token", type: "password", placeholder: "SentinelOne API token" },
    ],
    optionalFields: [],
    icon: "Radar",
    docsUrl: "https://your-instance.sentinelone.net/api-doc/overview",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/web/api/v2.1/system/status`, {
        headers: { Authorization: `ApiToken ${config.apiKey}` },
      });
      if (res.status >= 400) throw new Error(`SentinelOne returned ${res.status}`);
      return { success: true, message: "Successfully connected to sentinelone", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers = { Authorization: `ApiToken ${config.apiKey}`, "Content-Type": "application/json" };
    let url = `${config.baseUrl}/web/api/v2.1/threats?limit=100&sortBy=createdAt&sortOrder=desc`;
    if (since) {
      url += `&createdAt__gte=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return (res.data as Record<string, any>)?.data || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    const info = r.threatInfo || r;
    return {
      source: "SentinelOne EDR",
      sourceEventId: r.id?.toString() || info.threatId,
      title: info.threatName || info.classification || "SentinelOne Threat",
      description: info.storyline || info.classification || "",
      severity: mapSeverity(info.confidenceLevel || info.analystVerdict),
      category: mapCategory(info.classification),
      sourceIp: r.agentRealtimeInfo?.activeInterfaces?.[0]?.inet?.[0],
      hostname: r.agentDetectionInfo?.name || r.agentRealtimeInfo?.agentComputerName,
      userId: r.agentDetectionInfo?.agentLastLoggedInUserName,
      fileHash: info.sha256 || info.md5,
      domain: info.originDomain,
      detectedAt: info.createdAt ? new Date(info.createdAt) : new Date(),
      rawData: r,
    };
  },
};
