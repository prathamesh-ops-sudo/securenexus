import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(score?: number): string {
  if (!score) return "medium";
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score >= 10) return "low";
  return "informational";
}

function mapCategory(threatType?: string): string {
  if (!threatType) return "other";
  const t = threatType.toLowerCase();
  if (t.includes("malware") || t.includes("attachment")) return "malware";
  if (t.includes("phish") || t.includes("url")) return "phishing";
  if (t.includes("spam")) return "policy_violation";
  if (t.includes("impostor") || t.includes("bec")) return "phishing";
  return "other";
}

export const proofpointPlugin: ConnectorPlugin = {
  type: "proofpoint",
  alertSource: "Proofpoint Email",
  normalizerKey: "proofpoint",
  metadata: {
    name: "Proofpoint TAP",
    description: "Email Security - Pulls delivered messages from Proofpoint SIEM API",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "TAP API URL", type: "url", placeholder: "https://tap-api-v2.proofpoint.com" },
      { key: "username", label: "Service Principal", type: "text", placeholder: "Proofpoint API principal" },
      { key: "password", label: "Secret", type: "password", placeholder: "Proofpoint API secret" },
    ],
    optionalFields: [],
    icon: "Mail",
    docsUrl: "https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
      const res = await httpRequest(`${config.baseUrl}/v2/siem/messages/delivered?sinceSeconds=60&format=JSON`, {
        headers: { "Authorization": `Basic ${auth}` },
      });
      if (res.status >= 400) throw new Error(`Proofpoint returned ${res.status}`);
      return { success: true, message: "Successfully connected to proofpoint", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
    const headers: Record<string, string> = { "Authorization": `Basic ${auth}`, "Content-Type": "application/json" };
    const sinceSeconds = since ? Math.floor((Date.now() - since.getTime()) / 1000) : 86400;
    const url = `${config.baseUrl}/v2/siem/messages/delivered?sinceSeconds=${sinceSeconds}&format=JSON`;
    const res = await httpRequest(url, { headers });
    return (res.data as Record<string, any>)?.messagesDelivered || (res.data as Record<string, any>)?.records || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Proofpoint Email",
      sourceEventId: r.GUID || r.messageID || `proofpoint_${Date.now()}`,
      title: r.subject || r.threatsInfoMap?.[0]?.threat || "Proofpoint Alert",
      description: r.subject || "",
      severity: mapSeverity(r.spamScore || r.phishScore || r.malwareScore),
      category: mapCategory(r.threatsInfoMap?.[0]?.threatType),
      sourceIp: r.senderIP,
      userId: r.sender || r.fromAddress?.[0],
      url: r.threatsInfoMap?.[0]?.threatUrl,
      detectedAt: r.messageTime ? new Date(r.messageTime) : new Date(),
      rawData: r,
    };
  },
};
