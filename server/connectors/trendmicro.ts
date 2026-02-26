import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

function mapCategory(alertType?: string): string {
  if (!alertType) return "other";
  const t = alertType.toLowerCase();
  if (t.includes("malware") || t.includes("ransomware")) return "malware";
  if (t.includes("phish") || t.includes("email")) return "phishing";
  if (t.includes("lateral")) return "lateral_movement";
  if (t.includes("c2") || t.includes("callback")) return "command_and_control";
  return "other";
}

export const trendmicroPlugin: ConnectorPlugin = {
  type: "trendmicro",
  alertSource: "Trend Micro Vision One",
  normalizerKey: "trendmicro",
  metadata: {
    name: "Trend Micro Vision One",
    description: "XDR - Pulls workbench alerts from Vision One API",
    authType: "token",
    requiredFields: [
      { key: "baseUrl", label: "Vision One API URL", type: "url", placeholder: "https://api.xdr.trendmicro.com" },
      { key: "token", label: "API Token", type: "password", placeholder: "Vision One authentication token" },
    ],
    optionalFields: [],
    icon: "ShieldAlert",
    docsUrl: "https://automation.trendmicro.com/xdr/api-v3",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/v3.0/healthcheck/connectivity`, {
        headers: { "Authorization": `Bearer ${config.token}` },
      });
      if (res.status >= 400) throw new Error(`Trend Micro returned ${res.status}`);
      return { success: true, message: "Successfully connected to trendmicro", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "Authorization": `Bearer ${config.token}`, "Content-Type": "application/json" };
    let url = `${config.baseUrl}/v3.0/workbench/alerts?top=100&orderBy=createdDateTime%20desc`;
    if (since) {
      url += `&startDateTime=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return (res.data as Record<string, any>)?.items || (res.data as Record<string, any>)?.data || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Trend Micro Vision One",
      sourceEventId: r.id || r.alertId || `tm_${Date.now()}`,
      title: r.alertName || r.model || "Trend Micro Alert",
      description: r.description || r.investigationGuide || "",
      severity: mapSeverity(r.severity),
      category: mapCategory(r.alertType || r.model),
      sourceIp: r.impactScope?.entities?.[0]?.entityValue?.ips?.[0],
      hostname: r.impactScope?.entities?.[0]?.entityValue?.name,
      userId: r.impactScope?.entities?.[0]?.entityValue?.accountName,
      detectedAt: r.createdDateTime ? new Date(r.createdDateTime) : new Date(),
      rawData: r,
    };
  },
};
