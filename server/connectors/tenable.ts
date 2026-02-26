import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: number | string): string {
  if (!sev) return "medium";
  if (typeof sev === "number") {
    if (sev >= 4) return "critical";
    if (sev >= 3) return "high";
    if (sev >= 2) return "medium";
    if (sev >= 1) return "low";
    return "informational";
  }
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

export const tenablePlugin: ConnectorPlugin = {
  type: "tenable",
  alertSource: "Tenable Nessus",
  normalizerKey: "tenable",
  metadata: {
    name: "Tenable.io / Nessus",
    description: "Vulnerability Scanner - Pulls vulnerabilities from Tenable.io API",
    authType: "api_key",
    requiredFields: [
      { key: "baseUrl", label: "Tenable.io API URL", type: "url", placeholder: "https://cloud.tenable.com" },
      { key: "apiKey", label: "Access Key", type: "password", placeholder: "Tenable API access key" },
      { key: "token", label: "Secret Key", type: "password", placeholder: "Tenable API secret key" },
    ],
    optionalFields: [],
    icon: "Bug",
    docsUrl: "https://developer.tenable.com/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const secretKey = config.token || "";
      const res = await httpRequest(`${config.baseUrl}/server/status`, {
        headers: { "X-ApiKeys": `accessKey=${config.apiKey};secretKey=${secretKey}` },
      });
      if (res.status >= 400) throw new Error(`Tenable returned ${res.status}`);
      return { success: true, message: "Successfully connected to tenable", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const secretKey = config.token || "";
    const headers: Record<string, string> = {
      "X-ApiKeys": `accessKey=${config.apiKey};secretKey=${secretKey}`,
      "Content-Type": "application/json",
    };
    let url = `${config.baseUrl}/vulns?date_range=7&severity[]=critical&severity[]=high`;
    if (since) {
      url += `&since=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return (res.data as Record<string, any>)?.vulnerabilities || (res.data as Record<string, any>)?.vulns || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Tenable Nessus",
      sourceEventId: r.plugin_id?.toString() || r.id?.toString() || `tenable_${Date.now()}`,
      title: r.plugin_name || r.title || "Tenable Finding",
      description: r.description || r.synopsis || "",
      severity: mapSeverity(r.severity || r.risk_factor),
      category: "vulnerability",
      hostname: r.hostname || r.host?.hostname,
      sourceIp: r.host?.ip || r.ip,
      detectedAt: r.first_found ? new Date(r.first_found) : new Date(),
      rawData: r,
    };
  },
};
