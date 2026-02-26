import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: string | number): string {
  if (!sev) return "medium";
  if (typeof sev === "number") {
    if (sev >= 4) return "critical";
    if (sev >= 3) return "high";
    if (sev >= 2) return "medium";
    return "low";
  }
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

function mapCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("malware")) return "malware";
  if (t.includes("phish")) return "phishing";
  if (t.includes("botnet") || t.includes("c2")) return "command_and_control";
  if (t.includes("policy") || t.includes("dlp")) return "policy_violation";
  return "other";
}

export const zscalerPlugin: ConnectorPlugin = {
  type: "zscaler",
  alertSource: "Zscaler ZIA",
  normalizerKey: "zscaler",
  metadata: {
    name: "Zscaler ZIA",
    description: "Cloud Proxy / SWG - Pulls web application rules from Zscaler API",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "ZIA API URL", type: "url", placeholder: "https://zsapi.zscaler.net" },
      { key: "apiKey", label: "API Key", type: "password", placeholder: "Zscaler API key" },
      { key: "username", label: "Admin Username", type: "text", placeholder: "admin@company.com" },
      { key: "password", label: "Admin Password", type: "password", placeholder: "Zscaler admin password" },
    ],
    optionalFields: [],
    icon: "Globe",
    docsUrl: "https://help.zscaler.com/zia/api",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const authRes = await httpRequest(`${config.baseUrl}/api/v1/authenticatedSession`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: { apiKey: config.apiKey, username: config.username, password: config.password },
      });
      if (authRes.status >= 400) throw new Error(`Zscaler auth returned ${authRes.status}`);
      return { success: true, message: "Successfully connected to zscaler", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const authRes = await httpRequest(`${config.baseUrl}/api/v1/authenticatedSession`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { apiKey: config.apiKey, username: config.username, password: config.password },
    });
    const cookie = (authRes.data as Record<string, any>)?.authType === "session"
      ? (authRes.data as Record<string, any>)?.obfuscateApiKey
      : undefined;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Cookie": cookie ? `JSESSIONID=${cookie}` : "",
    };
    const body: Record<string, unknown> = { type: "all", pageSize: 100 };
    if (since) {
      body.startTime = since.getTime();
    }
    const res = await httpRequest(`${config.baseUrl}/api/v1/webApplicationRules`, {
      method: "POST",
      headers,
      body,
    });
    return (res.data as Record<string, any>)?.list || (res.data as Record<string, any>)?.rules || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Zscaler ZIA",
      sourceEventId: r.id?.toString() || r.ruleId?.toString() || `zscaler_${Date.now()}`,
      title: r.name || r.ruleName || "Zscaler ZIA Event",
      description: r.description || r.name || "",
      severity: mapSeverity(r.severity || r.rank),
      category: mapCategory(r.type || r.protocols),
      sourceIp: r.srcIp || r.clientIP,
      destIp: r.dstIp || r.serverIP,
      hostname: r.hostname || r.deviceName,
      userId: r.user || r.login,
      url: r.url,
      domain: r.hostname,
      detectedAt: r.time ? new Date(r.time) : new Date(),
      rawData: r,
    };
  },
};
