import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(verdict?: string): string {
  if (!verdict) return "medium";
  const v = verdict.toLowerCase();
  if (v === "blocked" || v === "malicious") return "high";
  if (v === "suspicious" || v === "proxied") return "medium";
  return "low";
}

function mapCategory(categories?: string[]): string {
  if (!categories || categories.length === 0) return "other";
  const c = categories.join(",").toLowerCase();
  if (c.includes("malware")) return "malware";
  if (c.includes("phish")) return "phishing";
  if (c.includes("botnet") || c.includes("c2") || c.includes("command")) return "command_and_control";
  if (c.includes("crypto")) return "policy_violation";
  return "other";
}

export const umbrellaPlugin: ConnectorPlugin = {
  type: "umbrella",
  alertSource: "Cisco Umbrella",
  normalizerKey: "umbrella",
  metadata: {
    name: "Cisco Umbrella",
    description: "DNS Security - Pulls security events from Cisco Umbrella Reporting API",
    authType: "token",
    requiredFields: [
      { key: "baseUrl", label: "Umbrella API URL", type: "url", placeholder: "https://reports.api.umbrella.com" },
      { key: "apiKey", label: "API Token", type: "password", placeholder: "Umbrella Reporting API token" },
    ],
    optionalFields: [],
    icon: "Umbrella",
    docsUrl: "https://developer.cisco.com/docs/cloud-security/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/v2/events?limit=1`, {
        headers: { "Authorization": `Bearer ${config.apiKey}` },
      });
      if (res.status >= 400) throw new Error(`Umbrella returned ${res.status}`);
      return { success: true, message: "Successfully connected to umbrella", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "Authorization": `Bearer ${config.apiKey}`, "Content-Type": "application/json" };
    let url = `${config.baseUrl}/v2/events?limit=100`;
    if (since) {
      url += `&from=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return (res.data as Record<string, any>)?.data || (res.data as Record<string, any>)?.events || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Cisco Umbrella",
      sourceEventId: r.id?.toString() || `umbrella_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.domain || r.destination || "Umbrella Security Event",
      description: r.actionTaken || r.verdict || "",
      severity: mapSeverity(r.verdict || r.actionTaken),
      category: mapCategory(r.categories),
      sourceIp: r.internalIp || r.externalIp,
      domain: r.domain || r.destination,
      url: r.url,
      hostname: r.device || r.originLabel,
      userId: r.identity || r.identities?.[0],
      detectedAt: r.timestamp ? new Date(r.timestamp) : new Date(),
      rawData: r,
    };
  },
};
