import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(priority?: string): string {
  if (!priority) return "medium";
  const p = priority.toLowerCase();
  if (p === "critical") return "critical";
  if (p === "high") return "high";
  if (p === "medium") return "medium";
  if (p === "low") return "low";
  return "informational";
}

function mapCategory(source?: string): string {
  if (!source) return "other";
  const s = source.toLowerCase();
  if (s.includes("malware")) return "malware";
  if (s.includes("phish")) return "phishing";
  if (s.includes("lateral")) return "lateral_movement";
  if (s.includes("credential") || s.includes("auth")) return "credential_access";
  return "other";
}

export const rapid7Plugin: ConnectorPlugin = {
  type: "rapid7",
  alertSource: "Rapid7 InsightIDR",
  normalizerKey: "rapid7",
  metadata: {
    name: "Rapid7 InsightIDR",
    description: "SIEM / XDR - Pulls investigations from InsightIDR API",
    authType: "api_key",
    requiredFields: [
      { key: "baseUrl", label: "InsightIDR API URL", type: "url", placeholder: "https://us.api.insight.rapid7.com" },
      { key: "apiKey", label: "API Key", type: "password", placeholder: "Rapid7 Platform API key" },
    ],
    optionalFields: [],
    icon: "Search",
    docsUrl: "https://docs.rapid7.com/insightidr/api/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/idr/v2/investigations?size=1`, {
        headers: { "X-Api-Key": config.apiKey! },
      });
      if (res.status >= 400) throw new Error(`Rapid7 returned ${res.status}`);
      return { success: true, message: "Successfully connected to rapid7", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "X-Api-Key": config.apiKey!, "Content-Type": "application/json" };
    let url = `${config.baseUrl}/idr/v2/investigations?statuses=OPEN&multi-customer=false&size=100`;
    if (since) {
      url += `&start_time=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return (res.data as Record<string, any>)?.data || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Rapid7 InsightIDR",
      sourceEventId: r.id || r.rrn || `rapid7_${Date.now()}`,
      title: r.title || "Rapid7 Investigation",
      description: r.description || r.title || "",
      severity: mapSeverity(r.priority),
      category: mapCategory(r.source),
      sourceIp: r.alerts?.[0]?.detection_rule_rrn,
      hostname: r.alerts?.[0]?.host?.hostname,
      userId: r.assignee?.email,
      detectedAt: r.created_time ? new Date(r.created_time) : new Date(),
      rawData: r,
    };
  },
};
