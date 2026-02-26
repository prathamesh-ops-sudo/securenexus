import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: number): string {
  if (!sev) return "medium";
  if (sev >= 8) return "critical";
  if (sev >= 6) return "high";
  if (sev >= 4) return "medium";
  if (sev >= 2) return "low";
  return "informational";
}

function mapCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("malware") || t.includes("virus")) return "malware";
  if (t.includes("watchlist")) return "reconnaissance";
  if (t.includes("device") || t.includes("policy")) return "policy_violation";
  return "other";
}

export const carbonblackPlugin: ConnectorPlugin = {
  type: "carbonblack",
  alertSource: "Carbon Black EDR",
  normalizerKey: "carbonblack",
  metadata: {
    name: "VMware Carbon Black",
    description: "EDR - Pulls alerts from Carbon Black Cloud API",
    authType: "api_key",
    requiredFields: [
      { key: "baseUrl", label: "CBC API URL", type: "url", placeholder: "https://defense.conferdeploy.net" },
      { key: "apiKey", label: "API Key + ID", type: "password", placeholder: "APIKEY/APIID" },
      { key: "orgKey", label: "Organization Key", type: "text", placeholder: "Your CBC Org Key" },
    ],
    optionalFields: [],
    icon: "Shield",
    docsUrl: "https://developer.carbonblack.com/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const orgKey = config.orgKey || config.clientId;
      if (!orgKey) throw new Error("Carbon Black requires orgKey or clientId in connector config");
      const res = await httpRequest(`${config.baseUrl}/api/alerts/v7/orgs/${orgKey}/alerts/_search`, {
        method: "POST",
        headers: { "X-Auth-Token": config.apiKey!, "Content-Type": "application/json" },
        body: { criteria: {}, rows: 1 },
      });
      if (res.status >= 400) throw new Error(`Carbon Black returned ${res.status}`);
      return { success: true, message: "Successfully connected to carbonblack", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const orgKey = config.orgKey || config.clientId;
    if (!orgKey) throw new Error("Carbon Black requires orgKey or clientId in connector config");
    const headers: Record<string, string> = { "X-Auth-Token": config.apiKey!, "Content-Type": "application/json" };
    const criteria: Record<string, unknown> = {};
    if (since) {
      criteria.create_time = { start: since.toISOString() };
    }
    const res = await httpRequest(`${config.baseUrl}/api/alerts/v7/orgs/${orgKey}/alerts/_search`, {
      method: "POST",
      headers,
      body: { criteria, rows: 100, sort: [{ field: "create_time", order: "DESC" }] },
    });
    return (res.data as Record<string, any>)?.results || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Carbon Black EDR",
      sourceEventId: r.id || `cb_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.reason || r.type || "Carbon Black Alert",
      description: r.reason || r.workflow?.state || "",
      severity: mapSeverity(r.severity),
      category: mapCategory(r.type),
      hostname: r.device_name || r.device_os,
      userId: r.device_username,
      fileHash: r.threat_cause_actor_sha256 || r.process_sha256,
      detectedAt: r.create_time ? new Date(r.create_time) : new Date(),
      rawData: r,
    };
  },
};
