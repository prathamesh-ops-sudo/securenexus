import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "critical" || s === "high") return s;
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

export const paloaltoPlugin: ConnectorPlugin = {
  type: "paloalto",
  alertSource: "Palo Alto Firewall",
  normalizerKey: "paloalto",
  metadata: {
    name: "Palo Alto Cortex XDR",
    description: "Firewall / XDR - Pulls incidents from Cortex XDR API",
    authType: "api_key",
    requiredFields: [
      { key: "baseUrl", label: "API URL", type: "url", placeholder: "https://api-your-instance.xdr.us.paloaltonetworks.com" },
      { key: "apiKey", label: "API Key", type: "password", placeholder: "Your Cortex XDR API key" },
    ],
    optionalFields: [
      { key: "clientId", label: "API Key ID", type: "text", placeholder: "1" },
    ],
    icon: "Flame",
    docsUrl: "https://docs-cortex.paloaltonetworks.com/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const headers: Record<string, string> = { "x-xdr-auth-id": config.clientId || "1", Authorization: config.apiKey! };
      const res = await httpRequest(`${config.baseUrl}/public_api/v1/healthcheck`, { headers });
      if (res.status >= 400) throw new Error(`Palo Alto returned ${res.status}`);
      return { success: true, message: "Successfully connected to paloalto", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = {
      "x-xdr-auth-id": config.clientId || "1",
      Authorization: config.apiKey!,
      "Content-Type": "application/json",
    };
    const filters: Record<string, unknown>[] = [];
    if (since) {
      filters.push({ field: "creation_time", operator: "gte", value: since.getTime() });
    }
    const body = { request_data: { filters, search_from: 0, search_to: 100, sort: { field: "creation_time", keyword: "desc" } } };
    const res = await httpRequest(`${config.baseUrl}/public_api/v1/incidents/get_incidents`, { method: "POST", headers, body });
    return (res.data as Record<string, any>)?.reply?.incidents || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Palo Alto Firewall",
      sourceEventId: r.incident_id?.toString() || `pa_${Date.now()}`,
      title: r.description || r.alert_name || "Palo Alto Incident",
      description: r.description || "",
      severity: mapSeverity(r.severity),
      category: r.category || "intrusion",
      sourceIp: r.src_ip || r.hosts?.[0],
      destIp: r.dst_ip,
      hostname: r.hosts?.[0],
      userId: r.users?.[0],
      detectedAt: r.creation_time ? new Date(r.creation_time) : new Date(),
      rawData: r,
    };
  },
};
