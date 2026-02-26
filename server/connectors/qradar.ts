import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(magnitude?: number): string {
  if (!magnitude) return "medium";
  if (magnitude >= 8) return "critical";
  if (magnitude >= 6) return "high";
  if (magnitude >= 4) return "medium";
  if (magnitude >= 2) return "low";
  return "informational";
}

export const qradarPlugin: ConnectorPlugin = {
  type: "qradar",
  alertSource: "IBM QRadar",
  normalizerKey: "qradar",
  metadata: {
    name: "IBM QRadar",
    description: "SIEM - Pulls offenses from QRadar REST API with magnitude filtering",
    authType: "token",
    requiredFields: [
      { key: "baseUrl", label: "QRadar Console URL", type: "url", placeholder: "https://your-qradar:443" },
      { key: "apiKey", label: "SEC Token", type: "password", placeholder: "QRadar authorized service token" },
    ],
    optionalFields: [],
    icon: "Database",
    docsUrl: "https://www.ibm.com/docs/en/qradar-common",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/api/help/versions`, {
        headers: { "SEC": config.apiKey!, "Accept": "application/json" },
      });
      if (res.status >= 400) throw new Error(`QRadar returned ${res.status}`);
      return { success: true, message: "Successfully connected to qradar", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "SEC": config.apiKey!, "Content-Type": "application/json", "Accept": "application/json" };
    let url = `${config.baseUrl}/api/siem/offenses?filter=magnitude%20%3E%3D%205&Range=items%3D0-99`;
    if (since) {
      url += `&filter=start_time%20%3E%20${since.getTime()}`;
    }
    const res = await httpRequest(url, { headers });
    return Array.isArray(res.data) ? (res.data as unknown[]) : [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "IBM QRadar",
      sourceEventId: r.id?.toString() || `qradar_${Date.now()}`,
      title: r.description || r.offense_type_str || "QRadar Offense",
      description: r.description || "",
      severity: mapSeverity(r.magnitude),
      category: r.offense_type_str || "other",
      sourceIp: r.offense_source,
      destIp: r.destination_networks?.[0],
      hostname: r.domain_str,
      detectedAt: r.start_time ? new Date(r.start_time) : new Date(),
      rawData: r,
    };
  },
};
