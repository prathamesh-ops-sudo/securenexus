import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(level?: string): string {
  if (!level) return "medium";
  const l = level.toLowerCase();
  if (l === "emergency" || l === "alert" || l === "critical") return "critical";
  if (l === "error") return "high";
  if (l === "warning") return "medium";
  if (l === "notice" || l === "information") return "low";
  return "informational";
}

function mapCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("virus") || t.includes("malware")) return "malware";
  if (t.includes("intrusion") || t.includes("ips")) return "intrusion";
  if (t.includes("web") || t.includes("url")) return "policy_violation";
  if (t.includes("traffic")) return "other";
  return "other";
}

export const fortigatePlugin: ConnectorPlugin = {
  type: "fortigate",
  alertSource: "Fortinet FortiGate",
  normalizerKey: "fortigate",
  metadata: {
    name: "Fortinet FortiGate",
    description: "NGFW - Pulls event logs from FortiGate REST API",
    authType: "api_key",
    requiredFields: [
      { key: "baseUrl", label: "FortiGate URL", type: "url", placeholder: "https://your-fortigate:443" },
      { key: "apiKey", label: "API Key (Access Token)", type: "password", placeholder: "FortiGate REST API access token" },
    ],
    optionalFields: [],
    icon: "Flame",
    docsUrl: "https://docs.fortinet.com/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/api/v2/cmdb/system/status?access_token=${encodeURIComponent(config.apiKey!)}`, {});
      if (res.status >= 400) throw new Error(`FortiGate returned ${res.status}`);
      return { success: true, message: "Successfully connected to fortigate", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    let url = `${config.baseUrl}/api/v2/log/event?rows=100&filter=level>=warning&access_token=${encodeURIComponent(config.apiKey!)}`;
    if (since) {
      url += `&since=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers: { "Content-Type": "application/json" } });
    return (res.data as Record<string, any>)?.results || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Fortinet FortiGate",
      sourceEventId: r.logid || r.eventid || `forti_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.msg || r.action || "FortiGate Event",
      description: r.msg || r.logdesc || "",
      severity: mapSeverity(r.level),
      category: mapCategory(r.type || r.subtype),
      sourceIp: r.srcip || r.srcintf,
      destIp: r.dstip || r.dstintf,
      sourcePort: r.srcport ? parseInt(r.srcport, 10) : undefined,
      destPort: r.dstport ? parseInt(r.dstport, 10) : undefined,
      protocol: r.proto || r.service,
      hostname: r.devname,
      detectedAt: r.date && r.time ? new Date(`${r.date} ${r.time}`) : new Date(),
      rawData: r,
    };
  },
};
