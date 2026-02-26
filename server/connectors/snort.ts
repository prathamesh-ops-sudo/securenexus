import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(priority?: number | string): string {
  const n = typeof priority === "string" ? parseInt(priority, 10) || 3 : (priority || 3);
  if (n <= 1) return "critical";
  if (n <= 2) return "high";
  if (n <= 3) return "medium";
  return "low";
}

function mapCategory(classtype?: string): string {
  if (!classtype) return "other";
  const c = classtype.toLowerCase();
  if (c.includes("trojan") || c.includes("malware")) return "malware";
  if (c.includes("exploit") || c.includes("shellcode")) return "intrusion";
  if (c.includes("scan") || c.includes("recon")) return "reconnaissance";
  if (c.includes("policy") || c.includes("inappropriate")) return "policy_violation";
  if (c.includes("web-application")) return "intrusion";
  return "other";
}

function buildAuthHeaders(config: ConnectorConfig): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.apiKey) {
    headers["Authorization"] = `Bearer ${config.apiKey}`;
  } else if (config.username && config.password) {
    headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
  }
  return headers;
}

export const snortPlugin: ConnectorPlugin = {
  type: "snort",
  alertSource: "Snort IDS",
  normalizerKey: "snort",
  metadata: {
    name: "Snort IDS",
    description: "Network IDS - Pulls alerts from Snort API endpoint",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "Snort API URL", type: "url", placeholder: "https://your-snort-manager:8080" },
    ],
    optionalFields: [
      { key: "apiKey", label: "API Key (alternative to basic auth)", type: "password", placeholder: "Bearer token" },
      { key: "username", label: "Username", type: "text", placeholder: "Snort username" },
      { key: "password", label: "Password", type: "password", placeholder: "Snort password" },
    ],
    icon: "Wifi",
    docsUrl: "https://www.snort.org/documents",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const headers = buildAuthHeaders(config);
      const res = await httpRequest(`${config.baseUrl}/api/alerts?limit=1`, { headers });
      if (res.status >= 400) throw new Error(`Snort returned ${res.status}`);
      return { success: true, message: "Successfully connected to snort", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers = buildAuthHeaders(config);
    let url = `${config.baseUrl}/api/alerts?limit=100`;
    if (since) {
      url += `&since=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return Array.isArray(res.data) ? (res.data as unknown[]) : (res.data as Record<string, any>)?.alerts || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Snort IDS",
      sourceEventId: r.sid?.toString() || r.gid?.toString() || `snort_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.msg || r.message || "Snort Alert",
      description: r.msg || r.reference || "",
      severity: mapSeverity(r.priority || r.rev),
      category: mapCategory(r.classtype || r.classification),
      sourceIp: r.src_addr || r.srcIP,
      destIp: r.dst_addr || r.dstIP,
      sourcePort: r.src_port || r.srcPort ? parseInt(r.src_port || r.srcPort, 10) : undefined,
      destPort: r.dst_port || r.dstPort ? parseInt(r.dst_port || r.dstPort, 10) : undefined,
      protocol: r.proto || r.protocol,
      detectedAt: r.timestamp ? new Date(r.timestamp) : new Date(),
      rawData: r,
    };
  },
};
