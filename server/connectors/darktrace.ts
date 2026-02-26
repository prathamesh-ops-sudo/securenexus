import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(score?: number): string {
  if (!score) return "medium";
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.4) return "medium";
  if (score >= 0.2) return "low";
  return "informational";
}

function mapCategory(modelName?: string): string {
  if (!modelName) return "other";
  const m = modelName.toLowerCase();
  if (m.includes("compromise") || m.includes("malware")) return "malware";
  if (m.includes("anomalous") || m.includes("unusual")) return "reconnaissance";
  if (m.includes("credential") || m.includes("brute")) return "credential_access";
  if (m.includes("exfiltration") || m.includes("data")) return "data_exfiltration";
  if (m.includes("c2") || m.includes("command")) return "command_and_control";
  return "other";
}

export const darktracePlugin: ConnectorPlugin = {
  type: "darktrace",
  alertSource: "Darktrace",
  normalizerKey: "darktrace",
  metadata: {
    name: "Darktrace",
    description: "NDR / AI Threat Detection - Pulls model breaches from Darktrace API",
    authType: "token",
    requiredFields: [
      { key: "baseUrl", label: "Darktrace Appliance URL", type: "url", placeholder: "https://your-darktrace.com" },
    ],
    optionalFields: [
      { key: "token", label: "API Token", type: "password", placeholder: "Darktrace API token (optional)" },
    ],
    icon: "Activity",
    docsUrl: "https://customerportal.darktrace.com/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const headers: Record<string, string> = {};
      if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
      const res = await httpRequest(`${config.baseUrl}/status`, { headers });
      if (res.status >= 400) throw new Error(`Darktrace returned ${res.status}`);
      return { success: true, message: "Successfully connected to darktrace", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (config.token) {
      headers["Authorization"] = `Bearer ${config.token}`;
    }
    let url = `${config.baseUrl}/modelbreaches?count=100`;
    if (since) {
      url += `&from=${Math.floor(since.getTime() / 1000)}`;
    }
    const res = await httpRequest(url, { headers });
    return Array.isArray(res.data) ? (res.data as unknown[]) : (res.data as Record<string, any>)?.breaches || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Darktrace",
      sourceEventId: r.pbid?.toString() || r.id?.toString() || `darktrace_${Date.now()}`,
      title: r.model?.name || r.modelName || "Darktrace Model Breach",
      description: r.model?.description || "",
      severity: mapSeverity(r.score || r.model?.then?.score),
      category: mapCategory(r.model?.name),
      sourceIp: r.device?.ip,
      hostname: r.device?.hostname || r.device?.label,
      detectedAt: r.time ? new Date(r.time * 1000) : new Date(),
      rawData: r,
    };
  },
};
