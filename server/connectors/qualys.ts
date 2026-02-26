import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: number | string): string {
  const n = typeof sev === "string" ? parseInt(sev, 10) || 0 : (sev || 0);
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "informational";
}

export const qualysPlugin: ConnectorPlugin = {
  type: "qualys",
  alertSource: "Qualys VMDR",
  normalizerKey: "qualys",
  metadata: {
    name: "Qualys VMDR",
    description: "Vulnerability Management - Pulls detections from Qualys VMDR API",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "Qualys API URL", type: "url", placeholder: "https://qualysapi.qualys.com" },
      { key: "username", label: "Username", type: "text", placeholder: "Qualys username" },
      { key: "password", label: "Password", type: "password", placeholder: "Qualys password" },
    ],
    optionalFields: [],
    icon: "Bug",
    docsUrl: "https://www.qualys.com/docs/qualys-api-vmpc-user-guide.htm",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
      const res = await httpRequest(`${config.baseUrl}/api/2.0/fo/activity_log/?action=list&output_format=JSON`, {
        headers: { "Authorization": `Basic ${auth}`, "X-Requested-With": "fetch" },
      });
      if (res.status >= 400) throw new Error(`Qualys returned ${res.status}`);
      return { success: true, message: "Successfully connected to qualys", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
    const headers: Record<string, string> = {
      "Authorization": `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Requested-With": "fetch",
    };
    let body = "action=list&output_format=JSON&severities=3,4,5";
    if (since) {
      body += `&detection_updated_since=${since.toISOString()}`;
    }
    const rawRes = await fetch(`${config.baseUrl}/api/2.0/fo/asset/host/vm/detection/?${body}`, {
      method: "POST",
      headers,
    });
    const text = await rawRes.text();
    let data;
    try { data = JSON.parse(text); } catch { data = []; }
    return Array.isArray(data) ? data : (data as Record<string, any>)?.data?.host_list_vm_detection_output?.response?.host_list?.host || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Qualys VMDR",
      sourceEventId: r.qid?.toString() || r.id?.toString() || `qualys_${Date.now()}`,
      title: r.title || r.vulnerability?.title || "Qualys Detection",
      description: r.consequence || r.solution || "",
      severity: mapSeverity(r.severity || r.vuln_severity),
      category: "vulnerability",
      hostname: r.hostname || r.ip || r.dns,
      sourceIp: r.ip,
      detectedAt: r.last_update || r.first_found ? new Date(r.last_update || r.first_found) : new Date(),
      rawData: r,
    };
  },
};
