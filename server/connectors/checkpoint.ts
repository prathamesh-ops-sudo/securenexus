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

function mapCategory(blade?: string): string {
  if (!blade) return "other";
  const b = blade.toLowerCase();
  if (b.includes("ips") || b.includes("intrusion")) return "intrusion";
  if (b.includes("anti-bot") || b.includes("antibot")) return "command_and_control";
  if (b.includes("threat") || b.includes("emulation")) return "malware";
  if (b.includes("antivirus") || b.includes("anti-virus")) return "malware";
  if (b.includes("url") || b.includes("application")) return "policy_violation";
  return "other";
}

async function authenticate(config: ConnectorConfig): Promise<Record<string, string>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.apiKey) {
    headers["X-chkp-sid"] = config.apiKey;
  } else if (config.username && config.password) {
    const loginRes = await httpRequest(`${config.baseUrl}/web_api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { user: config.username, password: config.password },
    });
    if (loginRes.data && (loginRes.data as Record<string, any>).sid) {
      headers["X-chkp-sid"] = (loginRes.data as Record<string, any>).sid;
    }
  }
  return headers;
}

export const checkpointPlugin: ConnectorPlugin = {
  type: "checkpoint",
  alertSource: "Check Point",
  normalizerKey: "checkpoint",
  metadata: {
    name: "Check Point",
    description: "NGFW / Security Gateway - Pulls logs from Check Point Management API",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "Management Server URL", type: "url", placeholder: "https://your-checkpoint-mgmt:443" },
    ],
    optionalFields: [
      { key: "apiKey", label: "Session ID (X-chkp-sid)", type: "password", placeholder: "Pre-authenticated session ID" },
      { key: "username", label: "Username", type: "text", placeholder: "Check Point admin username" },
      { key: "password", label: "Password", type: "password", placeholder: "Check Point admin password" },
    ],
    icon: "Shield",
    docsUrl: "https://sc1.checkpoint.com/documents/latest/APIs/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      if (config.username && config.password && !config.apiKey) {
        const loginRes = await httpRequest(`${config.baseUrl}/web_api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: { user: config.username, password: config.password },
        });
        if (loginRes.status >= 400) throw new Error(`Check Point login returned ${loginRes.status}`);
      } else {
        const headers = await authenticate(config);
        const res = await httpRequest(`${config.baseUrl}/web_api/show-session`, {
          method: "POST",
          headers,
          body: {},
        });
        if (res.status >= 400) throw new Error(`Check Point returned ${res.status}`);
      }
      return { success: true, message: "Successfully connected to checkpoint", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers = await authenticate(config);
    const body: Record<string, unknown> = {
      "new-query": { filter: "blade:IPS OR blade:Anti-Bot OR blade:Threat Emulation" },
      limit: 100,
    };
    if (since) {
      (body["new-query"] as Record<string, unknown>)["time-frame"] = `last-${Math.ceil((Date.now() - since.getTime()) / 3600000)}hours`;
    }
    const res = await httpRequest(`${config.baseUrl}/web_api/show-logs`, {
      method: "POST",
      headers,
      body,
    });
    return (res.data as Record<string, any>)?.logs || (res.data as Record<string, any>)?.tasks?.[0]?.task_details || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Check Point",
      sourceEventId: r.loguid || r.id || `checkpoint_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.attack || r.product || "Check Point Alert",
      description: r.attack || r.protection_name || "",
      severity: mapSeverity(r.severity || r.confidence_level),
      category: mapCategory(r.blade || r.product),
      sourceIp: r.src || r.origin,
      destIp: r.dst || r.destination,
      sourcePort: r.s_port ? parseInt(r.s_port, 10) : undefined,
      destPort: r.service ? parseInt(r.service, 10) : undefined,
      protocol: r.proto || r.ip_proto,
      hostname: r.origin_sic_name || r.hostname,
      detectedAt: r.time ? new Date(r.time) : new Date(),
      rawData: r,
    };
  },
};
