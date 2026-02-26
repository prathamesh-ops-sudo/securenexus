import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "error" || s === "failure") return "high";
  if (s === "warn" || s === "warning") return "medium";
  if (s === "info") return "low";
  return "informational";
}

function mapCategory(eventType?: string): string {
  if (!eventType) return "other";
  const e = eventType.toLowerCase();
  if (e.includes("user.session") || e.includes("login")) return "credential_access";
  if (e.includes("policy")) return "policy_violation";
  if (e.includes("privilege") || e.includes("admin")) return "privilege_escalation";
  if (e.includes("mfa") || e.includes("factor")) return "credential_access";
  return "other";
}

export const oktaPlugin: ConnectorPlugin = {
  type: "okta",
  alertSource: "Okta Identity",
  normalizerKey: "okta",
  metadata: {
    name: "Okta",
    description: "Identity Provider - Pulls system log events from Okta API",
    authType: "token",
    requiredFields: [
      { key: "baseUrl", label: "Okta Org URL", type: "url", placeholder: "https://your-org.okta.com" },
      { key: "apiKey", label: "API Token", type: "password", placeholder: "SSWS API token from Okta Admin" },
    ],
    optionalFields: [],
    icon: "Key",
    docsUrl: "https://developer.okta.com/docs/reference/api/system-log/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const res = await httpRequest(`${config.baseUrl}/api/v1/org`, {
        headers: { "Authorization": `SSWS ${config.apiKey}` },
      });
      if (res.status >= 400) throw new Error(`Okta returned ${res.status}`);
      return { success: true, message: "Successfully connected to okta", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "Authorization": `SSWS ${config.apiKey}`, "Content-Type": "application/json" };
    let url = `${config.baseUrl}/api/v1/logs?filter=${encodeURIComponent('severity eq "WARN" OR severity eq "ERROR"')}&limit=100`;
    if (since) {
      url += `&since=${since.toISOString()}`;
    }
    const res = await httpRequest(url, { headers });
    return Array.isArray(res.data) ? (res.data as unknown[]) : [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Okta Identity",
      sourceEventId: r.uuid || `okta_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.displayMessage || r.eventType || "Okta Event",
      description: r.displayMessage || "",
      severity: mapSeverity(r.severity),
      category: mapCategory(r.eventType),
      sourceIp: r.client?.ipAddress || r.request?.ipChain?.[0]?.ip,
      hostname: r.client?.device,
      userId: r.actor?.alternateId || r.actor?.displayName,
      detectedAt: r.published ? new Date(r.published) : new Date(),
      rawData: r,
    };
  },
};
