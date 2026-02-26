import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(sev?: string | number): string {
  if (!sev) return "medium";
  if (typeof sev === "number") {
    if (sev >= 75) return "critical";
    if (sev >= 50) return "high";
    if (sev >= 25) return "medium";
    return "low";
  }
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

function mapCategory(typeOrTags?: string | string[]): string {
  if (!typeOrTags) return "other";
  const t = (Array.isArray(typeOrTags) ? typeOrTags.join(",") : typeOrTags).toLowerCase();
  if (t.includes("malware")) return "malware";
  if (t.includes("intrusion") || t.includes("exploit")) return "intrusion";
  if (t.includes("credential")) return "credential_access";
  if (t.includes("lateral")) return "lateral_movement";
  if (t.includes("persistence")) return "persistence";
  return "other";
}

function buildAuthHeaders(config: ConnectorConfig): Record<string, string> {
  const headers: Record<string, string> = {};
  if (config.apiKey) {
    headers["Authorization"] = `ApiKey ${config.apiKey}`;
  } else if (config.username && config.password) {
    headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
  }
  return headers;
}

export const elasticPlugin: ConnectorPlugin = {
  type: "elastic",
  alertSource: "Elastic Security",
  normalizerKey: "elastic",
  metadata: {
    name: "Elastic Security",
    description: "SIEM - Pulls detection alerts from Elasticsearch SIEM signals index",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "Elasticsearch URL", type: "url", placeholder: "https://your-elastic:9200" },
      { key: "username", label: "Username", type: "text", placeholder: "elastic" },
      { key: "password", label: "Password", type: "password", placeholder: "Elasticsearch password" },
    ],
    optionalFields: [
      { key: "indexPattern", label: "Index Pattern", type: "text", placeholder: ".siem-signals*" },
    ],
    icon: "Database",
    docsUrl: "https://www.elastic.co/guide/en/security/current/api-overview.html",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const headers = buildAuthHeaders(config);
      const res = await httpRequest(`${config.baseUrl}/_cluster/health`, { headers });
      if (res.status >= 400) throw new Error(`Elastic returned ${res.status}`);
      return { success: true, message: "Successfully connected to elastic", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const headers: Record<string, string> = { "Content-Type": "application/json", ...buildAuthHeaders(config) };
    const indexPattern = config.indexPattern || ".siem-signals*";
    const must: Record<string, unknown>[] = [{ range: { "signal.rule.severity": { gte: 50 } } }];
    if (since) {
      must.push({ range: { "@timestamp": { gte: since.toISOString() } } });
    }
    const res = await httpRequest(`${config.baseUrl}/${indexPattern}/_search`, {
      method: "POST",
      headers,
      body: { size: 100, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must } } },
    });
    return ((res.data as Record<string, any>)?.hits?.hits || []).map((h: Record<string, any>) => h._source);
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    const signal = r.signal || r;
    return {
      source: "Elastic Security",
      sourceEventId: r._id || signal.rule?.id || `elastic_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: signal.rule?.name || signal.rule?.description || "Elastic Security Alert",
      description: signal.rule?.description || "",
      severity: mapSeverity(signal.rule?.severity || signal.severity),
      category: mapCategory(signal.rule?.type || signal.rule?.tags),
      sourceIp: r.source?.ip || signal.source?.ip,
      destIp: r.destination?.ip || signal.destination?.ip,
      hostname: r.host?.name || signal.host?.name,
      userId: r.user?.name || signal.user?.name,
      mitreTactic: signal.rule?.threat?.[0]?.tactic?.name,
      mitreTechnique: signal.rule?.threat?.[0]?.technique?.[0]?.id,
      detectedAt: r["@timestamp"] ? new Date(r["@timestamp"]) : new Date(),
      rawData: r,
    };
  },
};
