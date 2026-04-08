import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

function mapSeverity(level?: number): string {
  if (!level) return "medium";
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 4) return "low";
  return "informational";
}

function mapCategory(groups?: string[]): string {
  if (!groups || groups.length === 0) return "other";
  const g = groups.join(",").toLowerCase();
  if (g.includes("authentication") || g.includes("ssh")) return "credential_access";
  if (g.includes("syscheck") || g.includes("integrity")) return "persistence";
  if (g.includes("web") || g.includes("attack")) return "intrusion";
  if (g.includes("malware") || g.includes("rootcheck")) return "malware";
  if (g.includes("policy")) return "policy_violation";
  return "other";
}

export const wazuhPlugin: ConnectorPlugin = {
  type: "wazuh",
  alertSource: "Wazuh SIEM",
  normalizerKey: "wazuh",
  metadata: {
    name: "Wazuh",
    description: "SIEM / Host IDS - Pulls alerts from Wazuh Indexer (OpenSearch) API",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "Wazuh Indexer URL", type: "url", placeholder: "https://your-wazuh:9200" },
      { key: "username", label: "Username", type: "text", placeholder: "admin" },
      { key: "password", label: "Password", type: "password", placeholder: "Wazuh indexer password" },
    ],
    optionalFields: [{ key: "indexPattern", label: "Index Pattern", type: "text", placeholder: "wazuh-alerts*" }],
    icon: "Eye",
    docsUrl: "https://documentation.wazuh.com/current/user-manual/indexer-api/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
      const res = await httpRequest(`${config.baseUrl}`, { headers: { Authorization: `Basic ${auth}` } });
      if (res.status >= 400) throw new Error(`Wazuh returned ${res.status}`);
      return { success: true, message: "Successfully connected to wazuh", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
    const baseUrl = `${config.baseUrl}/${config.indexPattern || "wazuh-alerts*"}/_search`;
    const headers = { Authorization: `Basic ${auth}`, "Content-Type": "application/json" };

    // Fetch high-severity alerts first (level >= 7), then backfill with lower severity
    const sinceFilter = since ? [{ range: { timestamp: { gte: since.toISOString() } } }] : [];

    // Batch 1: High-severity (level >= 7) — SSH brute force, auth failures, malware, etc.
    const highQuery = {
      size: 500,
      sort: [{ "rule.level": { order: "desc" } }, { timestamp: { order: "desc" } }],
      query: { bool: { must: [{ range: { "rule.level": { gte: 7 } } }, ...sinceFilter] } },
    };
    const highRes = await httpRequest(baseUrl, { method: "POST", headers, body: highQuery });
    const highAlerts = ((highRes.data as Record<string, any>)?.hits?.hits || []).map(
      (h: Record<string, any>) => h._source,
    );

    // Batch 2: Medium-severity (level 3-6) — fill remaining capacity
    const remaining = Math.max(0, 500 - highAlerts.length);
    if (remaining > 0) {
      const medQuery = {
        size: remaining,
        sort: [{ timestamp: { order: "desc" } }],
        query: {
          bool: {
            must: [{ range: { "rule.level": { gte: 3, lt: 7 } } }, ...sinceFilter],
          },
        },
      };
      const medRes = await httpRequest(baseUrl, { method: "POST", headers, body: medQuery });
      const medAlerts = ((medRes.data as Record<string, any>)?.hits?.hits || []).map(
        (h: Record<string, any>) => h._source,
      );
      return [...highAlerts, ...medAlerts];
    }

    return highAlerts;
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Wazuh SIEM",
      sourceEventId: r.id || `wazuh_${r.rule?.id}_${r.timestamp}`,
      title: r.rule?.description || "Wazuh Alert",
      description: r.full_log || r.rule?.description || "",
      severity: mapSeverity(r.rule?.level),
      category: mapCategory(r.rule?.groups),
      sourceIp: r.data?.srcip || r.data?.src_ip,
      destIp: r.data?.dstip || r.data?.dst_ip,
      hostname: r.agent?.name || r.manager?.name,
      userId: r.data?.srcuser || r.data?.dstuser,
      mitreTactic: r.rule?.mitre?.tactic?.[0],
      mitreTechnique: r.rule?.mitre?.id?.[0],
      detectedAt: r.timestamp ? new Date(r.timestamp) : new Date(),
      rawData: r,
    };
  },
};
