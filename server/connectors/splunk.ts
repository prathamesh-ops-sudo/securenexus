import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";
import { logger } from "../logger";

function mapSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "critical" || s === "1") return "critical";
  if (s === "high" || s === "2") return "high";
  if (s === "medium" || s === "3" || s === "warning") return "medium";
  if (s === "low" || s === "4") return "low";
  return "informational";
}

export const splunkPlugin: ConnectorPlugin = {
  type: "splunk",
  alertSource: "Splunk SIEM",
  normalizerKey: "splunk",
  metadata: {
    name: "Splunk Enterprise / Cloud",
    description: "SIEM - Pulls search results from Splunk REST API with custom SPL queries",
    authType: "basic",
    requiredFields: [
      { key: "baseUrl", label: "Splunk API URL", type: "url", placeholder: "https://your-splunk:8089" },
      { key: "username", label: "Username", type: "text", placeholder: "admin" },
      { key: "password", label: "Password", type: "password", placeholder: "Splunk password" },
    ],
    optionalFields: [
      { key: "searchQuery", label: "SPL Search Query", type: "text", placeholder: "search index=main sourcetype=syslog level=error | head 100" },
    ],
    icon: "Database",
    docsUrl: "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
      const res = await httpRequest(`${config.baseUrl}/services/server/info?output_mode=json`, {
        headers: { Authorization: `Basic ${auth}` },
      });
      if (res.status >= 400) throw new Error(`Splunk returned ${res.status}`);
      return { success: true, message: "Successfully connected to splunk", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
    const headers = { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" };
    const searchQuery = config.searchQuery || "search index=main sourcetype=syslog OR sourcetype=WinEventLog level=error OR level=critical | head 100";
    const earliest = since ? since.toISOString() : "-24h";
    const jobRes = await fetch(`${config.baseUrl}/services/search/jobs/export`, {
      method: "POST",
      headers: { ...headers, Accept: "application/json" },
      body: `search=${encodeURIComponent(searchQuery)}&output_mode=json&earliest_time=${encodeURIComponent(earliest)}&exec_mode=oneshot`,
    });
    const text = await jobRes.text();
    const results: unknown[] = [];
    for (const line of text.split("\n").filter(l => l.trim())) {
      try {
        const parsed = JSON.parse(line);
        if (parsed.result) results.push(parsed.result);
      } catch (parseErr) {
        logger.child("connector-splunk").warn("Skipping malformed JSON line", { line: line.slice(0, 200), error: String(parseErr) });
      }
    }
    return results;
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "Splunk SIEM",
      sourceEventId: r._cd || r._serial || r.event_id || `splunk_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      title: r.source || r.sourcetype || "Splunk Event",
      description: r._raw || r.message || JSON.stringify(r).slice(0, 500),
      severity: mapSeverity(r.severity || r.urgency || r.level),
      category: r.category || "other",
      sourceIp: r.src_ip || r.src || r.source_ip,
      destIp: r.dest_ip || r.dest || r.destination_ip,
      sourcePort: r.src_port ? parseInt(r.src_port, 10) : undefined,
      destPort: r.dest_port ? parseInt(r.dest_port, 10) : undefined,
      hostname: r.host || r.hostname,
      userId: r.user || r.src_user,
      detectedAt: r._time ? new Date(r._time) : new Date(),
      rawData: r,
    };
  },
};
