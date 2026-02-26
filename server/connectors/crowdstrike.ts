import type { InsertAlert } from "@shared/schema";
import type { ConnectorPlugin, ConnectorConfig, ConnectorTestResult, ConnectorMetadata } from "./connector-plugin";
import { httpRequest } from "./connector-plugin";

async function getToken(config: ConnectorConfig): Promise<string> {
  const formBody = `client_id=${encodeURIComponent(config.clientId!)}&client_secret=${encodeURIComponent(config.clientSecret!)}`;
  const tokenRes = await fetch(`${config.baseUrl}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formBody,
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error("CrowdStrike OAuth2 failed: " + JSON.stringify(tokenData));
  return tokenData.access_token;
}

function mapSeverity(sev: number | string): string {
  const n = typeof sev === "number" ? sev : parseInt(sev, 10) || 0;
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "informational";
}

function mapCategory(tactic?: string): string {
  if (!tactic) return "other";
  const map: Record<string, string> = {
    "Initial Access": "intrusion", "Execution": "malware", "Persistence": "persistence",
    "Privilege Escalation": "privilege_escalation", "Defense Evasion": "malware",
    "Credential Access": "credential_access", "Discovery": "reconnaissance",
    "Lateral Movement": "lateral_movement", "Collection": "data_exfiltration",
    "Command and Control": "command_and_control", "Exfiltration": "data_exfiltration",
    "Impact": "malware",
  };
  return map[tactic] || "other";
}

export const crowdstrikePlugin: ConnectorPlugin = {
  type: "crowdstrike",
  alertSource: "CrowdStrike EDR",
  normalizerKey: "crowdstrike",
  metadata: {
    name: "CrowdStrike Falcon",
    description: "Endpoint Detection & Response (EDR) - Pulls alerts from the CrowdStrike Alerts API v2",
    authType: "oauth2",
    requiredFields: [
      { key: "baseUrl", label: "API Base URL", type: "url", placeholder: "https://api.crowdstrike.com" },
      { key: "clientId", label: "OAuth2 Client ID", type: "text", placeholder: "Your CrowdStrike API Client ID" },
      { key: "clientSecret", label: "OAuth2 Client Secret", type: "password", placeholder: "Your CrowdStrike API Client Secret" },
    ],
    optionalFields: [],
    icon: "Shield",
    docsUrl: "https://developer.crowdstrike.com/docs/openapi/",
  },

  async test(config: ConnectorConfig): Promise<ConnectorTestResult> {
    const start = Date.now();
    try {
      await getToken(config);
      return { success: true, message: "Successfully connected to crowdstrike", latencyMs: Date.now() - start };
    } catch (err: unknown) {
      return { success: false, message: (err as Error).message || "Connection failed", latencyMs: Date.now() - start };
    }
  },

  async fetch(config: ConnectorConfig, since?: Date): Promise<unknown[]> {
    const token = await getToken(config);
    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
    let filter = "product:'epp'+severity:>=3";
    if (since) {
      filter += `+created_timestamp:>'${since.toISOString()}'`;
    }
    const queryRes = await httpRequest(
      `${config.baseUrl}/alerts/queries/alerts/v2?filter=${encodeURIComponent(filter)}&limit=100&sort=created_timestamp.desc`,
      { headers },
    );
    const alertIds = (queryRes.data as Record<string, unknown[]>)?.resources || [];
    if (alertIds.length === 0) return [];
    const detailRes = await httpRequest(`${config.baseUrl}/alerts/entities/alerts/v2`, {
      method: "POST",
      headers,
      body: { composite_ids: alertIds },
    });
    return (detailRes.data as Record<string, unknown[]>)?.resources || [];
  },

  normalize(raw: unknown): Partial<InsertAlert> {
    const r = raw as Record<string, any>;
    return {
      source: "CrowdStrike EDR",
      sourceEventId: r.composite_id || r.detection_id || r.id,
      title: r.description || r.name || "CrowdStrike Alert",
      description: r.description || r.behaviors?.[0]?.description || "",
      severity: mapSeverity(r.severity || r.max_severity),
      category: mapCategory(r.tactic || r.behaviors?.[0]?.tactic),
      sourceIp: r.behaviors?.[0]?.external_ip || r.device?.external_ip,
      hostname: r.device?.hostname || r.hostname,
      userId: r.behaviors?.[0]?.user_name || r.user_name,
      fileHash: r.behaviors?.[0]?.sha256 || r.ioc_value,
      domain: r.behaviors?.[0]?.domain,
      mitreTactic: r.tactic || r.behaviors?.[0]?.tactic,
      mitreTechnique: r.technique_id || r.behaviors?.[0]?.technique_id,
      detectedAt: r.created_timestamp ? new Date(r.created_timestamp) : new Date(),
      rawData: r,
    };
  },
};
