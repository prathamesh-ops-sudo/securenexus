import { type Connector, type InsertAlert, type ConnectorJobRun, type InsertConnectorJobRun } from "@shared/schema";
import { normalizeAlert, toInsertAlert, SOURCE_KEYS } from "./normalizer";
import { storage } from "./storage";
import { config as appConfig } from "./config";

export interface ConnectorConfig {
  baseUrl: string;
  clientId?: string;
  clientSecret?: string;
  apiKey?: string;
  username?: string;
  password?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  token?: string;
  tenantId?: string;
  searchQuery?: string;
  indexPattern?: string;
  datacenter?: string;
  siteToken?: string;
  orgKey?: string;
}

export interface SyncResult {
  alertsReceived: number;
  alertsCreated: number;
  alertsDeduped: number;
  alertsFailed: number;
  errors: string[];
  rawAlerts: any[];
}

export interface ConnectorTestResult {
  success: boolean;
  message: string;
  latencyMs: number;
  details?: any;
}

type SourceNormalizerKey = keyof typeof SOURCE_KEYS;

const SOURCE_MAP: Record<string, { alertSource: string; normalizerKey: string }> = {
  crowdstrike: { alertSource: "CrowdStrike EDR", normalizerKey: "crowdstrike" },
  splunk: { alertSource: "Splunk SIEM", normalizerKey: "splunk" },
  wiz: { alertSource: "Wiz Cloud", normalizerKey: "wiz" },
  wazuh: { alertSource: "Wazuh SIEM", normalizerKey: "wazuh" },
  paloalto: { alertSource: "Palo Alto Firewall", normalizerKey: "paloalto" },
  guardduty: { alertSource: "AWS GuardDuty", normalizerKey: "guardduty" },
  defender: { alertSource: "Microsoft Defender", normalizerKey: "defender" },
  sentinelone: { alertSource: "SentinelOne EDR", normalizerKey: "sentinelone" },
  suricata: { alertSource: "Suricata IDS", normalizerKey: "suricata" },
  elastic: { alertSource: "Elastic Security", normalizerKey: "elastic" },
  qradar: { alertSource: "IBM QRadar", normalizerKey: "qradar" },
  fortigate: { alertSource: "Fortinet FortiGate", normalizerKey: "fortigate" },
  carbonblack: { alertSource: "Carbon Black EDR", normalizerKey: "carbonblack" },
  qualys: { alertSource: "Qualys VMDR", normalizerKey: "qualys" },
  tenable: { alertSource: "Tenable Nessus", normalizerKey: "tenable" },
  umbrella: { alertSource: "Cisco Umbrella", normalizerKey: "umbrella" },
  darktrace: { alertSource: "Darktrace", normalizerKey: "darktrace" },
  rapid7: { alertSource: "Rapid7 InsightIDR", normalizerKey: "rapid7" },
  trendmicro: { alertSource: "Trend Micro Vision One", normalizerKey: "trendmicro" },
  okta: { alertSource: "Okta Identity", normalizerKey: "okta" },
  proofpoint: { alertSource: "Proofpoint Email", normalizerKey: "proofpoint" },
  snort: { alertSource: "Snort IDS", normalizerKey: "snort" },
  zscaler: { alertSource: "Zscaler ZIA", normalizerKey: "zscaler" },
  checkpoint: { alertSource: "Check Point", normalizerKey: "checkpoint" },
};

async function httpRequest(url: string, options: {
  method?: string;
  headers?: Record<string, string>;
  body?: any;
  timeout?: number;
  rejectUnauthorized?: boolean;
}): Promise<{ status: number; data: any }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);
  try {
    const res = await fetch(url, {
      method: options.method || "GET",
      headers: options.headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data };
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") throw new Error("Request timed out");
    throw err;
  }
}

async function crowdstrikeGetToken(config: ConnectorConfig): Promise<string> {
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

async function fetchCrowdStrike(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const token = await crowdstrikeGetToken(config);
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  let filter = "product:'epp'+severity:>=3";
  if (since) {
    filter += `+created_timestamp:>'${since.toISOString()}'`;
  }
  const queryRes = await httpRequest(
    `${config.baseUrl}/alerts/queries/alerts/v2?filter=${encodeURIComponent(filter)}&limit=100&sort=created_timestamp.desc`,
    { headers }
  );
  const alertIds = queryRes.data?.resources || [];
  if (alertIds.length === 0) return [];

  const detailRes = await httpRequest(`${config.baseUrl}/alerts/entities/alerts/v2`, {
    method: "POST",
    headers,
    body: { composite_ids: alertIds },
  });
  return detailRes.data?.resources || [];
}

async function fetchSplunk(config: ConnectorConfig, since?: Date): Promise<any[]> {
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
  const results: any[] = [];
  for (const line of text.split("\n").filter(l => l.trim())) {
    try {
      const parsed = JSON.parse(line);
      if (parsed.result) results.push(parsed.result);
    } catch {}
  }
  return results;
}

async function wizGetToken(config: ConnectorConfig): Promise<string> {
  const authUrl = "https://auth.app.wiz.io/oauth/token";
  const tokenRes = await fetch(authUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: config.clientId!,
      client_secret: config.clientSecret!,
      audience: "wiz-api",
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error("Wiz OAuth2 failed: " + JSON.stringify(tokenData));
  return tokenData.access_token;
}

async function fetchWiz(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const token = await wizGetToken(config);
  const dc = config.datacenter || "us1";
  const endpoint = `https://api.${dc}.app.wiz.io/graphql`;
  const afterFilter = since ? `createdAt: { after: "${since.toISOString()}" }` : "";
  const query = `query {
    issues(first: 100, filterBy: { status: [OPEN, IN_PROGRESS], severity: [CRITICAL, HIGH, MEDIUM] ${afterFilter ? ", " + afterFilter : ""} }) {
      nodes {
        id type status severity createdAt updatedAt
        notes { text }
        entitySnapshot { id type nativeType name cloudPlatform region subscriptionId }
        sourceRule { id name description }
      }
      pageInfo { hasNextPage endCursor }
    }
  }`;
  const res = await httpRequest(endpoint, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: { query },
  });
  return res.data?.data?.issues?.nodes || [];
}

async function fetchWazuh(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
  const url = `${config.baseUrl}/${config.indexPattern || "wazuh-alerts*"}/_search`;
  const query: any = {
    size: 100,
    sort: [{ timestamp: { order: "desc" } }],
    query: {
      bool: {
        must: [{ range: { "rule.level": { gte: 7 } } }],
      },
    },
  };
  if (since) {
    query.query.bool.must.push({ range: { timestamp: { gte: since.toISOString() } } });
  }
  const res = await httpRequest(url, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
    body: query,
  });
  return (res.data?.hits?.hits || []).map((h: any) => h._source);
}

async function fetchPaloAlto(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "x-xdr-auth-id": config.clientId || "1",
    Authorization: config.apiKey!,
    "Content-Type": "application/json",
  };
  const filters: any[] = [];
  if (since) {
    filters.push({
      field: "creation_time",
      operator: "gte",
      value: since.getTime(),
    });
  }
  const body: any = {
    request_data: {
      filters,
      search_from: 0,
      search_to: 100,
      sort: { field: "creation_time", keyword: "desc" },
    },
  };
  const res = await httpRequest(`${config.baseUrl}/public_api/v1/incidents/get_incidents`, {
    method: "POST",
    headers,
    body,
  });
  return res.data?.reply?.incidents || [];
}

async function fetchGuardDuty(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const { GuardDutyClient, ListDetectorsCommand, ListFindingsCommand, GetFindingsCommand } = await import("@aws-sdk/client-guardduty");
  const resolvedAccessKeyId = config.accessKeyId || appConfig.aws.accessKeyId;
  const resolvedSecretAccessKey = config.secretAccessKey || appConfig.aws.secretAccessKey;
  const client = new GuardDutyClient({
    region: config.region || "us-east-1",
    ...(resolvedAccessKeyId && resolvedSecretAccessKey
      ? { credentials: { accessKeyId: resolvedAccessKeyId, secretAccessKey: resolvedSecretAccessKey } }
      : {}),
  });
  const detectorsRes = await client.send(new ListDetectorsCommand({}));
  const detectorId = detectorsRes.DetectorIds?.[0];
  if (!detectorId) return [];

  const criterion: any = { severity: { Gte: 4 } };
  if (since) {
    criterion.updatedAt = { Gte: since.getTime() };
  }
  const findingsRes = await client.send(new ListFindingsCommand({
    DetectorId: detectorId,
    FindingCriteria: { Criterion: criterion },
    MaxResults: 50,
  }));
  if (!findingsRes.FindingIds?.length) return [];

  const detailsRes = await client.send(new GetFindingsCommand({
    DetectorId: detectorId,
    FindingIds: findingsRes.FindingIds,
  }));
  return detailsRes.Findings || [];
}

async function defenderGetToken(config: ConnectorConfig): Promise<string> {
  const tokenRes = await fetch(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=client_credentials&client_id=${encodeURIComponent(config.clientId!)}&client_secret=${encodeURIComponent(config.clientSecret!)}&scope=https://graph.microsoft.com/.default`,
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error("Defender OAuth2 failed: " + JSON.stringify(tokenData));
  return tokenData.access_token;
}

async function fetchDefender(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const token = await defenderGetToken(config);
  let url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100&$orderby=createdDateTime desc";
  if (since) {
    url += `&$filter=createdDateTime ge ${since.toISOString()}`;
  }
  const res = await httpRequest(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data?.value || [];
}

async function fetchSentinelOne(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers = { Authorization: `ApiToken ${config.apiKey}`, "Content-Type": "application/json" };
  let url = `${config.baseUrl}/web/api/v2.1/threats?limit=100&sortBy=createdAt&sortOrder=desc`;
  if (since) {
    url += `&createdAt__gte=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return res.data?.data || [];
}

async function fetchElastic(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.apiKey) {
    headers["Authorization"] = `ApiKey ${config.apiKey}`;
  } else if (config.username && config.password) {
    headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
  }
  const indexPattern = config.indexPattern || ".siem-signals*";
  const must: any[] = [
    { range: { "signal.rule.severity": { gte: 50 } } },
  ];
  if (since) {
    must.push({ range: { "@timestamp": { gte: since.toISOString() } } });
  }
  const res = await httpRequest(`${config.baseUrl}/${indexPattern}/_search`, {
    method: "POST",
    headers,
    body: { size: 100, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must } } },
  });
  return (res.data?.hits?.hits || []).map((h: any) => h._source);
}

async function fetchQRadar(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "SEC": config.apiKey!,
    "Content-Type": "application/json",
    "Accept": "application/json",
  };
  let url = `${config.baseUrl}/api/siem/offenses?filter=magnitude%20%3E%3D%205&Range=items%3D0-99`;
  if (since) {
    const sinceMs = since.getTime();
    url += `&filter=start_time%20%3E%20${sinceMs}`;
  }
  const res = await httpRequest(url, { headers });
  return Array.isArray(res.data) ? res.data : [];
}

async function fetchFortiGate(config: ConnectorConfig, since?: Date): Promise<any[]> {
  let url = `${config.baseUrl}/api/v2/log/event?rows=100&filter=level>=warning&access_token=${encodeURIComponent(config.apiKey!)}`;
  if (since) {
    url += `&since=${since.toISOString()}`;
  }
  const res = await httpRequest(url, {
    headers: { "Content-Type": "application/json" },
  });
  return res.data?.results || [];
}

async function fetchCarbonBlack(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const orgKey = config.orgKey || config.clientId || "default";
  const headers: Record<string, string> = {
    "X-Auth-Token": config.apiKey!,
    "Content-Type": "application/json",
  };
  const criteria: any = {};
  if (since) {
    criteria.create_time = { start: since.toISOString() };
  }
  const res = await httpRequest(`${config.baseUrl}/api/alerts/v7/orgs/${orgKey}/alerts/_search`, {
    method: "POST",
    headers,
    body: { criteria, rows: 100, sort: [{ field: "create_time", order: "DESC" }] },
  });
  return res.data?.results || [];
}

async function fetchQualys(config: ConnectorConfig, since?: Date): Promise<any[]> {
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
  const res = await httpRequest(`${config.baseUrl}/api/2.0/fo/asset/host/vm/detection/`, {
    method: "POST",
    headers,
    body: undefined,
  });
  const rawRes = await fetch(`${config.baseUrl}/api/2.0/fo/asset/host/vm/detection/?${body}`, {
    method: "POST",
    headers,
  });
  const text = await rawRes.text();
  let data;
  try { data = JSON.parse(text); } catch { data = []; }
  return Array.isArray(data) ? data : data?.data?.host_list_vm_detection_output?.response?.host_list?.host || [];
}

async function fetchTenable(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const secretKey = config.token || "";
  const headers: Record<string, string> = {
    "X-ApiKeys": `accessKey=${config.apiKey};secretKey=${secretKey}`,
    "Content-Type": "application/json",
  };
  let url = `${config.baseUrl}/vulns?date_range=7&severity[]=critical&severity[]=high`;
  if (since) {
    url += `&since=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return res.data?.vulnerabilities || res.data?.vulns || [];
}

async function fetchUmbrella(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "Authorization": `Bearer ${config.apiKey}`,
    "Content-Type": "application/json",
  };
  let url = `${config.baseUrl}/v2/events?limit=100`;
  if (since) {
    url += `&from=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return res.data?.data || res.data?.events || [];
}

async function fetchDarktrace(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (config.token) {
    headers["Authorization"] = `Bearer ${config.token}`;
  }
  let url = `${config.baseUrl}/modelbreaches?count=100`;
  if (since) {
    url += `&from=${Math.floor(since.getTime() / 1000)}`;
  }
  const res = await httpRequest(url, { headers });
  return Array.isArray(res.data) ? res.data : res.data?.breaches || [];
}

async function fetchRapid7(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "X-Api-Key": config.apiKey!,
    "Content-Type": "application/json",
  };
  let url = `${config.baseUrl}/idr/v2/investigations?statuses=OPEN&multi-customer=false&size=100`;
  if (since) {
    url += `&start_time=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return res.data?.data || [];
}

async function fetchTrendMicro(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "Authorization": `Bearer ${config.token}`,
    "Content-Type": "application/json",
  };
  let url = `${config.baseUrl}/v3.0/workbench/alerts?top=100&orderBy=createdDateTime%20desc`;
  if (since) {
    url += `&startDateTime=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return res.data?.items || res.data?.data || [];
}

async function fetchOkta(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = {
    "Authorization": `SSWS ${config.apiKey}`,
    "Content-Type": "application/json",
  };
  let url = `${config.baseUrl}/api/v1/logs?filter=${encodeURIComponent('severity eq "WARN" OR severity eq "ERROR"')}&limit=100`;
  if (since) {
    url += `&since=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return Array.isArray(res.data) ? res.data : [];
}

async function fetchProofpoint(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
  const headers: Record<string, string> = {
    "Authorization": `Basic ${auth}`,
    "Content-Type": "application/json",
  };
  const sinceSeconds = since ? Math.floor((Date.now() - since.getTime()) / 1000) : 86400;
  const url = `${config.baseUrl}/v2/siem/messages/delivered?sinceSeconds=${sinceSeconds}&format=JSON`;
  const res = await httpRequest(url, { headers });
  return res.data?.messagesDelivered || res.data?.records || [];
}

async function fetchSnort(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.apiKey) {
    headers["Authorization"] = `Bearer ${config.apiKey}`;
  } else if (config.username && config.password) {
    headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
  }
  let url = `${config.baseUrl}/api/alerts?limit=100`;
  if (since) {
    url += `&since=${since.toISOString()}`;
  }
  const res = await httpRequest(url, { headers });
  return Array.isArray(res.data) ? res.data : res.data?.alerts || [];
}

async function fetchZscaler(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const authHeaders: Record<string, string> = { "Content-Type": "application/json" };
  const authRes = await httpRequest(`${config.baseUrl}/api/v1/authenticatedSession`, {
    method: "POST",
    headers: authHeaders,
    body: {
      apiKey: config.apiKey,
      username: config.username,
      password: config.password,
    },
  });
  const cookie = authRes.data?.authType === "session" ? authRes.data?.obfuscateApiKey : undefined;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Cookie": cookie ? `JSESSIONID=${cookie}` : "",
  };
  const body: any = { type: "all", pageSize: 100 };
  if (since) {
    body.startTime = since.getTime();
  }
  const res = await httpRequest(`${config.baseUrl}/api/v1/webApplicationRules`, {
    method: "POST",
    headers,
    body,
  });
  return res.data?.list || res.data?.rules || [];
}

async function fetchCheckPoint(config: ConnectorConfig, since?: Date): Promise<any[]> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.apiKey) {
    headers["X-chkp-sid"] = config.apiKey;
  } else if (config.username && config.password) {
    const loginRes = await httpRequest(`${config.baseUrl}/web_api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: { user: config.username, password: config.password },
    });
    if (loginRes.data?.sid) {
      headers["X-chkp-sid"] = loginRes.data.sid;
    }
  }
  const body: any = { "new-query": { filter: "blade:IPS OR blade:Anti-Bot OR blade:Threat Emulation" }, limit: 100 };
  if (since) {
    body["new-query"]["time-frame"] = `last-${Math.ceil((Date.now() - since.getTime()) / 3600000)}hours`;
  }
  const res = await httpRequest(`${config.baseUrl}/web_api/show-logs`, {
    method: "POST",
    headers,
    body,
  });
  return res.data?.logs || res.data?.tasks?.[0]?.task_details || [];
}

function normalizeCrowdStrikeAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "CrowdStrike EDR",
    sourceEventId: raw.composite_id || raw.detection_id || raw.id,
    title: raw.description || raw.name || "CrowdStrike Alert",
    description: raw.description || raw.behaviors?.[0]?.description || "",
    severity: mapCrowdStrikeSeverity(raw.severity || raw.max_severity),
    category: mapCrowdStrikeCategory(raw.tactic || raw.behaviors?.[0]?.tactic),
    sourceIp: raw.behaviors?.[0]?.external_ip || raw.device?.external_ip,
    hostname: raw.device?.hostname || raw.hostname,
    userId: raw.behaviors?.[0]?.user_name || raw.user_name,
    fileHash: raw.behaviors?.[0]?.sha256 || raw.ioc_value,
    domain: raw.behaviors?.[0]?.domain,
    mitreTactic: raw.tactic || raw.behaviors?.[0]?.tactic,
    mitreTechnique: raw.technique_id || raw.behaviors?.[0]?.technique_id,
    detectedAt: raw.created_timestamp ? new Date(raw.created_timestamp) : new Date(),
    rawData: raw,
  };
}

function normalizeSplunkAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Splunk SIEM",
    sourceEventId: raw._cd || raw._serial || raw.event_id || `splunk_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    title: raw.source || raw.sourcetype || "Splunk Event",
    description: raw._raw || raw.message || JSON.stringify(raw).slice(0, 500),
    severity: mapSplunkSeverity(raw.severity || raw.urgency || raw.level),
    category: raw.category || "other",
    sourceIp: raw.src_ip || raw.src || raw.source_ip,
    destIp: raw.dest_ip || raw.dest || raw.destination_ip,
    sourcePort: raw.src_port ? parseInt(raw.src_port) : undefined,
    destPort: raw.dest_port ? parseInt(raw.dest_port) : undefined,
    hostname: raw.host || raw.hostname,
    userId: raw.user || raw.src_user,
    detectedAt: raw._time ? new Date(raw._time) : new Date(),
    rawData: raw,
  };
}

function normalizeWizAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Wiz Cloud",
    sourceEventId: raw.id,
    title: raw.sourceRule?.name || raw.type || "Wiz Issue",
    description: raw.sourceRule?.description || raw.notes?.[0]?.text || "",
    severity: (raw.severity || "medium").toLowerCase(),
    category: mapWizCategory(raw.type),
    hostname: raw.entitySnapshot?.name,
    detectedAt: raw.createdAt ? new Date(raw.createdAt) : new Date(),
    rawData: raw,
    normalizedData: {
      cloudPlatform: raw.entitySnapshot?.cloudPlatform,
      region: raw.entitySnapshot?.region,
      resourceType: raw.entitySnapshot?.nativeType,
      subscriptionId: raw.entitySnapshot?.subscriptionId,
    },
  };
}

function normalizeWazuhAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Wazuh SIEM",
    sourceEventId: raw.id || `wazuh_${raw.rule?.id}_${raw.timestamp}`,
    title: raw.rule?.description || "Wazuh Alert",
    description: raw.full_log || raw.rule?.description || "",
    severity: mapWazuhSeverity(raw.rule?.level),
    category: mapWazuhCategory(raw.rule?.groups),
    sourceIp: raw.data?.srcip || raw.data?.src_ip,
    destIp: raw.data?.dstip || raw.data?.dst_ip,
    hostname: raw.agent?.name || raw.manager?.name,
    userId: raw.data?.srcuser || raw.data?.dstuser,
    mitreTactic: raw.rule?.mitre?.tactic?.[0],
    mitreTechnique: raw.rule?.mitre?.id?.[0],
    detectedAt: raw.timestamp ? new Date(raw.timestamp) : new Date(),
    rawData: raw,
  };
}

function normalizePaloAltoAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Palo Alto Firewall",
    sourceEventId: raw.incident_id?.toString() || `pa_${Date.now()}`,
    title: raw.description || raw.alert_name || "Palo Alto Incident",
    description: raw.description || "",
    severity: mapPaloAltoSeverity(raw.severity),
    category: raw.category || "intrusion",
    sourceIp: raw.src_ip || raw.hosts?.[0],
    destIp: raw.dst_ip,
    hostname: raw.hosts?.[0],
    userId: raw.users?.[0],
    detectedAt: raw.creation_time ? new Date(raw.creation_time) : new Date(),
    rawData: raw,
  };
}

function normalizeGuardDutyAlert(raw: any): Partial<InsertAlert> {
  const resource = raw.Resource || {};
  const service = raw.Service || {};
  const action = service.Action || {};
  return {
    source: "AWS GuardDuty",
    sourceEventId: raw.Id || raw.id,
    title: raw.Title || raw.Type || "GuardDuty Finding",
    description: raw.Description || "",
    severity: mapGuardDutySeverity(raw.Severity),
    category: mapGuardDutyCategory(raw.Type),
    sourceIp: action.NetworkConnectionAction?.RemoteIpDetails?.IpAddressV4 ||
              action.AwsApiCallAction?.RemoteIpDetails?.IpAddressV4,
    hostname: resource.InstanceDetails?.InstanceId,
    domain: action.DnsRequestAction?.Domain,
    detectedAt: raw.CreatedAt ? new Date(raw.CreatedAt) : new Date(),
    rawData: raw,
    normalizedData: {
      accountId: raw.AccountId,
      region: raw.Region,
      resourceType: raw.Resource?.ResourceType,
    },
  };
}

function normalizeDefenderAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Microsoft Defender",
    sourceEventId: raw.id,
    title: raw.title || "Defender Alert",
    description: raw.description || "",
    severity: (raw.severity || "medium").toLowerCase(),
    category: mapDefenderCategory(raw.category),
    sourceIp: raw.evidence?.[0]?.ipAddress,
    hostname: raw.evidence?.[0]?.deviceDnsName,
    userId: raw.evidence?.[0]?.userAccount?.accountName,
    fileHash: raw.evidence?.[0]?.fileDetails?.sha256,
    mitreTactic: raw.mitreTechniques?.[0]?.split(".")?.[0],
    mitreTechnique: raw.mitreTechniques?.[0],
    detectedAt: raw.createdDateTime ? new Date(raw.createdDateTime) : new Date(),
    rawData: raw,
  };
}

function normalizeSentinelOneAlert(raw: any): Partial<InsertAlert> {
  const info = raw.threatInfo || raw;
  return {
    source: "SentinelOne EDR",
    sourceEventId: raw.id?.toString() || info.threatId,
    title: info.threatName || info.classification || "SentinelOne Threat",
    description: info.storyline || info.classification || "",
    severity: mapS1Severity(info.confidenceLevel || info.analystVerdict),
    category: mapS1Category(info.classification),
    sourceIp: raw.agentRealtimeInfo?.activeInterfaces?.[0]?.inet?.[0],
    hostname: raw.agentDetectionInfo?.name || raw.agentRealtimeInfo?.agentComputerName,
    userId: raw.agentDetectionInfo?.agentLastLoggedInUserName,
    fileHash: info.sha256 || info.md5,
    domain: info.originDomain,
    detectedAt: info.createdAt ? new Date(info.createdAt) : new Date(),
    rawData: raw,
  };
}

function normalizeElasticAlert(raw: any): Partial<InsertAlert> {
  const signal = raw.signal || raw;
  return {
    source: "Elastic Security",
    sourceEventId: raw._id || signal.rule?.id || `elastic_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    title: signal.rule?.name || signal.rule?.description || "Elastic Security Alert",
    description: signal.rule?.description || "",
    severity: mapElasticSeverity(signal.rule?.severity || signal.severity),
    category: mapElasticCategory(signal.rule?.type || signal.rule?.tags),
    sourceIp: raw.source?.ip || signal.source?.ip,
    destIp: raw.destination?.ip || signal.destination?.ip,
    hostname: raw.host?.name || signal.host?.name,
    userId: raw.user?.name || signal.user?.name,
    mitreTactic: signal.rule?.threat?.[0]?.tactic?.name,
    mitreTechnique: signal.rule?.threat?.[0]?.technique?.[0]?.id,
    detectedAt: raw["@timestamp"] ? new Date(raw["@timestamp"]) : new Date(),
    rawData: raw,
  };
}

function normalizeQRadarAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "IBM QRadar",
    sourceEventId: raw.id?.toString() || `qradar_${Date.now()}`,
    title: raw.description || raw.offense_type_str || "QRadar Offense",
    description: raw.description || "",
    severity: mapQRadarSeverity(raw.magnitude || raw.severity),
    category: raw.offense_type_str || "other",
    sourceIp: raw.offense_source,
    destIp: raw.local_destination_address_ids?.[0]?.toString(),
    hostname: raw.domain_str,
    detectedAt: raw.start_time ? new Date(raw.start_time) : new Date(),
    rawData: raw,
  };
}

function normalizeFortiGateAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Fortinet FortiGate",
    sourceEventId: raw.logid || raw.eventid || `forti_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    title: raw.msg || raw.action || "FortiGate Event",
    description: raw.msg || raw.logdesc || "",
    severity: mapFortiGateSeverity(raw.level || raw.severity),
    category: mapFortiGateCategory(raw.type || raw.subtype),
    sourceIp: raw.srcip || raw.srcintf,
    destIp: raw.dstip,
    sourcePort: raw.srcport ? parseInt(raw.srcport) : undefined,
    destPort: raw.dstport ? parseInt(raw.dstport) : undefined,
    hostname: raw.devname || raw.hostname,
    userId: raw.user || raw.srcuser,
    detectedAt: raw.date && raw.time ? new Date(`${raw.date}T${raw.time}`) : new Date(),
    rawData: raw,
  };
}

function normalizeCarbonBlackAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Carbon Black EDR",
    sourceEventId: raw.id || raw.legacy_alert_id || `cb_${Date.now()}`,
    title: raw.reason || raw.type || "Carbon Black Alert",
    description: raw.reason || raw.threat_cause_actor_name || "",
    severity: mapCarbonBlackSeverity(raw.severity),
    category: mapCarbonBlackCategory(raw.type || raw.category),
    sourceIp: raw.device_internal_ip || raw.netconn_local_ip,
    hostname: raw.device_name || raw.device_os,
    userId: raw.device_username,
    fileHash: raw.threat_cause_actor_sha256 || raw.process_sha256,
    mitreTactic: raw.attack_tactic,
    mitreTechnique: raw.attack_technique,
    detectedAt: raw.create_time ? new Date(raw.create_time) : new Date(),
    rawData: raw,
  };
}

function normalizeQualysAlert(raw: any): Partial<InsertAlert> {
  const detection = raw.DETECTION_LIST?.DETECTION?.[0] || raw;
  return {
    source: "Qualys VMDR",
    sourceEventId: detection.QID?.toString() || raw.ID?.toString() || `qualys_${Date.now()}`,
    title: detection.TITLE || `Qualys Vulnerability QID ${detection.QID || "unknown"}`,
    description: detection.RESULTS || detection.TITLE || "",
    severity: mapQualysSeverity(detection.SEVERITY || raw.SEVERITY),
    category: "cloud_misconfiguration",
    hostname: raw.DNS || raw.IP || raw.HOSTNAME,
    sourceIp: raw.IP,
    detectedAt: detection.LAST_FOUND_DATETIME ? new Date(detection.LAST_FOUND_DATETIME) : new Date(),
    rawData: raw,
  };
}

function normalizeTenableAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Tenable Nessus",
    sourceEventId: raw.plugin_id?.toString() || raw.id?.toString() || `tenable_${Date.now()}`,
    title: raw.plugin_name || raw.name || "Tenable Vulnerability",
    description: raw.description || raw.synopsis || "",
    severity: mapTenableSeverity(raw.severity || raw.risk_factor),
    category: "cloud_misconfiguration",
    hostname: raw.hostname || raw.host?.hostname,
    sourceIp: raw.host_ip || raw.host?.ip,
    detectedAt: raw.last_found ? new Date(raw.last_found) : new Date(),
    rawData: raw,
  };
}

function normalizeUmbrellaAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Cisco Umbrella",
    sourceEventId: raw.eventId || raw.id || `umbrella_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    title: raw.actionTaken || raw.categories?.[0] || "Umbrella Security Event",
    description: raw.destination || raw.url || "",
    severity: mapUmbrellaSeverity(raw.verdict || raw.actionTaken),
    category: mapUmbrellaCategory(raw.categories),
    sourceIp: raw.internalIp || raw.externalIp,
    destIp: raw.destinationIp,
    domain: raw.destination || raw.domain,
    hostname: raw.hostname || raw.deviceName,
    userId: raw.identity || raw.email,
    detectedAt: raw.timestamp ? new Date(raw.timestamp) : new Date(),
    rawData: raw,
  };
}

function normalizeDarktraceAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Darktrace",
    sourceEventId: raw.pbid?.toString() || raw.id?.toString() || `darktrace_${Date.now()}`,
    title: raw.modelName || raw.model?.then?.name || "Darktrace Model Breach",
    description: raw.commentCount ? `Model breach with ${raw.commentCount} comments` : raw.modelName || "",
    severity: mapDarktraceSeverity(raw.score || raw.strength),
    category: mapDarktraceCategory(raw.modelName || raw.model?.then?.name),
    sourceIp: raw.device?.ip,
    hostname: raw.device?.hostname || raw.device?.label,
    detectedAt: raw.time ? new Date(raw.time * 1000) : new Date(),
    rawData: raw,
  };
}

function normalizeRapid7Alert(raw: any): Partial<InsertAlert> {
  return {
    source: "Rapid7 InsightIDR",
    sourceEventId: raw.id || raw.rrn || `rapid7_${Date.now()}`,
    title: raw.title || raw.alert_type_name || "Rapid7 Investigation",
    description: raw.title || "",
    severity: mapRapid7Severity(raw.priority || raw.severity),
    category: mapRapid7Category(raw.source || raw.alert_type),
    sourceIp: raw.source_ip,
    hostname: raw.asset_name,
    userId: raw.assignee?.email || raw.responsibility,
    detectedAt: raw.created_time ? new Date(raw.created_time) : new Date(),
    rawData: raw,
  };
}

function normalizeTrendMicroAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Trend Micro Vision One",
    sourceEventId: raw.id || raw.alertId || `trendmicro_${Date.now()}`,
    title: raw.alertName || raw.model || "Trend Micro Alert",
    description: raw.description || raw.alertName || "",
    severity: mapTrendMicroSeverity(raw.severity || raw.riskLevel),
    category: mapTrendMicroCategory(raw.alertType || raw.model),
    sourceIp: raw.srcIp || raw.highlightedObjects?.[0]?.value,
    hostname: raw.hostName || raw.endpointName,
    userId: raw.mailbox || raw.accountName,
    detectedAt: raw.createdDateTime ? new Date(raw.createdDateTime) : new Date(),
    rawData: raw,
  };
}

function normalizeOktaAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Okta Identity",
    sourceEventId: raw.uuid || raw.eventId || `okta_${Date.now()}`,
    title: raw.displayMessage || raw.eventType || "Okta Security Event",
    description: raw.displayMessage || "",
    severity: mapOktaSeverity(raw.severity || raw.outcome?.result),
    category: mapOktaCategory(raw.eventType),
    sourceIp: raw.client?.ipAddress || raw.request?.ipChain?.[0]?.ip,
    hostname: raw.client?.device,
    userId: raw.actor?.alternateId || raw.actor?.displayName,
    domain: raw.client?.geographicalContext?.country,
    detectedAt: raw.published ? new Date(raw.published) : new Date(),
    rawData: raw,
  };
}

function normalizeProofpointAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Proofpoint Email",
    sourceEventId: raw.GUID || raw.messageID || `proofpoint_${Date.now()}`,
    title: raw.subject || raw.threatsInfoMap?.[0]?.threat || "Proofpoint Email Alert",
    description: raw.subject || "",
    severity: mapProofpointSeverity(raw.spamScore || raw.phishScore || raw.malwareScore),
    category: mapProofpointCategory(raw.threatsInfoMap?.[0]?.threatType),
    sourceIp: raw.senderIP,
    userId: raw.sender || raw.fromAddress?.[0],
    domain: raw.senderIP,
    detectedAt: raw.messageTime ? new Date(raw.messageTime) : new Date(),
    rawData: raw,
  };
}

function normalizeSnortAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Snort IDS",
    sourceEventId: raw.sid?.toString() || raw.alert_id || `snort_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    title: raw.msg || raw.signature || "Snort IDS Alert",
    description: raw.msg || raw.payload || "",
    severity: mapSnortSeverity(raw.priority || raw.severity),
    category: mapSnortCategory(raw.classtype || raw.classification),
    sourceIp: raw.src_addr || raw.srcIP,
    destIp: raw.dst_addr || raw.dstIP,
    sourcePort: raw.src_port || raw.srcPort ? parseInt(raw.src_port || raw.srcPort) : undefined,
    destPort: raw.dst_port || raw.dstPort ? parseInt(raw.dst_port || raw.dstPort) : undefined,
    protocol: raw.proto || raw.protocol,
    detectedAt: raw.timestamp ? new Date(raw.timestamp) : new Date(),
    rawData: raw,
  };
}

function normalizeZscalerAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Zscaler ZIA",
    sourceEventId: raw.id?.toString() || raw.ruleId?.toString() || `zscaler_${Date.now()}`,
    title: raw.name || raw.ruleName || "Zscaler ZIA Event",
    description: raw.description || raw.name || "",
    severity: mapZscalerSeverity(raw.severity || raw.rank),
    category: mapZscalerCategory(raw.type || raw.protocols),
    sourceIp: raw.srcIp || raw.clientIP,
    destIp: raw.dstIp || raw.serverIP,
    hostname: raw.hostname || raw.deviceName,
    userId: raw.user || raw.login,
    url: raw.url,
    domain: raw.hostname,
    detectedAt: raw.time ? new Date(raw.time) : new Date(),
    rawData: raw,
  };
}

function normalizeCheckPointAlert(raw: any): Partial<InsertAlert> {
  return {
    source: "Check Point",
    sourceEventId: raw.loguid || raw.id || `checkpoint_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    title: raw.attack || raw.product || "Check Point Alert",
    description: raw.attack || raw.protection_name || "",
    severity: mapCheckPointSeverity(raw.severity || raw.confidence_level),
    category: mapCheckPointCategory(raw.blade || raw.product),
    sourceIp: raw.src || raw.origin,
    destIp: raw.dst || raw.destination,
    sourcePort: raw.s_port ? parseInt(raw.s_port) : undefined,
    destPort: raw.service ? parseInt(raw.service) : undefined,
    protocol: raw.proto || raw.ip_proto,
    hostname: raw.origin_sic_name || raw.hostname,
    detectedAt: raw.time ? new Date(raw.time) : new Date(),
    rawData: raw,
  };
}

function mapCrowdStrikeSeverity(sev: number | string): string {
  const n = typeof sev === "number" ? sev : parseInt(sev) || 0;
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "informational";
}

function mapCrowdStrikeCategory(tactic?: string): string {
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

function mapSplunkSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "critical" || s === "1") return "critical";
  if (s === "high" || s === "2") return "high";
  if (s === "medium" || s === "3" || s === "warning") return "medium";
  if (s === "low" || s === "4") return "low";
  return "informational";
}

function mapWizCategory(type?: string): string {
  if (!type) return "cloud_misconfiguration";
  const t = type.toLowerCase();
  if (t.includes("network")) return "intrusion";
  if (t.includes("iam") || t.includes("identity")) return "privilege_escalation";
  if (t.includes("data")) return "data_exfiltration";
  if (t.includes("malware") || t.includes("runtime")) return "malware";
  return "cloud_misconfiguration";
}

function mapWazuhSeverity(level?: number): string {
  if (!level) return "medium";
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 4) return "low";
  return "informational";
}

function mapWazuhCategory(groups?: string[]): string {
  if (!groups || groups.length === 0) return "other";
  const g = groups.join(",").toLowerCase();
  if (g.includes("authentication") || g.includes("ssh")) return "credential_access";
  if (g.includes("syscheck") || g.includes("integrity")) return "persistence";
  if (g.includes("web") || g.includes("attack")) return "intrusion";
  if (g.includes("malware") || g.includes("rootcheck")) return "malware";
  if (g.includes("policy")) return "policy_violation";
  return "other";
}

function mapPaloAltoSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "critical" || s === "high") return s;
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

function mapGuardDutySeverity(sev?: number): string {
  if (!sev) return "medium";
  if (sev >= 7) return "critical";
  if (sev >= 5) return "high";
  if (sev >= 3) return "medium";
  if (sev >= 1) return "low";
  return "informational";
}

function mapGuardDutyCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("trojan") || t.includes("malware")) return "malware";
  if (t.includes("unauthorized")) return "intrusion";
  if (t.includes("recon")) return "reconnaissance";
  if (t.includes("exfiltration")) return "data_exfiltration";
  if (t.includes("cryptomining") || t.includes("bitcoin")) return "policy_violation";
  if (t.includes("persistence")) return "persistence";
  return "other";
}

function mapDefenderCategory(cat?: string): string {
  if (!cat) return "other";
  const c = cat.toLowerCase();
  if (c.includes("malware")) return "malware";
  if (c.includes("phish")) return "phishing";
  if (c.includes("ransomware")) return "malware";
  if (c.includes("lateral")) return "lateral_movement";
  if (c.includes("credential")) return "credential_access";
  if (c.includes("command") || c.includes("c2")) return "command_and_control";
  return "other";
}

function mapS1Severity(level?: string): string {
  if (!level) return "medium";
  const l = level.toLowerCase();
  if (l === "malicious" || l === "suspicious") return "high";
  if (l === "true_positive") return "critical";
  return "medium";
}

function mapS1Category(classification?: string): string {
  if (!classification) return "other";
  const c = classification.toLowerCase();
  if (c.includes("ransomware")) return "malware";
  if (c.includes("trojan")) return "malware";
  if (c.includes("exploit")) return "intrusion";
  if (c.includes("pup")) return "policy_violation";
  return "malware";
}

function mapElasticSeverity(sev?: string | number): string {
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

function mapElasticCategory(typeOrTags?: string | string[]): string {
  if (!typeOrTags) return "other";
  const t = (Array.isArray(typeOrTags) ? typeOrTags.join(",") : typeOrTags).toLowerCase();
  if (t.includes("malware")) return "malware";
  if (t.includes("intrusion") || t.includes("exploit")) return "intrusion";
  if (t.includes("credential")) return "credential_access";
  if (t.includes("lateral")) return "lateral_movement";
  if (t.includes("persistence")) return "persistence";
  return "other";
}

function mapQRadarSeverity(magnitude?: number): string {
  if (!magnitude) return "medium";
  if (magnitude >= 8) return "critical";
  if (magnitude >= 6) return "high";
  if (magnitude >= 4) return "medium";
  if (magnitude >= 2) return "low";
  return "informational";
}

function mapFortiGateSeverity(level?: string): string {
  if (!level) return "medium";
  const l = level.toLowerCase();
  if (l === "emergency" || l === "alert" || l === "critical") return "critical";
  if (l === "error") return "high";
  if (l === "warning") return "medium";
  if (l === "notice" || l === "information") return "low";
  return "informational";
}

function mapFortiGateCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("virus") || t.includes("malware")) return "malware";
  if (t.includes("intrusion") || t.includes("ips")) return "intrusion";
  if (t.includes("web") || t.includes("url")) return "policy_violation";
  if (t.includes("traffic")) return "other";
  return "other";
}

function mapCarbonBlackSeverity(sev?: number): string {
  if (!sev) return "medium";
  if (sev >= 8) return "critical";
  if (sev >= 6) return "high";
  if (sev >= 4) return "medium";
  if (sev >= 2) return "low";
  return "informational";
}

function mapCarbonBlackCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("malware") || t.includes("virus")) return "malware";
  if (t.includes("watchlist")) return "reconnaissance";
  if (t.includes("device") || t.includes("policy")) return "policy_violation";
  return "other";
}

function mapQualysSeverity(sev?: number | string): string {
  const n = typeof sev === "string" ? parseInt(sev) || 0 : (sev || 0);
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "informational";
}

function mapTenableSeverity(sev?: number | string): string {
  if (!sev) return "medium";
  if (typeof sev === "number") {
    if (sev >= 4) return "critical";
    if (sev >= 3) return "high";
    if (sev >= 2) return "medium";
    if (sev >= 1) return "low";
    return "informational";
  }
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

function mapUmbrellaSeverity(verdict?: string): string {
  if (!verdict) return "medium";
  const v = verdict.toLowerCase();
  if (v === "blocked" || v === "malicious") return "high";
  if (v === "suspicious" || v === "proxied") return "medium";
  return "low";
}

function mapUmbrellaCategory(categories?: string[]): string {
  if (!categories || categories.length === 0) return "other";
  const c = categories.join(",").toLowerCase();
  if (c.includes("malware")) return "malware";
  if (c.includes("phish")) return "phishing";
  if (c.includes("botnet") || c.includes("c2") || c.includes("command")) return "command_and_control";
  if (c.includes("crypto")) return "policy_violation";
  return "other";
}

function mapDarktraceSeverity(score?: number): string {
  if (!score) return "medium";
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.4) return "medium";
  if (score >= 0.2) return "low";
  return "informational";
}

function mapDarktraceCategory(modelName?: string): string {
  if (!modelName) return "other";
  const m = modelName.toLowerCase();
  if (m.includes("compromise") || m.includes("malware")) return "malware";
  if (m.includes("anomalous") || m.includes("unusual")) return "reconnaissance";
  if (m.includes("credential") || m.includes("brute")) return "credential_access";
  if (m.includes("exfiltration") || m.includes("data")) return "data_exfiltration";
  if (m.includes("c2") || m.includes("command")) return "command_and_control";
  return "other";
}

function mapRapid7Severity(priority?: string): string {
  if (!priority) return "medium";
  const p = priority.toLowerCase();
  if (p === "critical") return "critical";
  if (p === "high") return "high";
  if (p === "medium") return "medium";
  if (p === "low") return "low";
  return "informational";
}

function mapRapid7Category(source?: string): string {
  if (!source) return "other";
  const s = source.toLowerCase();
  if (s.includes("malware")) return "malware";
  if (s.includes("phish")) return "phishing";
  if (s.includes("lateral")) return "lateral_movement";
  if (s.includes("credential") || s.includes("auth")) return "credential_access";
  return "other";
}

function mapTrendMicroSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

function mapTrendMicroCategory(alertType?: string): string {
  if (!alertType) return "other";
  const t = alertType.toLowerCase();
  if (t.includes("malware") || t.includes("ransomware")) return "malware";
  if (t.includes("phish") || t.includes("email")) return "phishing";
  if (t.includes("lateral")) return "lateral_movement";
  if (t.includes("c2") || t.includes("callback")) return "command_and_control";
  return "other";
}

function mapOktaSeverity(sev?: string): string {
  if (!sev) return "medium";
  const s = sev.toLowerCase();
  if (s === "error" || s === "failure") return "high";
  if (s === "warn" || s === "warning") return "medium";
  if (s === "info") return "low";
  return "informational";
}

function mapOktaCategory(eventType?: string): string {
  if (!eventType) return "other";
  const e = eventType.toLowerCase();
  if (e.includes("user.session") || e.includes("login")) return "credential_access";
  if (e.includes("policy")) return "policy_violation";
  if (e.includes("privilege") || e.includes("admin")) return "privilege_escalation";
  if (e.includes("mfa") || e.includes("factor")) return "credential_access";
  return "other";
}

function mapProofpointSeverity(score?: number): string {
  if (!score) return "medium";
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score >= 10) return "low";
  return "informational";
}

function mapProofpointCategory(threatType?: string): string {
  if (!threatType) return "other";
  const t = threatType.toLowerCase();
  if (t.includes("malware") || t.includes("attachment")) return "malware";
  if (t.includes("phish") || t.includes("url")) return "phishing";
  if (t.includes("spam")) return "policy_violation";
  if (t.includes("impostor") || t.includes("bec")) return "phishing";
  return "other";
}

function mapSnortSeverity(priority?: number | string): string {
  const n = typeof priority === "string" ? parseInt(priority) || 3 : (priority || 3);
  if (n <= 1) return "critical";
  if (n <= 2) return "high";
  if (n <= 3) return "medium";
  return "low";
}

function mapSnortCategory(classtype?: string): string {
  if (!classtype) return "other";
  const c = classtype.toLowerCase();
  if (c.includes("trojan") || c.includes("malware")) return "malware";
  if (c.includes("exploit") || c.includes("shellcode")) return "intrusion";
  if (c.includes("scan") || c.includes("recon")) return "reconnaissance";
  if (c.includes("policy") || c.includes("inappropriate")) return "policy_violation";
  if (c.includes("web-application")) return "intrusion";
  return "other";
}

function mapZscalerSeverity(sev?: string | number): string {
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

function mapZscalerCategory(type?: string): string {
  if (!type) return "other";
  const t = type.toLowerCase();
  if (t.includes("malware")) return "malware";
  if (t.includes("phish")) return "phishing";
  if (t.includes("botnet") || t.includes("c2")) return "command_and_control";
  if (t.includes("policy") || t.includes("dlp")) return "policy_violation";
  return "other";
}

function mapCheckPointSeverity(sev?: string | number): string {
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

function mapCheckPointCategory(blade?: string): string {
  if (!blade) return "other";
  const b = blade.toLowerCase();
  if (b.includes("ips") || b.includes("intrusion")) return "intrusion";
  if (b.includes("anti-bot") || b.includes("antibot")) return "command_and_control";
  if (b.includes("threat") || b.includes("emulation")) return "malware";
  if (b.includes("antivirus") || b.includes("anti-virus")) return "malware";
  if (b.includes("url") || b.includes("application")) return "policy_violation";
  return "other";
}

const NORMALIZERS: Record<string, (raw: any) => Partial<InsertAlert>> = {
  crowdstrike: normalizeCrowdStrikeAlert,
  splunk: normalizeSplunkAlert,
  wiz: normalizeWizAlert,
  wazuh: normalizeWazuhAlert,
  paloalto: normalizePaloAltoAlert,
  guardduty: normalizeGuardDutyAlert,
  defender: normalizeDefenderAlert,
  sentinelone: normalizeSentinelOneAlert,
  elastic: normalizeElasticAlert,
  qradar: normalizeQRadarAlert,
  fortigate: normalizeFortiGateAlert,
  carbonblack: normalizeCarbonBlackAlert,
  qualys: normalizeQualysAlert,
  tenable: normalizeTenableAlert,
  umbrella: normalizeUmbrellaAlert,
  darktrace: normalizeDarktraceAlert,
  rapid7: normalizeRapid7Alert,
  trendmicro: normalizeTrendMicroAlert,
  okta: normalizeOktaAlert,
  proofpoint: normalizeProofpointAlert,
  snort: normalizeSnortAlert,
  zscaler: normalizeZscalerAlert,
  checkpoint: normalizeCheckPointAlert,
};

const FETCHERS: Record<string, (config: ConnectorConfig, since?: Date) => Promise<any[]>> = {
  crowdstrike: fetchCrowdStrike,
  splunk: fetchSplunk,
  wiz: fetchWiz,
  wazuh: fetchWazuh,
  paloalto: fetchPaloAlto,
  guardduty: fetchGuardDuty,
  defender: fetchDefender,
  sentinelone: fetchSentinelOne,
  elastic: fetchElastic,
  qradar: fetchQRadar,
  fortigate: fetchFortiGate,
  carbonblack: fetchCarbonBlack,
  qualys: fetchQualys,
  tenable: fetchTenable,
  umbrella: fetchUmbrella,
  darktrace: fetchDarktrace,
  rapid7: fetchRapid7,
  trendmicro: fetchTrendMicro,
  okta: fetchOkta,
  proofpoint: fetchProofpoint,
  snort: fetchSnort,
  zscaler: fetchZscaler,
  checkpoint: fetchCheckPoint,
};

export async function testConnector(type: string, config: ConnectorConfig): Promise<ConnectorTestResult> {
  const start = Date.now();
  try {
    const fetcher = FETCHERS[type];
    if (!fetcher) {
      return { success: false, message: `Unknown connector type: ${type}`, latencyMs: Date.now() - start };
    }
    switch (type) {
      case "crowdstrike":
        await crowdstrikeGetToken(config);
        break;
      case "wiz":
        await wizGetToken(config);
        break;
      case "defender":
        await defenderGetToken(config);
        break;
      case "splunk": {
        const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
        const res = await httpRequest(`${config.baseUrl}/services/server/info?output_mode=json`, {
          headers: { Authorization: `Basic ${auth}` },
        });
        if (res.status >= 400) throw new Error(`Splunk returned ${res.status}`);
        break;
      }
      case "wazuh": {
        const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
        const res = await httpRequest(`${config.baseUrl}`, {
          headers: { Authorization: `Basic ${auth}` },
        });
        if (res.status >= 400) throw new Error(`Wazuh returned ${res.status}`);
        break;
      }
      case "paloalto": {
        const headers: Record<string, string> = {
          "x-xdr-auth-id": config.clientId || "1",
          Authorization: config.apiKey!,
        };
        const res = await httpRequest(`${config.baseUrl}/public_api/v1/healthcheck`, { headers });
        if (res.status >= 400) throw new Error(`Palo Alto returned ${res.status}`);
        break;
      }
      case "guardduty": {
        const { GuardDutyClient, ListDetectorsCommand } = await import("@aws-sdk/client-guardduty");
        const gdAccessKeyId = config.accessKeyId || appConfig.aws.accessKeyId;
        const gdSecretAccessKey = config.secretAccessKey || appConfig.aws.secretAccessKey;
        const client = new GuardDutyClient({
          region: config.region || "us-east-1",
          ...(gdAccessKeyId && gdSecretAccessKey
            ? { credentials: { accessKeyId: gdAccessKeyId, secretAccessKey: gdSecretAccessKey } }
            : {}),
        });
        const res = await client.send(new ListDetectorsCommand({}));
        if (!res.DetectorIds?.length) throw new Error("No GuardDuty detectors found");
        break;
      }
      case "sentinelone": {
        const res = await httpRequest(`${config.baseUrl}/web/api/v2.1/system/status`, {
          headers: { Authorization: `ApiToken ${config.apiKey}` },
        });
        if (res.status >= 400) throw new Error(`SentinelOne returned ${res.status}`);
        break;
      }
      case "elastic": {
        const headers: Record<string, string> = {};
        if (config.apiKey) {
          headers["Authorization"] = `ApiKey ${config.apiKey}`;
        } else if (config.username && config.password) {
          headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
        }
        const res = await httpRequest(`${config.baseUrl}/_cluster/health`, { headers });
        if (res.status >= 400) throw new Error(`Elastic returned ${res.status}`);
        break;
      }
      case "qradar": {
        const res = await httpRequest(`${config.baseUrl}/api/help/versions`, {
          headers: { "SEC": config.apiKey!, "Accept": "application/json" },
        });
        if (res.status >= 400) throw new Error(`QRadar returned ${res.status}`);
        break;
      }
      case "fortigate": {
        const res = await httpRequest(`${config.baseUrl}/api/v2/cmdb/system/status?access_token=${encodeURIComponent(config.apiKey!)}`, {});
        if (res.status >= 400) throw new Error(`FortiGate returned ${res.status}`);
        break;
      }
      case "carbonblack": {
        const orgKey = config.orgKey || config.clientId || "default";
        const res = await httpRequest(`${config.baseUrl}/api/alerts/v7/orgs/${orgKey}/alerts/_search`, {
          method: "POST",
          headers: { "X-Auth-Token": config.apiKey!, "Content-Type": "application/json" },
          body: { criteria: {}, rows: 1 },
        });
        if (res.status >= 400) throw new Error(`Carbon Black returned ${res.status}`);
        break;
      }
      case "qualys": {
        const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
        const res = await httpRequest(`${config.baseUrl}/api/2.0/fo/activity_log/?action=list&output_format=JSON`, {
          headers: { "Authorization": `Basic ${auth}`, "X-Requested-With": "fetch" },
        });
        if (res.status >= 400) throw new Error(`Qualys returned ${res.status}`);
        break;
      }
      case "tenable": {
        const secretKey = config.token || "";
        const res = await httpRequest(`${config.baseUrl}/server/status`, {
          headers: { "X-ApiKeys": `accessKey=${config.apiKey};secretKey=${secretKey}` },
        });
        if (res.status >= 400) throw new Error(`Tenable returned ${res.status}`);
        break;
      }
      case "umbrella": {
        const res = await httpRequest(`${config.baseUrl}/v2/events?limit=1`, {
          headers: { "Authorization": `Bearer ${config.apiKey}` },
        });
        if (res.status >= 400) throw new Error(`Umbrella returned ${res.status}`);
        break;
      }
      case "darktrace": {
        const headers: Record<string, string> = {};
        if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
        const res = await httpRequest(`${config.baseUrl}/status`, { headers });
        if (res.status >= 400) throw new Error(`Darktrace returned ${res.status}`);
        break;
      }
      case "rapid7": {
        const res = await httpRequest(`${config.baseUrl}/idr/v2/investigations?size=1`, {
          headers: { "X-Api-Key": config.apiKey! },
        });
        if (res.status >= 400) throw new Error(`Rapid7 returned ${res.status}`);
        break;
      }
      case "trendmicro": {
        const res = await httpRequest(`${config.baseUrl}/v3.0/healthcheck/connectivity`, {
          headers: { "Authorization": `Bearer ${config.token}` },
        });
        if (res.status >= 400) throw new Error(`Trend Micro returned ${res.status}`);
        break;
      }
      case "okta": {
        const res = await httpRequest(`${config.baseUrl}/api/v1/org`, {
          headers: { "Authorization": `SSWS ${config.apiKey}` },
        });
        if (res.status >= 400) throw new Error(`Okta returned ${res.status}`);
        break;
      }
      case "proofpoint": {
        const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
        const res = await httpRequest(`${config.baseUrl}/v2/siem/messages/delivered?sinceSeconds=60&format=JSON`, {
          headers: { "Authorization": `Basic ${auth}` },
        });
        if (res.status >= 400) throw new Error(`Proofpoint returned ${res.status}`);
        break;
      }
      case "snort": {
        const headers: Record<string, string> = {};
        if (config.apiKey) {
          headers["Authorization"] = `Bearer ${config.apiKey}`;
        } else if (config.username && config.password) {
          headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
        }
        const res = await httpRequest(`${config.baseUrl}/api/alerts?limit=1`, { headers });
        if (res.status >= 400) throw new Error(`Snort returned ${res.status}`);
        break;
      }
      case "zscaler": {
        const authRes = await httpRequest(`${config.baseUrl}/api/v1/authenticatedSession`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: { apiKey: config.apiKey, username: config.username, password: config.password },
        });
        if (authRes.status >= 400) throw new Error(`Zscaler auth returned ${authRes.status}`);
        break;
      }
      case "checkpoint": {
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (config.apiKey) {
          headers["X-chkp-sid"] = config.apiKey;
        } else if (config.username && config.password) {
          const loginRes = await httpRequest(`${config.baseUrl}/web_api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: { user: config.username, password: config.password },
          });
          if (loginRes.status >= 400) throw new Error(`Check Point login returned ${loginRes.status}`);
          break;
        }
        const res = await httpRequest(`${config.baseUrl}/web_api/show-session`, {
          method: "POST",
          headers,
          body: {},
        });
        if (res.status >= 400) throw new Error(`Check Point returned ${res.status}`);
        break;
      }
      default:
        throw new Error(`No test implementation for connector type: ${type}`);
    }
    return {
      success: true,
      message: `Successfully connected to ${type}`,
      latencyMs: Date.now() - start,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err.message || "Connection failed",
      latencyMs: Date.now() - start,
    };
  }
}

export async function syncConnector(connector: Connector): Promise<SyncResult> {
  const config = connector.config as ConnectorConfig;
  const type = connector.type;
  const fetcher = FETCHERS[type];
  const normalizer = NORMALIZERS[type];
  if (!fetcher || !normalizer) {
    return { alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0, errors: [`Unknown connector type: ${type}`], rawAlerts: [] };
  }
  const since = connector.lastSyncAt || undefined;
  let rawAlerts: any[];
  try {
    rawAlerts = await fetcher(config, since || undefined);
  } catch (err: any) {
    return { alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0, errors: [err.message], rawAlerts: [] };
  }

  const result: SyncResult = { alertsReceived: rawAlerts.length, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0, errors: [], rawAlerts: [] };

  for (const raw of rawAlerts) {
    try {
      const normalized = normalizer(raw);
      normalized.orgId = connector.orgId;
      result.rawAlerts.push(normalized);
    } catch (err: any) {
      result.alertsFailed++;
      result.errors.push(`Normalization failed: ${err.message}`);
    }
  }

  return result;
}

export async function syncConnectorWithRetry(
  connector: Connector,
  maxAttempts: number = 3
): Promise<ConnectorJobRun> {
  const startTime = Date.now();
  
  // Create initial job run record
  const jobRun = await storage.createConnectorJobRun({
    connectorId: connector.id,
    orgId: connector.orgId,
    status: "running",
    attempt: 1,
    maxAttempts,
    alertsReceived: 0,
    alertsCreated: 0,
    alertsDeduped: 0,
    alertsFailed: 0,
  });

  let currentAttempt = 1;
  let lastError: Error | null = null;

  while (currentAttempt <= maxAttempts) {
    try {
      // Call the existing syncConnector function
      const syncResult = await syncConnector(connector);
      
      // Calculate latency
      const latencyMs = Date.now() - startTime;
      
      // Update job run with success
      const updatedJobRun = await storage.updateConnectorJobRun(jobRun.id, {
        status: "success",
        attempt: currentAttempt,
        alertsReceived: syncResult.alertsReceived,
        alertsCreated: syncResult.alertsCreated,
        alertsDeduped: syncResult.alertsDeduped,
        alertsFailed: syncResult.alertsFailed,
        latencyMs,
        completedAt: new Date(),
      });

      return updatedJobRun;
    } catch (err: any) {
      lastError = err;
      const errorMessage = err.message || String(err);
      const errorLower = errorMessage.toLowerCase();
      
      // Detect error type
      let errorType = "api_error";
      let throttled = false;
      let httpStatus: number | undefined;

      if (errorLower.includes("429") || errorLower.includes("503") || 
          errorLower.includes("rate limit") || errorLower.includes("throttl")) {
        errorType = "throttle";
        throttled = true;
        // Extract HTTP status if available
        if (errorLower.includes("429")) httpStatus = 429;
        if (errorLower.includes("503")) httpStatus = 503;
      } else if (errorLower.includes("401") || errorLower.includes("403") || 
                 errorLower.includes("unauthorized") || errorLower.includes("forbidden")) {
        errorType = "auth_error";
        if (errorLower.includes("401")) httpStatus = 401;
        if (errorLower.includes("403")) httpStatus = 403;
      }

      // If max attempts exceeded, mark as dead letter
      if (currentAttempt >= maxAttempts) {
        const latencyMs = Date.now() - startTime;
        const updatedJobRun = await storage.updateConnectorJobRun(jobRun.id, {
          status: "failed",
          attempt: currentAttempt,
          latencyMs,
          errorMessage,
          errorType,
          httpStatus,
          throttled,
          isDeadLetter: true,
          completedAt: new Date(),
        });
        return updatedJobRun;
      }

      // If error and attempt < maxAttempts, calculate backoff and log next attempt
      const backoffSeconds = Math.pow(2, currentAttempt);
      console.log(
        `[Connector ${connector.id}] Sync failed on attempt ${currentAttempt}/${maxAttempts}. ` +
        `Error type: ${errorType}. Next retry in ${backoffSeconds} seconds. Error: ${errorMessage}`
      );

      // Update job run with error details but keep it in running state for retry
      await storage.updateConnectorJobRun(jobRun.id, {
        attempt: currentAttempt + 1,
        errorMessage,
        errorType,
        httpStatus,
        throttled,
      });

      // Increment attempt counter
      currentAttempt++;
    }
  }

  // If we exit the loop without success, return dead letter
  const latencyMs = Date.now() - startTime;
  return await storage.updateConnectorJobRun(jobRun.id, {
    status: "failed",
    attempt: currentAttempt - 1,
    latencyMs,
    errorMessage: lastError?.message || "Unknown error",
    errorType: "api_error",
    isDeadLetter: true,
    completedAt: new Date(),
  });
}

export function getConnectorMetadata(type: string): {
  name: string;
  description: string;
  authType: string;
  requiredFields: { key: string; label: string; type: string; placeholder: string }[];
  optionalFields: { key: string; label: string; type: string; placeholder: string }[];
  icon: string;
  docsUrl: string;
} | null {
  const metadata: Record<string, any> = {
    crowdstrike: {
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
    splunk: {
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
    wiz: {
      name: "Wiz",
      description: "Cloud Security - Pulls issues via Wiz GraphQL API with severity filtering",
      authType: "oauth2",
      requiredFields: [
        { key: "clientId", label: "Service Account Client ID", type: "text", placeholder: "53-character client ID" },
        { key: "clientSecret", label: "Service Account Secret", type: "password", placeholder: "64-character client secret" },
      ],
      optionalFields: [
        { key: "datacenter", label: "Data Center", type: "text", placeholder: "us1, us2, eu1, eu2" },
      ],
      icon: "Cloud",
      docsUrl: "https://docs.wiz.io",
    },
    wazuh: {
      name: "Wazuh",
      description: "SIEM / Host IDS - Pulls alerts from Wazuh Indexer (OpenSearch) API",
      authType: "basic",
      requiredFields: [
        { key: "baseUrl", label: "Wazuh Indexer URL", type: "url", placeholder: "https://your-wazuh:9200" },
        { key: "username", label: "Username", type: "text", placeholder: "admin" },
        { key: "password", label: "Password", type: "password", placeholder: "Wazuh indexer password" },
      ],
      optionalFields: [
        { key: "indexPattern", label: "Index Pattern", type: "text", placeholder: "wazuh-alerts*" },
      ],
      icon: "Eye",
      docsUrl: "https://documentation.wazuh.com/current/user-manual/indexer-api/",
    },
    paloalto: {
      name: "Palo Alto Cortex XDR",
      description: "Firewall / XDR - Pulls incidents from Cortex XDR API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "API URL", type: "url", placeholder: "https://api-your-instance.xdr.us.paloaltonetworks.com" },
        { key: "apiKey", label: "API Key", type: "password", placeholder: "Your Cortex XDR API key" },
      ],
      optionalFields: [
        { key: "clientId", label: "API Key ID", type: "text", placeholder: "1" },
      ],
      icon: "Flame",
      docsUrl: "https://docs-cortex.paloaltonetworks.com/",
    },
    guardduty: {
      name: "AWS GuardDuty",
      description: "Cloud Threat Detection - Pulls findings via AWS SDK with severity filtering",
      authType: "aws_credentials",
      requiredFields: [
        { key: "region", label: "AWS Region", type: "text", placeholder: "us-east-1" },
      ],
      optionalFields: [
        { key: "accessKeyId", label: "AWS Access Key ID (uses default if empty)", type: "text", placeholder: "AKIA..." },
        { key: "secretAccessKey", label: "AWS Secret Access Key", type: "password", placeholder: "Override default AWS credentials" },
      ],
      icon: "CloudLightning",
      docsUrl: "https://docs.aws.amazon.com/guardduty/latest/APIReference/",
    },
    defender: {
      name: "Microsoft Defender",
      description: "Endpoint / Cloud Security - Pulls alerts from Microsoft Graph Security API",
      authType: "oauth2",
      requiredFields: [
        { key: "tenantId", label: "Azure Tenant ID", type: "text", placeholder: "Your Azure AD Tenant ID" },
        { key: "clientId", label: "App Client ID", type: "text", placeholder: "Azure AD App Registration Client ID" },
        { key: "clientSecret", label: "App Client Secret", type: "password", placeholder: "Azure AD App Registration Secret" },
      ],
      optionalFields: [],
      icon: "ShieldCheck",
      docsUrl: "https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview",
    },
    sentinelone: {
      name: "SentinelOne",
      description: "EDR - Pulls threats from SentinelOne Management API",
      authType: "token",
      requiredFields: [
        { key: "baseUrl", label: "Management Console URL", type: "url", placeholder: "https://your-instance.sentinelone.net" },
        { key: "apiKey", label: "API Token", type: "password", placeholder: "SentinelOne API token" },
      ],
      optionalFields: [],
      icon: "Radar",
      docsUrl: "https://your-instance.sentinelone.net/api-doc/overview",
    },
    elastic: {
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
    qradar: {
      name: "IBM QRadar",
      description: "SIEM - Pulls offenses from QRadar SIEM API filtered by magnitude",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "QRadar Console URL", type: "url", placeholder: "https://your-qradar:443" },
        { key: "apiKey", label: "SEC Token", type: "password", placeholder: "Your QRadar authorized service token" },
      ],
      optionalFields: [],
      icon: "Database",
      docsUrl: "https://www.ibm.com/docs/en/qradar-common",
    },
    fortigate: {
      name: "Fortinet FortiGate",
      description: "Firewall - Pulls event logs from FortiGate REST API filtered by severity",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "FortiGate URL", type: "url", placeholder: "https://your-fortigate:443" },
        { key: "apiKey", label: "API Key (Access Token)", type: "password", placeholder: "Your FortiGate REST API token" },
      ],
      optionalFields: [],
      icon: "Flame",
      docsUrl: "https://docs.fortinet.com/document/fortigate/latest/administration-guide/",
    },
    carbonblack: {
      name: "Carbon Black (VMware)",
      description: "EDR - Pulls alerts from Carbon Black Cloud API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "CBC API URL", type: "url", placeholder: "https://defense.conferdeploy.net" },
        { key: "apiKey", label: "API Key (apiKey/apiId)", type: "password", placeholder: "API_SECRET_KEY/API_ID" },
      ],
      optionalFields: [
        { key: "clientId", label: "Org Key", type: "text", placeholder: "Your Carbon Black Org Key" },
      ],
      icon: "Shield",
      docsUrl: "https://developer.carbonblack.com/reference/carbon-black-cloud/",
    },
    qualys: {
      name: "Qualys VMDR",
      description: "Vulnerability Management - Pulls host VM detections from Qualys API",
      authType: "basic",
      requiredFields: [
        { key: "baseUrl", label: "Qualys API URL", type: "url", placeholder: "https://qualysapi.qualys.com" },
        { key: "username", label: "Username", type: "text", placeholder: "Qualys username" },
        { key: "password", label: "Password", type: "password", placeholder: "Qualys password" },
      ],
      optionalFields: [],
      icon: "Search",
      docsUrl: "https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf",
    },
    tenable: {
      name: "Tenable Nessus",
      description: "Vulnerability Scanner - Pulls vulnerability findings from Tenable.io/Nessus API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "Tenable API URL", type: "url", placeholder: "https://cloud.tenable.com" },
        { key: "apiKey", label: "Access Key", type: "password", placeholder: "Your Tenable access key" },
      ],
      optionalFields: [
        { key: "token", label: "Secret Key", type: "password", placeholder: "Your Tenable secret key" },
      ],
      icon: "Search",
      docsUrl: "https://developer.tenable.com/reference/navigate",
    },
    umbrella: {
      name: "Cisco Umbrella",
      description: "DNS Security - Pulls security events from Cisco Umbrella Reporting API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "Umbrella API URL", type: "url", placeholder: "https://api.umbrella.com" },
        { key: "apiKey", label: "API Token", type: "password", placeholder: "Your Umbrella API token" },
      ],
      optionalFields: [],
      icon: "Cloud",
      docsUrl: "https://developer.cisco.com/docs/cloud-security/",
    },
    darktrace: {
      name: "Darktrace",
      description: "NDR / AI Security - Pulls model breaches from Darktrace Threat Visualizer API",
      authType: "token",
      requiredFields: [
        { key: "baseUrl", label: "Darktrace Appliance URL", type: "url", placeholder: "https://your-darktrace:443" },
        { key: "token", label: "Private Token", type: "password", placeholder: "Your Darktrace private API token" },
      ],
      optionalFields: [
        { key: "apiKey", label: "Public Token", type: "text", placeholder: "Your Darktrace public API token" },
      ],
      icon: "Eye",
      docsUrl: "https://customerportal.darktrace.com/",
    },
    rapid7: {
      name: "Rapid7 InsightIDR",
      description: "SIEM / XDR - Pulls investigations from InsightIDR API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "InsightIDR API URL", type: "url", placeholder: "https://us.api.insight.rapid7.com" },
        { key: "apiKey", label: "API Key", type: "password", placeholder: "Your Rapid7 API key" },
      ],
      optionalFields: [],
      icon: "Radar",
      docsUrl: "https://docs.rapid7.com/insightidr/api/",
    },
    trendmicro: {
      name: "Trend Micro Vision One",
      description: "XDR - Pulls workbench alerts from Trend Micro Vision One API",
      authType: "token",
      requiredFields: [
        { key: "baseUrl", label: "Vision One API URL", type: "url", placeholder: "https://api.xdr.trendmicro.com" },
        { key: "token", label: "API Token", type: "password", placeholder: "Your Trend Micro API token" },
      ],
      optionalFields: [],
      icon: "ShieldCheck",
      docsUrl: "https://automation.trendmicro.com/xdr/home",
    },
    okta: {
      name: "Okta Identity",
      description: "Identity / IAM - Pulls system log events from Okta API filtered by severity",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "Okta Domain URL", type: "url", placeholder: "https://your-org.okta.com" },
        { key: "apiKey", label: "API Token (SSWS)", type: "password", placeholder: "Your Okta API token" },
      ],
      optionalFields: [],
      icon: "User",
      docsUrl: "https://developer.okta.com/docs/reference/api/system-log/",
    },
    proofpoint: {
      name: "Proofpoint Email Security",
      description: "Email Security - Pulls delivered messages from Proofpoint SIEM API",
      authType: "basic",
      requiredFields: [
        { key: "baseUrl", label: "Proofpoint API URL", type: "url", placeholder: "https://tap-api-v2.proofpoint.com" },
        { key: "username", label: "Service Principal", type: "text", placeholder: "Service principal ID" },
        { key: "password", label: "Secret", type: "password", placeholder: "Service principal secret" },
      ],
      optionalFields: [],
      icon: "Mail",
      docsUrl: "https://proofpoint.com/us/products/advanced-threat-protection",
    },
    snort: {
      name: "Snort IDS",
      description: "Network IDS - Pulls alerts from Snort management API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "Snort API URL", type: "url", placeholder: "https://your-snort-manager:8080" },
      ],
      optionalFields: [
        { key: "apiKey", label: "API Key", type: "password", placeholder: "Your Snort API key" },
        { key: "username", label: "Username", type: "text", placeholder: "Snort username" },
        { key: "password", label: "Password", type: "password", placeholder: "Snort password" },
      ],
      icon: "AlertTriangle",
      docsUrl: "https://www.snort.org/documents",
    },
    zscaler: {
      name: "Zscaler ZIA",
      description: "Cloud Firewall / Proxy - Pulls web application rules from Zscaler ZIA API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "ZIA API URL", type: "url", placeholder: "https://zsapi.zscaler.net" },
        { key: "apiKey", label: "API Key", type: "password", placeholder: "Your Zscaler API key" },
        { key: "username", label: "Admin Username", type: "text", placeholder: "admin@your-org.com" },
        { key: "password", label: "Admin Password", type: "password", placeholder: "Zscaler admin password" },
      ],
      optionalFields: [],
      icon: "Globe",
      docsUrl: "https://help.zscaler.com/zia/api",
    },
    checkpoint: {
      name: "Check Point",
      description: "Firewall / IPS - Pulls security logs from Check Point Management API",
      authType: "api_key",
      requiredFields: [
        { key: "baseUrl", label: "Management Server URL", type: "url", placeholder: "https://your-checkpoint:443" },
      ],
      optionalFields: [
        { key: "apiKey", label: "Session ID / API Key", type: "password", placeholder: "Your Check Point session ID" },
        { key: "username", label: "Username", type: "text", placeholder: "Check Point admin username" },
        { key: "password", label: "Password", type: "password", placeholder: "Check Point admin password" },
      ],
      icon: "ShieldCheck",
      docsUrl: "https://sc1.checkpoint.com/documents/latest/APIs/",
    },
  };
  return metadata[type] || null;
}

export function getAllConnectorTypes(): string[] {
  return Object.keys(FETCHERS);
}
