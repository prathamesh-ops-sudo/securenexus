/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomUUID, randomInt } from "crypto";

export type ConnectorCategory =
  | "ticketing"
  | "messaging"
  | "siem"
  | "soar"
  | "iam"
  | "cicd"
  | "vcs"
  | "cloud"
  | "endpoint";

export type AuthMethod = "oauth2" | "service_account" | "api_key" | "basic" | "aws_iam";

export type SyncDirection = "inbound" | "outbound" | "bidirectional";

export type PermissionMode = "read_only" | "scoped_write" | "full_write";

export type ConnectorStatus = "available" | "installed" | "configured" | "active" | "degraded" | "error" | "disabled";

export type WebhookEventStatus = "delivered" | "failed" | "replaying" | "dead_letter";

export interface MarketplaceConnector {
  id: string;
  name: string;
  vendor: string;
  category: ConnectorCategory;
  description: string;
  icon: string;
  supportedAuth: AuthMethod[];
  supportedSync: SyncDirection[];
  syncEntities: string[];
  version: string;
  docsUrl: string;
  status: ConnectorStatus;
  permissionMode: PermissionMode;
  installedAt: string | null;
  configuredAt: string | null;
  orgId: string;
}

export interface ConnectorInstance {
  id: string;
  connectorId: string;
  orgId: string;
  name: string;
  authMethod: AuthMethod;
  permissionMode: PermissionMode;
  syncDirection: SyncDirection;
  status: ConnectorStatus;
  config: Record<string, unknown>;
  installedAt: string;
  configuredAt: string | null;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  syncIntervalMinutes: number;
}

export interface QualityScore {
  connectorId: string;
  instanceId: string;
  latencyP50Ms: number;
  latencyP99Ms: number;
  reliabilityPercent: number;
  schemaCompleteness: number;
  uptimePercent: number;
  totalSyncs: number;
  successfulSyncs: number;
  failedSyncs: number;
  lastMeasuredAt: string;
}

export interface SyncEvent {
  id: string;
  instanceId: string;
  orgId: string;
  direction: SyncDirection;
  entity: string;
  recordsProcessed: number;
  recordsFailed: number;
  durationMs: number;
  status: "success" | "partial" | "failed";
  error: string | null;
  startedAt: string;
  completedAt: string;
}

export interface WebhookEvent {
  id: string;
  instanceId: string;
  orgId: string;
  eventType: string;
  payload: Record<string, unknown>;
  idempotencyKey: string;
  status: WebhookEventStatus;
  attempts: number;
  maxAttempts: number;
  lastAttemptAt: string | null;
  nextRetryAt: string | null;
  deliveredAt: string | null;
  error: string | null;
  createdAt: string;
}

export interface DeadLetterEntry {
  id: string;
  webhookEventId: string;
  instanceId: string;
  orgId: string;
  eventType: string;
  payload: Record<string, unknown>;
  failureReason: string;
  attempts: number;
  movedAt: string;
  retriedAt: string | null;
  resolvedAt: string | null;
}

export interface HealthCheck {
  id: string;
  instanceId: string;
  orgId: string;
  status: "healthy" | "degraded" | "unhealthy" | "unreachable";
  latencyMs: number;
  credentialStatus: "valid" | "expiring" | "expired" | "unknown";
  schemaVersion: string | null;
  driftDetected: boolean;
  driftDetails: string | null;
  checkedAt: string;
}

export interface FieldMapping {
  id: string;
  instanceId: string;
  sourceField: string;
  targetField: string;
  transform: string | null;
  direction: SyncDirection;
}

const MARKETPLACE_CATALOG: Omit<
  MarketplaceConnector,
  "id" | "status" | "permissionMode" | "installedAt" | "configuredAt" | "orgId"
>[] = [
  {
    name: "Jira",
    vendor: "Atlassian",
    category: "ticketing",
    description:
      "Bidirectional ticket sync with Jira Cloud and Server. Map findings to issues, sync status and comments.",
    icon: "ticket",
    supportedAuth: ["oauth2", "api_key"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["findings", "tickets", "comments", "status", "ownership"],
    version: "2.1.0",
    docsUrl: "https://docs.securenexus.io/connectors/jira",
  },
  {
    name: "ServiceNow",
    vendor: "ServiceNow",
    category: "ticketing",
    description: "ITSM integration for incident and change management. Sync remediation tasks and approval workflows.",
    icon: "ticket",
    supportedAuth: ["oauth2", "basic"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["incidents", "changes", "tasks", "cmdb", "ownership"],
    version: "1.8.0",
    docsUrl: "https://docs.securenexus.io/connectors/servicenow",
  },
  {
    name: "Slack",
    vendor: "Slack",
    category: "messaging",
    description: "Alert notifications, interactive triage, and escalation workflows via Slack channels and DMs.",
    icon: "message-square",
    supportedAuth: ["oauth2"],
    supportedSync: ["outbound", "bidirectional"],
    syncEntities: ["alerts", "notifications", "escalations", "acknowledgments"],
    version: "3.0.1",
    docsUrl: "https://docs.securenexus.io/connectors/slack",
  },
  {
    name: "Microsoft Teams",
    vendor: "Microsoft",
    category: "messaging",
    description: "Teams channel notifications, adaptive cards for alert triage, and incident collaboration.",
    icon: "message-square",
    supportedAuth: ["oauth2", "service_account"],
    supportedSync: ["outbound", "bidirectional"],
    syncEntities: ["alerts", "notifications", "incidents", "acknowledgments"],
    version: "2.3.0",
    docsUrl: "https://docs.securenexus.io/connectors/teams",
  },
  {
    name: "Splunk",
    vendor: "Splunk",
    category: "siem",
    description: "Ingest Splunk alerts and notable events. Forward enriched findings back for correlation.",
    icon: "database",
    supportedAuth: ["api_key", "basic"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["alerts", "events", "searches", "lookups"],
    version: "2.5.0",
    docsUrl: "https://docs.securenexus.io/connectors/splunk",
  },
  {
    name: "Microsoft Sentinel",
    vendor: "Microsoft",
    category: "siem",
    description: "Azure Sentinel integration for incident ingestion, KQL query forwarding, and playbook triggers.",
    icon: "database",
    supportedAuth: ["oauth2", "service_account"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["incidents", "alerts", "hunting_queries", "watchlists"],
    version: "1.9.0",
    docsUrl: "https://docs.securenexus.io/connectors/sentinel",
  },
  {
    name: "Palo Alto XSOAR",
    vendor: "Palo Alto Networks",
    category: "soar",
    description: "Orchestrate playbooks, sync war room data, and trigger automated response actions.",
    icon: "shield",
    supportedAuth: ["api_key", "service_account"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["incidents", "playbooks", "indicators", "war_room"],
    version: "1.6.0",
    docsUrl: "https://docs.securenexus.io/connectors/xsoar",
  },
  {
    name: "Okta",
    vendor: "Okta",
    category: "iam",
    description: "User lifecycle events, MFA status, suspicious login detection, and identity risk scoring.",
    icon: "user",
    supportedAuth: ["oauth2", "api_key"],
    supportedSync: ["inbound", "bidirectional"],
    syncEntities: ["users", "groups", "mfa_events", "login_events", "risk_scores"],
    version: "2.0.0",
    docsUrl: "https://docs.securenexus.io/connectors/okta",
  },
  {
    name: "Azure AD / Entra ID",
    vendor: "Microsoft",
    category: "iam",
    description: "Directory sync, conditional access policy monitoring, and identity threat detection.",
    icon: "user",
    supportedAuth: ["oauth2", "service_account"],
    supportedSync: ["inbound", "bidirectional"],
    syncEntities: ["users", "groups", "sign_ins", "risky_users", "policies"],
    version: "2.2.0",
    docsUrl: "https://docs.securenexus.io/connectors/azure-ad",
  },
  {
    name: "GitHub Actions",
    vendor: "GitHub",
    category: "cicd",
    description: "Pipeline security scanning, workflow run monitoring, and SAST/DAST result ingestion.",
    icon: "git-branch",
    supportedAuth: ["oauth2", "api_key"],
    supportedSync: ["inbound", "bidirectional"],
    syncEntities: ["workflows", "scan_results", "secrets", "dependabot_alerts"],
    version: "1.7.0",
    docsUrl: "https://docs.securenexus.io/connectors/github-actions",
  },
  {
    name: "GitLab CI",
    vendor: "GitLab",
    category: "cicd",
    description: "Pipeline security integration, SAST/DAST scanning, and merge request security gates.",
    icon: "git-branch",
    supportedAuth: ["oauth2", "api_key"],
    supportedSync: ["inbound", "bidirectional"],
    syncEntities: ["pipelines", "scan_results", "vulnerabilities", "merge_requests"],
    version: "1.4.0",
    docsUrl: "https://docs.securenexus.io/connectors/gitlab-ci",
  },
  {
    name: "GitHub",
    vendor: "GitHub",
    category: "vcs",
    description: "Repository monitoring, code scanning alerts, secret scanning, and Dependabot integration.",
    icon: "code",
    supportedAuth: ["oauth2", "api_key"],
    supportedSync: ["inbound", "bidirectional"],
    syncEntities: ["repos", "code_scans", "secret_alerts", "dependencies"],
    version: "3.1.0",
    docsUrl: "https://docs.securenexus.io/connectors/github",
  },
  {
    name: "AWS Security Hub",
    vendor: "Amazon Web Services",
    category: "cloud",
    description: "Aggregate findings from GuardDuty, Inspector, Macie, and third-party tools via Security Hub.",
    icon: "cloud",
    supportedAuth: ["aws_iam", "api_key"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["findings", "compliance", "resources", "accounts"],
    version: "2.4.0",
    docsUrl: "https://docs.securenexus.io/connectors/aws-security-hub",
  },
  {
    name: "GCP Security Command Center",
    vendor: "Google Cloud",
    category: "cloud",
    description: "Cloud asset inventory, vulnerability findings, and threat detection from SCC.",
    icon: "cloud",
    supportedAuth: ["service_account"],
    supportedSync: ["inbound", "bidirectional"],
    syncEntities: ["findings", "assets", "compliance", "vulnerabilities"],
    version: "1.5.0",
    docsUrl: "https://docs.securenexus.io/connectors/gcp-scc",
  },
  {
    name: "CrowdStrike Falcon",
    vendor: "CrowdStrike",
    category: "endpoint",
    description: "EDR telemetry ingestion, detection alerts, host containment actions, and IOC management.",
    icon: "monitor",
    supportedAuth: ["oauth2", "api_key"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["detections", "hosts", "iocs", "containment", "vulnerabilities"],
    version: "2.6.0",
    docsUrl: "https://docs.securenexus.io/connectors/crowdstrike",
  },
  {
    name: "SentinelOne",
    vendor: "SentinelOne",
    category: "endpoint",
    description: "Endpoint protection alerts, threat intelligence, and automated remediation actions.",
    icon: "monitor",
    supportedAuth: ["api_key"],
    supportedSync: ["inbound", "outbound", "bidirectional"],
    syncEntities: ["threats", "agents", "exclusions", "forensics"],
    version: "1.3.0",
    docsUrl: "https://docs.securenexus.io/connectors/sentinelone",
  },
];

const MAX_STORE_SIZE = 10000;

const instanceStore = new Map<string, ConnectorInstance>();
const qualityStore = new Map<string, QualityScore>();
const syncEventStore = new Map<string, SyncEvent>();
const webhookEventStore = new Map<string, WebhookEvent>();
const deadLetterStore = new Map<string, DeadLetterEntry>();
const healthStore = new Map<string, HealthCheck>();
const fieldMappingStore = new Map<string, FieldMapping>();

function evictOldest(
  store: Map<
    string,
    { createdAt?: string; startedAt?: string; checkedAt?: string; movedAt?: string; installedAt?: string }
  >,
): void {
  if (store.size <= MAX_STORE_SIZE) return;
  const entries = Array.from(store.entries());
  entries.sort((a, b) => {
    const aTime = a[1].createdAt || a[1].startedAt || a[1].checkedAt || a[1].movedAt || a[1].installedAt || "";
    const bTime = b[1].createdAt || b[1].startedAt || b[1].checkedAt || b[1].movedAt || b[1].installedAt || "";
    return new Date(aTime).getTime() - new Date(bTime).getTime();
  });
  const toRemove = entries.slice(0, store.size - MAX_STORE_SIZE);
  for (const [key] of toRemove) {
    store.delete(key);
  }
}

export function getMarketplaceCatalog(orgId: string, category?: ConnectorCategory): MarketplaceConnector[] {
  return MARKETPLACE_CATALOG.map((c) => {
    const instance = Array.from(instanceStore.values()).find((inst) => inst.orgId === orgId && inst.name === c.name);
    const status: ConnectorStatus = instance ? instance.status : "available";
    return {
      ...c,
      id: c.name.toLowerCase().replace(/[^a-z0-9]/g, "-"),
      status,
      permissionMode: instance ? instance.permissionMode : ("read_only" as PermissionMode),
      installedAt: instance ? instance.installedAt : null,
      configuredAt: instance ? instance.configuredAt : null,
      orgId,
    };
  }).filter((c) => !category || c.category === category);
}

export function getConnectorDetails(connectorSlug: string, orgId: string): MarketplaceConnector | null {
  const catalog = getMarketplaceCatalog(orgId);
  return catalog.find((c) => c.id === connectorSlug) || null;
}

export function installConnector(
  connectorSlug: string,
  orgId: string,
  authMethod: AuthMethod,
  syncDirection: SyncDirection,
  config: Record<string, unknown>,
): ConnectorInstance {
  const catalogEntry = MARKETPLACE_CATALOG.find(
    (c) => c.name.toLowerCase().replace(/[^a-z0-9]/g, "-") === connectorSlug,
  );
  if (!catalogEntry) {
    throw new Error("Connector not found in catalog: " + connectorSlug);
  }

  const instance: ConnectorInstance = {
    id: randomUUID(),
    connectorId: connectorSlug,
    orgId,
    name: catalogEntry.name,
    authMethod,
    permissionMode: "read_only",
    syncDirection,
    status: "installed",
    config,
    installedAt: new Date().toISOString(),
    configuredAt: null,
    lastSyncAt: null,
    lastSyncStatus: null,
    syncIntervalMinutes: 15,
  };

  instanceStore.set(instance.id, instance);
  evictOldest(instanceStore as any);

  initQualityScore(instance.connectorId, instance.id);

  return instance;
}

function initQualityScore(connectorId: string, instanceId: string): void {
  const score: QualityScore = {
    connectorId,
    instanceId,
    latencyP50Ms: 0,
    latencyP99Ms: 0,
    reliabilityPercent: 100,
    schemaCompleteness: 100,
    uptimePercent: 100,
    totalSyncs: 0,
    successfulSyncs: 0,
    failedSyncs: 0,
    lastMeasuredAt: new Date().toISOString(),
  };
  qualityStore.set(instanceId, score);
}

export function configureInstance(
  instanceId: string,
  orgId: string,
  updates: {
    config?: Record<string, unknown>;
    syncDirection?: SyncDirection;
    syncIntervalMinutes?: number;
  },
): ConnectorInstance | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;

  if (updates.config) {
    instance.config = { ...instance.config, ...updates.config };
  }
  if (updates.syncDirection) {
    instance.syncDirection = updates.syncDirection;
  }
  if (updates.syncIntervalMinutes !== undefined) {
    instance.syncIntervalMinutes = Math.max(1, Math.min(1440, updates.syncIntervalMinutes));
  }

  instance.status = "configured";
  instance.configuredAt = new Date().toISOString();
  instanceStore.set(instanceId, instance);
  return instance;
}

export function upgradePermissions(instanceId: string, orgId: string, mode: PermissionMode): ConnectorInstance | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;
  instance.permissionMode = mode;
  instanceStore.set(instanceId, instance);
  return instance;
}

export function getInstances(orgId: string): ConnectorInstance[] {
  return Array.from(instanceStore.values())
    .filter((inst) => inst.orgId === orgId)
    .sort((a, b) => new Date(b.installedAt).getTime() - new Date(a.installedAt).getTime());
}

export function getInstance(instanceId: string, orgId: string): ConnectorInstance | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;
  return instance;
}

export function deleteInstance(instanceId: string, orgId: string): boolean {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return false;
  instanceStore.delete(instanceId);
  qualityStore.delete(instanceId);
  const syncEvents = Array.from(syncEventStore.entries()).filter(([, e]) => e.instanceId === instanceId);
  for (const [key] of syncEvents) {
    syncEventStore.delete(key);
  }
  const webhookEvents = Array.from(webhookEventStore.entries()).filter(([, e]) => e.instanceId === instanceId);
  for (const [key] of webhookEvents) {
    webhookEventStore.delete(key);
  }
  return true;
}

export function triggerSync(instanceId: string, orgId: string): SyncEvent | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;
  if (instance.permissionMode === "read_only" && instance.syncDirection !== "inbound") {
    return null;
  }

  const startTime = Date.now();
  const recordsProcessed = 50;
  const recordsFailed = 0;
  const durationMs = 800;
  const status = "success" as const;

  const event: SyncEvent = {
    id: randomUUID(),
    instanceId,
    orgId,
    direction: instance.syncDirection,
    entity: "findings",
    recordsProcessed,
    recordsFailed,
    durationMs,
    status,
    error: recordsFailed > 0 ? "Partial sync: " + recordsFailed + " records failed schema validation" : null,
    startedAt: new Date(startTime).toISOString(),
    completedAt: new Date(startTime + durationMs).toISOString(),
  };

  syncEventStore.set(event.id, event);
  evictOldest(syncEventStore as any);

  instance.lastSyncAt = event.completedAt;
  instance.lastSyncStatus = status;
  instance.status = "active";
  instanceStore.set(instanceId, instance);

  updateQualityAfterSync(instanceId, durationMs, status === "success");

  return event;
}

function updateQualityAfterSync(instanceId: string, durationMs: number, success: boolean): void {
  const score = qualityStore.get(instanceId);
  if (!score) return;

  score.totalSyncs++;
  if (success) {
    score.successfulSyncs++;
  } else {
    score.failedSyncs++;
  }

  score.reliabilityPercent =
    score.totalSyncs > 0 ? Math.round((score.successfulSyncs / score.totalSyncs) * 10000) / 100 : 100;

  score.latencyP50Ms = Math.round((score.latencyP50Ms * (score.totalSyncs - 1) + durationMs) / score.totalSyncs);
  score.latencyP99Ms = Math.max(score.latencyP99Ms, durationMs);
  score.lastMeasuredAt = new Date().toISOString();
  qualityStore.set(instanceId, score);
}

export function getSyncHistory(instanceId: string, orgId: string, limit: number = 50): SyncEvent[] {
  return Array.from(syncEventStore.values())
    .filter((e) => e.instanceId === instanceId && e.orgId === orgId)
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, limit);
}

export function getQualityScore(instanceId: string, orgId: string): QualityScore | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;
  return qualityStore.get(instanceId) || null;
}

export function getAllQualityScores(orgId: string): QualityScore[] {
  const orgInstances = Array.from(instanceStore.values()).filter((i) => i.orgId === orgId);
  const scores: QualityScore[] = [];
  for (const inst of orgInstances) {
    const score = qualityStore.get(inst.id);
    if (score) scores.push(score);
  }
  return scores;
}

export function ingestWebhook(
  instanceId: string,
  orgId: string,
  eventType: string,
  payload: Record<string, unknown>,
  idempotencyKey: string,
): WebhookEvent | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;

  const existing = Array.from(webhookEventStore.values()).find(
    (e) => e.instanceId === instanceId && e.idempotencyKey === idempotencyKey,
  );
  if (existing) {
    return existing;
  }

  const event: WebhookEvent = {
    id: randomUUID(),
    instanceId,
    orgId,
    eventType,
    payload,
    idempotencyKey,
    status: "delivered",
    attempts: 1,
    maxAttempts: 5,
    lastAttemptAt: new Date().toISOString(),
    nextRetryAt: null,
    deliveredAt: new Date().toISOString(),
    error: null,
    createdAt: new Date().toISOString(),
  };

  webhookEventStore.set(event.id, event);
  evictOldest(webhookEventStore as any);
  return event;
}

export function getWebhookEvents(instanceId: string, orgId: string, limit: number = 50): WebhookEvent[] {
  return Array.from(webhookEventStore.values())
    .filter((e) => e.instanceId === instanceId && e.orgId === orgId)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, limit);
}

export function getDeadLetterQueue(orgId: string): DeadLetterEntry[] {
  return Array.from(deadLetterStore.values())
    .filter((e) => e.orgId === orgId && !e.resolvedAt)
    .sort((a, b) => new Date(b.movedAt).getTime() - new Date(a.movedAt).getTime());
}

export function retryDeadLetter(entryId: string, orgId: string): DeadLetterEntry | null {
  const entry = deadLetterStore.get(entryId);
  if (!entry || entry.orgId !== orgId) return null;

  entry.retriedAt = new Date().toISOString();
  entry.resolvedAt = new Date().toISOString();
  deadLetterStore.set(entryId, entry);
  return entry;
}

export function discardDeadLetter(entryId: string, orgId: string): boolean {
  const entry = deadLetterStore.get(entryId);
  if (!entry || entry.orgId !== orgId) return false;
  entry.resolvedAt = new Date().toISOString();
  deadLetterStore.set(entryId, entry);
  return true;
}

export function runHealthCheck(instanceId: string, orgId: string): HealthCheck | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;

  const latencyMs = 120;
  const healthyRoll = instance.status === "active" ? 0.5 : 0.98;
  let status: HealthCheck["status"] = "healthy";
  let driftDetected = false;
  let driftDetails: string | null = null;

  if (healthyRoll > 0.95) {
    status = "unhealthy";
  } else if (healthyRoll > 0.85) {
    status = "degraded";
    driftDetected = true;
    driftDetails = "Schema field 'severity_level' missing in upstream API v2 response";
  }

  const check: HealthCheck = {
    id: randomUUID(),
    instanceId,
    orgId,
    status,
    latencyMs,
    credentialStatus: status === "unhealthy" ? "expired" : "valid",
    schemaVersion: "v2.1",
    driftDetected,
    driftDetails,
    checkedAt: new Date().toISOString(),
  };

  healthStore.set(check.id, check);
  evictOldest(healthStore as any);

  if (status !== "healthy") {
    instance.status = status === "unhealthy" ? "error" : "degraded";
    instanceStore.set(instanceId, instance);
  }

  return check;
}

export function getHealthHistory(instanceId: string, orgId: string, limit: number = 20): HealthCheck[] {
  return Array.from(healthStore.values())
    .filter((h) => h.instanceId === instanceId && h.orgId === orgId)
    .sort((a, b) => new Date(b.checkedAt).getTime() - new Date(a.checkedAt).getTime())
    .slice(0, limit);
}

export function setFieldMappings(
  instanceId: string,
  orgId: string,
  mappings: Omit<FieldMapping, "id" | "instanceId">[],
): FieldMapping[] {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return [];

  const existing = Array.from(fieldMappingStore.entries()).filter(([, m]) => m.instanceId === instanceId);
  for (const [key] of existing) {
    fieldMappingStore.delete(key);
  }

  const created: FieldMapping[] = [];
  for (const m of mappings) {
    const mapping: FieldMapping = {
      id: randomUUID(),
      instanceId,
      sourceField: m.sourceField,
      targetField: m.targetField,
      transform: m.transform,
      direction: m.direction,
    };
    fieldMappingStore.set(mapping.id, mapping);
    created.push(mapping);
  }
  return created;
}

export function getFieldMappings(instanceId: string, orgId: string): FieldMapping[] {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return [];
  return Array.from(fieldMappingStore.values()).filter((m) => m.instanceId === instanceId);
}

export function getMarketplaceStats(orgId: string): {
  totalAvailable: number;
  installed: number;
  active: number;
  degraded: number;
  errors: number;
  categoryCounts: Record<string, number>;
} {
  const instances = getInstances(orgId);
  const categoryCounts: Record<string, number> = {};
  for (const c of MARKETPLACE_CATALOG) {
    const cat = c.category;
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  }

  return {
    totalAvailable: MARKETPLACE_CATALOG.length,
    installed: instances.length,
    active: instances.filter((i) => i.status === "active").length,
    degraded: instances.filter((i) => i.status === "degraded").length,
    errors: instances.filter((i) => i.status === "error").length,
    categoryCounts,
  };
}
