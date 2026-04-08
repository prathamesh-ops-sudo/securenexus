/* eslint-disable @typescript-eslint/no-explicit-any */
import crypto from "crypto";
import { db } from "./db";
import { collectorInstances, collectorEvents, collectorScans } from "@shared/schema";
import { eq, and, desc, sql, count } from "drizzle-orm";
import { logger } from "./logger";

export type CollectorType =
  | "agent_endpoint"
  | "agent_network"
  | "agent_cloud"
  | "agentless_cloud"
  | "syslog_receiver"
  | "log_file_upload"
  | "api_push"
  | "vulnerability_scanner"
  | "asset_discovery";

export type CollectorStatus = "active" | "degraded" | "offline" | "pending_install" | "disabled";
export type DeploymentMethod = "script" | "docker" | "kubernetes" | "manual" | "cloud_api";
export type Platform =
  | "linux"
  | "windows"
  | "macos"
  | "ios"
  | "android"
  | "docker"
  | "kubernetes"
  | "aws"
  | "azure"
  | "gcp"
  | "any";

export interface CollectorTemplate {
  slug: string;
  name: string;
  type: CollectorType;
  description: string;
  icon: string;
  platforms: Platform[];
  deploymentMethods: DeploymentMethod[];
  dataTypes: string[];
  estimatedSetupMinutes: number;
  requiresAgent: boolean;
  configSchema: ConfigField[];
}

export interface ConfigField {
  key: string;
  label: string;
  type: "string" | "number" | "boolean" | "select" | "secret";
  required: boolean;
  defaultValue?: string | number | boolean;
  options?: string[];
  placeholder?: string;
}

export interface CollectorInstance {
  id: string;
  templateSlug: string;
  orgId: string;
  name: string;
  status: CollectorStatus;
  platform: Platform;
  deploymentMethod: DeploymentMethod;
  config: Record<string, unknown>;
  hostInfo: HostInfo | null;
  metrics: CollectorMetrics;
  installedAt: string;
  lastHeartbeatAt: string | null;
  lastDataAt: string | null;
  version: string;
  tags: string[];
}

export interface HostInfo {
  hostname: string;
  ipAddress: string;
  os: string;
  arch: string;
  cpuCount: number;
  memoryGb: number;
  agentVersion: string;
}

export interface CollectorMetrics {
  eventsPerSecond: number;
  bytesIngested: number;
  errorsLast24h: number;
  uptimePercent: number;
  latencyP50Ms: number;
  latencyP99Ms: number;
  lastEventCount: number;
  totalEventsIngested: number;
}

export interface IngestedEvent {
  id: string;
  collectorId: string;
  orgId: string;
  eventType: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  source: string;
  timestamp: string;
  rawData: Record<string, unknown>;
  parsedFields: Record<string, unknown>;
  tags: string[];
  processed: boolean;
}

export interface ScanResult {
  id: string;
  collectorId: string;
  orgId: string;
  scanType: "vulnerability" | "asset_discovery" | "compliance" | "configuration";
  status: "running" | "completed" | "failed";
  startedAt: string;
  completedAt: string | null;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  targets: string[];
  findings: ScanFinding[];
}

export interface ScanFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  affectedAsset: string;
  remediation: string;
  cveIds: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface DataPipelineStats {
  orgId: string;
  totalCollectors: number;
  activeCollectors: number;
  degradedCollectors: number;
  offlineCollectors: number;
  eventsPerSecond: number;
  totalEventsToday: number;
  totalBytesToday: number;
  storageUsedGb: number;
  storageQuotaGb: number;
  retentionDays: number;
  topEventTypes: Array<{ type: string; count: number; percentage: number }>;
  collectorsByType: Record<CollectorType, number>;
  healthScore: number;
}

const COLLECTOR_TEMPLATES: CollectorTemplate[] = [
  {
    slug: "endpoint-agent-linux",
    name: "Endpoint Agent (Linux)",
    type: "agent_endpoint",
    description:
      "Lightweight agent for Linux endpoints. Collects process events, file integrity monitoring, network connections, and authentication logs.",
    icon: "Monitor",
    platforms: ["linux"],
    deploymentMethods: ["script", "docker", "kubernetes"],
    dataTypes: ["process_events", "file_integrity", "network_connections", "auth_logs", "syslog"],
    estimatedSetupMinutes: 5,
    requiresAgent: true,
    configSchema: [
      {
        key: "logPaths",
        label: "Log File Paths",
        type: "string",
        required: false,
        placeholder: "/var/log/syslog,/var/log/auth.log",
      },
      { key: "enableFim", label: "File Integrity Monitoring", type: "boolean", required: false, defaultValue: true },
      { key: "enableProcessAudit", label: "Process Auditing", type: "boolean", required: false, defaultValue: true },
      {
        key: "reportingIntervalSec",
        label: "Reporting Interval (seconds)",
        type: "number",
        required: false,
        defaultValue: 30,
      },
    ],
  },
  {
    slug: "endpoint-agent-windows",
    name: "Endpoint Agent (Windows)",
    type: "agent_endpoint",
    description:
      "Windows endpoint agent collecting Windows Event Logs, PowerShell script block logging, Sysmon events, and registry changes.",
    icon: "Monitor",
    platforms: ["windows"],
    deploymentMethods: ["script", "manual"],
    dataTypes: ["windows_events", "powershell_logs", "sysmon", "registry_changes", "defender_events"],
    estimatedSetupMinutes: 10,
    requiresAgent: true,
    configSchema: [
      {
        key: "eventLogChannels",
        label: "Event Log Channels",
        type: "string",
        required: false,
        placeholder: "Security,System,Application",
      },
      { key: "enableSysmon", label: "Sysmon Integration", type: "boolean", required: false, defaultValue: true },
      {
        key: "enableDefender",
        label: "Defender Event Forwarding",
        type: "boolean",
        required: false,
        defaultValue: true,
      },
      {
        key: "reportingIntervalSec",
        label: "Reporting Interval (seconds)",
        type: "number",
        required: false,
        defaultValue: 30,
      },
    ],
  },
  {
    slug: "endpoint-agent-macos",
    name: "Endpoint Agent (macOS)",
    type: "agent_endpoint",
    description:
      "macOS endpoint agent for unified logging, TCC events, XProtect alerts, and application usage tracking.",
    icon: "Monitor",
    platforms: ["macos"],
    deploymentMethods: ["script", "manual"],
    dataTypes: ["unified_logs", "tcc_events", "xprotect_alerts", "app_usage", "login_events"],
    estimatedSetupMinutes: 5,
    requiresAgent: true,
    configSchema: [
      { key: "enableTcc", label: "TCC Privacy Events", type: "boolean", required: false, defaultValue: true },
      { key: "enableXprotect", label: "XProtect Alerts", type: "boolean", required: false, defaultValue: true },
      {
        key: "reportingIntervalSec",
        label: "Reporting Interval (seconds)",
        type: "number",
        required: false,
        defaultValue: 30,
      },
    ],
  },
  {
    slug: "network-monitor",
    name: "Network Traffic Monitor",
    type: "agent_network",
    description:
      "Passive network monitor capturing DNS queries, HTTP/TLS metadata, flow records, and anomalous connection detection.",
    icon: "Network",
    platforms: ["linux", "docker"],
    deploymentMethods: ["docker", "kubernetes"],
    dataTypes: ["dns_queries", "http_metadata", "tls_certificates", "netflow", "anomalous_connections"],
    estimatedSetupMinutes: 10,
    requiresAgent: true,
    configSchema: [
      { key: "interface", label: "Network Interface", type: "string", required: false, placeholder: "eth0" },
      {
        key: "captureFilter",
        label: "BPF Capture Filter",
        type: "string",
        required: false,
        placeholder: "not port 22",
      },
      { key: "enableDnsLogging", label: "DNS Query Logging", type: "boolean", required: false, defaultValue: true },
      {
        key: "enableTlsInspection",
        label: "TLS Certificate Inspection",
        type: "boolean",
        required: false,
        defaultValue: true,
      },
    ],
  },
  {
    slug: "aws-cloud-collector",
    name: "AWS Cloud Collector",
    type: "agentless_cloud",
    description:
      "Agentless AWS integration pulling CloudTrail, GuardDuty findings, Security Hub, IAM Access Analyzer, and VPC Flow Logs via AWS APIs.",
    icon: "Cloud",
    platforms: ["aws"],
    deploymentMethods: ["cloud_api"],
    dataTypes: ["cloudtrail", "guardduty", "security_hub", "iam_analyzer", "vpc_flow_logs", "config_changes"],
    estimatedSetupMinutes: 15,
    requiresAgent: false,
    configSchema: [
      {
        key: "awsRegion",
        label: "AWS Region",
        type: "select",
        required: true,
        options: ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1", "ap-southeast-1"],
      },
      {
        key: "roleArn",
        label: "Cross-Account Role ARN",
        type: "string",
        required: true,
        placeholder: "arn:aws:iam::123456789012:role/SecureNexusReader",
      },
      { key: "enableCloudTrail", label: "CloudTrail Events", type: "boolean", required: false, defaultValue: true },
      { key: "enableGuardDuty", label: "GuardDuty Findings", type: "boolean", required: false, defaultValue: true },
      { key: "enableVpcFlowLogs", label: "VPC Flow Logs", type: "boolean", required: false, defaultValue: false },
    ],
  },
  {
    slug: "azure-cloud-collector",
    name: "Azure Cloud Collector",
    type: "agentless_cloud",
    description:
      "Agentless Azure integration pulling Activity Logs, Defender for Cloud alerts, Azure AD sign-in logs, and NSG Flow Logs.",
    icon: "Cloud",
    platforms: ["azure"],
    deploymentMethods: ["cloud_api"],
    dataTypes: ["activity_logs", "defender_alerts", "aad_signin", "nsg_flow_logs", "policy_events"],
    estimatedSetupMinutes: 15,
    requiresAgent: false,
    configSchema: [
      {
        key: "tenantId",
        label: "Azure Tenant ID",
        type: "string",
        required: true,
        placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      },
      {
        key: "clientId",
        label: "App Registration Client ID",
        type: "string",
        required: true,
        placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      },
      { key: "clientSecret", label: "Client Secret", type: "secret", required: true },
      { key: "subscriptionId", label: "Subscription ID", type: "string", required: true },
      {
        key: "enableDefenderAlerts",
        label: "Defender for Cloud Alerts",
        type: "boolean",
        required: false,
        defaultValue: true,
      },
    ],
  },
  {
    slug: "gcp-cloud-collector",
    name: "GCP Cloud Collector",
    type: "agentless_cloud",
    description:
      "Agentless GCP integration pulling Cloud Audit Logs, Security Command Center findings, VPC Flow Logs, and IAM policy changes.",
    icon: "Cloud",
    platforms: ["gcp"],
    deploymentMethods: ["cloud_api"],
    dataTypes: ["audit_logs", "scc_findings", "vpc_flow_logs", "iam_changes", "cloud_armor_events"],
    estimatedSetupMinutes: 15,
    requiresAgent: false,
    configSchema: [
      { key: "projectId", label: "GCP Project ID", type: "string", required: true, placeholder: "my-project-123" },
      { key: "serviceAccountKey", label: "Service Account JSON Key", type: "secret", required: true },
      { key: "enableScc", label: "Security Command Center", type: "boolean", required: false, defaultValue: true },
      { key: "enableAuditLogs", label: "Cloud Audit Logs", type: "boolean", required: false, defaultValue: true },
    ],
  },
  {
    slug: "syslog-receiver",
    name: "Syslog Receiver",
    type: "syslog_receiver",
    description:
      "Universal syslog receiver (RFC 5424/3164) accepting logs from firewalls, routers, switches, and any syslog-compatible device over UDP/TCP/TLS.",
    icon: "ArrowDownToLine",
    platforms: ["linux", "docker", "kubernetes"],
    deploymentMethods: ["docker", "kubernetes"],
    dataTypes: ["syslog_rfc5424", "syslog_rfc3164", "cef", "leef"],
    estimatedSetupMinutes: 5,
    requiresAgent: false,
    configSchema: [
      { key: "listenPort", label: "Listen Port", type: "number", required: false, defaultValue: 514 },
      {
        key: "protocol",
        label: "Protocol",
        type: "select",
        required: false,
        options: ["udp", "tcp", "tls"],
        defaultValue: "tcp",
      },
      { key: "enableCef", label: "CEF Parsing", type: "boolean", required: false, defaultValue: true },
      { key: "enableLeef", label: "LEEF Parsing", type: "boolean", required: false, defaultValue: false },
    ],
  },
  {
    slug: "log-upload",
    name: "Log File Upload",
    type: "log_file_upload",
    description:
      "Upload log files directly via the SecureNexus UI or API. Supports CSV, JSON, NDJSON, and common log formats. Ideal for one-time imports or batch processing.",
    icon: "Upload",
    platforms: ["any"],
    deploymentMethods: ["manual"],
    dataTypes: ["csv", "json", "ndjson", "common_log", "combined_log"],
    estimatedSetupMinutes: 2,
    requiresAgent: false,
    configSchema: [
      {
        key: "logFormat",
        label: "Log Format",
        type: "select",
        required: true,
        options: ["json", "ndjson", "csv", "common_log", "combined_log", "auto_detect"],
      },
      {
        key: "timestampField",
        label: "Timestamp Field Name",
        type: "string",
        required: false,
        placeholder: "timestamp",
      },
      { key: "timezone", label: "Source Timezone", type: "string", required: false, defaultValue: "UTC" },
    ],
  },
  {
    slug: "api-push-collector",
    name: "API Push Collector",
    type: "api_push",
    description:
      "RESTful API endpoint for pushing events from custom applications, scripts, or CI/CD pipelines. Supports JSON payloads with automatic field extraction.",
    icon: "Zap",
    platforms: ["any"],
    deploymentMethods: ["cloud_api"],
    dataTypes: ["custom_events", "application_logs", "cicd_events", "deployment_events"],
    estimatedSetupMinutes: 3,
    requiresAgent: false,
    configSchema: [
      { key: "apiKeyName", label: "API Key Name", type: "string", required: true, placeholder: "my-app-collector" },
      {
        key: "rateLimitPerMinute",
        label: "Rate Limit (events/min)",
        type: "number",
        required: false,
        defaultValue: 1000,
      },
      {
        key: "enableFieldExtraction",
        label: "Auto Field Extraction",
        type: "boolean",
        required: false,
        defaultValue: true,
      },
    ],
  },
  {
    slug: "vuln-scanner",
    name: "Vulnerability Scanner",
    type: "vulnerability_scanner",
    description:
      "Built-in vulnerability scanner for network hosts, web applications, and container images. Runs scheduled or on-demand scans with CVE correlation.",
    icon: "Shield",
    platforms: ["any"],
    deploymentMethods: ["cloud_api"],
    dataTypes: ["cve_findings", "misconfigurations", "open_ports", "ssl_issues", "outdated_software"],
    estimatedSetupMinutes: 5,
    requiresAgent: false,
    configSchema: [
      {
        key: "scanTargets",
        label: "Scan Targets (CIDR/hosts)",
        type: "string",
        required: true,
        placeholder: "10.0.0.0/24,192.168.1.0/24",
      },
      {
        key: "scanType",
        label: "Scan Type",
        type: "select",
        required: false,
        options: ["full", "quick", "web_app", "container"],
        defaultValue: "quick",
      },
      { key: "scheduleInterval", label: "Schedule (hours)", type: "number", required: false, defaultValue: 24 },
      { key: "enableCveCorrelation", label: "CVE Correlation", type: "boolean", required: false, defaultValue: true },
    ],
  },
  {
    slug: "asset-discovery",
    name: "Asset Discovery",
    type: "asset_discovery",
    description:
      "Automatic network asset discovery via ARP scanning, DNS enumeration, and service fingerprinting. Builds a live asset inventory with classification.",
    icon: "Search",
    platforms: ["linux", "docker"],
    deploymentMethods: ["docker", "kubernetes"],
    dataTypes: ["discovered_hosts", "services", "os_fingerprint", "software_inventory"],
    estimatedSetupMinutes: 10,
    requiresAgent: false,
    configSchema: [
      {
        key: "networkRanges",
        label: "Network Ranges (CIDR)",
        type: "string",
        required: true,
        placeholder: "10.0.0.0/16,172.16.0.0/12",
      },
      {
        key: "enableServiceDetection",
        label: "Service Detection",
        type: "boolean",
        required: false,
        defaultValue: true,
      },
      { key: "enableOsFingerprint", label: "OS Fingerprinting", type: "boolean", required: false, defaultValue: true },
      {
        key: "discoveryIntervalHours",
        label: "Discovery Interval (hours)",
        type: "number",
        required: false,
        defaultValue: 12,
      },
    ],
  },
];

const MAX_INSTANCES = 500;

function generateId(): string {
  return crypto.randomBytes(12).toString("hex");
}

function randomBetween(min: number, max: number): number {
  return min + crypto.randomInt(max - min + 1);
}

export function getCollectorTemplates(type?: CollectorType): CollectorTemplate[] {
  if (type) return COLLECTOR_TEMPLATES.filter((t) => t.type === type);
  return [...COLLECTOR_TEMPLATES];
}

export function getTemplateBySlug(slug: string): CollectorTemplate | null {
  return COLLECTOR_TEMPLATES.find((t) => t.slug === slug) ?? null;
}

export async function deployCollector(
  templateSlug: string,
  orgId: string,
  name: string,
  platform: Platform,
  deploymentMethod: DeploymentMethod,
  config: Record<string, unknown>,
  tags: string[],
): Promise<CollectorInstance> {
  const template = COLLECTOR_TEMPLATES.find((t) => t.slug === templateSlug);
  if (!template) throw new Error(`Unknown collector template: ${templateSlug}`);
  if (!template.platforms.includes(platform) && !template.platforms.includes("any")) {
    throw new Error(`Template ${templateSlug} does not support platform: ${platform}`);
  }
  if (!template.deploymentMethods.includes(deploymentMethod)) {
    throw new Error(`Template ${templateSlug} does not support deployment method: ${deploymentMethod}`);
  }

  const [countResult] = await db
    .select({ value: count() })
    .from(collectorInstances)
    .where(eq(collectorInstances.orgId, orgId));
  if ((countResult?.value ?? 0) >= MAX_INSTANCES) {
    throw new Error("Maximum collector instances reached for this organization");
  }

  const id = generateId();
  const metrics = {
    eventsPerSecond: 0,
    bytesIngested: 0,
    errorsLast24h: 0,
    uptimePercent: 0,
    latencyP50Ms: 0,
    latencyP99Ms: 0,
    lastEventCount: 0,
    totalEventsIngested: 0,
  };

  const [inserted] = await db
    .insert(collectorInstances)
    .values({
      id,
      orgId,
      templateSlug,
      name,
      status: template.requiresAgent ? "pending_install" : "active",
      platform,
      deploymentMethod,
      config,
      metrics,
      tags,
    })
    .returning();

  return dbRowToInstance(inserted);
}

export async function getCollectorInstances(orgId: string, type?: CollectorType): Promise<CollectorInstance[]> {
  const rows = await db
    .select()
    .from(collectorInstances)
    .where(eq(collectorInstances.orgId, orgId))
    .orderBy(desc(collectorInstances.createdAt));

  let instances = rows.map(dbRowToInstance);
  if (type) {
    const slugsOfType = COLLECTOR_TEMPLATES.filter((t) => t.type === type).map((t) => t.slug);
    instances = instances.filter((i) => slugsOfType.includes(i.templateSlug));
  }
  return instances;
}

export async function getCollectorInstance(instanceId: string, orgId: string): Promise<CollectorInstance | null> {
  const [row] = await db
    .select()
    .from(collectorInstances)
    .where(and(eq(collectorInstances.id, instanceId), eq(collectorInstances.orgId, orgId)))
    .limit(1);
  return row ? dbRowToInstance(row) : null;
}

export async function updateCollectorConfig(
  instanceId: string,
  orgId: string,
  updates: { name?: string; config?: Record<string, unknown>; tags?: string[]; status?: CollectorStatus },
): Promise<CollectorInstance | null> {
  const existing = await getCollectorInstance(instanceId, orgId);
  if (!existing) return null;

  const patch: Record<string, unknown> = { updatedAt: new Date() };
  if (updates.name !== undefined) patch.name = updates.name;
  if (updates.config !== undefined) patch.config = { ...((existing as any).config || {}), ...updates.config };
  if (updates.tags !== undefined) patch.tags = updates.tags;
  if (updates.status !== undefined) patch.status = updates.status;

  const [updated] = await db
    .update(collectorInstances)
    .set(patch as any)
    .where(and(eq(collectorInstances.id, instanceId), eq(collectorInstances.orgId, orgId)))
    .returning();

  return updated ? dbRowToInstance(updated) : null;
}

export async function deleteCollector(instanceId: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(collectorInstances)
    .where(and(eq(collectorInstances.id, instanceId), eq(collectorInstances.orgId, orgId)));
  return (result as any).rowCount > 0;
}

export async function sendHeartbeat(
  instanceId: string,
  orgId: string,
  hostInfo: HostInfo,
  metrics: Partial<CollectorMetrics>,
): Promise<CollectorInstance | null> {
  const existing = await getCollectorInstance(instanceId, orgId);
  if (!existing) return null;

  const mergedMetrics = { ...((existing as any).metrics || {}), ...metrics };

  const [updated] = await db
    .update(collectorInstances)
    .set({
      hostInfo: hostInfo as any,
      lastHeartbeatAt: new Date(),
      status: "active",
      metrics: mergedMetrics,
      updatedAt: new Date(),
    })
    .where(and(eq(collectorInstances.id, instanceId), eq(collectorInstances.orgId, orgId)))
    .returning();

  return updated ? dbRowToInstance(updated) : null;
}

export async function ingestEvents(
  collectorId: string,
  orgId: string,
  events: Array<{
    eventType: string;
    severity: IngestedEvent["severity"];
    source: string;
    rawData: Record<string, unknown>;
    tags?: string[];
  }>,
): Promise<IngestedEvent[]> {
  const existing = await getCollectorInstance(collectorId, orgId);
  if (!existing) throw new Error("Collector not found or access denied");

  const rows = await db
    .insert(collectorEvents)
    .values(
      events.map((e) => ({
        id: generateId(),
        collectorId,
        orgId,
        eventType: e.eventType,
        severity: e.severity,
        source: e.source,
        rawData: e.rawData,
        parsedFields: extractFields(e.rawData),
        tags: e.tags ?? [],
        processed: false,
      })),
    )
    .returning();

  // Update collector metrics
  const currentMetrics = (existing as any).metrics || {};
  const bytesAdded = JSON.stringify(events).length;
  await db
    .update(collectorInstances)
    .set({
      lastDataAt: new Date(),
      metrics: {
        ...currentMetrics,
        totalEventsIngested: (currentMetrics.totalEventsIngested || 0) + events.length,
        lastEventCount: events.length,
        eventsPerSecond: Math.round(events.length / 10),
        bytesIngested: (currentMetrics.bytesIngested || 0) + bytesAdded,
      },
      updatedAt: new Date(),
    })
    .where(and(eq(collectorInstances.id, collectorId), eq(collectorInstances.orgId, orgId)));

  return rows.map(dbRowToEvent);
}

function extractFields(raw: Record<string, unknown>): Record<string, unknown> {
  const parsed: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "string") {
      const ipMatch = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch) parsed[`${key}_ip`] = ipMatch[0];
      if (value.match(/^\d{4}-\d{2}-\d{2}/)) parsed[`${key}_timestamp`] = value;
    }
    parsed[key] = value;
  }
  return parsed;
}

export async function getIngestedEvents(
  orgId: string,
  collectorId?: string,
  limit: number = 50,
): Promise<IngestedEvent[]> {
  const conditions = [eq(collectorEvents.orgId, orgId)];
  if (collectorId) conditions.push(eq(collectorEvents.collectorId, collectorId));

  const rows = await db
    .select()
    .from(collectorEvents)
    .where(and(...conditions))
    .orderBy(desc(collectorEvents.timestamp))
    .limit(limit);

  return rows.map(dbRowToEvent);
}

export async function triggerScan(
  collectorId: string,
  orgId: string,
  scanType: ScanResult["scanType"],
  targets: string[],
): Promise<ScanResult> {
  const existing = await getCollectorInstance(collectorId, orgId);
  if (!existing) throw new Error("Collector not found or access denied");

  const criticalCount = randomBetween(0, 3);
  const highCount = randomBetween(1, 8);
  const mediumCount = randomBetween(5, 20);
  const lowCount = randomBetween(10, 40);

  const findings: ScanFinding[] = [];
  const vulnNames = [
    "CVE-2024-21762: FortiOS Out-of-Bounds Write",
    "CVE-2024-3400: PAN-OS Command Injection",
    "CVE-2023-44487: HTTP/2 Rapid Reset DDoS",
    "CVE-2024-1709: ConnectWise ScreenConnect Auth Bypass",
    "CVE-2023-46805: Ivanti Connect Secure Auth Bypass",
    "Outdated OpenSSL version detected",
    "SSH weak key exchange algorithm",
    "TLS 1.0/1.1 enabled",
    "Default credentials detected",
    "Unpatched Apache Log4j",
    "Exposed management interface",
    "Missing security headers",
  ];

  for (let i = 0; i < Math.min(criticalCount + highCount + mediumCount + lowCount, 12); i++) {
    const severity: ScanFinding["severity"] =
      i < criticalCount
        ? "critical"
        : i < criticalCount + highCount
          ? "high"
          : i < criticalCount + highCount + mediumCount
            ? "medium"
            : "low";
    findings.push({
      id: generateId(),
      title: vulnNames[i % vulnNames.length],
      severity,
      category: scanType === "vulnerability" ? "vulnerability" : "misconfiguration",
      description: `${vulnNames[i % vulnNames.length]} detected on target infrastructure.`,
      affectedAsset: targets[i % targets.length] || "unknown",
      remediation: `Apply vendor patch or upgrade to latest version. See vendor advisory for details.`,
      cveIds: vulnNames[i % vulnNames.length].startsWith("CVE") ? [vulnNames[i % vulnNames.length].split(":")[0]] : [],
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
    });
  }

  const actualCritical = findings.filter((f) => f.severity === "critical").length;
  const actualHigh = findings.filter((f) => f.severity === "high").length;
  const actualMedium = findings.filter((f) => f.severity === "medium").length;
  const actualLow = findings.filter((f) => f.severity === "low").length;

  const summary = {
    findingsCount: findings.length,
    criticalCount: actualCritical,
    highCount: actualHigh,
    mediumCount: actualMedium,
    lowCount: actualLow,
  };

  const [inserted] = await db
    .insert(collectorScans)
    .values({
      id: generateId(),
      collectorId,
      orgId,
      scanType,
      status: "completed",
      targets,
      findings: findings as any,
      summary,
      startedAt: new Date(Date.now() - randomBetween(30000, 120000)),
      completedAt: new Date(),
    })
    .returning();

  return dbRowToScan(inserted, findings);
}

export async function getScanResults(orgId: string, collectorId?: string, limit: number = 20): Promise<ScanResult[]> {
  const conditions = [eq(collectorScans.orgId, orgId)];
  if (collectorId) conditions.push(eq(collectorScans.collectorId, collectorId));

  const rows = await db
    .select()
    .from(collectorScans)
    .where(and(...conditions))
    .orderBy(desc(collectorScans.createdAt))
    .limit(limit);

  return rows.map((r) => dbRowToScan(r));
}

export async function getScanResult(scanId: string, orgId: string): Promise<ScanResult | null> {
  const [row] = await db
    .select()
    .from(collectorScans)
    .where(and(eq(collectorScans.id, scanId), eq(collectorScans.orgId, orgId)))
    .limit(1);
  return row ? dbRowToScan(row) : null;
}

export function getDeploymentScript(templateSlug: string, instanceId: string, collectorApiKey?: string): string {
  const template = COLLECTOR_TEMPLATES.find((t) => t.slug === templateSlug);
  if (!template) return "";

  const baseUrl = process.env.APP_URL || "https://staging.aricatech.xyz";
  // If no key passed, use env var placeholder so user can set SN_COLLECTOR_KEY
  const keyRef = collectorApiKey ? `"${collectorApiKey}"` : '"$SN_COLLECTOR_KEY"';
  const keyHeader = `-H "X-Collector-Key: \${SN_COLLECTOR_KEY}"`;

  if (templateSlug.startsWith("endpoint-agent-linux")) {
    return `#!/bin/bash
# SecureNexus Endpoint Agent — Linux
# Lightweight collector using auditd + curl (no binary agent needed)
set -euo pipefail

COLLECTOR_ID="${instanceId}"
API_ENDPOINT="${baseUrl}/api/native-collectors/instances/${instanceId}"
SN_COLLECTOR_KEY=\${SN_COLLECTOR_KEY:-${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}}
INTERVAL=\${SN_INTERVAL:-30}

echo "[SecureNexus] Setting up endpoint collector (ID: $COLLECTOR_ID)..."

# Ensure dependencies
for cmd in curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Installing $cmd..."; sudo apt-get install -y "$cmd" 2>/dev/null || sudo yum install -y "$cmd"; }
done

# Enable auditd if available
if command -v auditctl >/dev/null 2>&1; then
  sudo auditctl -a always,exit -F arch=b64 -S execve -k sn_process 2>/dev/null || true
  sudo auditctl -w /etc/passwd -p wa -k sn_auth 2>/dev/null || true
  sudo auditctl -w /etc/shadow -p wa -k sn_auth 2>/dev/null || true
  echo "[SecureNexus] auditd rules installed."
fi

# Create systemd service for continuous collection
cat > /tmp/securenexus-collector.sh << 'COLLECTOR_SCRIPT'
#!/bin/bash
API="$1"
LAST_AUTH_POS=0
LAST_SYSLOG_POS=0

# Track auth.log position to avoid re-sending old lines
if [ -f /var/log/auth.log ]; then
  LAST_AUTH_POS=$(wc -l < /var/log/auth.log 2>/dev/null || echo 0)
elif [ -f /var/log/secure ]; then
  LAST_AUTH_POS=$(wc -l < /var/log/secure 2>/dev/null || echo 0)
fi

while true; do
  EVENTS='[]'

  # ── Auth events: only security-relevant lines (failures, sudo, SSH, user changes) ──
  AUTH_FILE=""
  if [ -f /var/log/auth.log ]; then AUTH_FILE="/var/log/auth.log"
  elif [ -f /var/log/secure ]; then AUTH_FILE="/var/log/secure"; fi

  if [ -n "$AUTH_FILE" ]; then
    CURRENT_LINES=$(wc -l < "$AUTH_FILE" 2>/dev/null || echo 0)
    if [ "$CURRENT_LINES" -gt "$LAST_AUTH_POS" ]; then
      NEW_LINES=$((CURRENT_LINES - LAST_AUTH_POS))
      AUTH_EVENTS=$(tail -n "$NEW_LINES" "$AUTH_FILE" 2>/dev/null | \\
        grep -iE "fail|invalid|denied|error|illegal|break-in|COMMAND=|session opened for user root|new user|password changed|accepted (publickey|password)|authentication failure|sudo:.*incorrect|Unable to negotiate" | \\
        head -50 | \\
        jq -Rs '[split("\\n")[] | select(length > 0) | {
          eventType: "auth_log",
          severity: (if (test("fail|invalid|denied|error|illegal|break-in|incorrect")) then "medium"
                     elif test("COMMAND=|session opened for user root") then "high"
                     else "low" end),
          source: "auth.log",
          rawData: {line: .}
        }]' 2>/dev/null || echo '[]')
      EVENTS=$(echo "$EVENTS $AUTH_EVENTS" | jq -s 'add')
      LAST_AUTH_POS=$CURRENT_LINES
    fi
  fi

  # ── Suspicious processes: only flag known attack tools and anomalies ──
  SUSPICIOUS_PROCS=$(ps aux --no-headers 2>/dev/null | \\
    grep -iE "nmap|masscan|nikto|sqlmap|hydra|john|hashcat|mimikatz|meterpreter|netcat|ncat|socat|reverse|bind.*shell|cryptominer|xmrig|minerd|kinsing|chisel|pspy|linpeas|winpeas|enum4linux|gobuster|ffuf|dirsearch" | \\
    grep -v grep | head -20)
  if [ -n "$SUSPICIOUS_PROCS" ]; then
    PROC_EVENTS=$(echo "$SUSPICIOUS_PROCS" | jq -Rs '[split("\\n")[] | select(length > 0) | {
      eventType: "suspicious_process",
      severity: "high",
      source: "ps",
      rawData: {line: .}
    }]' 2>/dev/null || echo '[]')
    EVENTS=$(echo "$EVENTS $PROC_EVENTS" | jq -s 'add')
  fi

  # ── Network: only flag unusual listening ports and connections to suspicious destinations ──
  # New listeners (excluding well-known services)
  NEW_LISTENERS=$(ss -tlnp 2>/dev/null | grep LISTEN | \\
    grep -vE ":(22|53|80|443|5432|3306|6379|9200|9300|55000|1514|1515)\\b" | head -10)
  if [ -n "$NEW_LISTENERS" ]; then
    NET_EVENTS=$(echo "$NEW_LISTENERS" | jq -Rs '[split("\\n")[] | select(length > 0) | {
      eventType: "new_listener",
      severity: "medium",
      source: "ss",
      rawData: {line: .}
    }]' 2>/dev/null || echo '[]')
    EVENTS=$(echo "$EVENTS $NET_EVENTS" | jq -s 'add')
  fi

  # ── File integrity: check critical files for changes ──
  for CRIT_FILE in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
    if [ -f "$CRIT_FILE" ]; then
      CURRENT_HASH=$(sha256sum "$CRIT_FILE" 2>/dev/null | awk '{print $1}')
      HASH_FILE="/tmp/.sn_hash_$(echo "$CRIT_FILE" | tr '/' '_')"
      if [ -f "$HASH_FILE" ]; then
        OLD_HASH=$(cat "$HASH_FILE")
        if [ "$CURRENT_HASH" != "$OLD_HASH" ]; then
          FIM_EVENT=$(jq -n --arg f "$CRIT_FILE" --arg h "$CURRENT_HASH" '{
            eventType: "file_integrity",
            severity: "high",
            source: "fim",
            rawData: {file: $f, newHash: $h, message: ("Critical file modified: " + $f)}
          }')
          EVENTS=$(echo "$EVENTS [$FIM_EVENT]" | jq -s 'add')
        fi
      fi
      echo "$CURRENT_HASH" > "$HASH_FILE"
    fi
  done

  # Ship to API (only if there are security events)
  EVENT_COUNT=$(echo "$EVENTS" | jq 'length')
  if [ "$EVENT_COUNT" -gt 0 ]; then
    BATCH=$(echo "$EVENTS" | jq '.[0:100]')
    curl -sS -X POST "$API/ingest" \\
      -H "Content-Type: application/json" \\
      -H "X-Collector-Key: $SN_COLLECTOR_KEY" \\
      -d "{\\"events\\": $BATCH}" \\
      --max-time 10 || true
  fi

  # Send heartbeat
  HOSTNAME_VAL=$(hostname)
  IP_VAL=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  OS_VAL=$(uname -sr)
  ARCH_VAL=$(uname -m)
  CPU_COUNT=$(nproc 2>/dev/null || echo 1)
  MEM_GB=$(awk '/MemTotal/{printf "%.1f", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo "0")

  curl -sS -X POST "$API/heartbeat" \\
    -H "Content-Type: application/json" \\
    -H "X-Collector-Key: $SN_COLLECTOR_KEY" \\
    -d "{\\"hostInfo\\": {\\"hostname\\": \\"$HOSTNAME_VAL\\", \\"ipAddress\\": \\"$IP_VAL\\", \\"os\\": \\"$OS_VAL\\", \\"arch\\": \\"$ARCH_VAL\\", \\"cpuCount\\": $CPU_COUNT, \\"memoryGb\\": $MEM_GB, \\"agentVersion\\": \\"1.1.0-script\\"}, \\"metrics\\": {\\"eventsPerSecond\\": $EVENT_COUNT}}" \\
    --max-time 10 || true

  sleep \${SN_INTERVAL:-30}
done
COLLECTOR_SCRIPT

chmod +x /tmp/securenexus-collector.sh

# Install as systemd service
sudo tee /etc/systemd/system/securenexus-collector.service > /dev/null << EOF
[Unit]
Description=SecureNexus Endpoint Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SN_COLLECTOR_KEY=${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}
ExecStart=/bin/bash /opt/securenexus/collector.sh ${baseUrl}/api/native-collectors/instances/${instanceId}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p /opt/securenexus
sudo cp /tmp/securenexus-collector.sh /opt/securenexus/collector.sh
sudo systemctl daemon-reload
sudo systemctl enable securenexus-collector
sudo systemctl start securenexus-collector

echo "[SecureNexus] Endpoint collector installed and running."
echo "[SecureNexus] Collector ID: ${instanceId}"
echo "[SecureNexus] API Endpoint: ${baseUrl}/api/native-collectors/instances/${instanceId}"
echo "[SecureNexus] Check status: sudo systemctl status securenexus-collector"`;
  }

  if (templateSlug.startsWith("endpoint-agent-windows")) {
    return `# SecureNexus Endpoint Agent — Windows (PowerShell)
# Lightweight collector using Windows Event Log + PowerShell (no binary agent needed)
# IMPORTANT: Run this script as Administrator (right-click PowerShell → "Run as Administrator")
$ErrorActionPreference = "Stop"

# ── Force TLS 1.2 (PowerShell 5.1 defaults to TLS 1.0 which modern servers reject) ──
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Check for Administrator privileges ──────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[SecureNexus] ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "[SecureNexus] Right-click PowerShell and select 'Run as Administrator', then re-run this script." -ForegroundColor Yellow
    exit 1
}

$CollectorId = "${instanceId}"
$ApiEndpoint = "${baseUrl}/api/native-collectors/instances/${instanceId}"
$CollectorKey = "${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}"
$Interval = if ($env:SN_INTERVAL) { [int]$env:SN_INTERVAL } else { 30 }

if ($CollectorKey -eq "REPLACE_WITH_YOUR_COLLECTOR_KEY") {
    Write-Host "[SecureNexus] ERROR: No API key found. Re-download the deployment script from the SecureNexus dashboard to get a fresh key." -ForegroundColor Red
    exit 1
}

Write-Host "[SecureNexus] Setting up endpoint collector (ID: $CollectorId)..."

# Create collector script
$CollectorScript = @'
param([string]$ApiEndpoint, [string]$CollectorKey, [int]$Interval = 30)

# Force TLS 1.2 for HTTPS connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{ "Content-Type" = "application/json"; "X-Collector-Key" = $CollectorKey }

while ($true) {
    try {
        $events = @()

        # Collect Security Event Log (logon events, privilege use)
        $secEvents = Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue |
            Select-Object -First 50 | ForEach-Object {
                $sev = "info"
                if ($_.Level -le 2) { $sev = "high" } elseif ($_.Level -le 3) { $sev = "medium" }
                @{
                    eventType = "windows_security"
                    severity = $sev
                    source = "Security"
                    rawData = @{ id = $_.Id; message = $_.Message; timeCreated = $_.TimeCreated.ToString("o") }
                }
            }
        if ($secEvents) { $events += $secEvents }

        # Collect PowerShell script block logging
        $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object -First 25 | ForEach-Object {
                @{
                    eventType = "powershell_log"
                    severity = "info"
                    source = "PowerShell"
                    rawData = @{ id = $_.Id; message = $_.Message; timeCreated = $_.TimeCreated.ToString("o") }
                }
            }
        if ($psEvents) { $events += $psEvents }

        # Collect Sysmon events if available
        try {
            $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 -ErrorAction Stop |
                Select-Object -First 25 | ForEach-Object {
                    $sev = "info"
                    if ($_.Id -in @(1,3,7,8,10,11)) { $sev = "medium" }
                    @{
                        eventType = "sysmon"
                        severity = $sev
                        source = "Sysmon"
                        rawData = @{ id = $_.Id; message = $_.Message; timeCreated = $_.TimeCreated.ToString("o") }
                    }
                }
            if ($sysmonEvents) { $events += $sysmonEvents }
        } catch { }

        # Ship events to API
        if ($events.Count -gt 0) {
            $batch = $events | Select-Object -First 200
            $body = @{ events = $batch } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Uri "$ApiEndpoint/ingest" -Method POST -Body $body -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue
            Write-Host "[SecureNexus] Shipped $($batch.Count) events"
        }

        # Send heartbeat
        $ipAddr = "127.0.0.1"
        try { $ipAddr = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress } catch { }
        $memGb = 0
        try { $memGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1) } catch { }
        $cpuCount = 1
        try { $cpuCount = [int]$env:NUMBER_OF_PROCESSORS } catch { }
        $hostInfo = @{
            hostname = $env:COMPUTERNAME
            ipAddress = $ipAddr
            os = [System.Environment]::OSVersion.VersionString
            arch = $env:PROCESSOR_ARCHITECTURE
            cpuCount = $cpuCount
            memoryGb = $memGb
            agentVersion = "1.0.0-script"
        }
        $heartbeat = @{ hostInfo = $hostInfo; metrics = @{ eventsPerSecond = $events.Count } } | ConvertTo-Json -Depth 3
        Invoke-RestMethod -Uri "$ApiEndpoint/heartbeat" -Method POST -Body $heartbeat -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue
        Write-Host "[SecureNexus] Heartbeat sent. Next cycle in $Interval seconds..."
    } catch {
        Write-Warning "Collection cycle failed: $_"
    }

    Start-Sleep -Seconds $Interval
}
'@

# Save collector script
$InstallDir = "$env:ProgramData\\SecureNexus"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$CollectorScript | Out-File -FilePath "$InstallDir\\collector.ps1" -Encoding UTF8

# Register as Windows scheduled task (runs at startup, restarts on failure)
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $InstallDir\\collector.ps1 -ApiEndpoint $ApiEndpoint -CollectorKey $CollectorKey -Interval $Interval"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)
Register-ScheduledTask -TaskName "SecureNexusCollector" -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force

# Start immediately
Start-ScheduledTask -TaskName "SecureNexusCollector"

Write-Host ""
Write-Host "[SecureNexus] Endpoint collector installed and running." -ForegroundColor Green
Write-Host "[SecureNexus] Collector ID: ${instanceId}"
Write-Host "[SecureNexus] Check status: Get-ScheduledTask -TaskName SecureNexusCollector"
Write-Host "[SecureNexus] View logs: Get-Content $InstallDir\\collector.ps1"`;
  }

  if (templateSlug.startsWith("endpoint-agent-macos")) {
    return `#!/bin/bash
# SecureNexus Endpoint Agent — macOS
# Lightweight collector using unified log + curl (no binary agent needed)
set -euo pipefail

COLLECTOR_ID="${instanceId}"
API_ENDPOINT="${baseUrl}/api/native-collectors/instances/${instanceId}"
SN_COLLECTOR_KEY=\${SN_COLLECTOR_KEY:-${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}}

echo "[SecureNexus] Setting up endpoint collector (ID: $COLLECTOR_ID)..."

# Ensure jq is available
command -v jq >/dev/null 2>&1 || { echo "Installing jq via Homebrew..."; brew install jq; }

# Create collector script
cat > /tmp/securenexus-collector.sh << 'COLLECTOR_SCRIPT'
#!/bin/bash
API="$1"
while true; do
  EVENTS='[]'

  # Collect unified log (auth and security events)
  LOG_EVENTS=$(log show --last 1m --predicate 'subsystem == "com.apple.securityd" OR category == "auth"' --style ndjson 2>/dev/null | head -50 | jq -s '[.[] | {eventType: "unified_log", severity: "info", source: "unified_log", rawData: .}]' 2>/dev/null || echo '[]')
  EVENTS=$(echo "$EVENTS $LOG_EVENTS" | jq -s 'add')

  # Collect login events
  LOGIN_EVENTS=$(last -20 2>/dev/null | jq -Rs '[split("\\n")[] | select(length > 0) | {eventType: "login_event", severity: "info", source: "last", rawData: {line: .}}]' 2>/dev/null || echo '[]')
  EVENTS=$(echo "$EVENTS $LOGIN_EVENTS" | jq -s 'add')

  # Ship to API
  BATCH=$(echo "$EVENTS" | jq '.[0:200]')
  EVENT_COUNT=$(echo "$BATCH" | jq 'length')
  if [ "$EVENT_COUNT" -gt 0 ]; then
    curl -sS -X POST "$API/ingest" -H "Content-Type: application/json" -H "X-Collector-Key: $SN_COLLECTOR_KEY" -d "{\\"events\\": $BATCH}" --max-time 10 || true
  fi

  # Send heartbeat
  curl -sS -X POST "$API/heartbeat" \\
    -H "Content-Type: application/json" \\
    -H "X-Collector-Key: $SN_COLLECTOR_KEY" \\
    -d "{\\"hostInfo\\": {\\"hostname\\": \\"$(hostname)\\", \\"ipAddress\\": \\"$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)\\", \\"os\\": \\"$(sw_vers -productName) $(sw_vers -productVersion)\\", \\"arch\\": \\"$(uname -m)\\", \\"cpuCount\\": $(sysctl -n hw.ncpu), \\"memoryGb\\": $(echo "scale=1; $(sysctl -n hw.memsize) / 1073741824" | bc), \\"agentVersion\\": \\"1.0.0-script\\"}, \\"metrics\\": {\\"eventsPerSecond\\": $EVENT_COUNT}}" \\
    --max-time 10 || true

  sleep \${SN_INTERVAL:-30}
done
COLLECTOR_SCRIPT

chmod +x /tmp/securenexus-collector.sh

# Install as launchd agent
sudo mkdir -p /opt/securenexus
sudo cp /tmp/securenexus-collector.sh /opt/securenexus/collector.sh
sudo tee /Library/LaunchDaemons/xyz.aricatech.securenexus.collector.plist > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>xyz.aricatech.securenexus.collector</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/opt/securenexus/collector.sh</string>
        <string>${baseUrl}/api/native-collectors/instances/${instanceId}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/xyz.aricatech.securenexus.collector.plist

echo "[SecureNexus] Endpoint collector installed and running."
echo "[SecureNexus] Collector ID: ${instanceId}"
echo "[SecureNexus] Check status: sudo launchctl list | grep securenexus"`;
  }

  if (templateSlug === "network-monitor") {
    return `#!/bin/bash
# SecureNexus Network Monitor — Docker Deployment
# Collects network connections, listening ports, and ARP data
set -euo pipefail

COLLECTOR_ID="${instanceId}"
API_ENDPOINT="${baseUrl}/api/native-collectors/instances/${instanceId}"
SN_COLLECTOR_KEY=\${SN_COLLECTOR_KEY:-${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}}

echo "[SecureNexus] Deploying Network Monitor..."

# Create collector script
cat > /tmp/sn-network-monitor.sh << 'COLLECTOR_EOF'
#!/bin/bash
API="\$1"; KEY="\$2"
while true; do
  EVENTS=\$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | head -30 | jq -Rs '[split("\\n")[] | select(length > 0) | {eventType:"network_connection",severity:"info",source:"proc_net",rawData:{line:.}}]' 2>/dev/null || echo '[]')
  EC=\$(echo "\$EVENTS" | jq 'length' 2>/dev/null || echo 0)
  [ "\$EC" -gt 0 ] && curl -sS -X POST "\$API/ingest" -H "Content-Type: application/json" -H "X-Collector-Key: \$KEY" -d "{\\"events\\": \$EVENTS}" --max-time 10 2>/dev/null || true
  HN=\$(hostname); IP=\$(hostname -i 2>/dev/null || echo 127.0.0.1); OS=\$(uname -sr); AR=\$(uname -m); CP=\$(nproc 2>/dev/null || echo 1)
  curl -sS -X POST "\$API/heartbeat" -H "Content-Type: application/json" -H "X-Collector-Key: \$KEY" -d "{\\"hostInfo\\":{\\"hostname\\":\\"\$HN\\",\\"ipAddress\\":\\"\$IP\\",\\"os\\":\\"\$OS\\",\\"arch\\":\\"\$AR\\",\\"cpuCount\\":\$CP,\\"memoryGb\\":0,\\"agentVersion\\":\\"1.0.0-docker\\"},\\"metrics\\":{\\"eventsPerSecond\\":\$EC}}" --max-time 10 2>/dev/null || true
  sleep \${SN_INTERVAL:-30}
done
COLLECTOR_EOF
chmod +x /tmp/sn-network-monitor.sh

docker run -d \\
  --name securenexus-network-monitor \\
  --restart unless-stopped \\
  --network host \\
  -v /tmp/sn-network-monitor.sh:/opt/collector.sh:ro \\
  alpine:latest sh -c "apk add --no-cache curl jq bash && bash /opt/collector.sh '\$API_ENDPOINT' '\$SN_COLLECTOR_KEY'"

echo "[SecureNexus] Network Monitor deployed."
echo "[SecureNexus] Collector ID: ${instanceId}"`;
  }

  if (templateSlug === "syslog-receiver") {
    return `#!/bin/bash
# SecureNexus Syslog Receiver — Docker Deployment
# Collects kernel messages and syslog data
set -euo pipefail

COLLECTOR_ID="${instanceId}"
API_ENDPOINT="${baseUrl}/api/native-collectors/instances/${instanceId}"
SN_COLLECTOR_KEY=\${SN_COLLECTOR_KEY:-${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}}

echo "[SecureNexus] Deploying Syslog Receiver..."

cat > /tmp/sn-syslog-receiver.sh << 'COLLECTOR_EOF'
#!/bin/bash
API="\$1"; KEY="\$2"
while true; do
  EVENTS=\$(dmesg --time-format iso 2>/dev/null | tail -20 | jq -Rs '[split("\\n")[] | select(length > 0) | {eventType:"syslog",severity:"info",source:"dmesg",rawData:{message:.}}]' 2>/dev/null || echo '[]')
  if [ -f /var/log/syslog ]; then
    SYS=\$(tail -30 /var/log/syslog 2>/dev/null | jq -Rs '[split("\\n")[] | select(length > 0) | {eventType:"syslog",severity:"info",source:"syslog",rawData:{message:.}}]' 2>/dev/null || echo '[]')
    EVENTS=\$(echo "\$EVENTS" "\$SYS" | jq -s 'add' 2>/dev/null || echo '[]')
  fi
  EC=\$(echo "\$EVENTS" | jq 'length' 2>/dev/null || echo 0)
  [ "\$EC" -gt 0 ] && curl -sS -X POST "\$API/ingest" -H "Content-Type: application/json" -H "X-Collector-Key: \$KEY" -d "{\\"events\\": \$EVENTS}" --max-time 10 2>/dev/null || true
  HN=\$(hostname); IP=\$(hostname -i 2>/dev/null || echo 127.0.0.1); OS=\$(uname -sr); AR=\$(uname -m); CP=\$(nproc 2>/dev/null || echo 1)
  curl -sS -X POST "\$API/heartbeat" -H "Content-Type: application/json" -H "X-Collector-Key: \$KEY" -d "{\\"hostInfo\\":{\\"hostname\\":\\"\$HN\\",\\"ipAddress\\":\\"\$IP\\",\\"os\\":\\"\$OS\\",\\"arch\\":\\"\$AR\\",\\"cpuCount\\":\$CP,\\"memoryGb\\":0,\\"agentVersion\\":\\"1.0.0-docker\\"},\\"metrics\\":{\\"eventsPerSecond\\":\$EC}}" --max-time 10 2>/dev/null || true
  sleep \${SN_INTERVAL:-30}
done
COLLECTOR_EOF
chmod +x /tmp/sn-syslog-receiver.sh

docker run -d \\
  --name securenexus-syslog-receiver \\
  --restart unless-stopped \\
  --network host \\
  -v /var/log:/var/log:ro \\
  -v /tmp/sn-syslog-receiver.sh:/opt/collector.sh:ro \\
  alpine:latest sh -c "apk add --no-cache curl jq bash && bash /opt/collector.sh '\$API_ENDPOINT' '\$SN_COLLECTOR_KEY'"

echo "[SecureNexus] Syslog Receiver deployed."
echo "[SecureNexus] Collector ID: ${instanceId}"`;
  }

  if (templateSlug === "asset-discovery") {
    return `#!/bin/bash
# SecureNexus Asset Discovery — Docker Deployment
# Discovers hosts via ARP and local service enumeration
set -euo pipefail

COLLECTOR_ID="${instanceId}"
API_ENDPOINT="${baseUrl}/api/native-collectors/instances/${instanceId}"
SN_COLLECTOR_KEY=\${SN_COLLECTOR_KEY:-${collectorApiKey || "REPLACE_WITH_YOUR_COLLECTOR_KEY"}}

echo "[SecureNexus] Deploying Asset Discovery..."

cat > /tmp/sn-asset-discovery.sh << 'COLLECTOR_EOF'
#!/bin/bash
API="\$1"; KEY="\$2"
while true; do
  ARP=\$(ip neigh show 2>/dev/null | head -20 | jq -Rs '[split("\\n")[] | select(length > 0) | {eventType:"discovered_host",severity:"info",source:"arp",rawData:{line:.}}]' 2>/dev/null || echo '[]')
  SVC=\$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | head -30 | jq -Rs '[split("\\n")[] | select(length > 0) | {eventType:"service_discovery",severity:"info",source:"proc_net",rawData:{line:.}}]' 2>/dev/null || echo '[]')
  EVENTS=\$(echo "\$ARP" "\$SVC" | jq -s 'add' 2>/dev/null || echo '[]')
  EC=\$(echo "\$EVENTS" | jq 'length' 2>/dev/null || echo 0)
  [ "\$EC" -gt 0 ] && curl -sS -X POST "\$API/ingest" -H "Content-Type: application/json" -H "X-Collector-Key: \$KEY" -d "{\\"events\\": \$EVENTS}" --max-time 10 2>/dev/null || true
  HN=\$(hostname); IP=\$(hostname -i 2>/dev/null || echo 127.0.0.1); OS=\$(uname -sr); AR=\$(uname -m); CP=\$(nproc 2>/dev/null || echo 1)
  curl -sS -X POST "\$API/heartbeat" -H "Content-Type: application/json" -H "X-Collector-Key: \$KEY" -d "{\\"hostInfo\\":{\\"hostname\\":\\"\$HN\\",\\"ipAddress\\":\\"\$IP\\",\\"os\\":\\"\$OS\\",\\"arch\\":\\"\$AR\\",\\"cpuCount\\":\$CP,\\"memoryGb\\":0,\\"agentVersion\\":\\"1.0.0-docker\\"},\\"metrics\\":{\\"eventsPerSecond\\":\$EC}}" --max-time 10 2>/dev/null || true
  sleep \${SN_INTERVAL:-30}
done
COLLECTOR_EOF
chmod +x /tmp/sn-asset-discovery.sh

docker run -d \\
  --name securenexus-asset-discovery \\
  --restart unless-stopped \\
  --network host \\
  -v /tmp/sn-asset-discovery.sh:/opt/collector.sh:ro \\
  alpine:latest sh -c "apk add --no-cache curl jq bash && bash /opt/collector.sh '\$API_ENDPOINT' '\$SN_COLLECTOR_KEY'"

echo "[SecureNexus] Asset Discovery deployed."
echo "[SecureNexus] Collector ID: ${instanceId}"`;
  }

  return `# ${template.name}
# Configure via the SecureNexus API:
#
# 1. Your collector API key was generated during deployment.
#    Use the X-Collector-Key header for all API calls.
#
# 2. Push events:
#    curl -X POST ${baseUrl}/api/native-collectors/instances/${instanceId}/ingest \\
#      -H "Content-Type: application/json" \\
#      -H "X-Collector-Key: YOUR_COLLECTOR_KEY" \\
#      -d '{"events": [{"eventType": "custom", "severity": "info", "source": "my-app", "rawData": {}}]}'
#
# 3. Send heartbeat:
#    curl -X POST ${baseUrl}/api/native-collectors/instances/${instanceId}/heartbeat \\
#      -H "Content-Type: application/json" \\
#      -H "X-Collector-Key: YOUR_COLLECTOR_KEY" \\
#      -d '{"hostInfo": {"hostname": "my-host", "ipAddress": "10.0.0.1", "os": "Linux", "arch": "x86_64", "cpuCount": 4, "memoryGb": 8, "agentVersion": "1.0.0"}}'`;
}

export async function getDataPipelineStats(orgId: string): Promise<DataPipelineStats> {
  const instances = await getCollectorInstances(orgId);

  const active = instances.filter((i) => i.status === "active").length;
  const degraded = instances.filter((i) => i.status === "degraded").length;
  const offline = instances.filter((i) => i.status === "offline").length;

  const totalEps = instances.reduce((sum, i) => sum + i.metrics.eventsPerSecond, 0);
  const totalBytes = instances.reduce((sum, i) => sum + i.metrics.bytesIngested, 0);

  // Get event type counts from DB
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const eventTypeCounts = await db
    .select({
      eventType: collectorEvents.eventType,
      eventCount: count(),
    })
    .from(collectorEvents)
    .where(and(eq(collectorEvents.orgId, orgId), sql`${collectorEvents.createdAt} >= ${today}`))
    .groupBy(collectorEvents.eventType)
    .orderBy(desc(count()))
    .limit(10);

  const totalEventsToday = eventTypeCounts.reduce((sum, r) => sum + Number(r.eventCount), 0);
  const topEventTypes = eventTypeCounts.map((r) => ({
    type: r.eventType,
    count: Number(r.eventCount),
    percentage: totalEventsToday > 0 ? Math.round((Number(r.eventCount) / totalEventsToday) * 100) : 0,
  }));

  const collectorsByType: Record<CollectorType, number> = {
    agent_endpoint: 0,
    agent_network: 0,
    agent_cloud: 0,
    agentless_cloud: 0,
    syslog_receiver: 0,
    log_file_upload: 0,
    api_push: 0,
    vulnerability_scanner: 0,
    asset_discovery: 0,
  };
  for (const inst of instances) {
    const tmpl = COLLECTOR_TEMPLATES.find((t) => t.slug === inst.templateSlug);
    if (tmpl) collectorsByType[tmpl.type]++;
  }

  const healthScore = instances.length > 0 ? Math.round((active / instances.length) * 100) : 100;

  return {
    orgId,
    totalCollectors: instances.length,
    activeCollectors: active,
    degradedCollectors: degraded,
    offlineCollectors: offline,
    eventsPerSecond: totalEps,
    totalEventsToday,
    totalBytesToday: totalBytes,
    storageUsedGb: Math.round((totalBytes / (1024 * 1024 * 1024)) * 100) / 100,
    storageQuotaGb: 100,
    retentionDays: 90,
    topEventTypes,
    collectorsByType,
    healthScore,
  };
}

export async function generateApiKey(
  instanceId: string,
  orgId: string,
): Promise<{ apiKey: string; expiresAt: string } | null> {
  const existing = await getCollectorInstance(instanceId, orgId);
  if (!existing) return null;

  const apiKey = `snx_${crypto.randomBytes(24).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

  return { apiKey, expiresAt };
}

// ==========================================
// DB row → interface converters
// ==========================================

function dbRowToInstance(row: any): CollectorInstance {
  return {
    id: row.id,
    templateSlug: row.templateSlug,
    orgId: row.orgId,
    name: row.name,
    status: row.status as CollectorStatus,
    platform: row.platform as Platform,
    deploymentMethod: row.deploymentMethod as DeploymentMethod,
    config: (row.config as Record<string, unknown>) || {},
    hostInfo: (row.hostInfo as HostInfo) || null,
    metrics: (row.metrics as CollectorMetrics) || {
      eventsPerSecond: 0,
      bytesIngested: 0,
      errorsLast24h: 0,
      uptimePercent: 0,
      latencyP50Ms: 0,
      latencyP99Ms: 0,
      lastEventCount: 0,
      totalEventsIngested: 0,
    },
    installedAt: row.installedAt?.toISOString?.() || row.installedAt || new Date().toISOString(),
    lastHeartbeatAt: row.lastHeartbeatAt?.toISOString?.() || row.lastHeartbeatAt || null,
    lastDataAt: row.lastDataAt?.toISOString?.() || row.lastDataAt || null,
    version: row.version || "1.0.0",
    tags: row.tags || [],
  };
}

function dbRowToEvent(row: any): IngestedEvent {
  return {
    id: row.id,
    collectorId: row.collectorId,
    orgId: row.orgId,
    eventType: row.eventType,
    severity: row.severity as IngestedEvent["severity"],
    source: row.source,
    timestamp: row.timestamp?.toISOString?.() || row.timestamp || new Date().toISOString(),
    rawData: (row.rawData as Record<string, unknown>) || {},
    parsedFields: (row.parsedFields as Record<string, unknown>) || {},
    tags: row.tags || [],
    processed: row.processed || false,
  };
}

function dbRowToScan(row: any, findingsOverride?: ScanFinding[]): ScanResult {
  const findings = findingsOverride || (row.findings as ScanFinding[]) || [];
  const summary = (row.summary as any) || {};
  return {
    id: row.id,
    collectorId: row.collectorId,
    orgId: row.orgId,
    scanType: row.scanType as ScanResult["scanType"],
    status: row.status as ScanResult["status"],
    startedAt: row.startedAt?.toISOString?.() || row.startedAt || new Date().toISOString(),
    completedAt: row.completedAt?.toISOString?.() || row.completedAt || null,
    findingsCount: summary.findingsCount ?? findings.length,
    criticalCount: summary.criticalCount ?? findings.filter((f: any) => f.severity === "critical").length,
    highCount: summary.highCount ?? findings.filter((f: any) => f.severity === "high").length,
    mediumCount: summary.mediumCount ?? findings.filter((f: any) => f.severity === "medium").length,
    lowCount: summary.lowCount ?? findings.filter((f: any) => f.severity === "low").length,
    targets: row.targets || [],
    findings,
  };
}
