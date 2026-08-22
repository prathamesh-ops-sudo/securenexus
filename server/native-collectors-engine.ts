/* eslint-disable @typescript-eslint/no-explicit-any */
import crypto from "crypto";
import { db } from "./db";
import { getCollectorLifecycleState } from "./native-collector-lifecycle";
import { collectorInstances, collectorEvents } from "@shared/schema";
import { eq, and, desc, count, sql } from "drizzle-orm";

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
  lifecycleState: string;
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

export function getDeploymentScript(
  templateSlug: string,
  instanceId: string,
  enrollmentToken = "${ENROLLMENT_TOKEN}",
): string {
  const template = COLLECTOR_TEMPLATES.find((t) => t.slug === templateSlug);
  if (!template) return "";

  const baseUrl = process.env.APP_URL || process.env.PUBLIC_APP_URL || "";
  if (!baseUrl) {
    throw new Error("APP_URL or PUBLIC_APP_URL must be configured before generating a collector script.");
  }

  const shellQuote = (value: string): string => `'${value.replace(/'/g, "'\"'\"'")}'`;
  const powershellQuote = (value: string): string => `'${value.replace(/'/g, "''")}'`;
  const platform = template.platforms[0] ?? "linux";
  if (platform === "windows") {
    return `# SecureNexus collector bootstrap and worker
param([switch]$Worker)
$ErrorActionPreference = "Stop"
$ServerUrl = if ([string]::IsNullOrWhiteSpace($env:SERVER_URL)) { ${powershellQuote(baseUrl)} } else { $env:SERVER_URL.TrimEnd("/") }
$CollectorId = "${instanceId}"
$ConfigDir = Join-Path $env:ProgramData "SecureNexus"
$ConfigFile = Join-Path $ConfigDir "collector.json"
$ScriptPath = $MyInvocation.MyCommand.Path

function Invoke-AgentPost([string]$Path, [hashtable]$Body, [string]$Credential) {
  $headers = @{}
  if (-not [string]::IsNullOrWhiteSpace($Credential)) {
    $headers.Authorization = "Bearer $Credential"
  }
  return Invoke-RestMethod -Uri "$ServerUrl$Path" -Method Post -Headers $headers -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 12 -Compress)
}

function Get-HostInfo {
  $info = @{
    hostname = $env:COMPUTERNAME
    os = [Environment]::OSVersion.VersionString
    arch = $env:PROCESSOR_ARCHITECTURE
    agentVersion = "1.0.0"
  }
  $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
  if ($null -ne $processor.NumberOfLogicalProcessors) { $info.cpuCount = [int]$processor.NumberOfLogicalProcessors }
  $computer = Get-CimInstance Win32_ComputerSystem
  if ($null -ne $computer.TotalPhysicalMemory) { $info.memoryGb = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2) }
  $ip = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and $_.IPAddress -ne "0.0.0.0"
  } | Select-Object -First 1
  if ($null -ne $ip) { $info.ipAddress = $ip.IPAddress }
  return $info
}

function Get-Metrics {
  $metrics = @{}
  $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
  if ($null -ne $processor.LoadPercentage) { $metrics.cpuUsage = [double]$processor.LoadPercentage }
  $memory = Get-CimInstance Win32_OperatingSystem
  if ($null -ne $memory.TotalVisibleMemorySize -and $memory.TotalVisibleMemorySize -gt 0) {
    $metrics.memoryUsage = [math]::Round(($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) * 100 / $memory.TotalVisibleMemorySize, 1)
  }
  $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
  if ($null -ne $disk.Size -and $disk.Size -gt 0) {
    $metrics.diskUsage = [math]::Round(($disk.Size - $disk.FreeSpace) * 100 / $disk.Size, 1)
  }
  return $metrics
}

function Get-ObservedEvents {
  $events = [System.Collections.Generic.List[object]]::new()
  $source = $env:COMPUTERNAME
  Get-Process | Select-Object -First 200 | ForEach-Object {
    $events.Add(@{
      eventType = "process"
      severity = "info"
      source = $source
      rawData = @{
        processName = $_.ProcessName
        pid = $_.Id
        timestamp = [DateTime]::UtcNow.ToString("o")
      }
    })
  }
  Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
    $events.Add(@{
      eventType = "network"
      severity = "info"
      source = $source
      rawData = @{
        localAddress = $_.LocalAddress
        localPort = $_.LocalPort
        remoteAddress = $_.RemoteAddress
        remotePort = $_.RemotePort
        state = [string]$_.State
        timestamp = [DateTime]::UtcNow.ToString("o")
      }
    })
  }
  Get-WinEvent -LogName Security -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object {
    $events.Add(@{
      eventType = "auth"
      severity = "info"
      source = $source
      rawData = @{
        logName = "Security"
        eventId = $_.Id
        message = $_.Message
        timestamp = $_.TimeCreated.ToUniversalTime().ToString("o")
      }
    })
  }
  foreach ($path in @(
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  )) {
    if (Test-Path $path) {
      $file = Get-Item $path
      $events.Add(@{
        eventType = "file"
        severity = "info"
        source = $source
        rawData = @{
          filePath = $path
          fileAction = "snapshot"
          fileHash = (Get-FileHash -Algorithm SHA256 -Path $path).Hash
          fileSize = [int64]$file.Length
          timestamp = [DateTime]::UtcNow.ToString("o")
        }
      })
    }
  }
  return @($events)
}

if ($Worker) {
  if (-not (Test-Path $ConfigFile)) { throw "Collector configuration not found: $ConfigFile" }
  $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
  $ServerUrl = $config.serverUrl
  $CollectorId = $config.collectorId
  $credential = $config.credential
  while ($true) {
    $heartbeat = @{
      hostInfo = Get-HostInfo
      metrics = Get-Metrics
    }
    Invoke-AgentPost "/api/agent/v1/collectors/heartbeat" $heartbeat $credential | Out-Null
    $observed = @(Get-ObservedEvents)
    if ($observed.Count -gt 0) {
      Invoke-AgentPost "/api/agent/v1/collectors/events" @{
        batchId = "collector-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())-$PID"
        events = $observed
      } $credential | Out-Null
    }
    Start-Sleep -Seconds 30
  }
}

$enrollmentToken = $env:ENROLLMENT_TOKEN
if ([string]::IsNullOrWhiteSpace($enrollmentToken)) { throw "ENROLLMENT_TOKEN is required" }
$payload = @{
  agentType = "collector"
  collectorId = $CollectorId
  enrollmentToken = $enrollmentToken
  hostname = $env:COMPUTERNAME
  platform = "windows"
  osVersion = [Environment]::OSVersion.VersionString
  agentVersion = "1.0.0"
}
$result = Invoke-AgentPost "/api/agent/v1/enroll" $payload ""
$credential = $result.data.apiKey
if ([string]::IsNullOrWhiteSpace($credential) -or $credential -notlike "snx_collector_*") {
  throw "Enrollment response did not contain a collector credential"
}
New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
@{
  serverUrl = $ServerUrl
  collectorId = $CollectorId
  credential = $credential
} | ConvertTo-Json -Compress | Set-Content -Path $ConfigFile -Encoding UTF8
icacls $ConfigDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
icacls $ConfigFile /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "$ScriptPath" -Worker'
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "SecureNexus Collector $CollectorId" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "SecureNexus Collector $CollectorId"
Write-Host "SecureNexus collector enrolled and persistent telemetry collection started."
`;
  }

  return `#!/usr/bin/env bash
set -Eeuo pipefail
SERVER_URL="\${SERVER_URL:-}"
if [[ -z "$SERVER_URL" ]]; then SERVER_URL=${shellQuote(baseUrl)}; fi
ENROLLMENT_TOKEN="\${ENROLLMENT_TOKEN:-}"
if [[ -z "$ENROLLMENT_TOKEN" ]]; then ENROLLMENT_TOKEN=${shellQuote(enrollmentToken)}; fi
COLLECTOR_ID="${instanceId}"
AGENT_VERSION="1.0.0"
PLATFORM="${platform}"
INSTALL_DIR="\${INSTALL_DIR:-/opt/securenexus-collector}"
LOG_DIR="\${LOG_DIR:-/var/log/securenexus-collector}"
WORKER="$INSTALL_DIR/collector-worker.sh"
if [[ -z "$SERVER_URL" || -z "$ENROLLMENT_TOKEN" ]]; then
  echo "ERROR: SERVER_URL and ENROLLMENT_TOKEN are required." >&2
  exit 1
fi
for command_name in curl jq hostname; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required." >&2
    exit 1
  fi
done
HOSTNAME_VAL="$(hostname)"
OS_VERSION="$(uname -sr)"
PAYLOAD="$(jq -n --arg token "$ENROLLMENT_TOKEN" --arg host "$HOSTNAME_VAL" --arg platform "$PLATFORM" --arg os "$OS_VERSION" --arg collector "$COLLECTOR_ID" '{agentType:"collector",collectorId:$collector,enrollmentToken:$token,hostname:$host,platform:$platform,osVersion:$os,agentVersion:"1.0.0"}')"
RESPONSE="$(curl --fail-with-body --silent --show-error --max-time 30 -X POST "$SERVER_URL/api/agent/v1/enroll" -H "Content-Type: application/json" --data "$PAYLOAD")"
CREDENTIAL="$(jq -er '.data.apiKey' <<<"$RESPONSE")"
[[ "$CREDENTIAL" == snx_collector_* ]] || { echo "ERROR: enrollment did not return a collector credential." >&2; exit 1; }
install -d -m 700 "$INSTALL_DIR" "$LOG_DIR"
export INSTALL_DIR
umask 077
printf '%s' "$CREDENTIAL" > "$INSTALL_DIR/credential"
chmod 600 "$INSTALL_DIR/credential"
cat >"$WORKER" <<'WORKER_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source "\${INSTALL_DIR:-/opt/securenexus-collector}/collector.env"
EVENTS="[]"
HOSTNAME_VAL="$(hostname)"

api_post() {
  local path="$1"
  local body
  if [[ "$#" -ge 2 ]]; then
    body="$2"
  else
    body="$(cat)"
  fi
  curl --fail-with-body --silent --show-error --max-time 30 -X POST "$SERVER_URL$path" \
    -H "Authorization: Bearer $CREDENTIAL" -H "Content-Type: application/json" --data "$body"
}

get_cpu_usage() {
  [[ -r /proc/stat ]] || return 0
  local first second
  first="$(awk '$1 == "cpu" {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat)"
  sleep 1
  second="$(awk '$1 == "cpu" {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat)"
  awk -v first="$first" -v second="$second" 'BEGIN {
    split(first,a); split(second,b); t1=a[1]+a[2]+a[3]+a[4]+a[5]+a[6]+a[7]; t2=b[1]+b[2]+b[3]+b[4]+b[5]+b[6]+b[7];
    i1=a[4]+a[5]; i2=b[4]+b[5]; if (t2 > t1) printf "%.1f", (1-(i2-i1)/(t2-t1))*100;
  }'
}

get_memory_usage() {
  [[ -r /proc/meminfo ]] || return 0
  awk '/^MemTotal:/ {total=$2} /^MemAvailable:/ {available=$2} END {if (total > 0) printf "%.1f", (total-available)*100/total}' /proc/meminfo
}

get_disk_usage() {
  df -P / 2>/dev/null | awk 'NR == 2 {gsub(/%/,"",$5); if ($5 ~ /^[0-9]+([.][0-9]+)?$/) print $5}'
}

get_cpu_count() {
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN 2>/dev/null
  elif [[ -r /proc/cpuinfo ]]; then
    awk '/^processor[[:space:]]*:/ {count++} END {if (count > 0) print count}' /proc/cpuinfo
  fi
}

get_memory_gb() {
  [[ -r /proc/meminfo ]] || return 0
  awk '/^MemTotal:/ {if ($2 > 0) printf "%.2f", $2/1024/1024}' /proc/meminfo
}

get_ip_address() {
  if command -v ip >/dev/null 2>&1; then
    local route_ip
    route_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
    [[ -n "$route_ip" ]] && { printf '%s' "$route_ip"; return; }
  fi
  hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127[.]/){print $i;exit}}'
}

heartbeat() {
  local cpu memory disk ip cpu_count memory_gb
  cpu="$(get_cpu_usage)"; memory="$(get_memory_usage)"; disk="$(get_disk_usage)"; ip="$(get_ip_address)"
  cpu_count="$(get_cpu_count)"; memory_gb="$(get_memory_gb)"
  jq -n --arg host "$HOSTNAME_VAL" --arg os "$OS_VERSION" --arg arch "$(uname -m)" --arg cpu "$cpu" --arg memory "$memory" --arg disk "$disk" --arg ip "$ip" --arg cpu_count "$cpu_count" --arg memory_gb "$memory_gb" \
    '{
      hostInfo:{hostname:$host,os:$os,arch:$arch,agentVersion:"1.0.0"},
      metrics:{}
    } |
    if $cpu != "" then .metrics.cpuUsage=($cpu|tonumber) else . end |
    if $memory != "" then .metrics.memoryUsage=($memory|tonumber) else . end |
    if $disk != "" then .metrics.diskUsage=($disk|tonumber) else . end |
    if $cpu_count != "" then .hostInfo.cpuCount=($cpu_count|tonumber) else . end |
    if $memory_gb != "" then .hostInfo.memoryGb=($memory_gb|tonumber) else . end |
    if $ip != "" then .hostInfo.ipAddress=$ip else . end' |
    api_post "/api/agent/v1/collectors/heartbeat" >/dev/null
}

add_event() {
  EVENTS="$(jq --argjson event "$1" '. + [$event]' <<<"$EVENTS")"
}

collect_process_events() {
  command -v ps >/dev/null 2>&1 || return 0
  while read -r pid ppid user process_name process_args; do
    [[ "$pid" =~ ^[0-9]+$ && -n "$process_name" ]] || continue
    add_event "$(jq -n --arg source "$HOSTNAME_VAL" --arg name "$process_name" --arg args "$process_args" --arg user "$user" --argjson pid "$pid" --argjson ppid "\${ppid:-0}" \
      '{eventType:"process",severity:"info",source:$source,rawData:{processName:$name,processArgs:$args,userName:$user,pid:$pid,ppid:$ppid}}')"
  done < <(ps -eo pid=,ppid=,user=,comm=,args= 2>/dev/null | awk 'NR <= 200')
}

collect_network_events() {
  command -v ss >/dev/null 2>&1 || return 0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    add_event "$(jq -n --arg source "$HOSTNAME_VAL" --arg line "$line" '{eventType:"network",severity:"info",source:$source,rawData:{source:"ss",line:$line}}')"
  done < <(ss -H -tunap 2>/dev/null | awk 'NR <= 100')
}

collect_auth_events() {
  local auth_log
  for auth_log in /var/log/auth.log /var/log/secure; do
    [[ -r "$auth_log" ]] || continue
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      add_event "$(jq -n --arg source "$HOSTNAME_VAL" --arg logSource "$auth_log" --arg line "$line" '{eventType:"auth",severity:"info",source:$source,rawData:{logSource:$logSource,line:$line}}')"
    done < <(tail -n 20 "$auth_log")
  done
}

collect_file_events() {
  local file_path file_hash file_size
  for file_path in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab /root/.ssh/authorized_keys /etc/hosts; do
    [[ -r "$file_path" ]] || continue
    if command -v sha256sum >/dev/null 2>&1; then
      file_hash="$(sha256sum "$file_path" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      file_hash="$(shasum -a 256 "$file_path" | awk '{print $1}')"
    else
      continue
    fi
    file_size="$(wc -c <"$file_path" | tr -d ' ')"
    add_event "$(jq -n --arg source "$HOSTNAME_VAL" --arg path "$file_path" --arg hash "$file_hash" --arg size "$file_size" \
      '{eventType:"file",severity:"info",source:$source,rawData:{filePath:$path,fileAction:"snapshot",fileHash:$hash,fileSize:($size|tonumber)}}')"
  done
}

send_events() {
  local count payload
  count="$(jq 'length' <<<"$EVENTS")"
  [[ "$count" -gt 0 ]] || return 0
  payload="$(jq -n --arg batchId "collector-$(date +%s)-$$" --argjson events "$EVENTS" '{batchId:$batchId,events:$events}')"
  api_post "/api/agent/v1/collectors/events" "$payload" >/dev/null
  EVENTS="[]"
}

while :; do
  heartbeat
  collect_process_events
  collect_network_events
  collect_auth_events
  collect_file_events
  send_events
  sleep 30
done
WORKER_EOF
chmod 700 "$WORKER"
cat >"$INSTALL_DIR/collector.env" <<EOF
SERVER_URL=$(printf '%q' "$SERVER_URL")
CREDENTIAL=$(printf '%q' "$CREDENTIAL")
OS_VERSION=$(printf '%q' "$OS_VERSION")
EOF
chmod 600 "$INSTALL_DIR/collector.env"
if [[ -d /run/systemd/system && -x "$(command -v systemctl 2>/dev/null)" ]]; then
  cat >/etc/systemd/system/securenexus-collector.service <<EOF
[Unit]
Description=SecureNexus collector
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$WORKER
Environment=INSTALL_DIR=$INSTALL_DIR
Restart=always
RestartSec=10
User=root
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now securenexus-collector.service
elif [[ "$PLATFORM" == "macos" && -x /bin/launchctl ]]; then
  cat >/Library/LaunchDaemons/io.securenexus.collector.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.securenexus.collector</string>
<key>ProgramArguments</key><array><string>$WORKER</string></array>
<key>EnvironmentVariables</key><dict><key>INSTALL_DIR</key><string>$INSTALL_DIR</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
EOF
  launchctl bootstrap system /Library/LaunchDaemons/io.securenexus.collector.plist
else
  nohup "$WORKER" >>"$LOG_DIR/collector.log" 2>&1 &
  echo "$!" >"$INSTALL_DIR/collector.pid"
  chmod 600 "$INSTALL_DIR/collector.pid"
fi
echo "SecureNexus collector enrolled and persistent telemetry collection started."
`;
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
    lifecycleState: getCollectorLifecycleState(row),
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
