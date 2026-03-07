import crypto from "crypto";

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
export type Platform = "linux" | "windows" | "macos" | "docker" | "kubernetes" | "aws" | "azure" | "gcp" | "any";

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
const MAX_EVENTS = 5000;
const MAX_SCANS = 500;

const instanceStore = new Map<string, CollectorInstance>();
const eventStore = new Map<string, IngestedEvent>();
const scanStore = new Map<string, ScanResult>();

function generateId(): string {
  return crypto.randomBytes(12).toString("hex");
}

function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function getCollectorTemplates(type?: CollectorType): CollectorTemplate[] {
  if (type) return COLLECTOR_TEMPLATES.filter((t) => t.type === type);
  return [...COLLECTOR_TEMPLATES];
}

export function getTemplateBySlug(slug: string): CollectorTemplate | null {
  return COLLECTOR_TEMPLATES.find((t) => t.slug === slug) ?? null;
}

export function deployCollector(
  templateSlug: string,
  orgId: string,
  name: string,
  platform: Platform,
  deploymentMethod: DeploymentMethod,
  config: Record<string, unknown>,
  tags: string[],
): CollectorInstance {
  const template = COLLECTOR_TEMPLATES.find((t) => t.slug === templateSlug);
  if (!template) throw new Error(`Unknown collector template: ${templateSlug}`);
  if (!template.platforms.includes(platform) && !template.platforms.includes("any")) {
    throw new Error(`Template ${templateSlug} does not support platform: ${platform}`);
  }
  if (!template.deploymentMethods.includes(deploymentMethod)) {
    throw new Error(`Template ${templateSlug} does not support deployment method: ${deploymentMethod}`);
  }

  const orgInstanceCount = Array.from(instanceStore.values()).filter((i) => i.orgId === orgId).length;
  if (orgInstanceCount >= MAX_INSTANCES) {
    throw new Error("Maximum collector instances reached for this organization");
  }

  const instance: CollectorInstance = {
    id: generateId(),
    templateSlug,
    orgId,
    name,
    status: template.requiresAgent ? "pending_install" : "active",
    platform,
    deploymentMethod,
    config,
    hostInfo: null,
    metrics: {
      eventsPerSecond: 0,
      bytesIngested: 0,
      errorsLast24h: 0,
      uptimePercent: 0,
      latencyP50Ms: 0,
      latencyP99Ms: 0,
      lastEventCount: 0,
      totalEventsIngested: 0,
    },
    installedAt: new Date().toISOString(),
    lastHeartbeatAt: null,
    lastDataAt: null,
    version: "1.0.0",
    tags,
  };

  instanceStore.set(instance.id, instance);
  return instance;
}

export function getCollectorInstances(orgId: string, type?: CollectorType): CollectorInstance[] {
  const instances = Array.from(instanceStore.values()).filter((i) => i.orgId === orgId);
  if (type) {
    const slugsOfType = COLLECTOR_TEMPLATES.filter((t) => t.type === type).map((t) => t.slug);
    return instances.filter((i) => slugsOfType.includes(i.templateSlug));
  }
  return instances;
}

export function getCollectorInstance(instanceId: string, orgId: string): CollectorInstance | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;
  return instance;
}

export function updateCollectorConfig(
  instanceId: string,
  orgId: string,
  updates: { name?: string; config?: Record<string, unknown>; tags?: string[]; status?: CollectorStatus },
): CollectorInstance | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;

  if (updates.name !== undefined) instance.name = updates.name;
  if (updates.config !== undefined) instance.config = { ...instance.config, ...updates.config };
  if (updates.tags !== undefined) instance.tags = updates.tags;
  if (updates.status !== undefined) instance.status = updates.status;

  instanceStore.set(instanceId, instance);
  return instance;
}

export function deleteCollector(instanceId: string, orgId: string): boolean {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return false;
  instanceStore.delete(instanceId);
  return true;
}

export function sendHeartbeat(
  instanceId: string,
  orgId: string,
  hostInfo: HostInfo,
  metrics: Partial<CollectorMetrics>,
): CollectorInstance | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;

  instance.hostInfo = hostInfo;
  instance.lastHeartbeatAt = new Date().toISOString();
  instance.status = "active";
  instance.metrics = { ...instance.metrics, ...metrics };

  instanceStore.set(instanceId, instance);
  return instance;
}

export function ingestEvents(
  collectorId: string,
  orgId: string,
  events: Array<{
    eventType: string;
    severity: IngestedEvent["severity"];
    source: string;
    rawData: Record<string, unknown>;
    tags?: string[];
  }>,
): IngestedEvent[] {
  const instance = instanceStore.get(collectorId);
  if (!instance || instance.orgId !== orgId) throw new Error("Collector not found or access denied");

  if (eventStore.size + events.length > MAX_EVENTS) {
    const entriesToDelete = eventStore.size + events.length - MAX_EVENTS;
    const keys = Array.from(eventStore.keys());
    for (let i = 0; i < entriesToDelete; i++) {
      eventStore.delete(keys[i]);
    }
  }

  const ingested: IngestedEvent[] = events.map((e) => {
    const event: IngestedEvent = {
      id: generateId(),
      collectorId,
      orgId,
      eventType: e.eventType,
      severity: e.severity,
      source: e.source,
      timestamp: new Date().toISOString(),
      rawData: e.rawData,
      parsedFields: extractFields(e.rawData),
      tags: e.tags ?? [],
      processed: false,
    };
    eventStore.set(event.id, event);
    return event;
  });

  instance.lastDataAt = new Date().toISOString();
  instance.metrics.totalEventsIngested += events.length;
  instance.metrics.lastEventCount = events.length;
  instance.metrics.eventsPerSecond = Math.round(events.length / 10);
  instance.metrics.bytesIngested += JSON.stringify(events).length;
  instanceStore.set(collectorId, instance);

  return ingested;
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

export function getIngestedEvents(orgId: string, collectorId?: string, limit: number = 50): IngestedEvent[] {
  let events = Array.from(eventStore.values()).filter((e) => e.orgId === orgId);
  if (collectorId) events = events.filter((e) => e.collectorId === collectorId);
  return events.slice(-limit).reverse();
}

export function triggerScan(
  collectorId: string,
  orgId: string,
  scanType: ScanResult["scanType"],
  targets: string[],
): ScanResult {
  const instance = instanceStore.get(collectorId);
  if (!instance || instance.orgId !== orgId) throw new Error("Collector not found or access denied");

  if (scanStore.size >= MAX_SCANS) {
    const keys = Array.from(scanStore.keys());
    scanStore.delete(keys[0]);
  }

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

  const scan: ScanResult = {
    id: generateId(),
    collectorId,
    orgId,
    scanType,
    status: "completed",
    startedAt: new Date(Date.now() - randomBetween(30000, 120000)).toISOString(),
    completedAt: new Date().toISOString(),
    findingsCount: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    targets,
    findings,
  };

  scanStore.set(scan.id, scan);
  return scan;
}

export function getScanResults(orgId: string, collectorId?: string, limit: number = 20): ScanResult[] {
  let scans = Array.from(scanStore.values()).filter((s) => s.orgId === orgId);
  if (collectorId) scans = scans.filter((s) => s.collectorId === collectorId);
  return scans.slice(-limit).reverse();
}

export function getScanResult(scanId: string, orgId: string): ScanResult | null {
  const scan = scanStore.get(scanId);
  if (!scan || scan.orgId !== orgId) return null;
  return scan;
}

export function getDeploymentScript(templateSlug: string, instanceId: string): string {
  const template = COLLECTOR_TEMPLATES.find((t) => t.slug === templateSlug);
  if (!template) return "";

  const baseUrl = "https://nexus.aricatech.xyz";

  if (templateSlug.startsWith("endpoint-agent-linux")) {
    return `#!/bin/bash
# SecureNexus Endpoint Agent Installer — Linux
set -euo pipefail

COLLECTOR_ID="${instanceId}"
API_ENDPOINT="${baseUrl}/api/native-collectors"

echo "Installing SecureNexus Endpoint Agent..."
curl -fsSL ${baseUrl}/agent/linux/install.sh | sudo bash -s -- \\
  --collector-id "$COLLECTOR_ID" \\
  --api-endpoint "$API_ENDPOINT" \\
  --enable-fim \\
  --enable-process-audit

echo "Agent installed and reporting to SecureNexus."`;
  }

  if (templateSlug.startsWith("endpoint-agent-windows")) {
    return `# SecureNexus Endpoint Agent Installer — Windows (PowerShell)
$CollectorId = "${instanceId}"
$ApiEndpoint = "${baseUrl}/api/native-collectors"

Write-Host "Installing SecureNexus Endpoint Agent..."
Invoke-WebRequest -Uri "${baseUrl}/agent/windows/install.ps1" -OutFile "$env:TEMP\\sn-install.ps1"
& "$env:TEMP\\sn-install.ps1" -CollectorId $CollectorId -ApiEndpoint $ApiEndpoint -EnableSysmon -EnableDefender

Write-Host "Agent installed and reporting to SecureNexus."`;
  }

  if (templateSlug === "network-monitor" || templateSlug === "syslog-receiver" || templateSlug === "asset-discovery") {
    return `# SecureNexus ${template.name} — Docker Deployment
docker run -d \\
  --name securenexus-${templateSlug} \\
  --restart unless-stopped \\
  --network host \\
  -e COLLECTOR_ID=${instanceId} \\
  -e API_ENDPOINT=${baseUrl}/api/native-collectors \\
  aricatech/securenexus-${templateSlug}:latest`;
  }

  return `# ${template.name}
# Configure via the SecureNexus API:
# POST ${baseUrl}/api/native-collectors/instances/${instanceId}/configure
# See documentation: ${baseUrl}/docs/collectors/${templateSlug}`;
}

export function getDataPipelineStats(orgId: string): DataPipelineStats {
  const instances = Array.from(instanceStore.values()).filter((i) => i.orgId === orgId);
  const events = Array.from(eventStore.values()).filter((e) => e.orgId === orgId);

  const active = instances.filter((i) => i.status === "active").length;
  const degraded = instances.filter((i) => i.status === "degraded").length;
  const offline = instances.filter((i) => i.status === "offline").length;

  const totalEps = instances.reduce((sum, i) => sum + i.metrics.eventsPerSecond, 0);
  const totalBytes = instances.reduce((sum, i) => sum + i.metrics.bytesIngested, 0);

  const typeCounts: Record<string, number> = {};
  for (const e of events) {
    typeCounts[e.eventType] = (typeCounts[e.eventType] || 0) + 1;
  }
  const topEventTypes = Object.entries(typeCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .map(([type, count]) => ({
      type,
      count,
      percentage: events.length > 0 ? Math.round((count / events.length) * 100) : 0,
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
    totalEventsToday: events.length,
    totalBytesToday: totalBytes,
    storageUsedGb: Math.round((totalBytes / (1024 * 1024 * 1024)) * 100) / 100,
    storageQuotaGb: 100,
    retentionDays: 90,
    topEventTypes,
    collectorsByType,
    healthScore,
  };
}

export function generateApiKey(instanceId: string, orgId: string): { apiKey: string; expiresAt: string } | null {
  const instance = instanceStore.get(instanceId);
  if (!instance || instance.orgId !== orgId) return null;

  const apiKey = `snx_${crypto.randomBytes(24).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

  return { apiKey, expiresAt };
}
