/**
 * Syslog & Webhook Log Ingestion
 * Parses syslog messages (RFC 3164 / RFC 5424) and webhook payloads
 * from firewalls, EDR, cloud providers into normalized sensor events.
 */

import { logger } from "../routes/shared";

const log = logger.child("syslog-ingest");

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ParsedSyslogMessage {
  facility: number;
  severity: number;
  timestamp: Date;
  hostname: string;
  appName: string;
  procId: string | null;
  msgId: string | null;
  message: string;
  structuredData: Record<string, string>;
}

export interface NormalizedEvent {
  eventType: string;
  timestamp: string;
  processName?: string;
  processPath?: string;
  pid?: number;
  userName?: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: string;
  filePath?: string;
  fileAction?: string;
  authAction?: string;
  authResult?: string;
  dnsQuery?: string;
  dnsType?: string;
  dnsResponse?: string;
  logSource?: string;
  logLevel?: string;
  logMessage?: string;
  rawData?: string;
}

// ─── Syslog Severity & Facility ─────────────────────────────────────────────

const SYSLOG_SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"];

const SYSLOG_FACILITIES = [
  "kern",
  "user",
  "mail",
  "daemon",
  "auth",
  "syslog",
  "lpr",
  "news",
  "uucp",
  "cron",
  "authpriv",
  "ftp",
  "ntp",
  "audit",
  "alert",
  "clock",
  "local0",
  "local1",
  "local2",
  "local3",
  "local4",
  "local5",
  "local6",
  "local7",
];

// ─── RFC 3164 Parser ────────────────────────────────────────────────────────

const RFC3164_REGEX = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/;

export function parseRfc3164(raw: string): ParsedSyslogMessage | null {
  const match = raw.match(RFC3164_REGEX);
  if (!match) return null;

  const priority = parseInt(match[1], 10);
  const facility = Math.floor(priority / 8);
  const severity = priority % 8;

  // Parse BSD-style timestamp (e.g., "Mar 25 06:45:12")
  const currentYear = new Date().getFullYear();
  const timestamp = new Date(`${match[2]} ${currentYear}`);
  if (isNaN(timestamp.getTime())) {
    return null;
  }

  return {
    facility,
    severity,
    timestamp,
    hostname: match[3],
    appName: match[4],
    procId: match[5] || null,
    msgId: null,
    message: match[6],
    structuredData: {},
  };
}

// ─── RFC 5424 Parser ────────────────────────────────────────────────────────

const RFC5424_REGEX = /^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+((?:\[.*?\]\s*)*)?(.*)$/;

export function parseRfc5424(raw: string): ParsedSyslogMessage | null {
  const match = raw.match(RFC5424_REGEX);
  if (!match) return null;

  const priority = parseInt(match[1], 10);
  const facility = Math.floor(priority / 8);
  const severity = priority % 8;

  const timestampStr = match[3];
  const timestamp = timestampStr === "-" ? new Date() : new Date(timestampStr);
  if (isNaN(timestamp.getTime())) {
    return null;
  }

  // Parse structured data
  const structuredData: Record<string, string> = {};
  const sdStr = match[8] || "";
  const sdRegex = /\[(\S+?)\s+(.*?)\]/g;
  let sdMatch;
  while ((sdMatch = sdRegex.exec(sdStr)) !== null) {
    const params = sdMatch[2];
    const paramRegex = /(\S+?)="(.*?)"/g;
    let paramMatch;
    while ((paramMatch = paramRegex.exec(params)) !== null) {
      structuredData[`${sdMatch[1]}.${paramMatch[1]}`] = paramMatch[2];
    }
  }

  return {
    facility,
    severity,
    timestamp,
    hostname: match[4] === "-" ? "" : match[4],
    appName: match[5] === "-" ? "" : match[5],
    procId: match[6] === "-" ? null : match[6],
    msgId: match[7] === "-" ? null : match[7],
    message: match[9],
    structuredData,
  };
}

// ─── Auto-detect and parse ──────────────────────────────────────────────────

export function parseSyslog(raw: string): ParsedSyslogMessage | null {
  // Try RFC 5424 first (has version number after priority)
  const rfc5424 = parseRfc5424(raw);
  if (rfc5424) return rfc5424;

  // Fall back to RFC 3164
  const rfc3164 = parseRfc3164(raw);
  if (rfc3164) return rfc3164;

  // Last resort: treat the whole thing as a message
  log.debug(`Could not parse syslog message, treating as raw: ${raw.slice(0, 100)}`);
  return {
    facility: 1,
    severity: 6,
    timestamp: new Date(),
    hostname: "unknown",
    appName: "unknown",
    procId: null,
    msgId: null,
    message: raw,
    structuredData: {},
  };
}

// ─── Normalize syslog to sensor event ───────────────────────────────────────

export function syslogToEvent(parsed: ParsedSyslogMessage, source: string): NormalizedEvent {
  const severityLabel = SYSLOG_SEVERITIES[parsed.severity] || "informational";
  const facilityLabel = SYSLOG_FACILITIES[parsed.facility] || "user";

  // Detect event type from message content
  let eventType = "log_event";

  const msg = parsed.message.toLowerCase();

  // Auth events
  if (
    facilityLabel === "auth" ||
    facilityLabel === "authpriv" ||
    msg.includes("sshd") ||
    msg.includes("login") ||
    msg.includes("authentication") ||
    msg.includes("sudo") ||
    msg.includes("su:") ||
    msg.includes("pam_")
  ) {
    eventType = "auth_event";
  }
  // Network events
  else if (
    msg.includes("firewall") ||
    msg.includes("iptables") ||
    msg.includes("connection") ||
    msg.includes("denied") ||
    msg.includes("allowed") ||
    msg.includes("blocked") ||
    parsed.appName.toLowerCase().includes("fw")
  ) {
    eventType = "network_connection";
  }
  // DNS events
  else if (
    msg.includes("query") &&
    (msg.includes("dns") ||
      parsed.appName.toLowerCase().includes("named") ||
      parsed.appName.toLowerCase().includes("unbound") ||
      parsed.appName.toLowerCase().includes("dnsmasq"))
  ) {
    eventType = "dns_query";
  }
  // File events
  else if (
    msg.includes("file") &&
    (msg.includes("created") || msg.includes("modified") || msg.includes("deleted") || msg.includes("accessed"))
  ) {
    eventType = "file_modification";
  }
  // Process events
  else if (msg.includes("started") || msg.includes("spawned") || msg.includes("exec") || msg.includes("segfault")) {
    eventType = "process_start";
  }

  const event: NormalizedEvent = {
    eventType,
    timestamp: parsed.timestamp.toISOString(),
    logSource: source || `syslog-${facilityLabel}`,
    logLevel: severityLabel,
    logMessage: parsed.message,
    rawData: JSON.stringify({
      facility: facilityLabel,
      severity: severityLabel,
      hostname: parsed.hostname,
      appName: parsed.appName,
      procId: parsed.procId,
      structuredData: parsed.structuredData,
    }),
  };

  // Extract IP addresses from message
  const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
  const ips = msg.match(ipRegex);
  if (ips && ips.length >= 1) {
    event.srcIp = ips[0];
    if (ips.length >= 2) {
      event.dstIp = ips[1];
    }
  }

  // Extract port numbers
  const portRegex = /(?:port|dpt|spt|dst_port|src_port)[=:\s]+(\d+)/gi;
  const ports: number[] = [];
  let portMatch;
  while ((portMatch = portRegex.exec(msg)) !== null) {
    ports.push(parseInt(portMatch[1], 10));
  }
  if (ports.length >= 1) event.srcPort = ports[0];
  if (ports.length >= 2) event.dstPort = ports[1];

  // Extract username
  const userRegex = /(?:user|uid|account)[=:\s]+["']?(\w+)["']?/i;
  const userMatch = msg.match(userRegex);
  if (userMatch) {
    event.userName = userMatch[1];
  }

  // Extract process name
  if (parsed.appName && parsed.appName !== "unknown") {
    event.processName = parsed.appName;
  }
  if (parsed.procId) {
    event.pid = parseInt(parsed.procId, 10);
  }

  // Auth-specific fields
  if (eventType === "auth_event") {
    if (msg.includes("accepted") || msg.includes("succeeded") || msg.includes("success")) {
      event.authResult = "success";
    } else if (msg.includes("failed") || msg.includes("denied") || msg.includes("invalid")) {
      event.authResult = "failure";
    }
    if (msg.includes("ssh")) event.authAction = "ssh_login";
    else if (msg.includes("sudo")) event.authAction = "sudo";
    else if (msg.includes("su:") || msg.includes("su[")) event.authAction = "su";
    else event.authAction = "login";
  }

  // DNS-specific fields
  if (eventType === "dns_query") {
    const dnsQueryRegex = /query\[?\s*(\w+)\]?\s+(\S+)/i;
    const dnsMatch = msg.match(dnsQueryRegex);
    if (dnsMatch) {
      event.dnsType = dnsMatch[1];
      event.dnsQuery = dnsMatch[2];
    }
  }

  return event;
}

// ─── Webhook payload normalizers ────────────────────────────────────────────

/**
 * Normalize a Palo Alto Networks firewall webhook payload
 */
export function normalizePaloAltoEvent(payload: Record<string, unknown>): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];

  // Palo Alto sends logs as an array or single object
  const logs = Array.isArray(payload.logs) ? payload.logs : [payload];

  for (const entry of logs as Record<string, unknown>[]) {
    const event: NormalizedEvent = {
      eventType: "network_connection",
      timestamp: (entry.receive_time as string) || new Date().toISOString(),
      srcIp: (entry.src as string) || (entry.source_ip as string) || undefined,
      dstIp: (entry.dst as string) || (entry.destination_ip as string) || undefined,
      srcPort: typeof entry.sport === "number" ? entry.sport : undefined,
      dstPort: typeof entry.dport === "number" ? entry.dport : undefined,
      protocol: (entry.proto as string) || (entry.protocol as string) || undefined,
      logSource: "paloalto",
      logLevel: (entry.severity as string) || "informational",
      logMessage: (entry.action as string) || (entry.type as string) || "",
      rawData: JSON.stringify(entry),
    };

    // Map Palo Alto action to event type
    const action = String(entry.action || "").toLowerCase();
    if (action === "deny" || action === "drop" || action === "reset") {
      event.logMessage = `${action}: ${event.srcIp}:${event.srcPort} -> ${event.dstIp}:${event.dstPort}`;
    }

    events.push(event);
  }

  return events;
}

/**
 * Normalize a Fortinet FortiGate webhook payload
 */
export function normalizeFortinetEvent(payload: Record<string, unknown>): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];

  const logs = Array.isArray(payload.results) ? payload.results : [payload];

  for (const entry of logs as Record<string, unknown>[]) {
    events.push({
      eventType: "network_connection",
      timestamp: (entry.date as string) || new Date().toISOString(),
      srcIp: (entry.srcip as string) || undefined,
      dstIp: (entry.dstip as string) || undefined,
      srcPort: typeof entry.srcport === "number" ? entry.srcport : undefined,
      dstPort: typeof entry.dstport === "number" ? entry.dstport : undefined,
      protocol: (entry.proto as string) || undefined,
      logSource: "fortinet",
      logLevel: (entry.level as string) || "informational",
      logMessage: (entry.action as string) || "",
      rawData: JSON.stringify(entry),
    });
  }

  return events;
}

/**
 * Normalize a CrowdStrike Falcon webhook payload
 */
export function normalizeCrowdStrikeEvent(payload: Record<string, unknown>): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];

  const detections = Array.isArray(payload.resources) ? payload.resources : [payload];

  for (const detection of detections as Record<string, unknown>[]) {
    const behaviors = Array.isArray(detection.behaviors) ? detection.behaviors : [detection];

    for (const behavior of behaviors as Record<string, unknown>[]) {
      events.push({
        eventType: "process_start",
        timestamp: (behavior.timestamp as string) || new Date().toISOString(),
        processName: (behavior.filename as string) || (behavior.cmdline as string) || undefined,
        processPath: (behavior.filepath as string) || undefined,
        userName: (behavior.user_name as string) || undefined,
        srcIp: (behavior.local_ip as string) || undefined,
        dstIp: (behavior.remote_address as string) || undefined,
        logSource: "crowdstrike",
        logLevel: (behavior.severity_name as string) || "medium",
        logMessage: (behavior.tactic as string) || (behavior.technique as string) || "",
        rawData: JSON.stringify(behavior),
      });
    }
  }

  return events;
}

/**
 * Normalize an AWS CloudTrail webhook/SNS payload
 */
export function normalizeCloudTrailEvent(payload: Record<string, unknown>): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];

  // CloudTrail comes via SNS as a JSON string
  let records: Record<string, unknown>[] = [];
  if (Array.isArray(payload.Records)) {
    records = payload.Records as Record<string, unknown>[];
  } else if (typeof payload.Message === "string") {
    try {
      const parsed = JSON.parse(payload.Message as string);
      records = Array.isArray(parsed.Records) ? parsed.Records : [parsed];
    } catch {
      records = [payload];
    }
  } else {
    records = [payload];
  }

  for (const record of records) {
    const eventName = (record.eventName as string) || "";
    let eventType = "log_event";

    // Map CloudTrail event names to our event types
    if (eventName.match(/^(Create|Run|Start|Launch)/i)) eventType = "process_start";
    else if (eventName.match(/^(Login|Console|AssumeRole|GetSession)/i)) eventType = "auth_event";
    else if (eventName.match(/^(Put|Delete|Create).*?(Object|Bucket|File)/i)) eventType = "file_modification";
    else if (eventName.match(/^(Authorize|Revoke|Create|Delete).*?(Security|Ingress|Egress)/i))
      eventType = "network_connection";

    const sourceIp = (record.sourceIPAddress as string) || undefined;

    events.push({
      eventType,
      timestamp: (record.eventTime as string) || new Date().toISOString(),
      userName: ((record.userIdentity as Record<string, unknown>)?.userName as string) || undefined,
      srcIp: sourceIp,
      logSource: "aws-cloudtrail",
      logLevel: (record.errorCode as string) ? "error" : "informational",
      logMessage: `${eventName}: ${(record.eventSource as string) || ""}`,
      rawData: JSON.stringify(record),
    });
  }

  return events;
}

/**
 * Generic webhook normalizer — tries to detect the source and normalize
 */
export function normalizeWebhookPayload(payload: Record<string, unknown>, source?: string): NormalizedEvent[] {
  // Auto-detect source if not provided
  if (!source) {
    if (payload.serial || (payload.type && typeof payload.type === "string" && payload.type.includes("TRAFFIC"))) {
      source = "paloalto";
    } else if (payload.devid || payload.logid) {
      source = "fortinet";
    } else if (
      payload.resources ||
      (payload.meta as Record<string, unknown> | undefined)?.powered_by === "CrowdStrike"
    ) {
      source = "crowdstrike";
    } else if (
      payload.Records ||
      ((payload.detail as Record<string, unknown> | undefined)?.eventSource as string | undefined)?.endsWith(
        ".amazonaws.com",
      )
    ) {
      source = "aws-cloudtrail";
    }
  }

  switch (source) {
    case "paloalto":
      return normalizePaloAltoEvent(payload);
    case "fortinet":
      return normalizeFortinetEvent(payload);
    case "crowdstrike":
      return normalizeCrowdStrikeEvent(payload);
    case "aws-cloudtrail":
    case "cloudtrail":
      return normalizeCloudTrailEvent(payload);
    default:
      // Generic: treat the whole payload as a single log event
      return [
        {
          eventType: "log_event",
          timestamp: new Date().toISOString(),
          logSource: source || "webhook",
          logLevel: "informational",
          logMessage: JSON.stringify(payload).slice(0, 2000),
          rawData: JSON.stringify(payload),
        },
      ];
  }
}
