import type { NormalizedAlert } from "./normalizer";

export interface OCSFSeverity {
  id: number;
  name: string;
}

export interface OCSFEndpoint {
  ip?: string;
  port?: number;
  hostname?: string;
  domain?: string;
  name?: string;
  uid?: string;
}

export interface OCSFObservable {
  name: string;
  type: string;
  type_id: number;
  value: string;
  reputation?: { score_id: number };
}

export interface OCSFMitreAttack {
  tactic?: { uid?: string; name?: string };
  technique?: { uid?: string; name?: string };
  version?: string;
}

export interface OCSFMetadata {
  version: string;
  product: { name: string; vendor_name: string; uid?: string };
  log_name?: string;
  logged_time?: string;
  original_time?: string;
  processed_time: string;
  uid?: string;
}

export interface OCSFSecurityFinding {
  class_uid: 2001;
  class_name: "Security Finding";
  category_uid: number;
  category_name: string;
  type_uid: number;
  type_name: string;
  activity_id: number;
  activity_name: string;
  severity_id: number;
  severity: string;
  confidence_id?: number;
  confidence_score?: number;
  status_id: number;
  status: string;
  time: number;
  time_dt?: string;
  start_time_dt?: string;
  message: string;
  finding_info: {
    uid: string;
    title: string;
    desc?: string;
    types?: string[];
    src_url?: string;
    created_time_dt?: string;
    data_sources?: string[];
    analytic?: {
      category?: string;
      name?: string;
      type?: string;
      uid?: string;
    };
    attacks?: OCSFMitreAttack[];
  };
  metadata: OCSFMetadata;
  src_endpoint?: OCSFEndpoint;
  dst_endpoint?: OCSFEndpoint;
  observables?: OCSFObservable[];
  resources?: { uid?: string; name?: string; type?: string }[];
  enrichments?: { name: string; value: string; provider?: string; type?: string }[];
  raw_data?: string;
  unmapped?: Record<string, any>;
}

const SEVERITY_TO_OCSF: Record<string, { id: number; name: string }> = {
  critical: { id: 5, name: "Critical" },
  high: { id: 4, name: "High" },
  medium: { id: 3, name: "Medium" },
  low: { id: 2, name: "Low" },
  informational: { id: 1, name: "Informational" },
};

const CATEGORY_TO_OCSF: Record<string, { uid: number; name: string }> = {
  malware: { uid: 1, name: "Malware" },
  intrusion: { uid: 2, name: "Network Activity" },
  phishing: { uid: 6, name: "Application Activity" },
  data_exfiltration: { uid: 4, name: "Network Activity" },
  privilege_escalation: { uid: 3, name: "Identity & Access Management" },
  lateral_movement: { uid: 2, name: "Network Activity" },
  credential_access: { uid: 3, name: "Identity & Access Management" },
  reconnaissance: { uid: 2, name: "Network Activity" },
  persistence: { uid: 1, name: "System Activity" },
  command_and_control: { uid: 2, name: "Network Activity" },
  cloud_misconfiguration: { uid: 5, name: "Discovery" },
  policy_violation: { uid: 6, name: "Application Activity" },
  other: { uid: 0, name: "Uncategorized" },
};

const STATUS_TO_OCSF: Record<string, { id: number; name: string }> = {
  new: { id: 1, name: "New" },
  triaged: { id: 2, name: "In Progress" },
  correlated: { id: 2, name: "In Progress" },
  investigating: { id: 2, name: "In Progress" },
  resolved: { id: 4, name: "Closed" },
  dismissed: { id: 3, name: "Suppressed" },
  false_positive: { id: 3, name: "Suppressed" },
};

const OBSERVABLE_TYPES: Record<string, { type: string; type_id: number }> = {
  ip: { type: "IP Address", type_id: 2 },
  domain: { type: "Domain Name", type_id: 1 },
  hostname: { type: "Hostname", type_id: 3 },
  file_hash: { type: "Hash", type_id: 7 },
  url: { type: "URL String", type_id: 6 },
  user: { type: "User Name", type_id: 4 },
  email: { type: "Email Address", type_id: 5 },
  process: { type: "Process Name", type_id: 9 },
};

const MITRE_TACTIC_NAMES: Record<string, string> = {
  reconnaissance: "Reconnaissance",
  "resource-development": "Resource Development",
  "initial-access": "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  discovery: "Discovery",
  "lateral-movement": "Lateral Movement",
  collection: "Collection",
  "command-and-control": "Command and Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
};

function extractObservables(alert: NormalizedAlert): OCSFObservable[] {
  const observables: OCSFObservable[] = [];
  const seen = new Set<string>();

  const add = (value: string | undefined | null, obsType: string) => {
    if (!value || value.trim() === "") return;
    const key = `${obsType}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    const typeInfo = OBSERVABLE_TYPES[obsType] || { type: "Other", type_id: 0 };
    observables.push({
      name: obsType,
      type: typeInfo.type,
      type_id: typeInfo.type_id,
      value: value.trim(),
    });
  };

  add(alert.sourceIp, "ip");
  add(alert.destIp, "ip");
  add(alert.hostname, "hostname");
  add(alert.domain, "domain");
  add(alert.fileHash, "file_hash");
  add(alert.url, "url");
  add(alert.userId, "user");

  const normalized = alert.normalizedData as Record<string, any> | null;
  if (normalized) {
    add(normalized.email, "email");
    add(normalized.username, "user");
    add(normalized.account_name, "user");
    add(normalized.process_name, "process");
    add(normalized.dns_query, "domain");
    add(normalized.sha256, "file_hash");
    add(normalized.md5, "file_hash");
    add(normalized.src_ip, "ip");
    add(normalized.dest_ip, "ip");
    add(normalized.src_host, "hostname");
    add(normalized.dest_host, "hostname");
  }

  return observables;
}

export function toOCSFSecurityFinding(alert: NormalizedAlert, alertId?: string, alertStatus?: string): OCSFSecurityFinding {
  const now = new Date();
  const severity = SEVERITY_TO_OCSF[alert.severity] || SEVERITY_TO_OCSF.medium;
  const category = CATEGORY_TO_OCSF[alert.category] || CATEGORY_TO_OCSF.other;
  const status = STATUS_TO_OCSF[alertStatus || "new"] || STATUS_TO_OCSF["new"];

  const attacks: OCSFMitreAttack[] = [];
  if (alert.mitreTactic || alert.mitreTechnique) {
    attacks.push({
      tactic: alert.mitreTactic ? {
        uid: alert.mitreTactic,
        name: MITRE_TACTIC_NAMES[alert.mitreTactic] || alert.mitreTactic,
      } : undefined,
      technique: alert.mitreTechnique ? {
        uid: alert.mitreTechnique,
        name: alert.mitreTechnique,
      } : undefined,
      version: "14.1",
    });
  }

  const finding: OCSFSecurityFinding = {
    class_uid: 2001,
    class_name: "Security Finding",
    category_uid: category.uid,
    category_name: category.name,
    type_uid: 200101,
    type_name: "Security Finding: Create",
    activity_id: 1,
    activity_name: "Create",
    severity_id: severity.id,
    severity: severity.name,
    status_id: status.id,
    status: status.name,
    time: (alert.detectedAt || now).getTime(),
    time_dt: (alert.detectedAt || now).toISOString(),
    start_time_dt: alert.detectedAt?.toISOString(),
    message: alert.title,
    finding_info: {
      uid: alertId || alert.sourceEventId || `sn-${Date.now()}`,
      title: alert.title,
      desc: alert.description || undefined,
      types: [alert.category],
      data_sources: [alert.source],
      created_time_dt: (alert.detectedAt || now).toISOString(),
      analytic: {
        category: alert.category,
        name: alert.source,
        type: "Rule",
        uid: alert.sourceEventId,
      },
      attacks: attacks.length > 0 ? attacks : undefined,
    },
    metadata: {
      version: "1.1.0",
      product: {
        name: "SecureNexus",
        vendor_name: "SecureNexus",
        uid: "securenexus-platform",
      },
      log_name: alert.source,
      original_time: alert.detectedAt?.toISOString(),
      processed_time: now.toISOString(),
      uid: alertId || alert.sourceEventId,
    },
    observables: extractObservables(alert),
    raw_data: typeof alert.rawData === "string" ? alert.rawData : JSON.stringify(alert.rawData),
  };

  if (alert.sourceIp || alert.hostname) {
    finding.src_endpoint = {
      ip: alert.sourceIp,
      port: alert.sourcePort,
      hostname: alert.hostname,
      uid: alert.userId,
    };
  }

  if (alert.destIp) {
    finding.dst_endpoint = {
      ip: alert.destIp,
      port: alert.destPort,
      domain: alert.domain,
    };
  }

  return finding;
}

export function getOCSFCategoryName(categoryUid: number): string {
  const names: Record<number, string> = {
    0: "Uncategorized",
    1: "System Activity",
    2: "Network Activity",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
  };
  return names[categoryUid] || "Uncategorized";
}

export function getOCSFSeverityName(severityId: number): string {
  const names: Record<number, string> = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
  };
  return names[severityId] || "Unknown";
}

export function validateOCSFSecurityFinding(finding: OCSFSecurityFinding): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (finding.class_uid !== 2001) errors.push("class_uid must be 2001");
  if (!finding.finding_info?.uid) errors.push("finding_info.uid is required");
  if (!finding.finding_info?.title) errors.push("finding_info.title is required");
  if (finding.severity_id < 0 || finding.severity_id > 6) errors.push("severity_id must be 0-6");
  if (!finding.time) errors.push("time is required");
  if (!finding.metadata?.version) errors.push("metadata.version is required");
  if (!finding.metadata?.product?.name) errors.push("metadata.product.name is required");
  
  return { valid: errors.length === 0, errors };
}
