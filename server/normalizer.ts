import type { InsertAlert } from "@shared/schema";
import { toOCSFSecurityFinding } from "./ocsf";

export interface NormalizedAlert {
  source: string;
  sourceEventId: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  rawData: any;
  normalizedData: any;
  sourceIp?: string;
  destIp?: string;
  sourcePort?: number;
  destPort?: number;
  protocol?: string;
  userId?: string;
  hostname?: string;
  fileHash?: string;
  url?: string;
  domain?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
  detectedAt?: Date;
}

const SEVERITY_MAP: Record<string, string> = {
  "5": "critical", "4": "high", "3": "medium", "2": "low", "1": "informational",
  critical: "critical", high: "high", medium: "medium", low: "low", informational: "informational",
  urgent: "critical", severe: "critical", warning: "medium", info: "informational", notice: "low",
  error: "high", alert: "high", emergency: "critical",
};

function normalizeSeverity(raw: string | number): string {
  const key = String(raw).toLowerCase().trim();
  return SEVERITY_MAP[key] || "medium";
}

const CATEGORY_MAP: Record<string, string> = {
  malware: "malware", ransomware: "malware", trojan: "malware", virus: "malware",
  intrusion: "intrusion", "unauthorized access": "intrusion", breach: "intrusion",
  phishing: "phishing", "spear phishing": "phishing", "social engineering": "phishing",
  exfiltration: "data_exfiltration", "data leak": "data_exfiltration", "data theft": "data_exfiltration",
  "privilege escalation": "privilege_escalation", "elevation of privilege": "privilege_escalation",
  "lateral movement": "lateral_movement",
  "credential access": "credential_access", "credential theft": "credential_access", "brute force": "credential_access",
  reconnaissance: "reconnaissance", scanning: "reconnaissance", "port scan": "reconnaissance",
  persistence: "persistence", backdoor: "persistence",
  "command and control": "command_and_control", c2: "command_and_control", "c&c": "command_and_control",
  "cloud misconfiguration": "cloud_misconfiguration", misconfiguration: "cloud_misconfiguration",
  "policy violation": "policy_violation", compliance: "policy_violation",
};

function normalizeCategory(raw: string): string {
  const key = raw.toLowerCase().trim();
  return CATEGORY_MAP[key] || "other";
}

function parseTimestamp(raw: any): Date | undefined {
  if (!raw) return undefined;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? undefined : d;
}

function extractDomain(urlStr: string | undefined): string | undefined {
  if (!urlStr) return undefined;
  try {
    return new URL(urlStr).hostname;
  } catch {
    const match = urlStr.match(/(?:https?:\/\/)?([^\/:\s]+)/);
    return match?.[1];
  }
}

function normalizeCrowdStrike(payload: any): NormalizedAlert {
  const event = payload.event || payload.detection || payload;
  return {
    source: "CrowdStrike EDR",
    sourceEventId: event.detection_id || event.event_id || event.id || "",
    category: normalizeCategory(event.tactic || event.technique_name || event.category || "other"),
    severity: normalizeSeverity(event.severity || event.max_severity || "medium"),
    title: event.detect_name || event.description || event.technique_name || "CrowdStrike Detection",
    description: event.detect_description || event.description || "",
    rawData: payload,
    normalizedData: {
      normalized: true,
      source: "crowdstrike",
      ocsf_mapped: true,
      timestamp: new Date().toISOString(),
      src_ip: event.local_ip || event.source_ip,
      dest_ip: event.external_ip || event.dest_ip,
      src_host: event.computer_name || event.hostname || event.device?.hostname,
      username: event.user_name || event.user_id,
      process_name: event.filename || event.process_name,
      process_path: event.filepath || event.cmdline,
      sha256: event.sha256,
      md5: event.md5,
      parent_process: event.parent_details?.parent_process_graph_id,
      device_id: event.device?.device_id || event.aid,
      os_version: event.device?.os_version,
      platform: event.device?.platform_name || "endpoint",
      agent_version: event.device?.agent_version,
      confidence: event.confidence,
      ioc_type: event.ioc_type,
      ioc_value: event.ioc_value,
    },
    sourceIp: event.local_ip || event.source_ip,
    destIp: event.external_ip || event.dest_ip,
    hostname: event.computer_name || event.hostname || event.device?.hostname,
    userId: event.user_name || event.user_id,
    fileHash: event.sha256 || event.md5 || event.sha1,
    domain: event.domain_name,
    mitreTactic: event.tactic,
    mitreTechnique: event.technique_id || event.technique,
    detectedAt: parseTimestamp(event.created_timestamp || event.timestamp),
  };
}

function normalizeSplunk(payload: any): NormalizedAlert {
  const event = payload.result || payload.event || payload;
  return {
    source: "Splunk SIEM",
    sourceEventId: event.sid || event.event_id || event._cd || "",
    category: normalizeCategory(event.category || event.alert_type || "other"),
    severity: normalizeSeverity(event.severity || event.urgency || "medium"),
    title: event.search_name || event.alert_name || event.name || "Splunk Alert",
    description: event.description || event.message || event.raw || "",
    rawData: payload,
    normalizedData: {
      normalized: true,
      source: "splunk",
      ocsf_mapped: true,
      timestamp: new Date().toISOString(),
      src_ip: event.src_ip || event.src || event.source_ip,
      dest_ip: event.dest_ip || event.dest || event.destination_ip,
      src_host: event.host || event.hostname || event.dvc,
      dest_host: event.dest_host || event.dest_nt_host,
      username: event.user || event.src_user,
      account_name: event.Account_Name || event.account_name,
      email: event.sender || event.recipient,
      process_name: event.process || event.process_name,
      process_id: event.process_id || event.pid,
      dns_query: event.query || event.dns_query,
      sha256: event.sha256 || event.file_hash,
      app: event.app || event.sourcetype,
      action: event.action,
      status: event.status,
      bytes_in: event.bytes_in,
      bytes_out: event.bytes_out,
      duration: event.duration,
      index: event.index,
      sourcetype: event.sourcetype,
    },
    sourceIp: event.src_ip || event.src || event.source_ip,
    destIp: event.dest_ip || event.dest || event.destination_ip,
    sourcePort: parseInt(event.src_port) || undefined,
    destPort: parseInt(event.dest_port) || undefined,
    protocol: event.transport || event.protocol,
    hostname: event.host || event.hostname || event.dvc,
    userId: event.user || event.src_user,
    fileHash: event.file_hash || event.sha256,
    url: event.url || event.uri,
    domain: event.domain || extractDomain(event.url),
    mitreTactic: event.mitre_tactic || event.annotation?.mitre_attack?.tactic,
    mitreTechnique: event.mitre_technique || event.annotation?.mitre_attack?.technique_id,
    detectedAt: parseTimestamp(event._time || event.timestamp),
  };
}

function normalizePaloAlto(payload: any): NormalizedAlert {
  const event = payload.log || payload.threat || payload;
  return {
    source: "Palo Alto Firewall",
    sourceEventId: event.serial || event.seqno || event.log_id || "",
    category: normalizeCategory(event.type || event.subtype || event.threat_category || "other"),
    severity: normalizeSeverity(event.severity || "medium"),
    title: event.threatid_name || event.rule_name || event.threat_name || "Palo Alto Threat",
    description: event.description || event.misc || "",
    rawData: payload,
    normalizedData: {
      normalized: true,
      source: "paloalto",
      ocsf_mapped: true,
      timestamp: new Date().toISOString(),
      src_ip: event.src || event.source_ip || event.srcip,
      dest_ip: event.dst || event.destination_ip || event.dstip,
      src_host: event.device_name || event.hostname,
      username: event.srcuser || event.user,
      app: event.app || event.application,
      rule_name: event.rule || event.rule_name,
      action: event.action,
      session_id: event.sessionid,
      log_type: event.type,
      subtype: event.subtype,
      direction: event.direction || event.inbound_interface ? "inbound" : "outbound",
      bytes_sent: event.bytes_sent || event.bytes,
      bytes_received: event.bytes_received,
      packets_sent: event.pkts_sent,
      packets_received: event.pkts_received,
      nat_src_ip: event.natsrc,
      nat_dst_ip: event.natdst,
      zone_src: event.from || event.srcloc,
      zone_dst: event.to || event.dstloc,
      threat_id: event.threatid,
      threat_category: event.threat_category || event.thr_category,
    },
    sourceIp: event.src || event.source_ip || event.srcip,
    destIp: event.dst || event.destination_ip || event.dstip,
    sourcePort: parseInt(event.sport || event.src_port) || undefined,
    destPort: parseInt(event.dport || event.dst_port) || undefined,
    protocol: event.proto || event.protocol,
    hostname: event.device_name || event.hostname,
    userId: event.srcuser || event.user,
    url: event.url || event.misc,
    domain: event.domain || extractDomain(event.url),
    mitreTactic: event.tactic,
    mitreTechnique: event.technique,
    detectedAt: parseTimestamp(event.receive_time || event.generated_time || event.timestamp),
  };
}

function normalizeGuardDuty(payload: any): NormalizedAlert {
  const finding = payload.detail || payload;
  const resource = finding.resource || {};
  const service = finding.service || {};
  const action = service.action || {};
  const networkInfo = action.networkConnectionAction?.remoteIpDetails || {};
  const instanceDetails = resource.instanceDetails || {};
  return {
    source: "AWS GuardDuty",
    sourceEventId: finding.id || finding.arn || "",
    category: normalizeCategory(finding.type?.split("/")[0] || "other"),
    severity: normalizeSeverity(
      finding.severity >= 7 ? "critical" :
      finding.severity >= 4 ? "high" :
      finding.severity >= 2 ? "medium" : "low"
    ),
    title: finding.title || finding.type || "GuardDuty Finding",
    description: finding.description || "",
    rawData: payload,
    normalizedData: {
      normalized: true,
      source: "guardduty",
      ocsf_mapped: true,
      timestamp: new Date().toISOString(),
      src_ip: networkInfo.ipAddressV4 || action.remoteIpDetails?.ipAddressV4,
      dest_ip: instanceDetails.networkInterfaces?.[0]?.privateIpAddress,
      src_host: instanceDetails.instanceId,
      username: resource.accessKeyDetails?.userName,
      account_name: resource.accessKeyDetails?.principalId,
      aws_account_id: finding.accountId,
      aws_region: finding.region,
      resource_type: resource.resourceType,
      instance_type: instanceDetails.instanceType,
      instance_id: instanceDetails.instanceId,
      vpc_id: instanceDetails.networkInterfaces?.[0]?.vpcId,
      subnet_id: instanceDetails.networkInterfaces?.[0]?.subnetId,
      security_groups: instanceDetails.networkInterfaces?.[0]?.securityGroups?.map((sg: any) => sg.groupId),
      iam_role: instanceDetails.iamInstanceProfile?.arn,
      s3_bucket: resource.s3BucketDetails?.[0]?.name,
      finding_type: finding.type,
      action_type: service.action?.actionType,
      evidence: service.evidence,
      threat_intel: service.additionalInfo?.threatListName,
      country: networkInfo.country?.countryName,
      city: networkInfo.city?.cityName,
      asn_org: networkInfo.organization?.asnOrg,
    },
    sourceIp: networkInfo.ipAddressV4 || action.remoteIpDetails?.ipAddressV4,
    destIp: instanceDetails.networkInterfaces?.[0]?.privateIpAddress,
    hostname: instanceDetails.instanceId,
    userId: resource.accessKeyDetails?.userName || resource.accessKeyDetails?.principalId,
    domain: networkInfo.organization?.asnOrg,
    mitreTactic: finding.type?.split(":")?.[0],
    mitreTechnique: finding.type?.split("/")?.[1],
    detectedAt: parseTimestamp(finding.createdAt || service.eventFirstSeen),
  };
}

function normalizeSuricata(payload: any): NormalizedAlert {
  const event = payload.alert || payload;
  return {
    source: "Suricata IDS",
    sourceEventId: event.signature_id?.toString() || event.flow_id?.toString() || "",
    category: normalizeCategory(event.category || "intrusion"),
    severity: normalizeSeverity(
      event.severity === 1 ? "critical" :
      event.severity === 2 ? "high" :
      event.severity === 3 ? "medium" : "low"
    ),
    title: event.signature || event.msg || "Suricata Alert",
    description: event.payload_printable || event.signature || "",
    rawData: payload,
    normalizedData: {
      normalized: true,
      source: "suricata",
      ocsf_mapped: true,
      timestamp: new Date().toISOString(),
      src_ip: event.src_ip,
      dest_ip: event.dest_ip,
      src_host: event.hostname || event.in_iface,
      dns_query: event.dns?.rrname,
      http_hostname: event.http?.hostname,
      http_url: event.http?.url,
      http_method: event.http?.http_method,
      http_user_agent: event.http?.http_user_agent,
      http_status: event.http?.status,
      http_content_type: event.http?.http_content_type,
      tls_sni: event.tls?.sni,
      tls_version: event.tls?.version,
      tls_subject: event.tls?.subject,
      tls_issuer: event.tls?.issuerdn,
      flow_id: event.flow_id,
      community_id: event.community_id,
      in_iface: event.in_iface,
      signature_id: event.signature_id,
      signature_rev: event.rev,
      gid: event.gid,
      action: event.action,
      app_proto: event.app_proto,
      flow_bytes_toserver: event.flow?.bytes_toserver,
      flow_bytes_toclient: event.flow?.bytes_toclient,
      flow_pkts_toserver: event.flow?.pkts_toserver,
      flow_pkts_toclient: event.flow?.pkts_toclient,
    },
    sourceIp: event.src_ip,
    destIp: event.dest_ip,
    sourcePort: event.src_port,
    destPort: event.dest_port,
    protocol: event.proto,
    hostname: event.hostname || event.in_iface,
    domain: event.dns?.rrname || event.http?.hostname,
    url: event.http?.url,
    mitreTactic: event.metadata?.mitre_tactic?.[0],
    mitreTechnique: event.metadata?.mitre_technique_id?.[0],
    detectedAt: parseTimestamp(event.timestamp),
  };
}

function normalizeDefender(payload: any): NormalizedAlert {
  const event = payload.alert || payload.evidence || payload;
  return {
    source: "Microsoft Defender",
    sourceEventId: event.alertId || event.id || event.incidentId?.toString() || "",
    category: normalizeCategory(event.category || event.threatFamilyName || "other"),
    severity: normalizeSeverity(event.severity || "medium"),
    title: event.title || event.alertDisplayName || event.name || "Defender Alert",
    description: event.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "defender", timestamp: new Date().toISOString() },
    sourceIp: event.machineIp || event.localIp || event.evidence?.ipAddress,
    destIp: event.remoteIp,
    sourcePort: event.localPort,
    destPort: event.remotePort,
    hostname: event.computerDnsName || event.machineName || event.deviceName,
    userId: event.userPrincipalName || event.accountName,
    fileHash: event.sha256 || event.sha1 || event.md5,
    url: event.url || event.remoteUrl,
    domain: event.domainName,
    mitreTactic: event.mitreTechniques?.[0]?.split(".")?.[0] || event.category,
    mitreTechnique: event.mitreTechniques?.[0],
    detectedAt: parseTimestamp(event.alertCreationTime || event.firstEventTime || event.createdDateTime),
  };
}

function normalizeElastic(payload: any): NormalizedAlert {
  const event = payload.event || payload;
  const rule = payload.rule || event.rule || {};
  const source = payload.source || {};
  const destination = payload.destination || {};
  const network = payload.network || {};
  const host = payload.host || {};
  const user = payload.user || {};
  const file = payload.file || {};
  const urlObj = payload.url || {};
  const threat = payload.threat || {};
  return {
    source: "Elastic Security",
    sourceEventId: event.id || event.event?.id || "",
    category: normalizeCategory(event.category || event.event?.category || "other"),
    severity: normalizeSeverity(event.severity || event.event?.severity || "medium"),
    title: rule.name || rule.rule?.name || "Elastic Security Alert",
    description: rule.description || rule.rule?.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "elastic", timestamp: new Date().toISOString() },
    sourceIp: source.ip || event.source?.ip,
    destIp: destination.ip || event.destination?.ip,
    sourcePort: parseInt(source.port || event.source?.port) || undefined,
    destPort: parseInt(destination.port || event.destination?.port) || undefined,
    protocol: network.protocol || event.network?.protocol,
    hostname: host.hostname || event.host?.hostname,
    userId: user.name || event.user?.name,
    fileHash: file.hash?.sha256 || event.file?.hash?.sha256,
    url: urlObj.full || event.url?.full,
    domain: extractDomain(urlObj.full || event.url?.full),
    mitreTactic: threat.tactic?.name || event.event?.action,
    mitreTechnique: threat.technique?.id || event.threat?.technique?.id,
    detectedAt: parseTimestamp(payload["@timestamp"] || event.timestamp),
  };
}

function normalizeQRadar(payload: any): NormalizedAlert {
  const event = payload.event || payload;
  const magnitude = parseInt(event.magnitude) || 5;
  const severityStr =
    magnitude >= 9 ? "critical" :
    magnitude >= 7 ? "high" :
    magnitude >= 4 ? "medium" :
    magnitude >= 2 ? "low" : "informational";
  return {
    source: "IBM QRadar",
    sourceEventId: event.qid?.toString() || event.id?.toString() || "",
    category: normalizeCategory(event.category || "other"),
    severity: normalizeSeverity(severityStr),
    title: event.ruleName || event.rule_name || "QRadar Offense",
    description: event.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "qradar", timestamp: new Date().toISOString() },
    sourceIp: event.sourceIP || event.source_ip,
    destIp: event.destinationIP || event.destination_ip,
    sourcePort: parseInt(event.sourcePort || event.source_port) || undefined,
    destPort: parseInt(event.destinationPort || event.destination_port) || undefined,
    protocol: event.protocol,
    hostname: event.hostName || event.hostname,
    userId: event.username || event.user,
    detectedAt: parseTimestamp(event.startTime || event.start_time || event.timestamp),
  };
}

function normalizeFortiGate(payload: any): NormalizedAlert {
  const event = payload.log || payload;
  return {
    source: "Fortinet FortiGate",
    sourceEventId: event.logid || event.log_id || "",
    category: normalizeCategory(event.type || event.subtype || "other"),
    severity: normalizeSeverity(event.level || "medium"),
    title: event.attack || event.msg || event.action || "FortiGate Alert",
    description: event.msg || event.message || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "fortigate", timestamp: new Date().toISOString() },
    sourceIp: event.srcip || event.src,
    destIp: event.dstip || event.dst,
    sourcePort: parseInt(event.srcport) || undefined,
    destPort: parseInt(event.dstport) || undefined,
    protocol: event.proto || event.protocol,
    hostname: event.hostname || event.devname,
    userId: event.user || event.srcuser,
    url: event.url,
    domain: extractDomain(event.url),
    detectedAt: parseTimestamp(event.eventtime || event.date + " " + event.time || event.timestamp),
  };
}

function normalizeCarbonBlack(payload: any): NormalizedAlert {
  const event = payload.alert || payload;
  const severity = parseInt(event.severity) || 5;
  const severityStr =
    severity >= 9 ? "critical" :
    severity >= 7 ? "high" :
    severity >= 4 ? "medium" :
    severity >= 2 ? "low" : "informational";
  return {
    source: "Carbon Black EDR",
    sourceEventId: event.id?.toString() || event.alert_id?.toString() || "",
    category: normalizeCategory(event.type || event.reason || "other"),
    severity: normalizeSeverity(severityStr),
    title: event.reason || event.type || "Carbon Black Alert",
    description: event.description || event.reason || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "carbonblack", timestamp: new Date().toISOString() },
    sourceIp: event.device_external_ip || event.device_internal_ip,
    destIp: event.netconn_remote_ip,
    hostname: event.device_name || event.hostname,
    userId: event.device_username || event.user,
    fileHash: event.process_sha256 || event.md5,
    domain: event.netconn_domain,
    mitreTactic: event.threat_id,
    mitreTechnique: event.ioc_hit,
    detectedAt: parseTimestamp(event.create_time || event.timestamp),
  };
}

function normalizeQualys(payload: any): NormalizedAlert {
  const event = payload.vulnerability || payload;
  const severity = parseInt(event.severity) || 3;
  const severityStr =
    severity >= 5 ? "critical" :
    severity >= 4 ? "high" :
    severity >= 3 ? "medium" :
    severity >= 2 ? "low" : "informational";
  return {
    source: "Qualys VMDR",
    sourceEventId: event.id?.toString() || event.qid?.toString() || "",
    category: normalizeCategory(event.vulnType || event.category || "other"),
    severity: normalizeSeverity(severityStr),
    title: event.title || event.vuln_title || "Qualys Finding",
    description: event.consequence || event.solution || event.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "qualys", timestamp: new Date().toISOString() },
    sourceIp: event.ip || event.host_ip,
    sourcePort: parseInt(event.port) || undefined,
    protocol: event.protocol,
    hostname: event.fqdn || event.hostname || event.os,
    url: event.cveList ? `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${event.cveList}` : undefined,
    detectedAt: parseTimestamp(event.firstFound || event.first_found || event.timestamp),
  };
}

function normalizeTenable(payload: any): NormalizedAlert {
  const event = payload.vulnerability || payload;
  const plugin = event.plugin || {};
  const asset = event.asset || {};
  const port = event.port || {};
  const severity = parseInt(event.severity ?? plugin.severity) || 2;
  const severityStr =
    severity >= 4 ? "critical" :
    severity >= 3 ? "high" :
    severity >= 2 ? "medium" :
    severity >= 1 ? "low" : "informational";
  return {
    source: "Tenable Nessus",
    sourceEventId: plugin.id?.toString() || event.id?.toString() || "",
    category: normalizeCategory(plugin.family || "other"),
    severity: normalizeSeverity(severityStr),
    title: plugin.name || event.name || "Tenable Finding",
    description: plugin.description || event.output || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "tenable", timestamp: new Date().toISOString() },
    sourceIp: asset.ipv4 || event.ip,
    sourcePort: parseInt(port.port) || undefined,
    protocol: port.protocol,
    hostname: asset.hostname || event.hostname,
    detectedAt: parseTimestamp(event.first_found || event.timestamp),
  };
}

function normalizeCiscoUmbrella(payload: any): NormalizedAlert {
  const event = payload.event || payload;
  return {
    source: "Cisco Umbrella",
    sourceEventId: event.id?.toString() || event.originId?.toString() || "",
    category: normalizeCategory(event.type || event.disposition || "other"),
    severity: normalizeSeverity(event.disposition === "blocked" ? "high" : event.disposition === "allowed" ? "low" : "medium"),
    title: event.type ? `Umbrella ${event.type} Event` : "Cisco Umbrella Alert",
    description: event.categories?.join(", ") || event.disposition || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "umbrella", timestamp: new Date().toISOString() },
    sourceIp: event.internalIp || event.internal_ip,
    destIp: event.externalIp || event.external_ip,
    domain: event.domain,
    detectedAt: parseTimestamp(event.datetime || event.timestamp),
  };
}

function normalizeDarktrace(payload: any): NormalizedAlert {
  const event = payload.breach || payload;
  const model = event.model || {};
  const device = event.device || {};
  const score = parseInt(event.score) || 50;
  const severityStr =
    score >= 80 ? "critical" :
    score >= 60 ? "high" :
    score >= 40 ? "medium" :
    score >= 20 ? "low" : "informational";
  return {
    source: "Darktrace",
    sourceEventId: event.pbid?.toString() || event.id?.toString() || "",
    category: normalizeCategory(model.name || "other"),
    severity: normalizeSeverity(severityStr),
    title: model.name || "Darktrace Model Breach",
    description: model.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "darktrace", timestamp: new Date().toISOString() },
    sourceIp: device.ip || event.device_ip,
    hostname: device.hostname || device.label || event.device_hostname,
    mitreTactic: event.mitreTechniques?.[0]?.tactic,
    mitreTechnique: event.mitreTechniques?.[0]?.technique,
    detectedAt: parseTimestamp(event.createdAt || event.created_at || event.timestamp),
  };
}

function normalizeRapid7(payload: any): NormalizedAlert {
  const event = payload.investigation || payload;
  const priorityMap: Record<string, string> = {
    low: "low",
    medium: "medium",
    high: "high",
    critical: "critical",
  };
  return {
    source: "Rapid7 InsightIDR",
    sourceEventId: event.id?.toString() || event.rrn || "",
    category: normalizeCategory(event.source || event.type || "other"),
    severity: normalizeSeverity(priorityMap[(event.priority || "").toLowerCase()] || "medium"),
    title: event.name || event.title || "Rapid7 Investigation",
    description: event.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "rapid7", timestamp: new Date().toISOString() },
    userId: event.assignee || event.assigned_to,
    mitreTactic: event.detection_rule,
    detectedAt: parseTimestamp(event.created_time || event.created_at || event.timestamp),
  };
}

function normalizeTrendMicro(payload: any): NormalizedAlert {
  const event = payload.alert || payload;
  return {
    source: "Trend Micro Vision One",
    sourceEventId: event.id?.toString() || "",
    category: normalizeCategory(event.model || event.type || "other"),
    severity: normalizeSeverity(event.filterRiskLevel || event.severity || "medium"),
    title: event.model || event.name || "Trend Micro Alert",
    description: event.description || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "trendmicro", timestamp: new Date().toISOString() },
    sourceIp: event.srcIp || event.src_ip,
    destIp: event.dstIp || event.dst_ip,
    sourcePort: parseInt(event.srcPort || event.src_port) || undefined,
    destPort: parseInt(event.dstPort || event.dst_port) || undefined,
    hostname: event.endpointHostName || event.hostname,
    mitreTactic: event.matchedRules?.[0]?.name,
    mitreTechnique: event.matchedRules?.[0]?.id,
    detectedAt: parseTimestamp(event.createdDateTime || event.created_at || event.timestamp),
  };
}

function normalizeOkta(payload: any): NormalizedAlert {
  const event = payload.event || payload;
  const actor = event.actor || {};
  const client = event.client || {};
  const outcome = event.outcome || {};
  const target = event.target?.[0] || {};
  const severityMap: Record<string, string> = {
    debug: "informational",
    info: "low",
    warn: "medium",
    error: "high",
  };
  return {
    source: "Okta Identity",
    sourceEventId: event.uuid || event.id || "",
    category: normalizeCategory(event.eventType || "other"),
    severity: normalizeSeverity(severityMap[(event.severity || "").toLowerCase()] || "medium"),
    title: event.displayMessage || event.eventType || "Okta Event",
    description: `${event.displayMessage || ""} - Actor: ${actor.displayName || actor.alternateId || "unknown"} - Outcome: ${outcome.result || "unknown"}`,
    rawData: payload,
    normalizedData: { normalized: true, source: "okta", timestamp: new Date().toISOString() },
    sourceIp: client.ipAddress || event.client?.ipAddress,
    userId: actor.alternateId || actor.displayName,
    hostname: target.displayName,
    detectedAt: parseTimestamp(event.published || event.timestamp),
  };
}

function normalizeProofpoint(payload: any): NormalizedAlert {
  const event = payload.message || payload;
  const threatInfo = event.threatsInfoMap?.[0] || {};
  const spamScore = parseInt(event.spamScore) || 0;
  const phishScore = parseInt(event.phishScore) || 0;
  const maxScore = Math.max(spamScore, phishScore);
  const severityStr =
    maxScore >= 90 ? "critical" :
    maxScore >= 70 ? "high" :
    maxScore >= 40 ? "medium" :
    maxScore >= 10 ? "low" : "informational";
  return {
    source: "Proofpoint Email",
    sourceEventId: event.GUID || event.guid || event.id || "",
    category: normalizeCategory(event.classification || threatInfo.threatType || "phishing"),
    severity: normalizeSeverity(severityStr),
    title: event.subject || threatInfo.threat || "Proofpoint Email Threat",
    description: `Classification: ${event.classification || "unknown"} - Threat: ${threatInfo.threat || "none"} - Sender: ${event.sender || "unknown"}`,
    rawData: payload,
    normalizedData: { normalized: true, source: "proofpoint", timestamp: new Date().toISOString() },
    sourceIp: event.senderIP || event.sender_ip,
    userId: event.recipient || event.sender,
    url: threatInfo.threatUrl || threatInfo.url,
    domain: extractDomain(threatInfo.threatUrl || event.sender),
    detectedAt: parseTimestamp(event.messageTime || event.message_time || event.timestamp),
  };
}

function normalizeSnort(payload: any): NormalizedAlert {
  const event = payload.alert || payload;
  return {
    source: "Snort IDS",
    sourceEventId: event.signature_id?.toString() || event.sid?.toString() || "",
    category: normalizeCategory(event.classification || "intrusion"),
    severity: normalizeSeverity(
      event.priority === 1 ? "critical" :
      event.priority === 2 ? "high" :
      event.priority === 3 ? "medium" : "low"
    ),
    title: event.signature || event.msg || "Snort Alert",
    description: event.classification || event.signature || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "snort", timestamp: new Date().toISOString() },
    sourceIp: event.src_addr || event.src_ip,
    destIp: event.dst_addr || event.dst_ip,
    sourcePort: parseInt(event.src_port) || undefined,
    destPort: parseInt(event.dst_port) || undefined,
    protocol: event.proto || event.protocol,
    detectedAt: parseTimestamp(event.timestamp),
  };
}

function normalizeZscaler(payload: any): NormalizedAlert {
  const event = payload.event || payload;
  return {
    source: "Zscaler ZIA",
    sourceEventId: event.recordid?.toString() || event.id?.toString() || "",
    category: normalizeCategory(event.category || event.action || "other"),
    severity: normalizeSeverity(event.severity || "medium"),
    title: event.threatname || event.action || "Zscaler Alert",
    description: `Category: ${event.category || "unknown"} - Action: ${event.action || "unknown"} - Department: ${event.department || "unknown"}`,
    rawData: payload,
    normalizedData: { normalized: true, source: "zscaler", timestamp: new Date().toISOString() },
    sourceIp: event.srcip || event.clientpublicIP,
    destIp: event.dstip || event.serverip,
    userId: event.user || event.login,
    hostname: event.hostname || event.devicename,
    url: event.url,
    domain: extractDomain(event.url),
    detectedAt: parseTimestamp(event.datetime || event.timestamp),
  };
}

function normalizeCheckPoint(payload: any): NormalizedAlert {
  const event = payload.log || payload;
  return {
    source: "Check Point",
    sourceEventId: event.loguid || event.log_id || "",
    category: normalizeCategory(event.blade || event.product || "other"),
    severity: normalizeSeverity(event.severity || "medium"),
    title: event.rule_name || event.attack || event.product || "Check Point Alert",
    description: event.description || event.attack_info || event.attack || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "checkpoint", timestamp: new Date().toISOString() },
    sourceIp: event.src || event.source_ip,
    destIp: event.dst || event.destination_ip,
    sourcePort: parseInt(event.s_port || event.source_port) || undefined,
    destPort: parseInt(event.service || event.dest_port) || undefined,
    protocol: event.proto || event.protocol,
    hostname: event.origin || event.hostname,
    mitreTactic: event.attack,
    mitreTechnique: event.attack_info,
    detectedAt: parseTimestamp(event.time || event.timestamp),
  };
}

function normalizeCustom(payload: any): NormalizedAlert {
  return {
    source: "Custom",
    sourceEventId: payload.event_id || payload.id || "",
    category: normalizeCategory(payload.category || "other"),
    severity: normalizeSeverity(payload.severity || "medium"),
    title: payload.title || payload.name || "Custom Alert",
    description: payload.description || payload.message || "",
    rawData: payload,
    normalizedData: { normalized: true, source: "custom", timestamp: new Date().toISOString() },
    sourceIp: payload.source_ip || payload.src_ip,
    destIp: payload.dest_ip || payload.dst_ip,
    sourcePort: parseInt(payload.source_port) || undefined,
    destPort: parseInt(payload.dest_port) || undefined,
    protocol: payload.protocol,
    hostname: payload.hostname,
    userId: payload.user_id || payload.user,
    fileHash: payload.file_hash || payload.hash,
    url: payload.url,
    domain: payload.domain || extractDomain(payload.url),
    mitreTactic: payload.mitre_tactic,
    mitreTechnique: payload.mitre_technique,
    detectedAt: parseTimestamp(payload.detected_at || payload.timestamp),
  };
}

const NORMALIZERS: Record<string, (payload: any) => NormalizedAlert> = {
  crowdstrike: normalizeCrowdStrike,
  splunk: normalizeSplunk,
  paloalto: normalizePaloAlto,
  guardduty: normalizeGuardDuty,
  suricata: normalizeSuricata,
  defender: normalizeDefender,
  elastic: normalizeElastic,
  qradar: normalizeQRadar,
  fortigate: normalizeFortiGate,
  carbonblack: normalizeCarbonBlack,
  qualys: normalizeQualys,
  tenable: normalizeTenable,
  umbrella: normalizeCiscoUmbrella,
  darktrace: normalizeDarktrace,
  rapid7: normalizeRapid7,
  trendmicro: normalizeTrendMicro,
  okta: normalizeOkta,
  proofpoint: normalizeProofpoint,
  snort: normalizeSnort,
  zscaler: normalizeZscaler,
  checkpoint: normalizeCheckPoint,
  custom: normalizeCustom,
};

export const SOURCE_KEYS = Object.keys(NORMALIZERS);

export function normalizeAlert(source: string, payload: any): NormalizedAlert {
  const key = source.toLowerCase().replace(/[\s\-_]/g, "");
  const normalizer = Object.entries(NORMALIZERS).find(([k]) =>
    key.includes(k)
  );
  if (normalizer) return normalizer[1](payload);
  return normalizeCustom(payload);
}

export function toInsertAlert(normalized: NormalizedAlert, orgId?: string): InsertAlert {
  const ocsfData = toOCSFSecurityFinding(normalized);

  return {
    orgId: orgId || null,
    source: normalized.source,
    sourceEventId: normalized.sourceEventId || null,
    category: normalized.category,
    severity: normalized.severity,
    title: normalized.title.slice(0, 500),
    description: normalized.description?.slice(0, 5000) || null,
    rawData: normalized.rawData,
    normalizedData: normalized.normalizedData,
    ocsfData,
    sourceIp: normalized.sourceIp || null,
    destIp: normalized.destIp || null,
    sourcePort: normalized.sourcePort || null,
    destPort: normalized.destPort || null,
    protocol: normalized.protocol || null,
    userId: normalized.userId || null,
    hostname: normalized.hostname || null,
    fileHash: normalized.fileHash || null,
    url: normalized.url || null,
    domain: normalized.domain || null,
    mitreTactic: normalized.mitreTactic || null,
    mitreTechnique: normalized.mitreTechnique || null,
    status: "new",
    detectedAt: normalized.detectedAt || null,
  };
}
