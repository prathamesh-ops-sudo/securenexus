import { randomUUID } from "crypto";

export type ActionClass = "READ" | "SUGGEST" | "EXECUTE_WITH_APPROVAL" | "AUTO_EXECUTE_LOW_RISK";

export type TriageVerdict = "true_positive" | "false_positive" | "needs_investigation" | "benign";
export type HypothesisConfidence = "high" | "medium" | "low";
export type ActionStatus = "pending_approval" | "approved" | "rejected" | "executed" | "rolled_back" | "auto_executed";
export type FeedbackOutcome = "accepted" | "overridden" | "dismissed";
export type CopilotDomain = "triage" | "timeline" | "hypothesis" | "enrichment" | "policy";

export interface TriageSummary {
  id: string;
  orgId: string;
  alertId: string;
  alertTitle: string;
  severity: string;
  verdict: TriageVerdict;
  confidence: number;
  summary: string;
  keyIndicators: string[];
  recommendedActions: string[];
  relatedAlertIds: string[];
  analystNotes: string;
  createdAt: string;
  updatedAt: string;
}

export interface CorrelatedTimeline {
  id: string;
  orgId: string;
  incidentId: string;
  incidentTitle: string;
  entries: TimelineEntry[];
  generatedAt: string;
  scope: string;
  totalDurationMs: number;
}

export interface TimelineEntry {
  timestamp: string;
  source: string;
  eventType: string;
  description: string;
  severity: string;
  entityId: string | null;
  entityType: string | null;
  rawRef: string | null;
}

export interface IncidentHypothesis {
  id: string;
  orgId: string;
  incidentId: string;
  incidentTitle: string;
  hypothesis: string;
  confidence: HypothesisConfidence;
  confidenceScore: number;
  supportingEvidence: string[];
  attackTechniques: string[];
  suggestedInvestigationSteps: string[];
  status: "active" | "confirmed" | "rejected" | "superseded";
  analystFeedback: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AutonomousAction {
  id: string;
  orgId: string;
  actionClass: ActionClass;
  name: string;
  description: string;
  targetEntity: string;
  targetEntityType: string;
  confidenceScore: number;
  confidenceThreshold: number;
  status: ActionStatus;
  rollbackPlan: string;
  rollbackExecuted: boolean;
  executionResult: string | null;
  triggeredBy: string;
  approvedBy: string | null;
  rejectedBy: string | null;
  executedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface FeedbackRecord {
  id: string;
  orgId: string;
  actionId: string;
  actionType: CopilotDomain;
  outcome: FeedbackOutcome;
  analystId: string;
  originalSuggestion: string;
  analystOverride: string | null;
  reason: string;
  impactOnPolicy: string | null;
  createdAt: string;
}

export interface PolicyCalibration {
  id: string;
  orgId: string;
  domain: CopilotDomain;
  policyName: string;
  previousThreshold: number;
  newThreshold: number;
  triggerReason: string;
  feedbackCount: number;
  acceptanceRate: number;
  overrideRate: number;
  calibratedAt: string;
}

export interface CopilotStats {
  totalTriages: number;
  totalTimelines: number;
  totalHypotheses: number;
  totalActions: number;
  autoExecutedActions: number;
  pendingApprovals: number;
  feedbackCount: number;
  acceptanceRate: number;
  overrideRate: number;
  avgConfidence: number;
  byDomain: Record<string, { total: number; accepted: number; overridden: number }>;
  byActionClass: Record<string, { total: number; executed: number; rejected: number }>;
  recentCalibrations: number;
}

function genId(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomFloat(min: number, max: number): number {
  return Math.round((Math.random() * (max - min) + min) * 100) / 100;
}

const orgTriageStore = new Map<string, TriageSummary[]>();
const orgTimelineStore = new Map<string, CorrelatedTimeline[]>();
const orgHypothesisStore = new Map<string, IncidentHypothesis[]>();
const orgActionStore = new Map<string, AutonomousAction[]>();
const orgFeedbackStore = new Map<string, FeedbackRecord[]>();
const orgCalibrationStore = new Map<string, PolicyCalibration[]>();

function getTriages(orgId: string): TriageSummary[] {
  if (!orgTriageStore.has(orgId)) {
    orgTriageStore.set(orgId, seedTriages(orgId));
  }
  return orgTriageStore.get(orgId)!;
}

function getTimelines(orgId: string): CorrelatedTimeline[] {
  if (!orgTimelineStore.has(orgId)) {
    orgTimelineStore.set(orgId, seedTimelines(orgId));
  }
  return orgTimelineStore.get(orgId)!;
}

function getHypotheses(orgId: string): IncidentHypothesis[] {
  if (!orgHypothesisStore.has(orgId)) {
    orgHypothesisStore.set(orgId, seedHypotheses(orgId));
  }
  return orgHypothesisStore.get(orgId)!;
}

function getActions(orgId: string): AutonomousAction[] {
  if (!orgActionStore.has(orgId)) {
    orgActionStore.set(orgId, seedActions(orgId));
  }
  return orgActionStore.get(orgId)!;
}

function getFeedback(orgId: string): FeedbackRecord[] {
  if (!orgFeedbackStore.has(orgId)) {
    orgFeedbackStore.set(orgId, seedFeedback(orgId));
  }
  return orgFeedbackStore.get(orgId)!;
}

function getCalibrations(orgId: string): PolicyCalibration[] {
  if (!orgCalibrationStore.has(orgId)) {
    orgCalibrationStore.set(orgId, seedCalibrations(orgId));
  }
  return orgCalibrationStore.get(orgId)!;
}

function seedTriages(orgId: string): TriageSummary[] {
  const now = Date.now();
  const alerts = [
    {
      id: "ALT-4821",
      title: "Suspicious outbound connection to known C2 server",
      severity: "critical",
      verdict: "true_positive" as TriageVerdict,
      confidence: 0.94,
      summary:
        "Endpoint ws-prod-17 initiated a TLS connection to 185.220.101.42:443, a known Cobalt Strike C2 address flagged by 3 threat intel feeds. The connection occurred outside business hours and transferred 2.4MB of data. Process tree shows powershell.exe spawned from a Word macro.",
      keyIndicators: [
        "Known C2 IP (185.220.101.42) matched in 3 feeds",
        "Off-hours connection (02:14 UTC)",
        "PowerShell spawned from winword.exe",
        "2.4MB data exfiltrated",
      ],
      recommendedActions: [
        "Isolate endpoint ws-prod-17 immediately",
        "Block IP 185.220.101.42 at perimeter firewall",
        "Collect memory dump for forensic analysis",
        "Check lateral movement from ws-prod-17",
      ],
      relatedAlertIds: ["ALT-4819", "ALT-4820"],
    },
    {
      id: "ALT-4835",
      title: "Multiple failed SSH login attempts from external IP",
      severity: "high",
      verdict: "needs_investigation" as TriageVerdict,
      confidence: 0.72,
      summary:
        "42 failed SSH login attempts detected from 103.24.77.19 targeting bastion-01 over 15 minutes. The IP is not in any threat intel feed but originates from a cloud provider ASN commonly used for scanning. No successful authentication detected yet.",
      keyIndicators: [
        "42 failed attempts in 15 minutes",
        "Source IP from cloud provider ASN",
        "Targeting root and common service accounts",
        "No successful login detected",
      ],
      recommendedActions: [
        "Add IP to temporary blocklist (24h)",
        "Review bastion SSH key rotation status",
        "Check for concurrent attacks on other entry points",
        "Verify fail2ban is active on bastion-01",
      ],
      relatedAlertIds: ["ALT-4830"],
    },
    {
      id: "ALT-4847",
      title: "AWS IAM role assumption from unusual region",
      severity: "medium",
      verdict: "false_positive" as TriageVerdict,
      confidence: 0.88,
      summary:
        "IAM role data-pipeline-prod was assumed from eu-west-1, which is outside the normal us-east-1 usage pattern. Investigation shows this coincides with a scheduled DR failover drill documented in the change management system (CHG-2841).",
      keyIndicators: [
        "Role assumed from unexpected region eu-west-1",
        "Coincides with CHG-2841 DR drill",
        "Service principal matches known pipeline",
        "No privilege escalation attempted",
      ],
      recommendedActions: [
        "Close alert — matches approved change CHG-2841",
        "Update baseline to include eu-west-1 for DR drills",
        "Add change-management correlation to future detections",
      ],
      relatedAlertIds: [],
    },
    {
      id: "ALT-4862",
      title: "DNS tunneling pattern detected",
      severity: "high",
      verdict: "true_positive" as TriageVerdict,
      confidence: 0.85,
      summary:
        "Endpoint dev-laptop-09 generated 1,847 DNS TXT queries to subdomains of xf7k.attacker-infra.net over 30 minutes. Query entropy analysis (4.7 bits/char) and payload size (avg 180 bytes) are consistent with DNS tunneling for data exfiltration. User is a contractor with elevated access.",
      keyIndicators: [
        "1,847 DNS TXT queries in 30 minutes",
        "High entropy subdomain names (4.7 bits/char)",
        "Domain registered 48 hours ago",
        "User is contractor with elevated access",
      ],
      recommendedActions: [
        "Block domain xf7k.attacker-infra.net at DNS resolver",
        "Suspend contractor access pending investigation",
        "Analyze DNS payload content for exfiltrated data",
        "Review all contractor access patterns for past 72 hours",
      ],
      relatedAlertIds: ["ALT-4858", "ALT-4860"],
    },
    {
      id: "ALT-4879",
      title: "Endpoint AV disabled by local admin",
      severity: "low",
      verdict: "benign" as TriageVerdict,
      confidence: 0.91,
      summary:
        "Windows Defender real-time protection was disabled on build-server-03 by local admin account svc-build. This server is in the CI/CD build farm where AV is routinely disabled during compilation to avoid false positives on build artifacts. This matches the approved exception policy EXC-0042.",
      keyIndicators: [
        "Matches approved exception EXC-0042",
        "Build server in CI/CD farm",
        "Disabled by known service account",
        "Re-enabled after 4-hour build window",
      ],
      recommendedActions: ["Close alert — matches exception policy", "Verify re-enablement after build window"],
      relatedAlertIds: [],
    },
  ];

  return alerts.map((a, i) => ({
    id: genId("triage"),
    orgId,
    alertId: a.id,
    alertTitle: a.title,
    severity: a.severity,
    verdict: a.verdict,
    confidence: a.confidence,
    summary: a.summary,
    keyIndicators: a.keyIndicators,
    recommendedActions: a.recommendedActions,
    relatedAlertIds: a.relatedAlertIds,
    analystNotes: "",
    createdAt: new Date(now - randomBetween(3600000, 86400000 * 3) - i * 3600000).toISOString(),
    updatedAt: new Date(now - randomBetween(0, 3600000)).toISOString(),
  }));
}

function seedTimelines(orgId: string): CorrelatedTimeline[] {
  const now = Date.now();
  return [
    {
      id: genId("tl"),
      orgId,
      incidentId: "INC-0847",
      incidentTitle: "Cobalt Strike C2 Beaconing — Endpoint Compromise",
      entries: [
        {
          timestamp: new Date(now - 86400000 * 2 - 3600000 * 8).toISOString(),
          source: "email-gateway",
          eventType: "email_received",
          description: "Phishing email with macro-enabled Word attachment delivered to user j.martinez@corp.local",
          severity: "medium",
          entityId: "j.martinez@corp.local",
          entityType: "user",
          rawRef: "MSG-28471",
        },
        {
          timestamp: new Date(now - 86400000 * 2 - 3600000 * 7.5).toISOString(),
          source: "endpoint-edr",
          eventType: "process_creation",
          description: "winword.exe spawned powershell.exe with encoded command on ws-prod-17",
          severity: "high",
          entityId: "ws-prod-17",
          entityType: "endpoint",
          rawRef: "EDR-94821",
        },
        {
          timestamp: new Date(now - 86400000 * 2 - 3600000 * 7.4).toISOString(),
          source: "endpoint-edr",
          eventType: "file_creation",
          description: "Dropper created C:\\Users\\jmartinez\\AppData\\Local\\Temp\\svchost.exe (unsigned binary)",
          severity: "critical",
          entityId: "ws-prod-17",
          entityType: "endpoint",
          rawRef: "EDR-94822",
        },
        {
          timestamp: new Date(now - 86400000 * 2 - 3600000 * 7).toISOString(),
          source: "network-ids",
          eventType: "c2_beacon",
          description: "TLS connection established to 185.220.101.42:443 — Cobalt Strike beacon profile matched",
          severity: "critical",
          entityId: "185.220.101.42",
          entityType: "ip",
          rawRef: "IDS-77423",
        },
        {
          timestamp: new Date(now - 86400000 * 2 - 3600000 * 5).toISOString(),
          source: "ad-logs",
          eventType: "lateral_movement",
          description: "Pass-the-hash authentication from ws-prod-17 to file-server-02 using stolen NTLM hash",
          severity: "critical",
          entityId: "file-server-02",
          entityType: "endpoint",
          rawRef: "AD-18294",
        },
        {
          timestamp: new Date(now - 86400000 * 2 - 3600000 * 4).toISOString(),
          source: "dlp",
          eventType: "data_exfiltration",
          description: "2.4MB transferred to external C2 — file contents match financial reports directory",
          severity: "critical",
          entityId: "185.220.101.42",
          entityType: "ip",
          rawRef: "DLP-5821",
        },
      ],
      generatedAt: new Date(now - 3600000 * 2).toISOString(),
      scope: "Full kill chain from initial access through exfiltration",
      totalDurationMs: 3600000 * 4,
    },
    {
      id: genId("tl"),
      orgId,
      incidentId: "INC-0851",
      incidentTitle: "Brute Force Campaign Against Bastion Hosts",
      entries: [
        {
          timestamp: new Date(now - 86400000 - 3600000 * 6).toISOString(),
          source: "firewall",
          eventType: "connection_attempt",
          description: "Spike in SSH connections from 103.24.77.0/24 subnet targeting bastion-01 and bastion-02",
          severity: "medium",
          entityId: "103.24.77.19",
          entityType: "ip",
          rawRef: "FW-42891",
        },
        {
          timestamp: new Date(now - 86400000 - 3600000 * 5.5).toISOString(),
          source: "sshd-logs",
          eventType: "auth_failure",
          description: "42 failed SSH login attempts — targeting root, admin, ubuntu, deploy accounts",
          severity: "high",
          entityId: "bastion-01",
          entityType: "endpoint",
          rawRef: "SSH-7742",
        },
        {
          timestamp: new Date(now - 86400000 - 3600000 * 5).toISOString(),
          source: "fail2ban",
          eventType: "auto_block",
          description: "fail2ban triggered — blocked 103.24.77.19 for 24 hours after 10 failed attempts",
          severity: "low",
          entityId: "bastion-01",
          entityType: "endpoint",
          rawRef: "F2B-1142",
        },
        {
          timestamp: new Date(now - 86400000 - 3600000 * 4.5).toISOString(),
          source: "firewall",
          eventType: "connection_attempt",
          description: "Attacker rotated to 103.24.77.22 — continuing brute force from new IP in same subnet",
          severity: "high",
          entityId: "103.24.77.22",
          entityType: "ip",
          rawRef: "FW-42903",
        },
      ],
      generatedAt: new Date(now - 3600000).toISOString(),
      scope: "Brute force campaign with IP rotation",
      totalDurationMs: 3600000 * 1.5,
    },
  ];
}

function seedHypotheses(orgId: string): IncidentHypothesis[] {
  const now = Date.now();
  return [
    {
      id: genId("hyp"),
      orgId,
      incidentId: "INC-0847",
      incidentTitle: "Cobalt Strike C2 Beaconing — Endpoint Compromise",
      hypothesis:
        "Targeted spear-phishing campaign delivering Cobalt Strike via macro-enabled documents, with the objective of financial data exfiltration. The attacker likely has prior knowledge of the organization's structure based on the targeted user selection.",
      confidence: "high",
      confidenceScore: 0.91,
      supportingEvidence: [
        "Phishing email targeted a finance team member specifically",
        "Cobalt Strike malleable C2 profile matched known APT group signatures",
        "Exfiltrated data originated from financial reports directory",
        "C2 infrastructure registered 72 hours before the attack",
      ],
      attackTechniques: [
        "T1566.001 - Spearphishing Attachment",
        "T1059.001 - PowerShell",
        "T1071.001 - Web Protocols",
        "T1550.002 - Pass the Hash",
      ],
      suggestedInvestigationSteps: [
        "Check if other finance team members received similar phishing emails",
        "Analyze Cobalt Strike malleable profile for attribution indicators",
        "Investigate C2 domain registration for WHOIS and hosting patterns",
        "Review file-server-02 access logs for additional data staging",
        "Determine if credential harvesting occurred beyond the initial compromise",
      ],
      status: "active",
      analystFeedback: null,
      createdAt: new Date(now - 86400000 * 2).toISOString(),
      updatedAt: new Date(now - 3600000 * 4).toISOString(),
    },
    {
      id: genId("hyp"),
      orgId,
      incidentId: "INC-0847",
      incidentTitle: "Cobalt Strike C2 Beaconing — Endpoint Compromise",
      hypothesis:
        "Opportunistic attack leveraging a commodity phishing kit, with the Cobalt Strike payload being part of an access-broker operation. The attacker may be selling initial access rather than conducting targeted espionage.",
      confidence: "medium",
      confidenceScore: 0.58,
      supportingEvidence: [
        "C2 infrastructure hosted on bulletproof hosting commonly used by access brokers",
        "No persistence mechanisms beyond the initial beacon observed",
        "Lateral movement was automated rather than manually directed",
      ],
      attackTechniques: ["T1566.001 - Spearphishing Attachment", "T1059.001 - PowerShell", "T1071.001 - Web Protocols"],
      suggestedInvestigationSteps: [
        "Search dark web marketplaces for listings matching this infrastructure",
        "Compare C2 profile with known access-broker toolkits",
        "Monitor for secondary actors attempting to use established access",
      ],
      status: "active",
      analystFeedback: null,
      createdAt: new Date(now - 86400000 * 2).toISOString(),
      updatedAt: new Date(now - 3600000 * 4).toISOString(),
    },
    {
      id: genId("hyp"),
      orgId,
      incidentId: "INC-0851",
      incidentTitle: "Brute Force Campaign Against Bastion Hosts",
      hypothesis:
        "Automated credential-stuffing campaign using leaked credentials from a recent breach dump. The attacker is rotating through a cloud provider's IP range to evade IP-based blocking.",
      confidence: "high",
      confidenceScore: 0.82,
      supportingEvidence: [
        "Targeted usernames match common default and service account names",
        "IP rotation within same /24 subnet indicates automated tooling",
        "Attack pattern consistent with Hydra or Medusa brute-force tools",
        "Cloud provider ASN commonly associated with scanning campaigns",
      ],
      attackTechniques: ["T1110.001 - Password Guessing", "T1110.004 - Credential Stuffing", "T1090 - Proxy"],
      suggestedInvestigationSteps: [
        "Cross-reference targeted usernames with recent credential dump databases",
        "Block entire /24 subnet at network perimeter",
        "Audit bastion host SSH configuration for password authentication (should be key-only)",
        "Check VPN and other remote access services for similar patterns",
      ],
      status: "active",
      analystFeedback: null,
      createdAt: new Date(now - 86400000).toISOString(),
      updatedAt: new Date(now - 3600000 * 2).toISOString(),
    },
    {
      id: genId("hyp"),
      orgId,
      incidentId: "INC-0853",
      incidentTitle: "DNS Tunneling Exfiltration",
      hypothesis:
        "Insider threat — contractor with elevated access deliberately exfiltrating sensitive data via DNS tunneling to avoid DLP controls. The recently-registered domain and high entropy suggest purpose-built tunneling infrastructure.",
      confidence: "medium",
      confidenceScore: 0.67,
      supportingEvidence: [
        "Contractor has elevated access to sensitive repositories",
        "DNS tunneling domain registered 48 hours before activity",
        "Activity occurred during contractor's normal working hours",
        "No malware detected — suggests intentional tooling",
      ],
      attackTechniques: [
        "T1048.003 - Exfiltration Over Alternative Protocol",
        "T1071.004 - DNS",
        "T1567 - Exfiltration Over Web Service",
      ],
      suggestedInvestigationSteps: [
        "Interview contractor's manager about recent behavior changes",
        "Review contractor's code commits and repository access for past 30 days",
        "Analyze decoded DNS tunnel payload to determine what data was exfiltrated",
        "Check contractor's personal devices for tunneling tools",
      ],
      status: "active",
      analystFeedback: null,
      createdAt: new Date(now - 86400000 * 0.5).toISOString(),
      updatedAt: new Date(now - 3600000).toISOString(),
    },
  ];
}

function seedActions(orgId: string): AutonomousAction[] {
  const now = Date.now();
  return [
    {
      id: genId("act"),
      orgId,
      actionClass: "AUTO_EXECUTE_LOW_RISK",
      name: "Enrich IP reputation — 185.220.101.42",
      description: "Query VirusTotal, AbuseIPDB, and Shodan for reputation data on C2 IP address",
      targetEntity: "185.220.101.42",
      targetEntityType: "ip",
      confidenceScore: 0.98,
      confidenceThreshold: 0.7,
      status: "auto_executed",
      rollbackPlan: "No rollback needed — read-only enrichment action",
      rollbackExecuted: false,
      executionResult:
        "VirusTotal: 47/90 malicious | AbuseIPDB: 100% confidence score | Shodan: Cobalt Strike C2 on port 443",
      triggeredBy: "copilot-auto",
      approvedBy: null,
      rejectedBy: null,
      executedAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
      createdAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
      updatedAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "AUTO_EXECUTE_LOW_RISK",
      name: "WHOIS lookup — xf7k.attacker-infra.net",
      description: "Perform WHOIS and passive DNS lookup on suspicious DNS tunneling domain",
      targetEntity: "xf7k.attacker-infra.net",
      targetEntityType: "domain",
      confidenceScore: 0.95,
      confidenceThreshold: 0.7,
      status: "auto_executed",
      rollbackPlan: "No rollback needed — read-only enrichment action",
      rollbackExecuted: false,
      executionResult:
        "Registered 48h ago via Namecheap | Privacy-protected WHOIS | NS: ns1.bulletproof-dns.com | No historical DNS records",
      triggeredBy: "copilot-auto",
      approvedBy: null,
      rejectedBy: null,
      executedAt: new Date(now - 86400000 * 0.5).toISOString(),
      createdAt: new Date(now - 86400000 * 0.5).toISOString(),
      updatedAt: new Date(now - 86400000 * 0.5).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "AUTO_EXECUTE_LOW_RISK",
      name: "GeoIP enrichment — 103.24.77.19",
      description: "Resolve geolocation, ASN, and hosting provider for brute-force source IP",
      targetEntity: "103.24.77.19",
      targetEntityType: "ip",
      confidenceScore: 0.99,
      confidenceThreshold: 0.7,
      status: "auto_executed",
      rollbackPlan: "No rollback needed — read-only enrichment action",
      rollbackExecuted: false,
      executionResult:
        "Location: Singapore | ASN: AS136907 (Huawei Cloud) | Hosting: Cloud VPS | Abuse contact: abuse@huaweicloud.com",
      triggeredBy: "copilot-auto",
      approvedBy: null,
      rejectedBy: null,
      executedAt: new Date(now - 86400000 - 3600000 * 5).toISOString(),
      createdAt: new Date(now - 86400000 - 3600000 * 5).toISOString(),
      updatedAt: new Date(now - 86400000 - 3600000 * 5).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "EXECUTE_WITH_APPROVAL",
      name: "Isolate endpoint ws-prod-17",
      description: "Network-isolate the compromised endpoint via EDR API to contain active C2 beaconing",
      targetEntity: "ws-prod-17",
      targetEntityType: "endpoint",
      confidenceScore: 0.94,
      confidenceThreshold: 0.9,
      status: "approved",
      rollbackPlan: "Re-enable network access via EDR API: POST /api/endpoints/ws-prod-17/unisolate",
      rollbackExecuted: false,
      executionResult: "Endpoint ws-prod-17 isolated successfully — all network connections terminated",
      triggeredBy: "copilot-suggest",
      approvedBy: "analyst-sarah",
      rejectedBy: null,
      executedAt: new Date(now - 86400000 * 2 - 3600000 * 5).toISOString(),
      createdAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
      updatedAt: new Date(now - 86400000 * 2 - 3600000 * 5).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "EXECUTE_WITH_APPROVAL",
      name: "Block C2 IP at perimeter firewall",
      description: "Add 185.220.101.42 to deny-list on perimeter firewall and WAF",
      targetEntity: "185.220.101.42",
      targetEntityType: "ip",
      confidenceScore: 0.97,
      confidenceThreshold: 0.9,
      status: "executed",
      rollbackPlan: "Remove IP from deny-list: DELETE /api/firewall/rules/{rule-id}",
      rollbackExecuted: false,
      executionResult: "IP blocked on firewall (rule FW-8821) and WAF (rule WAF-4412)",
      triggeredBy: "copilot-suggest",
      approvedBy: "analyst-sarah",
      rejectedBy: null,
      executedAt: new Date(now - 86400000 * 2 - 3600000 * 4).toISOString(),
      createdAt: new Date(now - 86400000 * 2 - 3600000 * 5).toISOString(),
      updatedAt: new Date(now - 86400000 * 2 - 3600000 * 4).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "EXECUTE_WITH_APPROVAL",
      name: "Suspend contractor access — dev-laptop-09",
      description: "Disable contractor AD account and revoke VPN certificate pending DNS tunneling investigation",
      targetEntity: "contractor-dev-09",
      targetEntityType: "user",
      confidenceScore: 0.72,
      confidenceThreshold: 0.9,
      status: "pending_approval",
      rollbackPlan: "Re-enable AD account and re-issue VPN certificate: POST /api/iam/users/contractor-dev-09/enable",
      rollbackExecuted: false,
      executionResult: null,
      triggeredBy: "copilot-suggest",
      approvedBy: null,
      rejectedBy: null,
      executedAt: null,
      createdAt: new Date(now - 3600000 * 2).toISOString(),
      updatedAt: new Date(now - 3600000 * 2).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "SUGGEST",
      name: "Block /24 subnet at network perimeter",
      description: "Block entire 103.24.77.0/24 subnet to stop brute-force IP rotation within the same range",
      targetEntity: "103.24.77.0/24",
      targetEntityType: "network",
      confidenceScore: 0.78,
      confidenceThreshold: 0.9,
      status: "pending_approval",
      rollbackPlan: "Remove subnet block rule: DELETE /api/firewall/rules/{rule-id}",
      rollbackExecuted: false,
      executionResult: null,
      triggeredBy: "copilot-suggest",
      approvedBy: null,
      rejectedBy: null,
      executedAt: null,
      createdAt: new Date(now - 86400000 - 3600000 * 4).toISOString(),
      updatedAt: new Date(now - 86400000 - 3600000 * 4).toISOString(),
    },
    {
      id: genId("act"),
      orgId,
      actionClass: "READ",
      name: "Correlate user activity — j.martinez@corp.local",
      description: "Pull 30-day login history, file access patterns, and email activity for compromised user account",
      targetEntity: "j.martinez@corp.local",
      targetEntityType: "user",
      confidenceScore: 1.0,
      confidenceThreshold: 0.0,
      status: "executed",
      rollbackPlan: "No rollback needed — read-only action",
      rollbackExecuted: false,
      executionResult:
        "30-day activity report generated — 3 anomalous file access events detected on financial-reports share",
      triggeredBy: "copilot-auto",
      approvedBy: null,
      rejectedBy: null,
      executedAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
      createdAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
      updatedAt: new Date(now - 86400000 * 2 - 3600000 * 6).toISOString(),
    },
  ];
}

function seedFeedback(orgId: string): FeedbackRecord[] {
  const now = Date.now();
  return [
    {
      id: genId("fb"),
      orgId,
      actionId: "triage-1",
      actionType: "triage",
      outcome: "accepted",
      analystId: "analyst-sarah",
      originalSuggestion: "Verdict: true_positive — Cobalt Strike C2 beaconing confirmed",
      analystOverride: null,
      reason: "Agreed with triage assessment — evidence is conclusive",
      impactOnPolicy: null,
      createdAt: new Date(now - 86400000 * 2).toISOString(),
    },
    {
      id: genId("fb"),
      orgId,
      actionId: "triage-3",
      actionType: "triage",
      outcome: "accepted",
      analystId: "analyst-mike",
      originalSuggestion: "Verdict: false_positive — matches approved DR drill CHG-2841",
      analystOverride: null,
      reason: "Confirmed with change management team",
      impactOnPolicy: "Added eu-west-1 to IAM baseline for DR drill windows",
      createdAt: new Date(now - 86400000).toISOString(),
    },
    {
      id: genId("fb"),
      orgId,
      actionId: "hyp-1",
      actionType: "hypothesis",
      outcome: "accepted",
      analystId: "analyst-sarah",
      originalSuggestion: "Targeted spear-phishing with financial data exfiltration objective",
      analystOverride: null,
      reason: "Evidence strongly supports targeted attack hypothesis over opportunistic",
      impactOnPolicy: null,
      createdAt: new Date(now - 86400000 * 1.5).toISOString(),
    },
    {
      id: genId("fb"),
      orgId,
      actionId: "hyp-2",
      actionType: "hypothesis",
      outcome: "dismissed",
      analystId: "analyst-sarah",
      originalSuggestion: "Access-broker operation selling initial access",
      analystOverride: null,
      reason: "Lateral movement was too targeted for an access broker — rejected this hypothesis",
      impactOnPolicy: "Lowered weight for access-broker hypothesis pattern in similar incidents",
      createdAt: new Date(now - 86400000 * 1.5).toISOString(),
    },
    {
      id: genId("fb"),
      orgId,
      actionId: "action-isolate",
      actionType: "enrichment",
      outcome: "accepted",
      analystId: "analyst-sarah",
      originalSuggestion: "Isolate endpoint ws-prod-17 via EDR",
      analystOverride: null,
      reason: "Approved — active C2 beaconing warrants immediate containment",
      impactOnPolicy: null,
      createdAt: new Date(now - 86400000 * 2).toISOString(),
    },
    {
      id: genId("fb"),
      orgId,
      actionId: "action-block-subnet",
      actionType: "enrichment",
      outcome: "overridden",
      analystId: "analyst-mike",
      originalSuggestion: "Block entire 103.24.77.0/24 subnet",
      analystOverride: "Block only specific IPs 103.24.77.19 and 103.24.77.22 instead of entire /24",
      reason: "Blocking entire /24 may impact legitimate cloud services hosted in same range",
      impactOnPolicy: "Narrowed subnet blocking policy — require /32 blocks unless 5+ IPs from same /24 are malicious",
      createdAt: new Date(now - 86400000).toISOString(),
    },
    {
      id: genId("fb"),
      orgId,
      actionId: "triage-2",
      actionType: "triage",
      outcome: "overridden",
      analystId: "analyst-mike",
      originalSuggestion: "Verdict: needs_investigation",
      analystOverride: "Escalated to true_positive after finding credential match in leaked database",
      reason: "Found targeted usernames in recent breach dump — attack is using stolen credentials, not guessing",
      impactOnPolicy: "Increased confidence threshold for SSH brute-force triages involving cloud IPs",
      createdAt: new Date(now - 86400000 * 0.5).toISOString(),
    },
  ];
}

function seedCalibrations(orgId: string): PolicyCalibration[] {
  const now = Date.now();
  return [
    {
      id: genId("cal"),
      orgId,
      domain: "triage",
      policyName: "SSH Brute-Force Auto-Triage Confidence",
      previousThreshold: 0.65,
      newThreshold: 0.75,
      triggerReason: "Analyst overrides on SSH brute-force triages indicate under-confidence in initial assessments",
      feedbackCount: 12,
      acceptanceRate: 0.58,
      overrideRate: 0.42,
      calibratedAt: new Date(now - 86400000 * 3).toISOString(),
    },
    {
      id: genId("cal"),
      orgId,
      domain: "enrichment",
      policyName: "Subnet Block Scope Policy",
      previousThreshold: 0.7,
      newThreshold: 0.85,
      triggerReason: "Multiple analyst overrides narrowing /24 blocks to individual IPs",
      feedbackCount: 8,
      acceptanceRate: 0.38,
      overrideRate: 0.62,
      calibratedAt: new Date(now - 86400000 * 2).toISOString(),
    },
    {
      id: genId("cal"),
      orgId,
      domain: "hypothesis",
      policyName: "Access-Broker Hypothesis Weight",
      previousThreshold: 0.6,
      newThreshold: 0.45,
      triggerReason: "Analysts consistently dismissing access-broker hypotheses when lateral movement is targeted",
      feedbackCount: 5,
      acceptanceRate: 0.2,
      overrideRate: 0.0,
      calibratedAt: new Date(now - 86400000).toISOString(),
    },
  ];
}

export function getCopilotTriages(
  orgId: string,
  filters?: { verdict?: TriageVerdict; severity?: string },
): TriageSummary[] {
  let results = getTriages(orgId);
  if (filters?.verdict) results = results.filter((t) => t.verdict === filters.verdict);
  if (filters?.severity) results = results.filter((t) => t.severity === filters.severity);
  return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

export function getTriageById(orgId: string, triageId: string): TriageSummary | undefined {
  return getTriages(orgId).find((t) => t.id === triageId);
}

export function generateTriage(orgId: string, alertId: string, alertTitle: string, severity: string): TriageSummary {
  const verdicts: TriageVerdict[] = ["true_positive", "false_positive", "needs_investigation", "benign"];
  const verdict = verdicts[Math.floor(Math.random() * verdicts.length)];
  const confidence = randomFloat(0.55, 0.98);

  const summaryTemplates: Record<TriageVerdict, string> = {
    true_positive: `Alert ${alertId} confirmed as true positive with ${(confidence * 100).toFixed(0)}% confidence. Multiple corroborating indicators detected across endpoint, network, and identity data sources.`,
    false_positive: `Alert ${alertId} assessed as false positive with ${(confidence * 100).toFixed(0)}% confidence. Activity matches known benign pattern or approved change window.`,
    needs_investigation: `Alert ${alertId} requires further investigation. Confidence at ${(confidence * 100).toFixed(0)}% — ambiguous indicators suggest both benign and malicious interpretations are plausible.`,
    benign: `Alert ${alertId} assessed as benign activity with ${(confidence * 100).toFixed(0)}% confidence. Matches expected operational pattern for the affected system.`,
  };

  const triage: TriageSummary = {
    id: genId("triage"),
    orgId,
    alertId,
    alertTitle,
    severity,
    verdict,
    confidence,
    summary: summaryTemplates[verdict],
    keyIndicators: [
      "Behavioral analysis completed across 3 data sources",
      `Alert severity: ${severity}`,
      `Confidence score: ${(confidence * 100).toFixed(0)}%`,
    ],
    recommendedActions:
      verdict === "true_positive"
        ? ["Escalate to incident response", "Contain affected systems", "Preserve evidence"]
        : verdict === "needs_investigation"
          ? ["Gather additional context", "Correlate with recent alerts", "Review affected user activity"]
          : ["Close alert with documented rationale"],
    relatedAlertIds: [],
    analystNotes: "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  getTriages(orgId).unshift(triage);
  return triage;
}

export function updateTriageNotes(orgId: string, triageId: string, notes: string): TriageSummary | null {
  const triage = getTriages(orgId).find((t) => t.id === triageId);
  if (!triage) return null;
  triage.analystNotes = notes;
  triage.updatedAt = new Date().toISOString();
  return triage;
}

export function getCopilotTimelines(orgId: string): CorrelatedTimeline[] {
  return getTimelines(orgId).sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());
}

export function getTimelineById(orgId: string, timelineId: string): CorrelatedTimeline | undefined {
  return getTimelines(orgId).find((t) => t.id === timelineId);
}

export function getCopilotHypotheses(
  orgId: string,
  filters?: { incidentId?: string; confidence?: HypothesisConfidence; status?: string },
): IncidentHypothesis[] {
  let results = getHypotheses(orgId);
  if (filters?.incidentId) results = results.filter((h) => h.incidentId === filters.incidentId);
  if (filters?.confidence) results = results.filter((h) => h.confidence === filters.confidence);
  if (filters?.status) results = results.filter((h) => h.status === filters.status);
  return results.sort((a, b) => b.confidenceScore - a.confidenceScore);
}

export function updateHypothesisStatus(
  orgId: string,
  hypothesisId: string,
  status: IncidentHypothesis["status"],
  feedback?: string,
): IncidentHypothesis | null {
  const hyp = getHypotheses(orgId).find((h) => h.id === hypothesisId);
  if (!hyp) return null;
  hyp.status = status;
  if (feedback !== undefined) hyp.analystFeedback = feedback;
  hyp.updatedAt = new Date().toISOString();
  return hyp;
}

export function getCopilotActions(
  orgId: string,
  filters?: { actionClass?: ActionClass; status?: ActionStatus },
): AutonomousAction[] {
  let results = getActions(orgId);
  if (filters?.actionClass) results = results.filter((a) => a.actionClass === filters.actionClass);
  if (filters?.status) results = results.filter((a) => a.status === filters.status);
  return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

export function approveAction(orgId: string, actionId: string, analystId: string): AutonomousAction | null {
  const action = getActions(orgId).find((a) => a.id === actionId);
  if (!action) return null;
  if (action.status !== "pending_approval") return null;
  action.status = "approved";
  action.approvedBy = analystId;
  action.executedAt = new Date().toISOString();
  action.executionResult = `Action approved and executed by ${analystId}`;
  action.updatedAt = new Date().toISOString();
  return action;
}

export function rejectAction(orgId: string, actionId: string, analystId: string): AutonomousAction | null {
  const action = getActions(orgId).find((a) => a.id === actionId);
  if (!action) return null;
  if (action.status !== "pending_approval") return null;
  action.status = "rejected";
  action.rejectedBy = analystId;
  action.updatedAt = new Date().toISOString();
  return action;
}

export function rollbackAction(orgId: string, actionId: string): AutonomousAction | null {
  const action = getActions(orgId).find((a) => a.id === actionId);
  if (!action) return null;
  if (action.status !== "executed" && action.status !== "approved" && action.status !== "auto_executed") return null;
  action.status = "rolled_back";
  action.rollbackExecuted = true;
  action.updatedAt = new Date().toISOString();
  return action;
}

export function getCopilotFeedback(
  orgId: string,
  filters?: { actionType?: CopilotDomain; outcome?: FeedbackOutcome },
): FeedbackRecord[] {
  let results = getFeedback(orgId);
  if (filters?.actionType) results = results.filter((f) => f.actionType === filters.actionType);
  if (filters?.outcome) results = results.filter((f) => f.outcome === filters.outcome);
  return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

export function submitFeedback(
  orgId: string,
  data: Omit<FeedbackRecord, "id" | "orgId" | "createdAt">,
): FeedbackRecord {
  const record: FeedbackRecord = {
    id: genId("fb"),
    orgId,
    ...data,
    createdAt: new Date().toISOString(),
  };
  getFeedback(orgId).unshift(record);
  return record;
}

export function getCopilotCalibrations(orgId: string): PolicyCalibration[] {
  return getCalibrations(orgId).sort((a, b) => new Date(b.calibratedAt).getTime() - new Date(a.calibratedAt).getTime());
}

export function getCopilotStats(orgId: string): CopilotStats {
  const triages = getTriages(orgId);
  const timelines = getTimelines(orgId);
  const hypotheses = getHypotheses(orgId);
  const actions = getActions(orgId);
  const feedback = getFeedback(orgId);
  const calibrations = getCalibrations(orgId);

  const accepted = feedback.filter((f) => f.outcome === "accepted").length;
  const overridden = feedback.filter((f) => f.outcome === "overridden").length;
  const total = feedback.length;

  const byDomain: CopilotStats["byDomain"] = {};
  for (const f of feedback) {
    if (!byDomain[f.actionType]) byDomain[f.actionType] = { total: 0, accepted: 0, overridden: 0 };
    byDomain[f.actionType].total++;
    if (f.outcome === "accepted") byDomain[f.actionType].accepted++;
    if (f.outcome === "overridden") byDomain[f.actionType].overridden++;
  }

  const byActionClass: CopilotStats["byActionClass"] = {};
  for (const a of actions) {
    if (!byActionClass[a.actionClass]) byActionClass[a.actionClass] = { total: 0, executed: 0, rejected: 0 };
    byActionClass[a.actionClass].total++;
    if (a.status === "executed" || a.status === "auto_executed" || a.status === "approved")
      byActionClass[a.actionClass].executed++;
    if (a.status === "rejected") byActionClass[a.actionClass].rejected++;
  }

  const allConfidences = [
    ...triages.map((t) => t.confidence),
    ...hypotheses.map((h) => h.confidenceScore),
    ...actions.map((a) => a.confidenceScore),
  ];
  const avgConfidence =
    allConfidences.length > 0
      ? Math.round((allConfidences.reduce((s, c) => s + c, 0) / allConfidences.length) * 100) / 100
      : 0;

  return {
    totalTriages: triages.length,
    totalTimelines: timelines.length,
    totalHypotheses: hypotheses.length,
    totalActions: actions.length,
    autoExecutedActions: actions.filter((a) => a.status === "auto_executed").length,
    pendingApprovals: actions.filter((a) => a.status === "pending_approval").length,
    feedbackCount: total,
    acceptanceRate: total > 0 ? Math.round((accepted / total) * 100) : 0,
    overrideRate: total > 0 ? Math.round((overridden / total) * 100) : 0,
    avgConfidence,
    byDomain,
    byActionClass,
    recentCalibrations: calibrations.length,
  };
}
