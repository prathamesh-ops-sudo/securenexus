import { db } from "./db";
import { organizations, alerts, incidents } from "@shared/schema";
import { count } from "drizzle-orm";

export async function seedDatabase() {
  const [existing] = await db.select({ count: count() }).from(organizations);
  if (existing.count > 0) return;

  const [org] = await db.insert(organizations).values({
    name: "Acme Security Corp",
    slug: "acme-security",
  }).returning();

  const [inc1] = await db.insert(incidents).values({
    orgId: org.id,
    title: "Credential Stuffing Campaign Detected",
    summary: "Multiple failed login attempts from rotating IPs targeting VPN gateway. Pattern consistent with credential stuffing using leaked database.",
    severity: "high",
    status: "open",
    confidence: 0.87,
    alertCount: 12,
    mitreTactics: ["Credential Access", "Initial Access"],
    mitreTechniques: ["T1110.001 - Brute Force: Password Guessing", "T1078 - Valid Accounts"],
    aiNarrative: "Analysis indicates a coordinated credential stuffing campaign targeting the organization's VPN gateway. The attack originates from 47 distinct IP addresses across 12 countries, with timing patterns suggesting automated tooling. Correlation with dark web monitoring shows potential use of credentials from a recent third-party data breach. No successful authentications detected yet, but volume is increasing.",
    mitigationSteps: JSON.stringify([
      "Enable rate limiting on VPN gateway",
      "Enforce MFA for all VPN users",
      "Block identified malicious IP ranges",
      "Reset passwords for accounts in leaked credential databases",
      "Monitor for successful authentication anomalies"
    ]),
  }).returning();

  const [inc2] = await db.insert(incidents).values({
    orgId: org.id,
    title: "Suspicious Lateral Movement - Finance Segment",
    summary: "Endpoint in finance network segment exhibiting unusual SMB traffic patterns and WMI execution. Possible post-compromise lateral movement.",
    severity: "critical",
    status: "investigating",
    confidence: 0.92,
    alertCount: 8,
    mitreTactics: ["Lateral Movement", "Execution", "Discovery"],
    mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares", "T1047 - WMI", "T1083 - File and Directory Discovery"],
    aiNarrative: "High-confidence lateral movement detected originating from workstation FIN-WKS-042. The compromised endpoint is executing WMI commands against 6 other systems in the finance VLAN. SMB traffic analysis shows file enumeration patterns consistent with data staging for exfiltration. The initial compromise vector appears to be a malicious Excel attachment received via email 4 hours prior to lateral movement activity.",
    mitigationSteps: JSON.stringify([
      "Isolate FIN-WKS-042 from network immediately",
      "Contain affected finance VLAN segment",
      "Analyze email attachment for IOCs",
      "Scan all contacted endpoints for persistence mechanisms",
      "Preserve forensic evidence on affected systems",
      "Notify incident response team for full investigation"
    ]),
  }).returning();

  const [inc3] = await db.insert(incidents).values({
    orgId: org.id,
    title: "Cloud Misconfiguration - S3 Bucket Exposure",
    summary: "AWS S3 bucket containing customer PII found publicly accessible. No evidence of unauthorized access yet, but exposure window is approximately 72 hours.",
    severity: "high",
    status: "open",
    confidence: 0.95,
    alertCount: 3,
    mitreTactics: ["Collection"],
    mitreTechniques: ["T1530 - Data from Cloud Storage"],
    aiNarrative: "Cloud Security Posture Management detected a publicly accessible S3 bucket 'acme-customer-exports-2025' containing CSV files with customer PII including names, emails, and billing addresses. The bucket ACL was modified 72 hours ago during a deployment pipeline change. CloudTrail analysis shows no evidence of unauthorized GetObject requests during the exposure window.",
    mitigationSteps: JSON.stringify([
      "Restrict S3 bucket ACL immediately",
      "Audit CloudTrail for any unauthorized access",
      "Review deployment pipeline IAM permissions",
      "Assess breach notification obligations",
      "Implement S3 Block Public Access at account level"
    ]),
  }).returning();

  const alertData = [
    { orgId: org.id, source: "CrowdStrike EDR", severity: "high", title: "Suspicious process execution detected", description: "PowerShell executing encoded commands on FIN-WKS-042", sourceIp: "10.0.15.42", hostname: "FIN-WKS-042", mitreTactic: "Execution", mitreTechnique: "T1059.001", status: "correlated", incidentId: inc2.id },
    { orgId: org.id, source: "CrowdStrike EDR", severity: "medium", title: "WMI remote execution attempt", description: "WMI process creation detected targeting multiple endpoints", sourceIp: "10.0.15.42", destIp: "10.0.15.50", hostname: "FIN-WKS-042", mitreTactic: "Lateral Movement", mitreTechnique: "T1047", status: "correlated", incidentId: inc2.id },
    { orgId: org.id, source: "Palo Alto Firewall", severity: "high", title: "Anomalous SMB traffic volume", description: "10x normal SMB traffic from single source to finance VLAN", sourceIp: "10.0.15.42", destIp: "10.0.15.0/24", mitreTactic: "Lateral Movement", mitreTechnique: "T1021.002", status: "correlated", incidentId: inc2.id },
    { orgId: org.id, source: "Splunk SIEM", severity: "high", title: "Brute force authentication attempts", description: "847 failed VPN login attempts in 15 minutes from distributed IPs", sourceIp: "185.220.101.0/24", mitreTactic: "Credential Access", mitreTechnique: "T1110.001", status: "correlated", incidentId: inc1.id },
    { orgId: org.id, source: "Splunk SIEM", severity: "medium", title: "Failed login surge from new geolocation", description: "Authentication failures from IPs in Eastern Europe, not seen before", sourceIp: "91.234.12.45", mitreTactic: "Initial Access", mitreTechnique: "T1078", status: "correlated", incidentId: inc1.id },
    { orgId: org.id, source: "AWS GuardDuty", severity: "high", title: "S3 bucket policy change to public", description: "S3 bucket acme-customer-exports-2025 ACL changed to public-read", mitreTactic: "Collection", mitreTechnique: "T1530", status: "correlated", incidentId: inc3.id },
    { orgId: org.id, source: "CrowdStrike EDR", severity: "low", title: "Scheduled task created for persistence", description: "New scheduled task detected on marketing workstation", sourceIp: "10.0.20.15", hostname: "MKT-WKS-007", mitreTactic: "Persistence", mitreTechnique: "T1053.005", status: "new" },
    { orgId: org.id, source: "Palo Alto Firewall", severity: "medium", title: "DNS tunneling attempt detected", description: "Suspicious DNS queries with high entropy subdomain values", sourceIp: "10.0.10.88", destIp: "8.8.8.8", hostname: "DEV-SRV-003", mitreTactic: "Exfiltration", mitreTechnique: "T1048.003", status: "new" },
    { orgId: org.id, source: "Splunk SIEM", severity: "critical", title: "Privilege escalation detected", description: "User account elevated to domain admin outside change window", hostname: "DC-01", mitreTactic: "Privilege Escalation", mitreTechnique: "T1078.002", status: "new" },
    { orgId: org.id, source: "AWS GuardDuty", severity: "medium", title: "Unusual API call pattern", description: "IAM user making ListBuckets and GetBucketPolicy calls at unusual hours", mitreTactic: "Discovery", mitreTechnique: "T1580", status: "new" },
    { orgId: org.id, source: "CrowdStrike EDR", severity: "high", title: "Malicious file hash detected", description: "Known ransomware variant signature found on endpoint", sourceIp: "10.0.25.100", hostname: "HR-WKS-012", fileHash: "a1b2c3d4e5f6...deadbeef", mitreTactic: "Execution", mitreTechnique: "T1204.002", status: "new" },
    { orgId: org.id, source: "Palo Alto Firewall", severity: "low", title: "Port scan from internal host", description: "Sequential port scanning activity detected", sourceIp: "10.0.30.55", hostname: "QA-SRV-001", mitreTactic: "Discovery", mitreTechnique: "T1046", status: "dismissed" },
  ];

  await db.insert(alerts).values(alertData);
  console.log("Database seeded successfully");
}
