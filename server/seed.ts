import { db } from "./db";
import {
  organizations, alerts, incidents, tags, incidentTags, alertTags,
  auditLogs, incidentComments, connectors, integrationConfigs,
  endpointAssets, cspmAccounts, cspmScans, cspmFindings,
  endpointTelemetry, ingestionLogs,
} from "@shared/schema";
import { count } from "drizzle-orm";
import { logger } from "./logger";

export async function seedDatabase() {
  const [existing] = await db.select({ count: count() }).from(organizations);
  if (existing.count > 0) return;

  const [org] = await db.insert(organizations).values({
    name: "Acme Security Corp",
    slug: "acme-security",
    industry: "Technology",
    contactEmail: "security@acme-corp.com",
  }).returning();

  const seedTags = await db.insert(tags).values([
    { name: "APT", color: "#ef4444", category: "threat" },
    { name: "Ransomware", color: "#f97316", category: "threat" },
    { name: "Insider Threat", color: "#eab308", category: "threat" },
    { name: "Cloud", color: "#3b82f6", category: "environment" },
    { name: "On-Prem", color: "#8b5cf6", category: "environment" },
    { name: "Finance", color: "#10b981", category: "department" },
    { name: "Engineering", color: "#06b6d4", category: "department" },
    { name: "Automated", color: "#6366f1", category: "workflow" },
    { name: "Needs Review", color: "#f59e0b", category: "workflow" },
    { name: "Data Breach", color: "#dc2626", category: "compliance" },
  ]).returning();

  const tagMap = Object.fromEntries(seedTags.map(t => [t.name, t.id]));

  const [inc1] = await db.insert(incidents).values({
    orgId: org.id,
    title: "Credential Stuffing Campaign Detected",
    summary: "Multiple failed login attempts from rotating IPs targeting VPN gateway. Pattern consistent with credential stuffing using leaked database.",
    severity: "high",
    status: "open",
    priority: 2,
    confidence: 0.87,
    alertCount: 12,
    mitreTactics: ["Credential Access", "Initial Access"],
    mitreTechniques: ["T1110.001 - Brute Force: Password Guessing", "T1078 - Valid Accounts"],
    aiNarrative: "Analysis indicates a coordinated credential stuffing campaign targeting the organization's VPN gateway. The attack originates from 47 distinct IP addresses across 12 countries, with timing patterns suggesting automated tooling. Correlation with dark web monitoring shows potential use of credentials from a recent third-party data breach. No successful authentications detected yet, but volume is increasing.",
    aiSummary: "Coordinated credential stuffing via 47 IPs targeting VPN gateway using leaked credentials.",
    mitigationSteps: JSON.stringify([
      "Enable rate limiting on VPN gateway",
      "Enforce MFA for all VPN users",
      "Block identified malicious IP ranges",
      "Reset passwords for accounts in leaked credential databases",
      "Monitor for successful authentication anomalies"
    ]),
    affectedAssets: JSON.stringify(["vpn-gateway-01", "vpn-gateway-02"]),
    iocs: JSON.stringify({ ips: ["185.220.101.34", "91.234.12.45", "45.153.160.2"], domains: [] }),
  }).returning();

  const [inc2] = await db.insert(incidents).values({
    orgId: org.id,
    title: "Suspicious Lateral Movement - Finance Segment",
    summary: "Endpoint in finance network segment exhibiting unusual SMB traffic patterns and WMI execution. Possible post-compromise lateral movement.",
    severity: "critical",
    status: "investigating",
    priority: 1,
    confidence: 0.92,
    alertCount: 8,
    escalated: true,
    escalatedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    mitreTactics: ["Lateral Movement", "Execution", "Discovery"],
    mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares", "T1047 - WMI", "T1083 - File and Directory Discovery"],
    aiNarrative: "High-confidence lateral movement detected originating from workstation FIN-WKS-042. The compromised endpoint is executing WMI commands against 6 other systems in the finance VLAN. SMB traffic analysis shows file enumeration patterns consistent with data staging for exfiltration. The initial compromise vector appears to be a malicious Excel attachment received via email 4 hours prior to lateral movement activity.",
    aiSummary: "Active lateral movement from FIN-WKS-042 via WMI/SMB targeting finance VLAN after phishing compromise.",
    mitigationSteps: JSON.stringify([
      "Isolate FIN-WKS-042 from network immediately",
      "Contain affected finance VLAN segment",
      "Analyze email attachment for IOCs",
      "Scan all contacted endpoints for persistence mechanisms",
      "Preserve forensic evidence on affected systems",
      "Notify incident response team for full investigation"
    ]),
    affectedAssets: JSON.stringify(["FIN-WKS-042", "FIN-WKS-050", "FIN-SRV-01", "FIN-SRV-02"]),
    iocs: JSON.stringify({ ips: ["10.0.15.42"], file_hashes: ["d41d8cd98f00b204e9800998ecf8427e"], domains: [] }),
    leadAnalyst: "sarah.chen",
  }).returning();

  const [inc3] = await db.insert(incidents).values({
    orgId: org.id,
    title: "Cloud Misconfiguration - S3 Bucket Exposure",
    summary: "AWS S3 bucket containing customer PII found publicly accessible. No evidence of unauthorized access yet, but exposure window is approximately 72 hours.",
    severity: "high",
    status: "contained",
    priority: 2,
    confidence: 0.95,
    alertCount: 3,
    containedAt: new Date(Date.now() - 1 * 60 * 60 * 1000),
    mitreTactics: ["Collection"],
    mitreTechniques: ["T1530 - Data from Cloud Storage"],
    aiNarrative: "Cloud Security Posture Management detected a publicly accessible S3 bucket 'acme-customer-exports-2025' containing CSV files with customer PII including names, emails, and billing addresses. The bucket ACL was modified 72 hours ago during a deployment pipeline change. CloudTrail analysis shows no evidence of unauthorized GetObject requests during the exposure window.",
    aiSummary: "S3 bucket with customer PII publicly exposed for 72 hours due to pipeline misconfiguration.",
    mitigationSteps: JSON.stringify([
      "Restrict S3 bucket ACL immediately",
      "Audit CloudTrail for any unauthorized access",
      "Review deployment pipeline IAM permissions",
      "Assess breach notification obligations",
      "Implement S3 Block Public Access at account level"
    ]),
    affectedAssets: JSON.stringify(["s3://acme-customer-exports-2025"]),
    iocs: JSON.stringify({ buckets: ["acme-customer-exports-2025"] }),
  }).returning();

  // Tag incidents
  await db.insert(incidentTags).values([
    { incidentId: inc1.id, tagId: tagMap["APT"] },
    { incidentId: inc1.id, tagId: tagMap["On-Prem"] },
    { incidentId: inc2.id, tagId: tagMap["APT"] },
    { incidentId: inc2.id, tagId: tagMap["Finance"] },
    { incidentId: inc2.id, tagId: tagMap["On-Prem"] },
    { incidentId: inc3.id, tagId: tagMap["Cloud"] },
    { incidentId: inc3.id, tagId: tagMap["Data Breach"] },
  ]);

  const now = new Date();
  const alertData = [
    { orgId: org.id, source: "CrowdStrike EDR", category: "lateral_movement", severity: "high", title: "Suspicious process execution detected", description: "PowerShell executing encoded commands on FIN-WKS-042", sourceIp: "10.0.15.42", hostname: "FIN-WKS-042", mitreTactic: "Execution", mitreTechnique: "T1059.001", status: "correlated", incidentId: inc2.id, correlationScore: 0.94, correlationReason: "Same source host, temporal proximity, MITRE chain match", detectedAt: new Date(now.getTime() - 4 * 3600000), sourceEventId: "cs-evt-20250210-001" },
    { orgId: org.id, source: "CrowdStrike EDR", category: "lateral_movement", severity: "medium", title: "WMI remote execution attempt", description: "WMI process creation detected targeting multiple endpoints", sourceIp: "10.0.15.42", destIp: "10.0.15.50", hostname: "FIN-WKS-042", mitreTactic: "Lateral Movement", mitreTechnique: "T1047", status: "correlated", incidentId: inc2.id, correlationScore: 0.91, correlationReason: "Same source host, lateral technique", detectedAt: new Date(now.getTime() - 3.5 * 3600000), sourceEventId: "cs-evt-20250210-002" },
    { orgId: org.id, source: "Palo Alto Firewall", category: "lateral_movement", severity: "high", title: "Anomalous SMB traffic volume", description: "10x normal SMB traffic from single source to finance VLAN", sourceIp: "10.0.15.42", destIp: "10.0.15.0/24", mitreTactic: "Lateral Movement", mitreTechnique: "T1021.002", status: "correlated", incidentId: inc2.id, correlationScore: 0.88, correlationReason: "Same source host, finance segment", detectedAt: new Date(now.getTime() - 3 * 3600000), sourceEventId: "pa-evt-20250210-001" },
    { orgId: org.id, source: "Splunk SIEM", category: "credential_access", severity: "high", title: "Brute force authentication attempts", description: "847 failed VPN login attempts in 15 minutes from distributed IPs", sourceIp: "185.220.101.0/24", mitreTactic: "Credential Access", mitreTechnique: "T1110.001", status: "correlated", incidentId: inc1.id, correlationScore: 0.85, correlationReason: "Distributed source, same target, credential attack pattern", detectedAt: new Date(now.getTime() - 6 * 3600000), sourceEventId: "splunk-evt-20250210-001" },
    { orgId: org.id, source: "Splunk SIEM", category: "credential_access", severity: "medium", title: "Failed login surge from new geolocation", description: "Authentication failures from IPs in Eastern Europe, not seen before", sourceIp: "91.234.12.45", mitreTactic: "Initial Access", mitreTechnique: "T1078", status: "correlated", incidentId: inc1.id, correlationScore: 0.82, correlationReason: "Temporal correlation with brute force", detectedAt: new Date(now.getTime() - 5.5 * 3600000), sourceEventId: "splunk-evt-20250210-002" },
    { orgId: org.id, source: "AWS GuardDuty", category: "cloud_misconfiguration", severity: "high", title: "S3 bucket policy change to public", description: "S3 bucket acme-customer-exports-2025 ACL changed to public-read", mitreTactic: "Collection", mitreTechnique: "T1530", status: "correlated", incidentId: inc3.id, correlationScore: 0.96, correlationReason: "Direct causal event for cloud exposure", detectedAt: new Date(now.getTime() - 72 * 3600000), sourceEventId: "gd-evt-20250207-001" },
    { orgId: org.id, source: "CrowdStrike EDR", category: "persistence", severity: "low", title: "Scheduled task created for persistence", description: "New scheduled task detected on marketing workstation", sourceIp: "10.0.20.15", hostname: "MKT-WKS-007", mitreTactic: "Persistence", mitreTechnique: "T1053.005", status: "new", detectedAt: new Date(now.getTime() - 1 * 3600000), sourceEventId: "cs-evt-20250210-003" },
    { orgId: org.id, source: "Palo Alto Firewall", category: "data_exfiltration", severity: "medium", title: "DNS tunneling attempt detected", description: "Suspicious DNS queries with high entropy subdomain values", sourceIp: "10.0.10.88", destIp: "8.8.8.8", hostname: "DEV-SRV-003", mitreTactic: "Exfiltration", mitreTechnique: "T1048.003", status: "new", detectedAt: new Date(now.getTime() - 0.5 * 3600000), sourceEventId: "pa-evt-20250210-002", protocol: "DNS", destPort: 53 },
    { orgId: org.id, source: "Splunk SIEM", category: "privilege_escalation", severity: "critical", title: "Privilege escalation detected", description: "User account elevated to domain admin outside change window", hostname: "DC-01", mitreTactic: "Privilege Escalation", mitreTechnique: "T1078.002", status: "triaged", detectedAt: new Date(now.getTime() - 0.25 * 3600000), sourceEventId: "splunk-evt-20250210-003", assignedTo: "mike.johnson" },
    { orgId: org.id, source: "AWS GuardDuty", category: "reconnaissance", severity: "medium", title: "Unusual API call pattern", description: "IAM user making ListBuckets and GetBucketPolicy calls at unusual hours", mitreTactic: "Discovery", mitreTechnique: "T1580", status: "new", detectedAt: new Date(now.getTime() - 2 * 3600000), sourceEventId: "gd-evt-20250210-002" },
    { orgId: org.id, source: "CrowdStrike EDR", category: "malware", severity: "high", title: "Malicious file hash detected", description: "Known ransomware variant signature found on endpoint", sourceIp: "10.0.25.100", hostname: "HR-WKS-012", fileHash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", mitreTactic: "Execution", mitreTechnique: "T1204.002", status: "new", detectedAt: new Date(now.getTime() - 0.1 * 3600000), sourceEventId: "cs-evt-20250210-004" },
    { orgId: org.id, source: "Palo Alto Firewall", category: "reconnaissance", severity: "low", title: "Port scan from internal host", description: "Sequential port scanning activity detected", sourceIp: "10.0.30.55", hostname: "QA-SRV-001", mitreTactic: "Discovery", mitreTechnique: "T1046", status: "dismissed", detectedAt: new Date(now.getTime() - 24 * 3600000), sourceEventId: "pa-evt-20250209-001", analystNotes: "Expected behavior from vulnerability scanner" },
  ];

  const insertedAlerts = await db.insert(alerts).values(alertData).returning();

  // Tag some alerts
  await db.insert(alertTags).values([
    { alertId: insertedAlerts[0].id, tagId: tagMap["APT"] },
    { alertId: insertedAlerts[0].id, tagId: tagMap["Finance"] },
    { alertId: insertedAlerts[5].id, tagId: tagMap["Cloud"] },
    { alertId: insertedAlerts[5].id, tagId: tagMap["Data Breach"] },
    { alertId: insertedAlerts[10].id, tagId: tagMap["Ransomware"] },
    { alertId: insertedAlerts[8].id, tagId: tagMap["Needs Review"] },
  ]);

  // Add analyst comments to incidents
  await db.insert(incidentComments).values([
    { incidentId: inc2.id, userId: "sarah.chen", userName: "Sarah Chen", body: "Confirmed FIN-WKS-042 is compromised. Initial vector was phishing email with malicious Excel macro. Isolating the host now." },
    { incidentId: inc2.id, userId: "mike.johnson", userName: "Mike Johnson", body: "Network team has segmented the finance VLAN. No outbound exfiltration detected yet based on DLP logs." },
    { incidentId: inc2.id, userId: "sarah.chen", userName: "Sarah Chen", body: "Found persistence mechanism via scheduled task on FIN-WKS-042. Collecting memory dump for forensic analysis." },
    { incidentId: inc1.id, userId: "alex.wong", userName: "Alex Wong", body: "Rate limiting enabled on VPN gateway. Attack volume has decreased by 80%. Monitoring for any successful authentications." },
    { incidentId: inc3.id, userId: "priya.patel", userName: "Priya Patel", body: "S3 bucket ACL has been restricted. CloudTrail review complete - no evidence of unauthorized data access during exposure window." },
  ]);

  // Add audit logs
  await db.insert(auditLogs).values([
    { orgId: org.id, userId: "sarah.chen", userName: "Sarah Chen", action: "incident.escalate", resourceType: "incident", resourceId: inc2.id, details: JSON.stringify({ severity: "critical", reason: "Active lateral movement in finance segment" }) },
    { orgId: org.id, userId: "mike.johnson", userName: "Mike Johnson", action: "alert.triage", resourceType: "alert", resourceId: insertedAlerts[8].id, details: JSON.stringify({ newStatus: "triaged", previousStatus: "new" }) },
    { orgId: org.id, userId: "system", userName: "System", action: "alert.correlate", resourceType: "incident", resourceId: inc2.id, details: JSON.stringify({ alertsCorrelated: 3, method: "ai_correlation" }) },
    { orgId: org.id, userId: "priya.patel", userName: "Priya Patel", action: "incident.contain", resourceType: "incident", resourceId: inc3.id, details: JSON.stringify({ action: "S3 bucket ACL restricted" }) },
    { orgId: org.id, userId: "alex.wong", userName: "Alex Wong", action: "alert.dismiss", resourceType: "alert", resourceId: insertedAlerts[11].id, details: JSON.stringify({ reason: "Expected vulnerability scanner activity" }) },
  ]);

  // Seed connectors for onboarding checklist
  await db.insert(connectors).values([
    {
      orgId: org.id, name: "CrowdStrike Falcon", type: "crowdstrike", authType: "oauth2",
      config: { baseUrl: "https://api.crowdstrike.com", clientId: "demo-client-id" },
      status: "active", pollingIntervalMin: 5,
      lastSyncAt: new Date(now.getTime() - 5 * 60000), lastSyncStatus: "success", lastSyncAlerts: 3, totalAlertsSynced: 247,
    },
    {
      orgId: org.id, name: "Splunk Enterprise", type: "splunk", authType: "token",
      config: { baseUrl: "https://splunk.acme-corp.internal:8089", index: "security" },
      status: "active", pollingIntervalMin: 3,
      lastSyncAt: new Date(now.getTime() - 3 * 60000), lastSyncStatus: "success", lastSyncAlerts: 5, totalAlertsSynced: 412,
    },
    {
      orgId: org.id, name: "Palo Alto Cortex XDR", type: "paloalto", authType: "api_key",
      config: { baseUrl: "https://api.xdr.paloaltonetworks.com" },
      status: "active", pollingIntervalMin: 5,
      lastSyncAt: new Date(now.getTime() - 8 * 60000), lastSyncStatus: "success", lastSyncAlerts: 2, totalAlertsSynced: 189,
    },
    {
      orgId: org.id, name: "AWS GuardDuty", type: "aws_guardduty", authType: "iam_role",
      config: { region: "us-east-1", detectorId: "demo-detector" },
      status: "active", pollingIntervalMin: 10,
      lastSyncAt: new Date(now.getTime() - 12 * 60000), lastSyncStatus: "success", lastSyncAlerts: 1, totalAlertsSynced: 78,
    },
  ]);

  // Seed integration configs for onboarding
  await db.insert(integrationConfigs).values([
    {
      orgId: org.id, type: "siem", name: "Splunk SIEM Integration",
      config: { url: "https://splunk.acme-corp.internal:8089", token: "demo-hec-token" },
      status: "active", lastTestedAt: new Date(now.getTime() - 1 * 3600000), lastTestStatus: "success",
    },
    {
      orgId: org.id, type: "edr", name: "CrowdStrike EDR",
      config: { clientId: "demo-cs-client", baseUrl: "https://api.crowdstrike.com" },
      status: "active", lastTestedAt: new Date(now.getTime() - 2 * 3600000), lastTestStatus: "success",
    },
    {
      orgId: org.id, type: "ticketing", name: "ServiceNow ITSM",
      config: { instanceUrl: "https://acme.service-now.com", table: "incident" },
      status: "active", lastTestedAt: new Date(now.getTime() - 6 * 3600000), lastTestStatus: "success",
    },
  ]);

  // Seed endpoint assets
  const endpointData = [
    { orgId: org.id, hostname: "FIN-WKS-042", os: "Windows", osVersion: "11 Enterprise 23H2", agentVersion: "7.12.0", agentStatus: "isolated", ipAddress: "10.0.15.42", macAddress: "AA:BB:CC:DD:EE:01", riskScore: 95, tags: ["finance", "compromised"] },
    { orgId: org.id, hostname: "FIN-WKS-050", os: "Windows", osVersion: "11 Enterprise 23H2", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.15.50", macAddress: "AA:BB:CC:DD:EE:02", riskScore: 45, tags: ["finance"] },
    { orgId: org.id, hostname: "FIN-SRV-01", os: "Windows Server", osVersion: "2022 Datacenter", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.15.100", macAddress: "AA:BB:CC:DD:EE:03", riskScore: 60, tags: ["finance", "server"] },
    { orgId: org.id, hostname: "DC-01", os: "Windows Server", osVersion: "2022 Datacenter", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.1.10", macAddress: "AA:BB:CC:DD:EE:04", riskScore: 30, tags: ["domain-controller", "critical"] },
    { orgId: org.id, hostname: "HR-WKS-012", os: "Windows", osVersion: "11 Enterprise 23H2", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.25.100", macAddress: "AA:BB:CC:DD:EE:05", riskScore: 75, tags: ["hr"] },
    { orgId: org.id, hostname: "DEV-SRV-003", os: "Ubuntu", osVersion: "24.04 LTS", agentVersion: "7.11.2", agentStatus: "online", ipAddress: "10.0.10.88", macAddress: "AA:BB:CC:DD:EE:06", riskScore: 55, tags: ["engineering", "server"] },
    { orgId: org.id, hostname: "MKT-WKS-007", os: "macOS", osVersion: "15.2 Sequoia", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.20.15", macAddress: "AA:BB:CC:DD:EE:07", riskScore: 40, tags: ["marketing"] },
    { orgId: org.id, hostname: "QA-SRV-001", os: "Ubuntu", osVersion: "22.04 LTS", agentVersion: "7.10.5", agentStatus: "online", ipAddress: "10.0.30.55", macAddress: "AA:BB:CC:DD:EE:08", riskScore: 20, tags: ["qa", "server"] },
    { orgId: org.id, hostname: "EXEC-WKS-001", os: "macOS", osVersion: "15.2 Sequoia", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.5.10", macAddress: "AA:BB:CC:DD:EE:09", riskScore: 15, tags: ["executive", "critical"] },
    { orgId: org.id, hostname: "VPN-GW-01", os: "Linux", osVersion: "Debian 12", agentVersion: "7.12.0", agentStatus: "online", ipAddress: "10.0.0.1", macAddress: "AA:BB:CC:DD:EE:10", riskScore: 50, tags: ["network", "gateway", "critical"] },
  ];
  const insertedEndpoints = await db.insert(endpointAssets).values(endpointData).returning();

  // Seed telemetry for endpoints
  await db.insert(endpointTelemetry).values([
    { orgId: org.id, assetId: insertedEndpoints[0].id, metricType: "cpu_usage", metricValue: { percent: 87, processes: 142 } },
    { orgId: org.id, assetId: insertedEndpoints[0].id, metricType: "network_connections", metricValue: { active: 34, suspicious: 12 } },
    { orgId: org.id, assetId: insertedEndpoints[3].id, metricType: "cpu_usage", metricValue: { percent: 42, processes: 89 } },
    { orgId: org.id, assetId: insertedEndpoints[5].id, metricType: "disk_usage", metricValue: { percent: 78, available_gb: 45 } },
  ]);

  // Seed CSPM accounts
  const [cspmAws] = await db.insert(cspmAccounts).values([
    {
      orgId: org.id, cloudProvider: "aws", accountId: "557845624595",
      displayName: "Acme Production (AWS)", regions: ["us-east-1", "us-west-2", "eu-west-1"],
      status: "active", config: { roleArn: "arn:aws:iam::557845624595:role/CspmReadOnly" },
      lastScanAt: new Date(now.getTime() - 2 * 3600000),
    },
    {
      orgId: org.id, cloudProvider: "aws", accountId: "123456789012",
      displayName: "Acme Staging (AWS)", regions: ["us-east-1"],
      status: "active", config: { roleArn: "arn:aws:iam::123456789012:role/CspmReadOnly" },
      lastScanAt: new Date(now.getTime() - 4 * 3600000),
    },
  ]).returning();

  // Seed CSPM scans and findings
  const [scan1] = await db.insert(cspmScans).values({
    orgId: org.id, accountId: cspmAws.id, status: "completed", findingsCount: 5,
    summary: { critical: 1, high: 2, medium: 1, low: 1 },
    startedAt: new Date(now.getTime() - 2 * 3600000), completedAt: new Date(now.getTime() - 1.5 * 3600000),
  }).returning();

  await db.insert(cspmFindings).values([
    { orgId: org.id, scanId: scan1.id, accountId: cspmAws.id, ruleId: "CIS-1.14", ruleName: "Ensure access keys are rotated within 90 days", severity: "high", resourceType: "IAM User", resourceId: "arn:aws:iam::557845624595:user/deploy-bot", resourceRegion: "global", description: "IAM user deploy-bot has access keys older than 90 days", remediation: "Rotate access keys for user deploy-bot", complianceFrameworks: ["CIS AWS 1.4", "SOC 2"], status: "open" },
    { orgId: org.id, scanId: scan1.id, accountId: cspmAws.id, ruleId: "CIS-2.1.1", ruleName: "Ensure S3 Block Public Access is enabled", severity: "critical", resourceType: "S3 Bucket", resourceId: "acme-customer-exports-2025", resourceRegion: "us-east-1", description: "S3 bucket does not have Block Public Access enabled at bucket level", remediation: "Enable S3 Block Public Access setting on the bucket", complianceFrameworks: ["CIS AWS 1.4", "PCI DSS", "SOC 2"], status: "remediated" },
    { orgId: org.id, scanId: scan1.id, accountId: cspmAws.id, ruleId: "CIS-4.3", ruleName: "Ensure VPC flow logging is enabled", severity: "medium", resourceType: "VPC", resourceId: "vpc-0abc123def456789", resourceRegion: "us-east-1", description: "VPC does not have flow logs enabled", remediation: "Enable VPC flow logging to CloudWatch or S3", complianceFrameworks: ["CIS AWS 1.4", "NIST 800-53"], status: "open" },
    { orgId: org.id, scanId: scan1.id, accountId: cspmAws.id, ruleId: "CIS-2.2.1", ruleName: "Ensure EBS volume encryption is enabled by default", severity: "high", resourceType: "EBS Settings", resourceId: "us-east-1", resourceRegion: "us-east-1", description: "EBS default encryption is not enabled in us-east-1", remediation: "Enable default EBS encryption in the region settings", complianceFrameworks: ["CIS AWS 1.4", "HIPAA"], status: "open" },
    { orgId: org.id, scanId: scan1.id, accountId: cspmAws.id, ruleId: "CIS-1.4", ruleName: "Ensure no root account access key exists", severity: "low", resourceType: "IAM Root", resourceId: "root", resourceRegion: "global", description: "Root account has active access keys", remediation: "Delete root account access keys and use IAM users instead", complianceFrameworks: ["CIS AWS 1.4"], status: "open" },
  ]);

  // Seed ingestion logs
  const ingestionLogEntries = [
    { orgId: org.id, source: "CrowdStrike EDR", alertsReceived: 15, alertsCreated: 12, alertsDeduped: 3, alertsFailed: 0, durationMs: 1240 },
    { orgId: org.id, source: "Splunk SIEM", alertsReceived: 28, alertsCreated: 22, alertsDeduped: 5, alertsFailed: 1, durationMs: 2100 },
    { orgId: org.id, source: "Palo Alto Firewall", alertsReceived: 8, alertsCreated: 7, alertsDeduped: 1, alertsFailed: 0, durationMs: 890 },
    { orgId: org.id, source: "AWS GuardDuty", alertsReceived: 4, alertsCreated: 4, alertsDeduped: 0, alertsFailed: 0, durationMs: 650 },
    { orgId: org.id, source: "CrowdStrike EDR", alertsReceived: 10, alertsCreated: 8, alertsDeduped: 2, alertsFailed: 0, durationMs: 1100 },
    { orgId: org.id, source: "Splunk SIEM", alertsReceived: 19, alertsCreated: 16, alertsDeduped: 2, alertsFailed: 1, durationMs: 1800 },
  ];
  for (const entry of ingestionLogEntries) {
    await db.insert(ingestionLogs).values(entry);
  }

  logger.child("seed").info("Database seeded: org, 3 incidents, 12 alerts, 10 tags, 4 connectors, 3 integrations, 10 endpoints, 2 CSPM accounts, 5 findings, 6 ingestion logs");
}
