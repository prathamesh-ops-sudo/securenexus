import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, reply, replyError, strictLimiter } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { pool } from "../db";

const log = logger.child("mitre-attack-routes");

// ── Complete MITRE ATT&CK v15.1 Enterprise Matrix ────────────────────
// Source: https://attack.mitre.org/matrices/enterprise/

interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  subtechniques?: { id: string; name: string; description: string }[];
  platforms?: string[];
  dataSources?: string[];
  mitigations?: string[];
  url: string;
}

interface MitreTactic {
  id: string;
  shortName: string;
  name: string;
  description: string;
  techniques: MitreTechnique[];
}

const ATTACK_VERSION = "15.1";
const ATTACK_LAST_UPDATED = "2024-10-31";

const MITRE_TACTICS_DATA: MitreTactic[] = [
  {
    id: "TA0043",
    shortName: "reconnaissance",
    name: "Reconnaissance",
    description: "Gathering information to plan future operations",
    techniques: [
      {
        id: "T1595",
        name: "Active Scanning",
        description: "Scanning infrastructure to identify targets",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1595.001", name: "Scanning IP Blocks", description: "Scanning IP address blocks" },
          { id: "T1595.002", name: "Vulnerability Scanning", description: "Scanning for vulnerabilities" },
          { id: "T1595.003", name: "Wordlist Scanning", description: "Brute-force directories/DNS" },
        ],
        url: "https://attack.mitre.org/techniques/T1595",
      },
      {
        id: "T1592",
        name: "Gather Victim Host Information",
        description: "Gathering information about victim hosts",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1592.001", name: "Hardware", description: "Gathering victim hardware information" },
          { id: "T1592.002", name: "Software", description: "Gathering victim software information" },
          { id: "T1592.003", name: "Firmware", description: "Gathering victim firmware information" },
          { id: "T1592.004", name: "Client Configurations", description: "Gathering client configs" },
        ],
        url: "https://attack.mitre.org/techniques/T1592",
      },
      {
        id: "T1589",
        name: "Gather Victim Identity Information",
        description: "Gathering victim identity information",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1589.001", name: "Credentials", description: "Gathering victim credentials" },
          { id: "T1589.002", name: "Email Addresses", description: "Gathering email addresses" },
          { id: "T1589.003", name: "Employee Names", description: "Gathering employee names" },
        ],
        url: "https://attack.mitre.org/techniques/T1589",
      },
      {
        id: "T1590",
        name: "Gather Victim Network Information",
        description: "Gathering victim network information",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1590.001", name: "Domain Properties", description: "Gathering domain properties" },
          { id: "T1590.002", name: "DNS", description: "Gathering DNS information" },
          { id: "T1590.004", name: "Network Topology", description: "Gathering network topology" },
          { id: "T1590.005", name: "IP Addresses", description: "Gathering IP addresses" },
          { id: "T1590.006", name: "Network Security Appliances", description: "Gathering security appliance info" },
        ],
        url: "https://attack.mitre.org/techniques/T1590",
      },
      {
        id: "T1591",
        name: "Gather Victim Org Information",
        description: "Gathering victim org information",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1591.001", name: "Determine Physical Locations", description: "Gathering physical locations" },
          { id: "T1591.002", name: "Business Relationships", description: "Gathering business relationships" },
          { id: "T1591.004", name: "Identify Roles", description: "Identifying key roles" },
        ],
        url: "https://attack.mitre.org/techniques/T1591",
      },
      {
        id: "T1598",
        name: "Phishing for Information",
        description: "Sending phishing messages to gather information",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1598.001", name: "Spearphishing Service", description: "Phishing via services" },
          { id: "T1598.002", name: "Spearphishing Attachment", description: "Phishing with attachments" },
          { id: "T1598.003", name: "Spearphishing Link", description: "Phishing with links" },
        ],
        url: "https://attack.mitre.org/techniques/T1598",
      },
      {
        id: "T1597",
        name: "Search Closed Sources",
        description: "Searching closed sources for victim information",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1597.001", name: "Threat Intel Vendors", description: "Searching threat intel vendors" },
          { id: "T1597.002", name: "Purchase Technical Data", description: "Purchasing technical data" },
        ],
        url: "https://attack.mitre.org/techniques/T1597",
      },
      {
        id: "T1596",
        name: "Search Open Technical Databases",
        description: "Searching open technical databases",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1596.001", name: "DNS/Passive DNS", description: "Searching DNS data" },
          { id: "T1596.002", name: "WHOIS", description: "Searching WHOIS data" },
          { id: "T1596.003", name: "Digital Certificates", description: "Searching cert data" },
          { id: "T1596.005", name: "Scan Databases", description: "Searching scan databases" },
        ],
        url: "https://attack.mitre.org/techniques/T1596",
      },
      {
        id: "T1593",
        name: "Search Open Websites/Domains",
        description: "Searching open websites and domains",
        tactics: ["reconnaissance"],
        subtechniques: [
          { id: "T1593.001", name: "Social Media", description: "Searching social media" },
          { id: "T1593.002", name: "Search Engines", description: "Using search engines" },
          { id: "T1593.003", name: "Code Repositories", description: "Searching code repos" },
        ],
        url: "https://attack.mitre.org/techniques/T1593",
      },
      {
        id: "T1594",
        name: "Search Victim-Owned Websites",
        description: "Searching victim-owned websites",
        tactics: ["reconnaissance"],
        url: "https://attack.mitre.org/techniques/T1594",
      },
    ],
  },
  {
    id: "TA0042",
    shortName: "resource_development",
    name: "Resource Development",
    description: "Establishing resources for operations",
    techniques: [
      {
        id: "T1583",
        name: "Acquire Infrastructure",
        description: "Acquiring infrastructure for operations",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1583.001", name: "Domains", description: "Acquiring domains" },
          { id: "T1583.002", name: "DNS Server", description: "Setting up DNS servers" },
          { id: "T1583.003", name: "Virtual Private Server", description: "Acquiring VPS" },
          { id: "T1583.004", name: "Server", description: "Acquiring servers" },
          { id: "T1583.006", name: "Web Services", description: "Using web services" },
          { id: "T1583.008", name: "Malvertising", description: "Using malvertising" },
        ],
        url: "https://attack.mitre.org/techniques/T1583",
      },
      {
        id: "T1586",
        name: "Compromise Accounts",
        description: "Compromising accounts for operations",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1586.001", name: "Social Media Accounts", description: "Compromising social media" },
          { id: "T1586.002", name: "Email Accounts", description: "Compromising email accounts" },
          { id: "T1586.003", name: "Cloud Accounts", description: "Compromising cloud accounts" },
        ],
        url: "https://attack.mitre.org/techniques/T1586",
      },
      {
        id: "T1584",
        name: "Compromise Infrastructure",
        description: "Compromising infrastructure",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1584.001", name: "Domains", description: "Compromising domains" },
          { id: "T1584.004", name: "Server", description: "Compromising servers" },
          { id: "T1584.006", name: "Web Services", description: "Compromising web services" },
        ],
        url: "https://attack.mitre.org/techniques/T1584",
      },
      {
        id: "T1587",
        name: "Develop Capabilities",
        description: "Developing capabilities",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1587.001", name: "Malware", description: "Developing malware" },
          { id: "T1587.002", name: "Code Signing Certificates", description: "Developing code signing certs" },
          { id: "T1587.003", name: "Digital Certificates", description: "Developing digital certificates" },
          { id: "T1587.004", name: "Exploits", description: "Developing exploits" },
        ],
        url: "https://attack.mitre.org/techniques/T1587",
      },
      {
        id: "T1585",
        name: "Establish Accounts",
        description: "Establishing accounts",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1585.001", name: "Social Media Accounts", description: "Establishing social media" },
          { id: "T1585.002", name: "Email Accounts", description: "Establishing email accounts" },
          { id: "T1585.003", name: "Cloud Accounts", description: "Establishing cloud accounts" },
        ],
        url: "https://attack.mitre.org/techniques/T1585",
      },
      {
        id: "T1588",
        name: "Obtain Capabilities",
        description: "Obtaining capabilities",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1588.001", name: "Malware", description: "Obtaining malware" },
          { id: "T1588.002", name: "Tool", description: "Obtaining tools" },
          { id: "T1588.003", name: "Code Signing Certificates", description: "Obtaining code signing certs" },
          { id: "T1588.004", name: "Digital Certificates", description: "Obtaining digital certs" },
          { id: "T1588.005", name: "Exploits", description: "Obtaining exploits" },
          { id: "T1588.006", name: "Vulnerabilities", description: "Obtaining vulnerability info" },
        ],
        url: "https://attack.mitre.org/techniques/T1588",
      },
      {
        id: "T1608",
        name: "Stage Capabilities",
        description: "Staging capabilities",
        tactics: ["resource_development"],
        subtechniques: [
          { id: "T1608.001", name: "Upload Malware", description: "Uploading malware" },
          { id: "T1608.002", name: "Upload Tool", description: "Uploading tools" },
          { id: "T1608.003", name: "Install Digital Certificate", description: "Installing certs" },
          { id: "T1608.004", name: "Drive-by Target", description: "Setting up drive-by targets" },
          { id: "T1608.005", name: "Link Target", description: "Setting up link targets" },
          { id: "T1608.006", name: "SEO Poisoning", description: "Using SEO poisoning" },
        ],
        url: "https://attack.mitre.org/techniques/T1608",
      },
    ],
  },
  {
    id: "TA0001",
    shortName: "initial_access",
    name: "Initial Access",
    description: "Trying to get into your network",
    techniques: [
      {
        id: "T1189",
        name: "Drive-by Compromise",
        description: "Gaining access through drive-by compromise",
        tactics: ["initial_access"],
        url: "https://attack.mitre.org/techniques/T1189",
      },
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        description: "Exploiting public-facing apps",
        tactics: ["initial_access"],
        url: "https://attack.mitre.org/techniques/T1190",
      },
      {
        id: "T1133",
        name: "External Remote Services",
        description: "Using external remote services",
        tactics: ["initial_access"],
        url: "https://attack.mitre.org/techniques/T1133",
      },
      {
        id: "T1200",
        name: "Hardware Additions",
        description: "Introducing hardware to gain access",
        tactics: ["initial_access"],
        url: "https://attack.mitre.org/techniques/T1200",
      },
      {
        id: "T1566",
        name: "Phishing",
        description: "Phishing attacks",
        tactics: ["initial_access"],
        subtechniques: [
          { id: "T1566.001", name: "Spearphishing Attachment", description: "Spearphishing with attachments" },
          { id: "T1566.002", name: "Spearphishing Link", description: "Spearphishing with links" },
          { id: "T1566.003", name: "Spearphishing via Service", description: "Spearphishing via services" },
          { id: "T1566.004", name: "Spearphishing Voice", description: "Vishing" },
        ],
        url: "https://attack.mitre.org/techniques/T1566",
      },
      {
        id: "T1091",
        name: "Replication Through Removable Media",
        description: "Spreading through removable media",
        tactics: ["initial_access"],
        url: "https://attack.mitre.org/techniques/T1091",
      },
      {
        id: "T1195",
        name: "Supply Chain Compromise",
        description: "Compromising the supply chain",
        tactics: ["initial_access"],
        subtechniques: [
          { id: "T1195.001", name: "Compromise Software Dependencies", description: "Compromising dependencies" },
          {
            id: "T1195.002",
            name: "Compromise Software Supply Chain",
            description: "Compromising software supply chain",
          },
          {
            id: "T1195.003",
            name: "Compromise Hardware Supply Chain",
            description: "Compromising hardware supply chain",
          },
        ],
        url: "https://attack.mitre.org/techniques/T1195",
      },
      {
        id: "T1199",
        name: "Trusted Relationship",
        description: "Exploiting trusted relationships",
        tactics: ["initial_access"],
        url: "https://attack.mitre.org/techniques/T1199",
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        description: "Using valid accounts",
        tactics: ["initial_access", "defense_evasion", "persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1078.001", name: "Default Accounts", description: "Using default accounts" },
          { id: "T1078.002", name: "Domain Accounts", description: "Using domain accounts" },
          { id: "T1078.003", name: "Local Accounts", description: "Using local accounts" },
          { id: "T1078.004", name: "Cloud Accounts", description: "Using cloud accounts" },
        ],
        url: "https://attack.mitre.org/techniques/T1078",
      },
    ],
  },
  {
    id: "TA0002",
    shortName: "execution",
    name: "Execution",
    description: "Trying to run malicious code",
    techniques: [
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        description: "Using command-line interpreters and scripting",
        tactics: ["execution"],
        subtechniques: [
          { id: "T1059.001", name: "PowerShell", description: "Using PowerShell" },
          { id: "T1059.002", name: "AppleScript", description: "Using AppleScript" },
          { id: "T1059.003", name: "Windows Command Shell", description: "Using cmd.exe" },
          { id: "T1059.004", name: "Unix Shell", description: "Using bash/sh" },
          { id: "T1059.005", name: "Visual Basic", description: "Using VBScript" },
          { id: "T1059.006", name: "Python", description: "Using Python" },
          { id: "T1059.007", name: "JavaScript", description: "Using JavaScript/JScript" },
          { id: "T1059.008", name: "Network Device CLI", description: "Using network device CLI" },
          { id: "T1059.009", name: "Cloud API", description: "Using cloud APIs" },
        ],
        url: "https://attack.mitre.org/techniques/T1059",
      },
      {
        id: "T1609",
        name: "Container Administration Command",
        description: "Using container admin commands",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1609",
      },
      {
        id: "T1610",
        name: "Deploy Container",
        description: "Deploying containers",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1610",
      },
      {
        id: "T1203",
        name: "Exploitation for Client Execution",
        description: "Exploiting client applications",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1203",
      },
      {
        id: "T1559",
        name: "Inter-Process Communication",
        description: "Using IPC mechanisms",
        tactics: ["execution"],
        subtechniques: [
          { id: "T1559.001", name: "Component Object Model", description: "Using COM" },
          { id: "T1559.002", name: "Dynamic Data Exchange", description: "Using DDE" },
          { id: "T1559.003", name: "XPC Services", description: "Using XPC Services" },
        ],
        url: "https://attack.mitre.org/techniques/T1559",
      },
      {
        id: "T1106",
        name: "Native API",
        description: "Using native OS APIs",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1106",
      },
      {
        id: "T1053",
        name: "Scheduled Task/Job",
        description: "Using scheduled tasks",
        tactics: ["execution", "persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1053.002", name: "At", description: "Using at" },
          { id: "T1053.003", name: "Cron", description: "Using cron" },
          { id: "T1053.005", name: "Scheduled Task", description: "Using Windows scheduled tasks" },
          { id: "T1053.006", name: "Systemd Timers", description: "Using systemd timers" },
          { id: "T1053.007", name: "Container Orchestration Job", description: "Using container orchestration" },
        ],
        url: "https://attack.mitre.org/techniques/T1053",
      },
      {
        id: "T1648",
        name: "Serverless Execution",
        description: "Using serverless compute",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1648",
      },
      {
        id: "T1129",
        name: "Shared Modules",
        description: "Using shared modules",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1129",
      },
      {
        id: "T1072",
        name: "Software Deployment Tools",
        description: "Using software deployment tools",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1072",
      },
      {
        id: "T1569",
        name: "System Services",
        description: "Using system services",
        tactics: ["execution"],
        subtechniques: [
          { id: "T1569.001", name: "Launchctl", description: "Using launchctl" },
          { id: "T1569.002", name: "Service Execution", description: "Using service execution" },
        ],
        url: "https://attack.mitre.org/techniques/T1569",
      },
      {
        id: "T1204",
        name: "User Execution",
        description: "Relying on user execution",
        tactics: ["execution"],
        subtechniques: [
          { id: "T1204.001", name: "Malicious Link", description: "User clicking malicious link" },
          { id: "T1204.002", name: "Malicious File", description: "User opening malicious file" },
          { id: "T1204.003", name: "Malicious Image", description: "User running malicious image" },
        ],
        url: "https://attack.mitre.org/techniques/T1204",
      },
      {
        id: "T1047",
        name: "Windows Management Instrumentation",
        description: "Using WMI",
        tactics: ["execution"],
        url: "https://attack.mitre.org/techniques/T1047",
      },
    ],
  },
  {
    id: "TA0003",
    shortName: "persistence",
    name: "Persistence",
    description: "Trying to maintain their foothold",
    techniques: [
      {
        id: "T1098",
        name: "Account Manipulation",
        description: "Manipulating accounts",
        tactics: ["persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1098.001", name: "Additional Cloud Credentials", description: "Adding cloud credentials" },
          {
            id: "T1098.002",
            name: "Additional Email Delegate Permissions",
            description: "Adding email delegate permissions",
          },
          { id: "T1098.003", name: "Additional Cloud Roles", description: "Adding cloud roles" },
          { id: "T1098.004", name: "SSH Authorized Keys", description: "Adding SSH authorized keys" },
          { id: "T1098.005", name: "Device Registration", description: "Registering devices" },
          {
            id: "T1098.006",
            name: "Additional Container Cluster Roles",
            description: "Adding container cluster roles",
          },
        ],
        url: "https://attack.mitre.org/techniques/T1098",
      },
      {
        id: "T1197",
        name: "BITS Jobs",
        description: "Using BITS for persistence",
        tactics: ["persistence", "defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1197",
      },
      {
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        description: "Using autostart for persistence",
        tactics: ["persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1547.001", name: "Registry Run Keys / Startup Folder", description: "Using registry run keys" },
          { id: "T1547.004", name: "Winlogon Helper DLL", description: "Using Winlogon helper DLL" },
          { id: "T1547.009", name: "Shortcut Modification", description: "Modifying shortcuts" },
          { id: "T1547.012", name: "Print Processors", description: "Using print processors" },
          { id: "T1547.014", name: "Active Setup", description: "Using Active Setup" },
        ],
        url: "https://attack.mitre.org/techniques/T1547",
      },
      {
        id: "T1037",
        name: "Boot or Logon Initialization Scripts",
        description: "Using logon scripts",
        tactics: ["persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1037.001", name: "Logon Script (Windows)", description: "Using Windows logon scripts" },
          { id: "T1037.004", name: "RC Scripts", description: "Using RC scripts" },
          { id: "T1037.005", name: "Startup Items", description: "Using startup items" },
        ],
        url: "https://attack.mitre.org/techniques/T1037",
      },
      {
        id: "T1176",
        name: "Browser Extensions",
        description: "Using browser extensions",
        tactics: ["persistence"],
        url: "https://attack.mitre.org/techniques/T1176",
      },
      {
        id: "T1554",
        name: "Compromise Host Software Binary",
        description: "Modifying host software",
        tactics: ["persistence"],
        url: "https://attack.mitre.org/techniques/T1554",
      },
      {
        id: "T1136",
        name: "Create Account",
        description: "Creating accounts",
        tactics: ["persistence"],
        subtechniques: [
          { id: "T1136.001", name: "Local Account", description: "Creating local accounts" },
          { id: "T1136.002", name: "Domain Account", description: "Creating domain accounts" },
          { id: "T1136.003", name: "Cloud Account", description: "Creating cloud accounts" },
        ],
        url: "https://attack.mitre.org/techniques/T1136",
      },
      {
        id: "T1543",
        name: "Create or Modify System Process",
        description: "Modifying system processes",
        tactics: ["persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1543.001", name: "Launch Agent", description: "Using launch agents" },
          { id: "T1543.002", name: "Systemd Service", description: "Using systemd services" },
          { id: "T1543.003", name: "Windows Service", description: "Using Windows services" },
          { id: "T1543.004", name: "Launch Daemon", description: "Using launch daemons" },
        ],
        url: "https://attack.mitre.org/techniques/T1543",
      },
      {
        id: "T1546",
        name: "Event Triggered Execution",
        description: "Using event-triggered execution",
        tactics: ["persistence", "privilege_escalation"],
        subtechniques: [
          { id: "T1546.001", name: "Change Default File Association", description: "Changing file associations" },
          { id: "T1546.002", name: "Screensaver", description: "Using screensaver" },
          { id: "T1546.003", name: "WMI Event Subscription", description: "Using WMI event subscription" },
          { id: "T1546.008", name: "Accessibility Features", description: "Using accessibility features" },
          { id: "T1546.015", name: "COM Hijacking", description: "Hijacking COM" },
        ],
        url: "https://attack.mitre.org/techniques/T1546",
      },
      {
        id: "T1574",
        name: "Hijack Execution Flow",
        description: "Hijacking execution flow",
        tactics: ["persistence", "privilege_escalation", "defense_evasion"],
        subtechniques: [
          { id: "T1574.001", name: "DLL Search Order Hijacking", description: "Hijacking DLL search order" },
          { id: "T1574.002", name: "DLL Side-Loading", description: "Using DLL side-loading" },
          { id: "T1574.006", name: "Dynamic Linker Hijacking", description: "Hijacking dynamic linker" },
          {
            id: "T1574.011",
            name: "Services Registry Permissions Weakness",
            description: "Exploiting service registry",
          },
        ],
        url: "https://attack.mitre.org/techniques/T1574",
      },
      {
        id: "T1556",
        name: "Modify Authentication Process",
        description: "Modifying authentication",
        tactics: ["persistence", "credential_access", "defense_evasion"],
        subtechniques: [
          { id: "T1556.001", name: "Domain Controller Authentication", description: "Modifying DC auth" },
          { id: "T1556.003", name: "Pluggable Authentication Modules", description: "Modifying PAM" },
          { id: "T1556.004", name: "Network Device Authentication", description: "Modifying network device auth" },
          { id: "T1556.006", name: "Multi-Factor Authentication", description: "Modifying MFA" },
        ],
        url: "https://attack.mitre.org/techniques/T1556",
      },
      {
        id: "T1137",
        name: "Office Application Startup",
        description: "Using Office app startup",
        tactics: ["persistence"],
        subtechniques: [
          { id: "T1137.001", name: "Office Template Macros", description: "Using Office template macros" },
          { id: "T1137.006", name: "Add-ins", description: "Using Office add-ins" },
        ],
        url: "https://attack.mitre.org/techniques/T1137",
      },
      {
        id: "T1542",
        name: "Pre-OS Boot",
        description: "Using pre-OS boot mechanisms",
        tactics: ["persistence", "defense_evasion"],
        subtechniques: [
          { id: "T1542.001", name: "System Firmware", description: "Modifying system firmware" },
          { id: "T1542.003", name: "Bootkit", description: "Using bootkits" },
        ],
        url: "https://attack.mitre.org/techniques/T1542",
      },
      {
        id: "T1505",
        name: "Server Software Component",
        description: "Using server software components",
        tactics: ["persistence"],
        subtechniques: [
          { id: "T1505.001", name: "SQL Stored Procedures", description: "Using SQL stored procedures" },
          { id: "T1505.003", name: "Web Shell", description: "Using web shells" },
          { id: "T1505.004", name: "IIS Components", description: "Using IIS components" },
        ],
        url: "https://attack.mitre.org/techniques/T1505",
      },
      {
        id: "T1205",
        name: "Traffic Signaling",
        description: "Using traffic signaling",
        tactics: ["persistence", "defense_evasion", "command_and_control"],
        subtechniques: [{ id: "T1205.001", name: "Port Knocking", description: "Using port knocking" }],
        url: "https://attack.mitre.org/techniques/T1205",
      },
    ],
  },
  {
    id: "TA0004",
    shortName: "privilege_escalation",
    name: "Privilege Escalation",
    description: "Trying to gain higher-level permissions",
    techniques: [
      {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism",
        description: "Abusing elevation controls",
        tactics: ["privilege_escalation", "defense_evasion"],
        subtechniques: [
          { id: "T1548.001", name: "Setuid and Setgid", description: "Using setuid/setgid" },
          { id: "T1548.002", name: "Bypass User Account Control", description: "Bypassing UAC" },
          { id: "T1548.003", name: "Sudo and Sudo Caching", description: "Abusing sudo" },
          { id: "T1548.004", name: "Elevated Execution with Prompt", description: "Using elevation prompts" },
        ],
        url: "https://attack.mitre.org/techniques/T1548",
      },
      {
        id: "T1134",
        name: "Access Token Manipulation",
        description: "Manipulating access tokens",
        tactics: ["privilege_escalation", "defense_evasion"],
        subtechniques: [
          { id: "T1134.001", name: "Token Impersonation/Theft", description: "Impersonating tokens" },
          { id: "T1134.002", name: "Create Process with Token", description: "Creating processes with tokens" },
          { id: "T1134.003", name: "Make and Impersonate Token", description: "Making and impersonating tokens" },
          { id: "T1134.005", name: "SID-History Injection", description: "Injecting SID history" },
        ],
        url: "https://attack.mitre.org/techniques/T1134",
      },
      {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        description: "Exploiting for privilege escalation",
        tactics: ["privilege_escalation"],
        url: "https://attack.mitre.org/techniques/T1068",
      },
      {
        id: "T1484",
        name: "Domain or Tenant Policy Modification",
        description: "Modifying domain/tenant policies",
        tactics: ["privilege_escalation", "defense_evasion"],
        subtechniques: [
          { id: "T1484.001", name: "Group Policy Modification", description: "Modifying group policy" },
          { id: "T1484.002", name: "Trust Modification", description: "Modifying domain trusts" },
        ],
        url: "https://attack.mitre.org/techniques/T1484",
      },
      {
        id: "T1611",
        name: "Escape to Host",
        description: "Escaping container to host",
        tactics: ["privilege_escalation"],
        url: "https://attack.mitre.org/techniques/T1611",
      },
      {
        id: "T1055",
        name: "Process Injection",
        description: "Injecting into processes",
        tactics: ["privilege_escalation", "defense_evasion"],
        subtechniques: [
          { id: "T1055.001", name: "Dynamic-link Library Injection", description: "DLL injection" },
          { id: "T1055.002", name: "Portable Executable Injection", description: "PE injection" },
          { id: "T1055.003", name: "Thread Execution Hijacking", description: "Thread hijacking" },
          { id: "T1055.004", name: "Asynchronous Procedure Call", description: "APC injection" },
          { id: "T1055.008", name: "Ptrace System Calls", description: "Using ptrace" },
          { id: "T1055.012", name: "Process Hollowing", description: "Process hollowing" },
        ],
        url: "https://attack.mitre.org/techniques/T1055",
      },
    ],
  },
  {
    id: "TA0005",
    shortName: "defense_evasion",
    name: "Defense Evasion",
    description: "Trying to avoid being detected",
    techniques: [
      {
        id: "T1140",
        name: "Deobfuscate/Decode Files or Information",
        description: "Deobfuscating files",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1140",
      },
      {
        id: "T1006",
        name: "Direct Volume Access",
        description: "Accessing volumes directly",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1006",
      },
      {
        id: "T1480",
        name: "Execution Guardrails",
        description: "Using execution guardrails",
        tactics: ["defense_evasion"],
        subtechniques: [{ id: "T1480.001", name: "Environmental Keying", description: "Using environmental keying" }],
        url: "https://attack.mitre.org/techniques/T1480",
      },
      {
        id: "T1211",
        name: "Exploitation for Defense Evasion",
        description: "Exploiting for defense evasion",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1211",
      },
      {
        id: "T1222",
        name: "File and Directory Permissions Modification",
        description: "Modifying file permissions",
        tactics: ["defense_evasion"],
        subtechniques: [
          {
            id: "T1222.001",
            name: "Windows File and Directory Permissions Modification",
            description: "Modifying Windows permissions",
          },
          {
            id: "T1222.002",
            name: "Linux and Mac File and Directory Permissions Modification",
            description: "Modifying Linux/Mac permissions",
          },
        ],
        url: "https://attack.mitre.org/techniques/T1222",
      },
      {
        id: "T1564",
        name: "Hide Artifacts",
        description: "Hiding artifacts",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1564.001", name: "Hidden Files and Directories", description: "Using hidden files" },
          { id: "T1564.002", name: "Hidden Users", description: "Hiding users" },
          { id: "T1564.003", name: "Hidden Window", description: "Using hidden windows" },
          { id: "T1564.004", name: "NTFS File Attributes", description: "Using NTFS file attributes" },
          { id: "T1564.006", name: "Run Virtual Instance", description: "Running virtual instances" },
          { id: "T1564.008", name: "Email Hiding Rules", description: "Using email hiding rules" },
        ],
        url: "https://attack.mitre.org/techniques/T1564",
      },
      {
        id: "T1562",
        name: "Impair Defenses",
        description: "Impairing defenses",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1562.001", name: "Disable or Modify Tools", description: "Disabling security tools" },
          { id: "T1562.002", name: "Disable Windows Event Logging", description: "Disabling event logging" },
          { id: "T1562.003", name: "Impair Command History Logging", description: "Impairing command history" },
          { id: "T1562.004", name: "Disable or Modify System Firewall", description: "Disabling firewall" },
          { id: "T1562.006", name: "Indicator Blocking", description: "Blocking indicators" },
          { id: "T1562.007", name: "Disable or Modify Cloud Firewall", description: "Disabling cloud firewall" },
          { id: "T1562.008", name: "Disable or Modify Cloud Logs", description: "Disabling cloud logs" },
          { id: "T1562.010", name: "Downgrade Attack", description: "Downgrading security protocols" },
          { id: "T1562.012", name: "Disable or Modify Linux Audit System", description: "Disabling Linux audit" },
        ],
        url: "https://attack.mitre.org/techniques/T1562",
      },
      {
        id: "T1070",
        name: "Indicator Removal",
        description: "Removing indicators",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1070.001", name: "Clear Windows Event Logs", description: "Clearing Windows event logs" },
          { id: "T1070.002", name: "Clear Linux or Mac System Logs", description: "Clearing Linux/Mac logs" },
          { id: "T1070.003", name: "Clear Command History", description: "Clearing command history" },
          { id: "T1070.004", name: "File Deletion", description: "Deleting files" },
          { id: "T1070.006", name: "Timestomp", description: "Timestomping files" },
          { id: "T1070.009", name: "Clear Persistence", description: "Clearing persistence" },
        ],
        url: "https://attack.mitre.org/techniques/T1070",
      },
      {
        id: "T1202",
        name: "Indirect Command Execution",
        description: "Using indirect command execution",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1202",
      },
      {
        id: "T1036",
        name: "Masquerading",
        description: "Masquerading",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1036.001", name: "Invalid Code Signature", description: "Using invalid code signatures" },
          { id: "T1036.003", name: "Rename System Utilities", description: "Renaming system utilities" },
          { id: "T1036.004", name: "Masquerade Task or Service", description: "Masquerading tasks" },
          { id: "T1036.005", name: "Match Legitimate Name or Location", description: "Matching legitimate names" },
          { id: "T1036.007", name: "Double File Extension", description: "Using double file extensions" },
        ],
        url: "https://attack.mitre.org/techniques/T1036",
      },
      {
        id: "T1112",
        name: "Modify Registry",
        description: "Modifying the Windows registry",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1112",
      },
      {
        id: "T1027",
        name: "Obfuscated Files or Information",
        description: "Obfuscating files or information",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1027.001", name: "Binary Padding", description: "Using binary padding" },
          { id: "T1027.002", name: "Software Packing", description: "Using software packing" },
          { id: "T1027.003", name: "Steganography", description: "Using steganography" },
          { id: "T1027.004", name: "Compile After Delivery", description: "Compiling after delivery" },
          { id: "T1027.005", name: "Indicator Removal from Tools", description: "Removing indicators" },
          { id: "T1027.006", name: "HTML Smuggling", description: "Using HTML smuggling" },
          { id: "T1027.009", name: "Embedded Payloads", description: "Using embedded payloads" },
          { id: "T1027.010", name: "Command Obfuscation", description: "Obfuscating commands" },
          { id: "T1027.011", name: "Fileless Storage", description: "Using fileless storage" },
          { id: "T1027.013", name: "Encrypted/Encoded File", description: "Using encrypted/encoded files" },
        ],
        url: "https://attack.mitre.org/techniques/T1027",
      },
      {
        id: "T1553",
        name: "Subvert Trust Controls",
        description: "Subverting trust controls",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1553.001", name: "Gatekeeper Bypass", description: "Bypassing Gatekeeper" },
          { id: "T1553.002", name: "Code Signing", description: "Using code signing" },
          { id: "T1553.004", name: "Install Root Certificate", description: "Installing root certs" },
          { id: "T1553.006", name: "Code Signing Policy Modification", description: "Modifying code signing policy" },
        ],
        url: "https://attack.mitre.org/techniques/T1553",
      },
      {
        id: "T1218",
        name: "System Binary Proxy Execution",
        description: "Using system binary proxies",
        tactics: ["defense_evasion"],
        subtechniques: [
          { id: "T1218.001", name: "Compiled HTML File", description: "Using compiled HTML" },
          { id: "T1218.003", name: "CMSTP", description: "Using CMSTP" },
          { id: "T1218.005", name: "Mshta", description: "Using mshta" },
          { id: "T1218.007", name: "Msiexec", description: "Using msiexec" },
          { id: "T1218.010", name: "Regsvr32", description: "Using Regsvr32" },
          { id: "T1218.011", name: "Rundll32", description: "Using Rundll32" },
          { id: "T1218.014", name: "MMC", description: "Using MMC" },
        ],
        url: "https://attack.mitre.org/techniques/T1218",
      },
      {
        id: "T1221",
        name: "Template Injection",
        description: "Using template injection",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1221",
      },
      {
        id: "T1535",
        name: "Unused/Unsupported Cloud Regions",
        description: "Using unused cloud regions",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1535",
      },
      {
        id: "T1550",
        name: "Use Alternate Authentication Material",
        description: "Using alternate auth material",
        tactics: ["defense_evasion", "lateral_movement"],
        subtechniques: [
          { id: "T1550.001", name: "Application Access Token", description: "Using application tokens" },
          { id: "T1550.002", name: "Pass the Hash", description: "Using pass the hash" },
          { id: "T1550.003", name: "Pass the Ticket", description: "Using pass the ticket" },
          { id: "T1550.004", name: "Web Session Cookie", description: "Using web session cookies" },
        ],
        url: "https://attack.mitre.org/techniques/T1550",
      },
      {
        id: "T1497",
        name: "Virtualization/Sandbox Evasion",
        description: "Evading virtualization/sandbox",
        tactics: ["defense_evasion", "discovery"],
        subtechniques: [
          { id: "T1497.001", name: "System Checks", description: "Using system checks" },
          { id: "T1497.002", name: "User Activity Based Checks", description: "Using user activity checks" },
          { id: "T1497.003", name: "Time Based Evasion", description: "Using time-based evasion" },
        ],
        url: "https://attack.mitre.org/techniques/T1497",
      },
      {
        id: "T1620",
        name: "Reflective Code Loading",
        description: "Using reflective code loading",
        tactics: ["defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1620",
      },
    ],
  },
  {
    id: "TA0006",
    shortName: "credential_access",
    name: "Credential Access",
    description: "Trying to steal account names and passwords",
    techniques: [
      {
        id: "T1557",
        name: "Adversary-in-the-Middle",
        description: "Performing AitM attacks",
        tactics: ["credential_access", "collection"],
        subtechniques: [
          {
            id: "T1557.001",
            name: "LLMNR/NBT-NS Poisoning and SMB Relay",
            description: "Using LLMNR/NBT-NS poisoning",
          },
          { id: "T1557.002", name: "ARP Cache Poisoning", description: "Using ARP cache poisoning" },
          { id: "T1557.003", name: "DHCP Spoofing", description: "Using DHCP spoofing" },
        ],
        url: "https://attack.mitre.org/techniques/T1557",
      },
      {
        id: "T1110",
        name: "Brute Force",
        description: "Brute forcing credentials",
        tactics: ["credential_access"],
        subtechniques: [
          { id: "T1110.001", name: "Password Guessing", description: "Guessing passwords" },
          { id: "T1110.002", name: "Password Cracking", description: "Cracking passwords" },
          { id: "T1110.003", name: "Password Spraying", description: "Spraying passwords" },
          { id: "T1110.004", name: "Credential Stuffing", description: "Stuffing credentials" },
        ],
        url: "https://attack.mitre.org/techniques/T1110",
      },
      {
        id: "T1555",
        name: "Credentials from Password Stores",
        description: "Extracting credentials from stores",
        tactics: ["credential_access"],
        subtechniques: [
          { id: "T1555.001", name: "Keychain", description: "Accessing keychain" },
          { id: "T1555.003", name: "Credentials from Web Browsers", description: "Extracting from browsers" },
          { id: "T1555.004", name: "Windows Credential Manager", description: "Accessing Credential Manager" },
          { id: "T1555.005", name: "Password Managers", description: "Accessing password managers" },
          { id: "T1555.006", name: "Cloud Secrets Management Stores", description: "Accessing cloud secrets" },
        ],
        url: "https://attack.mitre.org/techniques/T1555",
      },
      {
        id: "T1212",
        name: "Exploitation for Credential Access",
        description: "Exploiting for credential access",
        tactics: ["credential_access"],
        url: "https://attack.mitre.org/techniques/T1212",
      },
      {
        id: "T1187",
        name: "Forced Authentication",
        description: "Forcing authentication",
        tactics: ["credential_access"],
        url: "https://attack.mitre.org/techniques/T1187",
      },
      {
        id: "T1606",
        name: "Forge Web Credentials",
        description: "Forging web credentials",
        tactics: ["credential_access"],
        subtechniques: [
          { id: "T1606.001", name: "Web Cookies", description: "Forging web cookies" },
          { id: "T1606.002", name: "SAML Tokens", description: "Forging SAML tokens" },
        ],
        url: "https://attack.mitre.org/techniques/T1606",
      },
      {
        id: "T1056",
        name: "Input Capture",
        description: "Capturing input",
        tactics: ["credential_access", "collection"],
        subtechniques: [
          { id: "T1056.001", name: "Keylogging", description: "Using keyloggers" },
          { id: "T1056.002", name: "GUI Input Capture", description: "Capturing GUI input" },
          { id: "T1056.003", name: "Web Portal Capture", description: "Capturing web portal input" },
          { id: "T1056.004", name: "Credential API Hooking", description: "Hooking credential APIs" },
        ],
        url: "https://attack.mitre.org/techniques/T1056",
      },
      {
        id: "T1111",
        name: "Multi-Factor Authentication Interception",
        description: "Intercepting MFA",
        tactics: ["credential_access"],
        url: "https://attack.mitre.org/techniques/T1111",
      },
      {
        id: "T1621",
        name: "Multi-Factor Authentication Request Generation",
        description: "MFA fatigue attacks",
        tactics: ["credential_access"],
        url: "https://attack.mitre.org/techniques/T1621",
      },
      {
        id: "T1040",
        name: "Network Sniffing",
        description: "Sniffing network traffic",
        tactics: ["credential_access", "discovery"],
        url: "https://attack.mitre.org/techniques/T1040",
      },
      {
        id: "T1003",
        name: "OS Credential Dumping",
        description: "Dumping OS credentials",
        tactics: ["credential_access"],
        subtechniques: [
          { id: "T1003.001", name: "LSASS Memory", description: "Dumping LSASS memory" },
          { id: "T1003.002", name: "Security Account Manager", description: "Accessing SAM" },
          { id: "T1003.003", name: "NTDS", description: "Accessing NTDS" },
          { id: "T1003.004", name: "LSA Secrets", description: "Accessing LSA secrets" },
          { id: "T1003.006", name: "DCSync", description: "Using DCSync" },
          { id: "T1003.007", name: "Proc Filesystem", description: "Accessing proc filesystem" },
          { id: "T1003.008", name: "/etc/passwd and /etc/shadow", description: "Accessing passwd/shadow" },
        ],
        url: "https://attack.mitre.org/techniques/T1003",
      },
      {
        id: "T1528",
        name: "Steal Application Access Token",
        description: "Stealing application tokens",
        tactics: ["credential_access"],
        url: "https://attack.mitre.org/techniques/T1528",
      },
      {
        id: "T1558",
        name: "Steal or Forge Kerberos Tickets",
        description: "Stealing/forging Kerberos tickets",
        tactics: ["credential_access"],
        subtechniques: [
          { id: "T1558.001", name: "Golden Ticket", description: "Using golden tickets" },
          { id: "T1558.002", name: "Silver Ticket", description: "Using silver tickets" },
          { id: "T1558.003", name: "Kerberoasting", description: "Performing Kerberoasting" },
          { id: "T1558.004", name: "AS-REP Roasting", description: "Performing AS-REP roasting" },
        ],
        url: "https://attack.mitre.org/techniques/T1558",
      },
      {
        id: "T1539",
        name: "Steal Web Session Cookie",
        description: "Stealing web session cookies",
        tactics: ["credential_access"],
        url: "https://attack.mitre.org/techniques/T1539",
      },
      {
        id: "T1552",
        name: "Unsecured Credentials",
        description: "Accessing unsecured credentials",
        tactics: ["credential_access"],
        subtechniques: [
          { id: "T1552.001", name: "Credentials In Files", description: "Finding credentials in files" },
          { id: "T1552.002", name: "Credentials in Registry", description: "Finding credentials in registry" },
          { id: "T1552.004", name: "Private Keys", description: "Finding private keys" },
          { id: "T1552.006", name: "Group Policy Preferences", description: "Finding GPP credentials" },
          { id: "T1552.007", name: "Container API", description: "Finding credentials in container APIs" },
          { id: "T1552.008", name: "Chat Messages", description: "Finding credentials in chat messages" },
        ],
        url: "https://attack.mitre.org/techniques/T1552",
      },
    ],
  },
  {
    id: "TA0007",
    shortName: "discovery",
    name: "Discovery",
    description: "Trying to figure out your environment",
    techniques: [
      {
        id: "T1087",
        name: "Account Discovery",
        description: "Discovering accounts",
        tactics: ["discovery"],
        subtechniques: [
          { id: "T1087.001", name: "Local Account", description: "Discovering local accounts" },
          { id: "T1087.002", name: "Domain Account", description: "Discovering domain accounts" },
          { id: "T1087.003", name: "Email Account", description: "Discovering email accounts" },
          { id: "T1087.004", name: "Cloud Account", description: "Discovering cloud accounts" },
        ],
        url: "https://attack.mitre.org/techniques/T1087",
      },
      {
        id: "T1010",
        name: "Application Window Discovery",
        description: "Discovering application windows",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1010",
      },
      {
        id: "T1217",
        name: "Browser Information Discovery",
        description: "Discovering browser information",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1217",
      },
      {
        id: "T1580",
        name: "Cloud Infrastructure Discovery",
        description: "Discovering cloud infrastructure",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1580",
      },
      {
        id: "T1538",
        name: "Cloud Service Dashboard",
        description: "Using cloud service dashboards",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1538",
      },
      {
        id: "T1526",
        name: "Cloud Service Discovery",
        description: "Discovering cloud services",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1526",
      },
      {
        id: "T1613",
        name: "Container and Resource Discovery",
        description: "Discovering containers",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1613",
      },
      {
        id: "T1622",
        name: "Debugger Evasion",
        description: "Evading debuggers",
        tactics: ["discovery", "defense_evasion"],
        url: "https://attack.mitre.org/techniques/T1622",
      },
      {
        id: "T1482",
        name: "Domain Trust Discovery",
        description: "Discovering domain trusts",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1482",
      },
      {
        id: "T1083",
        name: "File and Directory Discovery",
        description: "Discovering files and directories",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1083",
      },
      {
        id: "T1046",
        name: "Network Service Discovery",
        description: "Discovering network services",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1046",
      },
      {
        id: "T1135",
        name: "Network Share Discovery",
        description: "Discovering network shares",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1135",
      },
      {
        id: "T1120",
        name: "Peripheral Device Discovery",
        description: "Discovering peripheral devices",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1120",
      },
      {
        id: "T1069",
        name: "Permission Groups Discovery",
        description: "Discovering permission groups",
        tactics: ["discovery"],
        subtechniques: [
          { id: "T1069.001", name: "Local Groups", description: "Discovering local groups" },
          { id: "T1069.002", name: "Domain Groups", description: "Discovering domain groups" },
          { id: "T1069.003", name: "Cloud Groups", description: "Discovering cloud groups" },
        ],
        url: "https://attack.mitre.org/techniques/T1069",
      },
      {
        id: "T1057",
        name: "Process Discovery",
        description: "Discovering processes",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1057",
      },
      {
        id: "T1012",
        name: "Query Registry",
        description: "Querying the registry",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1012",
      },
      {
        id: "T1018",
        name: "Remote System Discovery",
        description: "Discovering remote systems",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1018",
      },
      {
        id: "T1518",
        name: "Software Discovery",
        description: "Discovering software",
        tactics: ["discovery"],
        subtechniques: [
          { id: "T1518.001", name: "Security Software Discovery", description: "Discovering security software" },
        ],
        url: "https://attack.mitre.org/techniques/T1518",
      },
      {
        id: "T1082",
        name: "System Information Discovery",
        description: "Discovering system information",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1082",
      },
      {
        id: "T1614",
        name: "System Location Discovery",
        description: "Discovering system location",
        tactics: ["discovery"],
        subtechniques: [
          { id: "T1614.001", name: "System Language Discovery", description: "Discovering system language" },
        ],
        url: "https://attack.mitre.org/techniques/T1614",
      },
      {
        id: "T1016",
        name: "System Network Configuration Discovery",
        description: "Discovering network configuration",
        tactics: ["discovery"],
        subtechniques: [
          { id: "T1016.001", name: "Internet Connection Discovery", description: "Discovering internet connection" },
        ],
        url: "https://attack.mitre.org/techniques/T1016",
      },
      {
        id: "T1049",
        name: "System Network Connections Discovery",
        description: "Discovering network connections",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1049",
      },
      {
        id: "T1033",
        name: "System Owner/User Discovery",
        description: "Discovering system owner/user",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1033",
      },
      {
        id: "T1007",
        name: "System Service Discovery",
        description: "Discovering system services",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1007",
      },
      {
        id: "T1124",
        name: "System Time Discovery",
        description: "Discovering system time",
        tactics: ["discovery"],
        url: "https://attack.mitre.org/techniques/T1124",
      },
    ],
  },
  {
    id: "TA0008",
    shortName: "lateral_movement",
    name: "Lateral Movement",
    description: "Trying to move through your environment",
    techniques: [
      {
        id: "T1210",
        name: "Exploitation of Remote Services",
        description: "Exploiting remote services",
        tactics: ["lateral_movement"],
        url: "https://attack.mitre.org/techniques/T1210",
      },
      {
        id: "T1534",
        name: "Internal Spearphishing",
        description: "Internal spearphishing",
        tactics: ["lateral_movement"],
        url: "https://attack.mitre.org/techniques/T1534",
      },
      {
        id: "T1570",
        name: "Lateral Tool Transfer",
        description: "Transferring tools laterally",
        tactics: ["lateral_movement"],
        url: "https://attack.mitre.org/techniques/T1570",
      },
      {
        id: "T1563",
        name: "Remote Service Session Hijacking",
        description: "Hijacking remote sessions",
        tactics: ["lateral_movement"],
        subtechniques: [
          { id: "T1563.001", name: "SSH Hijacking", description: "Hijacking SSH sessions" },
          { id: "T1563.002", name: "RDP Hijacking", description: "Hijacking RDP sessions" },
        ],
        url: "https://attack.mitre.org/techniques/T1563",
      },
      {
        id: "T1021",
        name: "Remote Services",
        description: "Using remote services",
        tactics: ["lateral_movement"],
        subtechniques: [
          { id: "T1021.001", name: "Remote Desktop Protocol", description: "Using RDP" },
          { id: "T1021.002", name: "SMB/Windows Admin Shares", description: "Using SMB shares" },
          { id: "T1021.003", name: "Distributed Component Object Model", description: "Using DCOM" },
          { id: "T1021.004", name: "SSH", description: "Using SSH" },
          { id: "T1021.005", name: "VNC", description: "Using VNC" },
          { id: "T1021.006", name: "Windows Remote Management", description: "Using WinRM" },
          { id: "T1021.007", name: "Cloud Services", description: "Using cloud services" },
        ],
        url: "https://attack.mitre.org/techniques/T1021",
      },
      {
        id: "T1080",
        name: "Taint Shared Content",
        description: "Tainting shared content",
        tactics: ["lateral_movement"],
        url: "https://attack.mitre.org/techniques/T1080",
      },
    ],
  },
  {
    id: "TA0009",
    shortName: "collection",
    name: "Collection",
    description: "Trying to gather data of interest",
    techniques: [
      {
        id: "T1560",
        name: "Archive Collected Data",
        description: "Archiving collected data",
        tactics: ["collection"],
        subtechniques: [
          { id: "T1560.001", name: "Archive via Utility", description: "Using archiving utilities" },
          { id: "T1560.002", name: "Archive via Library", description: "Using archiving libraries" },
          { id: "T1560.003", name: "Archive via Custom Method", description: "Using custom archiving" },
        ],
        url: "https://attack.mitre.org/techniques/T1560",
      },
      {
        id: "T1123",
        name: "Audio Capture",
        description: "Capturing audio",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1123",
      },
      {
        id: "T1119",
        name: "Automated Collection",
        description: "Automating data collection",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1119",
      },
      {
        id: "T1185",
        name: "Browser Session Hijacking",
        description: "Hijacking browser sessions",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1185",
      },
      {
        id: "T1115",
        name: "Clipboard Data",
        description: "Collecting clipboard data",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1115",
      },
      {
        id: "T1530",
        name: "Data from Cloud Storage",
        description: "Collecting cloud storage data",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1530",
      },
      {
        id: "T1602",
        name: "Data from Configuration Repository",
        description: "Collecting config data",
        tactics: ["collection"],
        subtechniques: [
          { id: "T1602.001", name: "SNMP (MIB Dump)", description: "Using SNMP MIB dumps" },
          { id: "T1602.002", name: "Network Device Configuration Dump", description: "Dumping device config" },
        ],
        url: "https://attack.mitre.org/techniques/T1602",
      },
      {
        id: "T1213",
        name: "Data from Information Repositories",
        description: "Collecting from info repos",
        tactics: ["collection"],
        subtechniques: [
          { id: "T1213.001", name: "Confluence", description: "Collecting from Confluence" },
          { id: "T1213.002", name: "Sharepoint", description: "Collecting from SharePoint" },
          { id: "T1213.003", name: "Code Repositories", description: "Collecting from code repos" },
        ],
        url: "https://attack.mitre.org/techniques/T1213",
      },
      {
        id: "T1005",
        name: "Data from Local System",
        description: "Collecting local data",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1005",
      },
      {
        id: "T1039",
        name: "Data from Network Shared Drive",
        description: "Collecting network share data",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1039",
      },
      {
        id: "T1025",
        name: "Data from Removable Media",
        description: "Collecting removable media data",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1025",
      },
      {
        id: "T1074",
        name: "Data Staged",
        description: "Staging collected data",
        tactics: ["collection"],
        subtechniques: [
          { id: "T1074.001", name: "Local Data Staging", description: "Staging data locally" },
          { id: "T1074.002", name: "Remote Data Staging", description: "Staging data remotely" },
        ],
        url: "https://attack.mitre.org/techniques/T1074",
      },
      {
        id: "T1114",
        name: "Email Collection",
        description: "Collecting emails",
        tactics: ["collection"],
        subtechniques: [
          { id: "T1114.001", name: "Local Email Collection", description: "Collecting local emails" },
          { id: "T1114.002", name: "Remote Email Collection", description: "Collecting remote emails" },
          { id: "T1114.003", name: "Email Forwarding Rule", description: "Using email forwarding rules" },
        ],
        url: "https://attack.mitre.org/techniques/T1114",
      },
      {
        id: "T1113",
        name: "Screen Capture",
        description: "Capturing screen",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1113",
      },
      {
        id: "T1125",
        name: "Video Capture",
        description: "Capturing video",
        tactics: ["collection"],
        url: "https://attack.mitre.org/techniques/T1125",
      },
    ],
  },
  {
    id: "TA0011",
    shortName: "command_and_control",
    name: "Command and Control",
    description: "Communicating with compromised systems",
    techniques: [
      {
        id: "T1071",
        name: "Application Layer Protocol",
        description: "Using application layer protocols",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1071.001", name: "Web Protocols", description: "Using HTTP/HTTPS" },
          { id: "T1071.002", name: "File Transfer Protocols", description: "Using FTP/SFTP" },
          { id: "T1071.003", name: "Mail Protocols", description: "Using mail protocols" },
          { id: "T1071.004", name: "DNS", description: "Using DNS for C2" },
        ],
        url: "https://attack.mitre.org/techniques/T1071",
      },
      {
        id: "T1132",
        name: "Data Encoding",
        description: "Encoding C2 data",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1132.001", name: "Standard Encoding", description: "Using standard encoding" },
          { id: "T1132.002", name: "Non-Standard Encoding", description: "Using non-standard encoding" },
        ],
        url: "https://attack.mitre.org/techniques/T1132",
      },
      {
        id: "T1001",
        name: "Data Obfuscation",
        description: "Obfuscating C2 data",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1001.001", name: "Junk Data", description: "Using junk data" },
          { id: "T1001.002", name: "Steganography", description: "Using steganography" },
          { id: "T1001.003", name: "Protocol Impersonation", description: "Impersonating protocols" },
        ],
        url: "https://attack.mitre.org/techniques/T1001",
      },
      {
        id: "T1568",
        name: "Dynamic Resolution",
        description: "Using dynamic resolution",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1568.001", name: "Fast Flux DNS", description: "Using fast flux DNS" },
          { id: "T1568.002", name: "Domain Generation Algorithms", description: "Using DGA" },
          { id: "T1568.003", name: "DNS Calculation", description: "Using DNS calculation" },
        ],
        url: "https://attack.mitre.org/techniques/T1568",
      },
      {
        id: "T1573",
        name: "Encrypted Channel",
        description: "Using encrypted channels",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1573.001", name: "Symmetric Cryptography", description: "Using symmetric crypto" },
          { id: "T1573.002", name: "Asymmetric Cryptography", description: "Using asymmetric crypto" },
        ],
        url: "https://attack.mitre.org/techniques/T1573",
      },
      {
        id: "T1008",
        name: "Fallback Channels",
        description: "Using fallback channels",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1008",
      },
      {
        id: "T1105",
        name: "Ingress Tool Transfer",
        description: "Transferring tools into network",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1105",
      },
      {
        id: "T1104",
        name: "Multi-Stage Channels",
        description: "Using multi-stage channels",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1104",
      },
      {
        id: "T1095",
        name: "Non-Application Layer Protocol",
        description: "Using non-application protocols",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1095",
      },
      {
        id: "T1571",
        name: "Non-Standard Port",
        description: "Using non-standard ports",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1571",
      },
      {
        id: "T1572",
        name: "Protocol Tunneling",
        description: "Using protocol tunneling",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1572",
      },
      {
        id: "T1090",
        name: "Proxy",
        description: "Using proxies",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1090.001", name: "Internal Proxy", description: "Using internal proxies" },
          { id: "T1090.002", name: "External Proxy", description: "Using external proxies" },
          { id: "T1090.003", name: "Multi-hop Proxy", description: "Using multi-hop proxies" },
          { id: "T1090.004", name: "Domain Fronting", description: "Using domain fronting" },
        ],
        url: "https://attack.mitre.org/techniques/T1090",
      },
      {
        id: "T1219",
        name: "Remote Access Software",
        description: "Using remote access software",
        tactics: ["command_and_control"],
        url: "https://attack.mitre.org/techniques/T1219",
      },
      {
        id: "T1102",
        name: "Web Service",
        description: "Using web services for C2",
        tactics: ["command_and_control"],
        subtechniques: [
          { id: "T1102.001", name: "Dead Drop Resolver", description: "Using dead drop resolvers" },
          { id: "T1102.002", name: "Bidirectional Communication", description: "Using bidirectional communication" },
          { id: "T1102.003", name: "One-Way Communication", description: "Using one-way communication" },
        ],
        url: "https://attack.mitre.org/techniques/T1102",
      },
    ],
  },
  {
    id: "TA0010",
    shortName: "exfiltration",
    name: "Exfiltration",
    description: "Trying to steal data",
    techniques: [
      {
        id: "T1020",
        name: "Automated Exfiltration",
        description: "Automating exfiltration",
        tactics: ["exfiltration"],
        subtechniques: [{ id: "T1020.001", name: "Traffic Duplication", description: "Using traffic duplication" }],
        url: "https://attack.mitre.org/techniques/T1020",
      },
      {
        id: "T1030",
        name: "Data Transfer Size Limits",
        description: "Using size limits",
        tactics: ["exfiltration"],
        url: "https://attack.mitre.org/techniques/T1030",
      },
      {
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        description: "Using alternative protocols",
        tactics: ["exfiltration"],
        subtechniques: [
          {
            id: "T1048.001",
            name: "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
            description: "Using symmetric encrypted protocols",
          },
          {
            id: "T1048.002",
            name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
            description: "Using asymmetric encrypted protocols",
          },
          {
            id: "T1048.003",
            name: "Exfiltration Over Unencrypted Non-C2 Protocol",
            description: "Using unencrypted protocols",
          },
        ],
        url: "https://attack.mitre.org/techniques/T1048",
      },
      {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        description: "Using C2 channel",
        tactics: ["exfiltration"],
        url: "https://attack.mitre.org/techniques/T1041",
      },
      {
        id: "T1011",
        name: "Exfiltration Over Other Network Medium",
        description: "Using other network media",
        tactics: ["exfiltration"],
        subtechniques: [{ id: "T1011.001", name: "Exfiltration Over Bluetooth", description: "Using Bluetooth" }],
        url: "https://attack.mitre.org/techniques/T1011",
      },
      {
        id: "T1052",
        name: "Exfiltration Over Physical Medium",
        description: "Using physical media",
        tactics: ["exfiltration"],
        subtechniques: [{ id: "T1052.001", name: "Exfiltration over USB", description: "Using USB" }],
        url: "https://attack.mitre.org/techniques/T1052",
      },
      {
        id: "T1567",
        name: "Exfiltration Over Web Service",
        description: "Using web services",
        tactics: ["exfiltration"],
        subtechniques: [
          { id: "T1567.001", name: "Exfiltration to Code Repository", description: "Exfiltrating to code repos" },
          { id: "T1567.002", name: "Exfiltration to Cloud Storage", description: "Exfiltrating to cloud storage" },
          { id: "T1567.003", name: "Exfiltration to Text Storage Sites", description: "Exfiltrating to paste sites" },
          { id: "T1567.004", name: "Exfiltration Over Webhook", description: "Exfiltrating via webhooks" },
        ],
        url: "https://attack.mitre.org/techniques/T1567",
      },
      {
        id: "T1029",
        name: "Scheduled Transfer",
        description: "Using scheduled transfers",
        tactics: ["exfiltration"],
        url: "https://attack.mitre.org/techniques/T1029",
      },
      {
        id: "T1537",
        name: "Transfer Data to Cloud Account",
        description: "Transferring to cloud accounts",
        tactics: ["exfiltration"],
        url: "https://attack.mitre.org/techniques/T1537",
      },
    ],
  },
  {
    id: "TA0040",
    shortName: "impact",
    name: "Impact",
    description: "Trying to manipulate, interrupt, or destroy systems and data",
    techniques: [
      {
        id: "T1531",
        name: "Account Access Removal",
        description: "Removing account access",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1531",
      },
      {
        id: "T1485",
        name: "Data Destruction",
        description: "Destroying data",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1485",
      },
      {
        id: "T1486",
        name: "Data Encrypted for Impact",
        description: "Encrypting data for impact (ransomware)",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1486",
      },
      {
        id: "T1565",
        name: "Data Manipulation",
        description: "Manipulating data",
        tactics: ["impact"],
        subtechniques: [
          { id: "T1565.001", name: "Stored Data Manipulation", description: "Manipulating stored data" },
          { id: "T1565.002", name: "Transmitted Data Manipulation", description: "Manipulating transmitted data" },
          { id: "T1565.003", name: "Runtime Data Manipulation", description: "Manipulating runtime data" },
        ],
        url: "https://attack.mitre.org/techniques/T1565",
      },
      {
        id: "T1491",
        name: "Defacement",
        description: "Defacing resources",
        tactics: ["impact"],
        subtechniques: [
          { id: "T1491.001", name: "Internal Defacement", description: "Internal defacement" },
          { id: "T1491.002", name: "External Defacement", description: "External defacement" },
        ],
        url: "https://attack.mitre.org/techniques/T1491",
      },
      {
        id: "T1561",
        name: "Disk Wipe",
        description: "Wiping disks",
        tactics: ["impact"],
        subtechniques: [
          { id: "T1561.001", name: "Disk Content Wipe", description: "Wiping disk content" },
          { id: "T1561.002", name: "Disk Structure Wipe", description: "Wiping disk structure" },
        ],
        url: "https://attack.mitre.org/techniques/T1561",
      },
      {
        id: "T1499",
        name: "Endpoint Denial of Service",
        description: "Endpoint DoS",
        tactics: ["impact"],
        subtechniques: [
          { id: "T1499.001", name: "OS Exhaustion Flood", description: "OS exhaustion flood" },
          { id: "T1499.002", name: "Service Exhaustion Flood", description: "Service exhaustion flood" },
          { id: "T1499.003", name: "Application Exhaustion Flood", description: "Application exhaustion flood" },
          {
            id: "T1499.004",
            name: "Application or System Exploitation",
            description: "Application/system exploitation DoS",
          },
        ],
        url: "https://attack.mitre.org/techniques/T1499",
      },
      {
        id: "T1657",
        name: "Financial Theft",
        description: "Stealing finances",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1657",
      },
      {
        id: "T1495",
        name: "Firmware Corruption",
        description: "Corrupting firmware",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1495",
      },
      {
        id: "T1490",
        name: "Inhibit System Recovery",
        description: "Inhibiting system recovery",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1490",
      },
      {
        id: "T1498",
        name: "Network Denial of Service",
        description: "Network DoS",
        tactics: ["impact"],
        subtechniques: [
          { id: "T1498.001", name: "Direct Network Flood", description: "Direct network flood" },
          { id: "T1498.002", name: "Reflection Amplification", description: "Reflection amplification" },
        ],
        url: "https://attack.mitre.org/techniques/T1498",
      },
      {
        id: "T1496",
        name: "Resource Hijacking",
        description: "Hijacking resources (cryptomining)",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1496",
      },
      {
        id: "T1489",
        name: "Service Stop",
        description: "Stopping services",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1489",
      },
      {
        id: "T1529",
        name: "System Shutdown/Reboot",
        description: "Shutting down/rebooting systems",
        tactics: ["impact"],
        url: "https://attack.mitre.org/techniques/T1529",
      },
    ],
  },
];

// ── Helpers ──────────────────────────────────────────────────────────

function countAll(): { techniques: number; subtechniques: number; total: number } {
  let techniques = 0;
  let subtechniques = 0;
  for (const tactic of MITRE_TACTICS_DATA) {
    techniques += tactic.techniques.length;
    for (const tech of tactic.techniques) {
      subtechniques += (tech.subtechniques || []).length;
    }
  }
  return { techniques, subtechniques, total: techniques + subtechniques };
}

function findTechnique(
  techniqueId: string,
): { technique: MitreTechnique; tacticName: string; parentTechnique: MitreTechnique | null } | null {
  for (const tactic of MITRE_TACTICS_DATA) {
    for (const tech of tactic.techniques) {
      if (tech.id === techniqueId) {
        return { technique: tech, tacticName: tactic.name, parentTechnique: null };
      }
      for (const sub of tech.subtechniques || []) {
        if (sub.id === techniqueId) {
          const subAsTech: MitreTechnique = {
            ...sub,
            tactics: tech.tactics,
            url: `https://attack.mitre.org/techniques/${sub.id.replace(".", "/")}`,
          };
          return { technique: subAsTech, tacticName: tactic.name, parentTechnique: tech };
        }
      }
    }
  }
  return null;
}

// ── Route Registration ──────────────────────────────────────────────

export function registerMitreAttackRoutes(app: Express): void {
  const auth = [isAuthenticated, resolveOrgContext, requireOrgId];

  // ── 9.1 + 9.6: Full ATT&CK Matrix ────────────────────────────────
  app.get("/api/mitre-attack/matrix", ...auth, async (_req: Request, res: Response) => {
    try {
      const counts = countAll();
      reply(res, {
        version: ATTACK_VERSION,
        lastUpdated: ATTACK_LAST_UPDATED,
        source: "MITRE ATT&CK Enterprise",
        totalTactics: MITRE_TACTICS_DATA.length,
        totalTechniques: counts.techniques,
        totalSubtechniques: counts.subtechniques,
        tactics: MITRE_TACTICS_DATA,
      });
    } catch (err) {
      log.error("Failed to get ATT&CK matrix", { error: String(err) });
      replyError(res, 500, [{ code: "MATRIX_ERROR", message: "Failed to get ATT&CK matrix" }]);
    }
  });

  // ── 9.2 + 9.4 + 9.7: Coverage Analysis ───────────────────────────
  app.get("/api/mitre-attack/coverage", ...auth, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);

      const rulesResult = await pool.query(
        `SELECT id, name, severity, status, mitre_tactic, mitre_technique, mitre_subtechnique,
                match_count, last_match_at
         FROM detection_rules
         WHERE org_id = $1 AND mitre_technique IS NOT NULL`,
        [orgId],
      );

      const alertsResult = await pool.query(
        `SELECT mitre_tactic, mitre_technique, COUNT(*)::int AS alert_count,
                MAX(detected_at) AS last_seen,
                array_agg(DISTINCT severity) AS severities
         FROM alerts
         WHERE org_id = $1
           AND mitre_technique IS NOT NULL
           AND detected_at > NOW() - INTERVAL '90 days'
         GROUP BY mitre_tactic, mitre_technique`,
        [orgId],
      );

      const detAlertResult = await pool.query(
        `SELECT mitre_tactic, mitre_technique, COUNT(*)::int AS alert_count,
                MAX(created_at) AS last_seen
         FROM detection_alerts
         WHERE org_id = $1
           AND mitre_technique IS NOT NULL
           AND created_at > NOW() - INTERVAL '90 days'
         GROUP BY mitre_tactic, mitre_technique`,
        [orgId],
      );

      // Build coverage map
      const coverageMap: Record<
        string,
        {
          techniqueId: string;
          rules: { id: string; name: string; severity: string; status: string; matchCount: number }[];
          alertCount: number;
          detectionAlertCount: number;
          lastSeen: string | null;
          severities: string[];
          coverageLevel: "none" | "low" | "medium" | "high";
        }
      > = {};

      // Initialize all techniques
      for (const tactic of MITRE_TACTICS_DATA) {
        for (const tech of tactic.techniques) {
          if (!coverageMap[tech.id]) {
            coverageMap[tech.id] = {
              techniqueId: tech.id,
              rules: [],
              alertCount: 0,
              detectionAlertCount: 0,
              lastSeen: null,
              severities: [],
              coverageLevel: "none",
            };
          }
          for (const sub of tech.subtechniques || []) {
            if (!coverageMap[sub.id]) {
              coverageMap[sub.id] = {
                techniqueId: sub.id,
                rules: [],
                alertCount: 0,
                detectionAlertCount: 0,
                lastSeen: null,
                severities: [],
                coverageLevel: "none",
              };
            }
          }
        }
      }

      // Map detection rules
      for (const rule of rulesResult.rows) {
        const techId = (rule.mitre_subtechnique || rule.mitre_technique) as string;
        if (techId && coverageMap[techId]) {
          coverageMap[techId].rules.push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            status: rule.status,
            matchCount: rule.match_count || 0,
          });
        }
        if (rule.mitre_technique && coverageMap[rule.mitre_technique as string] && techId !== rule.mitre_technique) {
          coverageMap[rule.mitre_technique as string].rules.push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            status: rule.status,
            matchCount: rule.match_count || 0,
          });
        }
      }

      // Map alerts
      for (const alert of alertsResult.rows) {
        const techId = alert.mitre_technique as string;
        if (techId && coverageMap[techId]) {
          coverageMap[techId].alertCount += alert.alert_count;
          if (alert.last_seen) coverageMap[techId].lastSeen = alert.last_seen;
          if (alert.severities) coverageMap[techId].severities.push(...(alert.severities as string[]));
        }
      }

      for (const alert of detAlertResult.rows) {
        const techId = alert.mitre_technique as string;
        if (techId && coverageMap[techId]) {
          coverageMap[techId].detectionAlertCount += alert.alert_count;
          if (alert.last_seen && !coverageMap[techId].lastSeen) coverageMap[techId].lastSeen = alert.last_seen;
        }
      }

      // Calculate coverage levels
      for (const entry of Object.values(coverageMap)) {
        const enabledRules = entry.rules.filter((r) => r.status === "enabled").length;
        if (enabledRules >= 3) entry.coverageLevel = "high";
        else if (enabledRules >= 1) entry.coverageLevel = "medium";
        else if (entry.alertCount > 0 || entry.detectionAlertCount > 0) entry.coverageLevel = "low";
        else entry.coverageLevel = "none";
      }

      const allTechIds = Object.keys(coverageMap);
      const covered = allTechIds.filter((id) => coverageMap[id].coverageLevel !== "none");
      const uncovered = allTechIds.filter((id) => coverageMap[id].coverageLevel === "none");

      reply(res, {
        summary: {
          totalTechniques: allTechIds.length,
          coveredTechniques: covered.length,
          uncoveredTechniques: uncovered.length,
          coveragePercent: allTechIds.length > 0 ? Math.round((covered.length / allTechIds.length) * 100) : 0,
          highCoverage: allTechIds.filter((id) => coverageMap[id].coverageLevel === "high").length,
          mediumCoverage: allTechIds.filter((id) => coverageMap[id].coverageLevel === "medium").length,
          lowCoverage: allTechIds.filter((id) => coverageMap[id].coverageLevel === "low").length,
          noCoverage: uncovered.length,
          totalDetectionRules: rulesResult.rows.length,
          totalAlerts: alertsResult.rows.reduce((sum: number, r: { alert_count: number }) => sum + r.alert_count, 0),
        },
        coverage: coverageMap,
        gaps: uncovered.map((id) => {
          const found = findTechnique(id);
          if (found)
            return {
              id,
              name: found.technique.name,
              tactic: found.tacticName,
              parentTechnique: found.parentTechnique?.id || null,
            };
          return { id, name: "Unknown", tactic: "Unknown", parentTechnique: null };
        }),
      });
    } catch (err) {
      log.error("Failed to get ATT&CK coverage", { error: String(err) });
      replyError(res, 500, [{ code: "COVERAGE_ERROR", message: "Failed to get ATT&CK coverage" }]);
    }
  });

  // ── 9.3: Technique Detail ─────────────────────────────────────────
  app.get("/api/mitre-attack/technique/:techniqueId", ...auth, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const techniqueId = p(req.params.techniqueId);

      const found = findTechnique(techniqueId);
      if (!found) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Technique not found" }]);
      }

      const rulesResult = await pool.query(
        `SELECT id, name, description, severity, status, match_count, last_match_at, created_at
         FROM detection_rules
         WHERE org_id = $1 AND (mitre_technique = $2 OR mitre_subtechnique = $2)
         ORDER BY match_count DESC`,
        [orgId, techniqueId],
      );

      const alertsResult = await pool.query(
        `SELECT id, title, severity, status, detected_at, source
         FROM alerts
         WHERE org_id = $1 AND mitre_technique = $2
           AND detected_at > NOW() - INTERVAL '30 days'
         ORDER BY detected_at DESC
         LIMIT 20`,
        [orgId, techniqueId],
      );

      const detAlertsResult = await pool.query(
        `SELECT id, title, severity, status, created_at
         FROM detection_alerts
         WHERE org_id = $1 AND mitre_technique = $2
           AND created_at > NOW() - INTERVAL '30 days'
         ORDER BY created_at DESC
         LIMIT 20`,
        [orgId, techniqueId],
      );

      const assetsResult = await pool.query(
        `SELECT DISTINCT a.source_ip, a.destination_ip, COUNT(*)::int AS alert_count
         FROM alerts a
         WHERE a.org_id = $1 AND a.mitre_technique = $2
           AND a.detected_at > NOW() - INTERVAL '90 days'
         GROUP BY a.source_ip, a.destination_ip
         ORDER BY alert_count DESC
         LIMIT 10`,
        [orgId, techniqueId],
      );

      const enabledRules = rulesResult.rows.filter((r: { status: string }) => r.status === "enabled").length;
      let coverageLevel: string;
      if (enabledRules >= 3) coverageLevel = "high";
      else if (enabledRules >= 1) coverageLevel = "medium";
      else if (alertsResult.rows.length > 0 || detAlertsResult.rows.length > 0) coverageLevel = "low";
      else coverageLevel = "none";

      reply(res, {
        technique: {
          ...found.technique,
          tactic: found.tacticName,
          parentTechnique: found.parentTechnique
            ? { id: found.parentTechnique.id, name: found.parentTechnique.name }
            : null,
        },
        coverageLevel,
        detectionRules: rulesResult.rows,
        recentAlerts: alertsResult.rows,
        detectionAlerts: detAlertsResult.rows,
        affectedAssets: assetsResult.rows,
        totalAlertCount: alertsResult.rows.length + detAlertsResult.rows.length,
        totalRuleCount: rulesResult.rows.length,
        enabledRuleCount: enabledRules,
      });
    } catch (err) {
      log.error("Failed to get technique detail", { error: String(err) });
      replyError(res, 500, [{ code: "TECHNIQUE_ERROR", message: "Failed to get technique detail" }]);
    }
  });

  // ── 9.5: ATT&CK Navigator Export ──────────────────────────────────
  app.get("/api/mitre-attack/navigator-export", ...auth, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);

      const rulesResult = await pool.query(
        `SELECT mitre_technique, mitre_subtechnique, COUNT(*)::int AS rule_count
         FROM detection_rules
         WHERE org_id = $1 AND mitre_technique IS NOT NULL AND status = 'enabled'
         GROUP BY mitre_technique, mitre_subtechnique`,
        [orgId],
      );

      const alertsResult = await pool.query(
        `SELECT mitre_technique, COUNT(*)::int AS alert_count
         FROM alerts
         WHERE org_id = $1 AND mitre_technique IS NOT NULL
           AND detected_at > NOW() - INTERVAL '90 days'
         GROUP BY mitre_technique`,
        [orgId],
      );

      const ruleCoverage: Record<string, number> = {};
      for (const r of rulesResult.rows) {
        const id = (r.mitre_subtechnique || r.mitre_technique) as string;
        ruleCoverage[id] = (ruleCoverage[id] || 0) + r.rule_count;
      }
      const alertCoverage: Record<string, number> = {};
      for (const a of alertsResult.rows) {
        alertCoverage[a.mitre_technique as string] = a.alert_count;
      }

      const techniques: {
        techniqueID: string;
        tactic: string;
        score: number;
        color: string;
        comment: string;
        enabled: boolean;
        metadata: never[];
        links: never[];
        showSubtechniques: boolean;
      }[] = [];

      for (const tactic of MITRE_TACTICS_DATA) {
        for (const tech of tactic.techniques) {
          const rCount = ruleCoverage[tech.id] || 0;
          const aCount = alertCoverage[tech.id] || 0;
          let score = 0;
          let color = "";
          if (rCount >= 3) {
            score = 4;
            color = "#1b4332";
          } else if (rCount >= 1) {
            score = 3;
            color = "#40916c";
          } else if (aCount > 0) {
            score = 2;
            color = "#95d5b2";
          }

          techniques.push({
            techniqueID: tech.id,
            tactic: tactic.shortName.replace(/_/g, "-"),
            score,
            color,
            comment:
              rCount > 0
                ? `${rCount} detection rule(s), ${aCount} alert(s)`
                : aCount > 0
                  ? `${aCount} alert(s), no detection rules`
                  : "No coverage",
            enabled: true,
            metadata: [],
            links: [],
            showSubtechniques: (tech.subtechniques || []).length > 0,
          });

          for (const sub of tech.subtechniques || []) {
            const subRCount = ruleCoverage[sub.id] || 0;
            let subScore = 0;
            let subColor = "";
            if (subRCount >= 3) {
              subScore = 4;
              subColor = "#1b4332";
            } else if (subRCount >= 1) {
              subScore = 3;
              subColor = "#40916c";
            }

            techniques.push({
              techniqueID: sub.id,
              tactic: tactic.shortName.replace(/_/g, "-"),
              score: subScore,
              color: subColor,
              comment: subRCount > 0 ? `${subRCount} detection rule(s)` : "No coverage",
              enabled: true,
              metadata: [],
              links: [],
              showSubtechniques: false,
            });
          }
        }
      }

      const navigatorLayer = {
        name: "SecureNexus Detection Coverage",
        versions: { attack: ATTACK_VERSION, navigator: "5.0.1", layer: "4.5" },
        domain: "enterprise-attack",
        description: `Detection coverage exported from SecureNexus on ${new Date().toISOString().split("T")[0]}`,
        filters: { platforms: ["Windows", "Linux", "macOS", "Cloud", "Network", "Containers"] },
        sorting: 3,
        layout: {
          layout: "side",
          aggregateFunction: "average",
          showID: true,
          showName: true,
          showAggregateScores: true,
          countUnscored: false,
        },
        hideDisabled: false,
        techniques,
        gradient: { colors: ["#ffffff", "#95d5b2", "#40916c", "#1b4332"], minValue: 0, maxValue: 4 },
        legendItems: [
          { label: "No Coverage", color: "#ffffff" },
          { label: "Alert Activity Only", color: "#95d5b2" },
          { label: "Detection Rules (1-2)", color: "#40916c" },
          { label: "Detection Rules (3+)", color: "#1b4332" },
        ],
        metadata: [],
        links: [],
        showTacticRowBackground: true,
        tacticRowBackground: "#dddddd",
        selectTechniquesAcrossTactics: true,
        selectSubtechniquesWithParent: false,
        selectVisibleTechniques: false,
      };

      res.setHeader("Content-Type", "application/json");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="securenexus-attack-coverage-${new Date().toISOString().split("T")[0]}.json"`,
      );
      res.send(JSON.stringify(navigatorLayer, null, 2));
    } catch (err) {
      log.error("Failed to export ATT&CK Navigator layer", { error: String(err) });
      replyError(res, 500, [{ code: "EXPORT_ERROR", message: "Failed to export Navigator layer" }]);
    }
  });

  // ── 9.6: STIX Sync Status ────────────────────────────────────────
  app.get("/api/mitre-attack/sync-status", ...auth, async (_req: Request, res: Response) => {
    try {
      const counts = countAll();
      const currentDate = new Date();
      const lastUpdatedDate = new Date(ATTACK_LAST_UPDATED);
      const daysSinceUpdate = Math.floor((currentDate.getTime() - lastUpdatedDate.getTime()) / (1000 * 60 * 60 * 24));
      const isStale = daysSinceUpdate > 120;

      reply(res, {
        version: ATTACK_VERSION,
        lastUpdated: ATTACK_LAST_UPDATED,
        source: "MITRE ATT&CK STIX (Enterprise)",
        daysSinceUpdate,
        isStale,
        nextExpectedUpdate: isStale
          ? "Update available - check https://github.com/mitre/cti"
          : `~${120 - daysSinceUpdate} days`,
        totalTactics: MITRE_TACTICS_DATA.length,
        totalTechniques: counts.techniques,
        totalSubtechniques: counts.subtechniques,
        totalEntries: counts.total,
      });
    } catch (err) {
      log.error("Failed to get sync status", { error: String(err) });
      replyError(res, 500, [{ code: "SYNC_ERROR", message: "Failed to get sync status" }]);
    }
  });

  // ── 9.8: Generate Detection Rule for Technique ────────────────────
  app.post("/api/mitre-attack/generate-rule", ...auth, strictLimiter, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const { techniqueId } = req.body;

      if (!techniqueId || typeof techniqueId !== "string") {
        return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "techniqueId is required" }]);
      }

      const found = findTechnique(techniqueId);
      if (!found) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Technique not found" }]);
      }

      // Check if rule already exists
      const existingResult = await pool.query(
        `SELECT id, name FROM detection_rules
         WHERE org_id = $1 AND (mitre_technique = $2 OR mitre_subtechnique = $2)
         LIMIT 1`,
        [orgId, techniqueId],
      );

      if (existingResult.rows.length > 0) {
        return reply(res, {
          status: "exists",
          existingRule: existingResult.rows[0],
          message: `Detection rule "${existingResult.rows[0].name}" already covers ${techniqueId}`,
        });
      }

      const ruleName = `Detect ${found.technique.name} (${techniqueId})`;
      const ruleDescription = `Auto-generated detection rule for MITRE ATT&CK technique ${techniqueId}: ${found.technique.name}. ${found.technique.description}`;

      const insertResult = await pool.query(
        `INSERT INTO detection_rules (org_id, name, description, severity, status, mitre_tactic, mitre_technique, mitre_subtechnique, condition_tree, tags, is_builtin, author)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false, 'AI Generated')
         RETURNING id, name`,
        [
          orgId,
          ruleName,
          ruleDescription,
          "medium",
          "draft",
          found.tacticName.toLowerCase().replace(/\s+/g, "_"),
          techniqueId.includes(".") ? techniqueId.split(".")[0] : techniqueId,
          techniqueId.includes(".") ? techniqueId : null,
          JSON.stringify({
            type: "and",
            conditions: [{ field: "event_type", operator: "equals", value: "suspicious_activity" }],
          }),
          [`mitre:${techniqueId}`, "ai-generated", "coverage-gap"],
        ],
      );

      reply(res, {
        status: "created",
        rule: insertResult.rows[0],
        message: `Detection rule created for ${techniqueId}: ${found.technique.name}. Review and refine the rule conditions before enabling.`,
        technique: { id: techniqueId, name: found.technique.name, tactic: found.tacticName },
      });
    } catch (err) {
      log.error("Failed to generate detection rule", { error: String(err) });
      replyError(res, 500, [{ code: "RULE_GEN_ERROR", message: "Failed to generate detection rule" }]);
    }
  });

  // ── 9.9: Launch BAS Simulation for Technique ─────────────────────
  app.post("/api/mitre-attack/simulate", ...auth, strictLimiter, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const { techniqueId } = req.body;

      if (!techniqueId || typeof techniqueId !== "string") {
        return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "techniqueId is required" }]);
      }

      const found = findTechnique(techniqueId);
      if (!found) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Technique not found" }]);
      }

      const scenarioResult = await pool.query(
        `INSERT INTO bas_scenarios (org_id, name, description, mitre_tactic, mitre_technique, attack_type, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW())
         RETURNING id, name, status`,
        [
          orgId,
          `BAS: ${found.technique.name} (${techniqueId})`,
          `Breach & Attack Simulation for MITRE ATT&CK technique ${techniqueId}: ${found.technique.name}. ${found.technique.description}`,
          found.tacticName.toLowerCase().replace(/\s+/g, "_"),
          techniqueId,
          found.tacticName.toLowerCase().replace(/\s+/g, "_"),
        ],
      );

      reply(res, {
        status: "created",
        scenario: scenarioResult.rows[0],
        message: `BAS simulation created for ${techniqueId}: ${found.technique.name}. Navigate to Chaos Engineering to run it.`,
        technique: { id: techniqueId, name: found.technique.name, tactic: found.tacticName },
      });
    } catch (err) {
      if (String(err).includes("does not exist")) {
        return reply(res, {
          status: "unavailable",
          message: "Chaos Engineering BAS module is not yet configured. Set up BAS scenarios first.",
          technique: { id: req.body.techniqueId },
        });
      }
      log.error("Failed to create BAS simulation", { error: String(err) });
      replyError(res, 500, [{ code: "BAS_ERROR", message: "Failed to create BAS simulation" }]);
    }
  });

  log.info("MITRE ATT&CK routes registered");
}
