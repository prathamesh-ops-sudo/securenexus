/**
 * 45 built-in MITRE ATT&CK detection rules across all 12 tactics.
 * Each rule has a Sigma-compatible condition tree that fires on raw sensor events.
 */

import type { ConditionNode } from "./evaluator";

export interface BuiltinRule {
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  mitreTactic: string;
  mitreTechnique: string;
  mitreSubtechnique?: string;
  eventTypes: string[];
  conditionTree: ConditionNode;
  tags: string[];
  falsePositiveNotes?: string;
  references: string[];
}

export const BUILTIN_RULES: BuiltinRule[] = [
  // ============================================================
  // TACTIC 1: INITIAL ACCESS (T1190, T1566, T1078)
  // ============================================================
  {
    name: "Brute Force Login Attempts",
    description:
      "Multiple failed authentication attempts from a single source, indicating potential brute force attack.",
    severity: "high",
    mitreTactic: "initial_access",
    mitreTechnique: "T1078",
    eventTypes: ["auth"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "auth" },
        { field: "authResult", op: "eq", value: "failure" },
      ],
    },
    tags: ["brute-force", "credential-stuffing"],
    falsePositiveNotes: "Users with forgotten passwords may trigger this.",
    references: ["https://attack.mitre.org/techniques/T1078/"],
  },
  {
    name: "SSH Login from Unusual Source",
    description: "SSH authentication from an external or unexpected IP range.",
    severity: "medium",
    mitreTactic: "initial_access",
    mitreTechnique: "T1078",
    mitreSubtechnique: "T1078.004",
    eventTypes: ["auth"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "auth" },
        { field: "authMethod", op: "eq", value: "ssh" },
        { field: "authResult", op: "eq", value: "success" },
      ],
    },
    tags: ["ssh", "remote-access"],
    references: ["https://attack.mitre.org/techniques/T1078/004/"],
  },
  {
    name: "Web Shell Upload Detected",
    description: "File write of a known web shell extension to a web-accessible directory.",
    severity: "critical",
    mitreTactic: "initial_access",
    mitreTechnique: "T1190",
    eventTypes: ["file"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "file" },
        { field: "fileAction", op: "eq", value: "create" },
        {
          or: [
            { field: "filePath", op: "endsWith", value: ".php" },
            { field: "filePath", op: "endsWith", value: ".jsp" },
            { field: "filePath", op: "endsWith", value: ".aspx" },
            { field: "filePath", op: "endsWith", value: ".ashx" },
          ],
        },
        {
          or: [
            { field: "filePath", op: "contains", value: "/var/www" },
            { field: "filePath", op: "contains", value: "wwwroot" },
            { field: "filePath", op: "contains", value: "htdocs" },
            { field: "filePath", op: "contains", value: "webapps" },
          ],
        },
      ],
    },
    tags: ["webshell", "exploit"],
    references: ["https://attack.mitre.org/techniques/T1190/"],
  },
  {
    name: "Phishing Attachment Execution",
    description: "Office or script file executed shortly after being downloaded or received via email.",
    severity: "high",
    mitreTactic: "initial_access",
    mitreTechnique: "T1566",
    mitreSubtechnique: "T1566.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "regex", value: "\\.(doc|docx|xls|xlsx|ppt|pptx|pdf|hta|vbs|js|wsf)$" },
            { field: "processPath", op: "contains", value: "Downloads" },
          ],
        },
        {
          or: [
            { field: "parentProcess", op: "contains", value: "outlook" },
            { field: "parentProcess", op: "contains", value: "thunderbird" },
            { field: "parentProcess", op: "contains", value: "chrome" },
            { field: "parentProcess", op: "contains", value: "firefox" },
            { field: "parentProcess", op: "contains", value: "edge" },
          ],
        },
      ],
    },
    tags: ["phishing", "spearphishing"],
    references: ["https://attack.mitre.org/techniques/T1566/001/"],
  },

  // ============================================================
  // TACTIC 2: EXECUTION (T1059, T1204)
  // ============================================================
  {
    name: "PowerShell Encoded Command",
    description:
      "PowerShell launched with -EncodedCommand or -enc flag, commonly used to obfuscate malicious payloads.",
    severity: "high",
    mitreTactic: "execution",
    mitreTechnique: "T1059",
    mitreSubtechnique: "T1059.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { field: "processName", op: "regex", value: "powershell(\\.exe)?$" },
        {
          or: [
            { field: "processArgs", op: "contains", value: "-EncodedCommand" },
            { field: "processArgs", op: "contains", value: "-enc " },
            { field: "processArgs", op: "contains", value: "-e " },
            { field: "processArgs", op: "regex", value: "\\-[eE][nN]?[cC]?\\s+" },
          ],
        },
      ],
    },
    tags: ["powershell", "obfuscation", "encoded"],
    references: ["https://attack.mitre.org/techniques/T1059/001/"],
  },
  {
    name: "Script Interpreter Spawned by Office Application",
    description: "cmd.exe, powershell, wscript, or cscript spawned by an Office process — classic macro execution.",
    severity: "critical",
    mitreTactic: "execution",
    mitreTechnique: "T1204",
    mitreSubtechnique: "T1204.002",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { or: [{ field: "processName", op: "regex", value: "(cmd|powershell|wscript|cscript)(\\.exe)?$" }] },
        {
          or: [
            { field: "parentProcess", op: "contains", value: "winword" },
            { field: "parentProcess", op: "contains", value: "excel" },
            { field: "parentProcess", op: "contains", value: "powerpnt" },
          ],
        },
      ],
    },
    tags: ["macro", "office-exploit"],
    references: ["https://attack.mitre.org/techniques/T1204/002/"],
  },
  {
    name: "Python/Perl/Ruby Script Execution",
    description: "Interpreted scripting language executing with suspicious arguments.",
    severity: "medium",
    mitreTactic: "execution",
    mitreTechnique: "T1059",
    mitreSubtechnique: "T1059.006",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { or: [{ field: "processName", op: "regex", value: "(python|python3|perl|ruby)(\\.exe)?$" }] },
        {
          or: [
            { field: "processArgs", op: "contains", value: "-c " },
            { field: "processArgs", op: "contains", value: "exec(" },
            { field: "processArgs", op: "contains", value: "import socket" },
            { field: "processArgs", op: "contains", value: "import subprocess" },
          ],
        },
      ],
    },
    tags: ["scripting", "interpreter"],
    references: ["https://attack.mitre.org/techniques/T1059/006/"],
  },
  {
    name: "Bash Reverse Shell",
    description: "Bash process with arguments indicating a reverse shell connection.",
    severity: "critical",
    mitreTactic: "execution",
    mitreTechnique: "T1059",
    mitreSubtechnique: "T1059.004",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { or: [{ field: "processName", op: "regex", value: "(bash|sh|zsh|dash)$" }] },
        {
          or: [
            { field: "processArgs", op: "contains", value: "/dev/tcp/" },
            { field: "processArgs", op: "regex", value: "bash\\s+-i\\s+>&\\s+/dev/tcp/" },
            { field: "processArgs", op: "contains", value: "mkfifo" },
            { field: "processArgs", op: "regex", value: "nc\\s+-e\\s+/bin/(ba)?sh" },
          ],
        },
      ],
    },
    tags: ["reverse-shell", "backdoor"],
    references: ["https://attack.mitre.org/techniques/T1059/004/"],
  },

  // ============================================================
  // TACTIC 3: PERSISTENCE (T1053, T1136, T1543)
  // ============================================================
  {
    name: "Cron Job Created",
    description: "New cron job written or crontab modified — potential persistence mechanism.",
    severity: "medium",
    mitreTactic: "persistence",
    mitreTechnique: "T1053",
    mitreSubtechnique: "T1053.003",
    eventTypes: ["file", "process"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "file" },
            { field: "fileAction", op: "in", value: ["create", "modify"] },
            {
              or: [
                { field: "filePath", op: "contains", value: "/etc/cron" },
                { field: "filePath", op: "contains", value: "/var/spool/cron" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            { field: "processName", op: "eq", value: "crontab" },
            { field: "processArgs", op: "contains", value: "-e" },
          ],
        },
      ],
    },
    tags: ["cron", "scheduled-task", "persistence"],
    references: ["https://attack.mitre.org/techniques/T1053/003/"],
  },
  {
    name: "New User Account Created",
    description: "Local user account creation detected via useradd/adduser or net user commands.",
    severity: "medium",
    mitreTactic: "persistence",
    mitreTechnique: "T1136",
    mitreSubtechnique: "T1136.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "in", value: ["useradd", "adduser"] },
            {
              and: [
                { field: "processName", op: "regex", value: "net(\\.exe)?$" },
                { field: "processArgs", op: "contains", value: "user /add" },
              ],
            },
          ],
        },
      ],
    },
    tags: ["account-creation", "persistence"],
    references: ["https://attack.mitre.org/techniques/T1136/001/"],
  },
  {
    name: "Systemd Service Created",
    description: "New systemd service unit file written, potential persistence via service installation.",
    severity: "high",
    mitreTactic: "persistence",
    mitreTechnique: "T1543",
    mitreSubtechnique: "T1543.002",
    eventTypes: ["file"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "file" },
        { field: "fileAction", op: "in", value: ["create", "modify"] },
        {
          or: [
            { field: "filePath", op: "contains", value: "/etc/systemd/system/" },
            { field: "filePath", op: "contains", value: "/usr/lib/systemd/system/" },
          ],
        },
        { field: "filePath", op: "endsWith", value: ".service" },
      ],
    },
    tags: ["systemd", "service", "persistence"],
    references: ["https://attack.mitre.org/techniques/T1543/002/"],
  },
  {
    name: "Windows Registry Run Key Modified",
    description: "Registry Run/RunOnce key modification for auto-start persistence.",
    severity: "high",
    mitreTactic: "persistence",
    mitreTechnique: "T1547",
    mitreSubtechnique: "T1547.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { field: "processName", op: "regex", value: "reg(\\.exe)?$" },
        { field: "processArgs", op: "contains", value: "add" },
        {
          or: [
            { field: "processArgs", op: "regex", value: "CurrentVersion\\\\Run" },
            { field: "processArgs", op: "regex", value: "CurrentVersion\\\\RunOnce" },
          ],
        },
      ],
    },
    tags: ["registry", "autostart", "persistence"],
    references: ["https://attack.mitre.org/techniques/T1547/001/"],
  },

  // ============================================================
  // TACTIC 4: PRIVILEGE ESCALATION (T1548, T1068)
  // ============================================================
  {
    name: "Sudo to Root",
    description: "Process executed via sudo gaining root privileges.",
    severity: "medium",
    mitreTactic: "privilege_escalation",
    mitreTechnique: "T1548",
    mitreSubtechnique: "T1548.003",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { field: "parentProcess", op: "contains", value: "sudo" },
        { field: "userName", op: "eq", value: "root" },
      ],
    },
    tags: ["sudo", "privilege-escalation"],
    falsePositiveNotes: "Legitimate admin activity uses sudo regularly.",
    references: ["https://attack.mitre.org/techniques/T1548/003/"],
  },
  {
    name: "SUID Binary Execution",
    description: "Execution of a SUID binary that could be exploited for privilege escalation.",
    severity: "high",
    mitreTactic: "privilege_escalation",
    mitreTechnique: "T1548",
    mitreSubtechnique: "T1548.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processPath", op: "contains", value: "/usr/bin/pkexec" },
            { field: "processPath", op: "contains", value: "/usr/bin/at" },
            { field: "processName", op: "eq", value: "nmap" },
            { field: "processName", op: "eq", value: "find" },
            { field: "processName", op: "eq", value: "vim" },
          ],
        },
        { field: "userName", op: "neq", value: "root" },
      ],
    },
    tags: ["suid", "privilege-escalation"],
    references: ["https://attack.mitre.org/techniques/T1548/001/"],
  },
  {
    name: "Windows UAC Bypass Attempt",
    description: "Process attempting to bypass User Account Control via known techniques.",
    severity: "critical",
    mitreTactic: "privilege_escalation",
    mitreTechnique: "T1548",
    mitreSubtechnique: "T1548.002",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            {
              and: [
                { field: "processName", op: "regex", value: "fodhelper(\\.exe)?$" },
                { field: "parentProcess", op: "regex", value: "(cmd|powershell)(\\.exe)?$" },
              ],
            },
            {
              and: [
                { field: "processName", op: "regex", value: "eventvwr(\\.exe)?$" },
                { field: "parentProcess", op: "regex", value: "(cmd|powershell)(\\.exe)?$" },
              ],
            },
            { field: "processArgs", op: "contains", value: "ms-settings" },
          ],
        },
      ],
    },
    tags: ["uac-bypass", "privilege-escalation"],
    references: ["https://attack.mitre.org/techniques/T1548/002/"],
  },

  // ============================================================
  // TACTIC 5: DEFENSE EVASION (T1070, T1562, T1027)
  // ============================================================
  {
    name: "Log Deletion or Tampering",
    description: "System or security logs cleared or deleted.",
    severity: "critical",
    mitreTactic: "defense_evasion",
    mitreTechnique: "T1070",
    mitreSubtechnique: "T1070.002",
    eventTypes: ["file", "process"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "file" },
            { field: "fileAction", op: "eq", value: "delete" },
            {
              or: [
                { field: "filePath", op: "contains", value: "/var/log/" },
                { field: "filePath", op: "endsWith", value: ".log" },
                { field: "filePath", op: "endsWith", value: ".evtx" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processName", op: "eq", value: "wevtutil" },
                { field: "processArgs", op: "contains", value: "clear-log" },
                { field: "processArgs", op: "regex", value: "rm\\s+-rf?\\s+/var/log" },
              ],
            },
          ],
        },
      ],
    },
    tags: ["log-tampering", "anti-forensics"],
    references: ["https://attack.mitre.org/techniques/T1070/002/"],
  },
  {
    name: "Security Tool Disabled",
    description: "Attempt to stop or disable security software (AV, firewall, EDR).",
    severity: "critical",
    mitreTactic: "defense_evasion",
    mitreTechnique: "T1562",
    mitreSubtechnique: "T1562.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processArgs", op: "contains", value: "stop MsMpSvc" },
            { field: "processArgs", op: "contains", value: "stop WinDefend" },
            { field: "processArgs", op: "regex", value: "iptables\\s+-F" },
            { field: "processArgs", op: "contains", value: "ufw disable" },
            { field: "processArgs", op: "contains", value: "systemctl stop firewalld" },
            { field: "processArgs", op: "regex", value: "Set-MpPreference\\s+-DisableRealtimeMonitoring" },
            { field: "processArgs", op: "contains", value: "setenforce 0" },
          ],
        },
      ],
    },
    tags: ["defense-evasion", "disable-security"],
    references: ["https://attack.mitre.org/techniques/T1562/001/"],
  },
  {
    name: "Process Injection via ptrace",
    description: "Use of ptrace to attach to another process — common code injection technique on Linux.",
    severity: "high",
    mitreTactic: "defense_evasion",
    mitreTechnique: "T1055",
    mitreSubtechnique: "T1055.008",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "eq", value: "strace" },
            { field: "processName", op: "eq", value: "ltrace" },
            { field: "processArgs", op: "contains", value: "ptrace" },
            { field: "processArgs", op: "contains", value: "PTRACE_ATTACH" },
          ],
        },
      ],
    },
    tags: ["process-injection", "ptrace"],
    references: ["https://attack.mitre.org/techniques/T1055/008/"],
  },
  {
    name: "Timestomping Detected",
    description: "File timestamp manipulation to evade forensic analysis.",
    severity: "high",
    mitreTactic: "defense_evasion",
    mitreTechnique: "T1070",
    mitreSubtechnique: "T1070.006",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "eq", value: "touch" },
            { field: "processArgs", op: "contains", value: "timestomp" },
            { field: "processArgs", op: "regex", value: "touch\\s+-[trd]" },
          ],
        },
      ],
    },
    tags: ["timestomping", "anti-forensics"],
    references: ["https://attack.mitre.org/techniques/T1070/006/"],
  },

  // ============================================================
  // TACTIC 6: CREDENTIAL ACCESS (T1003, T1110, T1552)
  // ============================================================
  {
    name: "LSASS Memory Dump",
    description: "Attempt to dump LSASS process memory for credential harvesting.",
    severity: "critical",
    mitreTactic: "credential_access",
    mitreTechnique: "T1003",
    mitreSubtechnique: "T1003.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processArgs", op: "contains", value: "lsass" },
            { field: "processName", op: "regex", value: "(procdump|mimikatz|sekurlsa)(\\.exe)?$" },
            { field: "processArgs", op: "contains", value: "sekurlsa::logonpasswords" },
            { field: "processArgs", op: "regex", value: "comsvcs\\.dll.*MiniDump" },
          ],
        },
      ],
    },
    tags: ["credential-dump", "lsass", "mimikatz"],
    references: ["https://attack.mitre.org/techniques/T1003/001/"],
  },
  {
    name: "/etc/shadow Access",
    description: "Direct read access to /etc/shadow file containing password hashes.",
    severity: "high",
    mitreTactic: "credential_access",
    mitreTechnique: "T1003",
    mitreSubtechnique: "T1003.008",
    eventTypes: ["file", "process"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "file" },
            { field: "filePath", op: "eq", value: "/etc/shadow" },
            { field: "fileAction", op: "eq", value: "read" },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            { field: "processArgs", op: "contains", value: "/etc/shadow" },
            { or: [{ field: "processName", op: "in", value: ["cat", "less", "more", "head", "tail", "cp", "scp"] }] },
          ],
        },
      ],
    },
    tags: ["credential-access", "shadow-file"],
    references: ["https://attack.mitre.org/techniques/T1003/008/"],
  },
  {
    name: "Credential File Access",
    description: "Access to common credential storage files (SSH keys, browser passwords, etc.).",
    severity: "high",
    mitreTactic: "credential_access",
    mitreTechnique: "T1552",
    mitreSubtechnique: "T1552.001",
    eventTypes: ["file"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "file" },
        { field: "fileAction", op: "in", value: ["read", "copy"] },
        {
          or: [
            { field: "filePath", op: "contains", value: ".ssh/id_rsa" },
            { field: "filePath", op: "contains", value: ".ssh/id_ed25519" },
            { field: "filePath", op: "contains", value: ".aws/credentials" },
            { field: "filePath", op: "contains", value: ".gnupg/" },
            { field: "filePath", op: "contains", value: "Login Data" },
            { field: "filePath", op: "contains", value: "Chrome/User Data" },
          ],
        },
      ],
    },
    tags: ["credential-theft", "ssh-keys", "browser-creds"],
    references: ["https://attack.mitre.org/techniques/T1552/001/"],
  },
  {
    name: "Password Spraying via Kerberos",
    description: "Kerberos authentication failures indicating password spray attack.",
    severity: "high",
    mitreTactic: "credential_access",
    mitreTechnique: "T1110",
    mitreSubtechnique: "T1110.003",
    eventTypes: ["auth"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "auth" },
        { field: "authMethod", op: "eq", value: "kerberos" },
        { field: "authResult", op: "eq", value: "failure" },
      ],
    },
    tags: ["kerberos", "password-spray"],
    references: ["https://attack.mitre.org/techniques/T1110/003/"],
  },

  // ============================================================
  // TACTIC 7: DISCOVERY (T1046, T1057, T1082)
  // ============================================================
  {
    name: "Network Port Scanning",
    description: "Port scanning activity detected from a host, indicating network reconnaissance.",
    severity: "medium",
    mitreTactic: "discovery",
    mitreTechnique: "T1046",
    eventTypes: ["process", "network"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processName", op: "in", value: ["nmap", "masscan", "zmap", "rustscan"] },
                { field: "processArgs", op: "contains", value: "-sS" },
                { field: "processArgs", op: "contains", value: "-sV" },
                { field: "processArgs", op: "contains", value: "-sT" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "exists", value: true },
            { field: "protocol", op: "eq", value: "tcp" },
          ],
        },
      ],
    },
    tags: ["port-scan", "reconnaissance"],
    references: ["https://attack.mitre.org/techniques/T1046/"],
  },
  {
    name: "System Information Discovery",
    description: "Commands used to enumerate system configuration and hardware details.",
    severity: "low",
    mitreTactic: "discovery",
    mitreTechnique: "T1082",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "in", value: ["systeminfo", "uname", "lsb_release", "hostnamectl"] },
            { field: "processArgs", op: "regex", value: "uname\\s+-a" },
            { field: "processArgs", op: "contains", value: "cat /etc/os-release" },
          ],
        },
      ],
    },
    tags: ["system-enumeration", "discovery"],
    falsePositiveNotes: "System monitoring scripts may trigger this.",
    references: ["https://attack.mitre.org/techniques/T1082/"],
  },
  {
    name: "Process Enumeration",
    description: "Listing running processes — reconnaissance for target selection.",
    severity: "low",
    mitreTactic: "discovery",
    mitreTechnique: "T1057",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "in", value: ["ps", "tasklist", "Get-Process"] },
            { field: "processArgs", op: "regex", value: "ps\\s+aux" },
            { field: "processArgs", op: "contains", value: "tasklist /v" },
          ],
        },
      ],
    },
    tags: ["process-discovery"],
    falsePositiveNotes: "Common admin activity; correlate with other suspicious events.",
    references: ["https://attack.mitre.org/techniques/T1057/"],
  },
  {
    name: "Active Directory Enumeration",
    description: "LDAP or AD enumeration tools used for domain reconnaissance.",
    severity: "medium",
    mitreTactic: "discovery",
    mitreTechnique: "T1087",
    mitreSubtechnique: "T1087.002",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "in", value: ["ldapsearch", "dsquery", "adfind", "bloodhound", "sharphound"] },
            { field: "processArgs", op: "contains", value: "Get-ADUser" },
            { field: "processArgs", op: "contains", value: "Get-ADComputer" },
            { field: "processArgs", op: "contains", value: "Get-ADGroup" },
          ],
        },
      ],
    },
    tags: ["ad-enumeration", "domain-discovery"],
    references: ["https://attack.mitre.org/techniques/T1087/002/"],
  },

  // ============================================================
  // TACTIC 8: LATERAL MOVEMENT (T1021, T1570)
  // ============================================================
  {
    name: "Lateral Movement via SSH",
    description: "SSH connections initiated from an internal host to another internal host.",
    severity: "medium",
    mitreTactic: "lateral_movement",
    mitreTechnique: "T1021",
    mitreSubtechnique: "T1021.004",
    eventTypes: ["network", "process"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "eq", value: 22 },
            { field: "protocol", op: "eq", value: "tcp" },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            { field: "processName", op: "in", value: ["ssh", "scp", "sftp"] },
          ],
        },
      ],
    },
    tags: ["ssh", "lateral-movement"],
    falsePositiveNotes: "Normal SSH admin activity. Correlate with source host behavior.",
    references: ["https://attack.mitre.org/techniques/T1021/004/"],
  },
  {
    name: "PsExec or SMB Remote Execution",
    description: "PsExec or similar SMB-based remote execution tool detected.",
    severity: "high",
    mitreTactic: "lateral_movement",
    mitreTechnique: "T1021",
    mitreSubtechnique: "T1021.002",
    eventTypes: ["process", "network"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processName", op: "regex", value: "psexec(\\.exe)?$" },
                { field: "processName", op: "regex", value: "paexec(\\.exe)?$" },
                { field: "processArgs", op: "contains", value: "\\\\ADMIN$" },
                { field: "processArgs", op: "contains", value: "\\\\C$\\" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "eq", value: 445 },
          ],
        },
      ],
    },
    tags: ["psexec", "smb", "lateral-movement"],
    references: ["https://attack.mitre.org/techniques/T1021/002/"],
  },
  {
    name: "RDP Lateral Movement",
    description: "Remote Desktop connections between internal hosts.",
    severity: "medium",
    mitreTactic: "lateral_movement",
    mitreTechnique: "T1021",
    mitreSubtechnique: "T1021.001",
    eventTypes: ["network"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "network" },
        { field: "dstPort", op: "eq", value: 3389 },
        { field: "protocol", op: "eq", value: "tcp" },
      ],
    },
    tags: ["rdp", "lateral-movement"],
    references: ["https://attack.mitre.org/techniques/T1021/001/"],
  },
  {
    name: "WinRM Remote Command Execution",
    description: "Windows Remote Management used for lateral movement.",
    severity: "high",
    mitreTactic: "lateral_movement",
    mitreTechnique: "T1021",
    mitreSubtechnique: "T1021.006",
    eventTypes: ["process", "network"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processName", op: "regex", value: "winrs(\\.exe)?$" },
                { field: "processArgs", op: "contains", value: "Invoke-Command" },
                { field: "processArgs", op: "contains", value: "Enter-PSSession" },
                { field: "processArgs", op: "contains", value: "New-PSSession" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "in", value: [5985, 5986] },
          ],
        },
      ],
    },
    tags: ["winrm", "lateral-movement"],
    references: ["https://attack.mitre.org/techniques/T1021/006/"],
  },

  // ============================================================
  // TACTIC 9: COLLECTION (T1005, T1560, T1115)
  // ============================================================
  {
    name: "Sensitive File Collection",
    description: "Mass reading or copying of sensitive documents, databases, or configuration files.",
    severity: "high",
    mitreTactic: "collection",
    mitreTechnique: "T1005",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processArgs", op: "regex", value: "find\\s+.*\\-name.*\\.(docx|xlsx|pdf|pptx|sql|csv)" },
            { field: "processArgs", op: "regex", value: "dir\\s+.*\\*\\.(docx|xlsx|pdf|sql)" },
            { field: "processArgs", op: "contains", value: "Get-ChildItem" },
          ],
        },
      ],
    },
    tags: ["data-collection", "sensitive-files"],
    references: ["https://attack.mitre.org/techniques/T1005/"],
  },
  {
    name: "Archive Creation for Exfiltration",
    description: "Data being compressed into archives, common pre-exfiltration step.",
    severity: "medium",
    mitreTactic: "collection",
    mitreTechnique: "T1560",
    mitreSubtechnique: "T1560.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processName", op: "in", value: ["tar", "zip", "7z", "rar", "gzip", "bzip2"] },
            { field: "processArgs", op: "contains", value: "Compress-Archive" },
            { field: "processArgs", op: "regex", value: "tar\\s+[czxvf]*c" },
          ],
        },
      ],
    },
    tags: ["archiving", "pre-exfiltration"],
    falsePositiveNotes: "Legitimate backup operations may trigger this.",
    references: ["https://attack.mitre.org/techniques/T1560/001/"],
  },
  {
    name: "Clipboard Data Access",
    description: "Automated clipboard capture or access detected.",
    severity: "medium",
    mitreTactic: "collection",
    mitreTechnique: "T1115",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processArgs", op: "contains", value: "xclip" },
            { field: "processArgs", op: "contains", value: "xsel" },
            { field: "processArgs", op: "contains", value: "pbpaste" },
            { field: "processArgs", op: "contains", value: "Get-Clipboard" },
            { field: "processArgs", op: "contains", value: "win32clipboard" },
          ],
        },
      ],
    },
    tags: ["clipboard", "data-collection"],
    references: ["https://attack.mitre.org/techniques/T1115/"],
  },

  // ============================================================
  // TACTIC 10: COMMAND AND CONTROL (T1071, T1572, T1573)
  // ============================================================
  {
    name: "DNS Tunneling Suspected",
    description: "Unusually long DNS queries or high frequency DNS lookups suggesting data exfiltration via DNS.",
    severity: "high",
    mitreTactic: "command_and_control",
    mitreTechnique: "T1071",
    mitreSubtechnique: "T1071.004",
    eventTypes: ["dns"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "dns" },
        { field: "dnsQuery", op: "exists", value: true },
        { field: "dnsQuery", op: "regex", value: "^[a-zA-Z0-9]{30,}\\." },
      ],
    },
    tags: ["dns-tunneling", "c2"],
    references: ["https://attack.mitre.org/techniques/T1071/004/"],
  },
  {
    name: "Known C2 Port Communication",
    description: "Outbound connection to ports commonly associated with command-and-control frameworks.",
    severity: "high",
    mitreTactic: "command_and_control",
    mitreTechnique: "T1571",
    eventTypes: ["network"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "network" },
        { field: "dstPort", op: "in", value: [4444, 5555, 6666, 8888, 1234, 9999, 31337, 12345] },
      ],
    },
    tags: ["c2-ports", "suspicious-connection"],
    references: ["https://attack.mitre.org/techniques/T1571/"],
  },
  {
    name: "Tor Network Connection",
    description: "Connection to known Tor relay ports or Tor browser process detected.",
    severity: "high",
    mitreTactic: "command_and_control",
    mitreTechnique: "T1572",
    eventTypes: ["network", "process"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "in", value: [9001, 9030, 9050, 9051, 9150] },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            { field: "processName", op: "in", value: ["tor", "tor.exe"] },
          ],
        },
      ],
    },
    tags: ["tor", "anonymization", "c2"],
    references: ["https://attack.mitre.org/techniques/T1572/"],
  },
  {
    name: "Cobalt Strike Beacon Indicators",
    description: "Process or network behavior matching known Cobalt Strike beacon patterns.",
    severity: "critical",
    mitreTactic: "command_and_control",
    mitreTechnique: "T1071",
    mitreSubtechnique: "T1071.001",
    eventTypes: ["process", "network"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processArgs", op: "contains", value: "cobaltstrike" },
                { field: "processArgs", op: "regex", value: "rundll32.*,Start" },
                { field: "processArgs", op: "contains", value: "beacon" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "in", value: [50050, 443] },
            { field: "protocol", op: "eq", value: "tcp" },
          ],
        },
      ],
    },
    tags: ["cobalt-strike", "apt", "c2"],
    references: ["https://attack.mitre.org/techniques/T1071/001/"],
  },

  // ============================================================
  // TACTIC 11: EXFILTRATION (T1048, T1567)
  // ============================================================
  {
    name: "Large Outbound Data Transfer",
    description: "Unusually large outbound network transfer suggesting data exfiltration.",
    severity: "high",
    mitreTactic: "exfiltration",
    mitreTechnique: "T1048",
    eventTypes: ["network"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "network" },
        { field: "bytesOut", op: "gt", value: 104857600 },
      ],
    },
    tags: ["data-exfiltration", "large-transfer"],
    falsePositiveNotes: "Legitimate backups or uploads may trigger this. Check destination.",
    references: ["https://attack.mitre.org/techniques/T1048/"],
  },
  {
    name: "Exfiltration via Cloud Storage",
    description: "Data upload to cloud storage services (S3, GCS, Azure Blob, Dropbox, etc.).",
    severity: "medium",
    mitreTactic: "exfiltration",
    mitreTechnique: "T1567",
    mitreSubtechnique: "T1567.002",
    eventTypes: ["dns", "process"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "dns" },
            {
              or: [
                { field: "dnsQuery", op: "contains", value: "s3.amazonaws.com" },
                { field: "dnsQuery", op: "contains", value: "storage.googleapis.com" },
                { field: "dnsQuery", op: "contains", value: "blob.core.windows.net" },
                { field: "dnsQuery", op: "contains", value: "dropbox.com" },
                { field: "dnsQuery", op: "contains", value: "mega.nz" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processName", op: "in", value: ["aws", "gsutil", "azcopy", "rclone"] },
                { field: "processArgs", op: "contains", value: "s3 cp" },
                { field: "processArgs", op: "contains", value: "s3 sync" },
              ],
            },
          ],
        },
      ],
    },
    tags: ["cloud-exfiltration", "data-theft"],
    references: ["https://attack.mitre.org/techniques/T1567/002/"],
  },
  {
    name: "DNS Exfiltration",
    description: "Data encoded and exfiltrated via DNS queries.",
    severity: "critical",
    mitreTactic: "exfiltration",
    mitreTechnique: "T1048",
    mitreSubtechnique: "T1048.003",
    eventTypes: ["dns"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "dns" },
        { field: "dnsType", op: "in", value: ["TXT", "CNAME", "MX"] },
        { field: "dnsQuery", op: "regex", value: "^[a-zA-Z0-9+/=]{20,}\\." },
      ],
    },
    tags: ["dns-exfiltration", "data-theft"],
    references: ["https://attack.mitre.org/techniques/T1048/003/"],
  },

  // ============================================================
  // TACTIC 12: IMPACT (T1486, T1489, T1496)
  // ============================================================
  {
    name: "Ransomware File Extension",
    description: "Files being renamed with known ransomware extensions.",
    severity: "critical",
    mitreTactic: "impact",
    mitreTechnique: "T1486",
    eventTypes: ["file"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "file" },
        { field: "fileAction", op: "in", value: ["rename", "modify", "create"] },
        {
          or: [
            { field: "filePath", op: "endsWith", value: ".encrypted" },
            { field: "filePath", op: "endsWith", value: ".locked" },
            { field: "filePath", op: "endsWith", value: ".crypt" },
            { field: "filePath", op: "endsWith", value: ".crypted" },
            { field: "filePath", op: "endsWith", value: ".enc" },
            { field: "filePath", op: "endsWith", value: ".locky" },
            { field: "filePath", op: "endsWith", value: ".cerber" },
            { field: "filePath", op: "endsWith", value: ".zepto" },
            { field: "filePath", op: "endsWith", value: ".wncry" },
            { field: "filePath", op: "endsWith", value: ".zzzzz" },
          ],
        },
      ],
    },
    tags: ["ransomware", "encryption"],
    references: ["https://attack.mitre.org/techniques/T1486/"],
  },
  {
    name: "Critical Service Stopped",
    description: "Critical system or business service stopped or killed.",
    severity: "high",
    mitreTactic: "impact",
    mitreTechnique: "T1489",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            {
              and: [
                { field: "processName", op: "regex", value: "(sc|net)(\\.exe)?$" },
                { field: "processArgs", op: "contains", value: "stop" },
              ],
            },
            {
              and: [
                { field: "processName", op: "eq", value: "systemctl" },
                { field: "processArgs", op: "contains", value: "stop" },
              ],
            },
            {
              and: [
                { field: "processName", op: "eq", value: "kill" },
                { field: "processArgs", op: "regex", value: "-9\\s+" },
              ],
            },
          ],
        },
      ],
    },
    tags: ["service-stop", "impact"],
    references: ["https://attack.mitre.org/techniques/T1489/"],
  },
  {
    name: "Cryptominer Execution",
    description: "Known cryptocurrency mining software detected.",
    severity: "high",
    mitreTactic: "impact",
    mitreTechnique: "T1496",
    eventTypes: ["process", "network"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                {
                  field: "processName",
                  op: "in",
                  value: ["xmrig", "cpuminer", "minerd", "cgminer", "bfgminer", "ethminer", "t-rex"],
                },
                { field: "processArgs", op: "contains", value: "stratum+tcp://" },
                { field: "processArgs", op: "contains", value: "--coin" },
                { field: "processArgs", op: "regex", value: "--(algo|coin|pool|wallet)" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "network" },
            { field: "dstPort", op: "in", value: [3333, 5555, 7777, 8332, 8333, 14444, 45560] },
          ],
        },
      ],
    },
    tags: ["cryptominer", "resource-hijacking"],
    references: ["https://attack.mitre.org/techniques/T1496/"],
  },
  {
    name: "Disk Wipe or Data Destruction",
    description: "Commands that destroy data by overwriting disks or deleting critical filesystems.",
    severity: "critical",
    mitreTactic: "impact",
    mitreTechnique: "T1561",
    mitreSubtechnique: "T1561.001",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        {
          or: [
            { field: "processArgs", op: "regex", value: "dd\\s+if=/dev/zero\\s+of=/dev/sd" },
            { field: "processArgs", op: "regex", value: "dd\\s+if=/dev/urandom\\s+of=/dev/sd" },
            { field: "processArgs", op: "regex", value: "shred\\s+-[vfuz]" },
            { field: "processArgs", op: "regex", value: "rm\\s+-rf\\s+/" },
            { field: "processName", op: "eq", value: "wipe" },
          ],
        },
      ],
    },
    tags: ["disk-wipe", "data-destruction"],
    references: ["https://attack.mitre.org/techniques/T1561/001/"],
  },

  // ============================================================
  // ADDITIONAL CROSS-TACTIC RULES
  // ============================================================
  {
    name: "Docker Container Escape Attempt",
    description: "Process behavior indicating an attempt to escape a Docker container.",
    severity: "critical",
    mitreTactic: "privilege_escalation",
    mitreTechnique: "T1611",
    eventTypes: ["process", "file"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processArgs", op: "contains", value: "nsenter" },
                { field: "processArgs", op: "contains", value: "--mount=/proc/1/ns/mnt" },
                { field: "processArgs", op: "contains", value: "chroot /host" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "file" },
            {
              or: [
                { field: "filePath", op: "contains", value: "/var/run/docker.sock" },
                { field: "filePath", op: "eq", value: "/proc/1/root" },
              ],
            },
          ],
        },
      ],
    },
    tags: ["container-escape", "docker"],
    references: ["https://attack.mitre.org/techniques/T1611/"],
  },
  {
    name: "Kubernetes Secret Access",
    description: "Unauthorized access to Kubernetes secrets from within a pod.",
    severity: "high",
    mitreTactic: "credential_access",
    mitreTechnique: "T1552",
    mitreSubtechnique: "T1552.007",
    eventTypes: ["process", "file"],
    conditionTree: {
      or: [
        {
          and: [
            { field: "eventType", op: "eq", value: "process" },
            {
              or: [
                { field: "processArgs", op: "contains", value: "kubectl get secrets" },
                { field: "processArgs", op: "contains", value: "kubectl get secret" },
              ],
            },
          ],
        },
        {
          and: [
            { field: "eventType", op: "eq", value: "file" },
            { field: "filePath", op: "contains", value: "/var/run/secrets/kubernetes.io" },
          ],
        },
      ],
    },
    tags: ["kubernetes", "secret-access"],
    references: ["https://attack.mitre.org/techniques/T1552/007/"],
  },
  {
    name: "Suspicious Wget/Curl Download",
    description: "Download of executable or script from external source via wget/curl.",
    severity: "medium",
    mitreTactic: "execution",
    mitreTechnique: "T1105",
    eventTypes: ["process"],
    conditionTree: {
      and: [
        { field: "eventType", op: "eq", value: "process" },
        { field: "processName", op: "in", value: ["wget", "curl"] },
        {
          or: [
            { field: "processArgs", op: "regex", value: "https?://.*\\.(sh|py|pl|exe|bin|elf)" },
            { field: "processArgs", op: "contains", value: "| bash" },
            { field: "processArgs", op: "contains", value: "| sh" },
            { field: "processArgs", op: "contains", value: "-o /tmp/" },
          ],
        },
      ],
    },
    tags: ["download-execute", "dropper"],
    references: ["https://attack.mitre.org/techniques/T1105/"],
  },
];
