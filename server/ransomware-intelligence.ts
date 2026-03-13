/**
 * Ransomware Intelligence Engine
 * Group profiles, TTPs, payment tracking, recovery recommendations
 */

// Known ransomware group profiles (seed data)
export interface RansomwareGroupProfile {
  name: string;
  aliases: string[];
  threatLevel: "critical" | "high" | "medium" | "low";
  isActive: boolean;
  firstSeen: string;
  lastActive: string;
  description: string;
  ttps: { id: string; name: string; tactic: string }[];
  targetIndustries: string[];
  targetRegions: string[];
  ransomwareVariants: { name: string; type: string }[];
  knownPaymentAddresses: { currency: string; address: string }[];
  avgRansomDemandUsd: number;
  decryptorAvailable: boolean;
  decryptorSource: string | null;
  iocIndicators: { type: string; value: string }[];
  referenceUrls: string[];
}

export const KNOWN_RANSOMWARE_GROUPS: RansomwareGroupProfile[] = [
  {
    name: "LockBit 3.0",
    aliases: ["LockBit Black", "LockBit Green"],
    threatLevel: "critical",
    isActive: true,
    firstSeen: "2019-09",
    lastActive: "2026-02",
    description:
      "Prolific RaaS operation responsible for over 1,700 attacks globally. Uses double extortion and has a bug bounty program.",
    ttps: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
      { id: "T1053.005", name: "Scheduled Task", tactic: "Execution" },
      { id: "T1047", name: "WMI", tactic: "Execution" },
      { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
    ],
    targetIndustries: ["Healthcare", "Manufacturing", "Government", "Education", "Financial"],
    targetRegions: ["North America", "Europe", "Asia-Pacific"],
    ransomwareVariants: [
      { name: "LockBit 3.0", type: "locker" },
      { name: "LockBit Green", type: "locker" },
      { name: "StealBit", type: "exfiltrator" },
    ],
    knownPaymentAddresses: [
      { currency: "BTC", address: "bc1q...redacted" },
      { currency: "XMR", address: "4...redacted" },
    ],
    avgRansomDemandUsd: 1500000,
    decryptorAvailable: true,
    decryptorSource: "No More Ransom / Law Enforcement (Feb 2024 takedown)",
    iocIndicators: [
      { type: "file_extension", value: ".lockbit" },
      { type: "file_extension", value: ".HLJkNskOq" },
      { type: "mutex", value: "Global\\{UUID}" },
      { type: "registry", value: "HKCU\\Software\\LockBit" },
    ],
    referenceUrls: [
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a",
      "https://www.nomoreransom.org",
    ],
  },
  {
    name: "BlackCat/ALPHV",
    aliases: ["ALPHV", "Noberus", "BlackCat"],
    threatLevel: "critical",
    isActive: false,
    firstSeen: "2021-11",
    lastActive: "2024-03",
    description:
      "First Rust-based RaaS. Known for triple extortion (encrypt + exfil + DDoS threat). Exit scammed affiliates in 2024.",
    ttps: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1562.001", name: "Disable Security Tools", tactic: "Defense Evasion" },
      { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
      { id: "T1071.001", name: "Application Layer Protocol", tactic: "Command and Control" },
    ],
    targetIndustries: ["Healthcare", "Technology", "Financial", "Legal", "Critical Infrastructure"],
    targetRegions: ["North America", "Europe", "Australia"],
    ransomwareVariants: [
      { name: "BlackCat", type: "locker" },
      { name: "Sphynx", type: "locker" },
      { name: "ExMatter", type: "exfiltrator" },
    ],
    knownPaymentAddresses: [
      { currency: "BTC", address: "bc1q...redacted" },
      { currency: "XMR", address: "8...redacted" },
    ],
    avgRansomDemandUsd: 2500000,
    decryptorAvailable: true,
    decryptorSource: "FBI (Dec 2023 seizure)",
    iocIndicators: [
      { type: "file_extension", value: ".alphv" },
      { type: "file_extension", value: ".sphynx" },
      { type: "user_agent", value: "Mozilla/5.0 ExMatter" },
    ],
    referenceUrls: [
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a",
      "https://www.ic3.gov/Media/News/2023/231219.pdf",
    ],
  },
  {
    name: "Cl0p",
    aliases: ["Clop", "TA505", "FIN11"],
    threatLevel: "critical",
    isActive: true,
    firstSeen: "2019-02",
    lastActive: "2026-01",
    description:
      "Known for mass exploitation of zero-day vulnerabilities in file transfer solutions (MOVEit, GoAnywhere, Accellion). Focuses on data theft over encryption.",
    ttps: [
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution" },
      { id: "T1070.004", name: "File Deletion", tactic: "Defense Evasion" },
    ],
    targetIndustries: ["Financial", "Government", "Healthcare", "Retail", "Technology"],
    targetRegions: ["North America", "Europe", "Global"],
    ransomwareVariants: [
      { name: "Cl0p", type: "locker" },
      { name: "DEWMODE", type: "webshell" },
      { name: "LEMURLOOT", type: "webshell" },
    ],
    knownPaymentAddresses: [{ currency: "BTC", address: "bc1q...redacted" }],
    avgRansomDemandUsd: 5000000,
    decryptorAvailable: false,
    decryptorSource: null,
    iocIndicators: [
      { type: "file_extension", value: ".clop" },
      { type: "file_extension", value: ".CIop" },
      { type: "webshell", value: "human2.aspx" },
    ],
    referenceUrls: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"],
  },
  {
    name: "Play",
    aliases: ["PlayCrypt", "Play Ransomware"],
    threatLevel: "high",
    isActive: true,
    firstSeen: "2022-06",
    lastActive: "2026-02",
    description:
      "Double extortion group known for targeting Latin American and European organizations. Uses intermittent encryption for speed.",
    ttps: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
      { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access" },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
    ],
    targetIndustries: ["Government", "Manufacturing", "Technology", "Telecom"],
    targetRegions: ["Latin America", "Europe", "North America"],
    ransomwareVariants: [{ name: "Play", type: "locker" }],
    knownPaymentAddresses: [{ currency: "BTC", address: "bc1q...redacted" }],
    avgRansomDemandUsd: 800000,
    decryptorAvailable: false,
    decryptorSource: null,
    iocIndicators: [
      { type: "file_extension", value: ".play" },
      { type: "filename", value: "ReadMe.txt" },
    ],
    referenceUrls: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"],
  },
  {
    name: "Akira",
    aliases: ["Akira Ransomware"],
    threatLevel: "high",
    isActive: true,
    firstSeen: "2023-03",
    lastActive: "2026-02",
    description:
      "Targets small-to-medium businesses. Known for exploiting Cisco VPN vulnerabilities. Operates both Windows and Linux variants.",
    ttps: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
      { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1562.001", name: "Disable Security Tools", tactic: "Defense Evasion" },
    ],
    targetIndustries: ["Healthcare", "Financial", "Manufacturing", "Technology", "Education"],
    targetRegions: ["North America", "Europe", "Asia-Pacific"],
    ransomwareVariants: [
      { name: "Akira", type: "locker" },
      { name: "Megazord", type: "locker" },
    ],
    knownPaymentAddresses: [{ currency: "BTC", address: "bc1q...redacted" }],
    avgRansomDemandUsd: 400000,
    decryptorAvailable: true,
    decryptorSource: "Avast (Jul 2023, v1 only)",
    iocIndicators: [
      { type: "file_extension", value: ".akira" },
      { type: "filename", value: "akira_readme.txt" },
    ],
    referenceUrls: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"],
  },
  {
    name: "Royal/BlackSuit",
    aliases: ["Royal", "BlackSuit", "Conti successor"],
    threatLevel: "high",
    isActive: true,
    firstSeen: "2022-09",
    lastActive: "2026-01",
    description:
      "Successor to Conti. Rebranded as BlackSuit in 2023. Targets critical infrastructure and healthcare. Uses callback phishing.",
    ttps: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
    ],
    targetIndustries: ["Healthcare", "Critical Infrastructure", "Education", "Manufacturing"],
    targetRegions: ["North America", "Europe"],
    ransomwareVariants: [
      { name: "Royal", type: "locker" },
      { name: "BlackSuit", type: "locker" },
    ],
    knownPaymentAddresses: [
      { currency: "BTC", address: "bc1q...redacted" },
      { currency: "XMR", address: "4...redacted" },
    ],
    avgRansomDemandUsd: 3000000,
    decryptorAvailable: false,
    decryptorSource: null,
    iocIndicators: [
      { type: "file_extension", value: ".royal" },
      { type: "file_extension", value: ".blacksuit" },
      { type: "filename", value: "README.BlackSuit.txt" },
    ],
    referenceUrls: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a"],
  },
];

// Ransomware file extensions database for detection
export const RANSOMWARE_EXTENSIONS: Record<string, string> = {
  ".lockbit": "LockBit",
  ".HLJkNskOq": "LockBit 3.0",
  ".alphv": "BlackCat/ALPHV",
  ".sphynx": "BlackCat/ALPHV",
  ".clop": "Cl0p",
  ".CIop": "Cl0p",
  ".play": "Play",
  ".akira": "Akira",
  ".royal": "Royal",
  ".blacksuit": "BlackSuit",
  ".basta": "Black Basta",
  ".rhysida": "Rhysida",
  ".medusa": "Medusa",
  ".phobos": "Phobos",
  ".hive": "Hive",
  ".ech0raix": "eCh0raix",
  ".mallox": "Mallox",
  ".trigona": "Trigona",
  ".cactus": "Cactus",
  ".bianlian": "BianLian",
  ".monti": "Monti",
  ".noescape": "NoEscape",
  ".hunters": "Hunters International",
  ".8base": "8Base",
  ".inc": "INC Ransom",
};

// Common ransomware indicators
export const RANSOMWARE_INDICATORS = {
  // Ransom note filenames
  ransomNotes: [
    "README.txt",
    "DECRYPT.txt",
    "HOW_TO_DECRYPT.txt",
    "HOW_TO_RECOVER.txt",
    "RESTORE_FILES.txt",
    "!!READ_ME!!.txt",
    "RECOVER-FILES.txt",
    "_readme.txt",
    "ReadMe.txt",
    "akira_readme.txt",
    "README.BlackSuit.txt",
    "HOW_TO_DECRYPT.html",
    "DECRYPT_INSTRUCTION.html",
  ],
  // Suspicious process names
  suspiciousProcesses: [
    "vssadmin.exe delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled No",
    "wbadmin delete catalog",
    "cipher /w:",
    "icacls * /grant Everyone:F /T /C /Q",
  ],
  // Registry keys often modified
  registryModifications: [
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
  ],
};

// Canary file templates — realistic-looking important files
export interface CanaryFileTemplate {
  fileName: string;
  fileType: string;
  description: string;
  contentHint: string;
}

export const CANARY_FILE_TEMPLATES: CanaryFileTemplate[] = [
  {
    fileName: "Q4_Financial_Report_2025_CONFIDENTIAL.xlsx",
    fileType: "xlsx",
    description: "Fake quarterly financial report",
    contentHint: "Contains simulated financial data with revenue and expense figures",
  },
  {
    fileName: "Board_Meeting_Minutes_Jan2026.docx",
    fileType: "docx",
    description: "Fake board meeting minutes",
    contentHint: "Simulated meeting notes with strategic decisions",
  },
  {
    fileName: "Employee_Salary_Database_2026.xlsx",
    fileType: "xlsx",
    description: "Fake salary database",
    contentHint: "Simulated employee compensation data",
  },
  {
    fileName: "M&A_Target_Analysis_RESTRICTED.pdf",
    fileType: "pdf",
    description: "Fake M&A analysis document",
    contentHint: "Simulated merger and acquisition target analysis",
  },
  {
    fileName: "customer_database_backup.sql",
    fileType: "sql",
    description: "Fake database backup",
    contentHint: "Simulated SQL dump with fake customer records",
  },
  {
    fileName: "API_Keys_and_Credentials.txt",
    fileType: "txt",
    description: "Fake credentials file",
    contentHint: "Simulated API keys and service credentials (all fake)",
  },
  {
    fileName: "Insurance_Policy_Details_2026.pdf",
    fileType: "pdf",
    description: "Fake cyber insurance policy",
    contentHint: "Simulated insurance coverage details",
  },
  {
    fileName: "Intellectual_Property_Patents.pptx",
    fileType: "pptx",
    description: "Fake IP portfolio presentation",
    contentHint: "Simulated patent and trade secret overview",
  },
  {
    fileName: "Private_Keys_Wallet.key",
    fileType: "key",
    description: "Fake cryptocurrency wallet keys",
    contentHint: "Simulated private keys (completely invalid)",
  },
  {
    fileName: "Executive_Contacts_Personal.xlsx",
    fileType: "xlsx",
    description: "Fake executive contact list",
    contentHint: "Simulated executive personal contact information",
  },
];

// Tabletop exercise scenario templates
export interface TabletopScenarioTemplate {
  title: string;
  scenarioType: string;
  difficulty: string;
  description: string;
  scenario: {
    background: string;
    initialCompromise: string;
    escalation: string;
    impact: string;
    objectives: string[];
  };
  injects: {
    order: number;
    timeMinutes: number;
    description: string;
    expectedResponse: string;
    hint: string;
  }[];
  durationMinutes: number;
}

export const TABLETOP_SCENARIOS: TabletopScenarioTemplate[] = [
  {
    title: "Healthcare Ransomware Attack",
    scenarioType: "ransomware",
    difficulty: "intermediate",
    description:
      "A ransomware attack targeting healthcare systems, encrypting patient records and disrupting clinical operations.",
    scenario: {
      background:
        "Your organization is a mid-sized healthcare provider with 3 hospitals and 15 clinics. It is a Monday morning.",
      initialCompromise:
        "A phishing email with a malicious attachment was opened by a staff member in the billing department on Friday evening. The attacker gained initial access via a macro-enabled document.",
      escalation:
        "Over the weekend, the attacker moved laterally using stolen Active Directory credentials, disabled Windows Defender via GPO, and staged the ransomware payload on domain controllers.",
      impact:
        "At 6:00 AM Monday, ransomware executes across all Windows systems. EHR systems are encrypted, lab systems are offline, pharmacy systems are down. Shadow copies have been deleted.",
      objectives: [
        "Activate incident response plan within 15 minutes",
        "Determine scope of encryption within 1 hour",
        "Establish alternative clinical workflows within 2 hours",
        "Notify regulatory bodies (HIPAA) within 24 hours",
        "Begin recovery operations within 4 hours",
      ],
    },
    injects: [
      {
        order: 1,
        timeMinutes: 0,
        description:
          "IT helpdesk receives 50+ calls reporting 'cannot access files' and blue ransom screens. How do you triage?",
        expectedResponse: "Activate IRP, page IR team, establish incident command, begin network isolation",
        hint: "Think about your first 3 actions — containment is priority",
      },
      {
        order: 2,
        timeMinutes: 10,
        description:
          "The CISO asks: should we pay the ransom? The group claims to have exfiltrated 2TB of patient data.",
        expectedResponse:
          "Do not make payment decision immediately. Verify exfiltration claim, assess backup viability, engage legal counsel and cyber insurer",
        hint: "Consider legal, regulatory, and ethical implications",
      },
      {
        order: 3,
        timeMinutes: 20,
        description:
          "A local news reporter calls asking about 'a cyberattack at your hospital'. Social media posts from staff are circulating.",
        expectedResponse:
          "Activate crisis communications plan, prepare holding statement, brief spokespersons, instruct staff on social media policy",
        hint: "Coordinate with PR/comms team before any public statement",
      },
      {
        order: 4,
        timeMinutes: 35,
        description:
          "Your backup team reports that 2 of 3 backup sets appear intact, but the most recent incremental from Friday is corrupted.",
        expectedResponse:
          "Verify remaining backups in isolated environment, calculate RPO impact, prioritize critical system restoration order",
        hint: "Test restore in sandbox before touching production",
      },
      {
        order: 5,
        timeMinutes: 50,
        description:
          "FBI contacts you — they are tracking this ransomware group and have a partial decryptor. They ask you not to pay and to preserve evidence.",
        expectedResponse:
          "Engage with FBI, preserve forensic evidence, test decryptor on non-critical systems first, continue parallel backup restoration",
        hint: "Law enforcement cooperation can provide additional resources and intelligence",
      },
    ],
    durationMinutes: 90,
  },
  {
    title: "Critical Infrastructure Ransomware",
    scenarioType: "ransomware",
    difficulty: "advanced",
    description:
      "A sophisticated attack targeting both IT and OT networks in a utility company, threatening physical safety.",
    scenario: {
      background:
        "Your organization operates a regional power grid serving 500,000 customers. You have both IT and OT environments with limited segmentation.",
      initialCompromise:
        "Attackers exploited a VPN zero-day vulnerability on a Friday night, gained access to the IT network, and moved through a poorly segmented jump box into the OT network.",
      escalation:
        "The attackers spent 3 weeks performing reconnaissance, mapping SCADA systems, and staging payloads. They encrypted IT systems and planted logic bombs in PLCs.",
      impact:
        "IT systems fully encrypted. OT HMI screens show ransom messages. SCADA communications are intermittent. Manual overrides are required for grid operations. Customer billing and communication systems are down.",
      objectives: [
        "Ensure physical safety of grid operations",
        "Isolate OT from IT networks completely",
        "Establish manual control of critical systems",
        "Coordinate with CISA/ICS-CERT",
        "Restore grid operations within 48 hours",
      ],
    },
    injects: [
      {
        order: 1,
        timeMinutes: 0,
        description:
          "Grid operators report anomalous SCADA readings and HMI screens displaying ransom notes. Automated load balancing is offline.",
        expectedResponse:
          "Immediately switch to manual operations, isolate OT network, activate physical safety protocols",
        hint: "Safety first — grid stability before IT recovery",
      },
      {
        order: 2,
        timeMinutes: 15,
        description:
          "The attackers threaten to manipulate grid controls if ransom is not paid within 24 hours. They demonstrate by briefly disrupting a substation.",
        expectedResponse:
          "Verify they have OT access, physically disconnect compromised PLCs, establish air-gapped control channels, contact CISA",
        hint: "Verify their actual capabilities vs bluff",
      },
      {
        order: 3,
        timeMinutes: 30,
        description: "NERC CIP compliance team asks about mandatory reporting timelines and potential violations.",
        expectedResponse:
          "Report to NERC within required timeframes, document all actions for compliance, engage legal for regulatory strategy",
        hint: "Critical infrastructure has specific mandatory reporting requirements",
      },
    ],
    durationMinutes: 120,
  },
  {
    title: "Supply Chain Ransomware",
    scenarioType: "supply_chain",
    difficulty: "advanced",
    description:
      "A ransomware attack originating from a compromised software vendor update, affecting multiple organizations simultaneously.",
    scenario: {
      background:
        "Your organization uses a popular managed service provider (MSP) tool for IT management across 200 endpoints.",
      initialCompromise:
        "The MSP's update server was compromised. A malicious update was pushed to all managed endpoints containing a dormant ransomware payload.",
      escalation:
        "The payload activated simultaneously across thousands of MSP customers worldwide. Your organization is one of the affected.",
      impact:
        "All 200 managed endpoints are encrypted. The MSP is unreachable. Other customers are reporting the same issue on social media.",
      objectives: [
        "Isolate all affected endpoints immediately",
        "Identify and remove the MSP agent from all systems",
        "Assess which systems were affected vs clean",
        "Coordinate with other affected organizations",
        "Evaluate third-party risk management processes",
      ],
    },
    injects: [
      {
        order: 1,
        timeMinutes: 0,
        description:
          "200 endpoints simultaneously encrypt. The MSP management console is inaccessible. How do you isolate at scale?",
        expectedResponse:
          "Network-level isolation (switch port shutdown, VLAN changes, firewall rules), disable MSP agent via GPO if domain controllers are clean",
        hint: "Network isolation is faster than endpoint-by-endpoint when dealing with mass infection",
      },
      {
        order: 2,
        timeMinutes: 15,
        description:
          "Your CEO asks if your cyber insurance covers supply chain attacks. Legal is asking about liability.",
        expectedResponse:
          "Review policy language for supply chain coverage, engage broker, document MSP contractual SLAs and liability clauses",
        hint: "Supply chain attacks often have complex liability chains",
      },
    ],
    durationMinutes: 90,
  },
];

/**
 * Generate a recovery runbook based on the attack scenario
 */
export function generateRecoverySteps(params: {
  ransomwareVariant?: string;
  affectedSystems: string[];
  affectedDataTypes: string[];
  hasBackups: boolean;
  backupAge?: string;
  decryptorAvailable: boolean;
}): {
  steps: {
    order: number;
    title: string;
    description: string;
    responsible: string;
    estimatedMinutes: number;
    status: string;
  }[];
  priorityActions: string[];
  communicationPlan: { stakeholder: string; timing: string; channel: string }[];
  legalRequirements: string[];
  estimatedDowntimeHours: number;
  estimatedRecoveryCostUsd: number;
} {
  const steps = [
    {
      order: 1,
      title: "Activate Incident Response Plan",
      description:
        "Assemble the IR team, establish incident command, and begin documentation. Notify CISO and senior leadership.",
      responsible: "IR Team Lead",
      estimatedMinutes: 15,
      status: "pending",
    },
    {
      order: 2,
      title: "Network Isolation & Containment",
      description:
        "Isolate all affected segments from the network. Disable compromised accounts. Block C2 domains/IPs at the firewall.",
      responsible: "Network Security",
      estimatedMinutes: 30,
      status: "pending",
    },
    {
      order: 3,
      title: "Scope Assessment",
      description: `Determine the full scope of encryption. Affected systems: ${params.affectedSystems.join(", ")}. Identify which systems are clean vs compromised.`,
      responsible: "Forensics Team",
      estimatedMinutes: 120,
      status: "pending",
    },
    {
      order: 4,
      title: "Evidence Preservation",
      description:
        "Capture forensic images of representative affected systems. Preserve logs, memory dumps, and ransom notes for law enforcement.",
      responsible: "Digital Forensics",
      estimatedMinutes: 180,
      status: "pending",
    },
    {
      order: 5,
      title: "Backup Verification",
      description: params.hasBackups
        ? `Verify backup integrity in an isolated environment. Last known good backup: ${params.backupAge || "unknown"}. Test restore on non-production systems first.`
        : "No verified backups available. Explore alternative recovery options: decryptors, shadow copies, file recovery tools.",
      responsible: "Backup Admin",
      estimatedMinutes: 240,
      status: "pending",
    },
  ];

  if (params.decryptorAvailable) {
    steps.push({
      order: 6,
      title: "Test Decryptor",
      description: `A decryptor is available for ${params.ransomwareVariant || "this variant"}. Test on isolated systems before mass deployment. Verify file integrity after decryption.`,
      responsible: "Security Engineering",
      estimatedMinutes: 120,
      status: "pending",
    });
  }

  steps.push(
    {
      order: steps.length + 1,
      title: "System Rebuild & Restoration",
      description:
        "Rebuild affected systems from clean images. Restore data from verified backups. Apply security patches before reconnecting to network.",
      responsible: "IT Operations",
      estimatedMinutes: 480,
      status: "pending",
    },
    {
      order: steps.length + 2,
      title: "Credential Reset",
      description:
        "Reset all Active Directory passwords, service accounts, and API keys. Revoke and reissue certificates. Enable MFA for all accounts.",
      responsible: "Identity Team",
      estimatedMinutes: 120,
      status: "pending",
    },
    {
      order: steps.length + 3,
      title: "Monitoring & Validation",
      description:
        "Deploy enhanced monitoring on recovered systems. Watch for re-infection indicators. Validate all critical services are functional.",
      responsible: "SOC Team",
      estimatedMinutes: 240,
      status: "pending",
    },
    {
      order: steps.length + 4,
      title: "Post-Incident Review",
      description:
        "Conduct thorough post-incident review. Document lessons learned, update IR playbooks, and implement recommendations.",
      responsible: "CISO",
      estimatedMinutes: 180,
      status: "pending",
    },
  );

  const priorityActions = [
    "IMMEDIATE: Isolate all affected network segments",
    "IMMEDIATE: Disable all compromised user accounts",
    "WITHIN 1 HOUR: Notify senior leadership and legal counsel",
    "WITHIN 1 HOUR: Engage cyber insurance carrier",
    "WITHIN 4 HOURS: Begin forensic evidence collection",
    "WITHIN 24 HOURS: File law enforcement report (FBI IC3)",
  ];

  if (params.affectedDataTypes.some((t) => ["PII", "PHI", "PCI"].includes(t))) {
    priorityActions.push("WITHIN 72 HOURS: Notify data protection authority (GDPR/HIPAA/PCI)");
  }

  const communicationPlan = [
    { stakeholder: "Board of Directors", timing: "Within 4 hours", channel: "Emergency board call" },
    { stakeholder: "Employees", timing: "Within 8 hours", channel: "All-hands email (from unaffected system)" },
    { stakeholder: "Customers", timing: "Within 24-48 hours", channel: "Email + website notice" },
    { stakeholder: "Regulators", timing: "Per regulatory requirements", channel: "Official notification channels" },
    { stakeholder: "Law Enforcement", timing: "Within 24 hours", channel: "FBI IC3 / local field office" },
    { stakeholder: "Cyber Insurance", timing: "Immediately", channel: "Policy hotline" },
    { stakeholder: "Media", timing: "After legal review", channel: "Press statement" },
  ];

  const legalRequirements: string[] = [];
  if (params.affectedDataTypes.includes("PII")) {
    legalRequirements.push("State breach notification laws (varies by state, typically 30-60 days)");
    legalRequirements.push("CCPA/CPRA notification to California residents if applicable");
  }
  if (params.affectedDataTypes.includes("PHI")) {
    legalRequirements.push("HIPAA breach notification to HHS within 60 days");
    legalRequirements.push("Individual notification to affected patients");
  }
  if (params.affectedDataTypes.includes("PCI")) {
    legalRequirements.push("PCI DSS incident reporting to acquiring bank");
    legalRequirements.push("Engage PCI Forensic Investigator (PFI)");
  }
  legalRequirements.push("Preserve all evidence for potential litigation");
  legalRequirements.push("Document all incident response actions and decisions");

  const systemCount = params.affectedSystems.length;
  const estimatedDowntimeHours = params.hasBackups ? Math.max(24, systemCount * 4) : Math.max(72, systemCount * 8);
  const estimatedRecoveryCostUsd = systemCount * 15000 + (params.hasBackups ? 50000 : 200000);

  return {
    steps,
    priorityActions,
    communicationPlan,
    legalRequirements,
    estimatedDowntimeHours,
    estimatedRecoveryCostUsd,
  };
}

/**
 * Match file extensions or indicators against known ransomware groups
 */
export function identifyRansomwareGroup(indicators: {
  fileExtension?: string;
  ransomNote?: string;
  processNames?: string[];
}): RansomwareGroupProfile | null {
  if (indicators.fileExtension) {
    const groupName = RANSOMWARE_EXTENSIONS[indicators.fileExtension];
    if (groupName) {
      return KNOWN_RANSOMWARE_GROUPS.find((g) => g.name === groupName || g.aliases.includes(groupName)) || null;
    }
  }

  if (indicators.ransomNote) {
    const noteLower = indicators.ransomNote.toLowerCase();
    for (const group of KNOWN_RANSOMWARE_GROUPS) {
      if (
        group.name.toLowerCase().includes(noteLower) ||
        group.aliases.some((a) => noteLower.includes(a.toLowerCase()))
      ) {
        return group;
      }
    }
  }

  return null;
}

/**
 * Compute a canary file hash (simulated SHA-256)
 */
export function computeCanaryHash(fileName: string, deployPath: string, timestamp: number): string {
  // In production, this would be a real SHA-256 of the file content
  // For now, generate a deterministic hash-like string
  const input = `${fileName}:${deployPath}:${timestamp}`;
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0; // Convert to 32-bit integer
  }
  const hex = Math.abs(hash).toString(16).padStart(8, "0");
  return `sha256:${hex}${hex}${hex}${hex}${hex}${hex}${hex}${hex}`;
}

/**
 * Get summary statistics for ransomware defense posture
 */
export function computeReadinessScore(params: {
  hasKillSwitch: boolean;
  canaryFileCount: number;
  backupVerifiedCount: number;
  backupFailedCount: number;
  lastTabletopDate: Date | null;
  hasRecoveryRunbook: boolean;
  lastKillSwitchTest: Date | null;
}): {
  score: number;
  grade: string;
  recommendations: string[];
} {
  let score = 0;
  const recommendations: string[] = [];

  // Kill switch readiness (20 points)
  if (params.hasKillSwitch) {
    score += 10;
    if (params.lastKillSwitchTest) {
      const daysSinceTest = (Date.now() - params.lastKillSwitchTest.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceTest < 30) score += 10;
      else if (daysSinceTest < 90) score += 5;
      else recommendations.push("Test kill switch functionality — last test was over 90 days ago");
    } else {
      recommendations.push("Test kill switch at least once to verify it works");
    }
  } else {
    recommendations.push("Deploy endpoint sensors to enable kill switch capability");
  }

  // Canary files (20 points)
  if (params.canaryFileCount >= 10) score += 20;
  else if (params.canaryFileCount >= 5) score += 15;
  else if (params.canaryFileCount >= 1) score += 10;
  else recommendations.push("Deploy canary files to critical file shares for early ransomware detection");

  // Backup verification (25 points)
  const totalBackups = params.backupVerifiedCount + params.backupFailedCount;
  if (totalBackups > 0) {
    const verifiedRate = params.backupVerifiedCount / totalBackups;
    score += Math.round(verifiedRate * 25);
    if (verifiedRate < 1) {
      recommendations.push(`${params.backupFailedCount} backup(s) failed verification — investigate and remediate`);
    }
  } else {
    recommendations.push("Verify backup integrity — no backups have been tested");
  }

  // Tabletop exercises (20 points)
  if (params.lastTabletopDate) {
    const daysSince = (Date.now() - params.lastTabletopDate.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSince < 90) score += 20;
    else if (daysSince < 180) score += 15;
    else if (daysSince < 365) score += 10;
    else recommendations.push("Conduct a tabletop exercise — last one was over a year ago");
  } else {
    recommendations.push("Schedule your first tabletop exercise to test incident response readiness");
  }

  // Recovery runbook (15 points)
  if (params.hasRecoveryRunbook) {
    score += 15;
  } else {
    recommendations.push("Generate a recovery runbook to ensure structured incident response");
  }

  let grade: string;
  if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";
  else grade = "F";

  return { score, grade, recommendations };
}
