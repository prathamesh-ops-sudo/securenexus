/**
 * Security Posture Score Engine v2
 *
 * Enhanced posture scoring with 6 domain sub-scores (Identity, Endpoint, Cloud,
 * Network, Application, Data), peer benchmarking percentiles, questionnaire
 * auto-answer templates, and score trend analysis.
 */

// ── Domain Weights (must sum to 100) ──────────────────────────────────────────

export const DOMAIN_WEIGHTS: Record<string, number> = {
  identity: 20,
  endpoint: 20,
  cloud: 18,
  network: 15,
  application: 15,
  data: 12,
};

// ── Domain Icons & Labels ─────────────────────────────────────────────────────

export const DOMAIN_META: Record<string, { label: string; description: string }> = {
  identity: {
    label: "Identity & Access",
    description: "MFA adoption, privileged access controls, SSO coverage, password policies, access reviews",
  },
  endpoint: {
    label: "Endpoint Protection",
    description: "EDR coverage, patch compliance, disk encryption, host isolation readiness, AV definitions",
  },
  cloud: {
    label: "Cloud Security",
    description: "CSPM findings, IAM misconfigurations, storage encryption, network segmentation, logging",
  },
  network: {
    label: "Network Security",
    description: "Firewall rules, IDS/IPS coverage, DNS filtering, segmentation, TLS enforcement",
  },
  application: {
    label: "Application Security",
    description: "SAST/DAST findings, dependency vulnerabilities, API security, WAF coverage, secure SDLC",
  },
  data: {
    label: "Data Protection",
    description: "Encryption at rest/transit, DLP policies, backup verification, data classification, retention",
  },
};

// ── Scoring Controls Per Domain ───────────────────────────────────────────────

export interface ScoringControl {
  id: string;
  name: string;
  domain: string;
  weight: number;
  description: string;
}

export const SCORING_CONTROLS: ScoringControl[] = [
  // Identity
  {
    id: "ID-01",
    name: "MFA Enforcement",
    domain: "identity",
    weight: 25,
    description: "Multi-factor authentication enforced for all users",
  },
  {
    id: "ID-02",
    name: "SSO Coverage",
    domain: "identity",
    weight: 20,
    description: "Single sign-on configured for all critical applications",
  },
  {
    id: "ID-03",
    name: "Privileged Access Management",
    domain: "identity",
    weight: 20,
    description: "PAM solution deployed with session recording",
  },
  {
    id: "ID-04",
    name: "Access Reviews",
    domain: "identity",
    weight: 15,
    description: "Quarterly access reviews completed for all systems",
  },
  {
    id: "ID-05",
    name: "Password Policy",
    domain: "identity",
    weight: 10,
    description: "Strong password policy enforced (14+ chars, complexity)",
  },
  {
    id: "ID-06",
    name: "Service Account Management",
    domain: "identity",
    weight: 10,
    description: "Service accounts inventoried with rotation policies",
  },

  // Endpoint
  {
    id: "EP-01",
    name: "EDR Coverage",
    domain: "endpoint",
    weight: 25,
    description: "EDR agent deployed on 100% of managed endpoints",
  },
  {
    id: "EP-02",
    name: "Patch Compliance",
    domain: "endpoint",
    weight: 25,
    description: "Critical patches applied within 72 hours",
  },
  {
    id: "EP-03",
    name: "Disk Encryption",
    domain: "endpoint",
    weight: 15,
    description: "Full disk encryption enabled on all endpoints",
  },
  {
    id: "EP-04",
    name: "Host Isolation Ready",
    domain: "endpoint",
    weight: 15,
    description: "Network isolation capability available for all endpoints",
  },
  {
    id: "EP-05",
    name: "AV Definitions Current",
    domain: "endpoint",
    weight: 10,
    description: "Antivirus definitions updated within 24 hours",
  },
  {
    id: "EP-06",
    name: "USB/Removable Media Control",
    domain: "endpoint",
    weight: 10,
    description: "Removable media policies enforced",
  },

  // Cloud
  {
    id: "CL-01",
    name: "CSPM Compliance",
    domain: "cloud",
    weight: 25,
    description: "Cloud security posture findings below threshold",
  },
  {
    id: "CL-02",
    name: "IAM Least Privilege",
    domain: "cloud",
    weight: 20,
    description: "No over-privileged IAM roles or users",
  },
  {
    id: "CL-03",
    name: "Storage Encryption",
    domain: "cloud",
    weight: 15,
    description: "All cloud storage buckets encrypted at rest",
  },
  {
    id: "CL-04",
    name: "Network Segmentation",
    domain: "cloud",
    weight: 15,
    description: "VPC/VNet segmentation with least-privilege security groups",
  },
  {
    id: "CL-05",
    name: "Logging & Monitoring",
    domain: "cloud",
    weight: 15,
    description: "CloudTrail/Activity Log enabled with alerting",
  },
  {
    id: "CL-06",
    name: "Container Security",
    domain: "cloud",
    weight: 10,
    description: "Container images scanned, runtime protection enabled",
  },

  // Network
  {
    id: "NW-01",
    name: "Firewall Configuration",
    domain: "network",
    weight: 25,
    description: "Firewall rules reviewed and least-privilege",
  },
  {
    id: "NW-02",
    name: "IDS/IPS Coverage",
    domain: "network",
    weight: 20,
    description: "Intrusion detection/prevention on all network segments",
  },
  {
    id: "NW-03",
    name: "DNS Filtering",
    domain: "network",
    weight: 15,
    description: "DNS-level filtering blocking malicious domains",
  },
  {
    id: "NW-04",
    name: "Network Segmentation",
    domain: "network",
    weight: 20,
    description: "Critical systems isolated in separate network segments",
  },
  {
    id: "NW-05",
    name: "TLS Enforcement",
    domain: "network",
    weight: 10,
    description: "TLS 1.2+ enforced on all internal and external traffic",
  },
  {
    id: "NW-06",
    name: "VPN/Zero Trust",
    domain: "network",
    weight: 10,
    description: "Zero trust or VPN access for remote workers",
  },

  // Application
  {
    id: "AP-01",
    name: "SAST/DAST Coverage",
    domain: "application",
    weight: 25,
    description: "Static and dynamic security testing in CI/CD pipeline",
  },
  {
    id: "AP-02",
    name: "Dependency Scanning",
    domain: "application",
    weight: 20,
    description: "Third-party library vulnerabilities tracked and patched",
  },
  {
    id: "AP-03",
    name: "API Security",
    domain: "application",
    weight: 20,
    description: "API inventory complete with authentication on all endpoints",
  },
  {
    id: "AP-04",
    name: "WAF Protection",
    domain: "application",
    weight: 15,
    description: "Web application firewall protecting public-facing apps",
  },
  {
    id: "AP-05",
    name: "Secure SDLC",
    domain: "application",
    weight: 10,
    description: "Secure development lifecycle practices documented and followed",
  },
  {
    id: "AP-06",
    name: "Code Signing",
    domain: "application",
    weight: 10,
    description: "Release artifacts signed and verified",
  },

  // Data
  {
    id: "DA-01",
    name: "Encryption at Rest",
    domain: "data",
    weight: 25,
    description: "All sensitive data encrypted at rest with managed keys",
  },
  {
    id: "DA-02",
    name: "Encryption in Transit",
    domain: "data",
    weight: 20,
    description: "All data transfers use TLS/mTLS encryption",
  },
  {
    id: "DA-03",
    name: "DLP Policies",
    domain: "data",
    weight: 15,
    description: "Data loss prevention policies active on email and endpoints",
  },
  {
    id: "DA-04",
    name: "Backup Verification",
    domain: "data",
    weight: 20,
    description: "Backup integrity verified with regular restore tests",
  },
  {
    id: "DA-05",
    name: "Data Classification",
    domain: "data",
    weight: 10,
    description: "Data classification scheme applied to all repositories",
  },
  {
    id: "DA-06",
    name: "Retention Policies",
    domain: "data",
    weight: 10,
    description: "Data retention and destruction policies enforced",
  },
];

// ── Peer Benchmark Data ───────────────────────────────────────────────────────

interface IndustryBenchmark {
  industry: string;
  companySize: string;
  avgOverall: number;
  sampleSize: number;
}

const INDUSTRY_BENCHMARKS: IndustryBenchmark[] = [
  { industry: "Technology", companySize: "small", avgOverall: 62, sampleSize: 340 },
  { industry: "Technology", companySize: "medium", avgOverall: 71, sampleSize: 280 },
  { industry: "Technology", companySize: "large", avgOverall: 78, sampleSize: 150 },
  { industry: "Technology", companySize: "enterprise", avgOverall: 84, sampleSize: 85 },
  { industry: "Financial Services", companySize: "small", avgOverall: 68, sampleSize: 210 },
  { industry: "Financial Services", companySize: "medium", avgOverall: 76, sampleSize: 175 },
  { industry: "Financial Services", companySize: "large", avgOverall: 83, sampleSize: 95 },
  { industry: "Financial Services", companySize: "enterprise", avgOverall: 88, sampleSize: 55 },
  { industry: "Healthcare", companySize: "small", avgOverall: 55, sampleSize: 180 },
  { industry: "Healthcare", companySize: "medium", avgOverall: 64, sampleSize: 140 },
  { industry: "Healthcare", companySize: "large", avgOverall: 74, sampleSize: 80 },
  { industry: "Healthcare", companySize: "enterprise", avgOverall: 80, sampleSize: 40 },
  { industry: "Retail", companySize: "small", avgOverall: 48, sampleSize: 260 },
  { industry: "Retail", companySize: "medium", avgOverall: 58, sampleSize: 200 },
  { industry: "Retail", companySize: "large", avgOverall: 68, sampleSize: 110 },
  { industry: "Manufacturing", companySize: "small", avgOverall: 42, sampleSize: 190 },
  { industry: "Manufacturing", companySize: "medium", avgOverall: 52, sampleSize: 150 },
  { industry: "Manufacturing", companySize: "large", avgOverall: 62, sampleSize: 90 },
  { industry: "Government", companySize: "medium", avgOverall: 60, sampleSize: 120 },
  { industry: "Government", companySize: "large", avgOverall: 70, sampleSize: 70 },
  { industry: "Education", companySize: "medium", avgOverall: 45, sampleSize: 160 },
  { industry: "Energy", companySize: "large", avgOverall: 66, sampleSize: 75 },
];

// ── Questionnaire Templates ───────────────────────────────────────────────────

export interface QuestionTemplate {
  questionNumber: number;
  questionText: string;
  category: string;
  autoAnswerKey: string;
  defaultAnswer: string;
  confidencePercent: number;
}

export interface QuestionnaireTemplate {
  framework: string;
  title: string;
  description: string;
  questions: QuestionTemplate[];
}

export const QUESTIONNAIRE_TEMPLATES: QuestionnaireTemplate[] = [
  {
    framework: "SOC2",
    title: "SOC 2 Type II Security Questionnaire",
    description:
      "Standard SOC 2 Trust Services Criteria questionnaire covering security, availability, processing integrity, confidentiality, and privacy",
    questions: [
      {
        questionNumber: 1,
        questionText: "Does the organization enforce multi-factor authentication (MFA) for all user accounts?",
        category: "Access Control",
        autoAnswerKey: "ID-01",
        defaultAnswer:
          "Yes. MFA is enforced for all user accounts via our identity provider. Hardware security keys and authenticator apps are supported.",
        confidencePercent: 92,
      },
      {
        questionNumber: 2,
        questionText: "Is there a formal access review process conducted at least quarterly?",
        category: "Access Control",
        autoAnswerKey: "ID-04",
        defaultAnswer:
          "Yes. Access reviews are conducted quarterly for all systems. Automated workflows flag unused accounts and excessive privileges.",
        confidencePercent: 88,
      },
      {
        questionNumber: 3,
        questionText: "Are all endpoints protected by an EDR solution?",
        category: "Endpoint Security",
        autoAnswerKey: "EP-01",
        defaultAnswer:
          "Yes. All managed endpoints have EDR agents deployed with real-time threat detection and automated response capabilities.",
        confidencePercent: 90,
      },
      {
        questionNumber: 4,
        questionText: "Is data encrypted at rest and in transit?",
        category: "Data Protection",
        autoAnswerKey: "DA-01",
        defaultAnswer:
          "Yes. All data is encrypted at rest using AES-256 and in transit using TLS 1.2+. Encryption keys are managed via a dedicated KMS.",
        confidencePercent: 95,
      },
      {
        questionNumber: 5,
        questionText: "Does the organization have a documented incident response plan?",
        category: "Incident Response",
        autoAnswerKey: "IR-01",
        defaultAnswer:
          "Yes. A formal incident response plan is maintained, tested annually through tabletop exercises, and updated based on lessons learned.",
        confidencePercent: 85,
      },
      {
        questionNumber: 6,
        questionText: "Are security patches applied within defined SLAs?",
        category: "Vulnerability Management",
        autoAnswerKey: "EP-02",
        defaultAnswer:
          "Yes. Critical patches are applied within 72 hours, high within 7 days, and medium within 30 days. Automated patch management is in place.",
        confidencePercent: 87,
      },
      {
        questionNumber: 7,
        questionText: "Is network traffic monitored for anomalous behavior?",
        category: "Network Security",
        autoAnswerKey: "NW-02",
        defaultAnswer:
          "Yes. IDS/IPS systems monitor all network segments with AI-driven anomaly detection and automated alerting.",
        confidencePercent: 84,
      },
      {
        questionNumber: 8,
        questionText: "Are backups regularly tested for integrity and recoverability?",
        category: "Business Continuity",
        autoAnswerKey: "DA-04",
        defaultAnswer:
          "Yes. Backup integrity verification is performed weekly. Full restore tests are conducted monthly with documented results.",
        confidencePercent: 82,
      },
      {
        questionNumber: 9,
        questionText: "Does the organization maintain a data classification policy?",
        category: "Data Governance",
        autoAnswerKey: "DA-05",
        defaultAnswer:
          "Yes. A four-tier data classification scheme (Public, Internal, Confidential, Restricted) is enforced across all data repositories.",
        confidencePercent: 80,
      },
      {
        questionNumber: 10,
        questionText: "Is there a formal vendor/third-party risk management program?",
        category: "Third-Party Risk",
        autoAnswerKey: "TP-01",
        defaultAnswer:
          "Yes. All vendors undergo security assessments before onboarding. Ongoing monitoring includes SOC 2 report reviews and SLA compliance tracking.",
        confidencePercent: 78,
      },
      {
        questionNumber: 11,
        questionText: "Are application security testing (SAST/DAST) integrated into the development pipeline?",
        category: "Application Security",
        autoAnswerKey: "AP-01",
        defaultAnswer:
          "Yes. SAST and DAST tools are integrated into our CI/CD pipeline. All code changes undergo automated security scanning before deployment.",
        confidencePercent: 86,
      },
      {
        questionNumber: 12,
        questionText: "Does the organization conduct regular security awareness training?",
        category: "Security Awareness",
        autoAnswerKey: "SA-01",
        defaultAnswer:
          "Yes. All employees complete security awareness training quarterly, including phishing simulations and role-specific security modules.",
        confidencePercent: 83,
      },
    ],
  },
  {
    framework: "ISO27001",
    title: "ISO 27001:2022 Security Questionnaire",
    description:
      "Information Security Management System (ISMS) questionnaire aligned to ISO/IEC 27001:2022 Annex A controls",
    questions: [
      {
        questionNumber: 1,
        questionText: "Is there a documented information security policy approved by management?",
        category: "Organizational Controls",
        autoAnswerKey: "GOV-01",
        defaultAnswer:
          "Yes. An information security policy is approved by the CISO and reviewed annually. The policy is communicated to all employees.",
        confidencePercent: 90,
      },
      {
        questionNumber: 2,
        questionText: "Are information security roles and responsibilities clearly defined?",
        category: "Organizational Controls",
        autoAnswerKey: "GOV-02",
        defaultAnswer:
          "Yes. Security roles are defined in the RACI matrix covering CISO, security engineers, SOC analysts, and business unit security champions.",
        confidencePercent: 88,
      },
      {
        questionNumber: 3,
        questionText: "Is there a process for managing information security risks?",
        category: "Risk Management",
        autoAnswerKey: "RISK-01",
        defaultAnswer:
          "Yes. A formal risk management framework is maintained with quarterly risk assessments, risk register, and risk treatment plans.",
        confidencePercent: 85,
      },
      {
        questionNumber: 4,
        questionText: "Are physical and environmental security controls in place for data centers?",
        category: "Physical Security",
        autoAnswerKey: "PHYS-01",
        defaultAnswer:
          "Yes. Data centers implement badge access, CCTV monitoring, environmental controls (temperature, humidity, fire suppression), and visitor logs.",
        confidencePercent: 82,
      },
      {
        questionNumber: 5,
        questionText: "Is cryptographic key management formally documented?",
        category: "Cryptography",
        autoAnswerKey: "CRYPTO-01",
        defaultAnswer:
          "Yes. Key management procedures cover key generation, distribution, storage, rotation, and destruction using an HSM-backed KMS.",
        confidencePercent: 86,
      },
      {
        questionNumber: 6,
        questionText: "Are there controls to prevent unauthorized software installation?",
        category: "Operations Security",
        autoAnswerKey: "EP-06",
        defaultAnswer:
          "Yes. Application whitelisting is enforced on all endpoints. Only approved software from the internal catalog can be installed.",
        confidencePercent: 84,
      },
      {
        questionNumber: 7,
        questionText: "Is there a formal change management process?",
        category: "Operations Security",
        autoAnswerKey: "CM-01",
        defaultAnswer:
          "Yes. All changes follow a documented change management process including risk assessment, approval, testing, and rollback procedures.",
        confidencePercent: 87,
      },
      {
        questionNumber: 8,
        questionText: "Are supplier relationships and service agreements regularly reviewed?",
        category: "Supplier Relations",
        autoAnswerKey: "TP-01",
        defaultAnswer:
          "Yes. Supplier security is reviewed annually. Service agreements include security requirements, SLAs, and right-to-audit clauses.",
        confidencePercent: 80,
      },
      {
        questionNumber: 9,
        questionText: "Is there a business continuity management system?",
        category: "Business Continuity",
        autoAnswerKey: "BC-01",
        defaultAnswer:
          "Yes. A business continuity plan with defined RPO/RTO targets is maintained. Annual DR drills validate recovery capabilities.",
        confidencePercent: 83,
      },
      {
        questionNumber: 10,
        questionText: "Are security events logged, monitored, and investigated?",
        category: "Security Monitoring",
        autoAnswerKey: "NW-02",
        defaultAnswer:
          "Yes. A 24/7 SOC monitors security events via SIEM. Alerts are triaged, investigated, and escalated per documented procedures.",
        confidencePercent: 91,
      },
    ],
  },
  {
    framework: "HIPAA",
    title: "HIPAA Security Rule Questionnaire",
    description:
      "Health Insurance Portability and Accountability Act security assessment for covered entities and business associates",
    questions: [
      {
        questionNumber: 1,
        questionText: "Has the organization conducted a risk analysis of ePHI as required by 164.308(a)(1)(ii)(A)?",
        category: "Administrative Safeguards",
        autoAnswerKey: "RISK-01",
        defaultAnswer:
          "Yes. A comprehensive risk analysis of all systems containing ePHI is conducted annually, identifying threats, vulnerabilities, and risk levels.",
        confidencePercent: 85,
      },
      {
        questionNumber: 2,
        questionText: "Are unique user IDs assigned to each workforce member accessing ePHI?",
        category: "Access Control",
        autoAnswerKey: "ID-01",
        defaultAnswer:
          "Yes. All workforce members have unique identifiers. Shared accounts are prohibited. Authentication requires MFA for ePHI systems.",
        confidencePercent: 92,
      },
      {
        questionNumber: 3,
        questionText: "Is ePHI encrypted when transmitted over electronic networks?",
        category: "Transmission Security",
        autoAnswerKey: "DA-02",
        defaultAnswer:
          "Yes. All ePHI transmissions use TLS 1.2+ encryption. VPN tunnels are used for site-to-site communications.",
        confidencePercent: 94,
      },
      {
        questionNumber: 4,
        questionText: "Are there policies for disposal of ePHI on electronic media?",
        category: "Device & Media Controls",
        autoAnswerKey: "DA-06",
        defaultAnswer:
          "Yes. Media sanitization follows NIST SP 800-88 guidelines. Certificates of destruction are maintained for disposed media.",
        confidencePercent: 80,
      },
      {
        questionNumber: 5,
        questionText: "Is there an emergency access procedure for ePHI systems?",
        category: "Contingency Plan",
        autoAnswerKey: "BC-01",
        defaultAnswer:
          "Yes. Break-glass procedures allow emergency access to ePHI systems with full audit logging and mandatory post-incident review.",
        confidencePercent: 82,
      },
      {
        questionNumber: 6,
        questionText: "Are audit logs maintained for all ePHI access?",
        category: "Audit Controls",
        autoAnswerKey: "NW-02",
        defaultAnswer:
          "Yes. All ePHI access is logged with user identity, timestamp, action performed, and resource accessed. Logs are retained for 6 years.",
        confidencePercent: 90,
      },
      {
        questionNumber: 7,
        questionText: "Is workforce security awareness training conducted regularly?",
        category: "Security Awareness",
        autoAnswerKey: "SA-01",
        defaultAnswer:
          "Yes. HIPAA-specific security awareness training is mandatory for all workforce members annually, with additional training for new hires.",
        confidencePercent: 86,
      },
      {
        questionNumber: 8,
        questionText: "Are business associate agreements (BAAs) in place with all vendors handling ePHI?",
        category: "Business Associate Management",
        autoAnswerKey: "TP-01",
        defaultAnswer:
          "Yes. BAAs are executed with all business associates before ePHI access is granted. Agreements are reviewed annually.",
        confidencePercent: 88,
      },
    ],
  },
  {
    framework: "PCI-DSS",
    title: "PCI DSS v4.0 Self-Assessment Questionnaire",
    description: "Payment Card Industry Data Security Standard assessment for merchants and service providers",
    questions: [
      {
        questionNumber: 1,
        questionText: "Is a firewall configuration established and maintained to protect cardholder data?",
        category: "Network Security",
        autoAnswerKey: "NW-01",
        defaultAnswer:
          "Yes. Firewalls are configured per PCI DSS requirements with deny-all rules and explicit allow rules for authorized traffic only.",
        confidencePercent: 88,
      },
      {
        questionNumber: 2,
        questionText: "Are vendor-supplied default passwords changed before systems are deployed?",
        category: "System Security",
        autoAnswerKey: "ID-05",
        defaultAnswer:
          "Yes. All vendor-supplied defaults are changed during provisioning. Automated compliance scans verify no default credentials remain.",
        confidencePercent: 90,
      },
      {
        questionNumber: 3,
        questionText: "Is stored cardholder data encrypted using strong cryptography?",
        category: "Data Protection",
        autoAnswerKey: "DA-01",
        defaultAnswer:
          "Yes. Cardholder data is encrypted at rest using AES-256. Primary Account Numbers (PANs) are rendered unreadable via tokenization.",
        confidencePercent: 93,
      },
      {
        questionNumber: 4,
        questionText: "Is anti-virus software deployed on all systems commonly affected by malware?",
        category: "Malware Protection",
        autoAnswerKey: "EP-05",
        defaultAnswer:
          "Yes. Anti-malware with real-time scanning is deployed on all Windows and Linux systems. Definitions are updated automatically.",
        confidencePercent: 91,
      },
      {
        questionNumber: 5,
        questionText: "Are all security patches installed within defined timeframes?",
        category: "Vulnerability Management",
        autoAnswerKey: "EP-02",
        defaultAnswer:
          "Yes. Critical security patches are applied within 30 days per PCI DSS 4.0 requirements. Automated patch management ensures compliance.",
        confidencePercent: 86,
      },
      {
        questionNumber: 6,
        questionText: "Is access to cardholder data restricted on a need-to-know basis?",
        category: "Access Control",
        autoAnswerKey: "ID-04",
        defaultAnswer:
          "Yes. Role-based access controls limit cardholder data access to authorized personnel only. Access is reviewed quarterly.",
        confidencePercent: 89,
      },
      {
        questionNumber: 7,
        questionText: "Are penetration tests conducted at least annually?",
        category: "Testing",
        autoAnswerKey: "AP-01",
        defaultAnswer:
          "Yes. External and internal penetration tests are conducted annually by a qualified assessor. Findings are remediated per defined SLAs.",
        confidencePercent: 84,
      },
      {
        questionNumber: 8,
        questionText: "Is an information security policy maintained and communicated to all personnel?",
        category: "Security Policy",
        autoAnswerKey: "GOV-01",
        defaultAnswer:
          "Yes. A comprehensive information security policy covering PCI DSS requirements is maintained, reviewed annually, and acknowledged by all staff.",
        confidencePercent: 87,
      },
    ],
  },
];

// ── Score Calculation Helpers ─────────────────────────────────────────────────

export interface DomainScore {
  domain: string;
  score: number;
  weight: number;
  controlsEvaluated: number;
  controlsPassed: number;
  controlsFailed: number;
  findings: Array<{ controlId: string; status: string; message: string }>;
  recommendations: string[];
  riskFactors: string[];
}

export function computeOverallScore(domainScores: DomainScore[]): number {
  let totalWeight = 0;
  let weightedSum = 0;

  for (const ds of domainScores) {
    const w = DOMAIN_WEIGHTS[ds.domain] || 16;
    weightedSum += ds.score * w;
    totalWeight += w;
  }

  return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
}

export function computePercentileRank(
  overallScore: number,
  industry: string,
  companySize: string,
): { percentile: number; peerCount: number; avgScore: number } {
  const benchmark = INDUSTRY_BENCHMARKS.find((b) => b.industry === industry && b.companySize === companySize);

  if (!benchmark) {
    return { percentile: 50, peerCount: 0, avgScore: 60 };
  }

  const diff = overallScore - benchmark.avgOverall;
  const rawPercentile = 50 + diff * 2;
  const percentile = Math.max(1, Math.min(99, Math.round(rawPercentile)));

  return {
    percentile,
    peerCount: benchmark.sampleSize,
    avgScore: benchmark.avgOverall,
  };
}

export function generateDomainScores(orgId: string): DomainScore[] {
  let seed = 0;
  for (let i = 0; i < orgId.length; i++) {
    seed = ((seed << 5) - seed + orgId.charCodeAt(i)) | 0;
  }

  function seededRandom(): number {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return (seed % 100) / 100;
  }

  const domains = ["identity", "endpoint", "cloud", "network", "application", "data"];
  const results: DomainScore[] = [];

  for (const domain of domains) {
    const controls = SCORING_CONTROLS.filter((c) => c.domain === domain);
    let totalWeight = 0;
    let passedWeight = 0;
    const findings: Array<{ controlId: string; status: string; message: string }> = [];
    const recommendations: string[] = [];
    const riskFactors: string[] = [];
    let passed = 0;
    let failed = 0;

    for (const control of controls) {
      totalWeight += control.weight;
      const rand = seededRandom();
      if (rand > 0.3) {
        passedWeight += control.weight;
        passed++;
        findings.push({ controlId: control.id, status: "passed", message: `${control.name}: Compliant` });
      } else if (rand > 0.15) {
        passedWeight += control.weight * 0.5;
        findings.push({ controlId: control.id, status: "partial", message: `${control.name}: Partially implemented` });
        recommendations.push(`Improve ${control.name}: ${control.description}`);
      } else {
        failed++;
        findings.push({ controlId: control.id, status: "failed", message: `${control.name}: Not implemented` });
        riskFactors.push(`Missing: ${control.name}`);
        recommendations.push(`Implement ${control.name}: ${control.description}`);
      }
    }

    const score = totalWeight > 0 ? Math.round((passedWeight / totalWeight) * 100) : 0;

    results.push({
      domain,
      score,
      weight: DOMAIN_WEIGHTS[domain] || 16,
      controlsEvaluated: controls.length,
      controlsPassed: passed,
      controlsFailed: failed,
      findings,
      recommendations,
      riskFactors,
    });
  }

  return results;
}

export function generateScoreTrend(
  currentScore: number,
  months: number = 12,
): Array<{ period: string; score: number; change: number }> {
  const trend: Array<{ period: string; score: number; change: number }> = [];
  const now = new Date();
  let prevScore = Math.max(20, currentScore - Math.floor(Math.random() * 25) - 10);

  for (let i = months - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setMonth(d.getMonth() - i);
    const period = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;

    const targetScore = i === 0 ? currentScore : prevScore + Math.floor(Math.random() * 5) - 1;
    const score = Math.max(0, Math.min(100, targetScore));
    const change = score - prevScore;

    trend.push({ period, score, change });
    prevScore = score;
  }

  return trend;
}

export function getAvailableIndustries(): string[] {
  return Array.from(new Set(INDUSTRY_BENCHMARKS.map((b) => b.industry)));
}

export function getAvailableCompanySizes(): string[] {
  return Array.from(new Set(INDUSTRY_BENCHMARKS.map((b) => b.companySize)));
}
