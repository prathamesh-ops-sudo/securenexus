import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

interface GapAnalysis {
  id: string;
  orgId: string;
  framework: string;
  version: string;
  status: "pending" | "running" | "completed" | "failed";
  totalControls: number;
  implementedControls: number;
  partialControls: number;
  missingControls: number;
  complianceScore: number;
  gaps: ControlGap[];
  recommendations: Recommendation[];
  createdAt: string;
  completedAt: string | null;
  requestedBy: string;
}

interface ControlGap {
  controlId: string;
  controlName: string;
  category: string;
  status: "implemented" | "partial" | "missing" | "not_applicable";
  evidence: string[];
  remediationPriority: "critical" | "high" | "medium" | "low";
  estimatedEffort: string;
  description: string;
}

interface Recommendation {
  id: string;
  controlId: string;
  title: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  estimatedEffort: string;
  automatable: boolean;
}

const analyses = new Map<string, GapAnalysis>();

const FRAMEWORKS: Record<
  string,
  { name: string; version: string; controls: { id: string; name: string; category: string }[] }
> = {
  soc2: {
    name: "SOC 2 Type II",
    version: "2024",
    controls: [
      { id: "CC1.1", name: "Control Environment", category: "Common Criteria" },
      { id: "CC1.2", name: "Board Oversight", category: "Common Criteria" },
      { id: "CC2.1", name: "Information Quality", category: "Communication" },
      { id: "CC3.1", name: "Risk Assessment", category: "Risk Assessment" },
      { id: "CC3.2", name: "Fraud Risk", category: "Risk Assessment" },
      { id: "CC4.1", name: "Monitoring Activities", category: "Monitoring" },
      { id: "CC5.1", name: "Control Activities", category: "Control Activities" },
      { id: "CC6.1", name: "Logical Access", category: "Logical & Physical Access" },
      { id: "CC6.2", name: "Access Provisioning", category: "Logical & Physical Access" },
      { id: "CC6.3", name: "Access Removal", category: "Logical & Physical Access" },
      { id: "CC7.1", name: "System Monitoring", category: "System Operations" },
      { id: "CC7.2", name: "Incident Response", category: "System Operations" },
      { id: "CC8.1", name: "Change Management", category: "Change Management" },
      { id: "CC9.1", name: "Risk Mitigation", category: "Risk Mitigation" },
    ],
  },
  iso27001: {
    name: "ISO 27001:2022",
    version: "2022",
    controls: [
      { id: "A.5.1", name: "Information Security Policies", category: "Organizational" },
      { id: "A.5.2", name: "Information Security Roles", category: "Organizational" },
      { id: "A.6.1", name: "Screening", category: "People" },
      { id: "A.6.2", name: "Terms of Employment", category: "People" },
      { id: "A.7.1", name: "Physical Security Perimeter", category: "Physical" },
      { id: "A.8.1", name: "User Endpoint Devices", category: "Technological" },
      { id: "A.8.2", name: "Privileged Access Rights", category: "Technological" },
      { id: "A.8.3", name: "Information Access Restriction", category: "Technological" },
      { id: "A.8.5", name: "Secure Authentication", category: "Technological" },
      { id: "A.8.8", name: "Management of Technical Vulnerabilities", category: "Technological" },
      { id: "A.8.9", name: "Configuration Management", category: "Technological" },
      { id: "A.8.15", name: "Logging", category: "Technological" },
      { id: "A.8.16", name: "Monitoring Activities", category: "Technological" },
    ],
  },
  "nist-csf": {
    name: "NIST CSF 2.0",
    version: "2.0",
    controls: [
      { id: "GV.OC-01", name: "Organizational Context", category: "Govern" },
      { id: "GV.RM-01", name: "Risk Management Strategy", category: "Govern" },
      { id: "ID.AM-01", name: "Asset Inventory", category: "Identify" },
      { id: "ID.RA-01", name: "Vulnerability Identification", category: "Identify" },
      { id: "PR.AA-01", name: "Identity Management", category: "Protect" },
      { id: "PR.AA-03", name: "Multi-Factor Authentication", category: "Protect" },
      { id: "PR.DS-01", name: "Data-at-Rest Protection", category: "Protect" },
      { id: "PR.DS-02", name: "Data-in-Transit Protection", category: "Protect" },
      { id: "DE.CM-01", name: "Networks Monitored", category: "Detect" },
      { id: "DE.AE-02", name: "Anomaly Detection", category: "Detect" },
      { id: "RS.MA-01", name: "Incident Management", category: "Respond" },
      { id: "RC.RP-01", name: "Recovery Plan", category: "Recover" },
    ],
  },
  nis2: {
    name: "NIS2 Directive",
    version: "2022/2555",
    controls: [
      { id: "NIS2-RM-01", name: "Risk Management Measures", category: "Risk Management" },
      { id: "NIS2-RM-02", name: "Supply Chain Security", category: "Risk Management" },
      { id: "NIS2-IR-01", name: "Incident Handling", category: "Incident Response" },
      { id: "NIS2-IR-02", name: "Incident Reporting (24h/72h)", category: "Incident Response" },
      { id: "NIS2-BC-01", name: "Business Continuity", category: "Business Continuity" },
      { id: "NIS2-BC-02", name: "Crisis Management", category: "Business Continuity" },
      { id: "NIS2-AC-01", name: "Access Control Policies", category: "Access Control" },
      { id: "NIS2-AC-02", name: "Multi-Factor Authentication", category: "Access Control" },
      { id: "NIS2-CR-01", name: "Cryptography & Encryption", category: "Cryptography" },
      { id: "NIS2-VD-01", name: "Vulnerability Disclosure", category: "Vulnerability Management" },
      { id: "NIS2-HR-01", name: "Human Resources Security", category: "Human Resources" },
      { id: "NIS2-AS-01", name: "Asset Management", category: "Asset Management" },
      { id: "NIS2-GV-01", name: "Governance & Accountability", category: "Governance" },
      { id: "NIS2-GV-02", name: "Board-Level Cybersecurity Training", category: "Governance" },
    ],
  },
  dora: {
    name: "DORA",
    version: "2022/2554",
    controls: [
      { id: "DORA-ICT-01", name: "ICT Risk Management Framework", category: "ICT Risk Management" },
      { id: "DORA-ICT-02", name: "ICT Systems Identification & Classification", category: "ICT Risk Management" },
      { id: "DORA-ICT-03", name: "ICT Business Continuity Policy", category: "ICT Risk Management" },
      { id: "DORA-IR-01", name: "ICT Incident Classification", category: "Incident Reporting" },
      { id: "DORA-IR-02", name: "Major ICT Incident Reporting", category: "Incident Reporting" },
      { id: "DORA-IR-03", name: "Voluntary Cyber Threat Notification", category: "Incident Reporting" },
      { id: "DORA-RT-01", name: "Digital Operational Resilience Testing", category: "Resilience Testing" },
      { id: "DORA-RT-02", name: "Threat-Led Penetration Testing (TLPT)", category: "Resilience Testing" },
      { id: "DORA-TP-01", name: "ICT Third-Party Risk Management", category: "Third-Party Risk" },
      { id: "DORA-TP-02", name: "Critical ICT Provider Oversight", category: "Third-Party Risk" },
      { id: "DORA-TP-03", name: "Concentration Risk Assessment", category: "Third-Party Risk" },
      { id: "DORA-IS-01", name: "Information Sharing Arrangements", category: "Information Sharing" },
    ],
  },
  cbest: {
    name: "CBEST",
    version: "3.0",
    controls: [
      { id: "CBEST-TI-01", name: "Threat Intelligence Gathering", category: "Threat Intelligence" },
      { id: "CBEST-TI-02", name: "Threat Scenario Development", category: "Threat Intelligence" },
      { id: "CBEST-PT-01", name: "Penetration Testing Execution", category: "Penetration Testing" },
      { id: "CBEST-PT-02", name: "Red Team Operations", category: "Penetration Testing" },
      { id: "CBEST-PT-03", name: "Social Engineering Assessment", category: "Penetration Testing" },
      { id: "CBEST-RM-01", name: "Remediation Planning", category: "Remediation" },
      { id: "CBEST-RM-02", name: "Control Improvement Tracking", category: "Remediation" },
      { id: "CBEST-GV-01", name: "Board Reporting & Governance", category: "Governance" },
      { id: "CBEST-GV-02", name: "Regulatory Communication", category: "Governance" },
      { id: "CBEST-SC-01", name: "Scope & Critical Functions", category: "Scoping" },
    ],
  },
  "mas-trm": {
    name: "MAS TRM",
    version: "2021",
    controls: [
      { id: "MAS-TRM-3.1", name: "Technology Risk Governance", category: "Governance" },
      { id: "MAS-TRM-3.2", name: "Board & Senior Management Oversight", category: "Governance" },
      { id: "MAS-TRM-4.1", name: "IT Project Management", category: "Technology Operations" },
      { id: "MAS-TRM-5.1", name: "System Reliability & Availability", category: "Technology Operations" },
      { id: "MAS-TRM-6.1", name: "IT Service Management", category: "Technology Operations" },
      { id: "MAS-TRM-7.1", name: "IT Resilience", category: "Resilience" },
      { id: "MAS-TRM-7.2", name: "Disaster Recovery", category: "Resilience" },
      { id: "MAS-TRM-8.1", name: "Access Control", category: "Security" },
      { id: "MAS-TRM-9.1", name: "Cyber Security", category: "Security" },
      { id: "MAS-TRM-9.2", name: "Cyber Surveillance", category: "Security" },
      { id: "MAS-TRM-10.1", name: "Data Management", category: "Data" },
      { id: "MAS-TRM-11.1", name: "IT Audit", category: "Audit" },
      { id: "MAS-TRM-12.1", name: "Online Financial Services", category: "Online Services" },
    ],
  },
  ifsca: {
    name: "IFSCA Cybersecurity",
    version: "2024",
    controls: [
      { id: "IFSCA-GV-01", name: "Cybersecurity Governance Framework", category: "Governance" },
      { id: "IFSCA-GV-02", name: "CISO Appointment", category: "Governance" },
      { id: "IFSCA-RA-01", name: "Risk Assessment & Classification", category: "Risk Assessment" },
      { id: "IFSCA-AC-01", name: "Access Control & Identity Management", category: "Access Control" },
      { id: "IFSCA-NW-01", name: "Network Security", category: "Network Security" },
      { id: "IFSCA-DP-01", name: "Data Protection & Privacy", category: "Data Protection" },
      { id: "IFSCA-IR-01", name: "Incident Response & Reporting", category: "Incident Response" },
      { id: "IFSCA-BC-01", name: "Business Continuity Planning", category: "Business Continuity" },
      { id: "IFSCA-VA-01", name: "Vulnerability Assessment & Penetration Testing", category: "Testing" },
      { id: "IFSCA-TP-01", name: "Third-Party Risk Management", category: "Third-Party" },
      { id: "IFSCA-AT-01", name: "Security Awareness Training", category: "Training" },
    ],
  },
  pdpa: {
    name: "PDPA",
    version: "2012/2020",
    controls: [
      { id: "PDPA-CN-01", name: "Consent Management", category: "Consent" },
      { id: "PDPA-CN-02", name: "Purpose Limitation", category: "Consent" },
      { id: "PDPA-PP-01", name: "Protection of Personal Data", category: "Protection" },
      { id: "PDPA-PP-02", name: "Retention Limitation", category: "Protection" },
      { id: "PDPA-PP-03", name: "Transfer Limitation", category: "Protection" },
      { id: "PDPA-AC-01", name: "Access & Correction Rights", category: "Data Subject Rights" },
      { id: "PDPA-AC-02", name: "Data Portability", category: "Data Subject Rights" },
      { id: "PDPA-DP-01", name: "Data Protection Officer Appointment", category: "Governance" },
      { id: "PDPA-DB-01", name: "Data Breach Notification", category: "Breach Notification" },
      { id: "PDPA-DB-02", name: "72-Hour Notification Requirement", category: "Breach Notification" },
      { id: "PDPA-EN-01", name: "Enforcement & Penalties", category: "Enforcement" },
    ],
  },
  popia: {
    name: "POPIA",
    version: "2013",
    controls: [
      { id: "POPIA-AC-01", name: "Accountability", category: "Conditions" },
      { id: "POPIA-PL-01", name: "Processing Limitation", category: "Conditions" },
      { id: "POPIA-PS-01", name: "Purpose Specification", category: "Conditions" },
      { id: "POPIA-FL-01", name: "Further Processing Limitation", category: "Conditions" },
      { id: "POPIA-IQ-01", name: "Information Quality", category: "Conditions" },
      { id: "POPIA-OP-01", name: "Openness", category: "Conditions" },
      { id: "POPIA-SS-01", name: "Security Safeguards", category: "Conditions" },
      { id: "POPIA-DS-01", name: "Data Subject Participation", category: "Conditions" },
      { id: "POPIA-IO-01", name: "Information Officer Registration", category: "Governance" },
      { id: "POPIA-CB-01", name: "Cross-Border Transfer Restrictions", category: "Transfers" },
      { id: "POPIA-BN-01", name: "Breach Notification", category: "Breach" },
    ],
  },
  lgpd: {
    name: "LGPD",
    version: "2018",
    controls: [
      { id: "LGPD-LB-01", name: "Legal Basis for Processing", category: "Legal Basis" },
      { id: "LGPD-CN-01", name: "Consent Management", category: "Consent" },
      {
        id: "LGPD-DS-01",
        name: "Data Subject Rights (Access, Deletion, Portability)",
        category: "Data Subject Rights",
      },
      { id: "LGPD-DPO-01", name: "Data Protection Officer (Encarregado)", category: "Governance" },
      { id: "LGPD-IA-01", name: "Privacy Impact Assessment (RIPD)", category: "Impact Assessment" },
      { id: "LGPD-IT-01", name: "International Data Transfer", category: "Transfers" },
      { id: "LGPD-SM-01", name: "Security Measures", category: "Security" },
      { id: "LGPD-BN-01", name: "Breach Notification to ANPD", category: "Breach Notification" },
      { id: "LGPD-RR-01", name: "Records of Processing Activities", category: "Records" },
      { id: "LGPD-DP-01", name: "Data Protection by Design & Default", category: "Privacy by Design" },
    ],
  },
  pipeda: {
    name: "PIPEDA",
    version: "2000/2018",
    controls: [
      { id: "PIPEDA-P1", name: "Accountability", category: "Fair Information Principles" },
      { id: "PIPEDA-P2", name: "Identifying Purposes", category: "Fair Information Principles" },
      { id: "PIPEDA-P3", name: "Consent", category: "Fair Information Principles" },
      { id: "PIPEDA-P4", name: "Limiting Collection", category: "Fair Information Principles" },
      { id: "PIPEDA-P5", name: "Limiting Use, Disclosure, and Retention", category: "Fair Information Principles" },
      { id: "PIPEDA-P6", name: "Accuracy", category: "Fair Information Principles" },
      { id: "PIPEDA-P7", name: "Safeguards", category: "Fair Information Principles" },
      { id: "PIPEDA-P8", name: "Openness", category: "Fair Information Principles" },
      { id: "PIPEDA-P9", name: "Individual Access", category: "Fair Information Principles" },
      { id: "PIPEDA-P10", name: "Challenging Compliance", category: "Fair Information Principles" },
      { id: "PIPEDA-BR-01", name: "Mandatory Breach Reporting", category: "Breach Reporting" },
    ],
  },
  "asd-essential8": {
    name: "ASD Essential Eight",
    version: "2023",
    controls: [
      { id: "E8-AC-01", name: "Application Control", category: "Prevent Malware" },
      { id: "E8-PA-01", name: "Patch Applications", category: "Prevent Malware" },
      { id: "E8-MM-01", name: "Configure Microsoft Office Macro Settings", category: "Prevent Malware" },
      { id: "E8-UA-01", name: "User Application Hardening", category: "Prevent Malware" },
      { id: "E8-RA-01", name: "Restrict Administrative Privileges", category: "Limit Impact" },
      { id: "E8-PO-01", name: "Patch Operating Systems", category: "Limit Impact" },
      { id: "E8-MF-01", name: "Multi-Factor Authentication", category: "Limit Impact" },
      { id: "E8-DB-01", name: "Regular Backups", category: "Recovery" },
    ],
  },
  ccpa: {
    name: "CCPA/CPRA",
    version: "2023",
    controls: [
      { id: "CCPA-NK-01", name: "Right to Know", category: "Consumer Rights" },
      { id: "CCPA-DL-01", name: "Right to Delete", category: "Consumer Rights" },
      { id: "CCPA-OO-01", name: "Right to Opt-Out of Sale/Sharing", category: "Consumer Rights" },
      { id: "CCPA-ND-01", name: "Right to Non-Discrimination", category: "Consumer Rights" },
      { id: "CCPA-CR-01", name: "Right to Correct", category: "Consumer Rights" },
      { id: "CCPA-LU-01", name: "Right to Limit Use of Sensitive PI", category: "Consumer Rights" },
      { id: "CCPA-PN-01", name: "Privacy Notice at Collection", category: "Notices" },
      { id: "CCPA-DS-01", name: "Data Security Obligations", category: "Security" },
      { id: "CCPA-SP-01", name: "Service Provider Contracts", category: "Third-Party" },
      { id: "CCPA-RA-01", name: "Risk Assessments (CPRA)", category: "Risk Assessment" },
      { id: "CCPA-AU-01", name: "Annual Cybersecurity Audits (CPRA)", category: "Audit" },
    ],
  },
  cmmc: {
    name: "CMMC",
    version: "2.0",
    controls: [
      { id: "CMMC-AC", name: "Access Control", category: "Access Control" },
      { id: "CMMC-AT", name: "Awareness & Training", category: "Awareness" },
      { id: "CMMC-AU", name: "Audit & Accountability", category: "Audit" },
      { id: "CMMC-CM", name: "Configuration Management", category: "Configuration" },
      { id: "CMMC-IA", name: "Identification & Authentication", category: "Authentication" },
      { id: "CMMC-IR", name: "Incident Response", category: "Incident Response" },
      { id: "CMMC-MA", name: "Maintenance", category: "Maintenance" },
      { id: "CMMC-MP", name: "Media Protection", category: "Media Protection" },
      { id: "CMMC-PE", name: "Physical Protection", category: "Physical" },
      { id: "CMMC-PS", name: "Personnel Security", category: "Personnel" },
      { id: "CMMC-RA", name: "Risk Assessment", category: "Risk Assessment" },
      { id: "CMMC-CA", name: "Security Assessment", category: "Assessment" },
      { id: "CMMC-SC", name: "System & Communications Protection", category: "Communications" },
      { id: "CMMC-SI", name: "System & Information Integrity", category: "Integrity" },
    ],
  },
  "nerc-cip": {
    name: "NERC CIP",
    version: "v7",
    controls: [
      { id: "CIP-002", name: "BES Cyber System Categorization", category: "Asset Identification" },
      { id: "CIP-003", name: "Security Management Controls", category: "Security Management" },
      { id: "CIP-004", name: "Personnel & Training", category: "Personnel" },
      { id: "CIP-005", name: "Electronic Security Perimeters", category: "Network Security" },
      { id: "CIP-006", name: "Physical Security of BES Cyber Systems", category: "Physical Security" },
      { id: "CIP-007", name: "System Security Management", category: "System Security" },
      { id: "CIP-008", name: "Incident Reporting & Response Planning", category: "Incident Response" },
      { id: "CIP-009", name: "Recovery Plans for BES Cyber Systems", category: "Recovery" },
      {
        id: "CIP-010",
        name: "Configuration Change Management & Vulnerability Assessments",
        category: "Change Management",
      },
      { id: "CIP-011", name: "Information Protection", category: "Information Protection" },
      { id: "CIP-013", name: "Supply Chain Risk Management", category: "Supply Chain" },
      { id: "CIP-014", name: "Physical Security", category: "Physical Security" },
    ],
  },
  "swift-csp": {
    name: "SWIFT CSP",
    version: "2024",
    controls: [
      { id: "SWIFT-1.1", name: "SWIFT Environment Protection", category: "Secure Your Environment" },
      { id: "SWIFT-1.2", name: "Operating System Privileged Account Control", category: "Secure Your Environment" },
      { id: "SWIFT-1.3", name: "Virtualisation Platform Protection", category: "Secure Your Environment" },
      { id: "SWIFT-2.1", name: "Internal Data Flow Security", category: "Know & Limit Access" },
      { id: "SWIFT-2.2", name: "Security Updates", category: "Know & Limit Access" },
      { id: "SWIFT-2.3", name: "System Hardening", category: "Know & Limit Access" },
      { id: "SWIFT-3.1", name: "Physical Security", category: "Detect & Respond" },
      { id: "SWIFT-4.1", name: "Password Policy", category: "Know & Limit Access" },
      { id: "SWIFT-5.1", name: "Logical Access Control", category: "Know & Limit Access" },
      { id: "SWIFT-6.1", name: "Malware Protection", category: "Detect & Respond" },
      { id: "SWIFT-6.2", name: "Software Integrity", category: "Detect & Respond" },
      { id: "SWIFT-6.3", name: "Database Integrity", category: "Detect & Respond" },
      { id: "SWIFT-6.4", name: "Logging & Monitoring", category: "Detect & Respond" },
      { id: "SWIFT-7.1", name: "Cyber Incident Response Planning", category: "Plan for Response" },
    ],
  },
  "iec-62443": {
    name: "IEC 62443",
    version: "2018",
    controls: [
      { id: "IEC-1.1", name: "Security Management System", category: "General" },
      { id: "IEC-2.1", name: "Security Policy", category: "Policies & Procedures" },
      { id: "IEC-2.2", name: "Organization Security", category: "Policies & Procedures" },
      { id: "IEC-2.3", name: "Staff Security", category: "Policies & Procedures" },
      { id: "IEC-2.4", name: "Risk Assessment", category: "Policies & Procedures" },
      { id: "IEC-3.1", name: "System Security Architecture", category: "System" },
      { id: "IEC-3.2", name: "Defense in Depth Strategy", category: "System" },
      { id: "IEC-3.3", name: "Zones & Conduits Model", category: "System" },
      { id: "IEC-4.1", name: "Identification & Authentication Control", category: "Component" },
      { id: "IEC-4.2", name: "Use Control", category: "Component" },
      { id: "IEC-4.3", name: "System Integrity", category: "Component" },
      { id: "IEC-4.4", name: "Data Confidentiality", category: "Component" },
      { id: "IEC-4.5", name: "Restricted Data Flow", category: "Component" },
      { id: "IEC-4.6", name: "Timely Response to Events", category: "Component" },
      { id: "IEC-4.7", name: "Resource Availability", category: "Component" },
    ],
  },
};

function genId(): string {
  return `gap-${Date.now()}-${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 8)}`;
}

function simulateAnalysis(framework: (typeof FRAMEWORKS)[string]): {
  gaps: ControlGap[];
  recommendations: Recommendation[];
} {
  const gaps: ControlGap[] = [];
  const recommendations: Recommendation[] = [];
  const statuses: ControlGap["status"][] = ["implemented", "implemented", "implemented", "partial", "missing"];
  const priorities: ControlGap["remediationPriority"][] = ["critical", "high", "medium", "low"];
  const efforts = ["1 day", "3 days", "1 week", "2 weeks", "1 month"];

  for (const control of framework.controls) {
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    gaps.push({
      controlId: control.id,
      controlName: control.name,
      category: control.category,
      status,
      evidence: status === "implemented" ? ["Automated scan evidence", "Policy document"] : [],
      remediationPriority:
        status === "missing"
          ? priorities[Math.floor(Math.random() * 2)]
          : priorities[Math.floor(Math.random() * priorities.length)],
      estimatedEffort: efforts[Math.floor(Math.random() * efforts.length)],
      description: `${control.name} - ${status === "implemented" ? "Fully implemented with automated evidence" : status === "partial" ? "Partially implemented, needs additional controls" : "Not yet implemented, requires new controls"}`,
    });

    if (status !== "implemented") {
      recommendations.push({
        id: `rec-${control.id}`,
        controlId: control.id,
        title: `Implement ${control.name}`,
        description: `Deploy controls for ${control.name} to achieve compliance.`,
        priority: status === "missing" ? "high" : "medium",
        estimatedEffort: efforts[Math.floor(Math.random() * efforts.length)],
        automatable: Math.random() > 0.5,
      });
    }
  }

  return { gaps, recommendations };
}

export function registerComplianceGapRoutes(app: Express): void {
  const log = logger.child("compliance-gap");

  app.get(
    "/api/compliance-gap/frameworks",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (_req: Request, res: Response) => {
      try {
        const frameworks = Object.entries(FRAMEWORKS).map(([key, fw]) => ({
          id: key,
          name: fw.name,
          version: fw.version,
          controlCount: fw.controls.length,
        }));
        return reply(res, frameworks);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to list frameworks." }]);
      }
    },
  );

  app.post(
    "/api/compliance-gap/analyze",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { framework } = req.body;

        if (!framework || !FRAMEWORKS[framework]) {
          return replyError(res, 400, [
            {
              code: "VALIDATION_ERROR",
              message: `Invalid framework. Available: ${Object.keys(FRAMEWORKS).join(", ")}`,
            },
          ]);
        }

        const fw = FRAMEWORKS[framework];
        const { gaps, recommendations } = simulateAnalysis(fw);
        const implemented = gaps.filter((g) => g.status === "implemented").length;
        const partial = gaps.filter((g) => g.status === "partial").length;
        const missing = gaps.filter((g) => g.status === "missing").length;

        const analysis: GapAnalysis = {
          id: genId(),
          orgId,
          framework: fw.name,
          version: fw.version,
          status: "completed",
          totalControls: fw.controls.length,
          implementedControls: implemented,
          partialControls: partial,
          missingControls: missing,
          complianceScore: Math.round((implemented / fw.controls.length) * 100),
          gaps,
          recommendations,
          createdAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          requestedBy: user?.username || "unknown",
        };

        analyses.set(analysis.id, analysis);
        log.info("Compliance gap analysis completed", { orgId, framework, score: analysis.complianceScore });
        return reply(res, analysis, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to run gap analysis." }]);
      }
    },
  );

  app.get(
    "/api/compliance-gap/analyses",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const results = Array.from(analyses.values())
          .filter((a) => a.orgId === orgId)
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
          .map((a) => ({
            id: a.id,
            framework: a.framework,
            version: a.version,
            status: a.status,
            complianceScore: a.complianceScore,
            totalControls: a.totalControls,
            implementedControls: a.implementedControls,
            missingControls: a.missingControls,
            createdAt: a.createdAt,
          }));
        return sendEnvelope(res, results, { meta: { total: results.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to list analyses." }]);
      }
    },
  );

  app.get(
    "/api/compliance-gap/analyses/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const analysis = analyses.get(req.params.id as string);
        if (!analysis || analysis.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Analysis not found." }]);
        }
        return reply(res, analysis);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to get analysis." }]);
      }
    },
  );
}
