import { randomBytes } from "crypto";
import { storage } from "./storage";
import { logger } from "./logger";

const log = logger.child("trust-center");

export interface ComplianceFramework {
  id: string;
  name: string;
  shortName: string;
  description: string;
  status: "certified" | "in_progress" | "planned" | "not_applicable";
  certificationDate: string | null;
  expirationDate: string | null;
  auditor: string | null;
  scopeDescription: string;
  controls: FrameworkControl[];
}

export interface FrameworkControl {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  description: string;
  status: "implemented" | "partial" | "planned" | "not_applicable";
  evidence: string[];
  mappings: ControlMapping[];
}

export interface ControlMapping {
  sourceFramework: string;
  sourceControlId: string;
  targetFramework: string;
  targetControlId: string;
  relationship: "equivalent" | "partial" | "related";
}

export interface SecurityArtifact {
  id: string;
  orgId: string;
  category: ArtifactCategory;
  title: string;
  description: string;
  version: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  uploadedBy: string;
  uploadedAt: string;
  lastReviewedAt: string | null;
  nextReviewDue: string | null;
  freshnessSlaDays: number;
  status: "current" | "expiring_soon" | "expired" | "under_review";
  accessLevel: "public" | "nda_required" | "customer_only" | "internal";
  downloadCount: number;
  tags: string[];
}

export type ArtifactCategory =
  | "soc2_report"
  | "iso27001_cert"
  | "pentest_report"
  | "security_architecture"
  | "incident_response_plan"
  | "privacy_policy"
  | "data_processing_agreement"
  | "business_continuity_plan"
  | "vulnerability_disclosure"
  | "encryption_policy"
  | "access_control_policy"
  | "vendor_security_assessment"
  | "gdpr_dpia"
  | "hipaa_baa"
  | "other";

export interface DownloadAuditEntry {
  id: string;
  orgId: string;
  artifactId: string;
  artifactTitle: string;
  downloadedBy: string;
  downloadedByEmail: string;
  downloadedAt: string;
  ipAddress: string;
  userAgent: string;
  accessLevel: string;
}

export interface FreshnessAlert {
  artifactId: string;
  artifactTitle: string;
  category: ArtifactCategory;
  status: "current" | "expiring_soon" | "expired";
  lastReviewedAt: string | null;
  nextReviewDue: string | null;
  daysUntilExpiry: number | null;
  freshnessSlaDays: number;
}

const frameworkCatalog: ComplianceFramework[] = [
  {
    id: "soc2-type2",
    name: "SOC 2 Type II",
    shortName: "SOC 2",
    description:
      "Service Organization Control 2 Type II report covering security, availability, and confidentiality trust service criteria.",
    status: "certified",
    certificationDate: "2025-09-15",
    expirationDate: "2026-09-14",
    auditor: "Deloitte LLP",
    scopeDescription:
      "SecureNexus SaaS platform including data processing, storage, AI analytics, and incident response subsystems.",
    controls: [
      {
        id: "cc1.1",
        frameworkId: "soc2-type2",
        controlId: "CC1.1",
        title: "COSO Principle 1: Integrity and Ethical Values",
        description: "The entity demonstrates a commitment to integrity and ethical values.",
        status: "implemented",
        evidence: ["Code of conduct", "Ethics training records", "Whistleblower policy"],
        mappings: [
          {
            sourceFramework: "SOC 2",
            sourceControlId: "CC1.1",
            targetFramework: "ISO 27001",
            targetControlId: "A.5.1",
            relationship: "related",
          },
        ],
      },
      {
        id: "cc6.1",
        frameworkId: "soc2-type2",
        controlId: "CC6.1",
        title: "Logical and Physical Access Controls",
        description:
          "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
        status: "implemented",
        evidence: ["IAM policies", "MFA enforcement logs", "Access review records"],
        mappings: [
          {
            sourceFramework: "SOC 2",
            sourceControlId: "CC6.1",
            targetFramework: "ISO 27001",
            targetControlId: "A.9.1",
            relationship: "equivalent",
          },
          {
            sourceFramework: "SOC 2",
            sourceControlId: "CC6.1",
            targetFramework: "GDPR",
            targetControlId: "Art.32",
            relationship: "partial",
          },
        ],
      },
      {
        id: "cc7.2",
        frameworkId: "soc2-type2",
        controlId: "CC7.2",
        title: "System Monitoring",
        description: "The entity monitors system components and the operation of those components for anomalies.",
        status: "implemented",
        evidence: ["SIEM configuration", "Alert rules", "Monitoring dashboards"],
        mappings: [
          {
            sourceFramework: "SOC 2",
            sourceControlId: "CC7.2",
            targetFramework: "ISO 27001",
            targetControlId: "A.12.4",
            relationship: "equivalent",
          },
        ],
      },
    ],
  },
  {
    id: "iso27001",
    name: "ISO/IEC 27001:2022",
    shortName: "ISO 27001",
    description:
      "Information security management system (ISMS) certification demonstrating systematic approach to managing sensitive information.",
    status: "certified",
    certificationDate: "2025-06-01",
    expirationDate: "2028-05-31",
    auditor: "BSI Group",
    scopeDescription:
      "Information security management for SecureNexus cloud-hosted SaaS platform and supporting infrastructure.",
    controls: [
      {
        id: "a5.1",
        frameworkId: "iso27001",
        controlId: "A.5.1",
        title: "Policies for Information Security",
        description:
          "A set of policies for information security shall be defined, approved by management, and communicated.",
        status: "implemented",
        evidence: ["Information security policy", "Policy review records", "Management approval"],
        mappings: [
          {
            sourceFramework: "ISO 27001",
            sourceControlId: "A.5.1",
            targetFramework: "SOC 2",
            targetControlId: "CC1.1",
            relationship: "related",
          },
        ],
      },
      {
        id: "a9.1",
        frameworkId: "iso27001",
        controlId: "A.9.1",
        title: "Access Control Policy",
        description:
          "An access control policy shall be established, documented and reviewed based on business and security requirements.",
        status: "implemented",
        evidence: ["RBAC configuration", "Access control policy", "Periodic access reviews"],
        mappings: [
          {
            sourceFramework: "ISO 27001",
            sourceControlId: "A.9.1",
            targetFramework: "SOC 2",
            targetControlId: "CC6.1",
            relationship: "equivalent",
          },
        ],
      },
    ],
  },
  {
    id: "gdpr",
    name: "General Data Protection Regulation",
    shortName: "GDPR",
    description:
      "EU regulation on data protection and privacy for individuals within the European Union and the European Economic Area.",
    status: "certified",
    certificationDate: "2025-01-15",
    expirationDate: null,
    auditor: "Internal DPO + TrustArc",
    scopeDescription:
      "All personal data processing activities within SecureNexus platform including log analysis, threat intelligence, and user management.",
    controls: [
      {
        id: "gdpr-art5",
        frameworkId: "gdpr",
        controlId: "Art.5",
        title: "Principles relating to processing of personal data",
        description: "Personal data shall be processed lawfully, fairly and in a transparent manner.",
        status: "implemented",
        evidence: ["Privacy policy", "Data processing records", "Consent management"],
        mappings: [],
      },
      {
        id: "gdpr-art32",
        frameworkId: "gdpr",
        controlId: "Art.32",
        title: "Security of Processing",
        description: "Appropriate technical and organisational measures to ensure security appropriate to the risk.",
        status: "implemented",
        evidence: ["Encryption at rest/transit", "Access controls", "Regular security testing"],
        mappings: [
          {
            sourceFramework: "GDPR",
            sourceControlId: "Art.32",
            targetFramework: "SOC 2",
            targetControlId: "CC6.1",
            relationship: "partial",
          },
        ],
      },
    ],
  },
  {
    id: "hipaa",
    name: "Health Insurance Portability and Accountability Act",
    shortName: "HIPAA",
    description: "US legislation providing data privacy and security provisions for safeguarding medical information.",
    status: "in_progress",
    certificationDate: null,
    expirationDate: null,
    auditor: null,
    scopeDescription: "Healthcare customer deployments processing protected health information (PHI).",
    controls: [
      {
        id: "hipaa-164.312a",
        frameworkId: "hipaa",
        controlId: "164.312(a)",
        title: "Access Control",
        description:
          "Implement technical policies and procedures for electronic information systems that maintain ePHI.",
        status: "partial",
        evidence: ["Access control policies", "Unique user identification"],
        mappings: [
          {
            sourceFramework: "HIPAA",
            sourceControlId: "164.312(a)",
            targetFramework: "ISO 27001",
            targetControlId: "A.9.1",
            relationship: "related",
          },
        ],
      },
    ],
  },
  {
    id: "ccpa",
    name: "California Consumer Privacy Act",
    shortName: "CCPA",
    description: "California state statute enhancing privacy rights and consumer protection for California residents.",
    status: "certified",
    certificationDate: "2025-03-01",
    expirationDate: null,
    auditor: "Internal Privacy Team",
    scopeDescription: "All personal information of California residents processed by SecureNexus.",
    controls: [
      {
        id: "ccpa-1798.100",
        frameworkId: "ccpa",
        controlId: "1798.100",
        title: "Right to Know",
        description: "Consumers have the right to request disclosure of personal information collected.",
        status: "implemented",
        evidence: ["DSAR workflow", "Privacy portal", "Data inventory"],
        mappings: [
          {
            sourceFramework: "CCPA",
            sourceControlId: "1798.100",
            targetFramework: "GDPR",
            targetControlId: "Art.15",
            relationship: "equivalent",
          },
        ],
      },
    ],
  },
  {
    id: "dpdp",
    name: "Digital Personal Data Protection Act (India)",
    shortName: "DPDP",
    description: "India's comprehensive data protection legislation governing digital personal data processing.",
    status: "in_progress",
    certificationDate: null,
    expirationDate: null,
    auditor: null,
    scopeDescription: "Processing of digital personal data of Indian residents within SecureNexus platform.",
    controls: [],
  },
];

const artifactStore = new Map<string, SecurityArtifact[]>();
const downloadLog = new Map<string, DownloadAuditEntry[]>();

function getOrgArtifacts(orgId: string): SecurityArtifact[] {
  if (!artifactStore.has(orgId)) {
    artifactStore.set(orgId, seedDefaultArtifacts(orgId));
  }
  return artifactStore.get(orgId)!;
}

function seedDefaultArtifacts(orgId: string): SecurityArtifact[] {
  const now = new Date();
  const threeMonthsAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  const sixMonthsAgo = new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000);
  const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const ninetyDaysFromNow = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  const sixMonthsFromNow = new Date(now.getTime() + 180 * 24 * 60 * 60 * 1000);

  return [
    {
      id: `${orgId}-soc2-report`,
      orgId,
      category: "soc2_report",
      title: "SOC 2 Type II Report (2025)",
      description:
        "Full SOC 2 Type II audit report covering Security, Availability, and Confidentiality trust service criteria.",
      version: "2025.1",
      fileName: "SecureNexus_SOC2_TypeII_2025.pdf",
      fileSize: 2_450_000,
      mimeType: "application/pdf",
      uploadedBy: "compliance-team",
      uploadedAt: threeMonthsAgo.toISOString(),
      lastReviewedAt: threeMonthsAgo.toISOString(),
      nextReviewDue: sixMonthsFromNow.toISOString(),
      freshnessSlaDays: 365,
      status: "current",
      accessLevel: "nda_required",
      downloadCount: 47,
      tags: ["soc2", "audit", "type-ii", "2025"],
    },
    {
      id: `${orgId}-iso27001-cert`,
      orgId,
      category: "iso27001_cert",
      title: "ISO 27001:2022 Certificate",
      description: "ISO/IEC 27001:2022 Information Security Management System certificate issued by BSI Group.",
      version: "2025.1",
      fileName: "SecureNexus_ISO27001_Certificate.pdf",
      fileSize: 850_000,
      mimeType: "application/pdf",
      uploadedBy: "compliance-team",
      uploadedAt: sixMonthsAgo.toISOString(),
      lastReviewedAt: threeMonthsAgo.toISOString(),
      nextReviewDue: ninetyDaysFromNow.toISOString(),
      freshnessSlaDays: 365,
      status: "current",
      accessLevel: "public",
      downloadCount: 123,
      tags: ["iso27001", "certificate", "isms"],
    },
    {
      id: `${orgId}-pentest-2025q4`,
      orgId,
      category: "pentest_report",
      title: "Penetration Test Report (2025 Q4)",
      description:
        "External penetration test conducted by NCC Group covering web application, API, and infrastructure testing.",
      version: "2025-Q4",
      fileName: "SecureNexus_PenTest_2025Q4.pdf",
      fileSize: 3_200_000,
      mimeType: "application/pdf",
      uploadedBy: "security-team",
      uploadedAt: threeMonthsAgo.toISOString(),
      lastReviewedAt: threeMonthsAgo.toISOString(),
      nextReviewDue: thirtyDaysFromNow.toISOString(),
      freshnessSlaDays: 90,
      status: "expiring_soon",
      accessLevel: "nda_required",
      downloadCount: 18,
      tags: ["pentest", "ncc-group", "2025", "q4"],
    },
    {
      id: `${orgId}-security-arch`,
      orgId,
      category: "security_architecture",
      title: "Security Architecture Overview",
      description:
        "High-level security architecture document covering network segmentation, encryption, access controls, and data flow.",
      version: "3.2",
      fileName: "SecureNexus_Security_Architecture_v3.2.pdf",
      fileSize: 1_800_000,
      mimeType: "application/pdf",
      uploadedBy: "engineering-team",
      uploadedAt: sixMonthsAgo.toISOString(),
      lastReviewedAt: sixMonthsAgo.toISOString(),
      nextReviewDue: thirtyDaysFromNow.toISOString(),
      freshnessSlaDays: 180,
      status: "expiring_soon",
      accessLevel: "customer_only",
      downloadCount: 35,
      tags: ["architecture", "network", "encryption", "infrastructure"],
    },
    {
      id: `${orgId}-ir-plan`,
      orgId,
      category: "incident_response_plan",
      title: "Incident Response Plan",
      description:
        "Comprehensive incident response plan including escalation procedures, communication templates, and recovery playbooks.",
      version: "2.1",
      fileName: "SecureNexus_IR_Plan_v2.1.pdf",
      fileSize: 1_200_000,
      mimeType: "application/pdf",
      uploadedBy: "security-team",
      uploadedAt: oneYearAgo.toISOString(),
      lastReviewedAt: oneYearAgo.toISOString(),
      nextReviewDue: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      freshnessSlaDays: 365,
      status: "expired",
      accessLevel: "customer_only",
      downloadCount: 22,
      tags: ["incident-response", "playbook", "escalation"],
    },
    {
      id: `${orgId}-privacy-policy`,
      orgId,
      category: "privacy_policy",
      title: "Privacy Policy",
      description: "Public privacy policy covering data collection, processing, retention, and subject rights.",
      version: "4.0",
      fileName: "SecureNexus_Privacy_Policy_v4.0.pdf",
      fileSize: 450_000,
      mimeType: "application/pdf",
      uploadedBy: "legal-team",
      uploadedAt: threeMonthsAgo.toISOString(),
      lastReviewedAt: threeMonthsAgo.toISOString(),
      nextReviewDue: ninetyDaysFromNow.toISOString(),
      freshnessSlaDays: 180,
      status: "current",
      accessLevel: "public",
      downloadCount: 89,
      tags: ["privacy", "gdpr", "ccpa", "policy"],
    },
    {
      id: `${orgId}-dpa`,
      orgId,
      category: "data_processing_agreement",
      title: "Data Processing Agreement (DPA)",
      description:
        "Standard data processing agreement template for customers requiring GDPR-compliant data processing terms.",
      version: "2.0",
      fileName: "SecureNexus_DPA_v2.0.pdf",
      fileSize: 380_000,
      mimeType: "application/pdf",
      uploadedBy: "legal-team",
      uploadedAt: sixMonthsAgo.toISOString(),
      lastReviewedAt: threeMonthsAgo.toISOString(),
      nextReviewDue: sixMonthsFromNow.toISOString(),
      freshnessSlaDays: 365,
      status: "current",
      accessLevel: "customer_only",
      downloadCount: 56,
      tags: ["dpa", "gdpr", "data-processing", "legal"],
    },
    {
      id: `${orgId}-bcp`,
      orgId,
      category: "business_continuity_plan",
      title: "Business Continuity & Disaster Recovery Plan",
      description:
        "Business continuity plan covering RTO/RPO targets, failover procedures, and disaster recovery testing results.",
      version: "1.5",
      fileName: "SecureNexus_BCP_DR_v1.5.pdf",
      fileSize: 1_600_000,
      mimeType: "application/pdf",
      uploadedBy: "operations-team",
      uploadedAt: sixMonthsAgo.toISOString(),
      lastReviewedAt: sixMonthsAgo.toISOString(),
      nextReviewDue: ninetyDaysFromNow.toISOString(),
      freshnessSlaDays: 180,
      status: "current",
      accessLevel: "nda_required",
      downloadCount: 12,
      tags: ["bcp", "disaster-recovery", "rto", "rpo"],
    },
  ];
}

export function getAllFrameworks(): ComplianceFramework[] {
  return frameworkCatalog;
}

export function getFrameworkById(frameworkId: string): ComplianceFramework | undefined {
  return frameworkCatalog.find((f) => f.id === frameworkId);
}

export function getAllControlMappings(): ControlMapping[] {
  const mappings: ControlMapping[] = [];
  for (const framework of frameworkCatalog) {
    for (const control of framework.controls) {
      for (const mapping of control.mappings) {
        mappings.push(mapping);
      }
    }
  }
  return mappings;
}

export function getControlMappingsForFramework(frameworkId: string): ControlMapping[] {
  const framework = frameworkCatalog.find((f) => f.id === frameworkId);
  if (!framework) return [];
  const mappings: ControlMapping[] = [];
  for (const control of framework.controls) {
    for (const mapping of control.mappings) {
      mappings.push(mapping);
    }
  }
  return mappings;
}

export function getArtifacts(orgId: string, category?: ArtifactCategory): SecurityArtifact[] {
  const artifacts = getOrgArtifacts(orgId);
  if (category) return artifacts.filter((a) => a.category === category);
  return artifacts;
}

export function getArtifactById(orgId: string, artifactId: string): SecurityArtifact | undefined {
  return getOrgArtifacts(orgId).find((a) => a.id === artifactId);
}

const VALID_CATEGORIES: ArtifactCategory[] = [
  "soc2_report",
  "iso27001_cert",
  "pentest_report",
  "security_architecture",
  "incident_response_plan",
  "privacy_policy",
  "data_processing_agreement",
  "business_continuity_plan",
  "vulnerability_disclosure",
  "encryption_policy",
  "access_control_policy",
  "vendor_security_assessment",
  "gdpr_dpia",
  "hipaa_baa",
  "other",
];

export function createArtifact(
  orgId: string,
  data: {
    category: string;
    title: string;
    description: string;
    version: string;
    fileName: string;
    fileSize: number;
    mimeType: string;
    uploadedBy: string;
    freshnessSlaDays: number;
    accessLevel: string;
    tags: string[];
  },
): SecurityArtifact | { error: string } {
  if (!VALID_CATEGORIES.includes(data.category as ArtifactCategory)) {
    return { error: `Invalid category: ${data.category}` };
  }
  const validAccessLevels = ["public", "nda_required", "customer_only", "internal"];
  if (!validAccessLevels.includes(data.accessLevel)) {
    return { error: `Invalid access level: ${data.accessLevel}` };
  }
  if (data.freshnessSlaDays < 1 || data.freshnessSlaDays > 730) {
    return { error: "freshnessSlaDays must be between 1 and 730" };
  }
  if (!data.title || data.title.length > 200) {
    return { error: "Title is required and must be under 200 characters" };
  }

  const now = new Date();
  const nextReviewDue = new Date(now.getTime() + data.freshnessSlaDays * 24 * 60 * 60 * 1000);

  const artifact: SecurityArtifact = {
    id: `${orgId}-${Date.now()}-${randomBytes(4).toString("hex")}`,
    orgId,
    category: data.category as ArtifactCategory,
    title: data.title,
    description: data.description,
    version: data.version,
    fileName: data.fileName,
    fileSize: data.fileSize,
    mimeType: data.mimeType,
    uploadedBy: data.uploadedBy,
    uploadedAt: now.toISOString(),
    lastReviewedAt: now.toISOString(),
    nextReviewDue: nextReviewDue.toISOString(),
    freshnessSlaDays: data.freshnessSlaDays,
    status: "current",
    accessLevel: data.accessLevel as SecurityArtifact["accessLevel"],
    downloadCount: 0,
    tags: data.tags,
  };

  const artifacts = getOrgArtifacts(orgId);
  artifacts.push(artifact);
  log.info("Artifact created", { orgId, artifactId: artifact.id, category: artifact.category });
  return artifact;
}

export function updateArtifact(
  orgId: string,
  artifactId: string,
  updates: Partial<
    Pick<SecurityArtifact, "title" | "description" | "version" | "accessLevel" | "freshnessSlaDays" | "tags" | "status">
  >,
): SecurityArtifact | null {
  const artifacts = getOrgArtifacts(orgId);
  const idx = artifacts.findIndex((a) => a.id === artifactId);
  if (idx === -1) return null;

  const artifact = artifacts[idx];
  if (updates.title !== undefined) artifact.title = updates.title;
  if (updates.description !== undefined) artifact.description = updates.description;
  if (updates.version !== undefined) artifact.version = updates.version;
  if (updates.accessLevel !== undefined) artifact.accessLevel = updates.accessLevel as SecurityArtifact["accessLevel"];
  if (updates.tags !== undefined) artifact.tags = updates.tags;
  if (updates.status !== undefined) artifact.status = updates.status;
  if (updates.freshnessSlaDays !== undefined) {
    artifact.freshnessSlaDays = updates.freshnessSlaDays;
    const now = new Date();
    artifact.nextReviewDue = new Date(now.getTime() + updates.freshnessSlaDays * 24 * 60 * 60 * 1000).toISOString();
  }

  artifacts[idx] = artifact;
  log.info("Artifact updated", { orgId, artifactId });
  return artifact;
}

export function markArtifactReviewed(orgId: string, artifactId: string): SecurityArtifact | null {
  const artifacts = getOrgArtifacts(orgId);
  const idx = artifacts.findIndex((a) => a.id === artifactId);
  if (idx === -1) return null;

  const artifact = artifacts[idx];
  const now = new Date();
  artifact.lastReviewedAt = now.toISOString();
  artifact.nextReviewDue = new Date(now.getTime() + artifact.freshnessSlaDays * 24 * 60 * 60 * 1000).toISOString();
  artifact.status = "current";
  artifacts[idx] = artifact;
  log.info("Artifact marked reviewed", { orgId, artifactId });
  return artifact;
}

export function deleteArtifact(orgId: string, artifactId: string): boolean {
  const artifacts = getOrgArtifacts(orgId);
  const idx = artifacts.findIndex((a) => a.id === artifactId);
  if (idx === -1) return false;
  artifacts.splice(idx, 1);
  log.info("Artifact deleted", { orgId, artifactId });
  return true;
}

export function recordDownload(
  orgId: string,
  artifactId: string,
  downloadedBy: string,
  downloadedByEmail: string,
  ipAddress: string,
  userAgent: string,
): DownloadAuditEntry | null {
  const artifact = getArtifactById(orgId, artifactId);
  if (!artifact) return null;

  artifact.downloadCount += 1;

  const entry: DownloadAuditEntry = {
    id: `dl-${Date.now()}-${randomBytes(4).toString("hex")}`,
    orgId,
    artifactId,
    artifactTitle: artifact.title,
    downloadedBy,
    downloadedByEmail,
    downloadedAt: new Date().toISOString(),
    ipAddress,
    userAgent,
    accessLevel: artifact.accessLevel,
  };

  if (!downloadLog.has(orgId)) {
    downloadLog.set(orgId, []);
  }
  downloadLog.get(orgId)!.push(entry);

  log.info("Artifact download recorded", { orgId, artifactId, downloadedBy });

  storage
    .createAuditLog({
      orgId,
      userId: downloadedBy,
      userName: downloadedByEmail,
      action: "trust_center_artifact_downloaded",
      resourceType: "security_artifact",
      resourceId: artifactId,
      details: { artifactTitle: artifact.title, accessLevel: artifact.accessLevel },
    })
    .catch((err) => log.warn("Failed to log artifact download audit", { error: String(err) }));

  return entry;
}

export function getDownloadAuditLog(orgId: string, limit: number = 100): DownloadAuditEntry[] {
  const entries = downloadLog.get(orgId) || [];
  return entries.slice(-limit).reverse();
}

export function getFreshnessAlerts(orgId: string): FreshnessAlert[] {
  const artifacts = getOrgArtifacts(orgId);
  const now = new Date();

  return artifacts.map((artifact) => {
    let daysUntilExpiry: number | null = null;
    let status: FreshnessAlert["status"] = "current";

    if (artifact.nextReviewDue) {
      const reviewDue = new Date(artifact.nextReviewDue);
      daysUntilExpiry = Math.ceil((reviewDue.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

      if (daysUntilExpiry <= 0) {
        status = "expired";
      } else if (daysUntilExpiry <= 30) {
        status = "expiring_soon";
      } else {
        status = "current";
      }
    }

    artifact.status = status;

    return {
      artifactId: artifact.id,
      artifactTitle: artifact.title,
      category: artifact.category,
      status,
      lastReviewedAt: artifact.lastReviewedAt,
      nextReviewDue: artifact.nextReviewDue,
      daysUntilExpiry,
      freshnessSlaDays: artifact.freshnessSlaDays,
    };
  });
}

export function getTrustCenterSummary(orgId: string): {
  totalFrameworks: number;
  certifiedFrameworks: number;
  inProgressFrameworks: number;
  totalArtifacts: number;
  currentArtifacts: number;
  expiringSoonArtifacts: number;
  expiredArtifacts: number;
  totalDownloads: number;
  totalControlMappings: number;
} {
  const frameworks = frameworkCatalog;
  const artifacts = getOrgArtifacts(orgId);
  const freshness = getFreshnessAlerts(orgId);

  return {
    totalFrameworks: frameworks.length,
    certifiedFrameworks: frameworks.filter((f) => f.status === "certified").length,
    inProgressFrameworks: frameworks.filter((f) => f.status === "in_progress").length,
    totalArtifacts: artifacts.length,
    currentArtifacts: freshness.filter((f) => f.status === "current").length,
    expiringSoonArtifacts: freshness.filter((f) => f.status === "expiring_soon").length,
    expiredArtifacts: freshness.filter((f) => f.status === "expired").length,
    totalDownloads: artifacts.reduce((sum, a) => sum + a.downloadCount, 0),
    totalControlMappings: getAllControlMappings().length,
  };
}
