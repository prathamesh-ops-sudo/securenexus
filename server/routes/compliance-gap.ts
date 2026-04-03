/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { randomBytes } from "crypto";
import { getComplianceControls, getComplianceControlMappings } from "../storage/compliance";

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
      { id: "A.7.1", name: "Physical Security Perimeters", category: "Physical" },
      { id: "A.8.1", name: "User Endpoint Devices", category: "Technological" },
      { id: "A.8.2", name: "Privileged Access Rights", category: "Technological" },
      { id: "A.8.3", name: "Information Access Restriction", category: "Technological" },
      { id: "A.8.4", name: "Access to Source Code", category: "Technological" },
      { id: "A.8.5", name: "Secure Authentication", category: "Technological" },
      { id: "A.8.6", name: "Capacity Management", category: "Technological" },
      { id: "A.8.7", name: "Protection Against Malware", category: "Technological" },
    ],
  },
  "nist-csf": {
    name: "NIST CSF",
    version: "2.0",
    controls: [
      { id: "GV.OC", name: "Organizational Context", category: "Govern" },
      { id: "GV.RM", name: "Risk Management Strategy", category: "Govern" },
      { id: "GV.RR", name: "Roles, Responsibilities", category: "Govern" },
      { id: "ID.AM", name: "Asset Management", category: "Identify" },
      { id: "ID.RA", name: "Risk Assessment", category: "Identify" },
      { id: "PR.AA", name: "Identity & Access Management", category: "Protect" },
      { id: "PR.AT", name: "Awareness & Training", category: "Protect" },
      { id: "PR.DS", name: "Data Security", category: "Protect" },
      { id: "PR.PS", name: "Platform Security", category: "Protect" },
      { id: "DE.CM", name: "Continuous Monitoring", category: "Detect" },
      { id: "DE.AE", name: "Adverse Event Analysis", category: "Detect" },
      { id: "RS.MA", name: "Incident Management", category: "Respond" },
      { id: "RS.AN", name: "Incident Analysis", category: "Respond" },
      { id: "RC.RP", name: "Incident Recovery Plan Execution", category: "Recover" },
    ],
  },
  hipaa: {
    name: "HIPAA",
    version: "2013",
    controls: [
      { id: "164.308(a)(1)", name: "Security Management Process", category: "Administrative" },
      { id: "164.308(a)(3)", name: "Workforce Security", category: "Administrative" },
      { id: "164.308(a)(4)", name: "Information Access Management", category: "Administrative" },
      { id: "164.308(a)(5)", name: "Security Awareness Training", category: "Administrative" },
      { id: "164.308(a)(6)", name: "Security Incident Procedures", category: "Administrative" },
      { id: "164.308(a)(7)", name: "Contingency Plan", category: "Administrative" },
      { id: "164.310(a)", name: "Facility Access Controls", category: "Physical" },
      { id: "164.310(b)", name: "Workstation Use", category: "Physical" },
      { id: "164.312(a)", name: "Access Control", category: "Technical" },
      { id: "164.312(b)", name: "Audit Controls", category: "Technical" },
      { id: "164.312(c)", name: "Integrity Controls", category: "Technical" },
      { id: "164.312(d)", name: "Person Authentication", category: "Technical" },
      { id: "164.312(e)", name: "Transmission Security", category: "Technical" },
    ],
  },
  gdpr: {
    name: "GDPR",
    version: "2016/2018",
    controls: [
      { id: "GDPR-5", name: "Principles of Processing", category: "Principles" },
      { id: "GDPR-6", name: "Lawful Basis for Processing", category: "Legal Basis" },
      { id: "GDPR-7", name: "Conditions for Consent", category: "Consent" },
      { id: "GDPR-12", name: "Transparent Communication", category: "Data Subject Rights" },
      { id: "GDPR-15", name: "Right of Access", category: "Data Subject Rights" },
      { id: "GDPR-17", name: "Right to Erasure", category: "Data Subject Rights" },
      { id: "GDPR-20", name: "Right to Data Portability", category: "Data Subject Rights" },
      { id: "GDPR-25", name: "Data Protection by Design & Default", category: "Security" },
      { id: "GDPR-30", name: "Records of Processing Activities", category: "Accountability" },
      { id: "GDPR-32", name: "Security of Processing", category: "Security" },
      { id: "GDPR-33", name: "Breach Notification", category: "Breach" },
      { id: "GDPR-35", name: "DPIA", category: "Impact Assessment" },
      { id: "GDPR-37", name: "DPO Designation", category: "Governance" },
    ],
  },
  pci_dss: {
    name: "PCI DSS",
    version: "4.0",
    controls: [
      { id: "PCI-1", name: "Network Security Controls", category: "Network" },
      { id: "PCI-2", name: "Secure Configurations", category: "Configuration" },
      { id: "PCI-3", name: "Protect Stored Account Data", category: "Data Protection" },
      { id: "PCI-4", name: "Protect Cardholder Data in Transit", category: "Encryption" },
      { id: "PCI-5", name: "Protect from Malicious Software", category: "Anti-Malware" },
      { id: "PCI-6", name: "Secure Systems & Software", category: "Development" },
      { id: "PCI-7", name: "Restrict Access by Business Need", category: "Access Control" },
      { id: "PCI-8", name: "Identify Users & Authenticate", category: "Authentication" },
      { id: "PCI-9", name: "Restrict Physical Access", category: "Physical" },
      { id: "PCI-10", name: "Log & Monitor All Access", category: "Logging" },
      { id: "PCI-11", name: "Test Security Regularly", category: "Testing" },
      { id: "PCI-12", name: "Organizational Policies & Programs", category: "Policy" },
    ],
  },
  nis2: {
    name: "NIS2",
    version: "2022",
    controls: [
      { id: "NIS2-RM-01", name: "Risk Management Measures", category: "Risk Management" },
      { id: "NIS2-IR-01", name: "Incident Handling & Reporting", category: "Incident Response" },
      { id: "NIS2-BC-01", name: "Business Continuity", category: "Business Continuity" },
      { id: "NIS2-SC-01", name: "Supply Chain Security", category: "Supply Chain" },
      { id: "NIS2-NS-01", name: "Network & Information System Security", category: "Network Security" },
      { id: "NIS2-VD-01", name: "Vulnerability Disclosure", category: "Vulnerability Management" },
      { id: "NIS2-CR-01", name: "Cryptography & Encryption", category: "Cryptography" },
      { id: "NIS2-HR-01", name: "Human Resources Security", category: "Personnel" },
      { id: "NIS2-AC-01", name: "Access Control & Asset Management", category: "Access Control" },
      { id: "NIS2-MF-01", name: "Multi-Factor Authentication", category: "Authentication" },
    ],
  },
  dora: {
    name: "DORA",
    version: "2022",
    controls: [
      { id: "DORA-ICT-01", name: "ICT Risk Management Framework", category: "ICT Risk" },
      { id: "DORA-ICT-02", name: "ICT Systems, Protocols & Tools", category: "ICT Risk" },
      { id: "DORA-IR-01", name: "ICT-related Incident Management", category: "Incident Management" },
      { id: "DORA-IR-02", name: "Major ICT Incident Classification", category: "Incident Management" },
      { id: "DORA-RT-01", name: "Digital Operational Resilience Testing", category: "Resilience Testing" },
      { id: "DORA-RT-02", name: "Threat-Led Penetration Testing", category: "Resilience Testing" },
      { id: "DORA-TP-01", name: "ICT Third-Party Risk Management", category: "Third-Party" },
      { id: "DORA-TP-02", name: "Contractual Arrangements", category: "Third-Party" },
      { id: "DORA-IS-01", name: "Information Sharing Arrangements", category: "Information Sharing" },
      { id: "DORA-OV-01", name: "Oversight of Critical ICT Providers", category: "Oversight" },
    ],
  },
  cbest: {
    name: "CBEST",
    version: "3.0",
    controls: [
      { id: "CBEST-TI-01", name: "Threat Intelligence Phase", category: "Threat Intelligence" },
      { id: "CBEST-PT-01", name: "Penetration Testing Phase", category: "Penetration Testing" },
      { id: "CBEST-RM-01", name: "Remediation Phase", category: "Remediation" },
      { id: "CBEST-SC-01", name: "Scope Definition", category: "Scoping" },
      { id: "CBEST-GP-01", name: "Governance & Process", category: "Governance" },
      { id: "CBEST-RP-01", name: "Reporting", category: "Reporting" },
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
};

async function analyzeCompliance(
  orgId: string,
  framework: (typeof FRAMEWORKS)[string],
  frameworkKey: string,
): Promise<{ gaps: ControlGap[]; recommendations: Recommendation[] }> {
  const gaps: ControlGap[] = [];
  const recommendations: Recommendation[] = [];

  // Query actual compliance controls and mappings from DB
  const dbControls = await getComplianceControls(frameworkKey);
  const allMappings = await getComplianceControlMappings(orgId);

  // Build lookup: DB control UUID → control text ID
  const controlUuidToTextId = new Map<string, string>();
  for (const c of dbControls) {
    controlUuidToTextId.set(c.id, c.controlId);
  }

  // Build lookup: control text ID → best status + evidence
  const controlStatusMap = new Map<string, { status: string; evidence: string[] }>();
  for (const m of allMappings) {
    const textId = controlUuidToTextId.get(m.controlId);
    if (!textId) continue;

    const existing = controlStatusMap.get(textId);
    const notes = m.evidenceNotes ? [m.evidenceNotes] : [];

    if (!existing) {
      controlStatusMap.set(textId, { status: m.status, evidence: notes });
    } else {
      if (m.status === "implemented" && existing.status !== "implemented") {
        existing.status = "implemented";
      } else if (m.status === "partial" && existing.status === "not_assessed") {
        existing.status = "partial";
      }
      existing.evidence.push(...notes);
    }
  }

  const effortByStatus: Record<string, string> = {
    missing: "2 weeks",
    partial: "1 week",
    implemented: "maintenance",
  };

  for (const control of framework.controls) {
    const mapping = controlStatusMap.get(control.id);

    let status: ControlGap["status"];
    let evidence: string[] = [];

    if (!mapping || mapping.status === "not_assessed") {
      status = "missing";
    } else if (mapping.status === "implemented") {
      status = "implemented";
      evidence = mapping.evidence;
    } else if (mapping.status === "partial") {
      status = "partial";
      evidence = mapping.evidence;
    } else {
      status = "missing";
    }

    const priority: ControlGap["remediationPriority"] =
      status === "missing" ? "high" : status === "partial" ? "medium" : "low";

    gaps.push({
      controlId: control.id,
      controlName: control.name,
      category: control.category,
      status,
      evidence,
      remediationPriority: priority,
      estimatedEffort: effortByStatus[status] || "2 weeks",
      description: `${control.name} — ${
        status === "implemented"
          ? "Implemented with evidence on record"
          : status === "partial"
            ? "Partially implemented — additional controls or evidence needed"
            : "Not yet implemented — requires new controls and evidence"
      }`,
    });

    if (status !== "implemented") {
      recommendations.push({
        id: `rec-${control.id}`,
        controlId: control.id,
        title: `Implement ${control.name}`,
        description: `Deploy controls for ${control.name} to achieve compliance.`,
        priority: status === "missing" ? "high" : "medium",
        estimatedEffort: effortByStatus[status] || "2 weeks",
        automatable: status === "partial",
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

  // Run a fresh compliance gap analysis against real DB data
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
        const { gaps, recommendations } = await analyzeCompliance(orgId, fw, framework);
        const implemented = gaps.filter((g) => g.status === "implemented").length;
        const partial = gaps.filter((g) => g.status === "partial").length;
        const missing = gaps.filter((g) => g.status === "missing").length;

        const analysis = {
          id: `gap-${Date.now()}-${randomBytes(4).toString("hex")}`,
          orgId,
          framework: fw.name,
          frameworkKey: framework,
          version: fw.version,
          status: "completed" as const,
          totalControls: fw.controls.length,
          implementedControls: implemented,
          partialControls: partial,
          missingControls: missing,
          complianceScore: fw.controls.length > 0 ? Math.round((implemented / fw.controls.length) * 100) : 0,
          gaps,
          recommendations,
          createdAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          requestedBy: user?.username || "unknown",
        };

        log.info("Compliance gap analysis completed", { orgId, framework, score: analysis.complianceScore });
        return reply(res, analysis, undefined, 201);
      } catch (error: unknown) {
        log.error("Compliance gap analysis failed", { error });
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to run gap analysis." }]);
      }
    },
  );

  // Get analysis summary for a specific framework (computed from live DB data)
  app.get(
    "/api/compliance-gap/analyses",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const frameworkFilter = req.query.framework as string | undefined;

        const frameworkKeys = frameworkFilter ? [frameworkFilter] : Object.keys(FRAMEWORKS);
        const results = [];

        for (const key of frameworkKeys) {
          const fw = FRAMEWORKS[key];
          if (!fw) continue;

          const { gaps } = await analyzeCompliance(orgId, fw, key);
          const implemented = gaps.filter((g) => g.status === "implemented").length;
          const partial = gaps.filter((g) => g.status === "partial").length;
          const missing = gaps.filter((g) => g.status === "missing").length;

          results.push({
            id: key,
            framework: fw.name,
            frameworkKey: key,
            version: fw.version,
            status: "completed",
            totalControls: fw.controls.length,
            implementedControls: implemented,
            partialControls: partial,
            missingControls: missing,
            complianceScore: fw.controls.length > 0 ? Math.round((implemented / fw.controls.length) * 100) : 0,
          });
        }

        return sendEnvelope(res, results, { meta: { total: results.length } });
      } catch (error: unknown) {
        log.error("Failed to list analyses", { error });
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to list analyses." }]);
      }
    },
  );

  // Get detailed analysis for a specific framework (computed from live DB data)
  app.get(
    "/api/compliance-gap/analyses/:framework",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const frameworkKey = String(req.params.framework);
        const fw = FRAMEWORKS[frameworkKey];
        if (!fw) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Framework not found." }]);
        }

        const { gaps, recommendations } = await analyzeCompliance(orgId, fw, frameworkKey);
        const implemented = gaps.filter((g) => g.status === "implemented").length;
        const partial = gaps.filter((g) => g.status === "partial").length;
        const missing = gaps.filter((g) => g.status === "missing").length;

        return reply(res, {
          framework: fw.name,
          frameworkKey,
          version: fw.version,
          totalControls: fw.controls.length,
          implementedControls: implemented,
          partialControls: partial,
          missingControls: missing,
          complianceScore: fw.controls.length > 0 ? Math.round((implemented / fw.controls.length) * 100) : 0,
          gaps,
          recommendations,
          analyzedAt: new Date().toISOString(),
        });
      } catch (error: unknown) {
        log.error("Failed to get analysis", { error });
        return replyError(res, 500, [{ code: "GAP_ERROR", message: "Failed to get analysis." }]);
      }
    },
  );
}
