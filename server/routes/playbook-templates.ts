import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

interface PlaybookTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  author: string;
  version: string;
  tags: string[];
  steps: TemplateStep[];
  usageCount: number;
  rating: number;
  isPublished: boolean;
  orgId: string | null;
  createdAt: string;
  updatedAt: string;
}

interface TemplateStep {
  id: string;
  order: number;
  name: string;
  type: "manual" | "automated" | "approval" | "notification";
  description: string;
  config: Record<string, unknown>;
}

const templates = new Map<string, PlaybookTemplate>();

// 23.3: Template rating tracking
interface TemplateRating {
  templateId: string;
  orgId: string;
  userId: string;
  rating: number;
  comment: string;
  createdAt: string;
}

// 23.5: Template version tracking
interface TemplateVersionInfo {
  templateId: string;
  version: string;
  changelog: string;
  publishedAt: string;
}

const templateRatings = new Map<string, TemplateRating[]>();
const templateVersionHistory = new Map<string, TemplateVersionInfo[]>();
const deployedTemplates = new Map<
  string,
  { orgId: string; templateId: string; templateVersion: string; deployedAt: string; playbookName: string }[]
>();

const CATALOG_TEMPLATES: Omit<PlaybookTemplate, "id" | "orgId" | "usageCount" | "createdAt" | "updatedAt">[] = [
  {
    name: "Ransomware Response",
    description: "Step-by-step ransomware containment and eradication playbook following NIST guidelines.",
    category: "Incident Response",
    severity: "critical",
    author: "SecureNexus",
    version: "2.1",
    tags: ["ransomware", "containment", "eradication", "NIST"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Isolate affected systems",
        type: "automated",
        description: "Network isolation via EDR",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Preserve forensic evidence",
        type: "manual",
        description: "Capture memory dumps and disk images",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Identify ransomware variant",
        type: "automated",
        description: "Hash analysis against TI feeds",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Notify stakeholders",
        type: "notification",
        description: "Alert CISO and legal team",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Approve restoration plan",
        type: "approval",
        description: "Commander approves restore from backup",
        config: {},
      },
    ],
    rating: 4.8,
    isPublished: true,
  },
  {
    name: "Phishing Investigation",
    description: "Automated phishing email triage, sender analysis, and user notification workflow.",
    category: "Email Security",
    severity: "medium",
    author: "SecureNexus",
    version: "1.5",
    tags: ["phishing", "email", "triage", "user-notification"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Extract email headers",
        type: "automated",
        description: "Parse DKIM, SPF, DMARC",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Analyze URLs and attachments",
        type: "automated",
        description: "Sandbox detonation",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Check sender reputation",
        type: "automated",
        description: "TI lookup on sender domain",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Quarantine email",
        type: "automated",
        description: "Remove from all inboxes",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Notify affected users",
        type: "notification",
        description: "Send awareness notification",
        config: {},
      },
    ],
    rating: 4.6,
    isPublished: true,
  },
  {
    name: "Cloud Misconfiguration Remediation",
    description: "Detect and remediate common cloud misconfigurations across AWS, Azure, and GCP.",
    category: "Cloud Security",
    severity: "high",
    author: "SecureNexus",
    version: "1.3",
    tags: ["cloud", "CSPM", "remediation", "AWS", "Azure", "GCP"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Identify misconfiguration",
        type: "automated",
        description: "CSPM scan results",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Assess blast radius",
        type: "automated",
        description: "Impact analysis",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Generate remediation plan",
        type: "automated",
        description: "IaC fix generation",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Approve remediation",
        type: "approval",
        description: "DevOps lead approval",
        config: {},
      },
      { id: "s5", order: 5, name: "Apply fix", type: "automated", description: "Terraform apply", config: {} },
    ],
    rating: 4.4,
    isPublished: true,
  },
  {
    name: "Insider Threat Detection",
    description: "Behavioral analysis and response for potential insider threat indicators.",
    category: "Insider Threat",
    severity: "high",
    author: "SecureNexus",
    version: "1.0",
    tags: ["insider-threat", "UEBA", "behavioral-analytics"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Aggregate user activity",
        type: "automated",
        description: "Pull logs from IAM, DLP, endpoint",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Behavioral baseline comparison",
        type: "automated",
        description: "Compare against 30-day baseline",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Risk scoring",
        type: "automated",
        description: "Calculate composite risk score",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "HR/Legal notification",
        type: "approval",
        description: "Escalate to HR if score > threshold",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Access restriction",
        type: "manual",
        description: "Limit access pending investigation",
        config: {},
      },
    ],
    rating: 4.2,
    isPublished: true,
  },
  {
    name: "Vulnerability Triage",
    description: "Prioritize and assign vulnerabilities based on exploitability and business context.",
    category: "Vulnerability Management",
    severity: "medium",
    author: "SecureNexus",
    version: "1.8",
    tags: ["vulnerability", "triage", "prioritization", "CVSS"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Enrich with CVSS and EPSS",
        type: "automated",
        description: "Pull scores from NVD",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Map to business assets",
        type: "automated",
        description: "CMDB correlation",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Calculate risk priority",
        type: "automated",
        description: "Business-context scoring",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Assign to remediation team",
        type: "automated",
        description: "Route to asset owner",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Verify remediation",
        type: "manual",
        description: "Rescan and confirm fix",
        config: {},
      },
    ],
    rating: 4.5,
    isPublished: true,
  },
  // 23.4: New templates — Data Breach Notification
  {
    name: "Data Breach Notification",
    description:
      "End-to-end data breach response including impact assessment, regulatory notification, and affected party communication.",
    category: "Incident Response",
    severity: "critical",
    author: "SecureNexus",
    version: "1.2",
    tags: ["data-breach", "notification", "GDPR", "compliance", "PII"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Identify affected data",
        type: "automated",
        description: "Scan data stores for exposed PII/PHI records",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Assess breach scope",
        type: "manual",
        description: "Determine number of affected individuals and data categories",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Legal review",
        type: "approval",
        description: "Legal counsel reviews notification requirements by jurisdiction",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Prepare notification letters",
        type: "automated",
        description: "Generate jurisdiction-specific notifications",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Notify regulators",
        type: "manual",
        description: "Submit to ICO, HHS, state AGs within required timeframes",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Notify affected individuals",
        type: "notification",
        description: "Send breach notification emails/letters",
        config: {},
      },
      {
        id: "s7",
        order: 7,
        name: "Offer credit monitoring",
        type: "manual",
        description: "Set up identity protection services",
        config: {},
      },
    ],
    rating: 4.7,
    isPublished: true,
  },
  // 23.4: Ransomware Containment (more focused)
  {
    name: "Ransomware Containment & Recovery",
    description: "Rapid containment of active ransomware with backup verification and staged recovery.",
    category: "Incident Response",
    severity: "critical",
    author: "SecureNexus",
    version: "1.0",
    tags: ["ransomware", "containment", "recovery", "backup", "BCP"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Kill malicious processes",
        type: "automated",
        description: "Terminate known ransomware processes via EDR",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Network segmentation",
        type: "automated",
        description: "Isolate affected VLAN segments",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Verify backup integrity",
        type: "automated",
        description: "Check last known good backups are not encrypted",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Identify encryption scope",
        type: "manual",
        description: "Map encrypted files and systems",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Approve recovery plan",
        type: "approval",
        description: "CISO approves staged recovery approach",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Restore from backup",
        type: "manual",
        description: "Staged restore of critical systems first",
        config: {},
      },
      {
        id: "s7",
        order: 7,
        name: "Verify restoration",
        type: "automated",
        description: "Confirm data integrity post-restore",
        config: {},
      },
    ],
    rating: 4.6,
    isPublished: true,
  },
  // 23.4: Compliance Audit
  {
    name: "Compliance Audit Preparation",
    description: "Automated evidence collection and gap analysis for SOC 2, ISO 27001, and PCI-DSS audits.",
    category: "Compliance",
    severity: "medium",
    author: "SecureNexus",
    version: "1.4",
    tags: ["compliance", "SOC2", "ISO27001", "PCI-DSS", "audit"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Collect access reviews",
        type: "automated",
        description: "Pull IAM access review logs for audit period",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Verify change management",
        type: "automated",
        description: "Validate all changes followed CM process",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Check security configurations",
        type: "automated",
        description: "Run CIS benchmark scans",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Identify control gaps",
        type: "automated",
        description: "Compare controls against framework requirements",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Generate audit package",
        type: "automated",
        description: "Compile evidence artifacts into report",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Management review",
        type: "approval",
        description: "Management signs off on audit readiness",
        config: {},
      },
    ],
    rating: 4.3,
    isPublished: true,
  },
  // 23.4: Vulnerability Patching
  {
    name: "Emergency Vulnerability Patching",
    description: "Rapid patch deployment for critical zero-day vulnerabilities with rollback planning.",
    category: "Remediation",
    severity: "critical",
    author: "SecureNexus",
    version: "1.1",
    tags: ["patching", "zero-day", "emergency", "rollback"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Identify vulnerable systems",
        type: "automated",
        description: "Scan for affected software versions",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Assess exploit availability",
        type: "automated",
        description: "Check CISA KEV and exploit databases",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Create rollback snapshot",
        type: "automated",
        description: "Snapshot all target systems before patching",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Test patch in staging",
        type: "manual",
        description: "Apply patch to staging environment and verify",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Approve production deployment",
        type: "approval",
        description: "Change advisory board approves emergency change",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Deploy to production",
        type: "automated",
        description: "Rolling patch deployment with health checks",
        config: {},
      },
      {
        id: "s7",
        order: 7,
        name: "Verify patch effectiveness",
        type: "automated",
        description: "Rescan to confirm vulnerability is remediated",
        config: {},
      },
    ],
    rating: 4.5,
    isPublished: true,
  },
  // 23.4: Insider Threat Investigation
  {
    name: "Insider Threat Investigation",
    description:
      "Structured investigation workflow for suspected insider threats with evidence preservation and HR coordination.",
    category: "Insider Threat",
    severity: "high",
    author: "SecureNexus",
    version: "1.0",
    tags: ["insider-threat", "investigation", "HR", "legal", "evidence"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Preserve digital evidence",
        type: "automated",
        description: "Capture email, file access, endpoint logs",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Analyze data exfiltration",
        type: "automated",
        description: "Check USB, cloud upload, email attachment patterns",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Review access anomalies",
        type: "automated",
        description: "Compare against UEBA baseline for deviations",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Coordinate with HR",
        type: "manual",
        description: "Brief HR on findings and plan next steps",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Legal hold notice",
        type: "notification",
        description: "Issue litigation hold if warranted",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Access revocation decision",
        type: "approval",
        description: "HR/Legal approve access changes",
        config: {},
      },
      {
        id: "s7",
        order: 7,
        name: "Execute access changes",
        type: "automated",
        description: "Disable or restrict user access",
        config: {},
      },
    ],
    rating: 4.4,
    isPublished: true,
  },
  // 23.4: Threat Hunting
  {
    name: "Threat Hunting — Lateral Movement",
    description: "Proactive hunt for lateral movement indicators using MITRE ATT&CK TTPs.",
    category: "Threat Hunting",
    severity: "high",
    author: "SecureNexus",
    version: "1.2",
    tags: ["threat-hunting", "lateral-movement", "MITRE", "ATT&CK"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Define hunt hypothesis",
        type: "manual",
        description: "T1021 — Remote Services exploitation hypothesis",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Query authentication logs",
        type: "automated",
        description: "Search for unusual RDP, SSH, WinRM patterns",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Analyze network flows",
        type: "automated",
        description: "Detect east-west traffic anomalies",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Check for credential reuse",
        type: "automated",
        description: "Identify accounts used across multiple hosts",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Document findings",
        type: "manual",
        description: "Record IOCs, affected systems, and timeline",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Create detection rules",
        type: "automated",
        description: "Generate Sigma rules from hunt findings",
        config: {},
      },
    ],
    rating: 4.1,
    isPublished: true,
  },
  // 23.4: DDoS Response
  {
    name: "DDoS Attack Response",
    description: "Coordinated response to distributed denial-of-service attacks with traffic analysis and mitigation.",
    category: "Incident Response",
    severity: "high",
    author: "SecureNexus",
    version: "1.0",
    tags: ["DDoS", "availability", "traffic-analysis", "mitigation"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Detect attack vector",
        type: "automated",
        description: "Classify DDoS type (volumetric, protocol, application)",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Enable rate limiting",
        type: "automated",
        description: "Apply rate limits at WAF/CDN layer",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Activate DDoS protection",
        type: "automated",
        description: "Enable cloud DDoS mitigation service",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Analyze traffic patterns",
        type: "automated",
        description: "Identify source IPs and traffic signatures",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Block malicious sources",
        type: "automated",
        description: "Add offending IPs/ranges to blocklist",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Notify stakeholders",
        type: "notification",
        description: "Update status page and notify customers",
        config: {},
      },
      {
        id: "s7",
        order: 7,
        name: "Post-attack analysis",
        type: "manual",
        description: "Document attack profile for future defense",
        config: {},
      },
    ],
    rating: 4.3,
    isPublished: true,
  },
];

function initCatalog(): void {
  if (templates.size > 0) return;
  for (const tpl of CATALOG_TEMPLATES) {
    const id = `tpl-${createHash("sha256").update(tpl.name).digest("hex").slice(0, 12)}`;
    templates.set(id, {
      ...tpl,
      id,
      orgId: null,
      usageCount: 0,
      createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }
}

export function registerPlaybookTemplateRoutes(app: Express): void {
  initCatalog();
  const log = logger.child("playbook-templates");

  app.get(
    "/api/playbook-templates",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const category = req.query.category as string | undefined;
        const search = req.query.search as string | undefined;

        let results = Array.from(templates.values()).filter(
          (t) => t.isPublished && (t.orgId === null || t.orgId === orgId),
        );

        if (category) results = results.filter((t) => t.category === category);
        if (search) {
          const q = search.toLowerCase();
          results = results.filter(
            (t) =>
              t.name.toLowerCase().includes(q) ||
              t.description.toLowerCase().includes(q) ||
              t.tags.some((tag) => tag.includes(q)),
          );
        }

        results.sort((a, b) => b.rating - a.rating);
        return sendEnvelope(res, results, { meta: { total: results.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to list templates." }]);
      }
    },
  );

  app.get(
    "/api/playbook-templates/categories",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (_req: Request, res: Response) => {
      try {
        const categories = Array.from(new Set(Array.from(templates.values()).map((t) => t.category)));
        return reply(res, categories);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to list categories." }]);
      }
    },
  );

  app.get(
    "/api/playbook-templates/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const tpl = templates.get(req.params.id as string);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }
        return reply(res, tpl);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to get template." }]);
      }
    },
  );

  app.post(
    "/api/playbook-templates/:id/deploy",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const tpl = templates.get(req.params.id as string);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        tpl.usageCount += 1;

        // 23.5: Track deployment for version update checks
        const playbookName = req.body.name || tpl.name;
        const orgDeps = deployedTemplates.get(orgId) || [];
        orgDeps.push({
          orgId,
          templateId: tpl.id,
          templateVersion: tpl.version,
          deployedAt: new Date().toISOString(),
          playbookName,
        });
        deployedTemplates.set(orgId, orgDeps);

        log.info("Playbook template deployed", { orgId, templateId: tpl.id, templateName: tpl.name });
        return reply(res, {
          message: `Template "${tpl.name}" deployed as a new playbook.`,
          templateId: tpl.id,
          playbookName,
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to deploy template." }]);
      }
    },
  );

  app.post(
    "/api/playbook-templates",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { name, description, category, severity, tags, steps } = req.body;

        if (!name || !description) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "name and description are required." }]);
        }

        const id = `tpl-${createHash("sha256").update(`${orgId}-${name}-${Date.now()}`).digest("hex").slice(0, 12)}`;
        const tpl: PlaybookTemplate = {
          id,
          name,
          description,
          category: category || "Custom",
          severity: severity || "medium",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          author: (req as any).user?.username || "Custom",
          version: "1.0",
          tags: Array.isArray(tags) ? tags : [],
          steps: Array.isArray(steps) ? steps : [],
          usageCount: 0,
          rating: 0,
          isPublished: true,
          orgId,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        templates.set(id, tpl);
        log.info("Custom playbook template created", { orgId, templateId: id });
        return reply(res, tpl, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to create template." }]);
      }
    },
  );

  // =============================
  // 23.2 — TEMPLATE PREVIEW (read-only workflow preview without importing)
  // =============================

  app.get(
    "/api/playbook-templates/:id/preview",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const tpl = templates.get(req.params.id as string);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        // Build a rich preview with workflow visualization data
        const stepConnections = tpl.steps.map((step, idx) => ({
          ...step,
          isFirst: idx === 0,
          isLast: idx === tpl.steps.length - 1,
          nextStep: idx < tpl.steps.length - 1 ? tpl.steps[idx + 1].name : null,
        }));

        const automatedCount = tpl.steps.filter((s) => s.type === "automated").length;
        const manualCount = tpl.steps.filter((s) => s.type === "manual").length;
        const approvalCount = tpl.steps.filter((s) => s.type === "approval").length;
        const notificationCount = tpl.steps.filter((s) => s.type === "notification").length;

        // Estimated execution time based on step types
        const estimatedMinutes = automatedCount * 2 + manualCount * 15 + approvalCount * 30 + notificationCount * 1;

        return reply(res, {
          id: tpl.id,
          name: tpl.name,
          description: tpl.description,
          category: tpl.category,
          severity: tpl.severity,
          author: tpl.author,
          version: tpl.version,
          tags: tpl.tags,
          rating: tpl.rating,
          usageCount: tpl.usageCount,
          workflow: {
            steps: stepConnections,
            totalSteps: tpl.steps.length,
            automatedSteps: automatedCount,
            manualSteps: manualCount,
            approvalSteps: approvalCount,
            notificationSteps: notificationCount,
            estimatedDurationMinutes: estimatedMinutes,
            estimatedDurationFormatted:
              estimatedMinutes < 60
                ? `${estimatedMinutes}m`
                : `${Math.floor(estimatedMinutes / 60)}h ${estimatedMinutes % 60}m`,
            automationPercentage: Math.round((automatedCount / tpl.steps.length) * 100),
          },
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to preview template." }]);
      }
    },
  );

  // =============================
  // 23.3 — TEMPLATE RATING AND USAGE STATISTICS
  // =============================

  app.post(
    "/api/playbook-templates/:id/rate",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const templateId = req.params.id as string;
        const tpl = templates.get(templateId);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        const { rating, comment } = req.body;
        if (typeof rating !== "number" || rating < 1 || rating > 5) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "rating must be a number between 1 and 5." },
          ]);
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const userId = (req as any).user?.id || "unknown";

        // Store rating
        const existing = templateRatings.get(templateId) || [];
        // Replace existing rating from same user
        const filtered = existing.filter((r) => !(r.orgId === orgId && r.userId === userId));
        filtered.push({
          templateId,
          orgId,
          userId,
          rating,
          comment: comment || "",
          createdAt: new Date().toISOString(),
        });
        templateRatings.set(templateId, filtered);

        // Recalculate average rating
        const avgRating = filtered.reduce((sum, r) => sum + r.rating, 0) / filtered.length;
        tpl.rating = Math.round(avgRating * 10) / 10;

        log.info("Template rated", { orgId, templateId, rating });
        return reply(res, { message: "Rating submitted", newAverage: tpl.rating, totalRatings: filtered.length });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to rate template." }]);
      }
    },
  );

  app.get(
    "/api/playbook-templates/:id/stats",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const templateId = req.params.id as string;
        const tpl = templates.get(templateId);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        const ratings = templateRatings.get(templateId) || [];
        const ratingDistribution = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 } as Record<number, number>;
        for (const r of ratings) {
          ratingDistribution[Math.round(r.rating)] = (ratingDistribution[Math.round(r.rating)] || 0) + 1;
        }

        return reply(res, {
          templateId,
          name: tpl.name,
          averageRating: tpl.rating,
          totalRatings: ratings.length,
          ratingDistribution,
          usageCount: tpl.usageCount,
          lastUpdated: tpl.updatedAt,
          version: tpl.version,
          recentReviews: ratings
            .slice(-5)
            .reverse()
            .map((r) => ({
              rating: r.rating,
              comment: r.comment,
              createdAt: r.createdAt,
            })),
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to get template stats." }]);
      }
    },
  );

  // =============================
  // 23.5 — TEMPLATE VERSIONING AND UPDATES
  // =============================

  app.get(
    "/api/playbook-templates/:id/versions",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const templateId = req.params.id as string;
        const tpl = templates.get(templateId);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        const history = templateVersionHistory.get(templateId) || [];

        // If no history yet, create the initial version entry
        if (history.length === 0) {
          history.push({
            templateId,
            version: tpl.version,
            changelog: "Initial release",
            publishedAt: tpl.createdAt,
          });
          templateVersionHistory.set(templateId, history);
        }

        return reply(res, {
          templateId,
          currentVersion: tpl.version,
          versions: history,
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to get template versions." }]);
      }
    },
  );

  app.post(
    "/api/playbook-templates/:id/publish-version",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const templateId = req.params.id as string;
        const tpl = templates.get(templateId);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        // Only org-owned templates can be versioned by org admins
        if (tpl.orgId !== null && tpl.orgId !== orgId) {
          return replyError(res, 403, [
            { code: "FORBIDDEN", message: "Cannot version templates from other organizations." },
          ]);
        }

        const { version, changelog, steps, description } = req.body;
        if (!version || !changelog) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "version and changelog are required." }]);
        }

        // Update template
        tpl.version = version;
        if (description) tpl.description = description;
        if (Array.isArray(steps)) tpl.steps = steps;
        tpl.updatedAt = new Date().toISOString();

        // Add version history entry
        const history = templateVersionHistory.get(templateId) || [];
        history.push({
          templateId,
          version,
          changelog,
          publishedAt: new Date().toISOString(),
        });
        templateVersionHistory.set(templateId, history);

        log.info("Template version published", { orgId, templateId, version });
        return reply(res, { message: "Version published", version, template: tpl });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to publish version." }]);
      }
    },
  );

  // Check for template updates for deployed playbooks
  app.get(
    "/api/playbook-templates/check-updates",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const orgDeployments = deployedTemplates.get(orgId) || [];

        const updates: {
          templateId: string;
          templateName: string;
          deployedVersion: string;
          latestVersion: string;
          changelog: string;
          playbookName: string;
        }[] = [];

        for (const dep of orgDeployments) {
          const tpl = templates.get(dep.templateId);
          if (tpl && tpl.version !== dep.templateVersion) {
            const history = templateVersionHistory.get(dep.templateId) || [];
            const newVersions = history.filter((v) => v.version !== dep.templateVersion);
            const latestChangelog = newVersions.map((v) => `v${v.version}: ${v.changelog}`).join("; ");

            updates.push({
              templateId: dep.templateId,
              templateName: tpl.name,
              deployedVersion: dep.templateVersion,
              latestVersion: tpl.version,
              changelog: latestChangelog || "No changelog available",
              playbookName: dep.playbookName,
            });
          }
        }

        return reply(res, { updates, count: updates.length });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to check for updates." }]);
      }
    },
  );
}
