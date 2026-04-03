/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";

interface TemplateStep {
  id: string;
  order: number;
  name: string;
  type: "manual" | "automated" | "approval" | "notification";
  description: string;
  config: Record<string, unknown>;
}

interface CatalogTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  author: string;
  version: string;
  tags: string[];
  steps: TemplateStep[];
  rating: number;
  isPublished: boolean;
}

const CATALOG_TEMPLATES: CatalogTemplate[] = [
  {
    id: "tpl-ransomware",
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
    id: "tpl-phishing",
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
    id: "tpl-cloud-misconfig",
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
    id: "tpl-insider-threat",
    name: "Insider Threat Detection",
    description: "Behavioral analysis and response for potential insider threat indicators.",
    category: "Insider Threat",
    severity: "high",
    author: "SecureNexus",
    version: "1.2",
    tags: ["insider-threat", "UEBA", "behavioral", "DLP"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Detect anomalous behavior",
        type: "automated",
        description: "UEBA threshold breach",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Correlate data access",
        type: "automated",
        description: "DLP event correlation",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Assess risk level",
        type: "automated",
        description: "Score against insider threat model",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "HR notification",
        type: "notification",
        description: "Alert HR and legal",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Access restriction approval",
        type: "approval",
        description: "Manager approval for access changes",
        config: {},
      },
    ],
    rating: 4.3,
    isPublished: true,
  },
  {
    id: "tpl-data-breach",
    name: "Data Breach Response",
    description: "Complete breach response playbook with regulatory notification requirements.",
    category: "Incident Response",
    severity: "critical",
    author: "SecureNexus",
    version: "2.0",
    tags: ["data-breach", "GDPR", "notification", "regulatory"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Assess scope of breach",
        type: "automated",
        description: "Identify affected records and systems",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Contain breach",
        type: "automated",
        description: "Block exfiltration paths",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Determine notification requirements",
        type: "manual",
        description: "Check GDPR/CCPA/HIPAA thresholds",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Legal review",
        type: "approval",
        description: "Legal team approves notification plan",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Notify regulators",
        type: "notification",
        description: "File 72-hour GDPR notification",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Notify affected individuals",
        type: "notification",
        description: "Send breach notifications",
        config: {},
      },
    ],
    rating: 4.7,
    isPublished: true,
  },
  {
    id: "tpl-vuln-patch",
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
        description: "Change advisory board approves",
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
        description: "Rescan to confirm remediation",
        config: {},
      },
    ],
    rating: 4.5,
    isPublished: true,
  },
  {
    id: "tpl-compliance-audit",
    name: "Compliance Audit Preparation",
    description: "Pre-audit evidence gathering and control validation for SOC 2, ISO 27001, and PCI DSS.",
    category: "Compliance",
    severity: "medium",
    author: "SecureNexus",
    version: "1.4",
    tags: ["compliance", "audit", "SOC2", "ISO27001", "PCI-DSS"],
    steps: [
      {
        id: "s1",
        order: 1,
        name: "Collect policy documents",
        type: "automated",
        description: "Aggregate current security policies",
        config: {},
      },
      {
        id: "s2",
        order: 2,
        name: "Gather access review evidence",
        type: "automated",
        description: "Export IAM audit logs",
        config: {},
      },
      {
        id: "s3",
        order: 3,
        name: "Validate technical controls",
        type: "automated",
        description: "Run automated control tests",
        config: {},
      },
      {
        id: "s4",
        order: 4,
        name: "Compare against framework",
        type: "automated",
        description: "Map controls to requirements",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Generate audit package",
        type: "automated",
        description: "Compile evidence into report",
        config: {},
      },
      {
        id: "s6",
        order: 6,
        name: "Management review",
        type: "approval",
        description: "Management signs off on readiness",
        config: {},
      },
    ],
    rating: 4.3,
    isPublished: true,
  },
  {
    id: "tpl-threat-hunt",
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
        description: "T1021 — Remote Services exploitation",
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
        name: "Correlate with endpoint data",
        type: "automated",
        description: "Match process execution events",
        config: {},
      },
      {
        id: "s5",
        order: 5,
        name: "Document findings",
        type: "manual",
        description: "Record indicators and recommendations",
        config: {},
      },
    ],
    rating: 4.5,
    isPublished: true,
  },
];

// Build lookup map for catalog templates
const catalogMap = new Map<string, CatalogTemplate>();
for (const tpl of CATALOG_TEMPLATES) {
  catalogMap.set(tpl.id, tpl);
}

export function registerPlaybookTemplateRoutes(app: Express): void {
  const log = logger.child("playbook-templates");

  // List available templates (catalog + org-specific from DB)
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

        // Get org playbooks marked as templates from DB
        const orgPlaybooks = await storage.getPlaybooks(orgId);
        const orgTemplates = orgPlaybooks
          .filter((p) => p.status === "template" || p.status === "published")
          .map((p) => ({
            id: p.id,
            name: p.name,
            description: p.description || "",
            category: ((p.conditions as any)?.category as string) || "Custom",
            severity: ((p.conditions as any)?.severity as string) || "medium",
            author: p.createdBy || "Custom",
            version: ((p.conditions as any)?.version as string) || "1.0",
            tags: ((p.conditions as any)?.tags as string[]) || [],
            steps: Array.isArray(p.actions) ? p.actions : [],
            rating: 0,
            isPublished: true,
            orgId: p.orgId,
          }));

        let results = [...CATALOG_TEMPLATES.map((t) => ({ ...t, orgId: null as string | null })), ...orgTemplates];

        if (category) results = results.filter((t) => t.category === category);
        if (search) {
          const q = search.toLowerCase();
          results = results.filter(
            (t) =>
              t.name.toLowerCase().includes(q) ||
              t.description.toLowerCase().includes(q) ||
              t.tags.some((tag: string) => tag.includes(q)),
          );
        }

        results.sort((a, b) => b.rating - a.rating);
        return sendEnvelope(res, results, { meta: { total: results.length } });
      } catch (error: unknown) {
        log.error("Failed to list templates", { error });
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to list templates." }]);
      }
    },
  );

  // List categories
  app.get(
    "/api/playbook-templates/categories",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (_req: Request, res: Response) => {
      try {
        const categories = Array.from(new Set(CATALOG_TEMPLATES.map((t) => t.category)));
        return reply(res, categories);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to list categories." }]);
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
        const orgPlaybooks = await storage.getPlaybooks(orgId);

        const updates: {
          templateId: string;
          templateName: string;
          deployedVersion: string;
          latestVersion: string;
          playbookName: string;
        }[] = [];

        for (const pb of orgPlaybooks) {
          const sourceTemplateId = (pb.conditions as any)?.sourceTemplateId;
          const deployedVersion = (pb.conditions as any)?.sourceTemplateVersion;
          if (!sourceTemplateId || !deployedVersion) continue;

          const catalogTpl = catalogMap.get(sourceTemplateId);
          if (catalogTpl && catalogTpl.version !== deployedVersion) {
            updates.push({
              templateId: catalogTpl.id,
              templateName: catalogTpl.name,
              deployedVersion,
              latestVersion: catalogTpl.version,
              playbookName: pb.name,
            });
          }
        }

        return reply(res, { updates, count: updates.length });
      } catch (error: unknown) {
        log.error("Failed to check updates", { error });
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to check for updates." }]);
      }
    },
  );

  // Get single template
  app.get(
    "/api/playbook-templates/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const templateId = String(req.params.id);

        // Check catalog first
        const catalogTpl = catalogMap.get(templateId);
        if (catalogTpl) return reply(res, catalogTpl);

        // Check org playbooks as templates
        const playbook = await storage.getPlaybook(templateId);
        if (playbook) {
          return reply(res, {
            id: playbook.id,
            name: playbook.name,
            description: playbook.description || "",
            category: ((playbook.conditions as any)?.category as string) || "Custom",
            severity: ((playbook.conditions as any)?.severity as string) || "medium",
            author: playbook.createdBy || "Custom",
            version: ((playbook.conditions as any)?.version as string) || "1.0",
            tags: ((playbook.conditions as any)?.tags as string[]) || [],
            steps: Array.isArray(playbook.actions) ? playbook.actions : [],
            rating: 0,
            isPublished: playbook.status !== "draft",
          });
        }

        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to get template." }]);
      }
    },
  );

  // Deploy template as a new playbook in the org (persisted to DB)
  app.post(
    "/api/playbook-templates/:id/deploy",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const templateId = String(req.params.id);
        const user = (req as any).user;

        const catalogTpl = catalogMap.get(templateId);
        if (!catalogTpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        const playbookName = req.body.name || catalogTpl.name;

        // Create a real playbook in the DB from this template
        const playbook = await storage.createPlaybook({
          orgId,
          name: playbookName,
          description: catalogTpl.description,
          trigger: "manual",
          conditions: {
            sourceTemplateId: catalogTpl.id,
            sourceTemplateVersion: catalogTpl.version,
            category: catalogTpl.category,
            severity: catalogTpl.severity,
            tags: catalogTpl.tags,
            version: catalogTpl.version,
          },
          actions: catalogTpl.steps,
          status: "active",
          createdBy: user?.id || null,
        });

        log.info("Playbook template deployed", { orgId, templateId, playbookId: playbook.id });
        return reply(
          res,
          {
            message: `Template "${catalogTpl.name}" deployed as playbook "${playbookName}".`,
            templateId: catalogTpl.id,
            playbookId: playbook.id,
            playbookName,
          },
          undefined,
          201,
        );
      } catch (error: unknown) {
        log.error("Failed to deploy template", { error });
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to deploy template." }]);
      }
    },
  );

  // Create custom template (saved as playbook with status=template)
  app.post(
    "/api/playbook-templates",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { name, description, category, severity, tags, steps } = req.body;

        if (!name || !description) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "name and description are required." }]);
        }

        const playbook = await storage.createPlaybook({
          orgId,
          name,
          description,
          trigger: "manual",
          conditions: {
            category: category || "Custom",
            severity: severity || "medium",
            tags: Array.isArray(tags) ? tags : [],
            version: "1.0",
          },
          actions: Array.isArray(steps) ? steps : [],
          status: "template",
          createdBy: user?.id || null,
        });

        log.info("Custom playbook template created", { orgId, playbookId: playbook.id });
        return reply(
          res,
          {
            id: playbook.id,
            name: playbook.name,
            description: playbook.description,
            category: category || "Custom",
            severity: severity || "medium",
            author: user?.username || "Custom",
            version: "1.0",
            tags: Array.isArray(tags) ? tags : [],
            steps: Array.isArray(steps) ? steps : [],
            rating: 0,
            isPublished: true,
            orgId,
          },
          undefined,
          201,
        );
      } catch (error: unknown) {
        log.error("Failed to create template", { error });
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to create template." }]);
      }
    },
  );

  // Template preview
  app.get(
    "/api/playbook-templates/:id/preview",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const templateId = String(req.params.id);
        const tpl = catalogMap.get(templateId);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

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
            automationPercentage: tpl.steps.length > 0 ? Math.round((automatedCount / tpl.steps.length) * 100) : 0,
          },
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to preview template." }]);
      }
    },
  );

  // Template stats (from DB execution data)
  app.get(
    "/api/playbook-templates/:id/stats",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const templateId = String(req.params.id);
        const tpl = catalogMap.get(templateId);
        if (!tpl) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        // Count deployments from DB
        const orgId = getOrgId(req);
        const orgPlaybooks = await storage.getPlaybooks(orgId);
        const deployments = orgPlaybooks.filter((p) => (p.conditions as any)?.sourceTemplateId === templateId);

        return reply(res, {
          templateId,
          name: tpl.name,
          averageRating: tpl.rating,
          deploymentCount: deployments.length,
          lastUpdated: tpl.version,
          version: tpl.version,
          deployedPlaybooks: deployments.map((d) => ({
            playbookId: d.id,
            name: d.name,
            status: d.status,
            deployedVersion: (d.conditions as any)?.sourceTemplateVersion || "unknown",
          })),
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TEMPLATE_ERROR", message: "Failed to get template stats." }]);
      }
    },
  );
}
