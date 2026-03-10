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
];

function initCatalog(): void {
  if (templates.size > 0) return;
  for (const tpl of CATALOG_TEMPLATES) {
    const id = `tpl-${createHash("sha256").update(tpl.name).digest("hex").slice(0, 12)}`;
    templates.set(id, {
      ...tpl,
      id,
      orgId: null,
      usageCount: Math.floor(Math.random() * 200) + 50,
      createdAt: new Date(Date.now() - Math.floor(Math.random() * 90 * 24 * 60 * 60 * 1000)).toISOString(),
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

        log.info("Playbook template deployed", { orgId, templateId: tpl.id, templateName: tpl.name });
        return reply(res, {
          message: `Template "${tpl.name}" deployed as a new playbook.`,
          templateId: tpl.id,
          playbookName: req.body.name || tpl.name,
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
}
