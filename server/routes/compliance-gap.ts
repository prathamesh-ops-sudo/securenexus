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
