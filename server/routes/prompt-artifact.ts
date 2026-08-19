import type { Express } from "express";
import { z } from "zod";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { runInvestigation, getSuggestedPrompts, getTemplates } from "../prompt-artifact-engine";
import type { ArtifactType, GeneratedArtifact } from "../prompt-artifact-engine";
import * as promptStorage from "../storage/prompt-artifact";

const log = logger.child("prompt-artifact");

// ─── Validation helpers ──────────────────────────────────────────────────────

interface ValidationResult {
  valid: boolean;
  errors: { field: string; message: string; severity: "error" | "warning" }[];
  artifactType: string;
  checkedAt: string;
}

function validateSigmaRule(content: Record<string, unknown>): ValidationResult {
  const errors: ValidationResult["errors"] = [];
  const requiredFields = ["title", "status", "description", "logsource", "detection"];
  for (const field of requiredFields) {
    if (!content[field]) {
      errors.push({ field, message: `Missing required Sigma field: ${field}`, severity: "error" });
    }
  }
  if (content["logsource"] && typeof content["logsource"] === "object") {
    const ls = content["logsource"] as Record<string, unknown>;
    if (!ls["category"] && !ls["product"] && !ls["service"]) {
      errors.push({
        field: "logsource",
        message: "Logsource must specify at least one of: category, product, service",
        severity: "error",
      });
    }
  }
  if (content["detection"] && typeof content["detection"] === "object") {
    const det = content["detection"] as Record<string, unknown>;
    if (!det["condition"]) {
      errors.push({ field: "detection.condition", message: "Detection must include a condition", severity: "error" });
    }
  }
  if (content["level"] && !["informational", "low", "medium", "high", "critical"].includes(String(content["level"]))) {
    errors.push({ field: "level", message: "Invalid severity level", severity: "warning" });
  }
  return {
    valid: errors.filter((e) => e.severity === "error").length === 0,
    errors,
    artifactType: "alert_rule",
    checkedAt: new Date().toISOString(),
  };
}

function validatePlaybook(content: Record<string, unknown>): ValidationResult {
  const errors: ValidationResult["errors"] = [];
  if (!content["name"]) errors.push({ field: "name", message: "Playbook must have a name", severity: "error" });
  if (!content["steps"] || !Array.isArray(content["steps"])) {
    errors.push({ field: "steps", message: "Playbook must have an array of steps", severity: "error" });
  } else {
    const steps = content["steps"] as Record<string, unknown>[];
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (!step["action"])
        errors.push({ field: `steps[${i}].action`, message: `Step ${i + 1} missing action`, severity: "error" });
      if (!step["description"])
        errors.push({
          field: `steps[${i}].description`,
          message: `Step ${i + 1} missing description`,
          severity: "warning",
        });
    }
  }
  return {
    valid: errors.filter((e) => e.severity === "error").length === 0,
    errors,
    artifactType: "workflow",
    checkedAt: new Date().toISOString(),
  };
}

function validateReport(content: Record<string, unknown>): ValidationResult {
  const errors: ValidationResult["errors"] = [];
  if (!content["title"]) errors.push({ field: "title", message: "Report must have a title", severity: "error" });
  if (!content["sections"] && !content["widgets"] && !content["metrics"]) {
    errors.push({
      field: "content",
      message: "Report must define sections, widgets, or metrics",
      severity: "warning",
    });
  }
  return {
    valid: errors.filter((e) => e.severity === "error").length === 0,
    errors,
    artifactType: "report",
    checkedAt: new Date().toISOString(),
  };
}

function validateArtifact(artifactType: string, content: Record<string, unknown>): ValidationResult {
  switch (artifactType) {
    case "alert_rule":
      return validateSigmaRule(content);
    case "workflow":
      return validatePlaybook(content);
    case "report":
      return validateReport(content);
    default:
      return { valid: true, errors: [], artifactType, checkedAt: new Date().toISOString() };
  }
}

const ARTIFACT_DEPLOY_TARGETS: Record<string, string> = {
  alert_rule: "Detection Rules",
  workflow: "Playbooks",
  report: "Reports",
  dashboard: "Dashboard",
  investigation: "Investigations",
  query: "Threat Hunting",
};

// ─── Route Registration ─────────────────────────────────────────────────────

const runInvestigationSchema = z.object({
  prompt: z.string().min(1, "Prompt is required").max(2000, "Prompt must be under 2000 characters"),
});

export function registerPromptArtifactRoutes(app: Express): void {
  // ── Investigations (DB-backed) ───────────────────────────────────────────

  app.post(
    "/api/prompt-artifact/investigate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = runInvestigationSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const { prompt } = parsed.data;
        const orgId = getOrgId(req);

        // Engine generates the investigation data
        const generated = runInvestigation(prompt, orgId);

        // Persist to DB
        const saved = await promptStorage.createPromptInvestigation({
          id: generated.id,
          orgId,
          prompt: generated.prompt,
          intent: generated.intent,
          status: generated.status,
          summary: generated.summary,
          steps: generated.steps as unknown as Record<string, unknown>,
          artifacts: generated.artifacts as unknown as Record<string, unknown>,
          citations: generated.citations as unknown as Record<string, unknown>,
          completedAt: generated.completedAt ? new Date(generated.completedAt) : null,
        });

        // Also save to prompt history
        const artifactType = generated.artifacts[0]?.type || "query";
        await promptStorage.createPromptHistoryEntry({
          orgId,
          prompt: generated.prompt,
          artifactType,
          resultId: saved.id,
        });

        res.json(saved);
      } catch (error) {
        log.error("Prompt-to-artifact investigation error", { error: String(error) });
        res.status(500).json({ message: "Failed to run investigation" });
      }
    },
  );

  app.get("/api/prompt-artifact/investigations", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const investigations = await promptStorage.getPromptInvestigations(orgId);
      res.json(investigations);
    } catch (error) {
      log.error("List investigations error", { error: String(error) });
      res.status(500).json({ message: "Failed to list investigations" });
    }
  });

  app.get("/api/prompt-artifact/investigations/:id", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const investigation = await promptStorage.getPromptInvestigation(id);
      if (!investigation || investigation.orgId !== orgId) {
        return res.status(404).json({ message: "Investigation not found" });
      }
      res.json(investigation);
    } catch (error) {
      log.error("Get investigation error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch investigation" });
    }
  });

  // ── Suggestions & Templates (static, no DB) ─────────────────────────────

  app.get("/api/prompt-artifact/suggestions", isAuthenticated, async (_req, res) => {
    try {
      const suggestions = getSuggestedPrompts();
      res.json(suggestions);
    } catch (error) {
      log.error("Suggestions error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch suggestions" });
    }
  });

  app.get("/api/prompt-artifact/templates", isAuthenticated, async (_req, res) => {
    try {
      const templates = getTemplates();
      res.json(templates);
    } catch (error) {
      log.error("Templates error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch templates" });
    }
  });

  // ── Approvals (DB-backed) ────────────────────────────────────────────────

  app.get("/api/prompt-artifact/approvals/pending", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const pending = await promptStorage.getPendingArtifactApprovals(orgId);
      res.json(pending);
    } catch (error) {
      log.error("Pending approvals error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch pending approvals" });
    }
  });

  const reviewSchema = z.object({
    reviewerName: z.string().min(1).max(200),
    decision: z.enum(["approved", "rejected"]),
    notes: z.string().max(2000).default(""),
  });

  app.post(
    "/api/prompt-artifact/approvals/:id/review",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = reviewSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);
        const approvalId = String(req.params.id);
        const { reviewerName, decision, notes } = parsed.data;

        const approval = await promptStorage.getArtifactApproval(approvalId);
        if (!approval || approval.orgId !== orgId) {
          return res.status(404).json({ message: "Approval not found" });
        }

        const updated = await promptStorage.updateArtifactApproval(approvalId, {
          status: decision,
          reviewedBy: reviewerName,
          reviewedAt: new Date(),
          reviewNotes: notes,
        });

        res.json(updated);
      } catch (error) {
        log.error("Review approval error", { error: String(error) });
        res.status(500).json({ message: "Failed to review approval" });
      }
    },
  );

  // ── Update artifact logic (DB-backed) ────────────────────────────────────

  const updateLogicSchema = z.object({
    investigationId: z.string().min(1),
    artifactId: z.string().min(1),
    blockId: z.string().min(1),
    newCode: z.string().min(1).max(50000),
  });

  app.post(
    "/api/prompt-artifact/artifacts/update-logic",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = updateLogicSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);
        const { investigationId, artifactId, blockId, newCode } = parsed.data;

        const investigation = await promptStorage.getPromptInvestigation(investigationId);
        if (!investigation || investigation.orgId !== orgId) {
          return res.status(404).json({ message: "Investigation not found" });
        }

        const artifacts = (investigation.artifacts as unknown as GeneratedArtifact[]) || [];
        const artifact = artifacts.find((a) => a.id === artifactId);
        if (!artifact) return res.status(404).json({ message: "Artifact not found" });

        const block = artifact.editableLogic?.find((b) => b.id === blockId);
        if (!block || !block.editable)
          return res.status(404).json({ message: "Logic block not found or not editable" });

        block.code = newCode.slice(0, 50000);

        await promptStorage.updatePromptInvestigation(investigationId, {
          artifacts: artifacts as unknown as Record<string, unknown>,
        });

        res.json(artifact);
      } catch (error) {
        log.error("Update logic error", { error: String(error) });
        res.status(500).json({ message: "Failed to update artifact logic" });
      }
    },
  );

  // ── Prompt History (DB-backed) ───────────────────────────────────────────

  app.get("/api/prompt-artifact/history", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      let history = await promptStorage.getPromptHistory(orgId);

      const keyword = typeof req.query.keyword === "string" ? req.query.keyword.toLowerCase() : null;
      const favoritesOnly = req.query.favorites === "true";

      if (keyword) history = history.filter((h) => h.prompt.toLowerCase().includes(keyword));
      if (favoritesOnly) history = history.filter((h) => h.isFavorite);

      res.json(history);
    } catch (error) {
      log.error("Prompt history error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch prompt history" });
    }
  });

  const toggleFavoriteSchema = z.object({ promptId: z.string().min(1) });

  app.post(
    "/api/prompt-artifact/history/toggle-favorite",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = toggleFavoriteSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);

        const entry = await promptStorage.getPromptHistoryEntry(parsed.data.promptId);
        if (!entry || entry.orgId !== orgId) return res.status(404).json({ message: "Prompt not found" });

        const updated = await promptStorage.updatePromptHistoryEntry(entry.id, { isFavorite: !entry.isFavorite });
        res.json(updated);
      } catch (error) {
        log.error("Toggle favorite error", { error: String(error) });
        res.status(500).json({ message: "Failed to toggle favorite" });
      }
    },
  );

  const sharePromptSchema = z.object({ promptId: z.string().min(1), shareWith: z.array(z.string().min(1)).max(50) });

  app.post(
    "/api/prompt-artifact/history/share",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = sharePromptSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);

        const entry = await promptStorage.getPromptHistoryEntry(parsed.data.promptId);
        if (!entry || entry.orgId !== orgId) return res.status(404).json({ message: "Prompt not found" });

        const existingShared = (entry.sharedWith as string[]) || [];
        const newShared = Array.from(new Set([...existingShared, ...parsed.data.shareWith]));
        const updated = await promptStorage.updatePromptHistoryEntry(entry.id, { sharedWith: newShared });
        res.json(updated);
      } catch (error) {
        log.error("Share prompt error", { error: String(error) });
        res.status(500).json({ message: "Failed to share prompt" });
      }
    },
  );

  // ── Artifact Validation ──────────────────────────────────────────────────

  const validateArtifactSchema = z.object({
    investigationId: z.string().min(1),
    artifactId: z.string().min(1),
  });

  app.post(
    "/api/prompt-artifact/artifacts/validate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = validateArtifactSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);

        const investigation = await promptStorage.getPromptInvestigation(parsed.data.investigationId);
        if (!investigation || investigation.orgId !== orgId) {
          return res.status(404).json({ message: "Investigation not found" });
        }

        const artifacts = (investigation.artifacts as unknown as GeneratedArtifact[]) || [];
        const artifact = artifacts.find((a) => a.id === parsed.data.artifactId);
        if (!artifact) return res.status(404).json({ message: "Artifact not found" });

        const result = validateArtifact(artifact.type, artifact.content);
        res.json(result);
      } catch (error) {
        log.error("Validate artifact error", { error: String(error) });
        res.status(500).json({ message: "Failed to validate artifact" });
      }
    },
  );

  // ── Artifact Deployment Pipeline (DB-backed) ─────────────────────────────

  const deployArtifactSchema = z.object({
    investigationId: z.string().min(1),
    artifactId: z.string().min(1),
  });

  app.post(
    "/api/prompt-artifact/artifacts/deploy",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = deployArtifactSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);

        const investigation = await promptStorage.getPromptInvestigation(parsed.data.investigationId);
        if (!investigation || investigation.orgId !== orgId) {
          return res.status(404).json({ message: "Investigation not found" });
        }

        const artifacts = (investigation.artifacts as unknown as GeneratedArtifact[]) || [];
        const artifact = artifacts.find((a) => a.id === parsed.data.artifactId);
        if (!artifact) return res.status(404).json({ message: "Artifact not found" });

        const validation = validateArtifact(artifact.type, artifact.content);
        if (!validation.valid) {
          return res.status(422).json({ message: "Artifact has validation errors", validation });
        }

        if (artifact.approvalGate && artifact.approvalGate.status !== "approved") {
          return res.status(403).json({ message: "Artifact requires approval before deployment" });
        }

        const deployment = await promptStorage.createArtifactDeployment({
          orgId,
          artifactId: artifact.id,
          investigationId: investigation.id,
          artifactType: artifact.type,
          targetPage: ARTIFACT_DEPLOY_TARGETS[artifact.type] || "Unknown",
          status: "deployed",
          deployedBy: "current-user",
          snapshotContent: JSON.parse(JSON.stringify(artifact.content)),
        });

        log.info("Artifact deployed", {
          deployId: deployment.id,
          artifactType: artifact.type,
          targetPage: deployment.targetPage,
        });

        res.json(deployment);
      } catch (error) {
        log.error("Deploy artifact error", { error: String(error) });
        res.status(500).json({ message: "Failed to deploy artifact" });
      }
    },
  );

  app.post(
    "/api/prompt-artifact/deployments/:id/rollback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const deployId = String(req.params.id);

        const deployment = await promptStorage.getArtifactDeployment(deployId);
        if (!deployment || deployment.orgId !== orgId) {
          return res.status(404).json({ message: "Deployment not found" });
        }

        if (deployment.status === "rolled_back") {
          return res.status(400).json({ message: "Deployment already rolled back" });
        }

        const updated = await promptStorage.updateArtifactDeployment(deployId, {
          status: "rolled_back",
          rolledBackAt: new Date(),
        });

        log.info("Deployment rolled back", { deployId });
        res.json(updated);
      } catch (error) {
        log.error("Rollback deployment error", { error: String(error) });
        res.status(500).json({ message: "Failed to rollback deployment" });
      }
    },
  );

  app.get("/api/prompt-artifact/deployments", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const deployments = await promptStorage.getArtifactDeployments(orgId);
      res.json(deployments);
    } catch (error) {
      log.error("List deployments error", { error: String(error) });
      res.status(500).json({ message: "Failed to list deployments" });
    }
  });

  // ── Artifact Type Templates (static) ─────────────────────────────────────

  app.get("/api/prompt-artifact/artifact-types", isAuthenticated, async (_req, res) => {
    try {
      const types = [
        {
          type: "alert_rule",
          label: "Detection Rule",
          description: "Sigma, YARA, or KQL detection rules for threat identification",
          examplePrompts: [
            "Create a Sigma rule for detecting lateral movement via PsExec",
            "Generate a detection rule for suspicious PowerShell encoded commands",
            "Build an alert for brute force login attempts exceeding 10 failures in 5 minutes",
          ],
          bestPractices: [
            "Specify the log source (e.g., Windows Security, Sysmon, Firewall)",
            "Include severity level and MITRE ATT&CK technique references",
            "Define clear false positive conditions to reduce noise",
          ],
        },
        {
          type: "workflow",
          label: "Playbook",
          description: "Automated response playbooks with step-by-step actions",
          examplePrompts: [
            "Create a playbook for phishing email triage and response",
            "Build an automated workflow for malware containment",
            "Design an incident escalation playbook for critical severity alerts",
          ],
          bestPractices: [
            "Define clear trigger conditions and escalation criteria",
            "Include human approval gates for destructive actions",
            "Add rollback steps for each automated action",
          ],
        },
        {
          type: "report",
          label: "Report Template",
          description: "Compliance and security posture reports with data-driven insights",
          examplePrompts: [
            "Generate a monthly security posture report for SOC2 compliance",
            "Create an executive summary of threat landscape for the last quarter",
            "Build a vulnerability trending report by severity and remediation time",
          ],
          bestPractices: [
            "Reference specific data sources and time ranges",
            "Include executive summary and detailed sections",
            "Add trend comparisons with previous reporting periods",
          ],
        },
        {
          type: "query",
          label: "Hunt Query",
          description: "Threat hunting queries in KQL, SQL, or Sigma format",
          examplePrompts: [
            "Search for beaconing activity with regular interval connections",
            "Find all DNS queries to newly registered domains in the last 7 days",
            "Identify users who accessed sensitive files outside business hours",
          ],
          bestPractices: [
            "Specify the target data source and time window",
            "Include expected output fields for analyst review",
            "Add baseline comparisons to highlight anomalies",
          ],
        },
        {
          type: "dashboard",
          label: "Dashboard",
          description: "Visual dashboards with widgets, charts, and real-time metrics",
          examplePrompts: [
            "Show me a dashboard of critical alerts from the last 24 hours",
            "Build a dashboard showing alert trends by severity over the past week",
            "Create a real-time overview of endpoint security posture",
          ],
          bestPractices: [
            "Focus on actionable metrics rather than vanity numbers",
            "Group related widgets logically for analyst workflow",
            "Include drill-down capabilities for each metric",
          ],
        },
        {
          type: "investigation",
          label: "Compliance Check",
          description: "Compliance gap analysis and control verification checks",
          examplePrompts: [
            "Check SOC2 Type II compliance status across all controls",
            "Verify GDPR data processing requirements for customer PII",
            "Audit access control policies against NIST 800-53 requirements",
          ],
          bestPractices: [
            "Specify the compliance framework and control identifiers",
            "Include evidence collection requirements",
            "Reference specific organizational policies and standards",
          ],
        },
      ];
      res.json(types);
    } catch (error) {
      log.error("Artifact types error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch artifact types" });
    }
  });

  // ── Generate with specific artifact type ─────────────────────────────────

  const generateTypedSchema = z.object({
    prompt: z.string().min(1).max(2000),
    artifactType: z.enum(["alert_rule", "workflow", "report", "query", "dashboard", "investigation"]),
  });

  app.post(
    "/api/prompt-artifact/generate-typed",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const parsed = generateTypedSchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid request", errors: parsed.error.flatten().fieldErrors });
        }
        const orgId = getOrgId(req);

        const typeHint = `[Generate ${parsed.data.artifactType.replace(/_/g, " ")}] `;
        const generated = runInvestigation(typeHint + parsed.data.prompt, orgId);

        const saved = await promptStorage.createPromptInvestigation({
          id: generated.id,
          orgId,
          prompt: generated.prompt,
          intent: generated.intent,
          status: generated.status,
          summary: generated.summary,
          steps: generated.steps as unknown as Record<string, unknown>,
          artifacts: generated.artifacts as unknown as Record<string, unknown>,
          citations: generated.citations as unknown as Record<string, unknown>,
          completedAt: generated.completedAt ? new Date(generated.completedAt) : null,
        });

        res.json(saved);
      } catch (error) {
        log.error("Typed generation error", { error: String(error) });
        res.status(500).json({ message: "Failed to generate typed artifact" });
      }
    },
  );
}
