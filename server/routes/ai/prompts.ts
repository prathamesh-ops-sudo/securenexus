import type { Express, Request, Response } from "express";
import { logger, p, getOrgId } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole } from "../../rbac";
import { getAllRegisteredPrompts, getPromptCatalogSummary, getPromptAuditLog, getPromptVersionHistory } from "../../ai";
import {
  getAbTestsByPrompt,
  createAbTest,
  updateAbTest,
  getQualityScoresByPrompt,
  createQualityScore,
} from "../../storage/prompt-ab-tests";

const log = logger.child("routes-ai-prompts");

// --- Prompt A/B Testing (DB-backed via prompt_ab_tests table) ---

// --- Prompt Variable Documentation ---

interface PromptVariable {
  name: string;
  description: string;
  required: boolean;
  exampleValue: string;
  type: "string" | "number" | "array" | "object" | "boolean";
}

function extractPromptVariables(template: string): PromptVariable[] {
  const varRegex = /\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g;
  const found = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = varRegex.exec(template)) !== null) {
    found.add(match[1]);
  }

  const KNOWN_VARS: Record<
    string,
    { description: string; required: boolean; example: string; type: PromptVariable["type"] }
  > = {
    alert_title: {
      description: "Title of the alert being analyzed",
      required: true,
      example: "Suspicious PowerShell Execution",
      type: "string",
    },
    severity: { description: "Alert severity level", required: true, example: "high", type: "string" },
    ioc_list: {
      description: "List of Indicators of Compromise",
      required: false,
      example: "192.168.1.100, evil.com, abc123.exe",
      type: "string",
    },
    alert_description: {
      description: "Detailed description of the alert",
      required: true,
      example: "PowerShell process spawned with encoded command...",
      type: "string",
    },
    source_ip: { description: "Source IP address involved", required: false, example: "10.0.0.50", type: "string" },
    dest_ip: { description: "Destination IP address", required: false, example: "203.0.113.45", type: "string" },
    alert_source: {
      description: "Source system that generated the alert",
      required: false,
      example: "CrowdStrike",
      type: "string",
    },
    category: { description: "Alert category classification", required: false, example: "malware", type: "string" },
    mitre_techniques: {
      description: "MITRE ATT&CK technique IDs",
      required: false,
      example: "T1059.001, T1027",
      type: "string",
    },
    timestamp: {
      description: "Event timestamp in ISO 8601",
      required: false,
      example: "2026-03-15T14:30:00Z",
      type: "string",
    },
    context: {
      description: "Additional investigation context",
      required: false,
      example: "Previous alerts from same host...",
      type: "string",
    },
    correlated_alerts: {
      description: "JSON array of related alert data",
      required: false,
      example: '[{"id": "alert-1", "title": "..."}]',
      type: "array",
    },
    user_question: {
      description: "Analyst's question or investigation query",
      required: false,
      example: "What lateral movement indicators exist?",
      type: "string",
    },
    raw_log: {
      description: "Raw log data for analysis",
      required: false,
      example: "Mar 15 14:30:01 server sshd[1234]: Failed password...",
      type: "string",
    },
  };

  return Array.from(found).map((name) => {
    const known = KNOWN_VARS[name];
    return {
      name,
      description: known?.description || "Template variable",
      required: known?.required ?? false,
      exampleValue: known?.example || `example_${name}`,
      type: known?.type || "string",
    };
  });
}

// --- Prompt Template Categories ---

const PROMPT_CATEGORIES: Record<string, { label: string; description: string; tiers: string[] }> = {
  triage: { label: "Triage", description: "Initial alert classification and severity assessment", tiers: ["triage"] },
  investigation: {
    label: "Investigation",
    description: "Deep-dive analysis and threat hunting",
    tiers: ["narrative", "correlation"],
  },
  summarization: {
    label: "Summarization",
    description: "Executive summaries and report generation",
    tiers: ["narrative", "general"],
  },
  rule_generation: {
    label: "Rule Generation",
    description: "Detection rule and YARA/Sigma authoring",
    tiers: ["general"],
  },
  report_generation: {
    label: "Report Generation",
    description: "Compliance and incident reports",
    tiers: ["general", "narrative"],
  },
  health: {
    label: "Health & Monitoring",
    description: "System health checks and operational monitoring",
    tiers: ["health"],
  },
};

// --- Prompt Quality Scoring (DB-backed via prompt_quality_scores table) ---

export function registerAiPromptsRoutes(app: Express): void {
  app.get("/api/ai/prompts", isAuthenticated, async (_req, res) => {
    try {
      const prompts = await getAllRegisteredPrompts();
      const summary = await getPromptCatalogSummary();
      res.json({ prompts, summary });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt catalog" });
    }
  });

  app.get("/api/ai/prompts/categories", isAuthenticated, async (_req, res) => {
    try {
      const prompts = await getAllRegisteredPrompts();
      const categorized: Record<
        string,
        { category: string; label: string; description: string; promptCount: number; promptIds: string[] }
      > = {};
      for (const [catId, cat] of Object.entries(PROMPT_CATEGORIES)) {
        const matching = prompts.filter((p2) => cat.tiers.includes(p2.tier) || p2.tags.includes(catId));
        categorized[catId] = {
          category: catId,
          label: cat.label,
          description: cat.description,
          promptCount: matching.length,
          promptIds: matching.map((m) => m.id),
        };
      }
      res.json(categorized);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt categories" });
    }
  });

  app.get("/api/ai/prompts/:id", isAuthenticated, async (req, res) => {
    try {
      const prompts = await getAllRegisteredPrompts();
      const prompt = prompts.find((pt) => pt.id === p(req.params.id));
      if (!prompt) return res.status(404).json({ message: "Prompt not found" });
      res.json(prompt);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt" });
    }
  });

  app.get("/api/ai/prompts/:id/history", isAuthenticated, async (req, res) => {
    try {
      const history = await getPromptVersionHistory(p(req.params.id));
      if (history.length === 0) return res.status(404).json({ message: "No version history found for prompt" });
      res.json(history);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt version history" });
    }
  });

  app.get("/api/ai/prompts/:id/audit", isAuthenticated, async (req, res) => {
    try {
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "50"), 10) || 50, 1), 200);
      const auditEntries = await getPromptAuditLog(p(req.params.id), limit);
      res.json(auditEntries);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch prompt audit log" });
    }
  });

  app.get("/api/ai/audit", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "100"), 10) || 100, 1), 500);
      const auditEntries = await getPromptAuditLog(undefined, limit);
      res.json(auditEntries);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch AI audit log" });
    }
  });

  // A/B Tests
  app.get("/api/ai/prompts/:id/ab-tests", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const promptId = p(req.params.id);
      const tests = await getAbTestsByPrompt(orgId, promptId);
      res.json(tests);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch A/B tests" });
    }
  });

  app.post(
    "/api/ai/prompts/:id/ab-tests",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const promptId = p(req.params.id);
        const { versionA, versionB, sampleSize } = req.body;
        if (!versionA || !versionB || versionA === versionB) {
          return res.status(400).json({ message: "versionA and versionB must be different valid versions" });
        }
        const test = await createAbTest({
          orgId,
          promptId,
          versionA: Number(versionA),
          versionB: Number(versionB),
          status: "running",
          sampleSize: Math.min(Math.max(Number(sampleSize) || 100, 10), 10000),
          results: {
            versionA: { avgQuality: 0, avgLatencyMs: 0, avgSatisfaction: 0, sampleCount: 0 },
            versionB: { avgQuality: 0, avgLatencyMs: 0, avgSatisfaction: 0, sampleCount: 0 },
          },
        });
        res.status(201).json(test);
      } catch (error) {
        res.status(500).json({ message: "Failed to create A/B test" });
      }
    },
  );

  app.patch(
    "/api/ai/prompts/:id/ab-tests/:testId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const testId = p(req.params.testId);
        const { status } = req.body;
        if (!status || !["running", "completed", "paused"].includes(status)) {
          return res.status(400).json({ message: "status must be running, completed, or paused" });
        }
        const updates: { status: string; completedAt?: Date } = { status };
        if (status === "completed") updates.completedAt = new Date();
        const test = await updateAbTest(testId, updates);
        if (!test) return res.status(404).json({ message: "A/B test not found" });
        res.json(test);
      } catch (error) {
        res.status(500).json({ message: "Failed to update A/B test" });
      }
    },
  );

  // Variables
  app.get("/api/ai/prompts/:id/variables", isAuthenticated, async (req, res) => {
    try {
      const prompts = await getAllRegisteredPrompts();
      const prompt = prompts.find((pt) => pt.id === p(req.params.id));
      if (!prompt) return res.status(404).json({ message: "Prompt not found" });
      const variables = extractPromptVariables(prompt.userTemplate);
      res.json({ promptId: prompt.id, promptName: prompt.name, variables });
    } catch (error) {
      res.status(500).json({ message: "Failed to extract prompt variables" });
    }
  });

  // Quality Scores
  app.get("/api/ai/prompts/:id/quality-scores", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const promptId = p(req.params.id);
      const scores = await getQualityScoresByPrompt(orgId, promptId);
      res.json(scores);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch quality scores" });
    }
  });

  app.post(
    "/api/ai/prompts/:id/quality-scores",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const promptId = p(req.params.id);
        const { version, relevance, accuracy, actionability, formatCompliance, sampleOutput } = req.body;
        if (
          typeof relevance !== "number" ||
          typeof accuracy !== "number" ||
          typeof actionability !== "number" ||
          typeof formatCompliance !== "number"
        ) {
          return res
            .status(400)
            .json({ message: "relevance, accuracy, actionability, formatCompliance must be numbers (0-100)" });
        }
        const clamp = (v: number) => Math.max(0, Math.min(100, v));
        const r = clamp(relevance);
        const a = clamp(accuracy);
        const act = clamp(actionability);
        const fc = clamp(formatCompliance);
        const overall = Math.round((r + a + act + fc) / 4);
        const score = await createQualityScore({
          orgId,
          promptId,
          version: Number(version) || 1,
          relevance: r,
          accuracy: a,
          actionability: act,
          formatCompliance: fc,
          overall,
          sampleOutput: String(sampleOutput || "").slice(0, 5000),
        });
        res.status(201).json(score);
      } catch (error) {
        res.status(500).json({ message: "Failed to record quality score" });
      }
    },
  );

  // Prompt Rollback with Safety Checks
  app.post(
    "/api/ai/prompts/:id/rollback",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const promptId = p(req.params.id);
        const { targetVersion } = req.body;
        if (!targetVersion || typeof targetVersion !== "number") {
          return res.status(400).json({ message: "targetVersion (number) is required" });
        }

        const prompts = await getAllRegisteredPrompts();
        const current = prompts.find((pt) => pt.id === promptId);
        if (!current) return res.status(404).json({ message: "Prompt not found" });

        const history = await getPromptVersionHistory(promptId);
        const target = history.find((h) => h.version === targetVersion);
        if (!target) return res.status(404).json({ message: `Version ${targetVersion} not found in history` });

        const currentVars = extractPromptVariables(current.userTemplate);
        const targetVars = extractPromptVariables(target.userTemplate);
        const currentVarNames = new Set(currentVars.map((v) => v.name));
        const targetVarNames = new Set(targetVars.map((v) => v.name));

        const newVarsInTarget = Array.from(targetVarNames).filter((v) => !currentVarNames.has(v));
        const removedVars = Array.from(currentVarNames).filter((v) => !targetVarNames.has(v));

        const warnings: string[] = [];
        if (newVarsInTarget.length > 0) {
          warnings.push(`Target version introduces variables not in current: ${newVarsInTarget.join(", ")}`);
        }
        if (removedVars.length > 0) {
          warnings.push(`Rolling back will remove variables: ${removedVars.join(", ")}`);
        }

        const currentSchema = current.outputSchema ? Object.keys(current.outputSchema) : [];
        const targetSchema = target.outputSchema ? Object.keys(target.outputSchema) : [];
        const schemaChanges = currentSchema.filter((k) => !targetSchema.includes(k));
        if (schemaChanges.length > 0) {
          warnings.push(`Output schema fields removed in target: ${schemaChanges.join(", ")}`);
        }

        const safetyResult = {
          safe: warnings.length === 0,
          warnings,
          currentVersion: current.version,
          targetVersion,
          variableCompatibility: {
            current: Array.from(currentVarNames),
            target: Array.from(targetVarNames),
            added: newVarsInTarget,
            removed: removedVars,
          },
        };

        if (req.query.dryRun === "true") {
          return res.json({ dryRun: true, ...safetyResult });
        }

        const { registerPrompt: regPrompt } = await import("../../ai/prompt-registry");
        await regPrompt({
          ...target,
          version: current.version + 1,
          deprecated: false,
          deprecatedAt: undefined,
          supersededBy: undefined,
        });

        res.json({
          rolled: true,
          newVersion: current.version + 1,
          ...safetyResult,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to rollback prompt" });
      }
    },
  );
}
