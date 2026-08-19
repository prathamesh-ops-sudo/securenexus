/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes } from "crypto";
import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

import * as storage from "../storage/soc-copilot";

const VALID_VERDICTS = ["true_positive", "false_positive", "needs_investigation", "benign"];
const VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"];
const VALID_ACTION_CLASSES = ["READ", "SUGGEST", "EXECUTE_WITH_APPROVAL", "AUTO_EXECUTE_LOW_RISK"];
const VALID_ACTION_STATUSES = ["pending_approval", "approved", "rejected", "executed", "rolled_back", "auto_executed"];
const VALID_HYPOTHESIS_CONFIDENCES = ["high", "medium", "low"];
const VALID_HYPOTHESIS_STATUSES = ["active", "confirmed", "rejected", "superseded"];
const VALID_FEEDBACK_OUTCOMES = ["accepted", "overridden", "dismissed"];
const VALID_COPILOT_DOMAINS = ["triage", "timeline", "hypothesis", "enrichment", "policy"];

export function registerSocCopilotRoutes(app: Express): void {
  app.get("/api/soc-copilot/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const emptyArr: never[] = [];
      const [triages, actions, hypotheses, feedback] = await Promise.all([
        storage.getCopilotTriages(orgId).catch(() => emptyArr),
        storage.getCopilotActions(orgId).catch(() => emptyArr),
        storage.getCopilotHypotheses(orgId).catch(() => emptyArr),
        storage.getCopilotFeedback(orgId).catch(() => emptyArr),
      ]);

      const autoExecuted = actions.filter((a: any) => a.status === "auto_executed");
      const pendingApprovals = actions.filter((a: any) => a.status === "pending_approval");

      const accepted = feedback.filter((f: any) => f.outcome === "accepted");
      const overridden = feedback.filter((f: any) => f.outcome === "overridden");
      const acceptanceRate = feedback.length > 0 ? Math.round((accepted.length / feedback.length) * 100) : 0;
      const overrideRate = feedback.length > 0 ? Math.round((overridden.length / feedback.length) * 100) : 0;

      const totalConfidence = triages.reduce((sum: number, t: any) => sum + (t.confidence ?? 0), 0);
      const avgConfidence = triages.length > 0 ? totalConfidence / triages.length : 0;

      const byDomain: Record<string, { total: number; accepted: number; overridden: number }> = {};
      for (const f of feedback) {
        const domain = (f as any).domain || "general";
        if (!byDomain[domain]) byDomain[domain] = { total: 0, accepted: 0, overridden: 0 };
        byDomain[domain].total++;
        if ((f as any).outcome === "accepted") byDomain[domain].accepted++;
        if ((f as any).outcome === "overridden") byDomain[domain].overridden++;
      }

      const byActionClass: Record<string, { total: number; executed: number; rejected: number }> = {};
      for (const a of actions) {
        const cls = (a as any).actionClass || "SUGGEST";
        if (!byActionClass[cls]) byActionClass[cls] = { total: 0, executed: 0, rejected: 0 };
        byActionClass[cls].total++;
        if ((a as any).status === "executed" || (a as any).status === "auto_executed") byActionClass[cls].executed++;
        if ((a as any).status === "rejected") byActionClass[cls].rejected++;
      }

      res.json({
        totalTriages: triages.length,
        totalTimelines: 0,
        totalHypotheses: hypotheses.length,
        totalActions: actions.length,
        autoExecutedActions: autoExecuted.length,
        pendingApprovals: pendingApprovals.length,
        feedbackCount: feedback.length,
        acceptanceRate,
        overrideRate,
        avgConfidence,
        byDomain,
        byActionClass,
        recentCalibrations: 0,
        triagesByVerdict: VALID_VERDICTS.reduce(
          (acc, v) => {
            acc[v] = triages.filter((t: any) => t.verdict === v).length;
            return acc;
          },
          {} as Record<string, number>,
        ),
        actionsByStatus: VALID_ACTION_STATUSES.reduce(
          (acc, s) => {
            acc[s] = actions.filter((a: any) => a.status === s).length;
            return acc;
          },
          {} as Record<string, number>,
        ),
      });
    } catch (error) {
      logger.child("routes").error("SOC copilot stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch SOC copilot stats" });
    }
  });

  app.get("/api/soc-copilot/triages", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      let triages = await storage.getCopilotTriages(orgId);
      if (typeof req.query.verdict === "string" && VALID_VERDICTS.includes(req.query.verdict))
        triages = triages.filter((t) => t.verdict === req.query.verdict);
      if (typeof req.query.severity === "string" && VALID_SEVERITIES.includes(req.query.severity))
        triages = triages.filter((t) => t.severity === req.query.severity);
      res.json(triages);
    } catch (error) {
      logger.child("routes").error("SOC copilot triages error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch triages" });
    }
  });

  app.get("/api/soc-copilot/triages/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const triage = await storage.getCopilotTriage(id);
      if (!triage || triage.orgId !== orgId) return res.status(404).json({ message: "Triage not found" });
      res.json(triage);
    } catch (error) {
      logger.child("routes").error("Get triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch triage" });
    }
  });

  app.post(
    "/api/soc-copilot/triages",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { alertId, alertTitle, severity } = req.body as {
          alertId?: string;
          alertTitle?: string;
          severity?: string;
        };
        if (!alertId || typeof alertId !== "string") return res.status(400).json({ message: "alertId is required" });
        if (!alertTitle || typeof alertTitle !== "string")
          return res.status(400).json({ message: "alertTitle is required" });
        if (!severity || !VALID_SEVERITIES.includes(severity))
          return res.status(400).json({ message: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` });
        const triage = await storage.createCopilotTriage({
          orgId,
          alertId,
          alertTitle,
          severity,
          verdict: "needs_investigation",
          confidence: 0,
          reasoning: "Pending AI analysis",
          suggestedActions: [],
          relatedAlerts: [],
        });
        res.status(201).json(triage);
      } catch (error) {
        logger.child("routes").error("Generate triage error", { error: String(error) });
        res.status(500).json({ message: "Failed to generate triage" });
      }
    },
  );

  app.patch(
    "/api/soc-copilot/triages/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { analystNotes } = req.body as { analystNotes?: string };
        if (analystNotes === undefined || typeof analystNotes !== "string")
          return res.status(400).json({ message: "analystNotes must be a string" });
        const existing = await storage.getCopilotTriage(id);
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Triage not found" });
        const updated = await storage.updateCopilotTriage(id, { analystNotes });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Update triage error", { error: String(error) });
        res.status(500).json({ message: "Failed to update triage" });
      }
    },
  );

  app.get("/api/soc-copilot/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      let hypotheses = await storage.getCopilotHypotheses(orgId);
      if (typeof req.query.confidence === "string" && VALID_HYPOTHESIS_CONFIDENCES.includes(req.query.confidence))
        hypotheses = hypotheses.filter((h) => h.confidence === req.query.confidence);
      if (typeof req.query.status === "string" && VALID_HYPOTHESIS_STATUSES.includes(req.query.status))
        hypotheses = hypotheses.filter((h) => h.status === req.query.status);
      if (typeof req.query.incidentId === "string")
        hypotheses = hypotheses.filter((h) => h.incidentId === req.query.incidentId);
      res.json(hypotheses);
    } catch (error) {
      logger.child("routes").error("SOC copilot hypotheses error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch hypotheses" });
    }
  });

  app.patch(
    "/api/soc-copilot/hypotheses/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const body = req.body;
        if (body.status !== undefined && !VALID_HYPOTHESIS_STATUSES.includes(body.status)) {
          return res.status(400).json({ message: `status must be one of: ${VALID_HYPOTHESIS_STATUSES.join(", ")}` });
        }
        if (body.status === undefined) {
          return res.status(400).json({ message: "status is required" });
        }
        const existing = await storage.getCopilotHypothesis(id);
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Hypothesis not found" });
        const updated = await storage.updateCopilotHypothesis(id, {
          status: body.status,
          analystVerdict: typeof body.analystFeedback === "string" ? body.analystFeedback : existing.analystVerdict,
        });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Update hypothesis error", { error: String(error) });
        res.status(500).json({ message: "Failed to update hypothesis" });
      }
    },
  );

  app.get("/api/soc-copilot/actions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      let actions = await storage.getCopilotActions(orgId);
      if (typeof req.query.actionClass === "string" && VALID_ACTION_CLASSES.includes(req.query.actionClass))
        actions = actions.filter((a) => a.actionClass === req.query.actionClass);
      if (typeof req.query.status === "string" && VALID_ACTION_STATUSES.includes(req.query.status))
        actions = actions.filter((a) => a.status === req.query.status);
      res.json(actions);
    } catch (error) {
      logger.child("routes").error("SOC copilot actions error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch actions" });
    }
  });

  app.post(
    "/api/soc-copilot/actions/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { analystId } = req.body as { analystId?: string };
        if (!analystId || typeof analystId !== "string")
          return res.status(400).json({ message: "analystId is required" });
        const action = await storage.getCopilotAction(id);
        if (!action || action.orgId !== orgId || action.status !== "pending_approval")
          return res.status(404).json({ message: "Action not found or not pending approval" });
        const updated = await storage.updateCopilotAction(id, {
          status: "approved",
          approvedBy: analystId,
          approvedAt: new Date(),
        });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Approve action error", { error: String(error) });
        res.status(500).json({ message: "Failed to approve action" });
      }
    },
  );

  app.post(
    "/api/soc-copilot/actions/:id/reject",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { analystId } = req.body as { analystId?: string };
        if (!analystId || typeof analystId !== "string")
          return res.status(400).json({ message: "analystId is required" });
        const action = await storage.getCopilotAction(id);
        if (!action || action.orgId !== orgId || action.status !== "pending_approval")
          return res.status(404).json({ message: "Action not found or not pending approval" });
        const updated = await storage.updateCopilotAction(id, { status: "rejected" });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Reject action error", { error: String(error) });
        res.status(500).json({ message: "Failed to reject action" });
      }
    },
  );

  app.post(
    "/api/soc-copilot/actions/:id/rollback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const action = await storage.getCopilotAction(id);
        if (!action || action.orgId !== orgId || !["executed", "auto_executed"].includes(action.status))
          return res.status(404).json({ message: "Action not found or not eligible for rollback" });
        const updated = await storage.updateCopilotAction(id, { status: "rolled_back" });
        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Rollback action error", { error: String(error) });
        res.status(500).json({ message: "Failed to rollback action" });
      }
    },
  );

  app.get("/api/soc-copilot/feedback", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      let feedback = await storage.getCopilotFeedback(orgId);
      if (typeof req.query.actionType === "string" && VALID_COPILOT_DOMAINS.includes(req.query.actionType))
        feedback = feedback.filter((f) => f.domain === req.query.actionType);
      if (typeof req.query.outcome === "string" && VALID_FEEDBACK_OUTCOMES.includes(req.query.outcome))
        feedback = feedback.filter((f) => f.outcome === req.query.outcome);
      res.json(feedback);
    } catch (error) {
      logger.child("routes").error("SOC copilot feedback error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch feedback" });
    }
  });

  app.post(
    "/api/soc-copilot/feedback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = req.body;
        if (!body.actionId || typeof body.actionId !== "string")
          return res.status(400).json({ message: "actionId is required" });
        if (!body.actionType || !VALID_COPILOT_DOMAINS.includes(body.actionType))
          return res.status(400).json({ message: `actionType must be one of: ${VALID_COPILOT_DOMAINS.join(", ")}` });
        if (!body.outcome || !VALID_FEEDBACK_OUTCOMES.includes(body.outcome))
          return res.status(400).json({ message: `outcome must be one of: ${VALID_FEEDBACK_OUTCOMES.join(", ")}` });
        if (!body.analystId || typeof body.analystId !== "string")
          return res.status(400).json({ message: "analystId is required" });
        if (!body.reason || typeof body.reason !== "string")
          return res.status(400).json({ message: "reason is required" });

        const record = await storage.createCopilotFeedbackEntry({
          orgId,
          domain: body.actionType,
          referenceId: body.actionId,
          outcome: body.outcome,
          analystId: body.analystId,
          comment: body.reason,
          metadata: {
            originalSuggestion: body.originalSuggestion || "",
            analystOverride: typeof body.analystOverride === "string" ? body.analystOverride : null,
            impactOnPolicy: typeof body.impactOnPolicy === "string" ? body.impactOnPolicy : null,
          },
        });
        res.status(201).json(record);
      } catch (error) {
        logger.child("routes").error("Submit feedback error", { error: String(error) });
        res.status(500).json({ message: "Failed to submit feedback" });
      }
    },
  );

  // ══════════════════════════════════════════════════════════════════════════════
  // 31.4 Conversation Memory Across Sessions
  // ══════════════════════════════════════════════════════════════════════════════
  app.get("/api/soc-copilot/conversations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = (req as any).user?.id || "anonymous";
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "20"), 10) || 20, 1), 100);
      res.json({ conversations: [], total: 0, userId, orgId, limit });
    } catch (error) {
      logger.child("routes").error("Copilot conversations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch conversations" });
    }
  });

  app.post(
    "/api/soc-copilot/conversations",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "anonymous";
        const { title, context, messages = [] } = req.body;
        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }
        const conversation = {
          id: `conv_${Date.now()}_${randomBytes(4).toString("hex")}`,
          orgId,
          userId,
          title: title.slice(0, 200),
          context: context || null,
          messages: Array.isArray(messages) ? messages : [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        res.status(201).json(conversation);
      } catch (error) {
        logger.child("routes").error("Create conversation error", { error: String(error) });
        res.status(500).json({ message: "Failed to create conversation" });
      }
    },
  );

  app.post(
    "/api/soc-copilot/conversations/:id/messages",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const conversationId = String(req.params.id);
        const { role, content } = req.body;
        if (!role || !["user", "assistant"].includes(role)) {
          return res.status(400).json({ message: "role must be 'user' or 'assistant'" });
        }
        if (!content || typeof content !== "string") {
          return res.status(400).json({ message: "content is required" });
        }
        const message = {
          id: `msg_${Date.now()}_${randomBytes(4).toString("hex")}`,
          conversationId,
          role,
          content: content.slice(0, 10000),
          timestamp: new Date().toISOString(),
        };
        res.status(201).json(message);
      } catch (error) {
        logger.child("routes").error("Add message error", { error: String(error) });
        res.status(500).json({ message: "Failed to add message" });
      }
    },
  );

  // ══════════════════════════════════════════════════════════════════════════════
  // 31.5 Skill-Based Routing to Specialized Prompts
  // ══════════════════════════════════════════════════════════════════════════════
  app.get("/api/soc-copilot/skills", isAuthenticated, async (_req, res) => {
    try {
      const skills = [
        {
          id: "threat_intel",
          name: "Threat Intelligence",
          description: "Analyze IOCs, threat actors, campaigns, and TTPs",
          icon: "Shield",
          keywords: ["ioc", "threat", "actor", "campaign", "ttp", "malware", "apt", "indicator"],
          promptTemplate: "You are a threat intelligence analyst. Analyze the following...",
          category: "analysis",
        },
        {
          id: "compliance",
          name: "Compliance & Audit",
          description: "Check compliance status, audit findings, and regulatory requirements",
          icon: "FileCheck",
          keywords: ["compliance", "audit", "regulation", "soc2", "gdpr", "hipaa", "pci", "nist"],
          promptTemplate: "You are a compliance specialist. Evaluate the following...",
          category: "governance",
        },
        {
          id: "remediation",
          name: "Remediation Guidance",
          description: "Provide step-by-step remediation for vulnerabilities and incidents",
          icon: "Wrench",
          keywords: ["fix", "remediate", "patch", "mitigate", "resolve", "respond", "contain"],
          promptTemplate: "You are a remediation engineer. Provide actionable steps to...",
          category: "response",
        },
        {
          id: "forensics",
          name: "Digital Forensics",
          description: "Analyze artifacts, memory dumps, disk images, and network captures",
          icon: "Microscope",
          keywords: ["forensic", "artifact", "memory", "disk", "pcap", "evidence", "timeline"],
          promptTemplate: "You are a digital forensics investigator. Analyze the following...",
          category: "investigation",
        },
        {
          id: "hunting",
          name: "Threat Hunting",
          description: "Proactive threat hunting queries and hypothesis generation",
          icon: "Crosshair",
          keywords: ["hunt", "hypothesis", "query", "search", "detect", "proactive", "sigma"],
          promptTemplate: "You are a threat hunter. Generate hunting hypotheses for...",
          category: "proactive",
        },
        {
          id: "incident_response",
          name: "Incident Response",
          description: "IR playbook execution, containment, eradication, and recovery",
          icon: "AlertTriangle",
          keywords: ["incident", "response", "playbook", "contain", "eradicate", "recover", "ir"],
          promptTemplate: "You are an incident responder. Guide the following response...",
          category: "response",
        },
        {
          id: "vulnerability_mgmt",
          name: "Vulnerability Management",
          description: "CVE analysis, risk scoring, patching priorities",
          icon: "Bug",
          keywords: ["cve", "vulnerability", "patch", "risk", "score", "epss", "cvss", "exploit"],
          promptTemplate: "You are a vulnerability management specialist. Assess the following...",
          category: "analysis",
        },
        {
          id: "cloud_security",
          name: "Cloud Security",
          description: "AWS/Azure/GCP security posture, IAM, and configuration review",
          icon: "Cloud",
          keywords: ["cloud", "aws", "azure", "gcp", "iam", "s3", "config", "cspm"],
          promptTemplate: "You are a cloud security architect. Review the following...",
          category: "infrastructure",
        },
      ];
      res.json({ skills, totalSkills: skills.length, categories: Array.from(new Set(skills.map((s) => s.category))) });
    } catch (error) {
      logger.child("routes").error("Copilot skills error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch skills" });
    }
  });

  app.post(
    "/api/soc-copilot/skills/route",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { query } = req.body;
        if (!query || typeof query !== "string") {
          return res.status(400).json({ message: "query is required" });
        }
        const skillKeywords: Record<string, string[]> = {
          threat_intel: ["ioc", "threat", "actor", "campaign", "ttp", "malware", "apt"],
          compliance: ["compliance", "audit", "regulation", "soc2", "gdpr", "hipaa"],
          remediation: ["fix", "remediate", "patch", "mitigate", "resolve"],
          forensics: ["forensic", "artifact", "memory", "disk", "pcap", "evidence"],
          hunting: ["hunt", "hypothesis", "detect", "proactive", "sigma"],
          incident_response: ["incident", "response", "playbook", "contain", "eradicate"],
          vulnerability_mgmt: ["cve", "vulnerability", "patch", "risk", "exploit"],
          cloud_security: ["cloud", "aws", "azure", "gcp", "iam", "cspm"],
        };
        const queryLower = query.toLowerCase();
        const scores: { skillId: string; score: number }[] = [];
        for (const [skillId, keywords] of Object.entries(skillKeywords)) {
          const matchCount = keywords.filter((kw) => queryLower.includes(kw)).length;
          if (matchCount > 0) scores.push({ skillId, score: matchCount / keywords.length });
        }
        scores.sort((a, b) => b.score - a.score);
        const bestMatch = scores[0] || { skillId: "threat_intel", score: 0 };
        res.json({
          query,
          routedSkill: bestMatch.skillId,
          confidence: Math.round(bestMatch.score * 100) / 100,
          alternativeSkills: scores.slice(1, 3).map((s) => s.skillId),
        });
      } catch (error) {
        logger.child("routes").error("Skill routing error", { error: String(error) });
        res.status(500).json({ message: "Failed to route query to skill" });
      }
    },
  );

  app.get("/api/soc-copilot/calibrations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const feedback = await storage.getCopilotFeedback(orgId);
      const total = feedback.length;
      const accepted = feedback.filter((f) => f.outcome === "accepted").length;
      const overridden = feedback.filter((f) => f.outcome === "overridden").length;
      const dismissed = feedback.filter((f) => f.outcome === "dismissed").length;
      res.json({
        total,
        accepted,
        overridden,
        dismissed,
        acceptanceRate: total > 0 ? accepted / total : 0,
        overrideRate: total > 0 ? overridden / total : 0,
      });
    } catch (error) {
      logger.child("routes").error("SOC copilot calibrations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch calibrations" });
    }
  });
}
