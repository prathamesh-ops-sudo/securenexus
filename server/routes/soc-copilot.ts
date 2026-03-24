import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getCopilotTriages,
  getTriageById,
  generateTriage,
  updateTriageNotes,
  getCopilotTimelines,
  getTimelineById,
  getCopilotHypotheses,
  updateHypothesisStatus,
  getCopilotActions,
  approveAction,
  rejectAction,
  rollbackAction,
  getCopilotFeedback,
  submitFeedback,
  getCopilotCalibrations,
  getCopilotStats,
  type ActionClass,
  type ActionStatus,
  type TriageVerdict,
  type HypothesisConfidence,
  type FeedbackOutcome,
  type CopilotDomain,
} from "../soc-copilot-engine";

const VALID_VERDICTS: TriageVerdict[] = ["true_positive", "false_positive", "needs_investigation", "benign"];
const VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"];
const VALID_ACTION_CLASSES: ActionClass[] = ["READ", "SUGGEST", "EXECUTE_WITH_APPROVAL", "AUTO_EXECUTE_LOW_RISK"];
const VALID_ACTION_STATUSES: ActionStatus[] = [
  "pending_approval",
  "approved",
  "rejected",
  "executed",
  "rolled_back",
  "auto_executed",
];
const VALID_HYPOTHESIS_CONFIDENCES: HypothesisConfidence[] = ["high", "medium", "low"];
const VALID_HYPOTHESIS_STATUSES = ["active", "confirmed", "rejected", "superseded"];
const VALID_FEEDBACK_OUTCOMES: FeedbackOutcome[] = ["accepted", "overridden", "dismissed"];
const VALID_COPILOT_DOMAINS: CopilotDomain[] = ["triage", "timeline", "hypothesis", "enrichment", "policy"];

export function registerSocCopilotRoutes(app: Express): void {
  app.get("/api/soc-copilot/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getCopilotStats(orgId));
    } catch (error) {
      logger.child("routes").error("SOC copilot stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch SOC copilot stats" });
    }
  });

  app.get("/api/soc-copilot/triages", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { verdict?: TriageVerdict; severity?: string } = {};
      if (typeof req.query.verdict === "string" && VALID_VERDICTS.includes(req.query.verdict as TriageVerdict))
        filters.verdict = req.query.verdict as TriageVerdict;
      if (typeof req.query.severity === "string" && VALID_SEVERITIES.includes(req.query.severity))
        filters.severity = req.query.severity;
      res.json(getCopilotTriages(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot triages error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch triages" });
    }
  });

  app.get("/api/soc-copilot/triages/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const triage = getTriageById(orgId, id);
      if (!triage) return res.status(404).json({ message: "Triage not found" });
      res.json(triage);
    } catch (error) {
      logger.child("routes").error("Get triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch triage" });
    }
  });

  app.post("/api/soc-copilot/triages", isAuthenticated, async (req, res) => {
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
      const triage = generateTriage(orgId, alertId, alertTitle, severity);
      res.status(201).json(triage);
    } catch (error) {
      logger.child("routes").error("Generate triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to generate triage" });
    }
  });

  app.patch("/api/soc-copilot/triages/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { analystNotes } = req.body as { analystNotes?: string };
      if (analystNotes === undefined || typeof analystNotes !== "string")
        return res.status(400).json({ message: "analystNotes must be a string" });
      const updated = updateTriageNotes(orgId, id, analystNotes);
      if (!updated) return res.status(404).json({ message: "Triage not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update triage error", { error: String(error) });
      res.status(500).json({ message: "Failed to update triage" });
    }
  });

  app.get("/api/soc-copilot/timelines", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getCopilotTimelines(orgId));
    } catch (error) {
      logger.child("routes").error("SOC copilot timelines error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch timelines" });
    }
  });

  app.get("/api/soc-copilot/timelines/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const timeline = getTimelineById(orgId, id);
      if (!timeline) return res.status(404).json({ message: "Timeline not found" });
      res.json(timeline);
    } catch (error) {
      logger.child("routes").error("Get timeline error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch timeline" });
    }
  });

  app.get("/api/soc-copilot/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { incidentId?: string; confidence?: HypothesisConfidence; status?: string } = {};
      if (typeof req.query.incidentId === "string") filters.incidentId = req.query.incidentId;
      if (
        typeof req.query.confidence === "string" &&
        VALID_HYPOTHESIS_CONFIDENCES.includes(req.query.confidence as HypothesisConfidence)
      )
        filters.confidence = req.query.confidence as HypothesisConfidence;
      if (typeof req.query.status === "string" && VALID_HYPOTHESIS_STATUSES.includes(req.query.status))
        filters.status = req.query.status;
      res.json(getCopilotHypotheses(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot hypotheses error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch hypotheses" });
    }
  });

  app.patch("/api/soc-copilot/hypotheses/:id", isAuthenticated, async (req, res) => {
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
      const feedback = typeof body.analystFeedback === "string" ? body.analystFeedback : undefined;
      const updated = updateHypothesisStatus(orgId, id, body.status, feedback);
      if (!updated) return res.status(404).json({ message: "Hypothesis not found" });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Update hypothesis error", { error: String(error) });
      res.status(500).json({ message: "Failed to update hypothesis" });
    }
  });

  app.get("/api/soc-copilot/actions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { actionClass?: ActionClass; status?: ActionStatus } = {};
      if (
        typeof req.query.actionClass === "string" &&
        VALID_ACTION_CLASSES.includes(req.query.actionClass as ActionClass)
      )
        filters.actionClass = req.query.actionClass as ActionClass;
      if (typeof req.query.status === "string" && VALID_ACTION_STATUSES.includes(req.query.status as ActionStatus))
        filters.status = req.query.status as ActionStatus;
      res.json(getCopilotActions(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot actions error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch actions" });
    }
  });

  app.post("/api/soc-copilot/actions/:id/approve", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { analystId } = req.body as { analystId?: string };
      if (!analystId || typeof analystId !== "string")
        return res.status(400).json({ message: "analystId is required" });
      const result = approveAction(orgId, id, analystId);
      if (!result) return res.status(404).json({ message: "Action not found or not pending approval" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Approve action error", { error: String(error) });
      res.status(500).json({ message: "Failed to approve action" });
    }
  });

  app.post("/api/soc-copilot/actions/:id/reject", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { analystId } = req.body as { analystId?: string };
      if (!analystId || typeof analystId !== "string")
        return res.status(400).json({ message: "analystId is required" });
      const result = rejectAction(orgId, id, analystId);
      if (!result) return res.status(404).json({ message: "Action not found or not pending approval" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Reject action error", { error: String(error) });
      res.status(500).json({ message: "Failed to reject action" });
    }
  });

  app.post("/api/soc-copilot/actions/:id/rollback", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const result = rollbackAction(orgId, id);
      if (!result) return res.status(404).json({ message: "Action not found or not eligible for rollback" });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Rollback action error", { error: String(error) });
      res.status(500).json({ message: "Failed to rollback action" });
    }
  });

  app.get("/api/soc-copilot/feedback", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters: { actionType?: CopilotDomain; outcome?: FeedbackOutcome } = {};
      if (
        typeof req.query.actionType === "string" &&
        VALID_COPILOT_DOMAINS.includes(req.query.actionType as CopilotDomain)
      )
        filters.actionType = req.query.actionType as CopilotDomain;
      if (
        typeof req.query.outcome === "string" &&
        VALID_FEEDBACK_OUTCOMES.includes(req.query.outcome as FeedbackOutcome)
      )
        filters.outcome = req.query.outcome as FeedbackOutcome;
      res.json(getCopilotFeedback(orgId, filters));
    } catch (error) {
      logger.child("routes").error("SOC copilot feedback error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch feedback" });
    }
  });

  app.post("/api/soc-copilot/feedback", isAuthenticated, async (req, res) => {
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
      if (!body.originalSuggestion || typeof body.originalSuggestion !== "string")
        return res.status(400).json({ message: "originalSuggestion is required" });
      if (!body.reason || typeof body.reason !== "string")
        return res.status(400).json({ message: "reason is required" });

      const record = submitFeedback(orgId, {
        actionId: body.actionId,
        actionType: body.actionType,
        outcome: body.outcome,
        analystId: body.analystId,
        originalSuggestion: body.originalSuggestion,
        analystOverride: typeof body.analystOverride === "string" ? body.analystOverride : null,
        reason: body.reason,
        impactOnPolicy: typeof body.impactOnPolicy === "string" ? body.impactOnPolicy : null,
      });
      res.status(201).json(record);
    } catch (error) {
      logger.child("routes").error("Submit feedback error", { error: String(error) });
      res.status(500).json({ message: "Failed to submit feedback" });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════════
  // 31.4 Conversation Memory Across Sessions
  // ══════════════════════════════════════════════════════════════════════════════
  app.get("/api/soc-copilot/conversations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = (req as any).user?.id || "anonymous";
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "20"), 10) || 20, 1), 100);

      // Return stored conversations for this user+org
      // In production, these would be persisted in a copilot_conversations table
      res.json({
        conversations: [],
        total: 0,
        userId,
        orgId,
        limit,
      });
    } catch (error) {
      logger.child("routes").error("Copilot conversations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch conversations" });
    }
  });

  app.post("/api/soc-copilot/conversations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = (req as any).user?.id || "anonymous";
      const { title, context, messages = [] } = req.body;

      if (!title || typeof title !== "string") {
        return res.status(400).json({ message: "title is required" });
      }

      const conversation = {
        id: `conv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
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
  });

  app.post("/api/soc-copilot/conversations/:id/messages", isAuthenticated, async (req, res) => {
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
        id: `msg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
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
  });

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

      res.json({
        skills,
        totalSkills: skills.length,
        categories: Array.from(new Set(skills.map((s) => s.category))),
      });
    } catch (error) {
      logger.child("routes").error("Copilot skills error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch skills" });
    }
  });

  app.post("/api/soc-copilot/skills/route", isAuthenticated, async (req, res) => {
    try {
      const { query } = req.body;
      if (!query || typeof query !== "string") {
        return res.status(400).json({ message: "query is required" });
      }

      // Simple keyword-based skill routing
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
        if (matchCount > 0) {
          scores.push({ skillId, score: matchCount / keywords.length });
        }
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
  });

  app.get("/api/soc-copilot/calibrations", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      res.json(getCopilotCalibrations(orgId));
    } catch (error) {
      logger.child("routes").error("SOC copilot calibrations error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch calibrations" });
    }
  });
}
