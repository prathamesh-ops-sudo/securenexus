import type { Express, Request, Response } from "express";
import { getOrgId, logger, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { requireOrgId, resolveOrgContext, requireMinRole } from "../../rbac";
import { bodySchemas, querySchemas, validateBody, validateQuery } from "../../request-validator";
import { recordFeedbackOutcome } from "../../ai/active-learning";
import { config as appConfig } from "../../config";
import { invokeModel as gatewayInvoke } from "../../ai/model-gateway";

const log = logger.child("routes-ai-feedback");

export function registerAiFeedbackRoutes(app: Express): void {
  // AI Feedback
  app.post(
    "/api/ai/feedback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    validateBody(bodySchemas.aiFeedback),
    async (req, res) => {
      try {
        const {
          resourceType,
          resourceId,
          rating,
          comment,
          aiOutput,
          correctionReason,
          correctedSeverity,
          correctedCategory,
        } = (req as any).validatedBody;
        const feedbackData: any = {
          orgId: getOrgId(req),
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          resourceType,
          resourceId,
          rating,
          comment,
          aiOutput,
        };
        if (correctionReason) feedbackData.correctionReason = correctionReason;
        if (correctedSeverity) feedbackData.correctedSeverity = correctedSeverity;
        if (correctedCategory) feedbackData.correctedCategory = correctedCategory;
        const feedback = await storage.createAiFeedback(feedbackData);
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_feedback_submitted",
          resourceType,
          resourceId,
          details: { rating, hasComment: !!comment, correctionReason, correctedSeverity, correctedCategory },
        });

        // Active Learning: process feedback for few-shot injection and FP tracking
        const orgId = (req as any).user?.orgId;
        if (orgId) {
          const isOverridden = !!(correctedSeverity || correctedCategory || correctionReason);
          const isDismissed = rating <= 2 && !isOverridden;
          const outcome = isOverridden ? "overridden" : isDismissed ? "dismissed" : "confirmed";

          let alertSource = "unknown";
          let alertCategory = "unknown";
          if (resourceType === "alert" && resourceId) {
            try {
              const alert = await storage.getAlert(resourceId);
              if (alert) {
                alertSource = alert.source || "unknown";
                alertCategory = alert.category || "unknown";
              }
            } catch {
              // non-fatal
            }
          }

          let originalAlertContext = "";
          if (resourceType === "alert" && resourceId) {
            try {
              const alertData = await storage.getAlert(resourceId);
              if (alertData) {
                originalAlertContext = JSON.stringify({
                  title: alertData.title,
                  description: alertData.description,
                  severity: alertData.severity,
                  source: alertData.source,
                  category: alertData.category,
                  sourceIp: alertData.sourceIp,
                  destIp: alertData.destIp,
                });
              }
            } catch {
              // non-fatal
            }
          }
          const aiOutputStr =
            typeof aiOutput === "object" && aiOutput !== null ? JSON.stringify(aiOutput) : String(aiOutput || "");
          const analystCorrection = [
            correctedSeverity ? `Severity: ${correctedSeverity}` : "",
            correctedCategory ? `Category: ${correctedCategory}` : "",
            comment || "",
          ]
            .filter(Boolean)
            .join("; ");

          recordFeedbackOutcome({
            orgId,
            feedbackId: feedback.id,
            outcome,
            source: alertSource,
            category: alertCategory,
            domain:
              resourceType === "correlation" ? "correlation" : resourceType === "narrative" ? "narrative" : "triage",
            originalContext: originalAlertContext || undefined,
            aiOutput: aiOutputStr || undefined,
            analystCorrection: analystCorrection || undefined,
            reason: correctionReason || comment || undefined,
          }).catch((err) =>
            logger.child("active-learning").warn("Failed to record feedback outcome", { error: String(err) }),
          );
        }

        res.status(201).json(feedback);
      } catch (error) {
        res.status(500).json({ message: "Failed to submit feedback" });
      }
    },
  );

  app.get(
    "/api/ai/feedback/metrics",
    isAuthenticated,
    validateQuery(querySchemas.feedbackMetrics),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const { days } = (req as any).validatedQuery;
        const metrics = await storage.getAiFeedbackMetrics(orgId, days);
        res.json(metrics);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feedback metrics" });
      }
    },
  );

  app.get(
    "/api/ai/feedback/:resourceType/:resourceId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feedback = await storage.getAiFeedbackByResource(
          orgId,
          String(req.params.resourceType),
          String(req.params.resourceId),
        );
        res.json(feedback);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feedback for resource" });
      }
    },
  );

  app.get(
    "/api/ai/feedback",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    validateQuery(querySchemas.aiFeedbackByQuery),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { resourceType, resourceId } = (req as any).validatedQuery;
        const feedback = await storage.getAiFeedback(orgId, resourceType as string, resourceId as string);
        res.json(feedback);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feedback" });
      }
    },
  );

  // Playbook Authoring Propose
  app.post(
    "/api/ai/playbook-authoring/propose",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const PROPOSAL_TIMEOUT_MS = 30_000;
      const plog = logger.child("ai-playbook-propose");
      try {
        const { objective, severity = "high", guardrails = [] } = req.body || {};
        const normalized = String(objective || "Contain suspicious activity").trim();
        const orgId: string | undefined = (req as any).orgId || (req as any).user?.orgId;

        const blocked = new Set(["delete_data", "shutdown_network", "disable_logging"]);
        const fallbackActions = [
          { type: "auto_triage", reason: "Initial enrichment and classification" },
          { type: "assign_analyst", reason: "Ensure analyst ownership" },
          severity === "critical"
            ? { type: "isolate_host", reason: "Containment for critical blast radius" }
            : { type: "notify_slack", reason: "Notify response channel" },
        ].filter((a) => !blocked.has(a.type));

        const fallbackResponse = {
          objective: normalized,
          guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
          proposedActions: fallbackActions,
          requiresAnalystApproval: true,
          source: "fallback" as const,
        };

        const systemPrompt = [
          "You are a SOC playbook architect. Given a security objective and severity, propose a JSON array of response actions.",
          "Each action must have: type (string), reason (string explaining why this step is needed).",
          "BLOCKED action types that must never appear: delete_data, shutdown_network, disable_logging.",
          "Available action types: auto_triage, assign_analyst, notify_slack, isolate_host, block_ip, quarantine_file, enrich_ioc, create_ticket, escalate, snapshot_evidence.",
          "Output ONLY a valid JSON array of action objects. No preamble, no markdown, no commentary.",
        ].join(" ");

        const userMessage = `Objective: ${normalized}\nSeverity: ${severity}\nGuardrails: ${guardrails.length > 0 ? guardrails.join(", ") : "none specified"}`;

        const aiPromise = gatewayInvoke({
          modelId: appConfig.ai.modelId,
          backend: appConfig.ai.backend,
          systemPrompt,
          userMessage,
          maxTokens: 1024,
          temperature: 0.3,
          topP: appConfig.ai.topP,
          sagemakerEndpoint: appConfig.ai.sagemakerEndpoint,
          orgId,
          promptId: "playbook-propose",
          skipCache: false,
        });

        const timeoutPromise = new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error("PROPOSAL_TIMEOUT")), PROPOSAL_TIMEOUT_MS);
        });

        const result = await Promise.race([aiPromise, timeoutPromise]);

        let proposedActions: { type: string; reason: string }[];
        try {
          const parsed = JSON.parse(result.text.trim());
          proposedActions = (Array.isArray(parsed) ? parsed : []).filter(
            (a: unknown): a is { type: string; reason: string } =>
              typeof a === "object" &&
              a !== null &&
              typeof (a as any).type === "string" &&
              typeof (a as any).reason === "string" &&
              !blocked.has((a as any).type),
          );
        } catch {
          plog.warn("AI returned non-JSON, using fallback", { raw: result.text.slice(0, 200) });
          return res.json(fallbackResponse);
        }

        if (proposedActions.length === 0) {
          plog.warn("AI returned empty actions, using fallback");
          return res.json(fallbackResponse);
        }

        res.json({
          objective: normalized,
          guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
          proposedActions,
          requiresAnalystApproval: true,
          source: "ai",
          latencyMs: result.latencyMs,
        });
      } catch (error) {
        const errMsg = String(error);
        if (errMsg.includes("PROPOSAL_TIMEOUT")) {
          plog.warn("Playbook proposal timed out after 30s, returning fallback");
          const { objective, severity = "high", guardrails = [] } = req.body || {};
          const normalized = String(objective || "Contain suspicious activity").trim();
          const blocked = new Set(["delete_data", "shutdown_network", "disable_logging"]);
          const fallbackActions = [
            { type: "auto_triage", reason: "Initial enrichment and classification" },
            { type: "assign_analyst", reason: "Ensure analyst ownership" },
            severity === "critical"
              ? { type: "isolate_host", reason: "Containment for critical blast radius" }
              : { type: "notify_slack", reason: "Notify response channel" },
          ].filter((a) => !blocked.has(a.type));
          return res.json({
            objective: normalized,
            guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
            proposedActions: fallbackActions,
            requiresAnalystApproval: true,
            source: "fallback_timeout",
          });
        }
        plog.error("Playbook proposal failed", { error: errMsg });
        res.status(500).json({ message: "Failed to generate playbook proposal" });
      }
    },
  );

  // Feedback Analytics
  app.get("/api/ai/feedback/analytics", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const days = Math.min(Math.max(parseInt(req.query.days as string, 10) || 30, 7), 365);
      const metrics = await storage.getAiFeedbackMetrics(orgId, days);

      const totalFeedback = metrics.reduce((s: number, m: any) => s + m.totalFeedback, 0);
      const totalPositive = metrics.reduce((s: number, m: any) => s + m.positiveFeedback, 0);
      const totalNegative = metrics.reduce((s: number, m: any) => s + m.negativeFeedback, 0);
      const avgRating =
        totalFeedback > 0
          ? metrics.reduce((s: number, m: any) => s + m.avgRating * m.totalFeedback, 0) / totalFeedback
          : 0;

      const allFeedback = await storage.getAiFeedback(orgId);
      const categoryBreakdown: Record<string, { count: number; avgRating: number; topIssues: string[] }> = {};
      const correctionReasons: Record<string, number> = {};

      for (const fb of Array.isArray(allFeedback) ? allFeedback : []) {
        const cat = (fb as any).resourceType || "unknown";
        if (!categoryBreakdown[cat]) categoryBreakdown[cat] = { count: 0, avgRating: 0, topIssues: [] };
        categoryBreakdown[cat].count++;
        categoryBreakdown[cat].avgRating += (fb as any).rating || 0;
        if ((fb as any).correctionReason) {
          const reason = String((fb as any).correctionReason).toLowerCase();
          correctionReasons[reason] = (correctionReasons[reason] || 0) + 1;
        }
      }
      for (const cat of Object.values(categoryBreakdown)) {
        cat.avgRating = cat.count > 0 ? Math.round((cat.avgRating / cat.count) * 10) / 10 : 0;
      }

      const sortedReasons = Object.entries(correctionReasons)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([reason, count]) => ({ reason, count }));

      const suggestions: Array<{ category: string; issue: string; suggestedFix: string; confidence: string }> = [];
      for (const [reason, count] of Object.entries(correctionReasons)) {
        if (count >= 3) {
          if (reason.includes("severity") || reason.includes("wrong severity")) {
            suggestions.push({
              category: "Severity Classification",
              issue: `${count} feedback entries report incorrect severity classification`,
              suggestedFix:
                "Add explicit severity calibration examples to the triage prompt. Include boundary cases between severity levels.",
              confidence: count >= 5 ? "high" : "medium",
            });
          }
          if (reason.includes("ioc") || reason.includes("missed") || reason.includes("indicator")) {
            suggestions.push({
              category: "IOC Extraction",
              issue: `${count} feedback entries report missed indicators`,
              suggestedFix: "Expand the IOC extraction section of the prompt with more indicator types and edge cases.",
              confidence: count >= 5 ? "high" : "medium",
            });
          }
          if (reason.includes("context") || reason.includes("irrelevant") || reason.includes("hallucin")) {
            suggestions.push({
              category: "Context Relevance",
              issue: `${count} feedback entries report irrelevant or hallucinated context`,
              suggestedFix:
                'Tighten the grounding instructions. Add "Only reference data from the provided context" constraints.',
              confidence: count >= 5 ? "high" : "medium",
            });
          }
          if (reason.includes("format") || reason.includes("json") || reason.includes("schema")) {
            suggestions.push({
              category: "Output Format",
              issue: `${count} feedback entries report format/schema issues`,
              suggestedFix: "Add stricter JSON schema validation in the prompt and include a concrete output example.",
              confidence: count >= 5 ? "high" : "medium",
            });
          }
        }
      }

      res.json({
        summary: {
          totalFeedback,
          totalPositive,
          totalNegative,
          avgRating,
          positiveRate: totalFeedback > 0 ? Math.round((totalPositive / totalFeedback) * 100) : 0,
        },
        trends: metrics,
        categoryBreakdown,
        topCorrectionReasons: sortedReasons,
        promptImprovementSuggestions: suggestions,
        period: `${days} days`,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch feedback analytics" });
    }
  });

  // Inline Feedback on AI Responses
  app.post(
    "/api/ai/feedback/inline",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { resourceType, resourceId, thumbs, comment, aiOutput } = req.body;
        if (!resourceType || !thumbs || !["up", "down"].includes(thumbs)) {
          return res.status(400).json({ message: "resourceType and thumbs (up|down) are required" });
        }
        const rating = thumbs === "up" ? 5 : 1;
        const feedback = await storage.createAiFeedback({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          resourceType: String(resourceType).slice(0, 64),
          resourceId: resourceId ? String(resourceId).slice(0, 255) : undefined,
          rating,
          comment: comment ? String(comment).slice(0, 2000) : undefined,
          aiOutput,
        });

        const orgId = (req as any).user?.orgId;
        if (orgId && thumbs === "down") {
          const outcome = "dismissed";
          recordFeedbackOutcome({
            orgId,
            feedbackId: feedback.id,
            outcome,
            source: "inline",
            category: String(resourceType),
            reason: comment ? String(comment).slice(0, 2000) : undefined,
          }).catch((err) =>
            logger.child("active-learning").warn("Failed to record inline feedback outcome", { error: String(err) }),
          );
        }

        res.status(201).json(feedback);
      } catch (error) {
        res.status(500).json({ message: "Failed to submit inline feedback" });
      }
    },
  );
}
