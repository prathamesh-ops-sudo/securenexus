import type { Express, Request, Response } from "express";
import { getOrgId, logger, storage, strictLimiter } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireMinRole, requireOrgId } from "../../rbac";
import { generateDetectionRules } from "../../ai";
import { enforcePlanLimit } from "../../middleware/plan-enforcement";

const log = logger.child("routes-ai-detection-rules");

export function registerAiDetectionRulesRoutes(app: Express): void {
  // POST /api/ai/investigation/:incidentId/generate-rules
  app.post(
    "/api/ai/investigation/:incidentId/generate-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    enforcePlanLimit("ai_analyses"),
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const incidentId = String(req.params.incidentId);
        const orgId = getOrgId(req);

        const incident = await storage.getIncident(incidentId);
        if (!incident || incident.orgId !== orgId) {
          return res.status(404).json({ message: "Incident not found" });
        }

        const incidentAlerts = await storage.getAlertsByIncident(incidentId);
        const techniques = Array.from(new Set(incidentAlerts.map((a) => a.mitreTechnique).filter(Boolean))) as string[];
        const indicators = incidentAlerts
          .flatMap((a) => [a.sourceIp, a.hostname].filter(Boolean))
          .filter((v, i, arr) => arr.indexOf(v) === i) as string[];

        const incidentSummary = `${incident.title}: ${incident.summary || "No description"} — Severity: ${incident.severity}, Alerts: ${incidentAlerts.length}`;

        const result = await generateDetectionRules(incidentSummary, techniques, indicators, orgId);

        const savedRules = [];
        for (const rule of result.rules) {
          const saved = await storage.createAiGeneratedRule({
            orgId,
            sourceIncidentId: incidentId,
            name: rule.name,
            description: rule.description,
            ruleContent: rule.conditionTree,
            sigmaNormalized: rule.sigmaRule,
            confidence: rule.confidence,
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechnique,
            generatedBy: "claude-opus",
          });
          savedRules.push(saved);
        }

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "ai_generate_detection_rules",
          resourceType: "incident",
          resourceId: String(incidentId),
          details: {
            rulesGenerated: savedRules.length,
            techniques,
            analysisNotes: result.analysisNotes,
          },
        });

        storage
          .incrementUsage(orgId, "ai_analyses")
          .catch((err) => log.warn("Failed to increment AI usage", { error: String(err), orgId }));

        res.json({
          rules: savedRules,
          analysisNotes: result.analysisNotes,
          coverageGaps: result.coverageGaps,
        });
      } catch (error: any) {
        logger.child("ai").error("Detection rule generation error", { error: String(error) });
        res.status(500).json({ message: "Detection rule generation failed. Please try again." });
      }
    },
  );

  // GET /api/ai/generated-rules
  app.get("/api/ai/generated-rules", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(Math.max(parseInt(String(req.query.limit || "50"), 10) || 50, 1), 200);
      const rules = await storage.getAiGeneratedRulesByOrg(orgId, limit);
      res.json(rules);
    } catch (error: any) {
      logger.child("ai").error("Get AI-generated rules error", { error: String(error) });
      res.status(500).json({ message: "Failed to retrieve AI-generated rules." });
    }
  });

  // PATCH /api/ai/generated-rules/:ruleId
  app.patch(
    "/api/ai/generated-rules/:ruleId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const ruleId = String(req.params.ruleId);
        const orgId = getOrgId(req);

        const rule = await storage.getAiGeneratedRule(ruleId);
        if (!rule || rule.orgId !== orgId) {
          return res.status(404).json({ message: "Rule not found" });
        }

        const allowedFields = ["status", "reviewedBy", "reviewedAt"] as const;
        const allowedStatuses = new Set(["draft", "review", "accepted", "rejected"]);
        const update: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            update[field] = req.body[field];
          }
        }

        if (update.status && !allowedStatuses.has(update.status as string)) {
          return res.status(400).json({ message: "Invalid status. Must be one of: draft, review, accepted, rejected" });
        }

        if (Object.keys(update).length === 0) {
          return res.status(400).json({ message: "No valid fields to update" });
        }

        const updated = await storage.updateAiGeneratedRule(ruleId, update);
        res.json(updated);
      } catch (error: any) {
        logger.child("ai").error("Update AI-generated rule error", { error: String(error) });
        res.status(500).json({ message: "Failed to update rule." });
      }
    },
  );
}
