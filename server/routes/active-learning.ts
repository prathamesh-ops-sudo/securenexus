import type { Express } from "express";
import { getOrgId, logger, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext } from "../rbac";
import {
  addFewShotExample,
  getAllFewShotExamples,
  deactivateFewShotExample,
  deleteFewShotExample,
  getActiveLearningStats,
  getSourceSignalScores,
  getSuppressedSources,
  toggleSourceSuppression,
  getLearningLog,
  recordFeedbackOutcome,
} from "../ai/active-learning";

const log = logger.child("active-learning-routes");

export function registerActiveLearningRoutes(app: Express): void {
  // ─── Few-Shot Examples ───────────────────────────────────────────────────

  /** GET /api/ai/active-learning/examples — List all few-shot examples for org */
  app.get("/api/ai/active-learning/examples", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const domain = req.query.domain as string | undefined;
      const examples = await getAllFewShotExamples(orgId, domain);
      sendEnvelope(res, examples);
    } catch (error) {
      log.error("Failed to list few-shot examples", { error: String(error) });
      res.status(500).json({ message: "Failed to list few-shot examples" });
    }
  });

  /** POST /api/ai/active-learning/examples — Manually add a few-shot example */
  app.post("/api/ai/active-learning/examples", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { domain, input, incorrectOutput, correctOutput, lesson, alertSource, alertCategory } = req.body;

      if (!domain || !input || !incorrectOutput || !correctOutput || !lesson) {
        return res.status(400).json({
          message: "domain, input, incorrectOutput, correctOutput, and lesson are required",
        });
      }

      const validDomains = ["triage", "correlation", "narrative"];
      if (!validDomains.includes(domain)) {
        return res.status(400).json({
          message: `domain must be one of: ${validDomains.join(", ")}`,
        });
      }

      const example = await addFewShotExample({
        orgId,
        domain,
        input: String(input).slice(0, 5000),
        incorrectOutput: String(incorrectOutput).slice(0, 3000),
        correctOutput: String(correctOutput).slice(0, 3000),
        lesson: String(lesson).slice(0, 2000),
        alertSource: alertSource ? String(alertSource).slice(0, 255) : undefined,
        alertCategory: alertCategory ? String(alertCategory).slice(0, 255) : undefined,
      });

      sendEnvelope(res, example, { status: 201 });
    } catch (error) {
      log.error("Failed to add few-shot example", { error: String(error) });
      res.status(500).json({ message: "Failed to add few-shot example" });
    }
  });

  /** PATCH /api/ai/active-learning/examples/:id/deactivate — Deactivate a few-shot example */
  app.patch("/api/ai/active-learning/examples/:id/deactivate", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const deactivated = await deactivateFewShotExample(id, orgId);
      if (!deactivated) {
        return res.status(404).json({ message: "Example not found" });
      }
      sendEnvelope(res, { message: "Example deactivated" });
    } catch (error) {
      log.error("Failed to deactivate example", { error: String(error) });
      res.status(500).json({ message: "Failed to deactivate example" });
    }
  });

  /** DELETE /api/ai/active-learning/examples/:id — Delete a few-shot example */
  app.delete("/api/ai/active-learning/examples/:id", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const deleted = await deleteFewShotExample(id, orgId);
      if (!deleted) {
        return res.status(404).json({ message: "Example not found" });
      }
      sendEnvelope(res, { message: "Example deleted" });
    } catch (error) {
      log.error("Failed to delete example", { error: String(error) });
      res.status(500).json({ message: "Failed to delete example" });
    }
  });

  // ─── Source Signal Scores & Suppression ─────────────────────────────────

  /** GET /api/ai/active-learning/source-scores — FP rate per source/category */
  app.get("/api/ai/active-learning/source-scores", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(Math.max(1, parseInt(req.query.limit as string, 10) || 50), 200);
      const scores = await getSourceSignalScores(orgId, limit);
      sendEnvelope(res, scores);
    } catch (error) {
      log.error("Failed to get source signal scores", { error: String(error) });
      res.status(500).json({ message: "Failed to get source signal scores" });
    }
  });

  /** GET /api/ai/active-learning/suppressed-sources — List auto-suppressed sources */
  app.get("/api/ai/active-learning/suppressed-sources", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const suppressed = await getSuppressedSources(orgId);
      sendEnvelope(res, suppressed);
    } catch (error) {
      log.error("Failed to get suppressed sources", { error: String(error) });
      res.status(500).json({ message: "Failed to get suppressed sources" });
    }
  });

  /** POST /api/ai/active-learning/toggle-suppression — Manually toggle source suppression */
  app.post("/api/ai/active-learning/toggle-suppression", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { source, category, suppressed } = req.body;

      if (!source || typeof suppressed !== "boolean") {
        return res.status(400).json({
          message: "source and suppressed (boolean) are required",
        });
      }

      const updated = await toggleSourceSuppression(
        orgId,
        String(source).slice(0, 255),
        String(category || "").slice(0, 255),
        suppressed,
      );

      if (!updated) {
        return res.status(404).json({ message: "Source/category combination not found" });
      }

      sendEnvelope(res, { message: `Source ${suppressed ? "suppressed" : "unsuppressed"}` });
    } catch (error) {
      log.error("Failed to toggle suppression", { error: String(error) });
      res.status(500).json({ message: "Failed to toggle suppression" });
    }
  });

  // ─── Stats & Learning Log ──────────────────────────────────────────────

  /** GET /api/ai/active-learning/stats — Active learning statistics */
  app.get("/api/ai/active-learning/stats", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await getActiveLearningStats(orgId);
      sendEnvelope(res, stats);
    } catch (error) {
      log.error("Failed to get active learning stats", { error: String(error) });
      res.status(500).json({ message: "Failed to get active learning stats" });
    }
  });

  /** GET /api/ai/active-learning/log — Learning log (audit trail of feedback-to-learning events) */
  app.get("/api/ai/active-learning/log", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(Math.max(1, parseInt(req.query.limit as string, 10) || 50), 200);
      const entries = await getLearningLog(orgId, limit);
      sendEnvelope(res, entries);
    } catch (error) {
      log.error("Failed to get learning log", { error: String(error) });
      res.status(500).json({ message: "Failed to get learning log" });
    }
  });

  /** POST /api/ai/active-learning/calibrate — Manually record a calibration outcome */
  app.post("/api/ai/active-learning/calibrate", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { feedbackId, outcome, source, category, domain, originalContext, aiOutput, analystCorrection, reason } =
        req.body;

      if (!feedbackId || !outcome || !source) {
        return res.status(400).json({
          message: "feedbackId, outcome, and source are required",
        });
      }

      const validOutcomes = ["overridden", "dismissed", "confirmed"];
      if (!validOutcomes.includes(outcome)) {
        return res.status(400).json({
          message: `outcome must be one of: ${validOutcomes.join(", ")}`,
        });
      }

      await recordFeedbackOutcome({
        orgId,
        feedbackId: String(feedbackId).slice(0, 255),
        outcome,
        source: String(source).slice(0, 255),
        category: String(category || "unknown").slice(0, 255),
        domain: domain ? String(domain).slice(0, 64) : undefined,
        originalContext: originalContext ? String(originalContext).slice(0, 5000) : undefined,
        aiOutput: aiOutput ? String(aiOutput).slice(0, 3000) : undefined,
        analystCorrection: analystCorrection ? String(analystCorrection).slice(0, 3000) : undefined,
        reason: reason ? String(reason).slice(0, 2000) : undefined,
      });

      sendEnvelope(res, { message: "Calibration recorded" }, { status: 201 });
    } catch (error) {
      log.error("Failed to record calibration", { error: String(error) });
      res.status(500).json({ message: "Failed to record calibration" });
    }
  });
}
