import type { Express, Request, Response } from "express";
import { getOrgId, logger } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext } from "../../rbac";

const log = logger.child("routes-ai-active-learning");

export function registerAiActiveLearningRoutes(app: Express): void {
  // Few-shot Example Injection from Feedback
  app.get("/api/ai/active-learning/auto-examples", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const domain = req.query.domain as string | undefined;
      const { getAllFewShotExamples: getFewShot } = await import("../../ai/active-learning");
      const examples = await getFewShot(orgId, domain);
      const autoInjected = examples.filter((ex) => ex.feedbackId !== null);
      const manual = examples.filter((ex) => ex.feedbackId === null);
      res.json({
        total: examples.length,
        autoInjected: autoInjected.length,
        manual: manual.length,
        examples: autoInjected.slice(0, 50),
        pipelineStatus: autoInjected.length > 0 ? "active" : "no_examples_yet",
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch auto-injected examples" });
    }
  });

  // Source-Level Suppression Verification
  app.get("/api/ai/active-learning/suppression-status", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { getSourceSignalScores: getScores, getSuppressedSources: getSuppressed } =
        await import("../../ai/active-learning");
      const scores = await getScores(orgId, 100);
      const suppressed = await getSuppressed(orgId);

      const highFpSources = scores.filter((s) => s.fpRate > 0.5 && !s.suppressed);
      const activelySuppressed = suppressed.length;
      const suppressionCandidates = highFpSources.map((s) => ({
        source: s.source,
        category: s.category,
        fpRate: s.fpRate,
        totalFeedback: s.totalFeedback,
        recommendation: s.fpRate > 0.8 ? "strongly_recommend_suppress" : "consider_suppression",
      }));

      res.json({
        activelySuppressed,
        suppressionCandidates,
        pipelineWorking: activelySuppressed > 0 || suppressionCandidates.length > 0,
        totalSourcesTracked: scores.length,
        highFpSourceCount: highFpSources.length,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch suppression status" });
    }
  });
}
