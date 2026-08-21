import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, count } from "drizzle-orm";
import {
  postureScores,
  postureSubScores,
  peerBenchmarks,
  publicTrustPages,
  securityQuestionnaires,
  questionnaireResponses,
  postureScoreHistory,
} from "../../shared/schema";
import {
  DOMAIN_WEIGHTS,
  DOMAIN_META,
  SCORING_CONTROLS,
  QUESTIONNAIRE_TEMPLATES,
  computeOverallScore,
  computePercentileRank,
  generateDomainScores,
  generateScoreTrend,
  getAvailableIndustries,
  getAvailableCompanySizes,
} from "../posture-engine-v2";

const log = logger.child("posture-trust");

const ALLOWED_TRUST_PAGE_FIELDS = [
  "companyName",
  "companyLogo",
  "tagline",
  "showSubScores",
  "showCertifications",
  "showLastAudit",
  "showPercentile",
  "customSections",
  "contactEmail",
  "brandColor",
  "status",
] as const;

const ALLOWED_QUESTIONNAIRE_FIELDS = [
  "title",
  "framework",
  "status",
  "assignedTo",
  "requestedBy",
  "requestedByEmail",
  "dueDate",
] as const;

const ALLOWED_RESPONSE_FIELDS = ["answerText", "answerSource", "confidencePercent", "evidenceRefs", "status"] as const;

export function registerPostureTrustRoutes(app: Express): void {
  // ==========================================================================
  // POSTURE SCORE — enhanced with 6 domain sub-scores
  // ==========================================================================

  // Calculate & store enhanced posture score
  app.post(
    "/api/posture-trust/calculate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { industry, companySize } = req.body;

        // Generate domain sub-scores
        const evidence = await generateDomainScores(orgId);
        if (evidence.status === "unavailable" || evidence.overallScore === null) {
          return res.status(422).json(evidence);
        }
        const { domainScores, overallScore } = evidence;

        // Compute peer benchmarking
        const hasCompleteDomainCoverage = domainScores.length === Object.keys(DOMAIN_WEIGHTS).length;
        const benchmarkResult = hasCompleteDomainCoverage
          ? computePercentileRank(
              overallScore,
              typeof industry === "string" ? industry : "Technology",
              typeof companySize === "string" ? companySize : "medium",
            )
          : null;

        // Store main posture score
        const [score] = await db
          .insert(postureScores)
          .values({
            orgId,
            overallScore,
            cspmScore: domainScores.find((d) => d.domain === "cloud")?.score ?? null,
            endpointScore: domainScores.find((d) => d.domain === "endpoint")?.score ?? null,
            incidentScore: domainScores.find((d) => d.domain === "network")?.score ?? null,
            complianceScore: domainScores.find((d) => d.domain === "data")?.score ?? null,
            breakdown: {
              domainScores: domainScores.map((d) => ({
                domain: d.domain,
                score: d.score,
                weight: d.weight,
                controlsEvaluated: d.controlsEvaluated,
                controlsPassed: d.controlsPassed,
                controlsFailed: d.controlsFailed,
              })),
              percentile: benchmarkResult?.percentile ?? null,
              peerCount: benchmarkResult?.peerCount ?? null,
            },
          })
          .returning();

        // Store sub-scores
        for (const ds of domainScores) {
          await db.insert(postureSubScores).values({
            orgId,
            postureScoreId: score.id,
            domain: ds.domain,
            score: ds.score,
            weight: ds.weight,
            findings: ds.findings,
            recommendations: ds.recommendations,
            controlsEvaluated: ds.controlsEvaluated,
            controlsPassed: ds.controlsPassed,
            controlsFailed: ds.controlsFailed,
            riskFactors: ds.riskFactors,
          });
        }

        // Peer benchmarks require complete domain coverage; do not encode absent domains as zero.
        if (hasCompleteDomainCoverage && benchmarkResult) {
          await db.insert(peerBenchmarks).values({
            orgId,
            industrySegment: typeof industry === "string" ? industry : "Technology",
            companySize: typeof companySize === "string" ? companySize : "medium",
            overallScore,
            identityScore: domainScores.find((d) => d.domain === "identity")?.score ?? null,
            endpointScore: domainScores.find((d) => d.domain === "endpoint")?.score ?? null,
            cloudScore: domainScores.find((d) => d.domain === "cloud")?.score ?? null,
            networkScore: domainScores.find((d) => d.domain === "network")?.score ?? null,
            applicationScore: domainScores.find((d) => d.domain === "application")?.score ?? null,
            dataScore: domainScores.find((d) => d.domain === "data")?.score ?? null,
            percentileRank: benchmarkResult.percentile,
            peerCount: benchmarkResult.peerCount,
            topStrengths: domainScores
              .filter((d) => d.score >= 80)
              .map((d) => d.domain)
              .slice(0, 3),
            topWeaknesses: domainScores
              .filter((d) => d.score < 60)
              .map((d) => d.domain)
              .slice(0, 3),
          });
        }

        // Store history entry
        const now = new Date();
        const period = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;

        // Get previous score for delta
        const [prevHistory] = await db
          .select()
          .from(postureScoreHistory)
          .where(eq(postureScoreHistory.orgId, orgId))
          .orderBy(desc(postureScoreHistory.generatedAt))
          .limit(1);

        const changeFromPrevious = prevHistory ? overallScore - prevHistory.overallScore : 0;

        if (hasCompleteDomainCoverage && benchmarkResult) {
          await db.insert(postureScoreHistory).values({
            orgId,
            overallScore,
            identityScore: domainScores.find((d) => d.domain === "identity")?.score ?? 0,
            endpointScore: domainScores.find((d) => d.domain === "endpoint")?.score ?? 0,
            cloudScore: domainScores.find((d) => d.domain === "cloud")?.score ?? 0,
            networkScore: domainScores.find((d) => d.domain === "network")?.score ?? 0,
            applicationScore: domainScores.find((d) => d.domain === "application")?.score ?? 0,
            dataScore: domainScores.find((d) => d.domain === "data")?.score ?? 0,
            percentileRank: benchmarkResult.percentile,
            changeFromPrevious,
            period,
            periodType: "monthly",
          });
        }

        // Update trust page if published
        const [trustPage] = await db
          .select()
          .from(publicTrustPages)
          .where(and(eq(publicTrustPages.orgId, orgId), eq(publicTrustPages.status, "published")));

        if (trustPage) {
          const domainScoreMap: Record<string, number> = {};
          for (const ds of domainScores) {
            domainScoreMap[ds.domain] = ds.score;
          }
          await db
            .update(publicTrustPages)
            .set({
              overallScore,
              domainScores: domainScoreMap,
              updatedAt: new Date(),
            })
            .where(eq(publicTrustPages.id, trustPage.id));
        }

        res.status(201).json({
          score,
          domainScores,
          benchmark: benchmarkResult,
          changeFromPrevious,
          measuredDomains: evidence.measuredDomains,
        });
      } catch (error) {
        log.error("Failed to calculate posture score", { error: String(error) });
        res.status(500).json({ message: "Failed to calculate posture score" });
      }
    },
  );

  // Get latest posture score with sub-scores
  app.get("/api/posture-trust/latest", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const evidence = await generateDomainScores(orgId);
      if (evidence.status === "unavailable") {
        return res.json({
          score: null,
          subScores: [],
          benchmark: null,
          domainMeta: DOMAIN_META,
          available: false,
          reason: evidence.reason,
          requiredEvidence: evidence.requiredEvidence,
        });
      }

      const [latestScore] = await db
        .select()
        .from(postureScores)
        .where(eq(postureScores.orgId, orgId))
        .orderBy(desc(postureScores.generatedAt))
        .limit(1);

      if (!latestScore) {
        return res.json(null);
      }

      // Get sub-scores for this calculation
      const subScores = await db
        .select()
        .from(postureSubScores)
        .where(and(eq(postureSubScores.orgId, orgId), eq(postureSubScores.postureScoreId, latestScore.id)));

      // Get latest benchmark
      const [benchmark] = await db
        .select()
        .from(peerBenchmarks)
        .where(eq(peerBenchmarks.orgId, orgId))
        .orderBy(desc(peerBenchmarks.calculatedAt))
        .limit(1);

      res.json({
        score: latestScore,
        subScores,
        benchmark: benchmark || null,
        domainMeta: DOMAIN_META,
      });
    } catch (error) {
      log.error("Failed to fetch latest posture score", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch latest posture score" });
    }
  });

  // Get score history / trend
  app.get("/api/posture-trust/history", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const periodType = typeof req.query.periodType === "string" ? req.query.periodType : "monthly";
      const limitParam = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 12;
      const safeLimit = Math.min(Math.max(1, limitParam), 100);

      const history = await db
        .select()
        .from(postureScoreHistory)
        .where(and(eq(postureScoreHistory.orgId, orgId), eq(postureScoreHistory.periodType, periodType)))
        .orderBy(desc(postureScoreHistory.generatedAt))
        .limit(safeLimit);

      // If no history exists, generate simulated trend
      if (history.length === 0) {
        const [latestScore] = await db
          .select()
          .from(postureScores)
          .where(eq(postureScores.orgId, orgId))
          .orderBy(desc(postureScores.generatedAt))
          .limit(1);

        const currentScore = latestScore?.overallScore || 65;
        const trend = generateScoreTrend(currentScore, safeLimit);
        return res.json({ history: trend, simulated: true });
      }

      res.json({ history: history.reverse(), simulated: false });
    } catch (error) {
      log.error("Failed to fetch score history", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch score history" });
    }
  });

  // Get domain controls reference
  app.get("/api/posture-trust/controls", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    res.json({
      controls: SCORING_CONTROLS,
      domainWeights: DOMAIN_WEIGHTS,
      domainMeta: DOMAIN_META,
    });
  });

  // ==========================================================================
  // PEER BENCHMARKING
  // ==========================================================================

  // Get peer benchmark data
  app.get("/api/posture-trust/benchmark", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [latest] = await db
        .select()
        .from(peerBenchmarks)
        .where(eq(peerBenchmarks.orgId, orgId))
        .orderBy(desc(peerBenchmarks.calculatedAt))
        .limit(1);

      if (!latest) {
        return res.json(null);
      }

      // Get all benchmarks for this org (history)
      const benchmarkHistory = await db
        .select()
        .from(peerBenchmarks)
        .where(eq(peerBenchmarks.orgId, orgId))
        .orderBy(desc(peerBenchmarks.calculatedAt))
        .limit(12);

      res.json({
        latest,
        history: benchmarkHistory.reverse(),
        availableIndustries: getAvailableIndustries(),
        availableCompanySizes: getAvailableCompanySizes(),
      });
    } catch (error) {
      log.error("Failed to fetch benchmark", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch benchmark" });
    }
  });

  // ==========================================================================
  // PUBLIC TRUST PAGES
  // ==========================================================================

  // Get org's trust page
  app.get("/api/posture-trust/trust-page", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [page] = await db.select().from(publicTrustPages).where(eq(publicTrustPages.orgId, orgId));

      res.json(page || null);
    } catch (error) {
      log.error("Failed to fetch trust page", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch trust page" });
    }
  });

  // Create / update trust page
  app.post(
    "/api/posture-trust/trust-page",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { companyName, slug } = req.body;

        if (!companyName || typeof companyName !== "string") {
          return res.status(400).json({ message: "companyName is required" });
        }
        if (!slug || typeof slug !== "string") {
          return res.status(400).json({ message: "slug is required" });
        }

        // Validate slug format
        if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(slug) && !/^[a-z0-9]$/.test(slug)) {
          return res.status(400).json({ message: "slug must be lowercase alphanumeric with hyphens only" });
        }

        // Check slug uniqueness (different org)
        const [existing] = await db.select().from(publicTrustPages).where(eq(publicTrustPages.slug, slug));

        if (existing && existing.orgId !== orgId) {
          return res.status(409).json({ message: "This slug is already taken by another organization" });
        }

        // Check if org already has a page
        const [existingPage] = await db.select().from(publicTrustPages).where(eq(publicTrustPages.orgId, orgId));

        // Get latest posture score
        const [latestScore] = await db
          .select()
          .from(postureScores)
          .where(eq(postureScores.orgId, orgId))
          .orderBy(desc(postureScores.generatedAt))
          .limit(1);

        // Get latest sub-scores
        const domainScoreMap: Record<string, number> = {};
        if (latestScore) {
          const subs = await db
            .select()
            .from(postureSubScores)
            .where(and(eq(postureSubScores.orgId, orgId), eq(postureSubScores.postureScoreId, latestScore.id)));
          for (const s of subs) {
            domainScoreMap[s.domain] = s.score;
          }
        }

        // Build update object with allowlisted fields
        const updateFields: Record<string, unknown> = {};
        for (const key of ALLOWED_TRUST_PAGE_FIELDS) {
          if (key in req.body && req.body[key] !== undefined) {
            updateFields[key] = req.body[key];
          }
        }

        if (existingPage) {
          // Update
          const [updated] = await db
            .update(publicTrustPages)
            .set({
              ...updateFields,
              slug,
              companyName,
              overallScore: latestScore?.overallScore || existingPage.overallScore,
              domainScores: Object.keys(domainScoreMap).length > 0 ? domainScoreMap : existingPage.domainScores,
              publishedAt:
                updateFields.status === "published" && !existingPage.publishedAt
                  ? new Date()
                  : existingPage.publishedAt,
              updatedAt: new Date(),
            })
            .where(eq(publicTrustPages.id, existingPage.id))
            .returning();

          return res.json(updated);
        }

        // Create new
        const [created] = await db
          .insert(publicTrustPages)
          .values({
            orgId,
            slug,
            companyName,
            ...updateFields,
            overallScore: latestScore?.overallScore || 0,
            domainScores: domainScoreMap,
          })
          .returning();

        res.status(201).json(created);
      } catch (error) {
        log.error("Failed to save trust page", { error: String(error) });
        res.status(500).json({ message: "Failed to save trust page" });
      }
    },
  );

  // Publish trust page
  app.post(
    "/api/posture-trust/trust-page/publish",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [page] = await db.select().from(publicTrustPages).where(eq(publicTrustPages.orgId, orgId));

        if (!page) {
          return res.status(404).json({ message: "Create a trust page first" });
        }

        const [updated] = await db
          .update(publicTrustPages)
          .set({
            status: "published",
            publishedAt: page.publishedAt || new Date(),
            updatedAt: new Date(),
          })
          .where(eq(publicTrustPages.id, page.id))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to publish trust page", { error: String(error) });
        res.status(500).json({ message: "Failed to publish trust page" });
      }
    },
  );

  // Archive trust page
  app.post(
    "/api/posture-trust/trust-page/archive",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [page] = await db.select().from(publicTrustPages).where(eq(publicTrustPages.orgId, orgId));

        if (!page) {
          return res.status(404).json({ message: "No trust page found" });
        }

        const [updated] = await db
          .update(publicTrustPages)
          .set({ status: "archived", updatedAt: new Date() })
          .where(eq(publicTrustPages.id, page.id))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to archive trust page", { error: String(error) });
        res.status(500).json({ message: "Failed to archive trust page" });
      }
    },
  );

  // PUBLIC endpoint — view trust page by slug (no auth required)
  app.get("/api/public/trust/:slug", async (req, res) => {
    try {
      const slug = String(req.params.slug);

      const [page] = await db
        .select()
        .from(publicTrustPages)
        .where(and(eq(publicTrustPages.slug, slug), eq(publicTrustPages.status, "published")));

      if (!page) {
        return res.status(404).json({ message: "Trust page not found" });
      }

      // Increment visit count
      await db
        .update(publicTrustPages)
        .set({ visitCount: (page.visitCount || 0) + 1 })
        .where(eq(publicTrustPages.id, page.id));

      // Return sanitized public data
      res.json({
        companyName: page.companyName,
        companyLogo: page.companyLogo,
        tagline: page.tagline,
        overallScore: page.overallScore,
        domainScores: page.showSubScores ? page.domainScores : undefined,
        certifications: page.showCertifications ? page.certifications : undefined,
        lastAuditDate: page.showLastAudit ? page.lastAuditDate : undefined,
        customSections: page.customSections,
        contactEmail: page.contactEmail,
        brandColor: page.brandColor,
        domainMeta: page.showSubScores ? DOMAIN_META : undefined,
        publishedAt: page.publishedAt,
      });
    } catch (error) {
      log.error("Failed to fetch public trust page", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch trust page" });
    }
  });

  // ==========================================================================
  // SECURITY QUESTIONNAIRES
  // ==========================================================================

  // List questionnaires
  app.get("/api/posture-trust/questionnaires", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;

      const conditions = [eq(securityQuestionnaires.orgId, orgId)];
      if (status && typeof status === "string") {
        conditions.push(eq(securityQuestionnaires.status, status));
      }

      const questionnaires = await db
        .select()
        .from(securityQuestionnaires)
        .where(and(...conditions))
        .orderBy(desc(securityQuestionnaires.createdAt))
        .limit(100);

      res.json(questionnaires);
    } catch (error) {
      log.error("Failed to list questionnaires", { error: String(error) });
      res.status(500).json({ message: "Failed to list questionnaires" });
    }
  });

  // Create questionnaire from template (auto-populate answers)
  app.post(
    "/api/posture-trust/questionnaires",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { framework, title, requestedBy, requestedByEmail, dueDate } = req.body;

        if (!framework || typeof framework !== "string") {
          return res.status(400).json({ message: "framework is required" });
        }

        // Find template
        const template = QUESTIONNAIRE_TEMPLATES.find((t) => t.framework.toLowerCase() === framework.toLowerCase());

        if (!template) {
          return res.status(400).json({
            message: `Unknown framework: ${framework}. Available: ${QUESTIONNAIRE_TEMPLATES.map((t) => t.framework).join(", ")}`,
          });
        }

        // Create questionnaire
        const [questionnaire] = await db
          .insert(securityQuestionnaires)
          .values({
            orgId,
            title: typeof title === "string" ? title : template.title,
            framework: template.framework,
            status: "in_progress",
            totalQuestions: template.questions.length,
            answeredQuestions: template.questions.length,
            autoAnsweredQuestions: template.questions.length,
            manualQuestions: 0,
            confidenceScore: Math.round(
              template.questions.reduce((sum, q) => sum + q.confidencePercent, 0) / template.questions.length,
            ),
            requestedBy: typeof requestedBy === "string" ? requestedBy : null,
            requestedByEmail: typeof requestedByEmail === "string" ? requestedByEmail : null,
            dueDate: dueDate ? new Date(dueDate) : null,
          })
          .returning();

        // Auto-populate responses
        for (const question of template.questions) {
          await db.insert(questionnaireResponses).values({
            orgId,
            questionnaireId: questionnaire.id,
            questionNumber: question.questionNumber,
            questionText: question.questionText,
            category: question.category,
            answerText: question.defaultAnswer,
            answerSource: "auto",
            confidencePercent: question.confidencePercent,
            evidenceRefs: [],
            status: "answered",
          });
        }

        res.status(201).json({
          questionnaire,
          autoAnswered: template.questions.length,
          message: `Created ${template.framework} questionnaire with ${template.questions.length} auto-answered questions`,
        });
      } catch (error) {
        log.error("Failed to create questionnaire", { error: String(error) });
        res.status(500).json({ message: "Failed to create questionnaire" });
      }
    },
  );

  // Get questionnaire detail with responses
  app.get(
    "/api/posture-trust/questionnaires/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [questionnaire] = await db
          .select()
          .from(securityQuestionnaires)
          .where(and(eq(securityQuestionnaires.id, id), eq(securityQuestionnaires.orgId, orgId)));

        if (!questionnaire) {
          return res.status(404).json({ message: "Questionnaire not found" });
        }

        const responses = await db
          .select()
          .from(questionnaireResponses)
          .where(and(eq(questionnaireResponses.questionnaireId, id), eq(questionnaireResponses.orgId, orgId)))
          .orderBy(questionnaireResponses.questionNumber);

        res.json({ questionnaire, responses });
      } catch (error) {
        log.error("Failed to fetch questionnaire", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch questionnaire" });
      }
    },
  );

  // Update questionnaire
  app.patch(
    "/api/posture-trust/questionnaires/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [existing] = await db
          .select()
          .from(securityQuestionnaires)
          .where(and(eq(securityQuestionnaires.id, id), eq(securityQuestionnaires.orgId, orgId)));

        if (!existing) {
          return res.status(404).json({ message: "Questionnaire not found" });
        }

        const updateFields: Record<string, unknown> = {};
        for (const key of ALLOWED_QUESTIONNAIRE_FIELDS) {
          if (key in req.body && req.body[key] !== undefined) {
            if (key === "dueDate") {
              updateFields[key] = new Date(req.body[key]);
            } else {
              updateFields[key] = req.body[key];
            }
          }
        }

        if (updateFields.status === "completed") {
          updateFields.completedAt = new Date();
        }
        if (updateFields.status === "submitted") {
          updateFields.submittedAt = new Date();
        }

        updateFields.updatedAt = new Date();

        const [updated] = await db
          .update(securityQuestionnaires)
          .set(updateFields)
          .where(eq(securityQuestionnaires.id, id))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update questionnaire", { error: String(error) });
        res.status(500).json({ message: "Failed to update questionnaire" });
      }
    },
  );

  // Delete questionnaire
  app.delete(
    "/api/posture-trust/questionnaires/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [existing] = await db
          .select()
          .from(securityQuestionnaires)
          .where(and(eq(securityQuestionnaires.id, id), eq(securityQuestionnaires.orgId, orgId)));

        if (!existing) {
          return res.status(404).json({ message: "Questionnaire not found" });
        }

        // Delete responses first
        await db
          .delete(questionnaireResponses)
          .where(and(eq(questionnaireResponses.questionnaireId, id), eq(questionnaireResponses.orgId, orgId)));

        await db.delete(securityQuestionnaires).where(eq(securityQuestionnaires.id, id));

        res.json({ message: "Questionnaire deleted" });
      } catch (error) {
        log.error("Failed to delete questionnaire", { error: String(error) });
        res.status(500).json({ message: "Failed to delete questionnaire" });
      }
    },
  );

  // Update a response within a questionnaire
  app.patch(
    "/api/posture-trust/questionnaires/:qid/responses/:rid",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const qid = String(req.params.qid);
        const rid = String(req.params.rid);

        // Verify questionnaire ownership
        const [q] = await db
          .select()
          .from(securityQuestionnaires)
          .where(and(eq(securityQuestionnaires.id, qid), eq(securityQuestionnaires.orgId, orgId)));

        if (!q) {
          return res.status(404).json({ message: "Questionnaire not found" });
        }

        const [response] = await db
          .select()
          .from(questionnaireResponses)
          .where(
            and(
              eq(questionnaireResponses.id, rid),
              eq(questionnaireResponses.questionnaireId, qid),
              eq(questionnaireResponses.orgId, orgId),
            ),
          );

        if (!response) {
          return res.status(404).json({ message: "Response not found" });
        }

        const updateFields: Record<string, unknown> = {};
        for (const key of ALLOWED_RESPONSE_FIELDS) {
          if (key in req.body && req.body[key] !== undefined) {
            updateFields[key] = req.body[key];
          }
        }
        updateFields.updatedAt = new Date();

        if (updateFields.status === "reviewed") {
          updateFields.reviewedAt = new Date();
          updateFields.reviewedBy = (req as any).user?.id || "unknown";
        }

        const [updated] = await db
          .update(questionnaireResponses)
          .set(updateFields)
          .where(eq(questionnaireResponses.id, rid))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update response", { error: String(error) });
        res.status(500).json({ message: "Failed to update response" });
      }
    },
  );

  // Get questionnaire templates
  app.get(
    "/api/posture-trust/questionnaire-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (_req, res) => {
      res.json(
        QUESTIONNAIRE_TEMPLATES.map((t) => ({
          framework: t.framework,
          title: t.title,
          description: t.description,
          questionCount: t.questions.length,
        })),
      );
    },
  );

  // ==========================================================================
  // SUMMARY — dashboard overview
  // ==========================================================================

  app.get("/api/posture-trust/summary", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const evidence = await generateDomainScores(orgId);

      // Latest score
      const [latestScore] = await db
        .select()
        .from(postureScores)
        .where(eq(postureScores.orgId, orgId))
        .orderBy(desc(postureScores.generatedAt))
        .limit(1);

      // Sub-scores
      const subScores = latestScore
        ? await db
            .select()
            .from(postureSubScores)
            .where(and(eq(postureSubScores.orgId, orgId), eq(postureSubScores.postureScoreId, latestScore.id)))
        : [];

      // Latest benchmark
      const [benchmark] = await db
        .select()
        .from(peerBenchmarks)
        .where(eq(peerBenchmarks.orgId, orgId))
        .orderBy(desc(peerBenchmarks.calculatedAt))
        .limit(1);

      // Trust page
      const [trustPage] = await db.select().from(publicTrustPages).where(eq(publicTrustPages.orgId, orgId));

      // Questionnaire counts
      const [{ value: totalQuestionnaires }] = await db
        .select({ value: count() })
        .from(securityQuestionnaires)
        .where(eq(securityQuestionnaires.orgId, orgId));

      const [{ value: completedQuestionnaires }] = await db
        .select({ value: count() })
        .from(securityQuestionnaires)
        .where(and(eq(securityQuestionnaires.orgId, orgId), eq(securityQuestionnaires.status, "completed")));

      const [{ value: inProgressQuestionnaires }] = await db
        .select({ value: count() })
        .from(securityQuestionnaires)
        .where(and(eq(securityQuestionnaires.orgId, orgId), eq(securityQuestionnaires.status, "in_progress")));

      // Score history count
      const [{ value: historyCount }] = await db
        .select({ value: count() })
        .from(postureScoreHistory)
        .where(eq(postureScoreHistory.orgId, orgId));

      res.json({
        overallScore: evidence.status === "completed" && latestScore ? latestScore.overallScore : null,
        available: evidence.status === "completed" && Boolean(latestScore),
        reason:
          evidence.status === "completed" && latestScore
            ? null
            : evidence.reason || "No posture evidence has been measured for this organization.",
        lastCalculated: evidence.status === "completed" ? latestScore?.generatedAt || null : null,
        subScores: subScores.map((s) => ({
          domain: s.domain,
          score: s.score,
          weight: s.weight,
          controlsEvaluated: s.controlsEvaluated,
          controlsPassed: s.controlsPassed,
          controlsFailed: s.controlsFailed,
        })),
        benchmark: benchmark
          ? {
              percentileRank: benchmark.percentileRank,
              peerCount: benchmark.peerCount,
              industry: benchmark.industrySegment,
              companySize: benchmark.companySize,
            }
          : null,
        trustPage: trustPage
          ? {
              slug: trustPage.slug,
              status: trustPage.status,
              visitCount: trustPage.visitCount,
              publishedAt: trustPage.publishedAt,
            }
          : null,
        questionnaires: {
          total: Number(totalQuestionnaires),
          completed: Number(completedQuestionnaires),
          inProgress: Number(inProgressQuestionnaires),
        },
        historyEntries: Number(historyCount),
        domainMeta: DOMAIN_META,
      });
    } catch (error) {
      log.error("Failed to fetch posture trust summary", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch summary" });
    }
  });

  // ==========================================================================
  // 60.5 — CONTINUOUS POSTURE RECALCULATION (webhook trigger)
  // ==========================================================================

  app.post(
    "/api/posture-trust/recalculate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { trigger } = req.body as { trigger?: string };

        // Re-generate domain scores based on current state
        const evidence = await generateDomainScores(orgId);
        if (evidence.status === "unavailable" || evidence.overallScore === null) {
          return res.status(422).json(evidence);
        }
        const { domainScores, overallScore } = evidence;

        // Fetch previous score for comparison
        const [prevScore] = await db
          .select()
          .from(postureScores)
          .where(eq(postureScores.orgId, orgId))
          .orderBy(desc(postureScores.generatedAt))
          .limit(1);

        const previousOverall = prevScore?.overallScore || 0;
        const scoreDelta = overallScore - previousOverall;

        // Store new score
        const [newScore] = await db
          .insert(postureScores)
          .values({
            orgId,
            overallScore,
            cspmScore: domainScores.find((d) => d.domain === "cloud")?.score ?? null,
            endpointScore: domainScores.find((d) => d.domain === "endpoint")?.score ?? null,
            incidentScore: domainScores.find((d) => d.domain === "network")?.score ?? null,
            complianceScore: domainScores.find((d) => d.domain === "data")?.score ?? null,
            breakdown: {
              domainScores: domainScores.map((d) => ({
                domain: d.domain,
                score: d.score,
                weight: d.weight,
                controlsEvaluated: d.controlsEvaluated,
                controlsPassed: d.controlsPassed,
                controlsFailed: d.controlsFailed,
              })),
              trigger: trigger || "manual_recalculation",
            },
          })
          .returning();

        // Store sub-scores
        for (const ds of domainScores) {
          await db.insert(postureSubScores).values({
            orgId,
            postureScoreId: newScore.id,
            domain: ds.domain,
            score: ds.score,
            weight: ds.weight,
            controlsEvaluated: ds.controlsEvaluated,
            controlsPassed: ds.controlsPassed,
            controlsFailed: ds.controlsFailed,
            findings: ds.findings || [],
            recommendations: ds.recommendations || [],
          });
        }

        res.json({
          overallScore,
          previousScore: previousOverall,
          delta: scoreDelta,
          trigger: trigger || "manual_recalculation",
          recalculatedAt: newScore.generatedAt,
          domainScores: domainScores.map((d) => ({
            domain: d.domain,
            score: d.score,
            weight: d.weight,
          })),
        });
      } catch (error) {
        log.error("Failed to recalculate posture score", { error: String(error) });
        res.status(500).json({ message: "Failed to recalculate" });
      }
    },
  );

  // ==========================================================================
  // 60.6 — QUESTIONNAIRE RESPONSE AUTO-POPULATION
  // ==========================================================================

  app.post(
    "/api/posture-trust/questionnaires/:id/auto-populate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const qId = String(req.params.id);

        // Verify questionnaire belongs to org
        const [questionnaire] = await db
          .select()
          .from(securityQuestionnaires)
          .where(and(eq(securityQuestionnaires.id, qId), eq(securityQuestionnaires.orgId, orgId)));

        if (!questionnaire) {
          return res.status(404).json({ message: "Questionnaire not found" });
        }

        // Get latest posture data to auto-populate answers
        const [latestScore] = await db
          .select()
          .from(postureScores)
          .where(eq(postureScores.orgId, orgId))
          .orderBy(desc(postureScores.generatedAt))
          .limit(1);

        const subScores = latestScore
          ? await db
              .select()
              .from(postureSubScores)
              .where(and(eq(postureSubScores.orgId, orgId), eq(postureSubScores.postureScoreId, latestScore.id)))
          : [];

        // Get existing responses to update
        const responses = await db
          .select()
          .from(questionnaireResponses)
          .where(eq(questionnaireResponses.questionnaireId, qId as string));

        let autoPopulatedCount = 0;

        for (const response of responses) {
          if (response.answerSource === "platform" && response.status === "auto_answered") {
            continue; // Already auto-populated
          }

          // Try to match response category to sub-score domain
          const matchedDomain = subScores.find(
            (s) => s.domain === response.category || response.category?.includes(s.domain),
          );

          if (matchedDomain) {
            const confidence = Math.min(Math.round(matchedDomain.score * 0.9 + 10), 100);
            const autoAnswer = `Based on platform data: ${matchedDomain.domain} domain scores ${matchedDomain.score}/100 with ${matchedDomain.controlsPassed}/${matchedDomain.controlsEvaluated} controls passing. ${matchedDomain.score >= 80 ? "Strong controls in place." : matchedDomain.score >= 60 ? "Moderate controls with room for improvement." : "Controls need strengthening."}`;

            await db
              .update(questionnaireResponses)
              .set({
                answerText: autoAnswer,
                answerSource: "platform",
                confidencePercent: confidence,
                status: "auto_answered",
              })
              .where(eq(questionnaireResponses.id, response.id));

            autoPopulatedCount++;
          }
        }

        // Update questionnaire answered count
        const answeredCount =
          responses.filter((r) => r.status === "auto_answered" || r.status === "reviewed").length + autoPopulatedCount;

        await db
          .update(securityQuestionnaires)
          .set({
            answeredQuestions: Math.min(answeredCount, questionnaire.totalQuestions ?? 0),
            confidenceScore: latestScore ? Math.round(latestScore.overallScore * 0.85) : 50,
          })
          .where(eq(securityQuestionnaires.id, qId as string));

        res.json({
          autoPopulatedCount,
          totalResponses: responses.length,
          overallScore: latestScore?.overallScore || 0,
          message: `Auto-populated ${autoPopulatedCount} responses from platform data`,
        });
      } catch (error) {
        log.error("Failed to auto-populate questionnaire", { error: String(error) });
        res.status(500).json({ message: "Failed to auto-populate" });
      }
    },
  );
}
