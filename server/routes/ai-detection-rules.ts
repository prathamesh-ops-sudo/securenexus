import type { Express } from "express";
import { eq, and, desc, sql, ilike, or } from "drizzle-orm";
import { db } from "../db";
import {
  ruleGenerationJobs,
  ruleAbTests,
  ruleMarketplace,
  ruleLifecycleEvents,
  detectionRules,
} from "../../shared/schema";
import { getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { logger } from "../logger";
import {
  generateSigmaRule,
  generateYaraRule,
  extractTTPs,
  generateRulesFromTTPs,
  scoreExistingRule,
  evaluateLifecycle,
} from "../ai/rule-generator";

const log = logger.child("ai-detection-rules");

const VALID_RULE_FORMATS = ["sigma", "yara", "custom"];
const VALID_SOURCES = ["incident", "threat_intel", "manual", "log_analysis"];
const VALID_AB_STATUSES = ["pending", "running", "completed", "cancelled"];
const VALID_MARKETPLACE_STATUSES = ["draft", "published", "deprecated", "removed"];
const VALID_SEVERITIES = ["low", "medium", "high", "critical"];
const VALID_LIFECYCLE_ACTIONS = ["created", "enabled", "disabled", "shadow_mode", "promoted", "deprecated", "archived"];

export function registerAiDetectionRulesRoutes(app: Express): void {
  // ==========================================================================
  // RULE GENERATION
  // ==========================================================================

  // Generate rule from context (incident, threat intel, manual)
  app.post("/api/ai-detection-rules/generate", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { source, sourceId, context, ruleFormat } = req.body;

      if (!context || typeof context !== "string" || context.trim().length < 10) {
        return res.status(400).json({ message: "context is required (min 10 characters)" });
      }
      const format = VALID_RULE_FORMATS.includes(ruleFormat) ? ruleFormat : "sigma";
      const src = VALID_SOURCES.includes(source) ? source : "manual";

      // Create generation job
      const [job] = await db
        .insert(ruleGenerationJobs)
        .values({
          orgId,
          source: src,
          sourceId: sourceId || null,
          sourceContext: context.slice(0, 10000),
          ruleFormat: format,
          status: "generating",
          requestedBy: (req as any).user?.email || null,
        })
        .returning();

      // Generate rule asynchronously but wait for result
      const start = Date.now();
      try {
        const result =
          format === "yara" ? await generateYaraRule(context, orgId) : await generateSigmaRule(context, orgId);

        const updateData: Record<string, unknown> = {
          status: "completed",
          generatedName: result.rule.name,
          generatedDescription: result.rule.description,
          generatedSeverity: result.rule.severity,
          generatedMitreTactic: result.rule.mitreTactic,
          generatedMitreTechnique: result.rule.mitreTechnique,
          generatedTags: result.rule.tags,
          generatedConditionTree: result.rule.conditionTree,
          qualityScore: result.quality.overall,
          estimatedFpRate: result.quality.estimatedFpRate,
          qualityBreakdown: result.quality.breakdown,
          modelId: result.modelId,
          inputTokens: result.inputTokens,
          outputTokens: result.outputTokens,
          costUsd: result.costUsd,
          latencyMs: result.latencyMs,
          completedAt: new Date(),
        };

        if ("sigmaYaml" in result.rule) {
          updateData.generatedSigmaYaml = result.rule.sigmaYaml;
        }
        if ("yaraRule" in result.rule) {
          updateData.generatedYaraRule = result.rule.yaraRule;
        }

        const [updated] = await db
          .update(ruleGenerationJobs)
          .set(updateData)
          .where(eq(ruleGenerationJobs.id, job.id))
          .returning();

        res.status(201).json({ job: updated, quality: result.quality });
      } catch (genError) {
        await db
          .update(ruleGenerationJobs)
          .set({
            status: "failed",
            errorMessage: String(genError),
            latencyMs: Date.now() - start,
          })
          .where(eq(ruleGenerationJobs.id, job.id));

        return res.status(500).json({
          message: "Rule generation failed",
          error: String(genError),
          jobId: job.id,
        });
      }
    } catch (error) {
      log.error("Failed to generate rule", { error: String(error) });
      res.status(500).json({ message: "Failed to generate rule" });
    }
  });

  // Generate rules from threat intel report (extract TTPs, then generate)
  app.post(
    "/api/ai-detection-rules/generate-from-threat-intel",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { report, ruleFormat } = req.body;

        if (!report || typeof report !== "string" || report.trim().length < 20) {
          return res.status(400).json({ message: "report is required (min 20 characters)" });
        }
        const format = ruleFormat === "yara" ? "yara" : "sigma";

        // Step 1: Extract TTPs
        const ttpResult = await extractTTPs(report, orgId);

        if (ttpResult.result.ttps.length === 0) {
          return res.status(200).json({
            ttps: [],
            rules: [],
            summary: ttpResult.result.summary,
            message: "No TTPs were extracted from the report",
          });
        }

        // Step 2: Generate rules from TTPs
        const ruleResults = await generateRulesFromTTPs(ttpResult.result.ttps, format as "sigma" | "yara", orgId);

        // Step 3: Save generation jobs
        const jobs = [];
        for (const result of ruleResults) {
          const jobInsert: typeof ruleGenerationJobs.$inferInsert = {
            orgId,
            source: "threat_intel",
            sourceContext: report.slice(0, 5000),
            ruleFormat: format,
            status: "completed",
            generatedName: result.rule.name,
            generatedDescription: result.rule.description,
            generatedSeverity: result.rule.severity,
            generatedMitreTactic: result.rule.mitreTactic,
            generatedMitreTechnique: result.rule.mitreTechnique,
            generatedTags: result.rule.tags,
            generatedConditionTree: result.rule.conditionTree,
            qualityScore: result.quality.overall,
            estimatedFpRate: result.quality.estimatedFpRate,
            qualityBreakdown: result.quality.breakdown,
            modelId: result.modelId,
            inputTokens: result.inputTokens,
            outputTokens: result.outputTokens,
            costUsd: result.costUsd,
            latencyMs: result.latencyMs,
            requestedBy: (req as any).user?.email || null,
            completedAt: new Date(),
          };

          if ("sigmaYaml" in result.rule) {
            jobInsert.generatedSigmaYaml = result.rule.sigmaYaml;
          }
          if ("yaraRule" in result.rule) {
            jobInsert.generatedYaraRule = result.rule.yaraRule;
          }

          const [job] = await db.insert(ruleGenerationJobs).values(jobInsert).returning();
          jobs.push({ job, quality: result.quality });
        }

        res.status(201).json({
          ttps: ttpResult.result.ttps,
          summary: ttpResult.result.summary,
          threatActor: ttpResult.result.threatActor,
          targetSectors: ttpResult.result.targetSectors,
          rules: jobs,
          ttpExtractionCost: ttpResult.costUsd,
        });
      } catch (error) {
        log.error("Failed to generate rules from threat intel", { error: String(error) });
        res.status(500).json({ message: "Failed to generate rules from threat intel" });
      }
    },
  );

  // List generation jobs
  app.get("/api/ai-detection-rules/jobs", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const source = req.query.source as string | undefined;
      const limitParam = Math.min(parseInt(String(req.query.limit || "50")), 200);
      const offsetParam = parseInt(String(req.query.offset || "0"));

      const conditions: unknown[] = [eq(ruleGenerationJobs.orgId, orgId)];
      if (status && status !== "all") conditions.push(eq(ruleGenerationJobs.status, status));
      if (source && source !== "all") conditions.push(eq(ruleGenerationJobs.source, source));

      const jobs = await db
        .select()
        .from(ruleGenerationJobs)
        .where(and(...(conditions as any[])))
        .orderBy(desc(ruleGenerationJobs.createdAt))
        .limit(limitParam)
        .offset(offsetParam);

      const [countResult] = await db
        .select({ count: sql<number>`count(*)` })
        .from(ruleGenerationJobs)
        .where(and(...(conditions as any[])));

      res.json({ jobs, total: Number(countResult?.count || 0) });
    } catch (error) {
      log.error("Failed to list generation jobs", { error: String(error) });
      res.status(500).json({ message: "Failed to list generation jobs" });
    }
  });

  // Get single generation job
  app.get("/api/ai-detection-rules/jobs/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const jobId = String(req.params.id);

      const [job] = await db
        .select()
        .from(ruleGenerationJobs)
        .where(and(eq(ruleGenerationJobs.id, jobId), eq(ruleGenerationJobs.orgId, orgId)))
        .limit(1);

      if (!job) {
        return res.status(404).json({ message: "Generation job not found" });
      }

      res.json({ job });
    } catch (error) {
      log.error("Failed to get generation job", { error: String(error) });
      res.status(500).json({ message: "Failed to get generation job" });
    }
  });

  // Deploy generated rule (create actual detection rule from generation job)
  app.post(
    "/api/ai-detection-rules/jobs/:id/deploy",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const jobId = String(req.params.id);

        const [job] = await db
          .select()
          .from(ruleGenerationJobs)
          .where(and(eq(ruleGenerationJobs.id, jobId), eq(ruleGenerationJobs.orgId, orgId)))
          .limit(1);

        if (!job) {
          return res.status(404).json({ message: "Generation job not found" });
        }
        if (job.status !== "completed") {
          return res.status(400).json({ message: "Only completed jobs can be deployed" });
        }
        if (!job.generatedConditionTree || !job.generatedName) {
          return res.status(400).json({ message: "Job has no generated rule data" });
        }

        // Create a detection rule from the generated job
        const [rule] = await db
          .insert(detectionRules)
          .values({
            orgId,
            name: job.generatedName,
            description: job.generatedDescription || null,
            severity: job.generatedSeverity || "medium",
            status: "enabled",
            mitreTactic: job.generatedMitreTactic || null,
            mitreTechnique: job.generatedMitreTechnique || null,
            conditionTree: job.generatedConditionTree,
            eventTypes: job.generatedTags || [],
            author: (req as any).user?.email || "ai-generated",
            tags: [...(job.generatedTags || []), "ai-generated"],
            isBuiltin: false,
          })
          .returning();

        // Update job with deployed rule ID
        await db.update(ruleGenerationJobs).set({ generatedRuleId: rule.id }).where(eq(ruleGenerationJobs.id, jobId));

        // Log lifecycle event
        await db.insert(ruleLifecycleEvents).values({
          orgId,
          ruleId: rule.id,
          action: "created",
          newStatus: "enabled",
          reason: `AI-generated from ${job.source} context`,
          performedBy: (req as any).user?.email || null,
          metadata: { generationJobId: jobId, qualityScore: job.qualityScore },
        });

        res.status(201).json({ rule, jobId });
      } catch (error) {
        log.error("Failed to deploy generated rule", { error: String(error) });
        res.status(500).json({ message: "Failed to deploy generated rule" });
      }
    },
  );

  // Score an existing rule's quality
  app.get(
    "/api/ai-detection-rules/quality/:ruleId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const ruleId = String(req.params.ruleId);

        const [rule] = await db
          .select()
          .from(detectionRules)
          .where(
            and(
              eq(detectionRules.id, ruleId),
              or(eq(detectionRules.orgId, orgId), sql`${detectionRules.orgId} IS NULL`),
            ),
          )
          .limit(1);

        if (!rule) {
          return res.status(404).json({ message: "Detection rule not found" });
        }

        const quality = scoreExistingRule({
          conditionTree: rule.conditionTree,
          mitreTactic: rule.mitreTactic,
          mitreTechnique: rule.mitreTechnique,
          falsePositiveNotes: rule.falsePositiveNotes,
          eventTypes: rule.eventTypes,
          tags: rule.tags,
        });

        res.json({ ruleId, quality });
      } catch (error) {
        log.error("Failed to score rule quality", { error: String(error) });
        res.status(500).json({ message: "Failed to score rule quality" });
      }
    },
  );

  // ==========================================================================
  // A/B TESTING
  // ==========================================================================

  // Create A/B test for a rule (shadow mode)
  app.post("/api/ai-detection-rules/ab-tests", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, description, ruleId, durationDays } = req.body;

      if (!name || typeof name !== "string") {
        return res.status(400).json({ message: "name is required" });
      }
      if (!ruleId || typeof ruleId !== "string") {
        return res.status(400).json({ message: "ruleId is required" });
      }

      // Verify rule exists and belongs to org
      const [rule] = await db
        .select()
        .from(detectionRules)
        .where(and(eq(detectionRules.id, ruleId), eq(detectionRules.orgId, orgId)))
        .limit(1);

      if (!rule) {
        return res.status(404).json({ message: "Detection rule not found" });
      }

      const [test] = await db
        .insert(ruleAbTests)
        .values({
          orgId,
          name,
          description: description || null,
          ruleId,
          durationDays: durationDays || 7,
          status: "pending",
          shadowModeEnabled: true,
          createdBy: (req as any).user?.email || null,
        })
        .returning();

      res.status(201).json({ test });
    } catch (error) {
      log.error("Failed to create A/B test", { error: String(error) });
      res.status(500).json({ message: "Failed to create A/B test" });
    }
  });

  // List A/B tests
  app.get("/api/ai-detection-rules/ab-tests", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;

      const conditions: unknown[] = [eq(ruleAbTests.orgId, orgId)];
      if (status && VALID_AB_STATUSES.includes(status)) {
        conditions.push(eq(ruleAbTests.status, status));
      }

      const tests = await db
        .select()
        .from(ruleAbTests)
        .where(and(...(conditions as any[])))
        .orderBy(desc(ruleAbTests.createdAt));

      res.json({ tests });
    } catch (error) {
      log.error("Failed to list A/B tests", { error: String(error) });
      res.status(500).json({ message: "Failed to list A/B tests" });
    }
  });

  // Start A/B test
  app.post(
    "/api/ai-detection-rules/ab-tests/:id/start",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const testId = String(req.params.id);

        const [test] = await db
          .select()
          .from(ruleAbTests)
          .where(and(eq(ruleAbTests.id, testId), eq(ruleAbTests.orgId, orgId)))
          .limit(1);

        if (!test) {
          return res.status(404).json({ message: "A/B test not found" });
        }
        if (test.status !== "pending") {
          return res.status(400).json({ message: "Test can only be started from pending state" });
        }

        const [updated] = await db
          .update(ruleAbTests)
          .set({
            status: "running",
            startedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(ruleAbTests.id, testId))
          .returning();

        // Log lifecycle event for the rule entering shadow mode
        await db.insert(ruleLifecycleEvents).values({
          orgId,
          ruleId: test.ruleId,
          action: "shadow_mode",
          reason: `A/B test "${test.name}" started`,
          performedBy: (req as any).user?.email || null,
          metadata: { abTestId: testId },
        });

        res.json({ test: updated });
      } catch (error) {
        log.error("Failed to start A/B test", { error: String(error) });
        res.status(500).json({ message: "Failed to start A/B test" });
      }
    },
  );

  // Complete A/B test with verdict
  app.post(
    "/api/ai-detection-rules/ab-tests/:id/complete",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const testId = String(req.params.id);
        const { verdict, verdictReason, promote } = req.body;

        const [test] = await db
          .select()
          .from(ruleAbTests)
          .where(and(eq(ruleAbTests.id, testId), eq(ruleAbTests.orgId, orgId)))
          .limit(1);

        if (!test) {
          return res.status(404).json({ message: "A/B test not found" });
        }
        if (test.status !== "running") {
          return res.status(400).json({ message: "Test can only be completed from running state" });
        }

        const updateFields: Record<string, unknown> = {
          status: "completed",
          endedAt: new Date(),
          updatedAt: new Date(),
          verdict: verdict || null,
          verdictReason: verdictReason || null,
        };

        if (promote) {
          updateFields.promotedAt = new Date();
        }

        const [updated] = await db.update(ruleAbTests).set(updateFields).where(eq(ruleAbTests.id, testId)).returning();

        // If promoting, enable the rule
        if (promote) {
          await db
            .update(detectionRules)
            .set({ status: "enabled", updatedAt: new Date() })
            .where(eq(detectionRules.id, test.ruleId));

          await db.insert(ruleLifecycleEvents).values({
            orgId,
            ruleId: test.ruleId,
            action: "promoted",
            previousStatus: "shadow_mode",
            newStatus: "enabled",
            reason: `A/B test "${test.name}" passed — promoted to production`,
            performedBy: (req as any).user?.email || null,
            metadata: { abTestId: testId, verdict },
          });
        }

        res.json({ test: updated });
      } catch (error) {
        log.error("Failed to complete A/B test", { error: String(error) });
        res.status(500).json({ message: "Failed to complete A/B test" });
      }
    },
  );

  // ==========================================================================
  // LIFECYCLE MANAGEMENT
  // ==========================================================================

  // Get lifecycle events for a rule
  app.get(
    "/api/ai-detection-rules/lifecycle/:ruleId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const ruleId = String(req.params.ruleId);

        const events = await db
          .select()
          .from(ruleLifecycleEvents)
          .where(and(eq(ruleLifecycleEvents.orgId, orgId), eq(ruleLifecycleEvents.ruleId, ruleId)))
          .orderBy(desc(ruleLifecycleEvents.createdAt));

        res.json({ events });
      } catch (error) {
        log.error("Failed to get lifecycle events", { error: String(error) });
        res.status(500).json({ message: "Failed to get lifecycle events" });
      }
    },
  );

  // Log a lifecycle event
  app.post("/api/ai-detection-rules/lifecycle", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { ruleId, action, previousStatus, newStatus, reason } = req.body;

      if (!ruleId || typeof ruleId !== "string") {
        return res.status(400).json({ message: "ruleId is required" });
      }
      if (!action || !VALID_LIFECYCLE_ACTIONS.includes(action)) {
        return res.status(400).json({ message: `action must be one of: ${VALID_LIFECYCLE_ACTIONS.join(", ")}` });
      }

      // Verify rule exists
      const [rule] = await db
        .select()
        .from(detectionRules)
        .where(
          and(eq(detectionRules.id, ruleId), or(eq(detectionRules.orgId, orgId), sql`${detectionRules.orgId} IS NULL`)),
        )
        .limit(1);

      if (!rule) {
        return res.status(404).json({ message: "Detection rule not found" });
      }

      const [event] = await db
        .insert(ruleLifecycleEvents)
        .values({
          orgId,
          ruleId,
          action,
          previousStatus: previousStatus || null,
          newStatus: newStatus || null,
          reason: reason || null,
          matchCountAtAction: rule.matchCount,
          performedBy: (req as any).user?.email || null,
        })
        .returning();

      res.status(201).json({ event });
    } catch (error) {
      log.error("Failed to log lifecycle event", { error: String(error) });
      res.status(500).json({ message: "Failed to log lifecycle event" });
    }
  });

  // Get deprecation candidates (rules with 0 hits in 90 days)
  app.get(
    "/api/ai-detection-rules/lifecycle/deprecation-candidates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const rules = await db
          .select()
          .from(detectionRules)
          .where(
            and(
              or(eq(detectionRules.orgId, orgId), sql`${detectionRules.orgId} IS NULL`),
              eq(detectionRules.status, "enabled"),
            ),
          );

        const candidates = rules
          .map((rule) =>
            evaluateLifecycle({
              id: rule.id,
              name: rule.name,
              matchCount: rule.matchCount,
              lastMatchAt: rule.lastMatchAt,
              createdAt: rule.createdAt,
              status: rule.status,
            }),
          )
          .filter((c) => c.recommendation !== "keep")
          .sort((a, b) => b.daysSinceLastMatch - a.daysSinceLastMatch);

        res.json({ candidates, total: candidates.length });
      } catch (error) {
        log.error("Failed to get deprecation candidates", { error: String(error) });
        res.status(500).json({ message: "Failed to get deprecation candidates" });
      }
    },
  );

  // ==========================================================================
  // MARKETPLACE
  // ==========================================================================

  // Publish rule to marketplace
  app.post(
    "/api/ai-detection-rules/marketplace",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { ruleId, title, description, category, tags } = req.body;

        if (!ruleId || typeof ruleId !== "string") {
          return res.status(400).json({ message: "ruleId is required" });
        }
        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }

        // Verify rule exists and belongs to org
        const [rule] = await db
          .select()
          .from(detectionRules)
          .where(and(eq(detectionRules.id, ruleId), eq(detectionRules.orgId, orgId)))
          .limit(1);

        if (!rule) {
          return res.status(404).json({ message: "Detection rule not found or not owned by org" });
        }

        const [entry] = await db
          .insert(ruleMarketplace)
          .values({
            orgId,
            ruleId,
            title,
            description: description || rule.description || null,
            category: category || "general",
            ruleFormat: "sigma",
            conditionTree: rule.conditionTree,
            mitreTactic: rule.mitreTactic,
            mitreTechnique: rule.mitreTechnique,
            severity: rule.severity,
            tags: tags || rule.tags || [],
            status: "published",
            publishedBy: (req as any).user?.email || null,
            publishedAt: new Date(),
          })
          .returning();

        res.status(201).json({ entry });
      } catch (error) {
        log.error("Failed to publish to marketplace", { error: String(error) });
        res.status(500).json({ message: "Failed to publish to marketplace" });
      }
    },
  );

  // List marketplace entries (public)
  app.get("/api/ai-detection-rules/marketplace", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const q = (req.query.q as string) || "";
      const category = req.query.category as string | undefined;
      const severity = req.query.severity as string | undefined;
      const limitParam = Math.min(parseInt(String(req.query.limit || "50")), 200);
      const offsetParam = parseInt(String(req.query.offset || "0"));

      const conditions: unknown[] = [eq(ruleMarketplace.status, "published")];
      if (category && category !== "all") {
        conditions.push(eq(ruleMarketplace.category, category));
      }
      if (severity && VALID_SEVERITIES.includes(severity)) {
        conditions.push(eq(ruleMarketplace.severity, severity));
      }
      if (q) {
        conditions.push(or(ilike(ruleMarketplace.title, `%${q}%`), ilike(ruleMarketplace.description, `%${q}%`)));
      }

      const entries = await db
        .select()
        .from(ruleMarketplace)
        .where(and(...(conditions as any[])))
        .orderBy(desc(ruleMarketplace.downloads), desc(ruleMarketplace.rating))
        .limit(limitParam)
        .offset(offsetParam);

      const [countResult] = await db
        .select({ count: sql<number>`count(*)` })
        .from(ruleMarketplace)
        .where(and(...(conditions as any[])));

      res.json({ entries, total: Number(countResult?.count || 0) });
    } catch (error) {
      log.error("Failed to list marketplace entries", { error: String(error) });
      res.status(500).json({ message: "Failed to list marketplace entries" });
    }
  });

  // Import rule from marketplace
  app.post(
    "/api/ai-detection-rules/marketplace/:id/import",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entryId = String(req.params.id);

        const [entry] = await db
          .select()
          .from(ruleMarketplace)
          .where(and(eq(ruleMarketplace.id, entryId), eq(ruleMarketplace.status, "published")))
          .limit(1);

        if (!entry) {
          return res.status(404).json({ message: "Marketplace entry not found" });
        }

        if (!entry.conditionTree) {
          return res.status(400).json({ message: "Entry has no condition tree to import" });
        }

        // Create detection rule from marketplace entry
        const [rule] = await db
          .insert(detectionRules)
          .values({
            orgId,
            name: entry.title,
            description: entry.description || null,
            severity: entry.severity,
            status: "enabled",
            mitreTactic: entry.mitreTactic || null,
            mitreTechnique: entry.mitreTechnique || null,
            conditionTree: entry.conditionTree,
            tags: [...(entry.tags || []), "marketplace-import"],
            author: `marketplace:${entry.publishedBy || "community"}`,
            isBuiltin: false,
          })
          .returning();

        // Increment download count atomically
        await db
          .update(ruleMarketplace)
          .set({ downloads: sql`${ruleMarketplace.downloads} + 1` })
          .where(eq(ruleMarketplace.id, entryId));

        // Log lifecycle event
        await db.insert(ruleLifecycleEvents).values({
          orgId,
          ruleId: rule.id,
          action: "created",
          newStatus: "enabled",
          reason: `Imported from marketplace: ${entry.title}`,
          performedBy: (req as any).user?.email || null,
          metadata: { marketplaceEntryId: entryId },
        });

        res.status(201).json({ rule });
      } catch (error) {
        log.error("Failed to import from marketplace", { error: String(error) });
        res.status(500).json({ message: "Failed to import from marketplace" });
      }
    },
  );

  // Rate a marketplace entry
  app.post(
    "/api/ai-detection-rules/marketplace/:id/rate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const entryId = String(req.params.id);
        const { rating } = req.body;

        if (typeof rating !== "number" || rating < 1 || rating > 5) {
          return res.status(400).json({ message: "rating must be a number between 1 and 5" });
        }

        const [entry] = await db.select().from(ruleMarketplace).where(eq(ruleMarketplace.id, entryId)).limit(1);

        if (!entry) {
          return res.status(404).json({ message: "Marketplace entry not found" });
        }

        // Calculate new weighted average
        const currentRating = entry.rating || 0;
        const currentCount = entry.ratingCount;
        const newCount = currentCount + 1;
        const newRating = (currentRating * currentCount + rating) / newCount;

        const [updated] = await db
          .update(ruleMarketplace)
          .set({
            rating: newRating,
            ratingCount: newCount,
            updatedAt: new Date(),
          })
          .where(eq(ruleMarketplace.id, entryId))
          .returning();

        res.json({ entry: updated });
      } catch (error) {
        log.error("Failed to rate marketplace entry", { error: String(error) });
        res.status(500).json({ message: "Failed to rate marketplace entry" });
      }
    },
  );

  // ==========================================================================
  // OVERVIEW / STATS
  // ==========================================================================

  app.get("/api/ai-detection-rules/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const genResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total_jobs,
            COUNT(*) FILTER (WHERE status = 'completed') AS completed_jobs,
            COUNT(*) FILTER (WHERE status = 'failed') AS failed_jobs,
            COUNT(*) FILTER (WHERE status = 'generating') AS in_progress_jobs,
            ROUND(AVG(quality_score) FILTER (WHERE status = 'completed'))::int AS avg_quality_score,
            ROUND(AVG(estimated_fp_rate) FILTER (WHERE status = 'completed'), 3)::float AS avg_fp_rate,
            COALESCE(SUM(cost_usd) FILTER (WHERE status = 'completed'), 0)::float AS total_cost
          FROM rule_generation_jobs
          WHERE org_id = ${orgId}
        `);

      const abResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total_tests,
            COUNT(*) FILTER (WHERE status = 'running') AS running_tests,
            COUNT(*) FILTER (WHERE status = 'completed') AS completed_tests,
            COUNT(*) FILTER (WHERE promoted_at IS NOT NULL) AS promoted_count
          FROM rule_ab_tests
          WHERE org_id = ${orgId}
        `);

      const marketplaceResult = await db.execute(sql`
          SELECT
            COUNT(*) AS published_count,
            COALESCE(SUM(downloads), 0) AS total_downloads,
            ROUND(AVG(rating), 1)::float AS avg_rating
          FROM rule_marketplace
          WHERE org_id = ${orgId} AND status = 'published'
        `);

      const lifecycleResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total_events,
            COUNT(*) FILTER (WHERE action = 'deprecated') AS deprecated_count,
            COUNT(*) FILTER (WHERE action = 'promoted') AS promoted_count,
            COUNT(*) FILTER (WHERE action = 'created') AS created_count
          FROM rule_lifecycle_events
          WHERE org_id = ${orgId}
        `);

      res.json({
        generation: genResult.rows[0] || {},
        abTesting: abResult.rows[0] || {},
        marketplace: marketplaceResult.rows[0] || {},
        lifecycle: lifecycleResult.rows[0] || {},
      });
    } catch (error) {
      log.error("Failed to get AI detection rules stats", { error: String(error) });
      res.status(500).json({ message: "Failed to get stats" });
    }
  });
}
