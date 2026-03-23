import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count, ilike, or, gte } from "drizzle-orm";
import {
  phishingCampaigns,
  phishingTemplates,
  phishingResults,
  employeeRiskScores,
  trainingModules,
  trainingAssignments,
  securityAwarenessConfig,
  PHISHING_CAMPAIGN_STATUSES,
  PHISHING_TEMPLATE_CATEGORIES,
  TRAINING_MODULE_TYPES,
} from "../../shared/schema";
import { launchCampaign, completeCampaign, recordPhishingEvent, recalculateRiskScore } from "../phishing-engine";

const log = logger.child("security-awareness");

const ALLOWED_CAMPAIGN_FIELDS = [
  "name",
  "description",
  "templateId",
  "templateCategory",
  "senderName",
  "senderEmail",
  "subject",
  "emailBody",
  "landingPageHtml",
  "targetDepartments",
  "targetEmails",
  "scheduledAt",
];
const ALLOWED_TEMPLATE_FIELDS = [
  "name",
  "category",
  "difficulty",
  "industry",
  "subject",
  "senderName",
  "senderEmail",
  "emailBody",
  "landingPageHtml",
  "isBuiltIn",
];
const ALLOWED_MODULE_FIELDS = [
  "title",
  "description",
  "moduleType",
  "category",
  "difficulty",
  "durationMinutes",
  "contentUrl",
  "passingScore",
  "isBuiltIn",
  "isActive",
];
const ALLOWED_CONFIG_FIELDS = [
  "isEnabled",
  "autoEnrollOnClick",
  "defaultTrainingModuleId",
  "phishingFrequencyDays",
  "vishingEnabled",
  "smishingEnabled",
  "riskScoreThreshold",
];

export function registerSecurityAwarenessRoutes(app: Express): void {
  // ==========================================================================
  // Phishing Campaigns
  // ==========================================================================

  // GET /api/security-awareness/campaigns
  app.get(
    "/api/security-awareness/campaigns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(phishingCampaigns.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(phishingCampaigns.status, status));
        }
        if (search && typeof search === "string") {
          const escaped = search.replace(/[%_\\]/g, "\\$&");
          conditions.push(ilike(phishingCampaigns.name, `%${escaped}%`));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(phishingCampaigns)
            .where(and(...conditions))
            .orderBy(desc(phishingCampaigns.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(phishingCampaigns)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list campaigns", { error: String(err) });
        res.status(500).json({ error: "Failed to list campaigns" });
      }
    },
  );

  // POST /api/security-awareness/campaigns
  app.post(
    "/api/security-awareness/campaigns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_CAMPAIGN_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name) {
          return res.status(400).json({ error: "name is required" });
        }

        const [created] = await db
          .insert(phishingCampaigns)
          .values({
            ...body,
            orgId,
            createdBy: (req as any).user?.id || null,
          } as typeof phishingCampaigns.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create campaign", { error: String(err) });
        res.status(500).json({ error: "Failed to create campaign" });
      }
    },
  );

  // GET /api/security-awareness/campaigns/:id
  app.get(
    "/api/security-awareness/campaigns/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [campaign] = await db
          .select()
          .from(phishingCampaigns)
          .where(and(eq(phishingCampaigns.id, String(req.params.id)), eq(phishingCampaigns.orgId, orgId)));
        if (!campaign) return res.status(404).json({ error: "Campaign not found" });

        // Get results for this campaign
        const results = await db
          .select()
          .from(phishingResults)
          .where(and(eq(phishingResults.campaignId, campaign.id), eq(phishingResults.orgId, orgId)));

        res.json({ ...campaign, results });
      } catch (err) {
        log.error("Failed to get campaign", { error: String(err) });
        res.status(500).json({ error: "Failed to get campaign" });
      }
    },
  );

  // PATCH /api/security-awareness/campaigns/:id
  app.patch(
    "/api/security-awareness/campaigns/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_CAMPAIGN_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [updated] = await db
          .update(phishingCampaigns)
          .set(updates)
          .where(and(eq(phishingCampaigns.id, String(req.params.id)), eq(phishingCampaigns.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Campaign not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update campaign", { error: String(err) });
        res.status(500).json({ error: "Failed to update campaign" });
      }
    },
  );

  // POST /api/security-awareness/campaigns/:id/launch
  app.post(
    "/api/security-awareness/campaigns/:id/launch",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await launchCampaign(String(req.params.id), orgId);
        res.json(result);
      } catch (err) {
        log.error("Failed to launch campaign", { error: String(err) });
        res.status(400).json({ error: String(err) });
      }
    },
  );

  // POST /api/security-awareness/campaigns/:id/complete
  app.post(
    "/api/security-awareness/campaigns/:id/complete",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        await completeCampaign(String(req.params.id), orgId);
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to complete campaign", { error: String(err) });
        res.status(500).json({ error: "Failed to complete campaign" });
      }
    },
  );

  // POST /api/security-awareness/campaigns/:id/results/:resultId/track
  app.post(
    "/api/security-awareness/campaigns/:id/results/:resultId/track",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { eventType, userAgent, ipAddress } = req.body;
        if (!eventType || !["opened", "clicked", "submitted", "reported"].includes(eventType)) {
          return res.status(400).json({ error: "eventType must be one of: opened, clicked, submitted, reported" });
        }
        await recordPhishingEvent(String(req.params.resultId), orgId, eventType, { userAgent, ipAddress });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to track event", { error: String(err) });
        res.status(500).json({ error: "Failed to track event" });
      }
    },
  );

  // ==========================================================================
  // Phishing Templates
  // ==========================================================================

  // GET /api/security-awareness/templates
  app.get(
    "/api/security-awareness/templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { category, difficulty, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(phishingTemplates.orgId, orgId)];
        if (category && typeof category === "string") {
          conditions.push(eq(phishingTemplates.category, category));
        }
        if (difficulty && typeof difficulty === "string") {
          conditions.push(eq(phishingTemplates.difficulty, difficulty));
        }
        if (search && typeof search === "string") {
          conditions.push(ilike(phishingTemplates.name, `%${search}%`));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(phishingTemplates)
            .where(and(...conditions))
            .orderBy(desc(phishingTemplates.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(phishingTemplates)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list templates", { error: String(err) });
        res.status(500).json({ error: "Failed to list templates" });
      }
    },
  );

  // POST /api/security-awareness/templates
  app.post(
    "/api/security-awareness/templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_TEMPLATE_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name || !body.category || !body.subject || !body.senderName || !body.senderEmail || !body.emailBody) {
          return res
            .status(400)
            .json({ error: "name, category, subject, senderName, senderEmail, and emailBody are required" });
        }

        const [created] = await db
          .insert(phishingTemplates)
          .values({ ...body, orgId } as typeof phishingTemplates.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create template", { error: String(err) });
        res.status(500).json({ error: "Failed to create template" });
      }
    },
  );

  // ==========================================================================
  // Employee Risk Scores
  // ==========================================================================

  // GET /api/security-awareness/risk-scores
  app.get(
    "/api/security-awareness/risk-scores",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { department, search, trend, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(employeeRiskScores.orgId, orgId)];
        if (department && typeof department === "string") {
          conditions.push(eq(employeeRiskScores.department, department));
        }
        if (trend && typeof trend === "string") {
          conditions.push(eq(employeeRiskScores.riskTrend, trend));
        }
        if (search && typeof search === "string") {
          conditions.push(
            or(ilike(employeeRiskScores.email, `%${search}%`), ilike(employeeRiskScores.name, `%${search}%`))!,
          );
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(employeeRiskScores)
            .where(and(...conditions))
            .orderBy(desc(employeeRiskScores.riskScore))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(employeeRiskScores)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list risk scores", { error: String(err) });
        res.status(500).json({ error: "Failed to list risk scores" });
      }
    },
  );

  // POST /api/security-awareness/risk-scores/recalculate
  app.post(
    "/api/security-awareness/risk-scores/recalculate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { email } = req.body;
        if (!email || typeof email !== "string") {
          return res.status(400).json({ error: "email is required" });
        }
        await recalculateRiskScore(orgId, email);
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to recalculate risk score", { error: String(err) });
        res.status(500).json({ error: "Failed to recalculate risk score" });
      }
    },
  );

  // ==========================================================================
  // Training Modules
  // ==========================================================================

  // GET /api/security-awareness/training/modules
  app.get(
    "/api/security-awareness/training/modules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { type, category, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(trainingModules.orgId, orgId)];
        if (type && typeof type === "string") {
          conditions.push(eq(trainingModules.moduleType, type));
        }
        if (category && typeof category === "string") {
          conditions.push(eq(trainingModules.category, category));
        }
        if (search && typeof search === "string") {
          conditions.push(ilike(trainingModules.title, `%${search}%`));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(trainingModules)
            .where(and(...conditions))
            .orderBy(desc(trainingModules.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(trainingModules)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list training modules", { error: String(err) });
        res.status(500).json({ error: "Failed to list training modules" });
      }
    },
  );

  // POST /api/security-awareness/training/modules
  app.post(
    "/api/security-awareness/training/modules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_MODULE_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.title || !body.moduleType || !body.category) {
          return res.status(400).json({ error: "title, moduleType, and category are required" });
        }

        const [created] = await db
          .insert(trainingModules)
          .values({ ...body, orgId } as typeof trainingModules.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create training module", { error: String(err) });
        res.status(500).json({ error: "Failed to create training module" });
      }
    },
  );

  // ==========================================================================
  // Training Assignments
  // ==========================================================================

  // GET /api/security-awareness/training/assignments
  app.get(
    "/api/security-awareness/training/assignments",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { email, completed, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(trainingAssignments.orgId, orgId)];
        if (email && typeof email === "string") {
          conditions.push(eq(trainingAssignments.employeeEmail, email));
        }
        if (completed === "true") {
          conditions.push(sql`${trainingAssignments.completedAt} IS NOT NULL`);
        }
        if (completed === "false") {
          conditions.push(sql`${trainingAssignments.completedAt} IS NULL`);
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(trainingAssignments)
            .where(and(...conditions))
            .orderBy(desc(trainingAssignments.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(trainingAssignments)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list training assignments", { error: String(err) });
        res.status(500).json({ error: "Failed to list training assignments" });
      }
    },
  );

  // POST /api/security-awareness/training/assignments
  app.post(
    "/api/security-awareness/training/assignments",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { moduleId, employeeEmail, employeeName, assignedReason, dueAt } = req.body;
        if (!moduleId || !employeeEmail) {
          return res.status(400).json({ error: "moduleId and employeeEmail are required" });
        }

        // Verify module exists and belongs to org
        const [module] = await db
          .select()
          .from(trainingModules)
          .where(and(eq(trainingModules.id, moduleId), eq(trainingModules.orgId, orgId)));
        if (!module) return res.status(404).json({ error: "Training module not found" });

        const [created] = await db
          .insert(trainingAssignments)
          .values({
            orgId,
            moduleId,
            employeeEmail,
            employeeName: employeeName || null,
            assignedReason: assignedReason || "manual",
            dueAt: dueAt ? new Date(dueAt) : null,
          })
          .returning();

        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create training assignment", { error: String(err) });
        res.status(500).json({ error: "Failed to create training assignment" });
      }
    },
  );

  // PATCH /api/security-awareness/training/assignments/:id/complete
  app.patch(
    "/api/security-awareness/training/assignments/:id/complete",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { score } = req.body;
        const [assignment] = await db
          .select()
          .from(trainingAssignments)
          .where(and(eq(trainingAssignments.id, String(req.params.id)), eq(trainingAssignments.orgId, orgId)));
        if (!assignment) return res.status(404).json({ error: "Assignment not found" });

        // Get module to check passing score
        const [module] = await db.select().from(trainingModules).where(eq(trainingModules.id, assignment.moduleId));
        const passingScore = module?.passingScore || 80;
        const passed = score != null ? score >= passingScore : true;

        const [updated] = await db
          .update(trainingAssignments)
          .set({
            completedAt: new Date(),
            score: score || null,
            passed,
            attempts: sql`${trainingAssignments.attempts} + 1`,
          })
          .where(eq(trainingAssignments.id, String(req.params.id)))
          .returning();

        // Update module completion count
        if (module) {
          await db
            .update(trainingModules)
            .set({
              completionCount: sql`${trainingModules.completionCount} + 1`,
            })
            .where(eq(trainingModules.id, module.id));
        }

        // 68.3 — Auto-assign training based on phishing failure
        if (!passed && module) {
          // Auto-assign remedial training for failed attempts
          const existingRemedial = await db
            .select()
            .from(trainingAssignments)
            .where(
              and(
                eq(trainingAssignments.orgId, orgId),
                eq(trainingAssignments.employeeEmail, assignment.employeeEmail),
                eq(trainingAssignments.assignedReason, "phishing_failure_remedial"),
                sql`${trainingAssignments.completedAt} IS NULL`,
              ),
            )
            .limit(1);

          if (existingRemedial.length === 0) {
            // Find a suitable remedial module
            const [remedialModule] = await db
              .select()
              .from(trainingModules)
              .where(
                and(
                  eq(trainingModules.orgId, orgId),
                  eq(trainingModules.isActive, true),
                  eq(trainingModules.category, module.category),
                ),
              )
              .limit(1);

            if (remedialModule && remedialModule.id !== module.id) {
              await db.insert(trainingAssignments).values({
                orgId,
                moduleId: remedialModule.id,
                employeeEmail: assignment.employeeEmail,
                employeeName: assignment.employeeName,
                assignedReason: "phishing_failure_remedial",
                dueAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
              });
              log.info("Auto-assigned remedial training", {
                employee: assignment.employeeEmail,
                moduleId: remedialModule.id,
              });
            }
          }
        }

        // Recalculate risk score
        await recalculateRiskScore(orgId, assignment.employeeEmail);

        res.json(updated);
      } catch (err) {
        log.error("Failed to complete assignment", { error: String(err) });
        res.status(500).json({ error: "Failed to complete assignment" });
      }
    },
  );

  // ==========================================================================
  // Configuration
  // ==========================================================================

  // GET /api/security-awareness/config
  app.get(
    "/api/security-awareness/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(securityAwarenessConfig)
          .where(eq(securityAwarenessConfig.orgId, orgId));
        res.json(
          existing || {
            isEnabled: false,
            autoEnrollOnClick: true,
            phishingFrequencyDays: 30,
            vishingEnabled: false,
            smishingEnabled: false,
            riskScoreThreshold: 75,
          },
        );
      } catch (err) {
        log.error("Failed to get config", { error: String(err) });
        res.status(500).json({ error: "Failed to get configuration" });
      }
    },
  );

  // PUT /api/security-awareness/config
  app.put(
    "/api/security-awareness/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("security_awareness", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_CONFIG_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [existing] = await db
          .select()
          .from(securityAwarenessConfig)
          .where(eq(securityAwarenessConfig.orgId, orgId));
        if (existing) {
          const [updated] = await db
            .update(securityAwarenessConfig)
            .set(updates)
            .where(eq(securityAwarenessConfig.id, existing.id))
            .returning();
          res.json(updated);
        } else {
          const [created] = await db
            .insert(securityAwarenessConfig)
            .values({ ...updates, orgId } as typeof securityAwarenessConfig.$inferInsert)
            .returning();
          res.status(201).json(created);
        }
      } catch (err) {
        log.error("Failed to update config", { error: String(err) });
        res.status(500).json({ error: "Failed to update configuration" });
      }
    },
  );

  // ==========================================================================
  // Dashboard / Stats
  // ==========================================================================

  // GET /api/security-awareness/dashboard
  app.get(
    "/api/security-awareness/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const [
          [{ value: totalCampaigns }],
          [{ value: activeCampaigns }],
          [{ value: totalTemplates }],
          [{ value: totalEmployees }],
          [{ value: highRiskCount }],
          [{ value: totalModules }],
          [{ value: pendingAssignments }],
          topRiskyEmployees,
          recentCampaigns,
          [{ value: avgClickRateRaw }],
        ] = await Promise.all([
          db.select({ value: count() }).from(phishingCampaigns).where(eq(phishingCampaigns.orgId, orgId)),
          db
            .select({ value: count() })
            .from(phishingCampaigns)
            .where(and(eq(phishingCampaigns.orgId, orgId), eq(phishingCampaigns.status, "running"))),
          db.select({ value: count() }).from(phishingTemplates).where(eq(phishingTemplates.orgId, orgId)),
          db.select({ value: count() }).from(employeeRiskScores).where(eq(employeeRiskScores.orgId, orgId)),
          db
            .select({ value: count() })
            .from(employeeRiskScores)
            .where(and(eq(employeeRiskScores.orgId, orgId), gte(employeeRiskScores.riskScore, 75))),
          db.select({ value: count() }).from(trainingModules).where(eq(trainingModules.orgId, orgId)),
          db
            .select({ value: count() })
            .from(trainingAssignments)
            .where(and(eq(trainingAssignments.orgId, orgId), sql`${trainingAssignments.completedAt} IS NULL`)),
          db
            .select()
            .from(employeeRiskScores)
            .where(eq(employeeRiskScores.orgId, orgId))
            .orderBy(desc(employeeRiskScores.riskScore))
            .limit(10),
          db
            .select()
            .from(phishingCampaigns)
            .where(eq(phishingCampaigns.orgId, orgId))
            .orderBy(desc(phishingCampaigns.createdAt))
            .limit(5),
          db
            .select({ value: sql<number>`COALESCE(AVG(${employeeRiskScores.phishingClickRate}), 0)` })
            .from(employeeRiskScores)
            .where(eq(employeeRiskScores.orgId, orgId)),
        ]);

        // Org-wide average click rate from all employees (not just top 10)
        const avgClickRate = Number(avgClickRateRaw) || 0;

        // 68.2 — Campaign results summary stats
        const campaignResults = recentCampaigns.map((c) => ({
          id: c.id,
          name: c.name,
          clickRate: c.emailsSent > 0 ? Math.round((c.linksClicked / c.emailsSent) * 100) : 0,
          reportRate: c.emailsSent > 0 ? Math.round((c.reported / c.emailsSent) * 100) : 0,
          submissionRate: c.emailsSent > 0 ? Math.round((c.credentialsSubmitted / c.emailsSent) * 100) : 0,
        }));

        // 68.5 — Email delivery stats
        const deliveryStats = {
          totalSent: recentCampaigns.reduce((sum, c) => sum + c.emailsSent, 0),
          totalOpened: recentCampaigns.reduce((sum, c) => sum + c.emailsOpened, 0),
          totalClicked: recentCampaigns.reduce((sum, c) => sum + c.linksClicked, 0),
          totalReported: recentCampaigns.reduce((sum, c) => sum + c.reported, 0),
        };

        // 68.6 — Click/submission tracking accuracy
        const trackingAccuracy =
          deliveryStats.totalSent > 0
            ? Math.round(((deliveryStats.totalOpened + deliveryStats.totalClicked) / deliveryStats.totalSent) * 100)
            : 0;

        res.json({
          totalCampaigns,
          activeCampaigns,
          totalTemplates,
          totalEmployees,
          highRiskCount,
          totalModules,
          pendingAssignments,
          avgClickRate: Math.round(avgClickRate * 10) / 10,
          topRiskyEmployees,
          recentCampaigns,
          campaignResults,
          deliveryStats,
          trackingAccuracy,
          campaignStatuses: PHISHING_CAMPAIGN_STATUSES,
          templateCategories: PHISHING_TEMPLATE_CATEGORIES,
          moduleTypes: TRAINING_MODULE_TYPES,
        });
      } catch (err) {
        log.error("Failed to get dashboard", { error: String(err) });
        res.status(500).json({ error: "Failed to get dashboard stats" });
      }
    },
  );
}
