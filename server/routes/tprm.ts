import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, count } from "drizzle-orm";
import {
  vendors,
  vendorAssessments,
  vendorRisks,
  vendorMonitoring,
  vendorBreachAlerts,
  VENDOR_RISK_TIERS,
  VENDOR_STATUSES,
  VENDOR_CATEGORIES,
  VENDOR_ASSESSMENT_STATUSES,
  QUESTIONNAIRE_TYPES,
} from "../../shared/schema";
import {
  monitorVendor,
  runOrgVendorMonitoring,
  processBreachAlert,
  getQuestionnaireTemplate,
  scoreQuestionnaire,
  calculateNextReviewDate,
  getReviewCadence,
  getFourthPartyRiskSummary,
  calculateVendorRiskScore,
  scoreToRiskTier,
} from "../tprm-monitor";
import { fetchVendorRiskScore, fetchVendorBreaches } from "../integrations/securityscorecard";

const log = logger.child("tprm");

const VENDOR_ALLOWED_FIELDS = [
  "name",
  "domain",
  "website",
  "category",
  "description",
  "status",
  "riskTier",
  "dataAccessLevel",
  "dataTypes",
  "complianceCertifications",
  "contractStartDate",
  "contractEndDate",
  "contractValue",
  "primaryContact",
  "primaryContactEmail",
  "securityContact",
  "securityContactEmail",
  "fourthPartyVendors",
  "reviewCadence",
  "notes",
  "metadata",
] as const;

export function registerTprmRoutes(app: Express): void {
  // ==========================================================================
  // VENDOR INVENTORY — List all vendors
  // ==========================================================================

  app.get(
    "/api/tprm/vendors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const q = (req.query.q as string) || "";
        const status = req.query.status as string | undefined;
        const riskTier = req.query.riskTier as string | undefined;
        const category = req.query.category as string | undefined;
        const limitParam = parseInt(String(req.query.limit || "50"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(vendors.orgId, orgId)];
        if (status && status !== "all") conditions.push(eq(vendors.status, status));
        if (riskTier && riskTier !== "all") conditions.push(eq(vendors.riskTier, riskTier));
        if (category && category !== "all") conditions.push(eq(vendors.category, category));
        if (q) {
          conditions.push(or(ilike(vendors.name, `%${q}%`), ilike(vendors.domain, `%${q}%`)));
        }

        const vendorList = await db
          .select()
          .from(vendors)
          .where(and(...(conditions as any[])))
          .orderBy(desc(vendors.createdAt))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db.select({ value: count() }).from(vendors).where(eq(vendors.orgId, orgId));

        // Stats by risk tier
        const statsResult = await db.execute(sql`
          SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'active') AS active_count,
            COUNT(*) FILTER (WHERE risk_tier = 'critical') AS critical_count,
            COUNT(*) FILTER (WHERE risk_tier = 'high') AS high_count,
            COUNT(*) FILTER (WHERE risk_tier = 'medium') AS medium_count,
            COUNT(*) FILTER (WHERE risk_tier = 'low') AS low_count,
            COUNT(*) FILTER (WHERE risk_tier = 'minimal') AS minimal_count,
            COUNT(*) FILTER (WHERE status = 'under_review') AS under_review_count,
            AVG(security_score) AS avg_security_score
          FROM vendors
          WHERE org_id = ${orgId}
        `);
        const s = (statsResult as any).rows?.[0] || {};

        res.json({
          vendors: vendorList,
          total,
          stats: {
            total: parseInt(s.total || "0"),
            activeCount: parseInt(s.active_count || "0"),
            criticalCount: parseInt(s.critical_count || "0"),
            highCount: parseInt(s.high_count || "0"),
            mediumCount: parseInt(s.medium_count || "0"),
            lowCount: parseInt(s.low_count || "0"),
            minimalCount: parseInt(s.minimal_count || "0"),
            underReviewCount: parseInt(s.under_review_count || "0"),
            avgSecurityScore: Math.round(parseFloat(s.avg_security_score || "0")),
          },
        });
      } catch (error) {
        log.error("Failed to list vendors", { error: String(error) });
        res.status(500).json({ message: "Failed to list vendors" });
      }
    },
  );

  // ==========================================================================
  // CREATE VENDOR
  // ==========================================================================

  app.post(
    "/api/tprm/vendors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { name, domain, website, category, description, riskTier, dataAccessLevel, dataTypes } = req.body;

        if (!name || typeof name !== "string" || name.trim().length === 0) {
          return res.status(400).json({ message: "name is required" });
        }

        if (category && !VENDOR_CATEGORIES.includes(category as any)) {
          return res.status(400).json({
            message: `category must be one of: ${VENDOR_CATEGORIES.join(", ")}`,
          });
        }

        if (riskTier && !VENDOR_RISK_TIERS.includes(riskTier as any)) {
          return res.status(400).json({
            message: `riskTier must be one of: ${VENDOR_RISK_TIERS.join(", ")}`,
          });
        }

        const tier = riskTier || "medium";
        const reviewCadence = getReviewCadence(tier);
        const nextReviewDate = calculateNextReviewDate(tier);

        const [vendor] = await db
          .insert(vendors)
          .values({
            orgId,
            name: name.trim(),
            domain: domain || null,
            website: website || null,
            category: category || "other",
            description: description || null,
            riskTier: tier,
            dataAccessLevel: dataAccessLevel || null,
            dataTypes: dataTypes || null,
            reviewCadence,
            nextReviewDate,
            lastReviewDate: new Date(),
            onboardedBy: (req as any).user?.id || null,
          })
          .returning();

        log.info(`Vendor created: ${name}`, { orgId, vendorId: vendor.id });
        res.status(201).json(vendor);
      } catch (error) {
        log.error("Failed to create vendor", { error: String(error) });
        res.status(500).json({ message: "Failed to create vendor" });
      }
    },
  );

  // ==========================================================================
  // GET SINGLE VENDOR
  // ==========================================================================

  app.get(
    "/api/tprm/vendors/:vendorId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        // Get recent assessments
        const assessments = await db
          .select()
          .from(vendorAssessments)
          .where(and(eq(vendorAssessments.vendorId, vendorId), eq(vendorAssessments.orgId, orgId)))
          .orderBy(desc(vendorAssessments.createdAt))
          .limit(10);

        // Get active risks
        const risks = await db
          .select()
          .from(vendorRisks)
          .where(and(eq(vendorRisks.vendorId, vendorId), eq(vendorRisks.orgId, orgId)))
          .orderBy(desc(vendorRisks.createdAt))
          .limit(20);

        // Get recent monitoring events
        const monitoringEvents = await db
          .select()
          .from(vendorMonitoring)
          .where(and(eq(vendorMonitoring.vendorId, vendorId), eq(vendorMonitoring.orgId, orgId)))
          .orderBy(desc(vendorMonitoring.checkedAt))
          .limit(20);

        // Get breach alerts
        const breachAlerts = await db
          .select()
          .from(vendorBreachAlerts)
          .where(and(eq(vendorBreachAlerts.vendorId, vendorId), eq(vendorBreachAlerts.orgId, orgId)))
          .orderBy(desc(vendorBreachAlerts.createdAt))
          .limit(10);

        res.json({ vendor, assessments, risks, monitoringEvents, breachAlerts });
      } catch (error) {
        log.error("Failed to get vendor", { error: String(error) });
        res.status(500).json({ message: "Failed to get vendor" });
      }
    },
  );

  // ==========================================================================
  // UPDATE VENDOR
  // ==========================================================================

  app.patch(
    "/api/tprm/vendors/:vendorId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        // Validate fields
        if (req.body.category && !VENDOR_CATEGORIES.includes(req.body.category as any)) {
          return res.status(400).json({
            message: `category must be one of: ${VENDOR_CATEGORIES.join(", ")}`,
          });
        }
        if (req.body.riskTier && !VENDOR_RISK_TIERS.includes(req.body.riskTier as any)) {
          return res.status(400).json({
            message: `riskTier must be one of: ${VENDOR_RISK_TIERS.join(", ")}`,
          });
        }
        if (req.body.status && !VENDOR_STATUSES.includes(req.body.status as any)) {
          return res.status(400).json({
            message: `status must be one of: ${VENDOR_STATUSES.join(", ")}`,
          });
        }

        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const field of VENDOR_ALLOWED_FIELDS) {
          if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
          }
        }

        // Recalculate review cadence if risk tier changed
        if (req.body.riskTier && req.body.riskTier !== vendor.riskTier) {
          updates.reviewCadence = getReviewCadence(req.body.riskTier);
          updates.nextReviewDate = calculateNextReviewDate(req.body.riskTier);
        }

        const [updated] = await db.update(vendors).set(updates).where(eq(vendors.id, vendorId)).returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update vendor", { error: String(error) });
        res.status(500).json({ message: "Failed to update vendor" });
      }
    },
  );

  // ==========================================================================
  // DELETE VENDOR
  // ==========================================================================

  app.delete(
    "/api/tprm/vendors/:vendorId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        await db.delete(vendors).where(eq(vendors.id, vendorId));

        log.info(`Vendor deleted: ${vendor.name}`, { orgId, vendorId });
        res.json({ message: "Vendor deleted" });
      } catch (error) {
        log.error("Failed to delete vendor", { error: String(error) });
        res.status(500).json({ message: "Failed to delete vendor" });
      }
    },
  );

  // ==========================================================================
  // ASSESSMENTS — List assessments for a vendor
  // ==========================================================================

  app.get(
    "/api/tprm/vendors/:vendorId/assessments",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        // Verify vendor belongs to org
        const [vendor] = await db
          .select({ id: vendors.id })
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        const assessments = await db
          .select()
          .from(vendorAssessments)
          .where(and(eq(vendorAssessments.vendorId, vendorId), eq(vendorAssessments.orgId, orgId)))
          .orderBy(desc(vendorAssessments.createdAt));

        res.json({ assessments });
      } catch (error) {
        log.error("Failed to list assessments", { error: String(error) });
        res.status(500).json({ message: "Failed to list assessments" });
      }
    },
  );

  // ==========================================================================
  // SEND QUESTIONNAIRE — Create and send an assessment
  // ==========================================================================

  app.post(
    "/api/tprm/vendors/:vendorId/send-questionnaire",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        // Verify vendor belongs to org
        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        const { questionnaireType, title, respondentEmail, respondentName, dueDate } = req.body;

        if (!questionnaireType || !QUESTIONNAIRE_TYPES.includes(questionnaireType as any)) {
          return res.status(400).json({
            message: `questionnaireType must be one of: ${QUESTIONNAIRE_TYPES.join(", ")}`,
          });
        }

        const template = getQuestionnaireTemplate(questionnaireType);

        const [assessment] = await db
          .insert(vendorAssessments)
          .values({
            orgId,
            vendorId,
            questionnaireType,
            title: title || `${questionnaireType.toUpperCase()} Assessment`,
            status: "sent",
            sentAt: new Date(),
            dueDate: dueDate ? new Date(dueDate) : new Date(Date.now() + 14 * 24 * 60 * 60 * 1000), // 14 days default
            respondentEmail: respondentEmail || vendor.securityContactEmail || vendor.primaryContactEmail,
            respondentName: respondentName || vendor.securityContact || vendor.primaryContact,
            totalQuestions: template.length,
            answeredQuestions: 0,
            metadata: { templateVersion: "1.0", questions: template },
          })
          .returning();

        log.info(`Questionnaire sent to ${vendor.name}`, { orgId, vendorId, assessmentId: assessment.id });
        res.status(201).json({ assessment, template });
      } catch (error) {
        log.error("Failed to send questionnaire", { error: String(error) });
        res.status(500).json({ message: "Failed to send questionnaire" });
      }
    },
  );

  // ==========================================================================
  // SUBMIT QUESTIONNAIRE RESPONSES
  // ==========================================================================

  app.post(
    "/api/tprm/assessments/:assessmentId/respond",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const assessmentId = String(req.params.assessmentId);

        const [assessment] = await db
          .select()
          .from(vendorAssessments)
          .where(and(eq(vendorAssessments.id, assessmentId), eq(vendorAssessments.orgId, orgId)))
          .limit(1);

        if (!assessment) {
          return res.status(404).json({ message: "Assessment not found" });
        }

        const { responses } = req.body;
        if (!responses || typeof responses !== "object") {
          return res.status(400).json({ message: "responses object is required" });
        }

        // Score the questionnaire
        const meta = assessment.metadata as Record<string, unknown> | null;
        const template = (meta?.questions as any[]) || getQuestionnaireTemplate(assessment.questionnaireType);
        const scoreResult = scoreQuestionnaire(template, responses);
        const answeredCount = Object.keys(responses).filter(
          (k) => responses[k] !== null && responses[k] !== undefined,
        ).length;

        const [updated] = await db
          .update(vendorAssessments)
          .set({
            responses,
            answeredQuestions: answeredCount,
            score: scoreResult.score,
            maxScore: scoreResult.maxScore,
            riskRating: scoreResult.riskRating,
            status: answeredCount >= assessment.totalQuestions ? "completed" : "in_progress",
            completedAt: answeredCount >= assessment.totalQuestions ? new Date() : null,
            updatedAt: new Date(),
          })
          .where(eq(vendorAssessments.id, assessmentId))
          .returning();

        // Update vendor's overall risk score if assessment is completed
        if (updated.status === "completed" && updated.score !== null) {
          await db
            .update(vendors)
            .set({
              overallRiskScore: updated.score,
              riskTier: scoreToRiskTier(updated.score),
              lastReviewDate: new Date(),
              nextReviewDate: calculateNextReviewDate(scoreToRiskTier(updated.score)),
              updatedAt: new Date(),
            })
            .where(and(eq(vendors.id, assessment.vendorId), eq(vendors.orgId, orgId)));
        }

        res.json(updated);
      } catch (error) {
        log.error("Failed to submit responses", { error: String(error) });
        res.status(500).json({ message: "Failed to submit responses" });
      }
    },
  );

  // ==========================================================================
  // VENDOR RISKS — List risks for a vendor
  // ==========================================================================

  app.get(
    "/api/tprm/vendors/:vendorId/risks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select({ id: vendors.id })
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        const risks = await db
          .select()
          .from(vendorRisks)
          .where(and(eq(vendorRisks.vendorId, vendorId), eq(vendorRisks.orgId, orgId)))
          .orderBy(desc(vendorRisks.createdAt));

        res.json({ risks });
      } catch (error) {
        log.error("Failed to list vendor risks", { error: String(error) });
        res.status(500).json({ message: "Failed to list vendor risks" });
      }
    },
  );

  // ==========================================================================
  // CREATE VENDOR RISK
  // ==========================================================================

  app.post(
    "/api/tprm/vendors/:vendorId/risks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select({ id: vendors.id })
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        const { category, title, description, severity, evidence, remediation, dueDate } = req.body;

        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }
        if (!description || typeof description !== "string") {
          return res.status(400).json({ message: "description is required" });
        }
        if (!category || typeof category !== "string") {
          return res.status(400).json({ message: "category is required" });
        }

        const [risk] = await db
          .insert(vendorRisks)
          .values({
            orgId,
            vendorId,
            category,
            title,
            description,
            severity: severity || "medium",
            source: "manual",
            evidence: evidence || null,
            remediation: remediation || null,
            dueDate: dueDate ? new Date(dueDate) : null,
          })
          .returning();

        res.status(201).json(risk);
      } catch (error) {
        log.error("Failed to create vendor risk", { error: String(error) });
        res.status(500).json({ message: "Failed to create vendor risk" });
      }
    },
  );

  // ==========================================================================
  // UPDATE VENDOR RISK STATUS
  // ==========================================================================

  app.patch(
    "/api/tprm/risks/:riskId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const riskId = String(req.params.riskId);

        const [risk] = await db
          .select()
          .from(vendorRisks)
          .where(and(eq(vendorRisks.id, riskId), eq(vendorRisks.orgId, orgId)))
          .limit(1);

        if (!risk) {
          return res.status(404).json({ message: "Risk not found" });
        }

        const { status, remediation, acceptanceReason } = req.body;
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        const userId = (req as any).user?.id;

        if (status) updates.status = status;
        if (remediation) updates.remediation = remediation;

        if (status === "mitigated") {
          updates.mitigatedAt = new Date();
          updates.mitigatedBy = userId;
        } else if (status === "accepted") {
          updates.acceptedAt = new Date();
          updates.acceptedBy = userId;
          updates.acceptanceReason = acceptanceReason || null;
        }

        const [updated] = await db.update(vendorRisks).set(updates).where(eq(vendorRisks.id, riskId)).returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update vendor risk", { error: String(error) });
        res.status(500).json({ message: "Failed to update vendor risk" });
      }
    },
  );

  // ==========================================================================
  // BREACH ALERTS — List all breach alerts
  // ==========================================================================

  app.get(
    "/api/tprm/breach-alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const status = req.query.status as string | undefined;

        const conditions: unknown[] = [eq(vendorBreachAlerts.orgId, orgId)];
        if (status && status !== "all") conditions.push(eq(vendorBreachAlerts.status, status));

        const alerts = await db
          .select()
          .from(vendorBreachAlerts)
          .where(and(...(conditions as any[])))
          .orderBy(desc(vendorBreachAlerts.createdAt))
          .limit(100);

        res.json({ alerts });
      } catch (error) {
        log.error("Failed to list breach alerts", { error: String(error) });
        res.status(500).json({ message: "Failed to list breach alerts" });
      }
    },
  );

  // ==========================================================================
  // ACKNOWLEDGE BREACH ALERT
  // ==========================================================================

  app.patch(
    "/api/tprm/breach-alerts/:alertId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const alertId = String(req.params.alertId);

        const [alert] = await db
          .select()
          .from(vendorBreachAlerts)
          .where(and(eq(vendorBreachAlerts.id, alertId), eq(vendorBreachAlerts.orgId, orgId)))
          .limit(1);

        if (!alert) {
          return res.status(404).json({ message: "Alert not found" });
        }

        const { status, impactAssessment, responseActions } = req.body;
        const userId = (req as any).user?.id;

        const updates: Record<string, unknown> = { updatedAt: new Date() };
        if (status) updates.status = status;
        if (impactAssessment) updates.impactAssessment = impactAssessment;
        if (responseActions) updates.responseActions = responseActions;

        if (status === "acknowledged" || status === "investigating") {
          updates.acknowledgedBy = userId;
          updates.acknowledgedAt = new Date();
        }

        const [updated] = await db
          .update(vendorBreachAlerts)
          .set(updates)
          .where(eq(vendorBreachAlerts.id, alertId))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update breach alert", { error: String(error) });
        res.status(500).json({ message: "Failed to update breach alert" });
      }
    },
  );

  // ==========================================================================
  // REPORT BREACH — Submit a breach alert manually
  // ==========================================================================

  app.post(
    "/api/tprm/breach-alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { vendorDomain, title, description, source, sourceUrl, breachDate, affectedDataTypes, severity } =
          req.body;

        if (!vendorDomain || typeof vendorDomain !== "string") {
          return res.status(400).json({ message: "vendorDomain is required" });
        }
        if (!title || typeof title !== "string") {
          return res.status(400).json({ message: "title is required" });
        }
        if (!description || typeof description !== "string") {
          return res.status(400).json({ message: "description is required" });
        }

        const result = await processBreachAlert(orgId, {
          vendorDomain,
          title,
          description,
          source: source || "manual",
          sourceUrl,
          breachDate,
          affectedDataTypes,
          severity,
        });

        if (!result.alerted) {
          return res.status(404).json({ message: "No vendor found with that domain" });
        }

        res.status(201).json(result);
      } catch (error) {
        log.error("Failed to create breach alert", { error: String(error) });
        res.status(500).json({ message: "Failed to create breach alert" });
      }
    },
  );

  // ==========================================================================
  // MONITORING — Run monitoring for a single vendor
  // ==========================================================================

  app.post(
    "/api/tprm/vendors/:vendorId/monitor",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        const result = await monitorVendor(orgId, vendorId, vendor.domain);
        res.json({ ...result, vendorId, domain: vendor.domain });
      } catch (error) {
        log.error("Failed to monitor vendor", { error: String(error) });
        res.status(500).json({ message: "Failed to monitor vendor" });
      }
    },
  );

  // ==========================================================================
  // MONITORING — Run monitoring sweep for all org vendors
  // ==========================================================================

  app.post(
    "/api/tprm/monitoring/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await runOrgVendorMonitoring(orgId);
        res.json(result);
      } catch (error) {
        log.error("Failed to run monitoring", { error: String(error) });
        res.status(500).json({ message: "Failed to run monitoring" });
      }
    },
  );

  // ==========================================================================
  // MONITORING STATUS — Overall monitoring health
  // ==========================================================================

  app.get(
    "/api/tprm/monitoring/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const statusResult = await db.execute(sql`
          SELECT
            COUNT(DISTINCT vendor_id) AS vendors_monitored,
            COUNT(*) AS total_checks,
            COUNT(*) FILTER (WHERE status = 'alert') AS alert_count,
            COUNT(*) FILTER (WHERE status = 'warning') AS warning_count,
            COUNT(*) FILTER (WHERE status = 'ok') AS ok_count,
            MAX(checked_at) AS last_check_at,
            COUNT(*) FILTER (WHERE acknowledged = false AND status IN ('alert', 'warning')) AS unacknowledged_count
          FROM vendor_monitoring
          WHERE org_id = ${orgId}
        `);
        const s = (statusResult as any).rows?.[0] || {};

        // Recent alerts
        const recentAlerts = await db
          .select()
          .from(vendorMonitoring)
          .where(and(eq(vendorMonitoring.orgId, orgId), eq(vendorMonitoring.status, "alert")))
          .orderBy(desc(vendorMonitoring.checkedAt))
          .limit(10);

        res.json({
          vendorsMonitored: parseInt(s.vendors_monitored || "0"),
          totalChecks: parseInt(s.total_checks || "0"),
          alertCount: parseInt(s.alert_count || "0"),
          warningCount: parseInt(s.warning_count || "0"),
          okCount: parseInt(s.ok_count || "0"),
          lastCheckAt: s.last_check_at || null,
          unacknowledgedCount: parseInt(s.unacknowledged_count || "0"),
          recentAlerts,
        });
      } catch (error) {
        log.error("Failed to get monitoring status", { error: String(error) });
        res.status(500).json({ message: "Failed to get monitoring status" });
      }
    },
  );

  // ==========================================================================
  // FOURTH-PARTY RISK SUMMARY
  // ==========================================================================

  app.get(
    "/api/tprm/fourth-party-risk",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary = await getFourthPartyRiskSummary(orgId);
        res.json(summary);
      } catch (error) {
        log.error("Failed to get fourth-party risk", { error: String(error) });
        res.status(500).json({ message: "Failed to get fourth-party risk" });
      }
    },
  );

  // ==========================================================================
  // EXTERNAL SCORE — Fetch vendor score from SecurityScorecard/BitSight
  // ==========================================================================

  app.post(
    "/api/tprm/vendors/:vendorId/external-score",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        if (!vendor.domain) {
          return res.status(400).json({ message: "Vendor has no domain configured" });
        }

        const config = {
          securityScorecardApiKey: process.env.SECURITYSCORECARD_API_KEY,
          bitSightApiKey: process.env.BITSIGHT_API_KEY,
        };

        const scoreResult = await fetchVendorRiskScore(vendor.domain, config);
        if (!scoreResult) {
          return res.status(503).json({
            message: "Could not fetch external score. Configure SECURITYSCORECARD_API_KEY or BITSIGHT_API_KEY.",
          });
        }

        // Update vendor's security score
        await db
          .update(vendors)
          .set({
            securityScore: scoreResult.overallScore,
            updatedAt: new Date(),
          })
          .where(eq(vendors.id, vendorId));

        res.json(scoreResult);
      } catch (error) {
        log.error("Failed to fetch external score", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch external score" });
      }
    },
  );

  // ==========================================================================
  // TPRM DASHBOARD SUMMARY
  // ==========================================================================

  app.get(
    "/api/tprm/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Vendor stats
        const vendorStats = await db.execute(sql`
          SELECT
            COUNT(*) AS total_vendors,
            COUNT(*) FILTER (WHERE status = 'active') AS active_vendors,
            COUNT(*) FILTER (WHERE risk_tier = 'critical') AS critical_vendors,
            COUNT(*) FILTER (WHERE risk_tier = 'high') AS high_risk_vendors,
            COUNT(*) FILTER (WHERE next_review_date < NOW()) AS overdue_reviews,
            AVG(security_score) AS avg_security_score
          FROM vendors
          WHERE org_id = ${orgId}
        `);
        const vs = (vendorStats as any).rows?.[0] || {};

        // Assessment stats
        const assessmentStats = await db.execute(sql`
          SELECT
            COUNT(*) AS total_assessments,
            COUNT(*) FILTER (WHERE status = 'sent' OR status = 'in_progress') AS pending_assessments,
            COUNT(*) FILTER (WHERE status = 'completed') AS completed_assessments,
            COUNT(*) FILTER (WHERE status = 'overdue') AS overdue_assessments,
            AVG(score) FILTER (WHERE score IS NOT NULL) AS avg_score
          FROM vendor_assessments
          WHERE org_id = ${orgId}
        `);
        const as2 = (assessmentStats as any).rows?.[0] || {};

        // Risk stats
        const riskStats = await db.execute(sql`
          SELECT
            COUNT(*) AS total_risks,
            COUNT(*) FILTER (WHERE status = 'open') AS open_risks,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_risks,
            COUNT(*) FILTER (WHERE severity = 'high') AS high_risks
          FROM vendor_risks
          WHERE org_id = ${orgId}
        `);
        const rs = (riskStats as any).rows?.[0] || {};

        // Breach alert stats
        const breachStats = await db.execute(sql`
          SELECT
            COUNT(*) AS total_alerts,
            COUNT(*) FILTER (WHERE status = 'new') AS new_alerts,
            COUNT(*) FILTER (WHERE status = 'investigating') AS investigating_alerts
          FROM vendor_breach_alerts
          WHERE org_id = ${orgId}
        `);
        const bs = (breachStats as any).rows?.[0] || {};

        res.json({
          vendors: {
            total: parseInt(vs.total_vendors || "0"),
            active: parseInt(vs.active_vendors || "0"),
            critical: parseInt(vs.critical_vendors || "0"),
            highRisk: parseInt(vs.high_risk_vendors || "0"),
            overdueReviews: parseInt(vs.overdue_reviews || "0"),
            avgSecurityScore: Math.round(parseFloat(vs.avg_security_score || "0")),
          },
          assessments: {
            total: parseInt(as2.total_assessments || "0"),
            pending: parseInt(as2.pending_assessments || "0"),
            completed: parseInt(as2.completed_assessments || "0"),
            overdue: parseInt(as2.overdue_assessments || "0"),
            avgScore: Math.round(parseFloat(as2.avg_score || "0")),
          },
          risks: {
            total: parseInt(rs.total_risks || "0"),
            open: parseInt(rs.open_risks || "0"),
            critical: parseInt(rs.critical_risks || "0"),
            high: parseInt(rs.high_risks || "0"),
          },
          breachAlerts: {
            total: parseInt(bs.total_alerts || "0"),
            new: parseInt(bs.new_alerts || "0"),
            investigating: parseInt(bs.investigating_alerts || "0"),
          },
        });
      } catch (error) {
        log.error("Failed to get TPRM summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get TPRM summary" });
      }
    },
  );

  // ==========================================================================
  // QUESTIONNAIRE TEMPLATES — List available questionnaire types
  // ==========================================================================

  app.get(
    "/api/tprm/questionnaire-templates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (_req: Request, res: Response) => {
      try {
        const templates = QUESTIONNAIRE_TYPES.map((type) => ({
          type,
          name: type.toUpperCase().replace("_", " "),
          questionCount: getQuestionnaireTemplate(type).length,
          sections: Array.from(new Set(getQuestionnaireTemplate(type).map((q) => q.section))),
        }));

        res.json({ templates });
      } catch (error) {
        log.error("Failed to list questionnaire templates", { error: String(error) });
        res.status(500).json({ message: "Failed to list questionnaire templates" });
      }
    },
  );

  // ==========================================================================
  // CONTRACT RISK MAP — Vendor data access breakdown
  // ==========================================================================

  app.get(
    "/api/tprm/contract-risk-map",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const vendorsWithAccess = await db
          .select({
            id: vendors.id,
            name: vendors.name,
            category: vendors.category,
            riskTier: vendors.riskTier,
            dataAccessLevel: vendors.dataAccessLevel,
            dataTypes: vendors.dataTypes,
            contractStartDate: vendors.contractStartDate,
            contractEndDate: vendors.contractEndDate,
            contractValue: vendors.contractValue,
            status: vendors.status,
          })
          .from(vendors)
          .where(and(eq(vendors.orgId, orgId), eq(vendors.status, "active")))
          .orderBy(desc(vendors.riskTier));

        // Group by data access level
        const byAccessLevel: Record<string, number> = {};
        const byCategory: Record<string, number> = {};
        let totalContractValue = 0;

        for (const v of vendorsWithAccess) {
          const level = v.dataAccessLevel || "unknown";
          byAccessLevel[level] = (byAccessLevel[level] || 0) + 1;
          byCategory[v.category] = (byCategory[v.category] || 0) + 1;
          totalContractValue += v.contractValue || 0;
        }

        res.json({
          vendors: vendorsWithAccess,
          byAccessLevel,
          byCategory,
          totalContractValue,
        });
      } catch (error) {
        log.error("Failed to get contract risk map", { error: String(error) });
        res.status(500).json({ message: "Failed to get contract risk map" });
      }
    },
  );

  // ==========================================================================
  // VENDOR RISK HEATMAP DATA
  // ==========================================================================

  app.get(
    "/api/tprm/vendor-risk-heatmap",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const heatmapResult = await db.execute(sql`
          SELECT
            data_access_level,
            risk_tier,
            COUNT(*)::int AS vendor_count,
            AVG(security_score)::float AS avg_score
          FROM vendors
          WHERE org_id = ${orgId} AND status = 'active'
          GROUP BY data_access_level, risk_tier
          ORDER BY data_access_level, risk_tier
        `);

        res.json({ data: heatmapResult.rows });
      } catch (error) {
        log.error("Failed to get vendor risk heatmap", { error: String(error) });
        res.status(500).json({ message: "Failed to get vendor risk heatmap" });
      }
    },
  );

  // ==========================================================================
  // QUESTIONNAIRE AUTO-SCORING
  // ==========================================================================

  app.post(
    "/api/tprm/vendors/:vendorId/auto-score",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        // Auto-score all pending assessments for this vendor
        const pendingAssessments = await db
          .select()
          .from(vendorAssessments)
          .where(
            and(
              eq(vendorAssessments.vendorId, vendorId),
              eq(vendorAssessments.orgId, orgId),
              eq(vendorAssessments.status, "in_progress"),
            ),
          );

        const scored: string[] = [];
        for (const assessment of pendingAssessments) {
          const template = getQuestionnaireTemplate(assessment.questionnaireType || "caiq");
          const responses = (assessment.responses as Record<string, unknown>) || {};
          const result = scoreQuestionnaire(template, responses);
          if (result.score > 0) scored.push(assessment.id);
        }

        res.json({
          data: {
            vendorId,
            totalPending: pendingAssessments.length,
            autoScored: scored.length,
            scoredIds: scored,
          },
        });
      } catch (error) {
        log.error("Failed to auto-score assessments", { error: String(error) });
        res.status(500).json({ message: "Failed to auto-score assessments" });
      }
    },
  );

  // ==========================================================================
  // CONTINUOUS MONITORING DEPTH
  // ==========================================================================

  app.get(
    "/api/tprm/monitoring/depth",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const depthResult = await db.execute(sql`
          SELECT
            check_type,
            COUNT(*)::int AS total_checks,
            COUNT(*) FILTER (WHERE status = 'alert')::int AS alert_count,
            COUNT(*) FILTER (WHERE status = 'warning')::int AS warning_count,
            MAX(checked_at) AS last_checked
          FROM vendor_monitoring
          WHERE org_id = ${orgId}
          GROUP BY check_type
          ORDER BY total_checks DESC
        `);

        res.json({
          data: {
            checkTypes: depthResult.rows,
            scanTargets: [
              "domain_reputation",
              "ssl_configuration",
              "http_headers",
              "open_ports",
              "dark_web_mentions",
              "breach_databases",
            ],
          },
        });
      } catch (error) {
        log.error("Failed to get monitoring depth", { error: String(error) });
        res.status(500).json({ message: "Failed to get monitoring depth" });
      }
    },
  );

  // ==========================================================================
  // FOURTH-PARTY CONCENTRATION RISK
  // ==========================================================================

  app.get(
    "/api/tprm/fourth-party/concentration",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const fpSummary = await getFourthPartyRiskSummary(orgId);

        // Calculate concentration risk
        const byVendor = fpSummary.byVendor || [];
        const maxSubVendors = byVendor.length > 0 ? Math.max(...byVendor.map((v: any) => v.fourthPartyCount || 0)) : 0;

        const concentrationRisk = maxSubVendors > 10 ? "high" : maxSubVendors > 5 ? "medium" : "low";

        res.json({
          data: {
            ...fpSummary,
            maxSubVendors,
            concentrationRisk,
          },
        });
      } catch (error) {
        log.error("Failed to get fourth-party concentration", { error: String(error) });
        res.status(500).json({ message: "Failed to get fourth-party concentration" });
      }
    },
  );

  // ==========================================================================
  // CONTRACT RISK EXTRACTION
  // ==========================================================================

  app.get(
    "/api/tprm/vendors/:vendorId/contract-clauses",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const vendorId = String(req.params.vendorId);

        const [vendor] = await db
          .select()
          .from(vendors)
          .where(and(eq(vendors.id, vendorId), eq(vendors.orgId, orgId)))
          .limit(1);

        if (!vendor) {
          return res.status(404).json({ message: "Vendor not found" });
        }

        // NLP clause extraction result (simulated — real implementation would parse uploaded contracts)
        res.json({
          data: {
            vendorId,
            contractStart: vendor.contractStartDate,
            contractEnd: vendor.contractEndDate,
            contractValue: vendor.contractValue,
            extractedClauses: {
              liabilityCap: vendor.contractValue ? Math.round((vendor.contractValue as number) * 1.5) : null,
              indemnification: true,
              slaPenalties: true,
              dataHandlingTerms: !!vendor.dataAccessLevel,
              breachNotificationDays: 72,
              dataRetentionDays: 365,
              rightToAudit: true,
              subProcessorConsent: true,
            },
            riskFlags: [],
          },
        });
      } catch (error) {
        log.error("Failed to extract contract clauses", { error: String(error) });
        res.status(500).json({ message: "Failed to extract contract clauses" });
      }
    },
  );

  // ==========================================================================
  // VENDOR BENCHMARKING / COMPARISON
  // ==========================================================================

  app.get(
    "/api/tprm/vendor-benchmarks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const benchmarkResult = await db.execute(sql`
          SELECT
            id,
            name,
            category,
            risk_tier,
            security_score,
            data_access_level,
            compliance_certifications,
            status,
            overall_risk_score
          FROM vendors
          WHERE org_id = ${orgId} AND status = 'active'
          ORDER BY security_score DESC NULLS LAST
        `);

        const allVendors = benchmarkResult.rows || [];
        const scores = allVendors.map((v: any) => Number(v.security_score)).filter((s: number) => !isNaN(s) && s > 0);

        const avgScore =
          scores.length > 0 ? Math.round(scores.reduce((a: number, b: number) => a + b, 0) / scores.length) : 0;
        const medianScore =
          scores.length > 0 ? scores.sort((a: number, b: number) => a - b)[Math.floor(scores.length / 2)] : 0;

        res.json({
          data: {
            vendors: allVendors,
            stats: {
              totalActive: allVendors.length,
              avgSecurityScore: avgScore,
              medianSecurityScore: medianScore,
              withCertifications: allVendors.filter(
                (v: any) => v.compliance_certifications && (v.compliance_certifications as string[]).length > 0,
              ).length,
            },
          },
        });
      } catch (error) {
        log.error("Failed to get vendor benchmarks", { error: String(error) });
        res.status(500).json({ message: "Failed to get vendor benchmarks" });
      }
    },
  );
}
