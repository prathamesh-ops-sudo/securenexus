import type { Express } from "express";
import { eq, and, desc, sql, count } from "drizzle-orm";
import { db } from "../db";
import {
  msspWhiteLabelConfigs,
  msspClientSlas,
  msspSlaBreaches,
  msspBillingRecords,
  msspClientOnboarding,
  organizations,
  alerts,
  incidents,
  connectors,
  SLA_PRIORITY_LEVELS,
  MSSP_BILLING_STATUSES,
} from "../../shared/schema";
import { logger, getOrgId, sendEnvelope, replyError, replyForbidden, ERROR_CODES } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { z } from "zod";
import { storage } from "../storage";

const log = logger.child("mssp-portal");

// ── Helpers ─────────────────────────────────────────────────────────

async function requireMsspParent(req: any, res: any): Promise<string | null> {
  const orgId = getOrgId(req);
  const org = await storage.getOrganization(orgId);
  if (!org || org.orgType !== "mssp_parent") {
    replyForbidden(res, "Organization is not an MSSP parent", ERROR_CODES.ORG_ACCESS_DENIED);
    return null;
  }
  return orgId;
}

async function verifyChildOwnership(parentOrgId: string, childOrgId: string): Promise<boolean> {
  const childOrg = await storage.getOrganization(childOrgId);
  return !!childOrg && childOrg.parentOrgId === parentOrgId;
}

// ── Validation Schemas ──────────────────────────────────────────────

const whiteLabelSchema = z.object({
  customLogoUrl: z.string().url().max(2000).optional().nullable(),
  customFaviconUrl: z.string().url().max(2000).optional().nullable(),
  primaryColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/)
    .optional(),
  secondaryColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/)
    .optional(),
  accentColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/)
    .optional(),
  customDomain: z.string().max(255).optional().nullable(),
  customAppName: z.string().max(100).optional().nullable(),
  customSupportEmail: z.string().email().max(255).optional().nullable(),
  customSupportUrl: z.string().url().max(2000).optional().nullable(),
  loginPageHtml: z.string().max(10000).optional().nullable(),
  emailHeaderHtml: z.string().max(5000).optional().nullable(),
  emailFooterHtml: z.string().max(5000).optional().nullable(),
  reportHeaderHtml: z.string().max(5000).optional().nullable(),
  reportFooterHtml: z.string().max(5000).optional().nullable(),
  hidePoweredBy: z.boolean().optional(),
  customCss: z.string().max(50000).optional().nullable(),
  isActive: z.boolean().optional(),
});

const slaSchema = z.object({
  childOrgId: z.string().min(1).max(255),
  name: z.string().min(2).max(200).trim(),
  priority: z.enum(SLA_PRIORITY_LEVELS),
  responseTimeMinutes: z.number().int().min(1).max(43200),
  resolutionTimeMinutes: z.number().int().min(1).max(43200),
  escalationContactEmail: z.string().email().max(255).optional().nullable(),
  escalationContactPhone: z.string().max(50).optional().nullable(),
  autoEscalateOnBreach: z.boolean().optional(),
  businessHoursOnly: z.boolean().optional(),
  businessHoursStart: z
    .string()
    .regex(/^\d{2}:\d{2}$/)
    .optional(),
  businessHoursEnd: z
    .string()
    .regex(/^\d{2}:\d{2}$/)
    .optional(),
  businessTimezone: z.string().max(100).optional(),
});

const billingSchema = z.object({
  childOrgId: z.string().min(1).max(255),
  periodStart: z.string().datetime(),
  periodEnd: z.string().datetime(),
  baseFee: z.number().int().min(0).optional(),
  markupPercent: z.number().min(0).max(100).optional(),
  notes: z.string().max(5000).optional().nullable(),
});

const onboardingStepSchema = z.object({
  key: z.string().min(1).max(100),
  done: z.boolean(),
});

export function registerMsspPortalRoutes(app: Express): void {
  // ==========================================================================
  // WHITE-LABEL BRANDING
  // ==========================================================================

  // GET white-label config for current org
  app.get(
    "/api/mssp-portal/white-label",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const [config] = await db
          .select()
          .from(msspWhiteLabelConfigs)
          .where(eq(msspWhiteLabelConfigs.orgId, orgId))
          .limit(1);

        return sendEnvelope(res, config || null);
      } catch (err) {
        log.error("Failed to get white-label config", { error: String(err) });
        return replyError(res, 500, [{ code: "WL_GET_FAILED", message: "Failed to get white-label config" }]);
      }
    },
  );

  // PUT (upsert) white-label config
  app.put(
    "/api/mssp-portal/white-label",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const parsed = whiteLabelSchema.safeParse(req.body);
        if (!parsed.success) {
          return replyError(
            res,
            400,
            parsed.error.errors.map((e) => ({ code: "VALIDATION_ERROR", message: e.message })),
          );
        }

        const [existing] = await db
          .select()
          .from(msspWhiteLabelConfigs)
          .where(eq(msspWhiteLabelConfigs.orgId, orgId))
          .limit(1);

        let result;
        if (existing) {
          [result] = await db
            .update(msspWhiteLabelConfigs)
            .set({ ...parsed.data, updatedAt: new Date() })
            .where(eq(msspWhiteLabelConfigs.id, existing.id))
            .returning();
        } else {
          [result] = await db
            .insert(msspWhiteLabelConfigs)
            .values({ orgId, ...parsed.data })
            .returning();
        }

        const userId = String((req as any).user?.id || "");
        const userName = String((req as any).user?.email || "unknown");
        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "mssp_white_label_updated",
          resourceType: "mssp_white_label_config",
          resourceId: result.id,
          details: { fields: Object.keys(parsed.data) },
        });

        return sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to update white-label config", { error: String(err) });
        return replyError(res, 500, [{ code: "WL_UPDATE_FAILED", message: "Failed to update white-label config" }]);
      }
    },
  );

  // GET white-label config for a specific child org (applies parent branding)
  app.get(
    "/api/mssp-portal/white-label/:childOrgId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const childOrgId = String(req.params.childOrgId);
        if (!(await verifyChildOwnership(orgId, childOrgId))) {
          return replyError(res, 404, [{ code: "CHILD_NOT_FOUND", message: "Child org not found" }]);
        }

        // Check child-specific override first, then fall back to parent config
        const [childConfig] = await db
          .select()
          .from(msspWhiteLabelConfigs)
          .where(eq(msspWhiteLabelConfigs.orgId, childOrgId))
          .limit(1);

        if (childConfig) return sendEnvelope(res, childConfig);

        const [parentConfig] = await db
          .select()
          .from(msspWhiteLabelConfigs)
          .where(eq(msspWhiteLabelConfigs.orgId, orgId))
          .limit(1);

        return sendEnvelope(res, parentConfig || null);
      } catch (err) {
        log.error("Failed to get child white-label config", { error: String(err) });
        return replyError(res, 500, [{ code: "WL_CHILD_FAILED", message: "Failed to get child white-label config" }]);
      }
    },
  );

  // ==========================================================================
  // SLA MANAGEMENT
  // ==========================================================================

  // List SLAs
  app.get(
    "/api/mssp-portal/slas",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const childOrgId = req.query.childOrgId as string | undefined;
        const conditions = [eq(msspClientSlas.parentOrgId, orgId)];
        if (childOrgId) conditions.push(eq(msspClientSlas.childOrgId, childOrgId));

        const slas = await db
          .select()
          .from(msspClientSlas)
          .where(and(...conditions))
          .orderBy(desc(msspClientSlas.createdAt));

        return sendEnvelope(res, slas);
      } catch (err) {
        log.error("Failed to list SLAs", { error: String(err) });
        return replyError(res, 500, [{ code: "SLA_LIST_FAILED", message: "Failed to list SLAs" }]);
      }
    },
  );

  // Create SLA
  app.post(
    "/api/mssp-portal/slas",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const parsed = slaSchema.safeParse(req.body);
        if (!parsed.success) {
          return replyError(
            res,
            400,
            parsed.error.errors.map((e) => ({ code: "VALIDATION_ERROR", message: e.message })),
          );
        }

        if (!(await verifyChildOwnership(orgId, parsed.data.childOrgId))) {
          return replyError(res, 404, [{ code: "CHILD_NOT_FOUND", message: "Child org not found or not owned" }]);
        }

        const [sla] = await db
          .insert(msspClientSlas)
          .values({
            parentOrgId: orgId,
            ...parsed.data,
          })
          .returning();

        const userId = String((req as any).user?.id || "");
        const userName = String((req as any).user?.email || "unknown");
        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "mssp_sla_created",
          resourceType: "mssp_client_sla",
          resourceId: sla.id,
          details: { childOrgId: parsed.data.childOrgId, priority: parsed.data.priority },
        });

        return sendEnvelope(res, sla, { status: 201 });
      } catch (err) {
        log.error("Failed to create SLA", { error: String(err) });
        return replyError(res, 500, [{ code: "SLA_CREATE_FAILED", message: "Failed to create SLA" }]);
      }
    },
  );

  // Update SLA
  app.patch(
    "/api/mssp-portal/slas/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const slaId = String(req.params.id);
        const [existing] = await db
          .select()
          .from(msspClientSlas)
          .where(and(eq(msspClientSlas.id, slaId), eq(msspClientSlas.parentOrgId, orgId)))
          .limit(1);

        if (!existing) {
          return replyError(res, 404, [{ code: "SLA_NOT_FOUND", message: "SLA not found" }]);
        }

        const allowedFields = slaSchema.partial().omit({ childOrgId: true });
        const parsed = allowedFields.safeParse(req.body);
        if (!parsed.success) {
          return replyError(
            res,
            400,
            parsed.error.errors.map((e) => ({ code: "VALIDATION_ERROR", message: e.message })),
          );
        }

        const [updated] = await db
          .update(msspClientSlas)
          .set({ ...parsed.data, updatedAt: new Date() })
          .where(eq(msspClientSlas.id, slaId))
          .returning();

        return sendEnvelope(res, updated);
      } catch (err) {
        log.error("Failed to update SLA", { error: String(err) });
        return replyError(res, 500, [{ code: "SLA_UPDATE_FAILED", message: "Failed to update SLA" }]);
      }
    },
  );

  // Delete SLA
  app.delete(
    "/api/mssp-portal/slas/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const slaId = String(req.params.id);
        const [existing] = await db
          .select()
          .from(msspClientSlas)
          .where(and(eq(msspClientSlas.id, slaId), eq(msspClientSlas.parentOrgId, orgId)))
          .limit(1);

        if (!existing) {
          return replyError(res, 404, [{ code: "SLA_NOT_FOUND", message: "SLA not found" }]);
        }

        await db.delete(msspClientSlas).where(eq(msspClientSlas.id, slaId));
        return sendEnvelope(res, { deleted: true });
      } catch (err) {
        log.error("Failed to delete SLA", { error: String(err) });
        return replyError(res, 500, [{ code: "SLA_DELETE_FAILED", message: "Failed to delete SLA" }]);
      }
    },
  );

  // List SLA breaches
  app.get(
    "/api/mssp-portal/sla-breaches",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const childOrgId = req.query.childOrgId as string | undefined;
        const status = req.query.status as string | undefined;

        const conditions = [eq(msspSlaBreaches.parentOrgId, orgId)];
        if (childOrgId) conditions.push(eq(msspSlaBreaches.childOrgId, childOrgId));
        if (status) conditions.push(eq(msspSlaBreaches.status, status));

        const breaches = await db
          .select()
          .from(msspSlaBreaches)
          .where(and(...conditions))
          .orderBy(desc(msspSlaBreaches.createdAt))
          .limit(200);

        return sendEnvelope(res, breaches);
      } catch (err) {
        log.error("Failed to list SLA breaches", { error: String(err) });
        return replyError(res, 500, [{ code: "SLA_BREACH_LIST_FAILED", message: "Failed to list SLA breaches" }]);
      }
    },
  );

  // Resolve SLA breach
  app.patch(
    "/api/mssp-portal/sla-breaches/:id/resolve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const breachId = String(req.params.id);
        const [existing] = await db
          .select()
          .from(msspSlaBreaches)
          .where(and(eq(msspSlaBreaches.id, breachId), eq(msspSlaBreaches.parentOrgId, orgId)))
          .limit(1);

        if (!existing) {
          return replyError(res, 404, [{ code: "BREACH_NOT_FOUND", message: "SLA breach not found" }]);
        }

        const userName = String((req as any).user?.email || "unknown");
        const [updated] = await db
          .update(msspSlaBreaches)
          .set({
            status: "resolved",
            resolvedAt: new Date(),
            resolvedBy: userName,
            notes: req.body.notes || null,
          })
          .where(eq(msspSlaBreaches.id, breachId))
          .returning();

        return sendEnvelope(res, updated);
      } catch (err) {
        log.error("Failed to resolve SLA breach", { error: String(err) });
        return replyError(res, 500, [{ code: "BREACH_RESOLVE_FAILED", message: "Failed to resolve SLA breach" }]);
      }
    },
  );

  // ==========================================================================
  // USAGE-BASED BILLING PASSTHROUGH
  // ==========================================================================

  // List billing records
  app.get(
    "/api/mssp-portal/billing",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const childOrgId = req.query.childOrgId as string | undefined;
        const status = req.query.status as string | undefined;

        const conditions = [eq(msspBillingRecords.parentOrgId, orgId)];
        if (childOrgId) conditions.push(eq(msspBillingRecords.childOrgId, childOrgId));
        if (status && MSSP_BILLING_STATUSES.includes(status as any)) {
          conditions.push(eq(msspBillingRecords.status, status));
        }

        const records = await db
          .select()
          .from(msspBillingRecords)
          .where(and(...conditions))
          .orderBy(desc(msspBillingRecords.periodStart))
          .limit(200);

        return sendEnvelope(res, records);
      } catch (err) {
        log.error("Failed to list billing records", { error: String(err) });
        return replyError(res, 500, [{ code: "BILLING_LIST_FAILED", message: "Failed to list billing records" }]);
      }
    },
  );

  // Generate billing record for a child org period
  app.post(
    "/api/mssp-portal/billing/generate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const parsed = billingSchema.safeParse(req.body);
        if (!parsed.success) {
          return replyError(
            res,
            400,
            parsed.error.errors.map((e) => ({ code: "VALIDATION_ERROR", message: e.message })),
          );
        }

        const { childOrgId, periodStart, periodEnd, baseFee, markupPercent, notes } = parsed.data;

        if (!(await verifyChildOwnership(orgId, childOrgId))) {
          return replyError(res, 404, [{ code: "CHILD_NOT_FOUND", message: "Child org not found or not owned" }]);
        }

        // Compute usage from real data
        const pStart = new Date(periodStart);
        const pEnd = new Date(periodEnd);

        const alertResult = await db
          .select({ cnt: count() })
          .from(alerts)
          .where(
            and(
              eq(alerts.orgId, childOrgId),
              sql`${alerts.createdAt} >= ${pStart}`,
              sql`${alerts.createdAt} < ${pEnd}`,
            ),
          );
        const alertsIngested = alertResult[0]?.cnt || 0;

        const userResult = await db.execute(
          sql`SELECT COUNT(DISTINCT user_id) AS cnt FROM organization_members WHERE org_id = ${childOrgId}`,
        );
        const userCount = Number(userResult.rows[0]?.cnt || 0);

        // Pricing: $0.01 per alert, $10 per user, $0.50 per GB, $0.05 per AI analysis
        const perAlertCents = 1;
        const perUserCents = 1000;
        const perGbCents = 50;
        const perAiCents = 5;

        const alertsCost = alertsIngested * perAlertCents;
        const userCost = userCount * perUserCents;
        const aiAnalyses = 0; // TODO: integrate with AI usage tracking
        const aiCost = aiAnalyses * perAiCents;
        const storageGb = 0; // TODO: integrate with storage metering
        const storageCost = Math.round(storageGb * perGbCents);
        const base = baseFee || 0;
        const subtotal = base + alertsCost + userCost + aiCost + storageCost;
        const markup = markupPercent || 0;
        const markupAmount = Math.round(subtotal * (markup / 100));
        const totalAmount = subtotal + markupAmount;

        const [record] = await db
          .insert(msspBillingRecords)
          .values({
            parentOrgId: orgId,
            childOrgId,
            periodStart: pStart,
            periodEnd: pEnd,
            baseFee: base,
            markupPercent: markup,
            alertsIngested,
            alertsCost,
            aiAnalyses,
            aiCost,
            storageGb,
            storageCost,
            userCount,
            userCost,
            subtotal,
            markupAmount,
            totalAmount,
            currency: "USD",
            status: "draft",
            notes: notes || null,
          })
          .returning();

        const userId = String((req as any).user?.id || "");
        const userName = String((req as any).user?.email || "unknown");
        await storage.createAuditLog({
          orgId,
          userId,
          userName,
          action: "mssp_billing_generated",
          resourceType: "mssp_billing_record",
          resourceId: record.id,
          details: { childOrgId, periodStart, periodEnd, totalAmount },
        });

        return sendEnvelope(res, record, { status: 201 });
      } catch (err) {
        log.error("Failed to generate billing record", { error: String(err) });
        return replyError(res, 500, [{ code: "BILLING_GEN_FAILED", message: "Failed to generate billing record" }]);
      }
    },
  );

  // Update billing status (send, mark paid, cancel)
  app.patch(
    "/api/mssp-portal/billing/:id/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const recordId = String(req.params.id);
        const newStatus = req.body.status as string;
        if (!MSSP_BILLING_STATUSES.includes(newStatus as any)) {
          return replyError(res, 400, [
            { code: "INVALID_STATUS", message: `Status must be one of: ${MSSP_BILLING_STATUSES.join(", ")}` },
          ]);
        }

        const [existing] = await db
          .select()
          .from(msspBillingRecords)
          .where(and(eq(msspBillingRecords.id, recordId), eq(msspBillingRecords.parentOrgId, orgId)))
          .limit(1);

        if (!existing) {
          return replyError(res, 404, [{ code: "RECORD_NOT_FOUND", message: "Billing record not found" }]);
        }

        const updateData: Record<string, unknown> = {
          status: newStatus,
          updatedAt: new Date(),
        };
        if (newStatus === "paid") {
          updateData.paidAt = new Date();
        }

        const [updated] = await db
          .update(msspBillingRecords)
          .set(updateData)
          .where(eq(msspBillingRecords.id, recordId))
          .returning();

        return sendEnvelope(res, updated);
      } catch (err) {
        log.error("Failed to update billing status", { error: String(err) });
        return replyError(res, 500, [{ code: "BILLING_STATUS_FAILED", message: "Failed to update billing status" }]);
      }
    },
  );

  // ==========================================================================
  // CLIENT ONBOARDING
  // ==========================================================================

  // List onboarding records
  app.get(
    "/api/mssp-portal/onboarding",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const status = req.query.status as string | undefined;
        const conditions = [eq(msspClientOnboarding.parentOrgId, orgId)];
        if (status) conditions.push(eq(msspClientOnboarding.status, status));

        const records = await db
          .select()
          .from(msspClientOnboarding)
          .where(and(...conditions))
          .orderBy(desc(msspClientOnboarding.createdAt));

        return sendEnvelope(res, records);
      } catch (err) {
        log.error("Failed to list onboarding records", { error: String(err) });
        return replyError(res, 500, [{ code: "ONBOARD_LIST_FAILED", message: "Failed to list onboarding records" }]);
      }
    },
  );

  // Create onboarding record (auto-created when child org is created)
  app.post(
    "/api/mssp-portal/onboarding",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const childOrgId = req.body.childOrgId as string;
        if (!childOrgId) {
          return replyError(res, 400, [{ code: "MISSING_CHILD_ORG", message: "childOrgId is required" }]);
        }

        if (!(await verifyChildOwnership(orgId, childOrgId))) {
          return replyError(res, 404, [{ code: "CHILD_NOT_FOUND", message: "Child org not found or not owned" }]);
        }

        // Check for existing onboarding record
        const [existing] = await db
          .select()
          .from(msspClientOnboarding)
          .where(and(eq(msspClientOnboarding.parentOrgId, orgId), eq(msspClientOnboarding.childOrgId, childOrgId)))
          .limit(1);

        if (existing) {
          return replyError(res, 409, [
            { code: "ONBOARD_EXISTS", message: "Onboarding record already exists for this client" },
          ]);
        }

        const [record] = await db
          .insert(msspClientOnboarding)
          .values({
            parentOrgId: orgId,
            childOrgId,
            status: "pending",
            assignedTo: req.body.assignedTo || null,
            targetGoLiveDate: req.body.targetGoLiveDate ? new Date(req.body.targetGoLiveDate) : null,
            notes: req.body.notes || null,
          })
          .returning();

        return sendEnvelope(res, record, { status: 201 });
      } catch (err) {
        log.error("Failed to create onboarding record", { error: String(err) });
        return replyError(res, 500, [{ code: "ONBOARD_CREATE_FAILED", message: "Failed to create onboarding record" }]);
      }
    },
  );

  // Update onboarding step
  app.patch(
    "/api/mssp-portal/onboarding/:id/steps",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const onboardingId = String(req.params.id);
        const [existing] = await db
          .select()
          .from(msspClientOnboarding)
          .where(and(eq(msspClientOnboarding.id, onboardingId), eq(msspClientOnboarding.parentOrgId, orgId)))
          .limit(1);

        if (!existing) {
          return replyError(res, 404, [{ code: "ONBOARD_NOT_FOUND", message: "Onboarding record not found" }]);
        }

        const stepUpdate = onboardingStepSchema.safeParse(req.body);
        if (!stepUpdate.success) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "Invalid step update (key and done required)" },
          ]);
        }

        const currentSteps = (existing.steps as Array<{ key: string; label: string; done: boolean }>) || [];
        const updatedSteps = currentSteps.map((s) =>
          s.key === stepUpdate.data.key ? { ...s, done: stepUpdate.data.done } : s,
        );

        const allDone = updatedSteps.every((s) => s.done);
        const newStatus = allDone ? "completed" : "in_progress";

        const updateData: Record<string, unknown> = {
          steps: updatedSteps,
          status: newStatus,
          updatedAt: new Date(),
        };
        if (allDone && !existing.actualGoLiveDate) {
          updateData.actualGoLiveDate = new Date();
        }

        const [updated] = await db
          .update(msspClientOnboarding)
          .set(updateData)
          .where(eq(msspClientOnboarding.id, onboardingId))
          .returning();

        return sendEnvelope(res, updated);
      } catch (err) {
        log.error("Failed to update onboarding step", { error: String(err) });
        return replyError(res, 500, [{ code: "ONBOARD_STEP_FAILED", message: "Failed to update onboarding step" }]);
      }
    },
  );

  // ==========================================================================
  // MSSP-TIER REPORTING (cross-client aggregation)
  // ==========================================================================

  // Get MSSP-wide report data
  app.get(
    "/api/mssp-portal/report",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const children = await storage.getChildOrganizations(orgId);
        const childOrgIds = children.map((c) => c.id);

        if (childOrgIds.length === 0) {
          return sendEnvelope(res, {
            parentOrgId: orgId,
            childCount: 0,
            clients: [],
            totals: {
              totalAlerts: 0,
              criticalAlerts: 0,
              openIncidents: 0,
              totalConnectors: 0,
              slaBreaches: 0,
              revenue: 0,
            },
          });
        }

        // Per-client stats
        const clientStats = [];
        for (const child of children) {
          const alertResult = await db.select({ cnt: count() }).from(alerts).where(eq(alerts.orgId, child.id));

          const criticalResult = await db
            .select({ cnt: count() })
            .from(alerts)
            .where(and(eq(alerts.orgId, child.id), eq(alerts.severity, "critical")));

          const incidentResult = await db
            .select({ cnt: count() })
            .from(incidents)
            .where(and(eq(incidents.orgId, child.id), eq(incidents.status, "open")));

          const connectorResult = await db
            .select({ cnt: count() })
            .from(connectors)
            .where(eq(connectors.orgId, child.id));

          const slaBreachResult = await db
            .select({ cnt: count() })
            .from(msspSlaBreaches)
            .where(and(eq(msspSlaBreaches.childOrgId, child.id), eq(msspSlaBreaches.status, "breached")));

          clientStats.push({
            orgId: child.id,
            orgName: child.name,
            orgSlug: child.slug,
            industry: child.industry,
            alertCount: alertResult[0]?.cnt || 0,
            criticalAlerts: criticalResult[0]?.cnt || 0,
            openIncidents: incidentResult[0]?.cnt || 0,
            connectorCount: connectorResult[0]?.cnt || 0,
            activeSlaBreaches: slaBreachResult[0]?.cnt || 0,
          });
        }

        // Totals
        const totals = clientStats.reduce(
          (acc, c) => ({
            totalAlerts: acc.totalAlerts + Number(c.alertCount),
            criticalAlerts: acc.criticalAlerts + Number(c.criticalAlerts),
            openIncidents: acc.openIncidents + Number(c.openIncidents),
            totalConnectors: acc.totalConnectors + Number(c.connectorCount),
            slaBreaches: acc.slaBreaches + Number(c.activeSlaBreaches),
            revenue: acc.revenue,
          }),
          { totalAlerts: 0, criticalAlerts: 0, openIncidents: 0, totalConnectors: 0, slaBreaches: 0, revenue: 0 },
        );

        // Revenue from billing
        const billingResult = await db
          .select({ total: sql<number>`COALESCE(SUM(total_amount), 0)` })
          .from(msspBillingRecords)
          .where(and(eq(msspBillingRecords.parentOrgId, orgId), eq(msspBillingRecords.status, "paid")));
        totals.revenue = Number(billingResult[0]?.total || 0);

        return sendEnvelope(res, {
          parentOrgId: orgId,
          childCount: children.length,
          clients: clientStats,
          totals,
        });
      } catch (err) {
        log.error("Failed to generate MSSP report", { error: String(err) });
        return replyError(res, 500, [{ code: "REPORT_FAILED", message: "Failed to generate MSSP report" }]);
      }
    },
  );

  // ==========================================================================
  // PARTNER PORTAL STATS
  // ==========================================================================

  app.get(
    "/api/mssp-portal/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = await requireMsspParent(req, res);
        if (!orgId) return;

        const children = await storage.getChildOrganizations(orgId);

        // SLA stats
        const slaResult = await db
          .select({ cnt: count() })
          .from(msspClientSlas)
          .where(and(eq(msspClientSlas.parentOrgId, orgId), eq(msspClientSlas.isActive, true)));

        const breachResult = await db
          .select({ cnt: count() })
          .from(msspSlaBreaches)
          .where(and(eq(msspSlaBreaches.parentOrgId, orgId), eq(msspSlaBreaches.status, "breached")));

        // Onboarding stats
        const onboardingPendingResult = await db
          .select({ cnt: count() })
          .from(msspClientOnboarding)
          .where(and(eq(msspClientOnboarding.parentOrgId, orgId), sql`${msspClientOnboarding.status} != 'completed'`));

        const onboardingCompletedResult = await db
          .select({ cnt: count() })
          .from(msspClientOnboarding)
          .where(and(eq(msspClientOnboarding.parentOrgId, orgId), eq(msspClientOnboarding.status, "completed")));

        // Billing stats
        const billingDraftResult = await db
          .select({ cnt: count() })
          .from(msspBillingRecords)
          .where(and(eq(msspBillingRecords.parentOrgId, orgId), eq(msspBillingRecords.status, "draft")));

        const billingPaidResult = await db
          .select({ total: sql<number>`COALESCE(SUM(total_amount), 0)` })
          .from(msspBillingRecords)
          .where(and(eq(msspBillingRecords.parentOrgId, orgId), eq(msspBillingRecords.status, "paid")));

        const billingOverdueResult = await db
          .select({ cnt: count() })
          .from(msspBillingRecords)
          .where(and(eq(msspBillingRecords.parentOrgId, orgId), eq(msspBillingRecords.status, "overdue")));

        // White-label status
        const [wlConfig] = await db
          .select()
          .from(msspWhiteLabelConfigs)
          .where(eq(msspWhiteLabelConfigs.orgId, orgId))
          .limit(1);

        return sendEnvelope(res, {
          clientCount: children.length,
          activeSlas: slaResult[0]?.cnt || 0,
          activeBreaches: breachResult[0]?.cnt || 0,
          onboardingPending: onboardingPendingResult[0]?.cnt || 0,
          onboardingCompleted: onboardingCompletedResult[0]?.cnt || 0,
          billingDraftInvoices: billingDraftResult[0]?.cnt || 0,
          billingTotalRevenue: Number(billingPaidResult[0]?.total || 0),
          billingOverdueCount: billingOverdueResult[0]?.cnt || 0,
          whiteLabelConfigured: !!wlConfig,
          whiteLabelActive: wlConfig?.isActive || false,
        });
      } catch (err) {
        log.error("Failed to get portal stats", { error: String(err) });
        return replyError(res, 500, [{ code: "STATS_FAILED", message: "Failed to get portal stats" }]);
      }
    },
  );
}
