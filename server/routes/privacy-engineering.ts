import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission, requireMinRole } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count, ilike, or } from "drizzle-orm";
import {
  dataAssets,
  dataFlows,
  privacyImpactAssessments,
  privacyScans,
  consentRecords,
  crossBorderTransferAlerts,
  dsarFulfillmentTasks,
  dsarRequests,
  DATA_CLASSIFICATION_LEVELS,
  PII_CATEGORIES,
  DATA_ASSET_TYPES,
  DATA_FLOW_STATUSES,
  PIA_STATUSES,
  PIA_RISK_LEVELS,
  CONSENT_PURPOSES,
  DSAR_TYPES,
  JURISDICTIONS,
} from "../../shared/schema";
import {
  getPrivacyDashboard,
  scanFieldNames,
  computePrivacyRiskScore,
  assessCrossBorderRisk,
  generateMinimizationReport,
} from "../data-discovery";

const log = logger.child("privacy-engineering");

const ALLOWED_ASSET_FIELDS = [
  "name",
  "description",
  "assetType",
  "connectionString",
  "hostname",
  "database",
  "schema",
  "tableName",
  "bucketName",
  "filePath",
  "classification",
  "piiCategories",
  "recordCount",
  "dataSubjectCount",
  "jurisdiction",
  "retentionDays",
  "isEncrypted",
  "encryptionMethod",
  "dataOwner",
  "dataProcessor",
  "legalBasis",
  "metadata",
];

const ALLOWED_FLOW_FIELDS = [
  "name",
  "description",
  "sourceAssetId",
  "sourceName",
  "sourceJurisdiction",
  "destinationAssetId",
  "destinationName",
  "destinationJurisdiction",
  "dataCategories",
  "piiCategories",
  "purpose",
  "legalBasis",
  "processorName",
  "isCrossBorder",
  "crossBorderMechanism",
  "transferRiskLevel",
  "status",
  "volumePerDay",
  "frequency",
  "encryptionInTransit",
  "metadata",
];

const ALLOWED_PIA_FIELDS = [
  "title",
  "description",
  "projectName",
  "assessorName",
  "assessorEmail",
  "status",
  "overallRisk",
  "dataCollected",
  "dataSubjectTypes",
  "processingPurposes",
  "legalBasis",
  "retentionPeriod",
  "thirdPartyRecipients",
  "crossBorderTransfers",
  "crossBorderDestinations",
  "securityMeasures",
  "privacyRisks",
  "mitigationPlan",
  "dpoApproval",
  "dpoComments",
  "reviewDate",
  "expiresAt",
  "metadata",
];

const ALLOWED_CONSENT_FIELDS = [
  "dataSubjectId",
  "dataSubjectEmail",
  "purpose",
  "granted",
  "source",
  "externalConsentId",
  "legalBasis",
  "jurisdiction",
  "consentVersion",
  "grantedAt",
  "withdrawnAt",
  "expiresAt",
  "metadata",
];

export function registerPrivacyEngineeringRoutes(app: Express): void {
  // ==========================================================================
  // Dashboard
  // ==========================================================================

  app.get(
    "/api/privacy-engineering/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const dashboard = await getPrivacyDashboard(orgId);
        res.json(dashboard);
      } catch (err) {
        log.error("Failed to get privacy dashboard", { error: String(err) });
        res.status(500).json({ error: "Failed to get privacy dashboard" });
      }
    },
  );

  // ==========================================================================
  // Data Assets CRUD
  // ==========================================================================

  app.get(
    "/api/privacy-engineering/data-assets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { classification, assetType, jurisdiction, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(dataAssets.orgId, orgId)];
        if (classification && typeof classification === "string") {
          conditions.push(eq(dataAssets.classification, classification));
        }
        if (assetType && typeof assetType === "string") {
          conditions.push(eq(dataAssets.assetType, assetType));
        }
        if (jurisdiction && typeof jurisdiction === "string") {
          conditions.push(eq(dataAssets.jurisdiction, jurisdiction));
        }
        if (search && typeof search === "string") {
          const escaped = search.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(
            or(
              ilike(dataAssets.name, `%${escaped}%`),
              ilike(dataAssets.hostname, `%${escaped}%`),
              ilike(dataAssets.dataOwner, `%${escaped}%`),
            )!,
          );
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(dataAssets)
            .where(and(...conditions))
            .orderBy(desc(dataAssets.riskScore))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(dataAssets)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list data assets", { error: String(err) });
        res.status(500).json({ error: "Failed to list data assets" });
      }
    },
  );

  app.post(
    "/api/privacy-engineering/data-assets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_ASSET_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name || !body.assetType) {
          return res.status(400).json({ error: "name and assetType are required" });
        }

        // Auto-compute risk score
        const riskScore = computePrivacyRiskScore({
          classification: String(body.classification || "internal"),
          piiCategories: (body.piiCategories as string[]) || [],
          isEncrypted: Boolean(body.isEncrypted),
          hasRetentionPolicy: Boolean(body.retentionDays),
          jurisdiction: String(body.jurisdiction || "OTHER"),
          isCrossBorder: false,
          recordCount: Number(body.recordCount) || 0,
          dataSubjectCount: Number(body.dataSubjectCount) || 0,
        });

        const [created] = await db
          .insert(dataAssets)
          .values({ ...body, orgId, riskScore } as typeof dataAssets.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create data asset", { error: String(err) });
        res.status(500).json({ error: "Failed to create data asset" });
      }
    },
  );

  app.patch(
    "/api/privacy-engineering/data-assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_ASSET_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        // Recompute risk score if relevant fields changed
        if (updates.classification || updates.piiCategories || updates.isEncrypted || updates.jurisdiction) {
          const [existing] = await db
            .select()
            .from(dataAssets)
            .where(and(eq(dataAssets.id, String(req.params.id)), eq(dataAssets.orgId, orgId)))
            .limit(1);
          if (existing) {
            updates.riskScore = computePrivacyRiskScore({
              classification: String(updates.classification ?? existing.classification),
              piiCategories: (updates.piiCategories as string[]) ?? (existing.piiCategories as string[]) ?? [],
              isEncrypted: updates.isEncrypted !== undefined ? Boolean(updates.isEncrypted) : existing.isEncrypted,
              hasRetentionPolicy: Boolean(updates.retentionDays ?? existing.retentionDays),
              jurisdiction: String(updates.jurisdiction ?? existing.jurisdiction),
              isCrossBorder: false,
              recordCount: Number(updates.recordCount ?? existing.recordCount) || 0,
              dataSubjectCount: Number(updates.dataSubjectCount ?? existing.dataSubjectCount) || 0,
            });
          }
        }

        const [updated] = await db
          .update(dataAssets)
          .set(updates as Partial<typeof dataAssets.$inferInsert>)
          .where(and(eq(dataAssets.id, String(req.params.id)), eq(dataAssets.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Data asset not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update data asset", { error: String(err) });
        res.status(500).json({ error: "Failed to update data asset" });
      }
    },
  );

  app.delete(
    "/api/privacy-engineering/data-assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(dataAssets)
          .where(and(eq(dataAssets.id, String(req.params.id)), eq(dataAssets.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Data asset not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete data asset", { error: String(err) });
        res.status(500).json({ error: "Failed to delete data asset" });
      }
    },
  );

  // ==========================================================================
  // Data Discovery — PII/PHI/PCI Scanning
  // ==========================================================================

  app.post(
    "/api/privacy-engineering/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { scanType, targetAssetId, fields, targetDescription } = req.body;

        if (!scanType) {
          return res.status(400).json({ error: "scanType is required" });
        }
        if (!fields || !Array.isArray(fields) || fields.length === 0) {
          return res.status(400).json({ error: "fields array is required" });
        }

        const startTime = Date.now();
        const scanResult = scanFieldNames(fields as string[]);
        const durationMs = Date.now() - startTime;

        const [scan] = await db
          .insert(privacyScans)
          .values({
            orgId,
            scanType: String(scanType),
            targetAssetId: targetAssetId ? String(targetAssetId) : null,
            targetDescription: targetDescription ? String(targetDescription) : null,
            status: "completed",
            findingsCount: scanResult.results.length,
            piiFieldsFound: scanResult.piiCount,
            phiFieldsFound: scanResult.phiCount,
            pciFieldsFound: scanResult.pciCount,
            classificationResults: scanResult.results,
            minimizationFindings: scanResult.minimizationFindings,
            scanDurationMs: durationMs,
            completedAt: new Date(),
          })
          .returning();

        // If a target asset was specified, update its PII categories and classification
        if (targetAssetId) {
          const detectedCategories = Array.from(new Set(scanResult.results.map((r) => r.detectedType)));
          await db
            .update(dataAssets)
            .set({
              piiCategories: detectedCategories,
              classification: scanResult.overallClassification,
              lastScannedAt: new Date(),
              scanFindings: {
                lastScanId: scan.id,
                piiCount: scanResult.piiCount,
                phiCount: scanResult.phiCount,
                pciCount: scanResult.pciCount,
              },
              minimizationRecommendations: scanResult.minimizationFindings.map((f) => f.recommendation),
              updatedAt: new Date(),
            })
            .where(and(eq(dataAssets.id, String(targetAssetId)), eq(dataAssets.orgId, orgId)));
        }

        res.status(201).json({
          scan,
          results: scanResult.results,
          minimizationFindings: scanResult.minimizationFindings,
          overallClassification: scanResult.overallClassification,
        });
      } catch (err) {
        log.error("Failed to run privacy scan", { error: String(err) });
        res.status(500).json({ error: "Failed to run privacy scan" });
      }
    },
  );

  app.get(
    "/api/privacy-engineering/scans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(Number(req.query.limit) || 50, 200);
        const offset = Number(req.query.offset) || 0;

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(privacyScans)
            .where(eq(privacyScans.orgId, orgId))
            .orderBy(desc(privacyScans.startedAt))
            .limit(limit)
            .offset(offset),
          db.select({ value: count() }).from(privacyScans).where(eq(privacyScans.orgId, orgId)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list privacy scans", { error: String(err) });
        res.status(500).json({ error: "Failed to list privacy scans" });
      }
    },
  );

  // ==========================================================================
  // Data Minimization Analysis
  // ==========================================================================

  app.post(
    "/api/privacy-engineering/minimization-analysis",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const { assetName, fields, purpose } = req.body;
        if (!assetName || !fields || !Array.isArray(fields)) {
          return res.status(400).json({ error: "assetName and fields array are required" });
        }
        const report = generateMinimizationReport(String(assetName), fields as string[], String(purpose || "general"));
        res.json(report);
      } catch (err) {
        log.error("Failed to generate minimization report", { error: String(err) });
        res.status(500).json({ error: "Failed to generate minimization report" });
      }
    },
  );

  // ==========================================================================
  // Data Flows CRUD
  // ==========================================================================

  app.get(
    "/api/privacy-engineering/data-flows",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, crossBorder, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(dataFlows.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(dataFlows.status, status));
        }
        if (crossBorder === "true") {
          conditions.push(eq(dataFlows.isCrossBorder, true));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(dataFlows)
            .where(and(...conditions))
            .orderBy(desc(dataFlows.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(dataFlows)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list data flows", { error: String(err) });
        res.status(500).json({ error: "Failed to list data flows" });
      }
    },
  );

  app.post(
    "/api/privacy-engineering/data-flows",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_FLOW_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.name || !body.sourceName || !body.destinationName) {
          return res.status(400).json({ error: "name, sourceName, and destinationName are required" });
        }

        // Auto-detect cross-border
        const srcJurisdiction = String(body.sourceJurisdiction || "OTHER");
        const destJurisdiction = String(body.destinationJurisdiction || "OTHER");
        if (srcJurisdiction !== destJurisdiction) {
          body.isCrossBorder = true;
          const risk = assessCrossBorderRisk(srcJurisdiction, destJurisdiction, (body.piiCategories as string[]) || []);
          body.transferRiskLevel = risk.riskLevel;
        }

        const [created] = await db
          .insert(dataFlows)
          .values({ ...body, orgId } as typeof dataFlows.$inferInsert)
          .returning();

        // Auto-generate cross-border alert if high risk
        if (body.isCrossBorder && (body.transferRiskLevel === "high" || body.transferRiskLevel === "very_high")) {
          const risk = assessCrossBorderRisk(srcJurisdiction, destJurisdiction, (body.piiCategories as string[]) || []);
          await db.insert(crossBorderTransferAlerts).values({
            orgId,
            dataFlowId: created.id,
            sourceJurisdiction: srcJurisdiction,
            destinationJurisdiction: destJurisdiction,
            dataCategories: (body.piiCategories as string[]) || [],
            riskLevel: risk.riskLevel,
            alertReason: risk.reasons.join("; "),
            legalMechanism: risk.requiredMechanisms.join(", "),
            requiresAction: true,
          });
        }

        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create data flow", { error: String(err) });
        res.status(500).json({ error: "Failed to create data flow" });
      }
    },
  );

  app.patch(
    "/api/privacy-engineering/data-flows/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_FLOW_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        const [updated] = await db
          .update(dataFlows)
          .set(updates as Partial<typeof dataFlows.$inferInsert>)
          .where(and(eq(dataFlows.id, String(req.params.id)), eq(dataFlows.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Data flow not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update data flow", { error: String(err) });
        res.status(500).json({ error: "Failed to update data flow" });
      }
    },
  );

  app.delete(
    "/api/privacy-engineering/data-flows/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(dataFlows)
          .where(and(eq(dataFlows.id, String(req.params.id)), eq(dataFlows.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "Data flow not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete data flow", { error: String(err) });
        res.status(500).json({ error: "Failed to delete data flow" });
      }
    },
  );

  // ==========================================================================
  // Cross-Border Transfer Risk Assessment
  // ==========================================================================

  app.post(
    "/api/privacy-engineering/cross-border-risk",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const { sourceJurisdiction, destinationJurisdiction, dataCategories } = req.body;
        if (!sourceJurisdiction || !destinationJurisdiction) {
          return res.status(400).json({ error: "sourceJurisdiction and destinationJurisdiction are required" });
        }
        const risk = assessCrossBorderRisk(
          String(sourceJurisdiction),
          String(destinationJurisdiction),
          (dataCategories as string[]) || [],
        );
        res.json(risk);
      } catch (err) {
        log.error("Failed to assess cross-border risk", { error: String(err) });
        res.status(500).json({ error: "Failed to assess cross-border risk" });
      }
    },
  );

  app.get(
    "/api/privacy-engineering/cross-border-alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(Number(req.query.limit) || 50, 200);

        const alerts = await db
          .select()
          .from(crossBorderTransferAlerts)
          .where(eq(crossBorderTransferAlerts.orgId, orgId))
          .orderBy(desc(crossBorderTransferAlerts.createdAt))
          .limit(limit);

        res.json(alerts);
      } catch (err) {
        log.error("Failed to list cross-border alerts", { error: String(err) });
        res.status(500).json({ error: "Failed to list cross-border alerts" });
      }
    },
  );

  app.patch(
    "/api/privacy-engineering/cross-border-alerts/:id/resolve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { resolutionNotes } = req.body;

        const [updated] = await db
          .update(crossBorderTransferAlerts)
          .set({
            requiresAction: false,
            resolvedAt: new Date(),
            resolvedBy: (req as any).user?.email || "system",
            resolutionNotes: resolutionNotes ? String(resolutionNotes) : null,
          })
          .where(
            and(eq(crossBorderTransferAlerts.id, String(req.params.id)), eq(crossBorderTransferAlerts.orgId, orgId)),
          )
          .returning();
        if (!updated) return res.status(404).json({ error: "Alert not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to resolve cross-border alert", { error: String(err) });
        res.status(500).json({ error: "Failed to resolve cross-border alert" });
      }
    },
  );

  // ==========================================================================
  // Privacy Impact Assessments CRUD
  // ==========================================================================

  app.get(
    "/api/privacy-engineering/pias",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, risk, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(privacyImpactAssessments.orgId, orgId)];
        if (status && typeof status === "string") {
          conditions.push(eq(privacyImpactAssessments.status, status));
        }
        if (risk && typeof risk === "string") {
          conditions.push(eq(privacyImpactAssessments.overallRisk, risk));
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(privacyImpactAssessments)
            .where(and(...conditions))
            .orderBy(desc(privacyImpactAssessments.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(privacyImpactAssessments)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list PIAs", { error: String(err) });
        res.status(500).json({ error: "Failed to list PIAs" });
      }
    },
  );

  app.post(
    "/api/privacy-engineering/pias",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_PIA_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.title) {
          return res.status(400).json({ error: "title is required" });
        }

        const [created] = await db
          .insert(privacyImpactAssessments)
          .values({ ...body, orgId } as typeof privacyImpactAssessments.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create PIA", { error: String(err) });
        res.status(500).json({ error: "Failed to create PIA" });
      }
    },
  );

  app.patch(
    "/api/privacy-engineering/pias/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const key of ALLOWED_PIA_FIELDS) {
          if (req.body[key] !== undefined) updates[key] = req.body[key];
        }

        if (updates.status === "approved") {
          updates.completedAt = new Date();
        } else if (updates.status && updates.status !== "approved") {
          updates.completedAt = null;
        }

        const [updated] = await db
          .update(privacyImpactAssessments)
          .set(updates as Partial<typeof privacyImpactAssessments.$inferInsert>)
          .where(and(eq(privacyImpactAssessments.id, String(req.params.id)), eq(privacyImpactAssessments.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "PIA not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update PIA", { error: String(err) });
        res.status(500).json({ error: "Failed to update PIA" });
      }
    },
  );

  app.delete(
    "/api/privacy-engineering/pias/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [deleted] = await db
          .delete(privacyImpactAssessments)
          .where(and(eq(privacyImpactAssessments.id, String(req.params.id)), eq(privacyImpactAssessments.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ error: "PIA not found" });
        res.json({ success: true });
      } catch (err) {
        log.error("Failed to delete PIA", { error: String(err) });
        res.status(500).json({ error: "Failed to delete PIA" });
      }
    },
  );

  // ==========================================================================
  // Consent Management
  // ==========================================================================

  app.get(
    "/api/privacy-engineering/consent-records",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { purpose, granted, search, limit: limitStr, offset: offsetStr } = req.query;
        const limit = Math.min(Number(limitStr) || 50, 200);
        const offset = Number(offsetStr) || 0;

        const conditions = [eq(consentRecords.orgId, orgId)];
        if (purpose && typeof purpose === "string") {
          conditions.push(eq(consentRecords.purpose, purpose));
        }
        if (granted === "true") {
          conditions.push(eq(consentRecords.granted, true));
        } else if (granted === "false") {
          conditions.push(eq(consentRecords.granted, false));
        }
        if (search && typeof search === "string") {
          const escaped = search.replace(/%/g, "\\%").replace(/_/g, "\\_");
          conditions.push(
            or(
              ilike(consentRecords.dataSubjectId, `%${escaped}%`),
              ilike(consentRecords.dataSubjectEmail, `%${escaped}%`),
            )!,
          );
        }

        const [items, [{ value: total }]] = await Promise.all([
          db
            .select()
            .from(consentRecords)
            .where(and(...conditions))
            .orderBy(desc(consentRecords.createdAt))
            .limit(limit)
            .offset(offset),
          db
            .select({ value: count() })
            .from(consentRecords)
            .where(and(...conditions)),
        ]);

        res.json({ items, total, limit, offset });
      } catch (err) {
        log.error("Failed to list consent records", { error: String(err) });
        res.status(500).json({ error: "Failed to list consent records" });
      }
    },
  );

  app.post(
    "/api/privacy-engineering/consent-records",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const body: Record<string, unknown> = {};
        for (const key of ALLOWED_CONSENT_FIELDS) {
          if (req.body[key] !== undefined) body[key] = req.body[key];
        }
        if (!body.dataSubjectId || !body.purpose) {
          return res.status(400).json({ error: "dataSubjectId and purpose are required" });
        }

        if (body.granted) {
          body.grantedAt = body.grantedAt || new Date();
        }

        const [created] = await db
          .insert(consentRecords)
          .values({ ...body, orgId } as typeof consentRecords.$inferInsert)
          .returning();
        res.status(201).json(created);
      } catch (err) {
        log.error("Failed to create consent record", { error: String(err) });
        res.status(500).json({ error: "Failed to create consent record" });
      }
    },
  );

  app.patch(
    "/api/privacy-engineering/consent-records/:id/withdraw",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const [updated] = await db
          .update(consentRecords)
          .set({
            granted: false,
            withdrawnAt: new Date(),
            updatedAt: new Date(),
          })
          .where(and(eq(consentRecords.id, String(req.params.id)), eq(consentRecords.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Consent record not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to withdraw consent", { error: String(err) });
        res.status(500).json({ error: "Failed to withdraw consent" });
      }
    },
  );

  // ==========================================================================
  // DSAR Fulfillment Automation
  // ==========================================================================

  app.get(
    "/api/privacy-engineering/dsar-fulfillment/:dsarId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const dsarId = String(req.params.dsarId);

        // Verify DSAR belongs to org
        const [dsar] = await db
          .select()
          .from(dsarRequests)
          .where(and(eq(dsarRequests.id, dsarId), eq(dsarRequests.orgId, orgId)))
          .limit(1);
        if (!dsar) return res.status(404).json({ error: "DSAR request not found" });

        const tasks = await db
          .select()
          .from(dsarFulfillmentTasks)
          .where(and(eq(dsarFulfillmentTasks.dsarRequestId, dsarId), eq(dsarFulfillmentTasks.orgId, orgId)))
          .orderBy(desc(dsarFulfillmentTasks.createdAt));

        res.json({ dsar, tasks });
      } catch (err) {
        log.error("Failed to get DSAR fulfillment", { error: String(err) });
        res.status(500).json({ error: "Failed to get DSAR fulfillment" });
      }
    },
  );

  app.post(
    "/api/privacy-engineering/dsar-fulfillment/:dsarId/generate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const dsarId = String(req.params.dsarId);

        // Verify DSAR belongs to org
        const [dsar] = await db
          .select()
          .from(dsarRequests)
          .where(and(eq(dsarRequests.id, dsarId), eq(dsarRequests.orgId, orgId)))
          .limit(1);
        if (!dsar) return res.status(404).json({ error: "DSAR request not found" });

        // Get all data assets for the org to generate fulfillment tasks
        const assets = await db.select().from(dataAssets).where(eq(dataAssets.orgId, orgId));

        const taskType =
          dsar.requestType === "deletion" ? "delete" : dsar.requestType === "access" ? "extract" : "locate";

        const tasks = [];
        for (const asset of assets) {
          const piiCats = (asset.piiCategories as string[]) || [];
          if (piiCats.length === 0) continue; // skip assets with no PII

          const [task] = await db
            .insert(dsarFulfillmentTasks)
            .values({
              orgId,
              dsarRequestId: dsarId,
              targetSystem: asset.name,
              targetAssetId: asset.id,
              taskType,
              status: "pending",
            })
            .returning();
          tasks.push(task);
        }

        // Update DSAR status to in_progress
        await db
          .update(dsarRequests)
          .set({ status: "in_progress", updatedAt: new Date() })
          .where(eq(dsarRequests.id, dsarId));

        res.status(201).json({ tasksGenerated: tasks.length, tasks });
      } catch (err) {
        log.error("Failed to generate DSAR fulfillment tasks", { error: String(err) });
        res.status(500).json({ error: "Failed to generate DSAR fulfillment tasks" });
      }
    },
  );

  app.patch(
    "/api/privacy-engineering/dsar-fulfillment-tasks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { status, recordsAffected, errorMessage } = req.body;
        const updates: Record<string, unknown> = {};

        if (status) {
          updates.status = String(status);
          if (status === "completed") {
            updates.completedAt = new Date();
          } else if (status === "in_progress") {
            updates.startedAt = new Date();
          }
        }
        if (recordsAffected !== undefined) updates.recordsAffected = Number(recordsAffected);
        if (errorMessage !== undefined) updates.errorMessage = errorMessage ? String(errorMessage) : null;

        const [updated] = await db
          .update(dsarFulfillmentTasks)
          .set(updates as Partial<typeof dsarFulfillmentTasks.$inferInsert>)
          .where(and(eq(dsarFulfillmentTasks.id, String(req.params.id)), eq(dsarFulfillmentTasks.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ error: "Fulfillment task not found" });
        res.json(updated);
      } catch (err) {
        log.error("Failed to update fulfillment task", { error: String(err) });
        res.status(500).json({ error: "Failed to update fulfillment task" });
      }
    },
  );

  // ==========================================================================
  // Enums
  // ==========================================================================

  app.get("/api/privacy-engineering/enums", isAuthenticated, async (_req: Request, res: Response) => {
    res.json({
      classificationLevels: DATA_CLASSIFICATION_LEVELS,
      piiCategories: PII_CATEGORIES,
      assetTypes: DATA_ASSET_TYPES,
      flowStatuses: DATA_FLOW_STATUSES,
      piaStatuses: PIA_STATUSES,
      piaRiskLevels: PIA_RISK_LEVELS,
      consentPurposes: CONSENT_PURPOSES,
      dsarTypes: DSAR_TYPES,
      jurisdictions: JURISDICTIONS,
    });
  });
}
