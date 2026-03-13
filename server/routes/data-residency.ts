import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { replyBadRequest } from "../api-response";
import { logger } from "../logger";
import { storage } from "../storage";
import { db } from "../db";
import { eq, and, desc } from "drizzle-orm";
import {
  organizations,
  sovereignKeys,
  crossBorderFlowRules,
  crossBorderFlowAudit,
  DATA_REGIONS,
  DATA_REGION_ENDPOINTS,
  SOVEREIGN_KEY_STATUSES,
  type DataRegion,
  type SovereignKeyStatus,
} from "../../shared/schema";
import { invalidateRegionCache, isValidDataRegion } from "../middleware/data-residency";

const log = logger.child("data-residency-routes");

const VALID_FLOW_ACTIONS = ["block", "alert", "allow", "require-approval"] as const;
const VALID_KEY_PROVIDERS = ["aws-kms", "azure-key-vault", "gcp-kms", "hashicorp-vault", "custom"] as const;
const MAX_KEY_ALIAS_LENGTH = 128;
const MAX_RULE_NAME_LENGTH = 256;
const MAX_JUSTIFICATION_LENGTH = 2000;

function isValidKeyStatus(v: unknown): v is SovereignKeyStatus {
  return typeof v === "string" && (SOVEREIGN_KEY_STATUSES as readonly string[]).includes(v);
}

export function registerDataResidencyRoutes(app: Express): void {
  /* ── Region Config ─────────────────────────────────────────────── */

  app.get(
    "/api/data-residency/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const org = await storage.getOrganization(orgId);
        if (!org) {
          return res.status(404).json({ message: "Organization not found" });
        }

        const region = (org.dataRegion as DataRegion) || "US";
        const endpoint = DATA_REGION_ENDPOINTS[region] || DATA_REGION_ENDPOINTS.US;

        res.json({
          dataRegion: region,
          dataResidency: org.dataResidency || "us-east-1",
          regionEndpoint: endpoint,
          sovereignKeyConfig: org.sovereignKeyConfig || null,
          crossBorderFlowControls: org.crossBorderFlowControls || { mode: "permissive" },
          availableRegions: DATA_REGIONS.map((r) => ({
            code: r,
            ...DATA_REGION_ENDPOINTS[r],
          })),
        });
      } catch (error) {
        log.error("Failed to get data residency config", { error: String(error) });
        res.status(500).json({ message: "Failed to get data residency config" });
      }
    },
  );

  app.put(
    "/api/data-residency/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const { dataRegion, crossBorderFlowControls } = req.body;

        if (dataRegion !== undefined && !isValidDataRegion(dataRegion)) {
          return replyBadRequest(res, `Invalid data region. Must be one of: ${DATA_REGIONS.join(", ")}`);
        }

        if (crossBorderFlowControls !== undefined) {
          if (typeof crossBorderFlowControls !== "object" || crossBorderFlowControls === null) {
            return replyBadRequest(res, "crossBorderFlowControls must be an object");
          }
          const mode = (crossBorderFlowControls as Record<string, unknown>).mode;
          if (mode !== undefined && !["permissive", "strict", "rule-based"].includes(mode as string)) {
            return replyBadRequest(res, "crossBorderFlowControls.mode must be: permissive, strict, or rule-based");
          }
        }

        const updates: Record<string, unknown> = {};
        if (dataRegion !== undefined) {
          updates.dataRegion = dataRegion;
          updates.dataResidency = DATA_REGION_ENDPOINTS[dataRegion as DataRegion].primary;
        }
        if (crossBorderFlowControls !== undefined) {
          updates.crossBorderFlowControls = crossBorderFlowControls;
        }
        updates.updatedAt = new Date();

        await db.update(organizations).set(updates).where(eq(organizations.id, orgId));
        invalidateRegionCache(orgId);

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "data_residency_config_updated",
            resourceType: "data_residency",
            details: updates,
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        const org = await storage.getOrganization(orgId);
        const region = (org?.dataRegion as DataRegion) || "US";
        const endpoint = DATA_REGION_ENDPOINTS[region] || DATA_REGION_ENDPOINTS.US;

        res.json({
          dataRegion: region,
          dataResidency: org?.dataResidency || "us-east-1",
          regionEndpoint: endpoint,
          sovereignKeyConfig: org?.sovereignKeyConfig || null,
          crossBorderFlowControls: org?.crossBorderFlowControls || { mode: "permissive" },
        });
      } catch (error) {
        log.error("Failed to update data residency config", { error: String(error) });
        res.status(500).json({ message: "Failed to update data residency config" });
      }
    },
  );

  /* ── BYOK Sovereign Keys ──────────────────────────────────────── */

  app.get(
    "/api/data-residency/byok/keys",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const keys = await db
          .select()
          .from(sovereignKeys)
          .where(eq(sovereignKeys.orgId, orgId))
          .orderBy(desc(sovereignKeys.createdAt));

        res.json({ keys });
      } catch (error) {
        log.error("Failed to list sovereign keys", { error: String(error) });
        res.status(500).json({ message: "Failed to list sovereign keys" });
      }
    },
  );

  app.post(
    "/api/data-residency/byok/keys",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const { keyAlias, keyProvider, keyArn, keyFingerprint, rotationIntervalDays, metadata } = req.body;

        if (!keyAlias || typeof keyAlias !== "string" || keyAlias.trim().length === 0) {
          return replyBadRequest(res, "keyAlias is required");
        }
        if (keyAlias.length > MAX_KEY_ALIAS_LENGTH) {
          return replyBadRequest(res, `keyAlias must be at most ${MAX_KEY_ALIAS_LENGTH} characters`);
        }
        if (keyProvider && !(VALID_KEY_PROVIDERS as readonly string[]).includes(keyProvider)) {
          return replyBadRequest(res, `Invalid key provider. Must be one of: ${VALID_KEY_PROVIDERS.join(", ")}`);
        }
        if (rotationIntervalDays !== undefined) {
          if (typeof rotationIntervalDays !== "number" || rotationIntervalDays < 1 || rotationIntervalDays > 365) {
            return replyBadRequest(res, "rotationIntervalDays must be between 1 and 365");
          }
        }

        const nextRotation = new Date();
        nextRotation.setDate(nextRotation.getDate() + (rotationIntervalDays || 90));

        const [created] = await db
          .insert(sovereignKeys)
          .values({
            orgId,
            keyAlias: keyAlias.trim(),
            keyProvider: keyProvider || "aws-kms",
            keyArn: keyArn || null,
            keyFingerprint: keyFingerprint || null,
            status: "active",
            rotationIntervalDays: rotationIntervalDays || 90,
            nextRotationAt: nextRotation,
            metadata: metadata || null,
            createdBy: user?.id || null,
          })
          .returning();

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "sovereign_key_registered",
            resourceType: "sovereign_key",
            resourceId: created.id,
            details: { keyAlias: created.keyAlias, keyProvider: created.keyProvider },
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        log.info("Sovereign key registered", { orgId, keyId: created.id, keyAlias: created.keyAlias });
        res.status(201).json(created);
      } catch (error) {
        log.error("Failed to register sovereign key", { error: String(error) });
        res.status(500).json({ message: "Failed to register sovereign key" });
      }
    },
  );

  app.put(
    "/api/data-residency/byok/keys/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const keyId = String(req.params.id);
        const { status, rotationIntervalDays, keyAlias, metadata } = req.body;

        const [existing] = await db
          .select()
          .from(sovereignKeys)
          .where(and(eq(sovereignKeys.id, keyId), eq(sovereignKeys.orgId, orgId)));

        if (!existing) {
          return res.status(404).json({ message: "Sovereign key not found" });
        }

        if (status !== undefined && !isValidKeyStatus(status)) {
          return replyBadRequest(res, `Invalid status. Must be one of: ${SOVEREIGN_KEY_STATUSES.join(", ")}`);
        }
        if (rotationIntervalDays !== undefined) {
          if (typeof rotationIntervalDays !== "number" || rotationIntervalDays < 1 || rotationIntervalDays > 365) {
            return replyBadRequest(res, "rotationIntervalDays must be between 1 and 365");
          }
        }
        if (keyAlias !== undefined && (typeof keyAlias !== "string" || keyAlias.length > MAX_KEY_ALIAS_LENGTH)) {
          return replyBadRequest(res, `keyAlias must be a string of at most ${MAX_KEY_ALIAS_LENGTH} characters`);
        }

        const updates: Record<string, unknown> = { updatedAt: new Date() };
        if (status !== undefined) updates.status = status;
        if (rotationIntervalDays !== undefined) {
          updates.rotationIntervalDays = rotationIntervalDays;
          const nextRotation = new Date();
          nextRotation.setDate(nextRotation.getDate() + rotationIntervalDays);
          updates.nextRotationAt = nextRotation;
        }
        if (keyAlias !== undefined) updates.keyAlias = keyAlias.trim();
        if (metadata !== undefined) updates.metadata = metadata;

        if (status === "rotating") {
          updates.lastRotatedAt = new Date();
        }

        const [updated] = await db
          .update(sovereignKeys)
          .set(updates)
          .where(and(eq(sovereignKeys.id, keyId), eq(sovereignKeys.orgId, orgId)))
          .returning();

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "sovereign_key_updated",
            resourceType: "sovereign_key",
            resourceId: String(keyId),
            details: updates,
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        res.json(updated);
      } catch (error) {
        log.error("Failed to update sovereign key", { error: String(error) });
        res.status(500).json({ message: "Failed to update sovereign key" });
      }
    },
  );

  app.delete(
    "/api/data-residency/byok/keys/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const keyId = String(req.params.id);

        const [existing] = await db
          .select()
          .from(sovereignKeys)
          .where(and(eq(sovereignKeys.id, keyId), eq(sovereignKeys.orgId, orgId)));

        if (!existing) {
          return res.status(404).json({ message: "Sovereign key not found" });
        }

        const [revoked] = await db
          .update(sovereignKeys)
          .set({ status: "revoked", updatedAt: new Date() })
          .where(and(eq(sovereignKeys.id, keyId), eq(sovereignKeys.orgId, orgId)))
          .returning();

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "sovereign_key_revoked",
            resourceType: "sovereign_key",
            resourceId: String(keyId),
            details: { keyAlias: existing.keyAlias },
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        log.info("Sovereign key revoked", { orgId, keyId });
        res.json(revoked);
      } catch (error) {
        log.error("Failed to revoke sovereign key", { error: String(error) });
        res.status(500).json({ message: "Failed to revoke sovereign key" });
      }
    },
  );

  /* ── Cross-Border Flow Rules ──────────────────────────────────── */

  app.get(
    "/api/data-residency/flow-controls",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const rules = await db
          .select()
          .from(crossBorderFlowRules)
          .where(eq(crossBorderFlowRules.orgId, orgId))
          .orderBy(desc(crossBorderFlowRules.createdAt));

        res.json({ rules });
      } catch (error) {
        log.error("Failed to list flow control rules", { error: String(error) });
        res.status(500).json({ message: "Failed to list flow control rules" });
      }
    },
  );

  app.post(
    "/api/data-residency/flow-controls",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const { name, sourceRegion, destinationRegion, action, dataClassification, requiresApproval, justification } =
          req.body;

        if (!name || typeof name !== "string" || name.trim().length === 0) {
          return replyBadRequest(res, "name is required");
        }
        if (name.length > MAX_RULE_NAME_LENGTH) {
          return replyBadRequest(res, `name must be at most ${MAX_RULE_NAME_LENGTH} characters`);
        }
        if (!sourceRegion || !isValidDataRegion(sourceRegion)) {
          return replyBadRequest(res, `sourceRegion must be one of: ${DATA_REGIONS.join(", ")}`);
        }
        if (!destinationRegion || !isValidDataRegion(destinationRegion)) {
          return replyBadRequest(res, `destinationRegion must be one of: ${DATA_REGIONS.join(", ")}`);
        }
        if (action && !(VALID_FLOW_ACTIONS as readonly string[]).includes(action)) {
          return replyBadRequest(res, `action must be one of: ${VALID_FLOW_ACTIONS.join(", ")}`);
        }
        if (justification && (typeof justification !== "string" || justification.length > MAX_JUSTIFICATION_LENGTH)) {
          return replyBadRequest(res, `justification must be at most ${MAX_JUSTIFICATION_LENGTH} characters`);
        }

        const [created] = await db
          .insert(crossBorderFlowRules)
          .values({
            orgId,
            name: name.trim(),
            sourceRegion,
            destinationRegion,
            action: action || "block",
            dataClassification: dataClassification || "all",
            requiresApproval: requiresApproval !== false,
            justification: justification || null,
            createdBy: user?.id || null,
          })
          .returning();

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "cross_border_rule_created",
            resourceType: "cross_border_flow_rule",
            resourceId: created.id,
            details: { name: created.name, sourceRegion, destinationRegion, ruleAction: action || "block" },
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        res.status(201).json(created);
      } catch (error) {
        log.error("Failed to create flow control rule", { error: String(error) });
        res.status(500).json({ message: "Failed to create flow control rule" });
      }
    },
  );

  app.put(
    "/api/data-residency/flow-controls/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const ruleId = String(req.params.id);
        const { name, action, enabled, requiresApproval, justification, dataClassification } = req.body;

        const [existing] = await db
          .select()
          .from(crossBorderFlowRules)
          .where(and(eq(crossBorderFlowRules.id, ruleId), eq(crossBorderFlowRules.orgId, orgId)));

        if (!existing) {
          return res.status(404).json({ message: "Flow control rule not found" });
        }

        if (name !== undefined && (typeof name !== "string" || name.length > MAX_RULE_NAME_LENGTH)) {
          return replyBadRequest(res, `name must be at most ${MAX_RULE_NAME_LENGTH} characters`);
        }
        if (action !== undefined && !(VALID_FLOW_ACTIONS as readonly string[]).includes(action)) {
          return replyBadRequest(res, `action must be one of: ${VALID_FLOW_ACTIONS.join(", ")}`);
        }

        const updates: Record<string, unknown> = { updatedAt: new Date() };
        if (name !== undefined) updates.name = name.trim();
        if (action !== undefined) updates.action = action;
        if (enabled !== undefined) updates.enabled = Boolean(enabled);
        if (requiresApproval !== undefined) updates.requiresApproval = Boolean(requiresApproval);
        if (justification !== undefined) updates.justification = justification;
        if (dataClassification !== undefined) updates.dataClassification = dataClassification;

        const [updated] = await db
          .update(crossBorderFlowRules)
          .set(updates)
          .where(and(eq(crossBorderFlowRules.id, ruleId), eq(crossBorderFlowRules.orgId, orgId)))
          .returning();

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "cross_border_rule_updated",
            resourceType: "cross_border_flow_rule",
            resourceId: String(ruleId),
            details: updates,
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        res.json(updated);
      } catch (error) {
        log.error("Failed to update flow control rule", { error: String(error) });
        res.status(500).json({ message: "Failed to update flow control rule" });
      }
    },
  );

  app.delete(
    "/api/data-residency/flow-controls/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const user = (req as any).user;
        const ruleId = String(req.params.id);

        const [existing] = await db
          .select()
          .from(crossBorderFlowRules)
          .where(and(eq(crossBorderFlowRules.id, ruleId), eq(crossBorderFlowRules.orgId, orgId)));

        if (!existing) {
          return res.status(404).json({ message: "Flow control rule not found" });
        }

        await db
          .delete(crossBorderFlowRules)
          .where(and(eq(crossBorderFlowRules.id, ruleId), eq(crossBorderFlowRules.orgId, orgId)));

        await storage
          .createAuditLog({
            orgId,
            userId: user?.id,
            userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
            action: "cross_border_rule_deleted",
            resourceType: "cross_border_flow_rule",
            resourceId: String(ruleId),
            details: { name: existing.name },
          })
          .catch((err) => log.error("Failed to create audit log", { error: String(err) }));

        res.json({ message: "Flow control rule deleted", id: ruleId });
      } catch (error) {
        log.error("Failed to delete flow control rule", { error: String(error) });
        res.status(500).json({ message: "Failed to delete flow control rule" });
      }
    },
  );

  /* ── Cross-Border Audit Log ───────────────────────────────────── */

  app.get(
    "/api/data-residency/audit",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const limit = Math.min(Math.max(parseInt(req.query.limit as string, 10) || 50, 1), 200);
        const offset = Math.max(parseInt(req.query.offset as string, 10) || 0, 0);

        const entries = await db
          .select()
          .from(crossBorderFlowAudit)
          .where(eq(crossBorderFlowAudit.orgId, orgId))
          .orderBy(desc(crossBorderFlowAudit.createdAt))
          .limit(limit)
          .offset(offset);

        res.json({ entries, limit, offset });
      } catch (error) {
        log.error("Failed to get cross-border audit log", { error: String(error) });
        res.status(500).json({ message: "Failed to get cross-border audit log" });
      }
    },
  );

  /* ── Regional Deployment Info ──────────────────────────────────── */

  app.get("/api/data-residency/regions", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      const regions = DATA_REGIONS.map((code) => {
        const ep = DATA_REGION_ENDPOINTS[code];
        return {
          code,
          label: ep.label,
          awsRegion: ep.primary,
          gdprApplicable: ep.gdprApplicable,
          regulations: getRegionRegulations(code),
        };
      });

      res.json({ regions });
    } catch (error) {
      log.error("Failed to list regions", { error: String(error) });
      res.status(500).json({ message: "Failed to list regions" });
    }
  });

  /* ── Compliance Summary ────────────────────────────────────────── */

  app.get(
    "/api/data-residency/compliance-summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = (req as any).orgId as string;
        const org = await storage.getOrganization(orgId);
        const region = (org?.dataRegion as DataRegion) || "US";

        const keys = await db
          .select()
          .from(sovereignKeys)
          .where(and(eq(sovereignKeys.orgId, orgId), eq(sovereignKeys.status, "active")));

        const rules = await db
          .select()
          .from(crossBorderFlowRules)
          .where(and(eq(crossBorderFlowRules.orgId, orgId), eq(crossBorderFlowRules.enabled, true)));

        const recentViolations = await db
          .select()
          .from(crossBorderFlowAudit)
          .where(and(eq(crossBorderFlowAudit.orgId, orgId), eq(crossBorderFlowAudit.blocked, true)))
          .orderBy(desc(crossBorderFlowAudit.createdAt))
          .limit(10);

        const flowMode = (org?.crossBorderFlowControls as Record<string, unknown>)?.mode || "permissive";

        res.json({
          region,
          regionLabel: DATA_REGION_ENDPOINTS[region]?.label || "Unknown",
          gdprApplicable: DATA_REGION_ENDPOINTS[region]?.gdprApplicable || false,
          regulations: getRegionRegulations(region),
          byokEnabled: keys.length > 0,
          activeKeyCount: keys.length,
          flowControlMode: flowMode,
          activeRuleCount: rules.length,
          recentViolationCount: recentViolations.length,
          recentViolations,
          complianceScore: calculateComplianceScore(region, keys.length, rules.length, flowMode as string),
        });
      } catch (error) {
        log.error("Failed to get compliance summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get compliance summary" });
      }
    },
  );
}

function getRegionRegulations(region: DataRegion): Array<{ name: string; description: string; mandatory: boolean }> {
  const regulations: Record<DataRegion, Array<{ name: string; description: string; mandatory: boolean }>> = {
    US: [
      { name: "CCPA/CPRA", description: "California Consumer Privacy Act", mandatory: false },
      { name: "SOX", description: "Sarbanes-Oxley Act (financial data)", mandatory: false },
      { name: "HIPAA", description: "Health Insurance Portability and Accountability Act", mandatory: false },
    ],
    EU: [
      { name: "GDPR", description: "General Data Protection Regulation", mandatory: true },
      { name: "NIS2", description: "Network and Information Security Directive", mandatory: true },
      { name: "DORA", description: "Digital Operational Resilience Act (financial)", mandatory: false },
      { name: "Schrems II", description: "EU-US data transfer framework", mandatory: true },
    ],
    APAC: [
      { name: "PIPL", description: "China Personal Information Protection Law", mandatory: true },
      { name: "PDPA", description: "Singapore Personal Data Protection Act", mandatory: true },
      { name: "APPs", description: "Australian Privacy Principles", mandatory: false },
    ],
    ME: [
      { name: "PDPL", description: "Saudi Arabia Personal Data Protection Law", mandatory: true },
      { name: "UAE Data Protection", description: "UAE Federal Data Protection Law", mandatory: true },
      {
        name: "DIFC DP Law",
        description: "Dubai International Financial Centre Data Protection Law",
        mandatory: false,
      },
    ],
  };

  return regulations[region] || [];
}

function calculateComplianceScore(
  region: DataRegion,
  activeKeyCount: number,
  activeRuleCount: number,
  flowMode: string,
): number {
  let score = 40; // Base score for having region set

  if (activeKeyCount > 0) score += 25; // BYOK enabled
  if (activeRuleCount > 0) score += 15; // Flow rules defined
  if (flowMode === "strict" || flowMode === "rule-based") score += 10; // Flow mode not permissive

  const gdpr = DATA_REGION_ENDPOINTS[region]?.gdprApplicable;
  if (gdpr && activeKeyCount > 0 && flowMode !== "permissive") {
    score += 10; // GDPR region with proper controls
  }

  return Math.min(score, 100);
}
