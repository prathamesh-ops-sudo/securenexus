import type { Express } from "express";
import { getOrgId, logger, replyError, reply } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { db } from "../db";
import { eq, and, desc, sql } from "drizzle-orm";
import {
  dataLakeRetentionPolicies,
  legalHolds,
  eDiscoveryExports,
  coldStorageInventory,
  tieringJobs,
  dataLakeQueries,
  DATA_LAKE_COMPLIANCE_FRAMEWORKS,
  RETENTION_DATA_TYPES,
  EDISCOVERY_STATUSES,
} from "@shared/schema";
import {
  executeTieringJob,
  getStorageStats,
  isUnderLegalHold,
  purgeExpiredColdData,
  FRAMEWORK_PRESETS,
} from "../storage/tiering-manager";
import { executeFederatedQuery, getQueryHistory } from "../storage/cold-query";
import { uploadFile, getSignedUrl } from "../s3";
import { createHash } from "crypto";
import zlib from "zlib";
import { promisify } from "util";

const log = logger.child("data-lake");
const gzip = promisify(zlib.gzip);

const VALID_DATA_TYPES: ReadonlySet<string> = new Set(RETENTION_DATA_TYPES);
const VALID_FRAMEWORKS: ReadonlySet<string> = new Set(DATA_LAKE_COMPLIANCE_FRAMEWORKS);
const VALID_EXPORT_FORMATS: ReadonlySet<string> = new Set(["json", "csv", "parquet"]);
const VALID_COMPRESSION_FORMATS: ReadonlySet<string> = new Set(["parquet", "gzip_json"]);

export function registerDataLakeRoutes(app: Express): void {
  // ─── Retention Policy CRUD ──────────────────────────────────────────────

  // List retention policies for org
  app.get("/api/data-lake/retention-policies", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policies = await db
        .select()
        .from(dataLakeRetentionPolicies)
        .where(eq(dataLakeRetentionPolicies.orgId, orgId))
        .orderBy(desc(dataLakeRetentionPolicies.createdAt));

      return reply(res, { policies });
    } catch (err) {
      log.error("Failed to list retention policies", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to list retention policies" }]);
    }
  });

  // Create retention policy
  app.post(
    "/api/data-lake/retention-policies",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const {
          name,
          dataType,
          complianceFramework,
          hotRetentionDays,
          warmRetentionDays,
          coldRetentionDays,
          purgeAfterDays,
          compressionFormat,
          filterCriteria,
          priority,
        } = req.body;

        if (!name || typeof name !== "string" || name.length < 1) {
          return replyError(res, 400, [{ code: "INVALID_NAME", message: "name is required" }]);
        }
        if (!VALID_DATA_TYPES.has(dataType)) {
          return replyError(res, 400, [{ code: "INVALID_DATA_TYPE", message: "Invalid dataType" }]);
        }
        if (complianceFramework && !VALID_FRAMEWORKS.has(complianceFramework)) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: "Invalid complianceFramework" }]);
        }
        if (compressionFormat && !VALID_COMPRESSION_FORMATS.has(compressionFormat)) {
          return replyError(res, 400, [
            { code: "INVALID_FORMAT", message: "compressionFormat must be parquet or gzip_json" },
          ]);
        }

        // Apply framework presets if specified
        const preset = complianceFramework ? FRAMEWORK_PRESETS[complianceFramework] : null;

        const [policy] = await db
          .insert(dataLakeRetentionPolicies)
          .values({
            orgId,
            name: String(name).substring(0, 200),
            dataType,
            complianceFramework: complianceFramework || "custom",
            hotRetentionDays: hotRetentionDays ?? preset?.hotDays ?? 90,
            warmRetentionDays: warmRetentionDays ?? preset?.warmDays ?? 365,
            coldRetentionDays: coldRetentionDays ?? preset?.coldDays ?? 2555,
            purgeAfterDays: purgeAfterDays ?? preset?.purgeAfterDays ?? null,
            compressionFormat: compressionFormat || "parquet",
            filterCriteria: filterCriteria || {},
            priority: typeof priority === "number" ? priority : 0,
            createdBy: user?.id || null,
          })
          .returning();

        return reply(res, { policy }, undefined, 201);
      } catch (err) {
        log.error("Failed to create retention policy", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to create retention policy" }]);
      }
    },
  );

  // Update retention policy
  app.patch(
    "/api/data-lake/retention-policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const policyId = String(req.params.id);
        const user = (req as any).user;

        // Verify ownership
        const [existing] = await db
          .select()
          .from(dataLakeRetentionPolicies)
          .where(and(eq(dataLakeRetentionPolicies.id, policyId), eq(dataLakeRetentionPolicies.orgId, orgId)));

        if (!existing) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Policy not found" }]);
        }

        const ALLOWED_FIELDS = [
          "name",
          "hotRetentionDays",
          "warmRetentionDays",
          "coldRetentionDays",
          "purgeAfterDays",
          "compressionFormat",
          "isActive",
          "priority",
          "filterCriteria",
        ] as const;

        const updates: Record<string, unknown> = { updatedBy: user?.id, updatedAt: new Date() };
        for (const field of ALLOWED_FIELDS) {
          if (req.body[field] !== undefined) {
            if (field === "compressionFormat" && !VALID_COMPRESSION_FORMATS.has(req.body[field])) {
              return replyError(res, 400, [{ code: "INVALID_FORMAT", message: "Invalid compressionFormat" }]);
            }
            updates[field] = req.body[field];
          }
        }

        const [updated] = await db
          .update(dataLakeRetentionPolicies)
          .set(updates)
          .where(and(eq(dataLakeRetentionPolicies.id, policyId), eq(dataLakeRetentionPolicies.orgId, orgId)))
          .returning();

        return reply(res, { policy: updated });
      } catch (err) {
        log.error("Failed to update retention policy", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to update retention policy" }]);
      }
    },
  );

  // Delete retention policy
  app.delete(
    "/api/data-lake/retention-policies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const policyId = String(req.params.id);

        const deleted = await db
          .delete(dataLakeRetentionPolicies)
          .where(and(eq(dataLakeRetentionPolicies.id, policyId), eq(dataLakeRetentionPolicies.orgId, orgId)))
          .returning();

        if (deleted.length === 0) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Policy not found" }]);
        }

        return reply(res, { deleted: true });
      } catch (err) {
        log.error("Failed to delete retention policy", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to delete retention policy" }]);
      }
    },
  );

  // Get compliance framework presets
  app.get("/api/data-lake/framework-presets", isAuthenticated, async (_req, res) => {
    try {
      return reply(res, { presets: FRAMEWORK_PRESETS, frameworks: DATA_LAKE_COMPLIANCE_FRAMEWORKS });
    } catch (err) {
      log.error("Failed to get framework presets", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get framework presets" }]);
    }
  });

  // ─── Legal Holds ──────────────────────────────────────────────────────────

  // List legal holds
  app.get("/api/data-lake/legal-holds", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const holds = await db
        .select()
        .from(legalHolds)
        .where(eq(legalHolds.orgId, orgId))
        .orderBy(desc(legalHolds.createdAt));

      return reply(res, { holds });
    } catch (err) {
      log.error("Failed to list legal holds", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to list legal holds" }]);
    }
  });

  // Create legal hold
  app.post(
    "/api/data-lake/legal-holds",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { name, description, holdType, tableScope, reason, caseReference } = req.body;

        if (!name || typeof name !== "string") {
          return replyError(res, 400, [{ code: "INVALID_NAME", message: "name is required" }]);
        }

        const validHoldTypes = ["full", "partial"];
        if (holdType && !validHoldTypes.includes(holdType)) {
          return replyError(res, 400, [{ code: "INVALID_HOLD_TYPE", message: "holdType must be full or partial" }]);
        }

        // Validate table scope
        if (tableScope && Array.isArray(tableScope)) {
          for (const t of tableScope) {
            if (!VALID_DATA_TYPES.has(t) && !["alerts", "incidents", "audit_logs"].includes(t)) {
              return replyError(res, 400, [{ code: "INVALID_SCOPE", message: `Invalid table scope: ${t}` }]);
            }
          }
        }

        const [hold] = await db
          .insert(legalHolds)
          .values({
            orgId,
            name: String(name).substring(0, 200),
            description: description ? String(description).substring(0, 2000) : null,
            holdType: holdType || "full",
            tableScope: Array.isArray(tableScope) ? tableScope : ["alerts", "incidents", "audit_logs"],
            reason: reason ? String(reason).substring(0, 2000) : null,
            caseReference: caseReference ? String(caseReference).substring(0, 200) : null,
            isActive: true,
            activatedBy: user?.id || null,
            activatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : null,
          })
          .returning();

        return reply(res, { hold }, undefined, 201);
      } catch (err) {
        log.error("Failed to create legal hold", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to create legal hold" }]);
      }
    },
  );

  // Deactivate legal hold
  app.post(
    "/api/data-lake/legal-holds/:id/deactivate",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const holdId = String(req.params.id);
        const user = (req as any).user;

        const [existing] = await db
          .select()
          .from(legalHolds)
          .where(and(eq(legalHolds.id, holdId), eq(legalHolds.orgId, orgId)));

        if (!existing) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Legal hold not found" }]);
        }

        const [updated] = await db
          .update(legalHolds)
          .set({
            isActive: false,
            deactivatedBy: user?.id || null,
            deactivatedAt: new Date(),
          })
          .where(and(eq(legalHolds.id, holdId), eq(legalHolds.orgId, orgId)))
          .returning();

        return reply(res, { hold: updated });
      } catch (err) {
        log.error("Failed to deactivate legal hold", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to deactivate legal hold" }]);
      }
    },
  );

  // Reactivate legal hold
  app.post(
    "/api/data-lake/legal-holds/:id/activate",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const holdId = String(req.params.id);
        const user = (req as any).user;

        const [existing] = await db
          .select()
          .from(legalHolds)
          .where(and(eq(legalHolds.id, holdId), eq(legalHolds.orgId, orgId)));

        if (!existing) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Legal hold not found" }]);
        }

        const [updated] = await db
          .update(legalHolds)
          .set({
            isActive: true,
            activatedBy: user?.id || null,
            activatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : null,
            activatedAt: new Date(),
            deactivatedBy: null,
            deactivatedAt: null,
          })
          .where(and(eq(legalHolds.id, holdId), eq(legalHolds.orgId, orgId)))
          .returning();

        return reply(res, { hold: updated });
      } catch (err) {
        log.error("Failed to activate legal hold", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to activate legal hold" }]);
      }
    },
  );

  // ─── Cold Storage & Tiering ───────────────────────────────────────────────

  // Get storage statistics
  app.get("/api/data-lake/storage-stats", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await getStorageStats(orgId);
      return reply(res, stats);
    } catch (err) {
      log.error("Failed to get storage stats", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get storage stats" }]);
    }
  });

  // Trigger tiering job
  app.post("/api/data-lake/tier", isAuthenticated, resolveOrgContext, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { dataType, sourceTier, targetTier, olderThanDays, retentionPolicyId } = req.body;

      if (!VALID_DATA_TYPES.has(dataType)) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPE", message: "Invalid dataType" }]);
      }

      const validTiers = ["hot", "warm", "cold"];
      if (!validTiers.includes(sourceTier) || !validTiers.includes(targetTier)) {
        return replyError(res, 400, [{ code: "INVALID_TIER", message: "Tiers must be hot, warm, or cold" }]);
      }

      if (typeof olderThanDays !== "number" || olderThanDays < 1) {
        return replyError(res, 400, [{ code: "INVALID_DAYS", message: "olderThanDays must be a positive number" }]);
      }

      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - olderThanDays);

      const result = await executeTieringJob(orgId, dataType, sourceTier, targetTier, cutoff, retentionPolicyId);
      return reply(res, result);
    } catch (err) {
      log.error("Tiering job failed", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: String(err) }]);
    }
  });

  // List tiering jobs
  app.get("/api/data-lake/tiering-jobs", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const jobs = await db
        .select()
        .from(tieringJobs)
        .where(eq(tieringJobs.orgId, orgId))
        .orderBy(desc(tieringJobs.createdAt))
        .limit(100);

      return reply(res, { jobs });
    } catch (err) {
      log.error("Failed to list tiering jobs", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to list tiering jobs" }]);
    }
  });

  // List cold storage inventory
  app.get("/api/data-lake/cold-inventory", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const inventory = await db
        .select()
        .from(coldStorageInventory)
        .where(eq(coldStorageInventory.orgId, orgId))
        .orderBy(desc(coldStorageInventory.createdAt))
        .limit(200);

      return reply(res, { inventory });
    } catch (err) {
      log.error("Failed to list cold inventory", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to list cold storage inventory" }]);
    }
  });

  // Purge expired cold data
  app.post(
    "/api/data-lake/purge-expired",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const result = await purgeExpiredColdData(orgId);
        return reply(res, result);
      } catch (err) {
        log.error("Purge expired data failed", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to purge expired data" }]);
      }
    },
  );

  // ─── Federated Query ──────────────────────────────────────────────────────

  // Execute federated query across hot + cold data
  app.post("/api/data-lake/query", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const user = (req as any).user;
      const { queryText, dataTypes, dateRangeStart, dateRangeEnd, limit, includeCold } = req.body;

      if (!queryText || typeof queryText !== "string") {
        return replyError(res, 400, [{ code: "INVALID_QUERY", message: "queryText is required" }]);
      }

      if (!Array.isArray(dataTypes) || dataTypes.length === 0) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPES", message: "dataTypes array is required" }]);
      }

      const validTypes = dataTypes.filter((dt: unknown) => typeof dt === "string" && VALID_DATA_TYPES.has(dt));
      if (validTypes.length === 0) {
        return replyError(res, 400, [{ code: "INVALID_DATA_TYPES", message: "No valid data types specified" }]);
      }

      const result = await executeFederatedQuery({
        orgId,
        queryText: String(queryText).substring(0, 10000),
        dataTypes: validTypes,
        dateRangeStart: dateRangeStart ? new Date(dateRangeStart) : undefined,
        dateRangeEnd: dateRangeEnd ? new Date(dateRangeEnd) : undefined,
        limit: typeof limit === "number" ? limit : 100,
        includeCold: includeCold !== false,
        executedBy: user?.id || null,
      });

      return reply(res, result);
    } catch (err) {
      log.error("Federated query failed", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Federated query failed" }]);
    }
  });

  // Get query history
  app.get("/api/data-lake/query-history", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limitParam = parseInt(String(req.query.limit || "50"), 10);
      const safeLimit = Number.isFinite(limitParam) && limitParam > 0 ? Math.min(limitParam, 200) : 50;
      const history = await getQueryHistory(orgId, safeLimit);
      return reply(res, { queries: history });
    } catch (err) {
      log.error("Failed to get query history", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get query history" }]);
    }
  });

  // ─── eDiscovery ───────────────────────────────────────────────────────────

  // List eDiscovery exports
  app.get("/api/data-lake/ediscovery", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const exports = await db
        .select()
        .from(eDiscoveryExports)
        .where(eq(eDiscoveryExports.orgId, orgId))
        .orderBy(desc(eDiscoveryExports.createdAt))
        .limit(100);

      return reply(res, { exports });
    } catch (err) {
      log.error("Failed to list eDiscovery exports", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to list eDiscovery exports" }]);
    }
  });

  // Create eDiscovery export request
  app.post(
    "/api/data-lake/ediscovery",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const {
          name,
          description,
          legalHoldId,
          dataTypes,
          dateRangeStart,
          dateRangeEnd,
          exportFormat,
          filterCriteria,
          includeMetadata,
          includeChainOfCustody,
        } = req.body;

        if (!name || typeof name !== "string") {
          return replyError(res, 400, [{ code: "INVALID_NAME", message: "name is required" }]);
        }

        if (exportFormat && !VALID_EXPORT_FORMATS.has(exportFormat)) {
          return replyError(res, 400, [
            { code: "INVALID_FORMAT", message: "exportFormat must be json, csv, or parquet" },
          ]);
        }

        // Validate legal hold exists if specified
        if (legalHoldId) {
          const [hold] = await db
            .select()
            .from(legalHolds)
            .where(and(eq(legalHolds.id, legalHoldId), eq(legalHolds.orgId, orgId)));

          if (!hold) {
            return replyError(res, 404, [{ code: "HOLD_NOT_FOUND", message: "Legal hold not found" }]);
          }
        }

        // Validate data types
        const validTypes = Array.isArray(dataTypes)
          ? dataTypes.filter((dt: unknown) => typeof dt === "string" && VALID_DATA_TYPES.has(dt))
          : ["alerts", "incidents", "audit_logs"];

        // Set expiry to 30 days
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        const [exportRecord] = await db
          .insert(eDiscoveryExports)
          .values({
            orgId,
            name: String(name).substring(0, 200),
            description: description ? String(description).substring(0, 2000) : null,
            status: "requested",
            legalHoldId: legalHoldId || null,
            dataTypes: validTypes,
            dateRangeStart: dateRangeStart ? new Date(dateRangeStart) : null,
            dateRangeEnd: dateRangeEnd ? new Date(dateRangeEnd) : null,
            filterCriteria: filterCriteria || {},
            exportFormat: exportFormat || "json",
            includeMetadata: includeMetadata !== false,
            includeChainOfCustody: includeChainOfCustody !== false,
            expiresAt,
            requestedBy: user?.id || null,
            requestedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : null,
          })
          .returning();

        // Trigger async export processing
        processEDiscoveryExport(exportRecord.id, orgId).catch((err) => {
          log.error("eDiscovery export processing failed", { exportId: exportRecord.id, error: String(err) });
        });

        return reply(res, { export: exportRecord }, undefined, 201);
      } catch (err) {
        log.error("Failed to create eDiscovery export", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to create eDiscovery export" }]);
      }
    },
  );

  // Download eDiscovery export
  app.get(
    "/api/data-lake/ediscovery/:id/download",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const exportId = String(req.params.id);

        const [exportRecord] = await db
          .select()
          .from(eDiscoveryExports)
          .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));

        if (!exportRecord) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Export not found" }]);
        }

        if (exportRecord.status !== "ready") {
          return replyError(res, 400, [{ code: "NOT_READY", message: `Export status is ${exportRecord.status}` }]);
        }

        if (!exportRecord.s3Key) {
          return replyError(res, 400, [{ code: "NO_FILE", message: "Export file not available" }]);
        }

        // Check expiry
        if (exportRecord.expiresAt && exportRecord.expiresAt < new Date()) {
          await db
            .update(eDiscoveryExports)
            .set({ status: "expired" })
            .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));
          return replyError(res, 410, [{ code: "EXPIRED", message: "Export has expired" }]);
        }

        // Generate signed URL
        const url = await getSignedUrl(exportRecord.s3Key, 3600);

        // Increment download count
        await db
          .update(eDiscoveryExports)
          .set({
            downloadCount: (exportRecord.downloadCount || 0) + 1,
            status: "downloaded",
          })
          .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));

        return reply(res, {
          downloadUrl: url,
          checksum: exportRecord.checksumSha256,
          format: exportRecord.exportFormat,
          totalRecords: exportRecord.totalRecords,
          expiresAt: exportRecord.expiresAt,
        });
      } catch (err) {
        log.error("Failed to download eDiscovery export", { error: String(err) });
        return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to download export" }]);
      }
    },
  );

  // ─── Dashboard Overview ───────────────────────────────────────────────────

  app.get("/api/data-lake/overview", isAuthenticated, resolveOrgContext, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [stats, policies, holds, recentExports] = await Promise.all([
        getStorageStats(orgId),
        db
          .select()
          .from(dataLakeRetentionPolicies)
          .where(eq(dataLakeRetentionPolicies.orgId, orgId))
          .orderBy(desc(dataLakeRetentionPolicies.createdAt))
          .limit(20),
        db.select().from(legalHolds).where(eq(legalHolds.orgId, orgId)).orderBy(desc(legalHolds.createdAt)).limit(10),
        db
          .select()
          .from(eDiscoveryExports)
          .where(eq(eDiscoveryExports.orgId, orgId))
          .orderBy(desc(eDiscoveryExports.createdAt))
          .limit(10),
      ]);

      return reply(res, {
        storage: stats,
        retentionPolicies: policies,
        legalHolds: holds,
        eDiscoveryExports: recentExports,
        complianceFrameworks: DATA_LAKE_COMPLIANCE_FRAMEWORKS,
        frameworkPresets: FRAMEWORK_PRESETS,
      });
    } catch (err) {
      log.error("Failed to get data lake overview", { error: String(err) });
      return replyError(res, 500, [{ code: "INTERNAL", message: "Failed to get data lake overview" }]);
    }
  });
}

// ─── Async eDiscovery Export Processing ─────────────────────────────────────

async function processEDiscoveryExport(exportId: string, orgId: string): Promise<void> {
  try {
    await db
      .update(eDiscoveryExports)
      .set({ status: "processing" })
      .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));

    const [exportRecord] = await db
      .select()
      .from(eDiscoveryExports)
      .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));

    if (!exportRecord) return;

    const dataTypes = Array.isArray(exportRecord.dataTypes) ? exportRecord.dataTypes : [];
    const validTypes = (dataTypes as string[]).filter((dt) => VALID_DATA_TYPES.has(dt));

    const allRecords: Record<string, unknown>[] = [];

    for (const dataType of validTypes) {
      if (!VALID_DATA_TYPES.has(dataType)) continue;

      // Query hot data using parameterized SQL
      const conditions = [sql`org_id = ${orgId}`];
      if (exportRecord.dateRangeStart) {
        conditions.push(sql`created_at >= ${exportRecord.dateRangeStart}`);
      }
      if (exportRecord.dateRangeEnd) {
        conditions.push(sql`created_at <= ${exportRecord.dateRangeEnd}`);
      }
      const whereClause = sql.join(conditions, sql` AND `);

      const rows = await db.execute(
        sql`SELECT * FROM ${sql.identifier(dataType)}
            WHERE ${whereClause}
            ORDER BY created_at ASC
            LIMIT 50000`,
      );

      const records = (rows as unknown as { rows: Record<string, unknown>[] }).rows || [];
      for (const record of records) {
        allRecords.push({ _dataType: dataType, ...record });
      }
    }

    // Build export package
    const chainOfCustody = exportRecord.includeChainOfCustody
      ? {
          exportId,
          orgId,
          requestedBy: exportRecord.requestedBy,
          requestedAt: exportRecord.createdAt?.toISOString(),
          dataTypes: validTypes,
          dateRange: {
            start: exportRecord.dateRangeStart?.toISOString() || null,
            end: exportRecord.dateRangeEnd?.toISOString() || null,
          },
          totalRecords: allRecords.length,
          exportedAt: new Date().toISOString(),
          integrityMethod: "SHA-256",
        }
      : null;

    const exportPackage = {
      metadata: {
        exportId,
        orgId,
        format: exportRecord.exportFormat,
        totalRecords: allRecords.length,
        exportedAt: new Date().toISOString(),
      },
      chainOfCustody,
      records: allRecords,
    };

    const jsonData = JSON.stringify(exportPackage, null, 2);
    const compressed = await gzip(Buffer.from(jsonData, "utf-8"));
    const checksum = createHash("sha256").update(compressed).digest("hex");

    const s3Key = `data-lake/${orgId}/ediscovery/${exportId}.json.gz`;
    await uploadFile(s3Key, compressed, "application/gzip");

    await db
      .update(eDiscoveryExports)
      .set({
        status: "ready",
        totalRecords: allRecords.length,
        exportSizeBytes: compressed.length,
        s3Key,
        checksumSha256: checksum,
        completedAt: new Date(),
      })
      .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));

    log.info("eDiscovery export completed", { exportId, records: allRecords.length, size: compressed.length });
  } catch (err) {
    log.error("eDiscovery export processing failed", { exportId, error: String(err) });

    await db
      .update(eDiscoveryExports)
      .set({
        status: "failed",
        completedAt: new Date(),
      })
      .where(and(eq(eDiscoveryExports.id, exportId), eq(eDiscoveryExports.orgId, orgId)));
  }
}
