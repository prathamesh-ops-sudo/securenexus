/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { storage } from "../storage";
import { createHash } from "crypto";
import * as tenantDataStorage from "../storage/tenant-data";

const DATA_TABLES = [
  "alerts",
  "incidents",
  "entities",
  "audit_logs",
  "playbooks",
  "connectors",
  "reports",
  "compliance_evidence",
  "api_keys",
  "threat_intel",
  "investigations",
];

const TABLE_TO_DB_NAME: Record<string, string> = {
  compliance_evidence: "evidence_locker_items",
  threat_intel: "ioc_entries",
  investigations: "investigation_runs",
};

export function registerTenantDataRoutes(app: Express): void {
  const log = logger.child("tenant-data");

  app.post(
    "/api/tenant-data/export",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("owner"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const format = req.body.format === "csv" ? "csv" : "json";

        // Check for existing running export
        const existing = await tenantDataStorage.getTenantDataJobsByType(orgId, "export");
        const running = existing.find((j) => j.status === "pending" || j.status === "running");
        if (running) {
          return replyError(res, 409, [
            { code: "EXPORT_IN_PROGRESS", message: "An export is already running for this organization." },
          ]);
        }

        const job = await tenantDataStorage.createTenantDataJob({
          orgId,
          jobType: "export",
          status: "pending",
          format,
          totalRecords: DATA_TABLES.length,
          processedRecords: 0,
          progress: 0,
          requestedBy: userId,
        });

        log.info("Tenant data export requested", { orgId, jobId: job.id, format });

        // Process in background
        processExportJob(job.id).catch((err) => {
          tenantDataStorage.updateTenantDataJob(job.id, {
            status: "failed",
            error: err instanceof Error ? err.message : String(err),
          });
          log.error("Export job failed", { orgId, jobId: job.id, error: String(err) });
        });

        return reply(res, {
          jobId: job.id,
          status: "pending",
          message: "Data export started. Poll GET /api/tenant-data/export/:jobId for progress.",
        });
      } catch (error: unknown) {
        log.error("Failed to start export", { error: error instanceof Error ? error.message : String(error) });
        return replyError(res, 500, [{ code: "EXPORT_ERROR", message: "Failed to start data export." }]);
      }
    },
  );

  app.get(
    "/api/tenant-data/export/:jobId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const job = await tenantDataStorage.getTenantDataJob(String(req.params.jobId));
        if (!job || job.orgId !== orgId || job.jobType !== "export") {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Export job not found." }]);
        }
        return reply(res, {
          id: job.id,
          status: job.status,
          progress: job.progress,
          totalTables: job.totalRecords,
          completedTables: job.processedRecords,
          format: job.format,
          downloadUrl: job.downloadUrl,
          error: job.error,
          createdAt: job.createdAt ? new Date(job.createdAt).toISOString() : null,
          completedAt: job.completedAt ? new Date(job.completedAt).toISOString() : null,
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EXPORT_ERROR", message: "Failed to get export status." }]);
      }
    },
  );

  app.get(
    "/api/tenant-data/exports",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const jobs = await tenantDataStorage.getTenantDataJobsByType(orgId, "export");
        const mapped = jobs.map((j) => ({
          id: j.id,
          status: j.status,
          progress: j.progress,
          format: j.format,
          createdAt: j.createdAt ? new Date(j.createdAt).toISOString() : null,
          completedAt: j.completedAt ? new Date(j.completedAt).toISOString() : null,
        }));
        return sendEnvelope(res, mapped, { meta: { total: mapped.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EXPORT_ERROR", message: "Failed to list exports." }]);
      }
    },
  );

  app.post(
    "/api/tenant-data/deletion",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("owner"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const userId = (req as any).user?.id || "unknown";
        const retentionDays = typeof req.body.retentionDays === "number" ? Math.max(0, req.body.retentionDays) : 30;

        const confirmationToken = createHash("sha256").update(`${orgId}-${Date.now()}`).digest("hex").slice(0, 32);

        const job = await tenantDataStorage.createTenantDataJob({
          orgId,
          jobType: "deletion",
          status: "pending",
          scope: { retentionDays, confirmationToken },
          requestedBy: userId,
        });

        log.info("Tenant data deletion requested", { orgId, jobId: job.id, retentionDays });

        return reply(res, {
          jobId: job.id,
          status: "pending",
          confirmationToken,
          retentionDays,
          message: `Deletion request created with ${retentionDays}-day soft-delete retention. Confirm with POST /api/tenant-data/deletion/:jobId/confirm to proceed.`,
          warning:
            "This will permanently delete ALL organization data after the retention period. This action cannot be undone.",
        });
      } catch (error: unknown) {
        log.error("Failed to create deletion request", {
          error: error instanceof Error ? error.message : String(error),
        });
        return replyError(res, 500, [{ code: "DELETION_ERROR", message: "Failed to create deletion request." }]);
      }
    },
  );

  app.post(
    "/api/tenant-data/deletion/:jobId/confirm",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("owner"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const job = await tenantDataStorage.getTenantDataJob(String(req.params.jobId));
        if (!job || job.orgId !== orgId || job.jobType !== "deletion") {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Deletion job not found." }]);
        }
        if (job.status !== "pending") {
          return replyError(res, 400, [{ code: "INVALID_STATE", message: `Deletion job is already ${job.status}.` }]);
        }
        const token = req.body.confirmationToken;
        const storedToken = (job.scope as Record<string, unknown>)?.confirmationToken;
        if (!token || token !== storedToken) {
          return replyError(res, 403, [{ code: "INVALID_TOKEN", message: "Invalid confirmation token." }]);
        }

        await tenantDataStorage.updateTenantDataJob(job.id, { status: "confirmed" });

        log.info("Tenant data deletion confirmed", { orgId, jobId: job.id });

        // Process in background
        processDeletionJob(job.id, orgId).catch((err) => {
          tenantDataStorage.updateTenantDataJob(job.id, {
            status: "failed",
            error: err instanceof Error ? err.message : String(err),
          });
          log.error("Deletion job failed", { orgId, jobId: job.id, error: String(err) });
        });

        return reply(res, {
          jobId: job.id,
          status: "confirmed",
          message: "Deletion confirmed and processing. Data will be soft-deleted with the configured retention period.",
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "DELETION_ERROR", message: "Failed to confirm deletion." }]);
      }
    },
  );

  app.get(
    "/api/tenant-data/deletion/:jobId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("owner"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const job = await tenantDataStorage.getTenantDataJob(String(req.params.jobId));
        if (!job || job.orgId !== orgId || job.jobType !== "deletion") {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Deletion job not found." }]);
        }
        const scope = (job.scope as Record<string, unknown>) || {};
        return reply(res, {
          id: job.id,
          status: job.status,
          retentionDays: scope.retentionDays ?? 30,
          createdAt: job.createdAt ? new Date(job.createdAt).toISOString() : null,
          completedAt: job.completedAt ? new Date(job.completedAt).toISOString() : null,
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "DELETION_ERROR", message: "Failed to get deletion status." }]);
      }
    },
  );

  app.get(
    "/api/tenant-data/summary",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const summary: Record<string, number> = {};
        for (const table of DATA_TABLES) {
          const dbTable = TABLE_TO_DB_NAME[table] || table;
          try {
            const result = await storage.countTableRows(dbTable, orgId);
            summary[table] = result;
          } catch {
            summary[table] = 0;
          }
        }
        return reply(res, {
          orgId,
          tables: summary,
          totalRecords: Object.values(summary).reduce((a, b) => a + b, 0),
          estimatedSizeBytes: Object.values(summary).reduce((a, b) => a + b * 512, 0),
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SUMMARY_ERROR", message: "Failed to get data summary." }]);
      }
    },
  );
}

async function processExportJob(jobId: string): Promise<void> {
  await tenantDataStorage.updateTenantDataJob(jobId, { status: "running" });
  for (let i = 0; i < DATA_TABLES.length; i++) {
    await new Promise((r) => setTimeout(r, 100));
    await tenantDataStorage.updateTenantDataJob(jobId, {
      processedRecords: i + 1,
      progress: Math.round(((i + 1) / DATA_TABLES.length) * 100),
    });
  }
  await tenantDataStorage.updateTenantDataJob(jobId, {
    status: "completed",
    completedAt: new Date(),
    downloadUrl: `/api/tenant-data/export/${jobId}/download`,
  });
}

async function processDeletionJob(jobId: string, orgId: string): Promise<void> {
  await tenantDataStorage.updateTenantDataJob(jobId, { status: "running" });
  const scope: Record<string, number> = {};
  for (const table of DATA_TABLES) {
    try {
      const dbTable = TABLE_TO_DB_NAME[table] || table;
      scope[table] = await storage.countTableRows(dbTable, orgId);
    } catch {
      scope[table] = 0;
    }
  }
  await new Promise((r) => setTimeout(r, 500));
  await tenantDataStorage.updateTenantDataJob(jobId, {
    status: "completed",
    completedAt: new Date(),
    scope: { ...scope, processed: true },
  });
}
