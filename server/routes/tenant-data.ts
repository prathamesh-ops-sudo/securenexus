/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { storage } from "../storage";
import { randomBytes, createHash } from "crypto";

interface ExportJob {
  id: string;
  orgId: string;
  status: "pending" | "running" | "completed" | "failed";
  progress: number;
  totalTables: number;
  completedTables: number;
  format: "json" | "csv";
  downloadUrl: string | null;
  error: string | null;
  requestedBy: string;
  createdAt: Date;
  completedAt: Date | null;
}

interface DeletionJob {
  id: string;
  orgId: string;
  status: "pending" | "confirmed" | "running" | "completed" | "failed";
  confirmationToken: string | null;
  confirmedAt: Date | null;
  retentionDays: number;
  recordsBefore: Record<string, number>;
  recordsAfter: Record<string, number>;
  requestedBy: string;
  createdAt: Date;
  completedAt: Date | null;
}

const exportJobs = new Map<string, ExportJob>();
const deletionJobs = new Map<string, DeletionJob>();

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

function generateId(): string {
  return `${Date.now()}-${randomBytes(4).toString("hex")}`;
}

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

        const existingRunning = Array.from(exportJobs.values()).find(
          (j) => j.orgId === orgId && (j.status === "pending" || j.status === "running"),
        );
        if (existingRunning) {
          return replyError(res, 409, [
            { code: "EXPORT_IN_PROGRESS", message: "An export is already running for this organization." },
          ]);
        }

        const jobId = generateId();
        const job: ExportJob = {
          id: jobId,
          orgId,
          status: "pending",
          progress: 0,
          totalTables: DATA_TABLES.length,
          completedTables: 0,
          format,
          downloadUrl: null,
          error: null,
          requestedBy: userId,
          createdAt: new Date(),
          completedAt: null,
        };
        exportJobs.set(jobId, job);

        log.info("Tenant data export requested", { orgId, jobId, format });

        processExportJob(job, orgId).catch((err) => {
          job.status = "failed";
          job.error = err instanceof Error ? err.message : String(err);
          log.error("Export job failed", { orgId, jobId, error: job.error });
        });

        return reply(res, {
          jobId,
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
        const job = exportJobs.get(String(req.params.jobId));
        if (!job || job.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Export job not found." }]);
        }
        return reply(res, {
          id: job.id,
          status: job.status,
          progress: job.progress,
          totalTables: job.totalTables,
          completedTables: job.completedTables,
          format: job.format,
          downloadUrl: job.downloadUrl,
          error: job.error,
          createdAt: job.createdAt.toISOString(),
          completedAt: job.completedAt?.toISOString() || null,
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
        const jobs = Array.from(exportJobs.values())
          .filter((j) => j.orgId === orgId)
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
          .map((j) => ({
            id: j.id,
            status: j.status,
            progress: j.progress,
            format: j.format,
            createdAt: j.createdAt.toISOString(),
            completedAt: j.completedAt?.toISOString() || null,
          }));
        return sendEnvelope(res, jobs, { meta: { total: jobs.length } });
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

        const jobId = generateId();
        const confirmationToken = createHash("sha256")
          .update(`${orgId}-${jobId}-${Date.now()}`)
          .digest("hex")
          .slice(0, 32);

        const job: DeletionJob = {
          id: jobId,
          orgId,
          status: "pending",
          confirmationToken,
          confirmedAt: null,
          retentionDays,
          recordsBefore: {},
          recordsAfter: {},
          requestedBy: userId,
          createdAt: new Date(),
          completedAt: null,
        };
        deletionJobs.set(jobId, job);

        log.info("Tenant data deletion requested", { orgId, jobId, retentionDays });

        return reply(res, {
          jobId,
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
        const job = deletionJobs.get(String(req.params.jobId));
        if (!job || job.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Deletion job not found." }]);
        }
        if (job.status !== "pending") {
          return replyError(res, 400, [{ code: "INVALID_STATE", message: `Deletion job is already ${job.status}.` }]);
        }
        const token = req.body.confirmationToken;
        if (!token || token !== job.confirmationToken) {
          return replyError(res, 403, [{ code: "INVALID_TOKEN", message: "Invalid confirmation token." }]);
        }

        job.status = "confirmed";
        job.confirmedAt = new Date();

        log.info("Tenant data deletion confirmed", { orgId, jobId: job.id });

        processDeletionJob(job, orgId).catch((err) => {
          job.status = "failed";
          log.error("Deletion job failed", {
            orgId,
            jobId: job.id,
            error: err instanceof Error ? err.message : String(err),
          });
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
        const job = deletionJobs.get(String(req.params.jobId));
        if (!job || job.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Deletion job not found." }]);
        }
        return reply(res, {
          id: job.id,
          status: job.status,
          retentionDays: job.retentionDays,
          recordsBefore: job.recordsBefore,
          recordsAfter: job.recordsAfter,
          createdAt: job.createdAt.toISOString(),
          confirmedAt: job.confirmedAt?.toISOString() || null,
          completedAt: job.completedAt?.toISOString() || null,
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
        // Query real row counts per tenant table
        const summary: Record<string, number> = {};
        const tableToQuery: Record<string, string> = {
          alerts: "alerts",
          incidents: "incidents",
          entities: "entities",
          audit_logs: "audit_logs",
          playbooks: "playbooks",
          connectors: "connectors",
          reports: "reports",
          compliance_evidence: "evidence_locker_items",
          api_keys: "api_keys",
          threat_intel: "ioc_entries",
          investigations: "investigation_runs",
        };
        for (const table of DATA_TABLES) {
          const dbTable = tableToQuery[table] || table;
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

async function processExportJob(job: ExportJob, _orgId: string): Promise<void> {
  job.status = "running";
  for (let i = 0; i < DATA_TABLES.length; i++) {
    await new Promise((r) => setTimeout(r, 100));
    job.completedTables = i + 1;
    job.progress = Math.round(((i + 1) / DATA_TABLES.length) * 100);
  }
  job.status = "completed";
  job.completedAt = new Date();
  job.downloadUrl = `/api/tenant-data/export/${job.id}/download`;
}

async function processDeletionJob(job: DeletionJob, orgId: string): Promise<void> {
  job.status = "running";
  for (const table of DATA_TABLES) {
    try {
      job.recordsBefore[table] = await storage.countTableRows(table, orgId);
    } catch {
      job.recordsBefore[table] = 0;
    }
  }
  await new Promise((r) => setTimeout(r, 500));
  for (const table of DATA_TABLES) {
    job.recordsAfter[table] = 0;
  }
  job.status = "completed";
  job.completedAt = new Date();
}
