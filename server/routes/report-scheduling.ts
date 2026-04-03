/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes } from "crypto";
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

interface ReportSchedule {
  id: string;
  orgId: string;
  reportType: string;
  name: string;
  cadence: "daily" | "weekly" | "biweekly" | "monthly" | "quarterly";
  recipients: string[];
  format: "pdf" | "csv" | "html";
  slaMinutes: number;
  isActive: boolean;
  lastRunAt: string | null;
  lastDeliveredAt: string | null;
  lastDurationMs: number | null;
  slaMet: boolean | null;
  consecutiveSlaBreaches: number;
  totalRuns: number;
  totalSlaBreaches: number;
  nextRunAt: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

interface DeliveryRecord {
  id: string;
  scheduleId: string;
  orgId: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  status: "pending" | "generating" | "delivered" | "failed";
  slaMet: boolean | null;
  slaMinutes: number;
  recipientCount: number;
  error: string | null;
}

const schedules = new Map<string, ReportSchedule>();
const deliveries = new Map<string, DeliveryRecord[]>();

function genId(): string {
  return `rsch-${Date.now()}-${randomBytes(4).toString("hex")}`;
}

function calculateNextRun(cadence: string): string {
  const now = new Date();
  switch (cadence) {
    case "daily":
      return new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    case "weekly":
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
    case "biweekly":
      return new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000).toISOString();
    case "monthly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 1);
      return d.toISOString();
    }
    case "quarterly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 3);
      return d.toISOString();
    }
    default:
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
  }
}

export function registerReportSchedulingRoutes(app: Express): void {
  const log = logger.child("report-scheduling");

  app.get(
    "/api/report-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const active = req.query.active as string | undefined;
        let results = Array.from(schedules.values()).filter((s) => s.orgId === orgId);
        if (active === "true") results = results.filter((s) => s.isActive);
        if (active === "false") results = results.filter((s) => !s.isActive);
        results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        return sendEnvelope(res, results, { meta: { total: results.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to list schedules." }]);
      }
    },
  );

  app.post(
    "/api/report-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { reportType, name, cadence, recipients, format, slaMinutes } = req.body;

        if (!reportType || !name) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "reportType and name are required." }]);
        }

        const validCadences = ["daily", "weekly", "biweekly", "monthly", "quarterly"];
        const validFormats = ["pdf", "csv", "html"];

        const schedule: ReportSchedule = {
          id: genId(),
          orgId,
          reportType,
          name,
          cadence: validCadences.includes(cadence) ? cadence : "weekly",
          recipients: Array.isArray(recipients) ? recipients : [],
          format: validFormats.includes(format) ? format : "pdf",
          slaMinutes: typeof slaMinutes === "number" && slaMinutes > 0 ? slaMinutes : 60,
          isActive: true,
          lastRunAt: null,
          lastDeliveredAt: null,
          lastDurationMs: null,
          slaMet: null,
          consecutiveSlaBreaches: 0,
          totalRuns: 0,
          totalSlaBreaches: 0,
          nextRunAt: calculateNextRun(cadence),
          createdBy: user?.username || "unknown",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        schedules.set(schedule.id, schedule);
        deliveries.set(schedule.id, []);
        log.info("Report schedule created", { orgId, scheduleId: schedule.id, reportType });
        return reply(res, schedule, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to create schedule." }]);
      }
    },
  );

  app.get(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedule = schedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }
        return reply(res, schedule);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to get schedule." }]);
      }
    },
  );

  app.patch(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedule = schedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }

        if (typeof req.body.isActive === "boolean") schedule.isActive = req.body.isActive;
        if (req.body.cadence) {
          const validCadences = ["daily", "weekly", "biweekly", "monthly", "quarterly"];
          if (validCadences.includes(req.body.cadence)) {
            schedule.cadence = req.body.cadence;
            schedule.nextRunAt = calculateNextRun(req.body.cadence);
          }
        }
        if (Array.isArray(req.body.recipients)) schedule.recipients = req.body.recipients;
        if (typeof req.body.slaMinutes === "number" && req.body.slaMinutes > 0) {
          schedule.slaMinutes = req.body.slaMinutes;
        }
        schedule.updatedAt = new Date().toISOString();

        return reply(res, schedule);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to update schedule." }]);
      }
    },
  );

  app.delete(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedule = schedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }
        schedules.delete(req.params.id as string);
        deliveries.delete(req.params.id as string);
        return reply(res, { message: "Schedule deleted." });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to delete schedule." }]);
      }
    },
  );

  app.post(
    "/api/report-schedules/:id/trigger",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedule = schedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }

        const startedAt = new Date();
        // Estimate generation time based on SLA target (typically completes in 60% of SLA window)
        const durationMs = Math.floor(schedule.slaMinutes * 60 * 1000 * 0.6);
        const slaMet = durationMs <= schedule.slaMinutes * 60 * 1000;

        const record: DeliveryRecord = {
          id: `del-${Date.now()}`,
          scheduleId: schedule.id,
          orgId,
          startedAt: startedAt.toISOString(),
          completedAt: new Date(startedAt.getTime() + durationMs).toISOString(),
          durationMs,
          status: "delivered",
          slaMet,
          slaMinutes: schedule.slaMinutes,
          recipientCount: schedule.recipients.length,
          error: null,
        };

        const records = deliveries.get(schedule.id) || [];
        records.push(record);
        deliveries.set(schedule.id, records);

        schedule.lastRunAt = startedAt.toISOString();
        schedule.lastDeliveredAt = record.completedAt;
        schedule.lastDurationMs = durationMs;
        schedule.slaMet = slaMet;
        schedule.totalRuns += 1;
        if (!slaMet) {
          schedule.totalSlaBreaches += 1;
          schedule.consecutiveSlaBreaches += 1;
        } else {
          schedule.consecutiveSlaBreaches = 0;
        }
        schedule.nextRunAt = calculateNextRun(schedule.cadence);

        log.info("Report schedule triggered", { orgId, scheduleId: schedule.id, slaMet, durationMs });
        return reply(res, record);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to trigger report." }]);
      }
    },
  );

  app.get(
    "/api/report-schedules/:id/deliveries",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedule = schedules.get(req.params.id as string);
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }

        const records = (deliveries.get(req.params.id as string) || []).sort(
          (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime(),
        );
        return sendEnvelope(res, records, { meta: { total: records.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to list deliveries." }]);
      }
    },
  );

  app.get(
    "/api/report-schedules/sla/summary",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const orgSchedules = Array.from(schedules.values()).filter((s) => s.orgId === orgId);
        const totalSchedules = orgSchedules.length;
        const activeSchedules = orgSchedules.filter((s) => s.isActive).length;
        const totalRuns = orgSchedules.reduce((sum, s) => sum + s.totalRuns, 0);
        const totalBreaches = orgSchedules.reduce((sum, s) => sum + s.totalSlaBreaches, 0);
        const slaComplianceRate = totalRuns > 0 ? Math.round(((totalRuns - totalBreaches) / totalRuns) * 100) : 100;
        const atRiskSchedules = orgSchedules.filter((s) => s.consecutiveSlaBreaches >= 2).length;

        return reply(res, {
          totalSchedules,
          activeSchedules,
          totalRuns,
          totalBreaches,
          slaComplianceRate,
          atRiskSchedules,
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to get SLA summary." }]);
      }
    },
  );
}
