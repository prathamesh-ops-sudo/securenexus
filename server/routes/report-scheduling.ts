/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";

function calculateNextRun(cadence: string): Date {
  const now = new Date();
  switch (cadence) {
    case "daily":
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case "weekly":
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case "biweekly":
      return new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    case "monthly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 1);
      return d;
    }
    case "quarterly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 3);
      return d;
    }
    default:
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
}

export function registerReportSchedulingRoutes(app: Express): void {
  const log = logger.child("report-scheduling");

  // List all report schedules for the org
  app.get(
    "/api/report-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const results = await storage.getReportSchedules(orgId);
        const active = req.query.active as string | undefined;
        let filtered = results;
        if (active === "true") filtered = results.filter((s) => s.enabled);
        if (active === "false") filtered = results.filter((s) => !s.enabled);
        return sendEnvelope(res, filtered, { meta: { total: filtered.length } });
      } catch (error: unknown) {
        log.error("Failed to list schedules", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to list schedules." }]);
      }
    },
  );

  // Create a new report schedule
  app.post(
    "/api/report-schedules",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { templateId, name, cadence, deliveryTargets, timezone } = req.body;

        if (!name) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "name is required." }]);
        }

        const validCadences = ["daily", "weekly", "biweekly", "monthly", "quarterly"];
        const resolvedCadence = validCadences.includes(cadence) ? cadence : "weekly";

        const schedule = await storage.createReportSchedule({
          orgId,
          templateId: templateId || "default",
          name,
          cadence: resolvedCadence,
          timezone: timezone || "UTC",
          deliveryTargets: Array.isArray(deliveryTargets) ? JSON.stringify(deliveryTargets) : deliveryTargets || null,
          enabled: true,
          createdBy: user?.id || user?.username || null,
        });

        log.info("Report schedule created", { orgId, scheduleId: schedule.id });
        return reply(res, schedule, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to create schedule", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to create schedule." }]);
      }
    },
  );

  // Get a single report schedule
  app.get(
    "/api/report-schedules/sla/summary",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedules = await storage.getReportSchedules(orgId);
        const runs = await storage.getReportRuns(orgId, undefined, 1000);

        const totalSchedules = schedules.length;
        const activeSchedules = schedules.filter((s) => s.enabled).length;
        const totalRuns = runs.length;
        const completedRuns = runs.filter((r) => r.status === "completed");
        const failedRuns = runs.filter((r) => r.status === "failed");

        return reply(res, {
          totalSchedules,
          activeSchedules,
          totalRuns,
          completedRuns: completedRuns.length,
          failedRuns: failedRuns.length,
          successRate: totalRuns > 0 ? Math.round((completedRuns.length / totalRuns) * 100) : null,
          available: totalRuns > 0,
          reason: totalRuns > 0 ? null : "No scheduled report runs in the selected window.",
        });
      } catch (error: unknown) {
        log.error("Failed to get SLA summary", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to get SLA summary." }]);
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
        const schedule = await storage.getReportSchedule(String(req.params.id));
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }
        return reply(res, schedule);
      } catch (error: unknown) {
        log.error("Failed to get schedule", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to get schedule." }]);
      }
    },
  );

  // Update a report schedule
  app.patch(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getReportSchedule(String(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }

        const updates: Record<string, unknown> = {};
        if (typeof req.body.enabled === "boolean") updates.enabled = req.body.enabled;
        if (req.body.name) updates.name = req.body.name;
        if (req.body.cadence) {
          const validCadences = ["daily", "weekly", "biweekly", "monthly", "quarterly"];
          if (validCadences.includes(req.body.cadence)) {
            updates.cadence = req.body.cadence;
            updates.nextRunAt = calculateNextRun(req.body.cadence);
          }
        }
        if (req.body.deliveryTargets) {
          updates.deliveryTargets = Array.isArray(req.body.deliveryTargets)
            ? JSON.stringify(req.body.deliveryTargets)
            : req.body.deliveryTargets;
        }
        if (req.body.timezone) updates.timezone = req.body.timezone;

        const updated = await storage.updateReportSchedule(String(req.params.id), updates);
        return reply(res, updated);
      } catch (error: unknown) {
        log.error("Failed to update schedule", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to update schedule." }]);
      }
    },
  );

  // Delete a report schedule
  app.delete(
    "/api/report-schedules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getReportSchedule(String(req.params.id));
        if (!existing || existing.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }
        await storage.deleteReportSchedule(String(req.params.id));
        return reply(res, { message: "Schedule deleted." });
      } catch (error: unknown) {
        log.error("Failed to delete schedule", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to delete schedule." }]);
      }
    },
  );

  // Trigger a report schedule manually
  app.post(
    "/api/report-schedules/:id/trigger",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const schedule = await storage.getReportSchedule(String(req.params.id));
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }

        // Create a report run record
        const run = await storage.createReportRun({
          orgId,
          templateId: schedule.templateId,
          scheduleId: schedule.id,
          status: "queued",
          format: "pdf",
          createdBy: user?.id || user?.username || null,
        });

        // Update schedule last run and next run
        await storage.updateReportSchedule(schedule.id, {
          lastRunAt: new Date(),
          nextRunAt: calculateNextRun(schedule.cadence),
        });

        log.info("Report schedule triggered", { orgId, scheduleId: schedule.id, runId: run.id });
        return reply(res, run);
      } catch (error: unknown) {
        log.error("Failed to trigger report", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to trigger report." }]);
      }
    },
  );

  // Get delivery/run history for a schedule
  app.get(
    "/api/report-schedules/:id/deliveries",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const schedule = await storage.getReportSchedule(String(req.params.id));
        if (!schedule || schedule.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Schedule not found." }]);
        }

        const runs = await storage.getReportRuns(orgId, String(schedule.templateId));
        const scheduleRuns = runs.filter((r) => r.scheduleId === schedule.id);
        return sendEnvelope(res, scheduleRuns, { meta: { total: scheduleRuns.length } });
      } catch (error: unknown) {
        log.error("Failed to list deliveries", { error });
        return replyError(res, 500, [{ code: "SCHEDULE_ERROR", message: "Failed to list deliveries." }]);
      }
    },
  );
}
