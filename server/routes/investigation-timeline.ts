/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";

export function registerInvestigationTimelineRoutes(app: Express): void {
  const log = logger.child("investigation-timeline");

  // List all investigation timelines (runs) for the org
  app.get(
    "/api/investigation-timelines",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const runs = await storage.getInvestigationRuns(orgId);

        const status = req.query.status as string | undefined;
        let filtered = runs;
        if (status) filtered = runs.filter((r) => r.status === status);

        const summaries = filtered.map((r) => ({
          investigationId: r.id,
          title: r.summary || `Investigation ${r.id}`,
          status: r.status,
          startTime: r.createdAt,
          endTime: r.completedAt,
          leadAnalyst: r.triggeredBy,
          incidentId: r.incidentId,
        }));

        return sendEnvelope(res, summaries, { meta: { total: summaries.length } });
      } catch (error: unknown) {
        log.error("Failed to list timelines", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to list timelines." }]);
      }
    },
  );

  // Create a new investigation timeline
  app.post(
    "/api/investigation-timelines",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { incidentId, title } = req.body;

        if (!title) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "title is required." }]);
        }

        const run = await storage.createInvestigationRun({
          orgId,
          incidentId: incidentId || null,
          triggeredBy: user?.username || user?.id || "unknown",
          triggerSource: "manual",
          status: "running",
          summary: title,
        });

        // Create initial step
        await storage.createInvestigationStep({
          runId: run.id,
          stepType: "action",
          stepOrder: 1,
          title: "Investigation opened",
          description: `Investigation "${title}" created by ${user?.username || "analyst"}`,
          status: "completed",
        });

        log.info("Investigation timeline created", { orgId, runId: run.id });
        return reply(res, run, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to create timeline", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to create timeline." }]);
      }
    },
  );

  // Get a single investigation timeline with its events (steps)
  app.get(
    "/api/investigation-timelines/:investigationId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const run = await storage.getInvestigationRun(String(req.params.investigationId));
        if (!run || run.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        const steps = await storage.getInvestigationSteps(run.id);

        return reply(res, {
          investigationId: run.id,
          title: run.summary || `Investigation ${run.id}`,
          status: run.status,
          startTime: run.createdAt,
          endTime: run.completedAt,
          leadAnalyst: run.triggeredBy,
          incidentId: run.incidentId,
          events: steps.map((s) => ({
            id: s.id,
            type: s.stepType,
            title: s.title,
            description: s.description,
            status: s.status,
            order: s.stepOrder,
            result: s.result,
            artifacts: s.artifacts,
            duration: s.duration,
            createdAt: s.createdAt,
          })),
        });
      } catch (error: unknown) {
        log.error("Failed to get timeline", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to get timeline." }]);
      }
    },
  );

  // Add event to timeline
  app.post(
    "/api/investigation-timelines/:investigationId/events",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const run = await storage.getInvestigationRun(String(req.params.investigationId));
        if (!run || run.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        if (run.status === "completed" || run.status === "failed") {
          return replyError(res, 400, [
            { code: "TIMELINE_CLOSED", message: "Cannot add events to a completed timeline." },
          ]);
        }

        const { type, title, description, metadata } = req.body;

        if (!title) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "title is required." }]);
        }

        const validTypes = [
          "alert",
          "action",
          "evidence",
          "hypothesis",
          "decision",
          "escalation",
          "communication",
          "artifact",
        ];

        // Get next step order
        const existingSteps = await storage.getInvestigationSteps(run.id);
        const nextOrder = existingSteps.length + 1;

        const step = await storage.createInvestigationStep({
          runId: run.id,
          stepType: validTypes.includes(type) ? type : "action",
          stepOrder: nextOrder,
          title,
          description: description || "",
          status: "completed",
          result: metadata ? metadata : null,
        });

        return reply(res, step, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to add event", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to add event." }]);
      }
    },
  );

  // Update timeline status
  app.patch(
    "/api/investigation-timelines/:investigationId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const run = await storage.getInvestigationRun(String(req.params.investigationId));
        if (!run || run.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        const updates: Record<string, unknown> = {};
        const validStatuses = ["queued", "running", "completed", "failed"];
        if (req.body.status && validStatuses.includes(req.body.status)) {
          updates.status = req.body.status;
          if (req.body.status === "completed" || req.body.status === "failed") {
            updates.completedAt = new Date();
          }
        }
        if (req.body.summary) updates.summary = req.body.summary;

        const updated = await storage.updateInvestigationRun(String(req.params.investigationId), updates);
        return reply(res, updated);
      } catch (error: unknown) {
        log.error("Failed to update timeline", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to update timeline." }]);
      }
    },
  );

  // Multi-incident timeline overlay
  app.post(
    "/api/investigation-timelines/overlay",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { investigationIds } = req.body;
        if (!Array.isArray(investigationIds) || investigationIds.length < 2) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "At least 2 investigationIds required." }]);
        }

        const overlayTimelines = [];
        for (const id of investigationIds) {
          const run = await storage.getInvestigationRun(id);
          if (run && run.orgId === orgId) {
            const steps = await storage.getInvestigationSteps(run.id);
            overlayTimelines.push({
              investigationId: run.id,
              title: run.summary || `Investigation ${run.id}`,
              status: run.status,
              events: steps.map((s) => ({
                id: s.id,
                type: s.stepType,
                title: s.title,
                description: s.description,
                createdAt: s.createdAt,
                timelineTitle: run.summary || `Investigation ${run.id}`,
              })),
            });
          }
        }

        if (overlayTimelines.length === 0) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "No matching timelines found." }]);
        }

        const allEvents = overlayTimelines.flatMap((t) => t.events);
        allEvents.sort(
          (a, b) => new Date(String(a.createdAt ?? "")).getTime() - new Date(String(b.createdAt ?? "")).getTime(),
        );
        const timeRange = {
          start: allEvents.length > 0 ? allEvents[0].createdAt : null,
          end: allEvents.length > 0 ? allEvents[allEvents.length - 1].createdAt : null,
        };

        return reply(res, { timelines: overlayTimelines, timeRange, totalEvents: allEvents.length });
      } catch (error: unknown) {
        log.error("Failed to build overlay", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to build overlay." }]);
      }
    },
  );

  // Export timeline
  app.get(
    "/api/investigation-timelines/:investigationId/export",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const run = await storage.getInvestigationRun(String(req.params.investigationId));
        if (!run || run.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        const steps = await storage.getInvestigationSteps(run.id);
        const format = (req.query.format as string) || "json";

        if (format === "csv") {
          const header = "Order,Type,Title,Description,Status,CreatedAt\n";
          const rows = steps
            .map(
              (s) =>
                `${s.stepOrder},"${s.stepType}","${(s.title || "").replace(/"/g, '""')}","${(s.description || "").replace(/"/g, '""')}","${s.status}","${s.createdAt}"`,
            )
            .join("\n");
          res.setHeader("Content-Type", "text/csv");
          res.setHeader("Content-Disposition", `attachment; filename="timeline-${run.id}.csv"`);
          return res.send(header + rows);
        }

        // Default JSON export
        const exportData = {
          investigationId: run.id,
          title: run.summary,
          status: run.status,
          startTime: run.createdAt,
          endTime: run.completedAt,
          leadAnalyst: run.triggeredBy,
          events: steps,
          exportedAt: new Date().toISOString(),
        };
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Disposition", `attachment; filename="timeline-${run.id}.json"`);
        return res.json(exportData);
      } catch (error: unknown) {
        log.error("Failed to export timeline", { error });
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to export timeline." }]);
      }
    },
  );
}
