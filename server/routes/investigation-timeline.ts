import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

interface TimelineEvent {
  id: string;
  investigationId: string;
  orgId: string;
  timestamp: string;
  type: "alert" | "action" | "evidence" | "hypothesis" | "decision" | "escalation" | "communication" | "artifact";
  title: string;
  description: string;
  actor: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  linkedEntities: string[];
  metadata: Record<string, unknown>;
}

interface InvestigationTimeline {
  investigationId: string;
  orgId: string;
  title: string;
  status: "open" | "in_progress" | "closed";
  events: TimelineEvent[];
  startTime: string;
  endTime: string | null;
  leadAnalyst: string;
  summary: string;
}

const timelines = new Map<string, InvestigationTimeline>();

function genId(): string {
  return `evt-${Date.now()}-${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 8)}`;
}

export function registerInvestigationTimelineRoutes(app: Express): void {
  const log = logger.child("investigation-timeline");

  app.get(
    "/api/investigation-timelines",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const status = req.query.status as string | undefined;
        let results = Array.from(timelines.values()).filter((t) => t.orgId === orgId);
        if (status) results = results.filter((t) => t.status === status);
        results.sort((a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime());

        const summaries = results.map((t) => ({
          investigationId: t.investigationId,
          title: t.title,
          status: t.status,
          eventCount: t.events.length,
          startTime: t.startTime,
          endTime: t.endTime,
          leadAnalyst: t.leadAnalyst,
        }));

        return sendEnvelope(res, summaries, { meta: { total: summaries.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to list timelines." }]);
      }
    },
  );

  app.post(
    "/api/investigation-timelines",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { investigationId, title } = req.body;

        if (!investigationId || !title) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "investigationId and title are required." },
          ]);
        }

        if (timelines.has(investigationId)) {
          return replyError(res, 409, [
            { code: "DUPLICATE", message: "Timeline already exists for this investigation." },
          ]);
        }

        const timeline: InvestigationTimeline = {
          investigationId,
          orgId,
          title,
          status: "open",
          events: [
            {
              id: genId(),
              investigationId,
              orgId,
              timestamp: new Date().toISOString(),
              type: "action",
              title: "Investigation opened",
              description: `Investigation "${title}" created by ${user?.username || "analyst"}`,
              actor: user?.username || "unknown",
              severity: "info",
              source: "system",
              linkedEntities: [],
              metadata: {},
            },
          ],
          startTime: new Date().toISOString(),
          endTime: null,
          leadAnalyst: user?.username || "unknown",
          summary: "",
        };

        timelines.set(investigationId, timeline);
        log.info("Investigation timeline created", { orgId, investigationId });
        return reply(res, timeline, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to create timeline." }]);
      }
    },
  );

  app.get(
    "/api/investigation-timelines/:investigationId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const timeline = timelines.get(req.params.investigationId as string);
        if (!timeline || timeline.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        const from = req.query.from as string | undefined;
        const to = req.query.to as string | undefined;
        let events = timeline.events;

        if (from) events = events.filter((e) => new Date(e.timestamp) >= new Date(from));
        if (to) events = events.filter((e) => new Date(e.timestamp) <= new Date(to));

        return reply(res, { ...timeline, events });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to get timeline." }]);
      }
    },
  );

  app.post(
    "/api/investigation-timelines/:investigationId/events",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const timeline = timelines.get(req.params.investigationId as string);
        if (!timeline || timeline.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        if (timeline.status === "closed") {
          return replyError(res, 400, [
            { code: "TIMELINE_CLOSED", message: "Cannot add events to a closed timeline." },
          ]);
        }

        const user = (req as any).user;
        const { type, title, description, severity, source, linkedEntities, metadata } = req.body;

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
        const validSeverities = ["critical", "high", "medium", "low", "info"];

        const event: TimelineEvent = {
          id: genId(),
          investigationId: req.params.investigationId as string,
          orgId,
          timestamp: new Date().toISOString(),
          type: validTypes.includes(type) ? type : "action",
          title,
          description: description || "",
          actor: user?.username || "unknown",
          severity: validSeverities.includes(severity) ? severity : "info",
          source: source || "manual",
          linkedEntities: Array.isArray(linkedEntities) ? linkedEntities : [],
          metadata: metadata || {},
        };

        timeline.events.push(event);
        return reply(res, event, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to add event." }]);
      }
    },
  );

  app.patch(
    "/api/investigation-timelines/:investigationId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const timeline = timelines.get(req.params.investigationId as string);
        if (!timeline || timeline.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Timeline not found." }]);
        }

        const validStatuses = ["open", "in_progress", "closed"];
        if (req.body.status && validStatuses.includes(req.body.status)) {
          timeline.status = req.body.status;
          if (req.body.status === "closed") {
            timeline.endTime = new Date().toISOString();
          }
        }
        if (req.body.summary) timeline.summary = req.body.summary;

        return reply(res, timeline);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to update timeline." }]);
      }
    },
  );
}
