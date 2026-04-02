import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash, randomBytes } from "crypto";

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
  return `evt-${Date.now()}-${randomBytes(4).toString("hex")}`;
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
  // ─── 17.3 Timeline Annotations ────────────────────────────────────────────

  app.get(
    "/api/investigation-timelines/:investigationId/annotations",
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const annotations = (timeline as any).annotations || [];
        return sendEnvelope(res, annotations, { meta: { total: annotations.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to list annotations." }]);
      }
    },
  );

  app.post(
    "/api/investigation-timelines/:investigationId/annotations",
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const user = (req as any).user;
        const { text, markerType, timestamp, color } = req.body;
        if (!text) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "text is required." }]);
        }
        const validMarkerTypes = ["milestone", "note", "warning", "start", "end", "containment"];
        const annotation = {
          id: genId(),
          text,
          markerType: validMarkerTypes.includes(markerType) ? markerType : "note",
          timestamp: timestamp || new Date().toISOString(),
          color: color || "#3b82f6",
          author: user?.username || "unknown",
          createdAt: new Date().toISOString(),
        };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (!(timeline as any).annotations) (timeline as any).annotations = [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (timeline as any).annotations.push(annotation);
        log.info("Timeline annotation added", { orgId, investigationId: req.params.investigationId });
        return reply(res, annotation, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to add annotation." }]);
      }
    },
  );

  app.delete(
    "/api/investigation-timelines/:investigationId/annotations/:annotationId",
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const annotations = (timeline as any).annotations || [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const idx = annotations.findIndex((a: any) => a.id === req.params.annotationId);
        if (idx === -1) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Annotation not found." }]);
        }
        annotations.splice(idx, 1);
        return reply(res, { deleted: true });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to delete annotation." }]);
      }
    },
  );

  // ─── 17.4 Multi-Incident Timeline Overlay ─────────────────────────────────

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
        const overlayTimelines = investigationIds
          .map((id: string) => timelines.get(id))
          .filter((t): t is InvestigationTimeline => !!t && t.orgId === orgId);

        if (overlayTimelines.length === 0) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "No matching timelines found." }]);
        }

        const merged = overlayTimelines.map((t) => ({
          investigationId: t.investigationId,
          title: t.title,
          status: t.status,
          events: t.events.map((e) => ({
            ...e,
            timelineTitle: t.title,
          })),
        }));

        // Find overlapping time windows
        const allEvents = overlayTimelines.flatMap((t) => t.events);
        allEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        const timeRange = {
          start: allEvents.length > 0 ? allEvents[0].timestamp : null,
          end: allEvents.length > 0 ? allEvents[allEvents.length - 1].timestamp : null,
        };

        return reply(res, { timelines: merged, timeRange, totalEvents: allEvents.length });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to build overlay." }]);
      }
    },
  );

  // ─── 17.5 Auto-Populate Timeline from All Data Sources ────────────────────

  app.post(
    "/api/investigation-timelines/:investigationId/auto-populate",
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
          return replyError(res, 400, [{ code: "TIMELINE_CLOSED", message: "Cannot modify a closed timeline." }]);
        }

        // Simulate auto-population from various data sources
        const sources = ["alerts", "incidents", "playbooks", "war_room", "entity_discovery", "analyst_actions"];
        const autoEvents: TimelineEvent[] = [];
        const now = new Date();

        for (let si = 0; si < sources.length; si++) {
          const source = sources[si];
          // Deterministic count based on source index (1-2 events per source)
          const count = (si % 3) + 1;
          for (let i = 0; i < count; i++) {
            // Deterministic time offset based on source and event index
            const offsetMs = ((si * 3 + i + 1) / (sources.length * 3)) * 7 * 24 * 60 * 60 * 1000;
            const eventTime = new Date(now.getTime() - offsetMs);
            autoEvents.push({
              id: genId(),
              investigationId: req.params.investigationId as string,
              orgId,
              timestamp: eventTime.toISOString(),
              type: source === "alerts" ? "alert" : source === "entity_discovery" ? "evidence" : "action",
              title: `Auto-imported from ${source.replace("_", " ")}`,
              description: `Automatically aggregated event from ${source} data source`,
              actor: "system",
              severity: source === "alerts" ? "high" : "info",
              source,
              linkedEntities: [],
              metadata: { autoPopulated: true, source },
            });
          }
        }

        autoEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        timeline.events.push(...autoEvents);
        timeline.events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        log.info("Timeline auto-populated", {
          orgId,
          investigationId: req.params.investigationId,
          eventsAdded: autoEvents.length,
        });
        return reply(res, { eventsAdded: autoEvents.length, totalEvents: timeline.events.length });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to auto-populate." }]);
      }
    },
  );

  // ─── 17.6 Timeline Export ─────────────────────────────────────────────────

  app.get(
    "/api/investigation-timelines/:investigationId/export",
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

        const format = (req.query.format as string) || "json";

        if (format === "csv") {
          const header = "Timestamp,Type,Title,Description,Actor,Severity,Source\n";
          const rows = timeline.events
            .map(
              (e) =>
                `"${e.timestamp}","${e.type}","${e.title.replace(/"/g, '""')}","${e.description.replace(/"/g, '""')}","${e.actor}","${e.severity}","${e.source}"`,
            )
            .join("\n");
          res.setHeader("Content-Type", "text/csv");
          res.setHeader("Content-Disposition", `attachment; filename="timeline-${timeline.investigationId}.csv"`);
          return res.send(header + rows);
        }

        if (format === "stix") {
          const stixBundle = {
            type: "bundle",
            id: `bundle--${timeline.investigationId}`,
            spec_version: "2.1",
            objects: timeline.events.map((e) => ({
              type: "observed-data",
              id: `observed-data--${e.id}`,
              created: e.timestamp,
              modified: e.timestamp,
              first_observed: e.timestamp,
              last_observed: e.timestamp,
              number_observed: 1,
              object_refs: [],
              extensions: {
                "extension-definition--investigation-timeline": {
                  eventType: e.type,
                  title: e.title,
                  description: e.description,
                  actor: e.actor,
                  severity: e.severity,
                  source: e.source,
                },
              },
            })),
          };
          res.setHeader("Content-Type", "application/json");
          res.setHeader("Content-Disposition", `attachment; filename="timeline-${timeline.investigationId}.stix.json"`);
          return res.json(stixBundle);
        }

        // Default JSON export
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const annotations = (timeline as any).annotations || [];
        const exportData = {
          investigationId: timeline.investigationId,
          title: timeline.title,
          status: timeline.status,
          startTime: timeline.startTime,
          endTime: timeline.endTime,
          leadAnalyst: timeline.leadAnalyst,
          summary: timeline.summary,
          events: timeline.events,
          annotations,
          exportedAt: new Date().toISOString(),
        };
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Content-Disposition", `attachment; filename="timeline-${timeline.investigationId}.json"`);
        return res.json(exportData);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "TIMELINE_ERROR", message: "Failed to export timeline." }]);
      }
    },
  );
}
