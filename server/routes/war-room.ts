import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

interface WarRoom {
  id: string;
  orgId: string;
  incidentId: string;
  name: string;
  status: "active" | "standby" | "closed";
  severity: "critical" | "high" | "medium" | "low";
  commander: string;
  participants: Participant[];
  timeline: TimelineEntry[];
  actions: ActionItem[];
  createdAt: string;
  closedAt: string | null;
}

interface Participant {
  userId: string;
  displayName: string;
  role: "commander" | "responder" | "observer";
  joinedAt: string;
}

interface TimelineEntry {
  id: string;
  timestamp: string;
  actor: string;
  type: "message" | "action" | "status_change" | "evidence" | "decision";
  content: string;
  metadata: Record<string, unknown>;
}

interface ActionItem {
  id: string;
  title: string;
  assignee: string;
  status: "pending" | "in_progress" | "completed" | "blocked";
  priority: "critical" | "high" | "medium" | "low";
  createdAt: string;
  completedAt: string | null;
}

const warRooms = new Map<string, WarRoom>();

function genId(): string {
  return `wr-${Date.now()}-${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 8)}`;
}

export function registerWarRoomRoutes(app: Express): void {
  const log = logger.child("war-room");

  app.get(
    "/api/war-rooms",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const status = req.query.status as string | undefined;
        let rooms = Array.from(warRooms.values()).filter((r) => r.orgId === orgId);
        if (status) rooms = rooms.filter((r) => r.status === status);
        rooms.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        return sendEnvelope(res, rooms, { meta: { total: rooms.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to list war rooms." }]);
      }
    },
  );

  app.post(
    "/api/war-rooms",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { incidentId, name, severity } = req.body;

        if (!incidentId || !name) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "incidentId and name are required." }]);
        }

        const validSeverities = ["critical", "high", "medium", "low"];
        const sev = validSeverities.includes(severity) ? severity : "high";

        const room: WarRoom = {
          id: genId(),
          orgId,
          incidentId,
          name,
          status: "active",
          severity: sev,
          commander: user?.username || user?.id || "unknown",
          participants: [
            {
              userId: user?.id || "unknown",
              displayName: user?.username || "Commander",
              role: "commander",
              joinedAt: new Date().toISOString(),
            },
          ],
          timeline: [
            {
              id: `te-${Date.now()}`,
              timestamp: new Date().toISOString(),
              actor: user?.username || "system",
              type: "status_change",
              content: `War room "${name}" opened for incident ${incidentId}`,
              metadata: { severity: sev },
            },
          ],
          actions: [],
          createdAt: new Date().toISOString(),
          closedAt: null,
        };

        warRooms.set(room.id, room);
        log.info("War room created", { orgId, roomId: room.id, incidentId });
        return reply(res, room, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create war room." }]);
      }
    },
  );

  app.get(
    "/api/war-rooms/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = warRooms.get(req.params.id as string);
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        return reply(res, room);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get war room." }]);
      }
    },
  );

  app.post(
    "/api/war-rooms/:id/timeline",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = warRooms.get(req.params.id as string);
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        if (room.status === "closed") {
          return replyError(res, 400, [{ code: "ROOM_CLOSED", message: "Cannot post to a closed war room." }]);
        }

        const user = (req as any).user;
        const { type, content, metadata } = req.body;
        if (!content) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "content is required." }]);
        }

        const validTypes = ["message", "action", "status_change", "evidence", "decision"];
        const entryType = validTypes.includes(type) ? type : "message";

        const entry: TimelineEntry = {
          id: `te-${Date.now()}`,
          timestamp: new Date().toISOString(),
          actor: user?.username || "unknown",
          type: entryType,
          content,
          metadata: metadata || {},
        };

        room.timeline.push(entry);
        return reply(res, entry, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to post timeline entry." }]);
      }
    },
  );

  app.post(
    "/api/war-rooms/:id/actions",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = warRooms.get(req.params.id as string);
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const { title, assignee, priority } = req.body;
        if (!title) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "title is required." }]);
        }

        const validPriorities = ["critical", "high", "medium", "low"];
        const prio = validPriorities.includes(priority) ? priority : "medium";

        const action: ActionItem = {
          id: `act-${Date.now()}`,
          title,
          assignee: assignee || "unassigned",
          status: "pending",
          priority: prio,
          createdAt: new Date().toISOString(),
          completedAt: null,
        };

        room.actions.push(action);
        return reply(res, action, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create action item." }]);
      }
    },
  );

  app.patch(
    "/api/war-rooms/:id/actions/:actionId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = warRooms.get(req.params.id as string);
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const action = room.actions.find((a) => a.id === (req.params.actionId as string));
        if (!action) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Action item not found." }]);
        }

        const validStatuses = ["pending", "in_progress", "completed", "blocked"];
        if (req.body.status && validStatuses.includes(req.body.status)) {
          action.status = req.body.status;
          if (req.body.status === "completed") {
            action.completedAt = new Date().toISOString();
          }
        }
        if (req.body.assignee) action.assignee = req.body.assignee;

        return reply(res, action);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to update action item." }]);
      }
    },
  );

  app.post(
    "/api/war-rooms/:id/join",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = warRooms.get(req.params.id as string);
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const user = (req as any).user;
        const userId = user?.id || "unknown";
        const existing = room.participants.find((p) => p.userId === userId);
        if (existing) {
          return reply(res, { message: "Already a participant.", participant: existing });
        }

        const participant: Participant = {
          userId,
          displayName: user?.username || "Analyst",
          role: "responder",
          joinedAt: new Date().toISOString(),
        };
        room.participants.push(participant);

        room.timeline.push({
          id: `te-${Date.now()}`,
          timestamp: new Date().toISOString(),
          actor: participant.displayName,
          type: "status_change",
          content: `${participant.displayName} joined the war room`,
          metadata: {},
        });

        return reply(res, { message: "Joined war room.", participant });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to join war room." }]);
      }
    },
  );

  app.post(
    "/api/war-rooms/:id/close",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = warRooms.get(req.params.id as string);
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        room.status = "closed";
        room.closedAt = new Date().toISOString();

        const user = (req as any).user;
        room.timeline.push({
          id: `te-${Date.now()}`,
          timestamp: new Date().toISOString(),
          actor: user?.username || "system",
          type: "status_change",
          content: `War room closed. Resolution: ${req.body.resolution || "No resolution provided."}`,
          metadata: { resolution: req.body.resolution || "" },
        });

        log.info("War room closed", { orgId, roomId: room.id });
        return reply(res, room);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to close war room." }]);
      }
    },
  );
}
