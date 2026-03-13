import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { storage } from "../storage";
import { tryCreateSlackChannel, tryPostSlackMessage } from "../integrations/slack-channel";

const VALID_SEVERITIES = ["critical", "high", "medium", "low"];
const VALID_STATUSES = ["active", "standby", "closed"];
const VALID_ACTION_STATUSES = ["pending", "in_progress", "completed", "blocked"];
const VALID_PRIORITIES = ["critical", "high", "medium", "low"];
const VALID_TIMELINE_TYPES = [
  "message",
  "action",
  "status_change",
  "evidence",
  "decision",
  "hypothesis",
  "handoff",
  "system",
];

/**
 * Assemble a full war room view with participants, timeline, and actions
 * to maintain backwards-compat with the old in-memory response shape.
 */
async function assembleWarRoom(roomId: string) {
  const [participants, timeline, actions] = await Promise.all([
    storage.getWarRoomParticipants(roomId),
    storage.getWarRoomMessages(roomId),
    storage.getWarRoomActionItems(roomId),
  ]);
  return { participants, timeline, actions };
}

export function registerWarRoomRoutes(app: Express): void {
  const log = logger.child("war-room");

  // ─── List War Rooms ───────────────────────────────────────────────────────
  app.get(
    "/api/war-rooms",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const status = req.query.status as string | undefined;
        const validStatus = status && VALID_STATUSES.includes(status) ? status : undefined;
        const rooms = await storage.getWarRooms(orgId, validStatus);

        // Enrich each room with participant count for list view
        const enriched = await Promise.all(
          rooms.map(async (room) => {
            const participants = await storage.getWarRoomParticipants(room.id);
            return {
              ...room,
              participants,
              participantCount: participants.length,
            };
          }),
        );

        return sendEnvelope(res, enriched, { meta: { total: enriched.length } });
      } catch (error: unknown) {
        log.error("Failed to list war rooms", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to list war rooms." }]);
      }
    },
  );

  // ─── Create War Room ──────────────────────────────────────────────────────
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

        if (typeof name !== "string" || name.length > 200) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "name must be a string with max 200 characters." },
          ]);
        }

        const sev = VALID_SEVERITIES.includes(severity) ? severity : "high";
        const commanderId = user?.id || "unknown";
        const commanderName = user?.username || "Commander";

        // Create the war room record
        const room = await storage.createWarRoom({
          orgId,
          incidentId,
          name,
          severity: sev,
          commander: commanderId,
          commanderName,
          status: "active",
        });

        // Add creator as commander participant
        await storage.addWarRoomParticipant({
          warRoomId: room.id,
          userId: commanderId,
          displayName: commanderName,
          role: "commander",
        });

        // Add initial timeline entry
        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: commanderName,
          actorId: commanderId,
          type: "status_change",
          content: `War room "${name}" opened for incident ${incidentId}`,
          metadata: { severity: sev },
        });

        // Try to auto-create a Slack incident channel (non-blocking)
        tryCreateSlackChannel(orgId, room.id, name, incidentId).catch((err) => {
          log.warn("Slack channel creation failed (non-blocking)", { error: err });
        });

        const assembled = await assembleWarRoom(room.id);
        log.info("War room created", { orgId, roomId: room.id, incidentId });
        return reply(res, { ...room, ...assembled }, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to create war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create war room." }]);
      }
    },
  );

  // ─── Get War Room ─────────────────────────────────────────────────────────
  app.get(
    "/api/war-rooms/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        const assembled = await assembleWarRoom(room.id);
        return reply(res, { ...room, ...assembled });
      } catch (error: unknown) {
        log.error("Failed to get war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get war room." }]);
      }
    },
  );

  // ─── Post Timeline Entry ──────────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/timeline",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        if (room.status === "closed") {
          return replyError(res, 400, [{ code: "ROOM_CLOSED", message: "Cannot post to a closed war room." }]);
        }

        const user = (req as any).user;
        const { type, content, metadata } = req.body;
        if (!content || typeof content !== "string") {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "content is required." }]);
        }

        const entryType = VALID_TIMELINE_TYPES.includes(type) ? type : "message";

        const entry = await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "unknown",
          actorId: user?.id,
          type: entryType,
          content,
          metadata: metadata || {},
        });

        // Forward to Slack if channel exists (non-blocking)
        if (room.slackChannelId) {
          tryPostSlackMessage(
            orgId,
            room.slackChannelId,
            `[${entryType.toUpperCase()}] ${user?.username || "unknown"}: ${content}`,
          ).catch(() => {});
        }

        return reply(res, entry, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to post timeline entry", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to post timeline entry." }]);
      }
    },
  );

  // ─── Create Action Item ───────────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/actions",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const { title, assignee, priority } = req.body;
        if (!title || typeof title !== "string") {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "title is required." }]);
        }

        const prio = VALID_PRIORITIES.includes(priority) ? priority : "medium";

        const action = await storage.createWarRoomActionItem({
          warRoomId: room.id,
          orgId,
          title,
          assignee: assignee || "unassigned",
          status: "pending",
          priority: prio,
        });

        return reply(res, action, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to create action item", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create action item." }]);
      }
    },
  );

  // ─── Update Action Item ───────────────────────────────────────────────────
  app.patch(
    "/api/war-rooms/:id/actions/:actionId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const action = await storage.getWarRoomActionItem(p(req.params.actionId));
        if (!action || action.warRoomId !== room.id) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Action item not found." }]);
        }

        const updateData: Record<string, unknown> = {};
        if (req.body.status && VALID_ACTION_STATUSES.includes(req.body.status)) {
          updateData.status = req.body.status;
          if (req.body.status === "completed") {
            updateData.completedAt = new Date();
          }
        }
        if (req.body.assignee && typeof req.body.assignee === "string") {
          updateData.assignee = req.body.assignee;
        }

        const updated = await storage.updateWarRoomActionItem(action.id, updateData);
        return reply(res, updated);
      } catch (error: unknown) {
        log.error("Failed to update action item", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to update action item." }]);
      }
    },
  );

  // ─── Join War Room ────────────────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/join",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const user = (req as any).user;
        const userId = user?.id || "unknown";

        const existing = await storage.getWarRoomParticipantByUser(room.id, userId);
        if (existing) {
          return reply(res, { message: "Already a participant.", participant: existing });
        }

        const displayName = user?.username || "Analyst";
        const participant = await storage.addWarRoomParticipant({
          warRoomId: room.id,
          userId,
          displayName,
          role: "responder",
        });

        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: displayName,
          actorId: userId,
          type: "status_change",
          content: `${displayName} joined the war room`,
          metadata: {},
        });

        return reply(res, { message: "Joined war room.", participant });
      } catch (error: unknown) {
        log.error("Failed to join war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to join war room." }]);
      }
    },
  );

  // ─── Close War Room ───────────────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/close",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        if (room.status === "closed") {
          return replyError(res, 400, [{ code: "ALREADY_CLOSED", message: "War room is already closed." }]);
        }

        const user = (req as any).user;
        const resolution = req.body.resolution || "No resolution provided.";

        const updated = await storage.updateWarRoom(room.id, {
          status: "closed",
          closedAt: new Date(),
          resolution,
        });

        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "system",
          actorId: user?.id,
          type: "status_change",
          content: `War room closed. Resolution: ${resolution}`,
          metadata: { resolution },
        });

        const assembled = await assembleWarRoom(room.id);
        log.info("War room closed", { orgId, roomId: room.id });
        return reply(res, { ...updated, ...assembled });
      } catch (error: unknown) {
        log.error("Failed to close war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to close war room." }]);
      }
    },
  );

  // ─── Command Handoff Protocol ─────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/handoff",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        if (room.status === "closed") {
          return replyError(res, 400, [{ code: "ROOM_CLOSED", message: "Cannot handoff in a closed war room." }]);
        }

        const user = (req as any).user;
        const { toUserId, toUserName, summary, keyFindings, nextSteps } = req.body;

        if (!toUserId || !toUserName || !summary) {
          return replyError(res, 400, [
            {
              code: "VALIDATION_ERROR",
              message: "toUserId, toUserName, and summary are required.",
            },
          ]);
        }

        // Snapshot open action items
        const allActions = await storage.getWarRoomActionItems(room.id);
        const openActions = allActions.filter((a) => a.status === "pending" || a.status === "in_progress");

        const handoff = await storage.createWarRoomHandoff({
          warRoomId: room.id,
          orgId,
          fromUserId: user?.id || "unknown",
          fromUserName: user?.username || "Unknown",
          toUserId,
          toUserName,
          summary,
          openActions: openActions.map((a) => ({
            id: a.id,
            title: a.title,
            status: a.status,
            priority: a.priority,
            assignee: a.assignee,
          })),
          keyFindings: Array.isArray(keyFindings) ? keyFindings : [],
          nextSteps: Array.isArray(nextSteps) ? nextSteps : [],
        });

        // Update commander to new user
        await storage.updateWarRoom(room.id, {
          commander: toUserId,
          commanderName: toUserName,
        });

        // Record timeline entry for handoff
        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "system",
          actorId: user?.id,
          type: "handoff",
          content: `Command handoff: ${user?.username || "Unknown"} -> ${toUserName}. ${summary}`,
          metadata: { handoffId: handoff.id, fromUser: user?.username, toUser: toUserName },
        });

        log.info("War room handoff completed", {
          orgId,
          roomId: room.id,
          from: user?.id,
          to: toUserId,
        });
        return reply(res, handoff, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to create handoff", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create handoff." }]);
      }
    },
  );

  // ─── Acknowledge Handoff ──────────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/handoff/:handoffId/acknowledge",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const handoff = await storage.getWarRoomHandoff(p(req.params.handoffId));
        if (!handoff || handoff.warRoomId !== room.id) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Handoff not found." }]);
        }

        const user = (req as any).user;

        if (handoff.toUserId !== (user?.id || "")) {
          return replyError(res, 403, [
            { code: "FORBIDDEN", message: "Only the receiving user can acknowledge a handoff." },
          ]);
        }

        const updated = await storage.updateWarRoomHandoff(handoff.id, {
          status: "acknowledged",
          acknowledgedAt: new Date(),
        });

        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "system",
          actorId: user?.id,
          type: "handoff",
          content: `${user?.username || "Incoming commander"} acknowledged command handoff`,
          metadata: { handoffId: handoff.id },
        });

        return reply(res, updated);
      } catch (error: unknown) {
        log.error("Failed to acknowledge handoff", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to acknowledge handoff." }]);
      }
    },
  );

  // ─── Get Handoffs ─────────────────────────────────────────────────────────
  app.get(
    "/api/war-rooms/:id/handoffs",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        const handoffs = await storage.getWarRoomHandoffs(room.id);
        return sendEnvelope(res, handoffs, { meta: { total: handoffs.length } });
      } catch (error: unknown) {
        log.error("Failed to get handoffs", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get handoffs." }]);
      }
    },
  );

  // ─── Post-Mortem (PIR) Generation ─────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/post-mortem",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }
        if (room.status !== "closed") {
          return replyError(res, 400, [
            { code: "ROOM_NOT_CLOSED", message: "War room must be closed before generating post-mortem." },
          ]);
        }

        // Gather all war room data for PIR generation
        const [participants, timeline, actions, handoffs] = await Promise.all([
          storage.getWarRoomParticipants(room.id),
          storage.getWarRoomMessages(room.id),
          storage.getWarRoomActionItems(room.id),
          storage.getWarRoomHandoffs(room.id),
        ]);

        // Extract key events and decisions from timeline
        const decisions = timeline.filter((t) => t.type === "decision");
        const evidence = timeline.filter((t) => t.type === "evidence");
        const hypotheses = timeline.filter((t) => t.type === "hypothesis");
        const statusChanges = timeline.filter((t) => t.type === "status_change");

        // Build structured PIR document
        const pir = {
          id: `pir-${room.id}`,
          warRoomId: room.id,
          incidentId: room.incidentId,
          title: `Post-Incident Review: ${room.name}`,
          generatedAt: new Date().toISOString(),
          incidentSummary: {
            name: room.name,
            severity: room.severity,
            commander: room.commanderName,
            openedAt: room.createdAt,
            closedAt: room.closedAt,
            resolution: room.resolution,
            durationMinutes: room.closedAt
              ? Math.round((new Date(room.closedAt).getTime() - new Date(room.createdAt).getTime()) / 60000)
              : null,
          },
          timeline: {
            totalEntries: timeline.length,
            firstEntry: timeline[0]?.createdAt || null,
            lastEntry: timeline[timeline.length - 1]?.createdAt || null,
            keyEvents: statusChanges.map((e) => ({
              timestamp: e.createdAt,
              actor: e.actor,
              content: e.content,
            })),
          },
          decisions: decisions.map((d) => ({
            timestamp: d.createdAt,
            actor: d.actor,
            content: d.content,
            metadata: d.metadata,
          })),
          evidence: evidence.map((e) => ({
            timestamp: e.createdAt,
            actor: e.actor,
            content: e.content,
            metadata: e.metadata,
          })),
          hypotheses: hypotheses.map((h) => ({
            timestamp: h.createdAt,
            actor: h.actor,
            content: h.content,
          })),
          actionItems: {
            total: actions.length,
            completed: actions.filter((a) => a.status === "completed").length,
            pending: actions.filter((a) => a.status === "pending").length,
            blocked: actions.filter((a) => a.status === "blocked").length,
            items: actions.map((a) => ({
              title: a.title,
              assignee: a.assignee,
              status: a.status,
              priority: a.priority,
              createdAt: a.createdAt,
              completedAt: a.completedAt,
            })),
          },
          participants: participants.map((p) => ({
            displayName: p.displayName,
            role: p.role,
            joinedAt: p.joinedAt,
          })),
          handoffs: handoffs.map((h) => ({
            from: h.fromUserName,
            to: h.toUserName,
            summary: h.summary,
            status: h.status,
            createdAt: h.createdAt,
            acknowledgedAt: h.acknowledgedAt,
          })),
          lessonsLearned: {
            whatWentWell: [] as string[],
            whatCouldImprove: [] as string[],
            actionItemsForFuture: [] as string[],
          },
        };

        log.info("Post-mortem generated", { orgId, roomId: room.id, pirId: pir.id });
        return reply(res, pir, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to generate post-mortem", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to generate post-mortem." }]);
      }
    },
  );

  // ─── War Room Replay ──────────────────────────────────────────────────────
  app.get(
    "/api/war-rooms/:id/replay",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        // Get all data in chronological order
        const [participants, timeline, actions, handoffs] = await Promise.all([
          storage.getWarRoomParticipants(room.id),
          storage.getWarRoomMessages(room.id),
          storage.getWarRoomActionItems(room.id),
          storage.getWarRoomHandoffs(room.id),
        ]);

        // Build unified chronological event stream for replay
        interface ReplayEvent {
          timestamp: string | Date;
          type: string;
          category: "message" | "action" | "participant" | "handoff";
          actor: string;
          content: string;
          metadata: Record<string, unknown>;
        }

        const events: ReplayEvent[] = [];

        // Timeline messages
        for (const msg of timeline) {
          events.push({
            timestamp: msg.createdAt,
            type: msg.type,
            category: "message",
            actor: msg.actor,
            content: msg.content,
            metadata: (msg.metadata as Record<string, unknown>) || {},
          });
        }

        // Action item events
        for (const action of actions) {
          events.push({
            timestamp: action.createdAt,
            type: "action_created",
            category: "action",
            actor: action.assignee,
            content: `Action created: ${action.title} [${action.priority}]`,
            metadata: { actionId: action.id, status: action.status },
          });
          if (action.completedAt) {
            events.push({
              timestamp: action.completedAt,
              type: "action_completed",
              category: "action",
              actor: action.assignee,
              content: `Action completed: ${action.title}`,
              metadata: { actionId: action.id },
            });
          }
        }

        // Handoff events
        for (const h of handoffs) {
          events.push({
            timestamp: h.createdAt,
            type: "handoff",
            category: "handoff",
            actor: h.fromUserName,
            content: `Command handoff: ${h.fromUserName} -> ${h.toUserName}`,
            metadata: {
              handoffId: h.id,
              summary: h.summary,
              status: h.status,
            },
          });
        }

        // Sort chronologically
        events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        const replay = {
          warRoom: {
            id: room.id,
            name: room.name,
            incidentId: room.incidentId,
            severity: room.severity,
            status: room.status,
            commander: room.commanderName,
            createdAt: room.createdAt,
            closedAt: room.closedAt,
            resolution: room.resolution,
            durationMinutes:
              room.closedAt && room.createdAt
                ? Math.round((new Date(room.closedAt).getTime() - new Date(room.createdAt).getTime()) / 60000)
                : null,
          },
          participants: participants.map((p) => ({
            displayName: p.displayName,
            role: p.role,
            joinedAt: p.joinedAt,
          })),
          events,
          stats: {
            totalEvents: events.length,
            messageCount: timeline.length,
            actionCount: actions.length,
            handoffCount: handoffs.length,
            participantCount: participants.length,
            decisionsCount: timeline.filter((t) => t.type === "decision").length,
            evidenceCount: timeline.filter((t) => t.type === "evidence").length,
          },
        };

        return reply(res, replay);
      } catch (error: unknown) {
        log.error("Failed to build replay", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to build replay." }]);
      }
    },
  );

  // ─── Investigation Canvas: Hypotheses ─────────────────────────────────────
  app.get(
    "/api/war-rooms/:id/canvas/hypotheses",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const hypotheses = await storage.getWarRoomMessagesByType(room.id, "hypothesis");
        return sendEnvelope(res, hypotheses, { meta: { total: hypotheses.length } });
      } catch (error: unknown) {
        log.error("Failed to get hypotheses", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get hypotheses." }]);
      }
    },
  );

  // ─── Investigation Canvas: Evidence ───────────────────────────────────────
  app.get(
    "/api/war-rooms/:id/canvas/evidence",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const evidence = await storage.getWarRoomMessagesByType(room.id, "evidence");
        return sendEnvelope(res, evidence, { meta: { total: evidence.length } });
      } catch (error: unknown) {
        log.error("Failed to get evidence", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get evidence." }]);
      }
    },
  );

  // ─── Investigation Canvas: Decisions ──────────────────────────────────────
  app.get(
    "/api/war-rooms/:id/canvas/decisions",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const decisions = await storage.getWarRoomMessagesByType(room.id, "decision");
        return sendEnvelope(res, decisions, { meta: { total: decisions.length } });
      } catch (error: unknown) {
        log.error("Failed to get decisions", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get decisions." }]);
      }
    },
  );

  // ─── Leave War Room ───────────────────────────────────────────────────────
  app.post(
    "/api/war-rooms/:id/leave",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const user = (req as any).user;
        const userId = user?.id || "unknown";

        await storage.removeWarRoomParticipant(room.id, userId);

        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "unknown",
          actorId: userId,
          type: "status_change",
          content: `${user?.username || "unknown"} left the war room`,
          metadata: {},
        });

        return reply(res, { message: "Left war room." });
      } catch (error: unknown) {
        log.error("Failed to leave war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to leave war room." }]);
      }
    },
  );

  // ─── Update War Room Status (standby/active toggle) ───────────────────────
  app.patch(
    "/api/war-rooms/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const room = await storage.getWarRoom(p(req.params.id));
        if (!room || room.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "War room not found." }]);
        }

        const allowedFields = ["status", "severity", "name"];
        const updateData: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) {
            if (field === "status" && !VALID_STATUSES.includes(req.body[field])) continue;
            if (field === "severity" && !VALID_SEVERITIES.includes(req.body[field])) continue;
            if (field === "name" && (typeof req.body[field] !== "string" || (req.body[field] as string).length > 200))
              continue;
            updateData[field] = req.body[field];
          }
        }

        if (Object.keys(updateData).length === 0) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "No valid fields to update." }]);
        }

        const updated = await storage.updateWarRoom(room.id, updateData);
        const assembled = await assembleWarRoom(room.id);
        return reply(res, { ...updated, ...assembled });
      } catch (error: unknown) {
        log.error("Failed to update war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to update war room." }]);
      }
    },
  );
}
