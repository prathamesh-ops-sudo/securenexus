import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { storage } from "../storage";
import { tryCreateSlackChannel, tryPostSlackMessage } from "../integrations/slack-channel";
import { db } from "../db";
import { warRoomMessages, warRoomParticipants, warRoomTemplates, warRoomActivityLog, warRooms } from "@shared/schema";
import { eq, and, desc, asc, ilike, or, isNull } from "drizzle-orm";

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
  "playbook_result",
  "call_event",
];

const VALID_CONTENT_FORMATS = ["plain", "markdown"];
const VALID_PARTICIPANT_ROLES = ["commander", "analyst", "observer"];
const VALID_ACTIVITY_ACTIONS = [
  "joined",
  "left",
  "evidence_pinned",
  "evidence_unpinned",
  "status_changed",
  "playbook_triggered",
  "role_changed",
  "call_started",
  "call_ended",
  "archived",
  "template_applied",
];

const BUILT_IN_TEMPLATES = [
  {
    name: "Ransomware Response",
    description: "Pre-configured war room for ransomware incident response with isolation and recovery checklist",
    incidentType: "ransomware",
    severity: "critical",
    channels: ["containment", "forensics", "communications", "recovery"],
    checklist: [
      { title: "Isolate affected systems from network", priority: "critical" },
      { title: "Identify ransomware variant and IOCs", priority: "critical" },
      { title: "Check backup integrity and availability", priority: "high" },
      { title: "Notify legal and compliance teams", priority: "high" },
      { title: "Engage threat intelligence for decryptor availability", priority: "medium" },
      { title: "Document timeline of infection spread", priority: "medium" },
      { title: "Prepare external communication (customers, regulators)", priority: "high" },
      { title: "Plan and execute system restoration", priority: "high" },
    ],
    roleAssignments: [
      { role: "commander", label: "Incident Commander" },
      { role: "analyst", label: "Forensic Analyst" },
      { role: "analyst", label: "Network Engineer" },
      { role: "observer", label: "Legal/Compliance" },
    ],
  },
  {
    name: "Data Breach Response",
    description: "Structured response for data breach incidents — evidence preservation, notification, and remediation",
    incidentType: "data_breach",
    severity: "critical",
    channels: ["investigation", "legal", "notification", "remediation"],
    checklist: [
      { title: "Identify scope of data exposure", priority: "critical" },
      { title: "Preserve forensic evidence", priority: "critical" },
      { title: "Determine affected data subjects", priority: "high" },
      { title: "Engage legal counsel for breach notification", priority: "high" },
      { title: "Assess regulatory reporting obligations", priority: "high" },
      { title: "Patch/close vulnerability exploited", priority: "critical" },
      { title: "Prepare breach notification letters", priority: "medium" },
      { title: "Conduct post-breach security review", priority: "medium" },
    ],
    roleAssignments: [
      { role: "commander", label: "Breach Commander" },
      { role: "analyst", label: "Data Analyst" },
      { role: "analyst", label: "Security Engineer" },
      { role: "observer", label: "Privacy Officer" },
    ],
  },
  {
    name: "Phishing Campaign Response",
    description: "Coordinated response to active phishing campaigns targeting the organization",
    incidentType: "phishing",
    severity: "high",
    channels: ["analysis", "containment", "user-comms"],
    checklist: [
      { title: "Collect and analyze phishing samples", priority: "critical" },
      { title: "Block sender domains/IPs at email gateway", priority: "critical" },
      { title: "Identify users who clicked/submitted credentials", priority: "high" },
      { title: "Force password reset for compromised accounts", priority: "critical" },
      { title: "Check for lateral movement from compromised accounts", priority: "high" },
      { title: "Send org-wide awareness alert", priority: "medium" },
      { title: "Update email filtering rules", priority: "medium" },
    ],
    roleAssignments: [
      { role: "commander", label: "SOC Lead" },
      { role: "analyst", label: "Email Security Analyst" },
      { role: "analyst", label: "Identity Team" },
    ],
  },
  {
    name: "DDoS Attack Response",
    description: "Rapid response template for distributed denial-of-service attacks",
    incidentType: "ddos",
    severity: "high",
    channels: ["mitigation", "monitoring", "communications"],
    checklist: [
      { title: "Enable DDoS mitigation (WAF/CDN scrubbing)", priority: "critical" },
      { title: "Identify attack vector and source IPs", priority: "high" },
      { title: "Scale infrastructure if needed", priority: "high" },
      { title: "Monitor service availability metrics", priority: "medium" },
      { title: "Coordinate with ISP/hosting provider", priority: "medium" },
      { title: "Document attack characteristics for post-mortem", priority: "low" },
    ],
    roleAssignments: [
      { role: "commander", label: "Network Lead" },
      { role: "analyst", label: "Network Engineer" },
      { role: "observer", label: "Service Owner" },
    ],
  },
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
        const { type, content, metadata, contentFormat, parentMessageId, attachments } = req.body;
        if (!content || typeof content !== "string") {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "content is required." }]);
        }

        // 15.7: Role-based access check
        const participant = await storage.getWarRoomParticipantByUser(room.id, user?.id || "unknown");
        if (participant && participant.role === "observer") {
          return replyError(res, 403, [{ code: "FORBIDDEN", message: "Observers cannot post messages." }]);
        }

        const entryType = VALID_TIMELINE_TYPES.includes(type) ? type : "message";
        const format = VALID_CONTENT_FORMATS.includes(contentFormat) ? contentFormat : "plain";

        // 15.2: Validate parent message if threading
        if (parentMessageId) {
          const parentMessages = await db
            .select()
            .from(warRoomMessages)
            .where(and(eq(warRoomMessages.id, parentMessageId), eq(warRoomMessages.warRoomId, room.id)));
          if (parentMessages.length === 0) {
            return replyError(res, 400, [
              { code: "VALIDATION_ERROR", message: "Parent message not found in this war room." },
            ]);
          }
        }

        const entry = await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "unknown",
          actorId: user?.id,
          type: entryType,
          content,
          contentFormat: format,
          parentMessageId: parentMessageId || null,
          attachments: Array.isArray(attachments) ? attachments.slice(0, 10) : [],
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

        // 15.5: Activity log
        await db.insert(warRoomActivityLog).values({
          warRoomId: room.id,
          orgId,
          action: "joined",
          actorId: userId,
          actorName: displayName,
          details: { role: "responder" },
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

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.2: Message Threading — get thread replies for a message
  // ═══════════════════════════════════════════════════════════════════════════
  app.get(
    "/api/war-rooms/:id/messages/:messageId/thread",
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

        const messageId = p(req.params.messageId);
        const replies = await db
          .select()
          .from(warRoomMessages)
          .where(and(eq(warRoomMessages.warRoomId, room.id), eq(warRoomMessages.parentMessageId, messageId)))
          .orderBy(asc(warRoomMessages.createdAt));

        return sendEnvelope(res, replies, { meta: { total: replies.length, parentMessageId: messageId } });
      } catch (error: unknown) {
        log.error("Failed to get message thread", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get message thread." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.3: War Room Templates — CRUD + create-from-template
  // ═══════════════════════════════════════════════════════════════════════════
  app.get(
    "/api/war-room-templates",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const templates = await db
          .select()
          .from(warRoomTemplates)
          .where(or(eq(warRoomTemplates.orgId, orgId), eq(warRoomTemplates.isBuiltIn, true)))
          .orderBy(desc(warRoomTemplates.isBuiltIn), asc(warRoomTemplates.name));

        return sendEnvelope(res, templates, { meta: { total: templates.length } });
      } catch (error: unknown) {
        log.error("Failed to list templates", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to list templates." }]);
      }
    },
  );

  app.post(
    "/api/war-room-templates",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { name, description, incidentType, severity, channels, checklist, roleAssignments } = req.body;

        if (!name || !incidentType) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "name and incidentType are required." }]);
        }

        const [template] = await db
          .insert(warRoomTemplates)
          .values({
            orgId,
            name,
            description: description || null,
            incidentType,
            severity: severity || "high",
            channels: Array.isArray(channels) ? channels : [],
            checklist: Array.isArray(checklist) ? checklist : [],
            roleAssignments: Array.isArray(roleAssignments) ? roleAssignments : [],
            isBuiltIn: false,
            createdBy: user?.id || null,
          })
          .returning();

        return reply(res, template, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to create template", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create template." }]);
      }
    },
  );

  // Seed built-in templates on first request
  app.post(
    "/api/war-room-templates/seed",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Check if built-in templates already exist for this org
        const existing = await db
          .select()
          .from(warRoomTemplates)
          .where(and(eq(warRoomTemplates.orgId, orgId), eq(warRoomTemplates.isBuiltIn, true)));

        if (existing.length > 0) {
          return reply(res, { message: "Built-in templates already seeded.", count: existing.length });
        }

        const seeded = [];
        for (const tmpl of BUILT_IN_TEMPLATES) {
          const [created] = await db
            .insert(warRoomTemplates)
            .values({
              orgId,
              name: tmpl.name,
              description: tmpl.description,
              incidentType: tmpl.incidentType,
              severity: tmpl.severity,
              channels: tmpl.channels,
              checklist: tmpl.checklist,
              roleAssignments: tmpl.roleAssignments,
              isBuiltIn: true,
              createdBy: null,
            })
            .returning();
          seeded.push(created);
        }

        return reply(
          res,
          { message: "Built-in templates seeded.", count: seeded.length, templates: seeded },
          undefined,
          201,
        );
      } catch (error: unknown) {
        log.error("Failed to seed templates", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to seed templates." }]);
      }
    },
  );

  // Create war room from template
  app.post(
    "/api/war-rooms/from-template",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { templateId, incidentId, name } = req.body;

        if (!templateId || !incidentId) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "templateId and incidentId are required." },
          ]);
        }

        const [template] = await db.select().from(warRoomTemplates).where(eq(warRoomTemplates.id, templateId));

        if (!template) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found." }]);
        }

        const roomName = name || `${template.name} — ${incidentId}`;
        const commanderId = user?.id || "unknown";
        const commanderName = user?.username || "Commander";

        // Create room from template
        const room = await storage.createWarRoom({
          orgId,
          incidentId,
          name: roomName,
          severity: template.severity,
          commander: commanderId,
          commanderName,
          status: "active",
          templateId,
        });

        // Add creator as commander
        await storage.addWarRoomParticipant({
          warRoomId: room.id,
          userId: commanderId,
          displayName: commanderName,
          role: "commander",
        });

        // Create checklist items from template
        const checklist = Array.isArray(template.checklist)
          ? (template.checklist as { title: string; priority: string }[])
          : [];
        for (const item of checklist) {
          await storage.createWarRoomActionItem({
            warRoomId: room.id,
            orgId,
            title: item.title,
            assignee: "unassigned",
            status: "pending",
            priority: item.priority || "medium",
          });
        }

        // Add opening message
        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: "system",
          actorId: null,
          type: "system",
          content: `War room created from template "${template.name}". ${checklist.length} action items pre-loaded.`,
          metadata: { templateId, templateName: template.name, incidentType: template.incidentType },
        });

        // 15.5: Activity log
        await db.insert(warRoomActivityLog).values({
          warRoomId: room.id,
          orgId,
          action: "template_applied",
          actorId: commanderId,
          actorName: commanderName,
          details: { templateId, templateName: template.name },
        });

        const assembled = await assembleWarRoom(room.id);
        log.info("War room created from template", { orgId, roomId: room.id, templateId });
        return reply(
          res,
          { ...room, ...assembled, template: { id: template.id, name: template.name } },
          undefined,
          201,
        );
      } catch (error: unknown) {
        log.error("Failed to create war room from template", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to create war room from template." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.4: Audio/Video Call Integration — start call with meeting link
  // ═══════════════════════════════════════════════════════════════════════════
  app.post(
    "/api/war-rooms/:id/start-call",
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
        const { provider, customUrl } = req.body;

        // Generate meeting link based on provider
        let meetingUrl = "";
        let providerName = "custom";

        if (provider === "google_meet") {
          meetingUrl = `https://meet.google.com/new?hs=180&authuser=0`;
          providerName = "Google Meet";
        } else if (provider === "zoom") {
          meetingUrl = `https://zoom.us/start/videomeeting`;
          providerName = "Zoom";
        } else if (provider === "teams") {
          meetingUrl = `https://teams.microsoft.com/l/meetup-join/new`;
          providerName = "Microsoft Teams";
        } else if (customUrl && typeof customUrl === "string") {
          meetingUrl = customUrl;
          providerName = "Custom";
        } else {
          // Default: generate a unique Jitsi Meet room (free, no account needed)
          const roomSlug = room.name
            .toLowerCase()
            .replace(/[^a-z0-9]/g, "-")
            .slice(0, 30);
          meetingUrl = `https://meet.jit.si/securenexus-${roomSlug}-${room.id.slice(0, 8)}`;
          providerName = "Jitsi Meet";
        }

        // Post call event to timeline
        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "unknown",
          actorId: user?.id,
          type: "call_event",
          content: `${user?.username || "Unknown"} started a ${providerName} call: ${meetingUrl}`,
          metadata: { provider: providerName, meetingUrl, action: "started" },
        });

        // 15.5: Activity log
        await db.insert(warRoomActivityLog).values({
          warRoomId: room.id,
          orgId,
          action: "call_started",
          actorId: user?.id || null,
          actorName: user?.username || "unknown",
          details: { provider: providerName, meetingUrl },
        });

        return reply(res, { meetingUrl, provider: providerName, startedBy: user?.username });
      } catch (error: unknown) {
        log.error("Failed to start call", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to start call." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.5: War Room Activity Log — automatic activity tracking
  // ═══════════════════════════════════════════════════════════════════════════
  app.get(
    "/api/war-rooms/:id/activity-log",
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

        const activities = await db
          .select()
          .from(warRoomActivityLog)
          .where(eq(warRoomActivityLog.warRoomId, room.id))
          .orderBy(desc(warRoomActivityLog.createdAt))
          .limit(200);

        return sendEnvelope(res, activities, { meta: { total: activities.length } });
      } catch (error: unknown) {
        log.error("Failed to get activity log", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to get activity log." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.6: War Room Archival, Search, and Export
  // ═══════════════════════════════════════════════════════════════════════════
  app.post(
    "/api/war-rooms/:id/archive",
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
            { code: "VALIDATION_ERROR", message: "Only closed war rooms can be archived." },
          ]);
        }

        const user = (req as any).user;
        const updated = await storage.updateWarRoom(room.id, {
          archivedAt: new Date(),
          archivedBy: user?.id || "unknown",
        });

        // 15.5: Activity log
        await db.insert(warRoomActivityLog).values({
          warRoomId: room.id,
          orgId,
          action: "archived",
          actorId: user?.id || null,
          actorName: user?.username || "unknown",
          details: {},
        });

        log.info("War room archived", { orgId, roomId: room.id });
        return reply(res, updated);
      } catch (error: unknown) {
        log.error("Failed to archive war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to archive war room." }]);
      }
    },
  );

  app.get(
    "/api/war-rooms/archived",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const search = (req.query.q as string) || "";

        const conditions = [eq(warRooms.orgId, orgId), eq(warRooms.status, "closed")];

        const archived = await db
          .select()
          .from(warRooms)
          .where(and(...conditions))
          .orderBy(desc(warRooms.closedAt))
          .limit(100);

        // Filter by search term if provided
        const filtered = search
          ? archived.filter(
              (r) =>
                r.name.toLowerCase().includes(search.toLowerCase()) ||
                (r.resolution && r.resolution.toLowerCase().includes(search.toLowerCase())) ||
                r.incidentId.toLowerCase().includes(search.toLowerCase()),
            )
          : archived;

        return sendEnvelope(res, filtered, { meta: { total: filtered.length, search } });
      } catch (error: unknown) {
        log.error("Failed to search archived war rooms", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to search archived war rooms." }]);
      }
    },
  );

  // Export war room as structured JSON (for PDF/HTML generation on frontend)
  app.get(
    "/api/war-rooms/:id/export",
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

        const [participants, timeline, actions, handoffs] = await Promise.all([
          storage.getWarRoomParticipants(room.id),
          storage.getWarRoomMessages(room.id),
          storage.getWarRoomActionItems(room.id),
          storage.getWarRoomHandoffs(room.id),
        ]);

        const activities = await db
          .select()
          .from(warRoomActivityLog)
          .where(eq(warRoomActivityLog.warRoomId, room.id))
          .orderBy(asc(warRoomActivityLog.createdAt));

        const exportData = {
          warRoom: {
            id: room.id,
            name: room.name,
            incidentId: room.incidentId,
            severity: room.severity,
            status: room.status,
            commander: room.commanderName,
            resolution: room.resolution,
            createdAt: room.createdAt,
            closedAt: room.closedAt,
            archivedAt: room.archivedAt,
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
          timeline: timeline.map((t) => ({
            id: t.id,
            type: t.type,
            actor: t.actor,
            content: t.content,
            contentFormat: t.contentFormat,
            parentMessageId: t.parentMessageId,
            createdAt: t.createdAt,
          })),
          actions: actions.map((a) => ({
            title: a.title,
            assignee: a.assignee,
            status: a.status,
            priority: a.priority,
            createdAt: a.createdAt,
            completedAt: a.completedAt,
          })),
          handoffs: handoffs.map((h) => ({
            from: h.fromUserName,
            to: h.toUserName,
            summary: h.summary,
            status: h.status,
            createdAt: h.createdAt,
          })),
          activityLog: activities.map((a) => ({
            action: a.action,
            actorName: a.actorName,
            details: a.details,
            createdAt: a.createdAt,
          })),
          exportedAt: new Date().toISOString(),
        };

        return reply(res, exportData);
      } catch (error: unknown) {
        log.error("Failed to export war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to export war room." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.7: Role-Based Access — update participant role
  // ═══════════════════════════════════════════════════════════════════════════
  app.patch(
    "/api/war-rooms/:id/participants/:userId/role",
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

        const targetUserId = p(req.params.userId);
        const { role } = req.body;

        if (!role || !VALID_PARTICIPANT_ROLES.includes(role)) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: `role must be one of: ${VALID_PARTICIPANT_ROLES.join(", ")}` },
          ]);
        }

        const participant = await storage.getWarRoomParticipantByUser(room.id, targetUserId);
        if (!participant) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Participant not found in this war room." }]);
        }

        // Update the participant role
        const [updated] = await db
          .update(warRoomParticipants)
          .set({ role })
          .where(eq(warRoomParticipants.id, participant.id))
          .returning();

        // If promoting to commander, update room commander
        if (role === "commander") {
          await storage.updateWarRoom(room.id, {
            commander: targetUserId as string,
            commanderName: participant.displayName,
          });
        }

        const currentUser = (req as any).user;

        // 15.5: Activity log
        await db.insert(warRoomActivityLog).values({
          warRoomId: room.id,
          orgId,
          action: "role_changed",
          actorId: currentUser?.id || null,
          actorName: currentUser?.username || "unknown",
          details: { targetUserId, targetName: participant.displayName, oldRole: participant.role, newRole: role },
        });

        return reply(res, updated);
      } catch (error: unknown) {
        log.error("Failed to update participant role", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to update participant role." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.8: War Room → Playbook Execution
  // ═══════════════════════════════════════════════════════════════════════════
  app.post(
    "/api/war-rooms/:id/run-playbook",
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
          return replyError(res, 400, [{ code: "ROOM_CLOSED", message: "Cannot run playbooks in a closed war room." }]);
        }

        const user = (req as any).user;
        const { playbookId, playbookName, target, parameters } = req.body;

        if (!playbookId || !playbookName) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "playbookId and playbookName are required." },
          ]);
        }

        // 15.7: Observer check
        const participant = await storage.getWarRoomParticipantByUser(room.id, user?.id || "unknown");
        if (participant && participant.role === "observer") {
          return replyError(res, 403, [{ code: "FORBIDDEN", message: "Observers cannot execute playbooks." }]);
        }

        // Post to timeline that playbook was triggered
        await storage.createWarRoomMessage({
          warRoomId: room.id,
          orgId,
          actor: user?.username || "unknown",
          actorId: user?.id,
          type: "playbook_result",
          content: `Triggered playbook "${playbookName}"${target ? ` on target ${target}` : ""}. Execution pending...`,
          metadata: {
            playbookId,
            playbookName,
            target: target || null,
            parameters: parameters || {},
            status: "triggered",
          },
        });

        // 15.5: Activity log
        await db.insert(warRoomActivityLog).values({
          warRoomId: room.id,
          orgId,
          action: "playbook_triggered",
          actorId: user?.id || null,
          actorName: user?.username || "unknown",
          details: { playbookId, playbookName, target },
        });

        return reply(res, {
          message: `Playbook "${playbookName}" triggered from war room`,
          playbookId,
          warRoomId: room.id,
          triggeredBy: user?.username,
        });
      } catch (error: unknown) {
        log.error("Failed to run playbook from war room", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to run playbook from war room." }]);
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 15.9: Post-Incident Review Auto-Generation (enhanced)
  // ═══════════════════════════════════════════════════════════════════════════
  app.post(
    "/api/war-rooms/:id/generate-review",
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
            { code: "ROOM_NOT_CLOSED", message: "War room must be closed to generate review." },
          ]);
        }

        // Gather comprehensive data
        const [participants, timeline, actions, handoffs] = await Promise.all([
          storage.getWarRoomParticipants(room.id),
          storage.getWarRoomMessages(room.id),
          storage.getWarRoomActionItems(room.id),
          storage.getWarRoomHandoffs(room.id),
        ]);

        const activities = await db
          .select()
          .from(warRoomActivityLog)
          .where(eq(warRoomActivityLog.warRoomId, room.id))
          .orderBy(asc(warRoomActivityLog.createdAt));

        // Extract key events
        const decisions = timeline.filter((t) => t.type === "decision");
        const evidence = timeline.filter((t) => t.type === "evidence");
        const hypotheses = timeline.filter((t) => t.type === "hypothesis");
        const statusChanges = timeline.filter((t) => t.type === "status_change");
        const playbookResults = timeline.filter((t) => t.type === "playbook_result");
        const messages = timeline.filter((t) => t.type === "message");

        // Auto-generate structured PIR from chat history
        const durationMinutes = room.closedAt
          ? Math.round((new Date(room.closedAt).getTime() - new Date(room.createdAt).getTime()) / 60000)
          : null;

        // Derive MTTD and MTTR estimates from timeline
        const firstEvidenceTime = evidence.length > 0 ? new Date(evidence[0].createdAt).getTime() : null;
        const roomOpenTime = new Date(room.createdAt).getTime();
        const roomCloseTime = room.closedAt ? new Date(room.closedAt).getTime() : null;

        const review = {
          id: `pir-${room.id}-${Date.now()}`,
          warRoomId: room.id,
          incidentId: room.incidentId,
          title: `Post-Incident Review: ${room.name}`,
          generatedAt: new Date().toISOString(),
          autoGenerated: true,

          executiveSummary: {
            incidentName: room.name,
            severity: room.severity,
            commander: room.commanderName,
            duration: durationMinutes ? `${durationMinutes} minutes` : "Ongoing",
            resolution: room.resolution || "Not specified",
            totalParticipants: participants.length,
            totalMessages: messages.length,
            totalDecisions: decisions.length,
            totalActions: actions.length,
            actionsCompleted: actions.filter((a) => a.status === "completed").length,
          },

          timeline: {
            openedAt: room.createdAt,
            closedAt: room.closedAt,
            durationMinutes,
            totalEntries: timeline.length,
            keyEvents: statusChanges.map((e) => ({
              timestamp: e.createdAt,
              actor: e.actor,
              content: e.content,
            })),
            mttrEstimateMinutes: durationMinutes,
            mttdEstimateMinutes:
              firstEvidenceTime && roomOpenTime ? Math.round((firstEvidenceTime - roomOpenTime) / 60000) : null,
          },

          decisions: decisions.map((d) => ({
            timestamp: d.createdAt,
            actor: d.actor,
            content: d.content,
          })),

          evidence: evidence.map((e) => ({
            timestamp: e.createdAt,
            actor: e.actor,
            content: e.content,
          })),

          hypotheses: hypotheses.map((h) => ({
            timestamp: h.createdAt,
            actor: h.actor,
            content: h.content,
          })),

          playbooksExecuted: playbookResults.map((p) => ({
            timestamp: p.createdAt,
            actor: p.actor,
            content: p.content,
            metadata: p.metadata,
          })),

          actionItems: {
            total: actions.length,
            completed: actions.filter((a) => a.status === "completed").length,
            pending: actions.filter((a) => a.status === "pending").length,
            blocked: actions.filter((a) => a.status === "blocked").length,
            inProgress: actions.filter((a) => a.status === "in_progress").length,
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

          activityLog: activities.map((a) => ({
            action: a.action,
            actorName: a.actorName,
            details: a.details,
            createdAt: a.createdAt,
          })),

          lessonsLearned: {
            whatWentWell: decisions.length > 0 ? [`${decisions.length} key decisions documented during incident`] : [],
            whatCouldImprove:
              actions.filter((a) => a.status === "blocked").length > 0
                ? [`${actions.filter((a) => a.status === "blocked").length} action items were blocked during response`]
                : [],
            recommendations: [
              ...(durationMinutes && durationMinutes > 120
                ? ["Consider pre-staged response playbooks to reduce response time"]
                : []),
              ...(handoffs.length > 2 ? ["Multiple handoffs occurred — consider longer shift rotations"] : []),
              ...(playbookResults.length === 0
                ? ["No playbooks were used — consider automating common response actions"]
                : []),
            ],
          },
        };

        log.info("Post-incident review auto-generated", { orgId, roomId: room.id });
        return reply(res, review, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to generate post-incident review", { error });
        return replyError(res, 500, [{ code: "WAR_ROOM_ERROR", message: "Failed to generate post-incident review." }]);
      }
    },
  );
}
