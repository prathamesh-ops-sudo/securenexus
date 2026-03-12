/**
 * Agent Remote Response API
 *
 * Lets analysts push remediation commands (kill process, isolate host, block IP, etc.)
 * directly to sensor agents without needing CrowdStrike or any third-party EDR.
 *
 * Analyst-facing routes (user session auth):
 *   POST   /api/native/response/actions           — Create a response action
 *   GET    /api/native/response/actions           — List all actions for org
 *   GET    /api/native/response/actions/:id       — Get action detail
 *   POST   /api/native/response/actions/:id/approve — Approve a high-risk action (admin)
 *   POST   /api/native/response/actions/:id/cancel  — Cancel a pending action
 *   DELETE /api/native/response/actions/:id       — Soft-delete (cancel) an action
 *   GET    /api/native/response/stats             — Action counts and recent completions
 *
 * Agent-facing routes (sensor token auth, no user session):
 *   GET    /api/native/response/pending           — Agent polls for dispatched commands
 *   POST   /api/native/response/actions/:id/complete — Agent reports completion result
 *
 * Action param shapes (for reference):
 *   kill_process:      { pid?: number, processName?: string }
 *   isolate_host:      { allowedIps?: string[] }          — cuts all network except management
 *   block_ip:          { ip: string, direction: "inbound"|"outbound"|"both", duration?: number } — via iptables/Windows Firewall
 *   quarantine_file:   { filePath: string }
 *   disable_user:      { username: string }
 *   run_script:        { script: string, interpreter?: "bash"|"powershell"|"cmd" }
 *   collect_forensics: { targets: string[] }              — collect memory/process/network snapshot
 */

import type { Express } from "express";
import { eq, desc, and, sql, inArray, or } from "drizzle-orm";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { requireOrgId, requireMinRole, resolveOrgContext } from "../rbac";
import { db } from "../db";
import { logger, getOrgId, sendEnvelope } from "./shared";
import { broadcastEvent } from "../event-bus";
import {
  agentResponseActions,
  nativeSensors,
} from "../../shared/schema";

const log = logger.child("agent-response-actions");

// ============================================================================
// Constants
// ============================================================================

/**
 * Actions that automatically require approval before being dispatched to the agent.
 * These carry significant risk: host isolation, file deletion, account lockout, or
 * arbitrary script execution.
 */
export const HIGH_RISK_ACTIONS = new Set([
  "isolate_host",
  "delete_file",
  "disable_user",
  "run_script",
]);

/** How long an agent has to acknowledge and complete a dispatched action. */
const ACTION_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

// ============================================================================
// Validation schemas
// ============================================================================

const createActionSchema = z.object({
  sensorId: z.string().min(1),
  actionType: z.enum([
    "kill_process",
    "isolate_host",
    "block_ip",
    "quarantine_file",
    "delete_file",
    "disable_user",
    "run_script",
    "collect_forensics",
  ]),
  params: z.record(z.unknown()).default({}),
  triggeredByAlertId: z.string().optional(),
  triggeredByIncidentId: z.string().optional(),
  notes: z.string().max(2000).optional(),
});

const completeActionSchema = z.object({
  token: z.string().min(1),
  sensorId: z.string().min(1),
  resultCode: z.number().int(),
  resultOutput: z.string().optional(),
  errorMessage: z.string().optional(),
});

const listActionsQuerySchema = z.object({
  sensorId: z.string().optional(),
  status: z.string().optional(),
  actionType: z.string().optional(),
});

// ============================================================================
// Helpers
// ============================================================================

/**
 * Verify that a sensor token is valid and active, and that the given sensorId
 * belongs to the same sensor record identified by that token.
 */
async function authenticateSensor(token: string, sensorId: string) {
  const rows = await db
    .select()
    .from(nativeSensors)
    .where(eq(nativeSensors.registrationToken, token))
    .limit(1);

  const sensor = rows[0] ?? null;
  if (!sensor) return null;
  if (!sensor.isActive) return null;
  if (sensor.id !== sensorId) return null;
  return sensor;
}

// ============================================================================
// Route registration
// ============================================================================

export function registerAgentResponseActionsRoutes(app: Express): void {

  // --------------------------------------------------------------------------
  // CREATE ACTION
  // --------------------------------------------------------------------------

  /**
   * Create a new response action targeting a specific sensor.
   *
   * High-risk actions (isolate_host, delete_file, disable_user, run_script)
   * are placed in "pending" status with requiresApproval=true and must be
   * approved by an admin before dispatch. All other actions are automatically
   * set to "dispatched" so the agent can pick them up on its next poll.
   */
  app.post(
    "/api/native/response/actions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const body = createActionSchema.parse(req.body);

        // Verify the target sensor belongs to this org
        const [sensor] = await db
          .select()
          .from(nativeSensors)
          .where(
            and(
              eq(nativeSensors.id, body.sensorId),
              eq(nativeSensors.orgId, orgId),
            ),
          )
          .limit(1);

        if (!sensor) {
          return res.status(404).json({ error: "Sensor not found or not accessible" });
        }
        if (!sensor.isActive) {
          return res.status(400).json({ error: "Sensor is decommissioned and cannot receive actions" });
        }

        const requiresApproval = HIGH_RISK_ACTIONS.has(body.actionType);
        // Auto-approve: if approval is not required, dispatch immediately.
        const initialStatus = requiresApproval ? "pending" : "dispatched";
        const timeoutAt = new Date(Date.now() + ACTION_TIMEOUT_MS);

        const [action] = await db
          .insert(agentResponseActions)
          .values({
            orgId,
            sensorId: body.sensorId,
            actionType: body.actionType,
            params: body.params,
            triggeredBy: "manual",
            triggeredByUserId: user?.id ?? null,
            triggeredByAlertId: body.triggeredByAlertId ?? null,
            triggeredByIncidentId: body.triggeredByIncidentId ?? null,
            status: initialStatus,
            requiresApproval,
            timeoutAt,
            dispatchedAt: requiresApproval ? null : new Date(),
          })
          .returning();

        log.info("Response action created", {
          actionId: action.id,
          actionType: body.actionType,
          sensorId: body.sensorId,
          orgId,
          requiresApproval,
          status: initialStatus,
        });

        return sendEnvelope(res, action, { status: 201 });
      } catch (err: any) {
        if (err instanceof z.ZodError) {
          return res.status(400).json({ error: "Validation failed", details: err.errors });
        }
        log.error("Failed to create response action", { error: String(err) });
        return res.status(500).json({ error: "Failed to create response action" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // LIST ACTIONS
  // --------------------------------------------------------------------------

  /**
   * List all response actions for the authenticated org.
   * Optional query filters: sensorId, status, actionType.
   * Each result includes the sensor hostname for display purposes.
   */
  app.get(
    "/api/native/response/actions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const query = listActionsQuerySchema.parse(req.query);

        const conditions = [eq(agentResponseActions.orgId, orgId)];

        if (query.sensorId) {
          conditions.push(eq(agentResponseActions.sensorId, query.sensorId));
        }
        if (query.status) {
          conditions.push(eq(agentResponseActions.status, query.status));
        }
        if (query.actionType) {
          conditions.push(eq(agentResponseActions.actionType, query.actionType));
        }

        const rows = await db
          .select({
            action: agentResponseActions,
            sensorHostname: nativeSensors.hostname,
          })
          .from(agentResponseActions)
          .leftJoin(nativeSensors, eq(agentResponseActions.sensorId, nativeSensors.id))
          .where(and(...conditions))
          .orderBy(desc(agentResponseActions.createdAt));

        const result = rows.map(({ action, sensorHostname }) => ({
          ...action,
          sensorHostname: sensorHostname ?? null,
        }));

        return sendEnvelope(res, result);
      } catch (err: any) {
        log.error("Failed to list response actions", { error: String(err) });
        return res.status(500).json({ error: "Failed to list response actions" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // GET ACTION DETAIL
  // --------------------------------------------------------------------------

  /**
   * Retrieve full detail for a single response action.
   */
  app.get(
    "/api/native/response/actions/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const rows = await db
          .select({
            action: agentResponseActions,
            sensorHostname: nativeSensors.hostname,
          })
          .from(agentResponseActions)
          .leftJoin(nativeSensors, eq(agentResponseActions.sensorId, nativeSensors.id))
          .where(
            and(
              eq(agentResponseActions.id, req.params.id),
              eq(agentResponseActions.orgId, orgId),
            ),
          )
          .limit(1);

        if (rows.length === 0) {
          return res.status(404).json({ error: "Action not found" });
        }

        const { action, sensorHostname } = rows[0];
        return sendEnvelope(res, { ...action, sensorHostname: sensorHostname ?? null });
      } catch (err: any) {
        log.error("Failed to get response action", { error: String(err) });
        return res.status(500).json({ error: "Failed to get response action" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // APPROVE ACTION
  // --------------------------------------------------------------------------

  /**
   * Approve a high-risk action that is awaiting analyst approval.
   * Restricted to admin role. Transitions status from "pending" to "dispatched".
   */
  app.post(
    "/api/native/response/actions/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;

        const [existing] = await db
          .select()
          .from(agentResponseActions)
          .where(
            and(
              eq(agentResponseActions.id, req.params.id),
              eq(agentResponseActions.orgId, orgId),
            ),
          )
          .limit(1);

        if (!existing) {
          return res.status(404).json({ error: "Action not found" });
        }
        if (!existing.requiresApproval) {
          return res.status(400).json({ error: "This action does not require approval" });
        }
        if (existing.status !== "pending") {
          return res.status(400).json({
            error: `Cannot approve action in "${existing.status}" status. Only pending actions can be approved.`,
          });
        }

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "dispatched",
            approvedBy: user?.id ?? null,
            approvedAt: new Date(),
            dispatchedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, existing.id))
          .returning();

        log.info("Response action approved", {
          actionId: existing.id,
          actionType: existing.actionType,
          approvedBy: user?.id,
          orgId,
        });

        return sendEnvelope(res, updated);
      } catch (err: any) {
        log.error("Failed to approve response action", { error: String(err) });
        return res.status(500).json({ error: "Failed to approve response action" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // CANCEL ACTION
  // --------------------------------------------------------------------------

  /**
   * Cancel a response action that has not yet been acknowledged by the agent.
   * Cancelled actions are permanently stopped — they will not be dispatched.
   */
  app.post(
    "/api/native/response/actions/:id/cancel",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [existing] = await db
          .select()
          .from(agentResponseActions)
          .where(
            and(
              eq(agentResponseActions.id, req.params.id),
              eq(agentResponseActions.orgId, orgId),
            ),
          )
          .limit(1);

        if (!existing) {
          return res.status(404).json({ error: "Action not found" });
        }

        const cancellableStatuses = ["pending", "dispatched"];
        if (!cancellableStatuses.includes(existing.status)) {
          return res.status(400).json({
            error: `Cannot cancel action in "${existing.status}" status. Only pending or dispatched actions can be cancelled.`,
          });
        }

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "cancelled",
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, existing.id))
          .returning();

        log.info("Response action cancelled", {
          actionId: existing.id,
          actionType: existing.actionType,
          orgId,
        });

        return sendEnvelope(res, updated);
      } catch (err: any) {
        log.error("Failed to cancel response action", { error: String(err) });
        return res.status(500).json({ error: "Failed to cancel response action" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // DELETE (SOFT) ACTION
  // --------------------------------------------------------------------------

  /**
   * Soft-delete a response action by cancelling it.
   * Mirrors the cancel endpoint semantics; keeps the record for audit purposes.
   */
  app.delete(
    "/api/native/response/actions/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [existing] = await db
          .select()
          .from(agentResponseActions)
          .where(
            and(
              eq(agentResponseActions.id, req.params.id),
              eq(agentResponseActions.orgId, orgId),
            ),
          )
          .limit(1);

        if (!existing) {
          return res.status(404).json({ error: "Action not found" });
        }

        // Already in a terminal state — treat as a no-op success
        const terminalStatuses = ["cancelled", "completed", "failed"];
        if (terminalStatuses.includes(existing.status)) {
          return sendEnvelope(res, existing);
        }

        const [updated] = await db
          .update(agentResponseActions)
          .set({
            status: "cancelled",
            updatedAt: new Date(),
          })
          .where(eq(agentResponseActions.id, existing.id))
          .returning();

        log.info("Response action soft-deleted (cancelled)", {
          actionId: existing.id,
          actionType: existing.actionType,
          orgId,
        });

        return sendEnvelope(res, updated);
      } catch (err: any) {
        log.error("Failed to delete response action", { error: String(err) });
        return res.status(500).json({ error: "Failed to delete response action" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // AGENT: POLL FOR PENDING COMMANDS
  // --------------------------------------------------------------------------

  /**
   * Agent polls this endpoint for commands it needs to execute.
   *
   * Authentication: sensor registration token + sensorId passed as query params.
   * Returns all actions in "dispatched" status for the authenticated sensor,
   * plus any "pending" actions that do not require approval (these were created
   * but the auto-dispatch path has not yet updated them — edge case safety net).
   *
   * Side effect: marks returned actions as "acknowledged" with the current timestamp.
   */
  app.get("/api/native/response/pending", async (req, res) => {
    try {
      const token = String(req.query.token ?? "");
      const sensorId = String(req.query.sensorId ?? "");

      if (!token || !sensorId) {
        return res.status(401).json({ error: "token and sensorId query parameters are required" });
      }

      const sensor = await authenticateSensor(token, sensorId);
      if (!sensor) {
        return res.status(401).json({ error: "Invalid sensor token or sensor ID" });
      }

      // Fetch dispatched actions, plus any pending non-approval actions
      // (the latter handles the rare race condition where creation succeeded
      //  but the auto-dispatch update has not yet landed).
      const actions = await db
        .select()
        .from(agentResponseActions)
        .where(
          and(
            eq(agentResponseActions.sensorId, sensor.id),
            or(
              eq(agentResponseActions.status, "dispatched"),
              and(
                eq(agentResponseActions.status, "pending"),
                eq(agentResponseActions.requiresApproval, false),
              ),
            ),
          ),
        )
        .orderBy(agentResponseActions.createdAt);

      if (actions.length === 0) {
        return res.json({ actions: [] });
      }

      const actionIds = actions.map((a) => a.id);
      const now = new Date();

      await db
        .update(agentResponseActions)
        .set({
          status: "acknowledged",
          acknowledgedAt: now,
          updatedAt: now,
        })
        .where(inArray(agentResponseActions.id, actionIds));

      log.info("Agent polled and acknowledged actions", {
        sensorId: sensor.id,
        count: actions.length,
      });

      return res.json({ actions });
    } catch (err: any) {
      log.error("Agent poll for pending actions failed", { error: String(err) });
      return res.status(500).json({ error: "Failed to retrieve pending actions" });
    }
  });

  // --------------------------------------------------------------------------
  // AGENT: REPORT COMPLETION
  // --------------------------------------------------------------------------

  /**
   * Agent calls this endpoint after executing a response action to report the result.
   *
   * Authentication: sensor registration token + sensorId in request body.
   * resultCode 0 = success → status becomes "completed".
   * Any other resultCode → status becomes "failed".
   *
   * Broadcasts "agent_action:completed" to connected SSE clients for real-time
   * dashboard updates.
   */
  app.post("/api/native/response/actions/:id/complete", async (req, res) => {
    try {
      const body = completeActionSchema.parse(req.body);

      const sensor = await authenticateSensor(body.token, body.sensorId);
      if (!sensor) {
        return res.status(401).json({ error: "Invalid sensor token or sensor ID" });
      }

      const [existing] = await db
        .select()
        .from(agentResponseActions)
        .where(eq(agentResponseActions.id, req.params.id))
        .limit(1);

      if (!existing) {
        return res.status(404).json({ error: "Action not found" });
      }

      // Ensure the action actually belongs to this sensor
      if (existing.sensorId !== sensor.id) {
        return res.status(403).json({ error: "Action does not belong to this sensor" });
      }

      // Only acknowledged actions (or dispatched, for resilience) can be completed
      const completableStatuses = ["acknowledged", "dispatched"];
      if (!completableStatuses.includes(existing.status)) {
        return res.status(400).json({
          error: `Cannot complete action in "${existing.status}" status`,
        });
      }

      const succeeded = body.resultCode === 0;
      const finalStatus = succeeded ? "completed" : "failed";
      const now = new Date();

      const [updated] = await db
        .update(agentResponseActions)
        .set({
          status: finalStatus,
          resultCode: body.resultCode,
          resultOutput: body.resultOutput ?? null,
          errorMessage: body.errorMessage ?? null,
          completedAt: now,
          updatedAt: now,
        })
        .where(eq(agentResponseActions.id, existing.id))
        .returning();

      log.info("Response action completed by agent", {
        actionId: existing.id,
        actionType: existing.actionType,
        sensorId: sensor.id,
        orgId: existing.orgId,
        resultCode: body.resultCode,
        status: finalStatus,
      });

      broadcastEvent({
        type: "agent_action:completed",
        orgId: existing.orgId,
        data: {
          actionId: existing.id,
          actionType: existing.actionType,
          sensorId: sensor.id,
          sensorHostname: sensor.hostname,
          status: finalStatus,
          resultCode: body.resultCode,
          resultOutput: body.resultOutput ?? null,
          errorMessage: body.errorMessage ?? null,
          completedAt: now.toISOString(),
        },
      });

      return res.json({ ok: true, actionId: updated.id, status: finalStatus });
    } catch (err: any) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: err.errors });
      }
      log.error("Failed to complete response action", { error: String(err) });
      return res.status(500).json({ error: "Failed to record action completion" });
    }
  });

  // --------------------------------------------------------------------------
  // STATS
  // --------------------------------------------------------------------------

  /**
   * Returns aggregate statistics for response actions in this org:
   * - counts broken down by status
   * - counts broken down by action type
   * - the 10 most recently completed actions (for a live activity feed)
   */
  app.get(
    "/api/native/response/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [statusCounts, typeCounts, recentCompletions] = await Promise.all([
          // Count by status
          db
            .select({
              status: agentResponseActions.status,
              count: sql<number>`cast(count(*) as integer)`,
            })
            .from(agentResponseActions)
            .where(eq(agentResponseActions.orgId, orgId))
            .groupBy(agentResponseActions.status),

          // Count by action type
          db
            .select({
              actionType: agentResponseActions.actionType,
              count: sql<number>`cast(count(*) as integer)`,
            })
            .from(agentResponseActions)
            .where(eq(agentResponseActions.orgId, orgId))
            .groupBy(agentResponseActions.actionType),

          // 10 most recently completed/failed, enriched with sensor hostname
          db
            .select({
              action: agentResponseActions,
              sensorHostname: nativeSensors.hostname,
            })
            .from(agentResponseActions)
            .leftJoin(nativeSensors, eq(agentResponseActions.sensorId, nativeSensors.id))
            .where(
              and(
                eq(agentResponseActions.orgId, orgId),
                inArray(agentResponseActions.status, ["completed", "failed"]),
              ),
            )
            .orderBy(desc(agentResponseActions.completedAt))
            .limit(10),
        ]);

        const byStatus: Record<string, number> = {};
        for (const row of statusCounts) {
          byStatus[row.status] = row.count;
        }

        const byType: Record<string, number> = {};
        for (const row of typeCounts) {
          byType[row.actionType] = row.count;
        }

        return sendEnvelope(res, {
          byStatus,
          byType,
          recentCompletions: recentCompletions.map(({ action, sensorHostname }) => ({
            ...action,
            sensorHostname: sensorHostname ?? null,
          })),
        });
      } catch (err: any) {
        log.error("Failed to get response action stats", { error: String(err) });
        return res.status(500).json({ error: "Failed to get stats" });
      }
    },
  );
}
