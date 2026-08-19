import type { Express } from "express";
import { eq, and, desc, count, or } from "drizzle-orm";
import { randomBytes } from "crypto";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

import { db } from "../db";
import { pamSessions } from "@shared/schema";

const log = logger.child("pam");

function generateSessionToken(): string {
  return `pam_${randomBytes(32).toString("hex")}`;
}

export function registerPamRoutes(app: Express): void {
  // =========================================================================
  // PAM SESSION MANAGEMENT
  // =========================================================================

  // List PAM sessions
  app.get("/api/pam/sessions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status ? String(req.query.status) : undefined;
      const targetSystem = req.query.targetSystem ? String(req.query.targetSystem) : undefined;

      const conditions = [eq(pamSessions.orgId, orgId)];
      if (status) conditions.push(eq(pamSessions.status, status));
      if (targetSystem) conditions.push(eq(pamSessions.targetSystem, targetSystem));

      const sessions = await db
        .select()
        .from(pamSessions)
        .where(and(...conditions))
        .orderBy(desc(pamSessions.createdAt))
        .limit(200);

      // Stats
      const [totalResult] = await db.select({ cnt: count() }).from(pamSessions).where(eq(pamSessions.orgId, orgId));

      const [activeResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "active")));

      const [pendingResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "requested")));

      const [deniedResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "denied")));

      const [completedResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(
          and(eq(pamSessions.orgId, orgId), or(eq(pamSessions.status, "completed"), eq(pamSessions.status, "expired"))),
        );

      res.json({
        sessions,
        stats: {
          total: totalResult.cnt,
          active: activeResult.cnt,
          pending: pendingResult.cnt,
          denied: deniedResult.cnt,
          completed: completedResult.cnt,
        },
      });
    } catch (error) {
      log.error("List PAM sessions error", { error: String(error) });
      res.status(500).json({ message: "Failed to list PAM sessions" });
    }
  });

  // Request elevated access (PAM session)
  app.post(
    "/api/pam/sessions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          requesterName,
          requesterEmail,
          targetSystem,
          targetHost,
          targetAccount,
          accessLevel,
          justification,
          incidentId,
          durationMinutes,
        } = req.body;

        if (!requesterName || typeof requesterName !== "string") {
          return res.status(400).json({ message: "requesterName is required" });
        }
        if (!targetSystem || typeof targetSystem !== "string") {
          return res.status(400).json({ message: "targetSystem is required" });
        }
        if (!targetAccount || typeof targetAccount !== "string") {
          return res.status(400).json({ message: "targetAccount is required" });
        }

        const validAccessLevels = ["read", "write", "admin", "superadmin"];
        if (!accessLevel || !validAccessLevels.includes(accessLevel)) {
          return res.status(400).json({ message: `accessLevel must be: ${validAccessLevels.join(", ")}` });
        }

        if (!justification || typeof justification !== "string" || justification.trim().length < 10) {
          return res.status(400).json({ message: "justification is required (min 10 chars)" });
        }

        const dur = typeof durationMinutes === "number" ? durationMinutes : 60;
        if (dur < 5 || dur > 480) {
          return res.status(400).json({ message: "durationMinutes must be 5-480" });
        }

        // Calculate risk score based on access level and target
        let riskScore = 0;
        if (accessLevel === "superadmin") riskScore += 40;
        else if (accessLevel === "admin") riskScore += 30;
        else if (accessLevel === "write") riskScore += 15;
        if (targetAccount === "root" || targetAccount === "Administrator") riskScore += 30;
        if (dur > 120) riskScore += 15;
        if (dur > 240) riskScore += 10;
        riskScore = Math.min(100, riskScore);

        const riskFactors: string[] = [];
        if (accessLevel === "superadmin" || accessLevel === "admin") riskFactors.push("Elevated access level");
        if (targetAccount === "root" || targetAccount === "Administrator")
          riskFactors.push("Root/admin target account");
        if (dur > 120) riskFactors.push("Extended duration (>2h)");

        const requesterId = (req as any).user?.id || "system";

        const [session] = await db
          .insert(pamSessions)
          .values({
            orgId,
            requesterId,
            requesterName: String(requesterName).trim(),
            requesterEmail: typeof requesterEmail === "string" ? requesterEmail : null,
            targetSystem: String(targetSystem).trim(),
            targetHost: typeof targetHost === "string" ? targetHost : null,
            targetAccount: String(targetAccount).trim(),
            accessLevel,
            justification: String(justification).trim(),
            incidentId: typeof incidentId === "string" ? incidentId : null,
            status: "requested",
            durationMinutes: dur,
            recordingEnabled: true,
            riskScore,
            riskFactors,
          })
          .returning();

        res.status(201).json(session);
      } catch (error) {
        log.error("Request PAM session error", { error: String(error) });
        res.status(500).json({ message: "Failed to request PAM session" });
      }
    },
  );

  // Get PAM session detail
  app.get("/api/pam/sessions/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [session] = await db
        .select()
        .from(pamSessions)
        .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)));

      if (!session) {
        return res.status(404).json({ message: "PAM session not found" });
      }

      res.json(session);
    } catch (error) {
      log.error("Get PAM session error", { error: String(error) });
      res.status(500).json({ message: "Failed to get PAM session" });
    }
  });

  // Approve PAM session
  app.post(
    "/api/pam/sessions/:id/approve",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [session] = await db
          .select()
          .from(pamSessions)
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)));

        if (!session) {
          return res.status(404).json({ message: "PAM session not found" });
        }
        if (session.status !== "requested") {
          return res.status(400).json({ message: "Session must be in 'requested' status to approve" });
        }

        const approverUserId = (req as any).user?.id || "system";
        const expiresAt = new Date(Date.now() + session.durationMinutes * 60 * 1000);
        const sessionToken = generateSessionToken();

        const [updated] = await db
          .update(pamSessions)
          .set({
            status: "approved",
            approvedBy: approverUserId,
            approvedAt: new Date(),
            expiresAt,
            sessionToken,
            updatedAt: new Date(),
          })
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Approve PAM session error", { error: String(error) });
        res.status(500).json({ message: "Failed to approve PAM session" });
      }
    },
  );

  // Deny PAM session
  app.post(
    "/api/pam/sessions/:id/deny",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { reason } = req.body;

        const [session] = await db
          .select()
          .from(pamSessions)
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)));

        if (!session) {
          return res.status(404).json({ message: "PAM session not found" });
        }
        if (session.status !== "requested") {
          return res.status(400).json({ message: "Session must be in 'requested' status to deny" });
        }

        const denierUserId = (req as any).user?.id || "system";

        const [updated] = await db
          .update(pamSessions)
          .set({
            status: "denied",
            deniedBy: denierUserId,
            deniedReason: typeof reason === "string" ? reason : "Access denied by administrator",
            updatedAt: new Date(),
          })
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Deny PAM session error", { error: String(error) });
        res.status(500).json({ message: "Failed to deny PAM session" });
      }
    },
  );

  // Activate PAM session (user starts using it)
  app.post(
    "/api/pam/sessions/:id/activate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);

        const [session] = await db
          .select()
          .from(pamSessions)
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)));

        if (!session) {
          return res.status(404).json({ message: "PAM session not found" });
        }
        if (session.status !== "approved") {
          return res.status(400).json({ message: "Session must be approved before activation" });
        }

        const [updated] = await db
          .update(pamSessions)
          .set({
            status: "active",
            activatedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Activate PAM session error", { error: String(error) });
        res.status(500).json({ message: "Failed to activate PAM session" });
      }
    },
  );

  // Terminate PAM session (admin force-end)
  app.post(
    "/api/pam/sessions/:id/terminate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { reason } = req.body;

        const [session] = await db
          .select()
          .from(pamSessions)
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)));

        if (!session) {
          return res.status(404).json({ message: "PAM session not found" });
        }
        if (!["active", "approved"].includes(session.status)) {
          return res.status(400).json({ message: "Session must be active or approved to terminate" });
        }

        const terminatorId = (req as any).user?.id || "system";

        const [updated] = await db
          .update(pamSessions)
          .set({
            status: "terminated",
            terminatedAt: new Date(),
            terminatedBy: terminatorId,
            terminationReason: typeof reason === "string" ? reason : "Terminated by administrator",
            sessionToken: null,
            updatedAt: new Date(),
          })
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Terminate PAM session error", { error: String(error) });
        res.status(500).json({ message: "Failed to terminate PAM session" });
      }
    },
  );

  // Complete PAM session (user finishes work)
  app.post(
    "/api/pam/sessions/:id/complete",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = String(req.params.id);
        const { commandCount, keystrokeCount } = req.body;

        const [session] = await db
          .select()
          .from(pamSessions)
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)));

        if (!session) {
          return res.status(404).json({ message: "PAM session not found" });
        }
        if (session.status !== "active") {
          return res.status(400).json({ message: "Session must be active to complete" });
        }

        const [updated] = await db
          .update(pamSessions)
          .set({
            status: "completed",
            sessionToken: null,
            commandCount: typeof commandCount === "number" ? commandCount : session.commandCount,
            keystrokeCount: typeof keystrokeCount === "number" ? keystrokeCount : session.keystrokeCount,
            updatedAt: new Date(),
          })
          .where(and(eq(pamSessions.id, id), eq(pamSessions.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Complete PAM session error", { error: String(error) });
        res.status(500).json({ message: "Failed to complete PAM session" });
      }
    },
  );

  // =========================================================================
  // PAM SUMMARY / STATS
  // =========================================================================

  app.get("/api/pam/summary", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [totalResult] = await db.select({ cnt: count() }).from(pamSessions).where(eq(pamSessions.orgId, orgId));

      const [activeResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "active")));

      const [pendingResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "requested")));

      const [completedResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(
          and(eq(pamSessions.orgId, orgId), or(eq(pamSessions.status, "completed"), eq(pamSessions.status, "expired"))),
        );

      const [terminatedResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "terminated")));

      const [deniedResult] = await db
        .select({ cnt: count() })
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "denied")));

      // Recent high-risk sessions
      const highRiskSessions = await db
        .select()
        .from(pamSessions)
        .where(and(eq(pamSessions.orgId, orgId), eq(pamSessions.status, "active")))
        .orderBy(desc(pamSessions.riskScore))
        .limit(5);

      res.json({
        total: totalResult.cnt,
        active: activeResult.cnt,
        pending: pendingResult.cnt,
        completed: completedResult.cnt,
        terminated: terminatedResult.cnt,
        denied: deniedResult.cnt,
        highRiskActiveSessions: highRiskSessions,
      });
    } catch (error) {
      log.error("Get PAM summary error", { error: String(error) });
      res.status(500).json({ message: "Failed to get PAM summary" });
    }
  });
}
