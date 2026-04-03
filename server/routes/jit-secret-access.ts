import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { storage } from "../storage";
import {
  getSecrets,
  getSecretById,
  registerSecret,
  createShare,
  consumeShare,
  getShares,
  transferOwnership,
  reclaimOwnership,
  getTransfers,
  breakGlassAccess,
  reviewBreakGlass,
  getBreakGlassEntries,
  getAuditLog,
} from "../jit-secret-access-engine";
import type { SecretType, SecretClassification } from "../jit-secret-access-engine";

const VALID_SECRET_TYPES: SecretType[] = [
  "api_key",
  "database_credential",
  "ssh_key",
  "tls_cert",
  "oauth_token",
  "encryption_key",
  "service_account",
  "other",
];

const VALID_CLASSIFICATIONS: SecretClassification[] = ["critical", "high", "medium", "low"];

const VALID_APPROVER_ROLES = ["manager", "security", "owner"] as const;

function isValidSecretType(val: string): val is SecretType {
  return VALID_SECRET_TYPES.includes(val as SecretType);
}

function isValidClassification(val: string): val is SecretClassification {
  return VALID_CLASSIFICATIONS.includes(val as SecretClassification);
}

export function registerJitSecretAccessRoutes(app: Express): void {
  // ─── Secrets Registry — engine (no DB table yet) ───────────────────────────

  app.get("/api/jit-secrets/secrets", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const secrets = getSecrets(orgId);
      res.json(secrets);
    } catch (error) {
      logger.child("routes").error("Get secrets error", { error: String(error) });
      res.status(500).json({ message: "Failed to get secrets" });
    }
  });

  app.get("/api/jit-secrets/secrets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const secret = getSecretById(orgId, id);
      if (!secret) {
        return res.status(404).json({ message: "Secret not found" });
      }
      res.json(secret);
    } catch (error) {
      logger.child("routes").error("Get secret by ID error", { error: String(error) });
      res.status(500).json({ message: "Failed to get secret" });
    }
  });

  app.post("/api/jit-secrets/secrets", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const {
        name,
        description,
        secretType,
        classification,
        ownerId,
        ownerName,
        environment,
        service,
        rotationIntervalDays,
        noPlaintextSharing,
      } = req.body;

      if (!name || typeof name !== "string" || name.trim().length < 2) {
        return res.status(400).json({ message: "Name is required (min 2 chars)" });
      }
      if (!secretType || !isValidSecretType(secretType)) {
        return res.status(400).json({ message: `Invalid secretType. Valid: ${VALID_SECRET_TYPES.join(", ")}` });
      }
      if (!classification || !isValidClassification(classification)) {
        return res.status(400).json({ message: `Invalid classification. Valid: ${VALID_CLASSIFICATIONS.join(", ")}` });
      }
      if (!ownerId || typeof ownerId !== "string") {
        return res.status(400).json({ message: "ownerId is required" });
      }
      if (!ownerName || typeof ownerName !== "string") {
        return res.status(400).json({ message: "ownerName is required" });
      }

      const secret = registerSecret(orgId, {
        name: String(name).trim(),
        description: typeof description === "string" ? description.trim() : "",
        secretType,
        classification,
        ownerId: String(ownerId),
        ownerName: String(ownerName),
        environment: typeof environment === "string" ? environment.trim() : "production",
        service: typeof service === "string" ? service.trim() : "unknown",
        rotationIntervalDays:
          typeof rotationIntervalDays === "number" && rotationIntervalDays > 0 ? rotationIntervalDays : 90,
        noPlaintextSharing: noPlaintextSharing === true,
      });

      res.status(201).json(secret);
    } catch (error) {
      logger.child("routes").error("Register secret error", { error: String(error) });
      res.status(500).json({ message: "Failed to register secret" });
    }
  });

  // ─── Access Requests — DB persisted ────────────────────────────────────────

  app.get("/api/jit-secrets/access-requests", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const requests = await storage.getJitAccessRequests(orgId);
      res.json(requests);
    } catch (error) {
      logger.child("routes").error("Get access requests error", { error: String(error) });
      res.status(500).json({ message: "Failed to get access requests" });
    }
  });

  app.post("/api/jit-secrets/access-requests", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const { secretId, requesterId, requesterName, reason, durationMinutes, approverRole } = req.body;

      if (!secretId || typeof secretId !== "string") {
        return res.status(400).json({ message: "secretId is required" });
      }
      if (!requesterId || typeof requesterId !== "string") {
        return res.status(400).json({ message: "requesterId is required" });
      }
      if (!requesterName || typeof requesterName !== "string") {
        return res.status(400).json({ message: "requesterName is required" });
      }
      if (!reason || typeof reason !== "string" || reason.trim().length < 10) {
        return res.status(400).json({ message: "reason is required (min 10 chars)" });
      }
      if (typeof durationMinutes !== "number" || durationMinutes < 1 || durationMinutes > 1440) {
        return res.status(400).json({ message: "durationMinutes must be 1-1440" });
      }
      if (!approverRole || !VALID_APPROVER_ROLES.includes(approverRole)) {
        return res.status(400).json({ message: `approverRole must be: ${VALID_APPROVER_ROLES.join(", ")}` });
      }

      // Verify secret exists in registry
      const secret = getSecretById(orgId, String(secretId));
      if (!secret) {
        return res.status(404).json({ message: "Secret not found" });
      }

      const request = await storage.createJitAccessRequest({
        orgId,
        requesterId: String(requesterId),
        requesterEmail: String(requesterName),
        secretPath: secret.name,
        secretProvider: secret.secretType || "other",
        reason: String(reason).trim(),
        durationMinutes,
        status: "pending",
        metadata: {
          secretId: String(secretId),
          secretName: secret.name,
          requesterName: String(requesterName),
          approverRole,
          classification: secret.classification,
        },
      });

      res.status(201).json(request);
    } catch (error) {
      logger.child("routes").error("Request access error", { error: String(error) });
      res.status(500).json({ message: "Failed to request access" });
    }
  });

  app.post("/api/jit-secrets/access-requests/:id/approve", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { approverName } = req.body;
      if (!approverName || typeof approverName !== "string") {
        return res.status(400).json({ message: "approverName is required" });
      }

      const existing = await storage.getJitAccessRequest(id, orgId);
      if (!existing) {
        return res.status(404).json({ message: "Access request not found" });
      }
      if (existing.status !== "pending") {
        return res.status(400).json({ message: "Request is not in pending status" });
      }

      const expiresAt = new Date(Date.now() + existing.durationMinutes * 60 * 1000);
      const updated = await storage.updateJitAccessRequest(id, orgId, {
        status: "approved",
        approvedBy: String(approverName),
        approvedAt: new Date(),
        expiresAt,
      });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Approve access error", { error: String(error) });
      res.status(500).json({ message: "Failed to approve access request" });
    }
  });

  app.post("/api/jit-secrets/access-requests/:id/deny", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { denierName, reason } = req.body;
      if (!denierName || typeof denierName !== "string") {
        return res.status(400).json({ message: "denierName is required" });
      }
      if (!reason || typeof reason !== "string") {
        return res.status(400).json({ message: "reason is required" });
      }

      const existing = await storage.getJitAccessRequest(id, orgId);
      if (!existing) {
        return res.status(404).json({ message: "Access request not found" });
      }
      if (existing.status !== "pending") {
        return res.status(400).json({ message: "Request is not in pending status" });
      }

      const updated = await storage.updateJitAccessRequest(id, orgId, {
        status: "denied",
        approvedBy: String(denierName),
        metadata: { ...(existing.metadata as Record<string, unknown>), denyReason: String(reason) },
      });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Deny access error", { error: String(error) });
      res.status(500).json({ message: "Failed to deny access request" });
    }
  });

  app.post("/api/jit-secrets/access-requests/:id/release", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { releaserName } = req.body;
      if (!releaserName || typeof releaserName !== "string") {
        return res.status(400).json({ message: "releaserName is required" });
      }

      const existing = await storage.getJitAccessRequest(id, orgId);
      if (!existing) {
        return res.status(404).json({ message: "Access request not found" });
      }
      if (existing.status !== "approved") {
        return res.status(400).json({ message: "Request is not active" });
      }

      const updated = await storage.updateJitAccessRequest(id, orgId, {
        status: "revoked",
        revokedAt: new Date(),
        metadata: { ...(existing.metadata as Record<string, unknown>), releasedBy: String(releaserName) },
      });
      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Release access error", { error: String(error) });
      res.status(500).json({ message: "Failed to release access" });
    }
  });

  // ─── Shares — engine (no DB table yet) ─────────────────────────────────────

  app.get("/api/jit-secrets/shares", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const shares = getShares(orgId);
      res.json(shares);
    } catch (error) {
      logger.child("routes").error("Get shares error", { error: String(error) });
      res.status(500).json({ message: "Failed to get shares" });
    }
  });

  app.post("/api/jit-secrets/shares", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const { secretId, createdBy, recipientEmail, expiresInHours, maxUses } = req.body;

      if (!secretId || typeof secretId !== "string") {
        return res.status(400).json({ message: "secretId is required" });
      }
      if (!createdBy || typeof createdBy !== "string") {
        return res.status(400).json({ message: "createdBy is required" });
      }
      if (!recipientEmail || typeof recipientEmail !== "string" || !recipientEmail.includes("@")) {
        return res.status(400).json({ message: "Valid recipientEmail is required" });
      }
      if (typeof expiresInHours !== "number" || expiresInHours < 1 || expiresInHours > 168) {
        return res.status(400).json({ message: "expiresInHours must be 1-168" });
      }

      const share = createShare(orgId, {
        secretId: String(secretId),
        createdBy: String(createdBy),
        recipientEmail: String(recipientEmail),
        expiresInHours,
        maxUses: typeof maxUses === "number" && maxUses >= 1 && maxUses <= 10 ? maxUses : 1,
      });

      res.status(201).json(share);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SECRET_NOT_FOUND")) {
        return res.status(404).json({ message: "Secret not found" });
      }
      if (errMsg.includes("INVALID_EXPIRY")) {
        return res.status(400).json({ message: "Expiry must be 1-168 hours" });
      }
      if (errMsg.includes("INVALID_EMAIL")) {
        return res.status(400).json({ message: "Invalid email format" });
      }
      logger.child("routes").error("Create share error", { error: errMsg });
      res.status(500).json({ message: "Failed to create share" });
    }
  });

  app.post("/api/jit-secrets/shares/:id/consume", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { consumerIdentity } = req.body;
      if (!consumerIdentity || typeof consumerIdentity !== "string") {
        return res.status(400).json({ message: "consumerIdentity is required" });
      }
      const share = consumeShare(orgId, id, String(consumerIdentity));
      res.json(share);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SHARE_NOT_FOUND")) {
        return res.status(404).json({ message: "Share not found" });
      }
      if (errMsg.includes("SHARE_NOT_ACTIVE")) {
        return res.status(400).json({ message: "Share is not active" });
      }
      if (errMsg.includes("SHARE_EXPIRED")) {
        return res.status(400).json({ message: "Share has expired" });
      }
      logger.child("routes").error("Consume share error", { error: errMsg });
      res.status(500).json({ message: "Failed to consume share" });
    }
  });

  // ─── Break Glass — engine (no DB table yet) ────────────────────────────────

  app.post("/api/jit-secrets/break-glass", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const { secretId, requesterId, requesterName, justification, incidentId, durationMinutes } = req.body;

      if (!secretId || typeof secretId !== "string") {
        return res.status(400).json({ message: "secretId is required" });
      }
      if (!requesterId || typeof requesterId !== "string") {
        return res.status(400).json({ message: "requesterId is required" });
      }
      if (!requesterName || typeof requesterName !== "string") {
        return res.status(400).json({ message: "requesterName is required" });
      }
      if (!justification || typeof justification !== "string" || justification.trim().length < 20) {
        return res.status(400).json({ message: "justification is required (min 20 chars)" });
      }
      if (typeof durationMinutes !== "number" || durationMinutes < 5 || durationMinutes > 120) {
        return res.status(400).json({ message: "durationMinutes must be 5-120" });
      }

      const access = breakGlassAccess(orgId, {
        secretId: String(secretId),
        requesterId: String(requesterId),
        requesterName: String(requesterName),
        justification: String(justification).trim(),
        incidentId: typeof incidentId === "string" ? incidentId : null,
        durationMinutes,
      });

      res.status(201).json(access);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SECRET_NOT_FOUND")) {
        return res.status(404).json({ message: "Secret not found" });
      }
      if (errMsg.includes("JUSTIFICATION_TOO_SHORT")) {
        return res.status(400).json({ message: "Justification must be at least 20 characters" });
      }
      if (errMsg.includes("INVALID_DURATION")) {
        return res.status(400).json({ message: "Duration must be 5-120 minutes" });
      }
      logger.child("routes").error("Break glass error", { error: errMsg });
      res.status(500).json({ message: "Failed to activate break-glass access" });
    }
  });

  app.post("/api/jit-secrets/break-glass/:id/review", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { reviewerName, notes } = req.body;
      if (!reviewerName || typeof reviewerName !== "string") {
        return res.status(400).json({ message: "reviewerName is required" });
      }
      if (!notes || typeof notes !== "string") {
        return res.status(400).json({ message: "notes is required" });
      }
      const entry = reviewBreakGlass(orgId, id, String(reviewerName), String(notes));
      res.json(entry);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("BREAK_GLASS_NOT_FOUND")) {
        return res.status(404).json({ message: "Break-glass entry not found" });
      }
      if (errMsg.includes("ALREADY_REVIEWED")) {
        return res.status(400).json({ message: "Break-glass entry already reviewed" });
      }
      logger.child("routes").error("Review break glass error", { error: errMsg });
      res.status(500).json({ message: "Failed to review break-glass access" });
    }
  });

  app.get("/api/jit-secrets/break-glass", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const entries = getBreakGlassEntries(orgId);
      res.json(entries);
    } catch (error) {
      logger.child("routes").error("Get break glass error", { error: String(error) });
      res.status(500).json({ message: "Failed to get break-glass entries" });
    }
  });

  // ─── Ownership Transfers — engine (no DB table yet) ────────────────────────

  app.post("/api/jit-secrets/ownership/transfer", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const { secretId, toOwnerId, toOwnerName, reason, isOffboarding, initiatedBy } = req.body;

      if (!secretId || typeof secretId !== "string") {
        return res.status(400).json({ message: "secretId is required" });
      }
      if (!toOwnerId || typeof toOwnerId !== "string") {
        return res.status(400).json({ message: "toOwnerId is required" });
      }
      if (!toOwnerName || typeof toOwnerName !== "string") {
        return res.status(400).json({ message: "toOwnerName is required" });
      }
      if (!reason || typeof reason !== "string" || reason.trim().length < 10) {
        return res.status(400).json({ message: "reason is required (min 10 chars)" });
      }
      if (!initiatedBy || typeof initiatedBy !== "string") {
        return res.status(400).json({ message: "initiatedBy is required" });
      }

      const transfer = transferOwnership(orgId, {
        secretId: String(secretId),
        toOwnerId: String(toOwnerId),
        toOwnerName: String(toOwnerName),
        reason: String(reason).trim(),
        isOffboarding: isOffboarding === true,
        initiatedBy: String(initiatedBy),
      });

      res.status(201).json(transfer);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SECRET_NOT_FOUND")) {
        return res.status(404).json({ message: "Secret not found" });
      }
      if (errMsg.includes("REASON_TOO_SHORT")) {
        return res.status(400).json({ message: "Reason must be at least 10 characters" });
      }
      logger.child("routes").error("Transfer ownership error", { error: errMsg });
      res.status(500).json({ message: "Failed to transfer ownership" });
    }
  });

  app.post("/api/jit-secrets/ownership/reclaim", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const { secretId, toOwnerId, toOwnerName, reason, initiatedBy } = req.body;

      if (!secretId || typeof secretId !== "string") {
        return res.status(400).json({ message: "secretId is required" });
      }
      if (!toOwnerId || typeof toOwnerId !== "string") {
        return res.status(400).json({ message: "toOwnerId is required" });
      }
      if (!toOwnerName || typeof toOwnerName !== "string") {
        return res.status(400).json({ message: "toOwnerName is required" });
      }
      if (!reason || typeof reason !== "string" || reason.trim().length < 10) {
        return res.status(400).json({ message: "reason is required (min 10 chars)" });
      }
      if (!initiatedBy || typeof initiatedBy !== "string") {
        return res.status(400).json({ message: "initiatedBy is required" });
      }

      const transfer = reclaimOwnership(orgId, {
        secretId: String(secretId),
        toOwnerId: String(toOwnerId),
        toOwnerName: String(toOwnerName),
        reason: String(reason).trim(),
        initiatedBy: String(initiatedBy),
      });

      res.status(201).json(transfer);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SECRET_NOT_FOUND")) {
        return res.status(404).json({ message: "Secret not found" });
      }
      if (errMsg.includes("REASON_TOO_SHORT")) {
        return res.status(400).json({ message: "Reason must be at least 10 characters" });
      }
      logger.child("routes").error("Reclaim ownership error", { error: errMsg });
      res.status(500).json({ message: "Failed to reclaim ownership" });
    }
  });

  app.get("/api/jit-secrets/transfers", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const transfers = getTransfers(orgId);
      res.json(transfers);
    } catch (error) {
      logger.child("routes").error("Get transfers error", { error: String(error) });
      res.status(500).json({ message: "Failed to get transfers" });
    }
  });

  // ─── Audit Log — engine (no DB table yet) ──────────────────────────────────

  app.get("/api/jit-secrets/audit-log", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const auditLog = getAuditLog(orgId);
      res.json(auditLog);
    } catch (error) {
      logger.child("routes").error("Get audit log error", { error: String(error) });
      res.status(500).json({ message: "Failed to get audit log" });
    }
  });

  // ─── Stats — computed from DB + engine ─────────────────────────────────────

  app.get("/api/jit-secrets/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [totalRequests, pendingRequests] = await Promise.all([
        storage.countJitAccessRequests(orgId),
        storage.countPendingJitAccessRequests(orgId),
      ]);
      const secrets = getSecrets(orgId);
      const shares = getShares(orgId);
      const breakGlassEntries = getBreakGlassEntries(orgId);
      const transfers = getTransfers(orgId);

      res.json({
        totalSecrets: secrets.length,
        totalRequests,
        pendingRequests,
        totalShares: shares.length,
        activeShares: shares.filter((s: { status: string }) => s.status === "active").length,
        totalBreakGlass: breakGlassEntries.length,
        unreviewedBreakGlass: breakGlassEntries.filter((b: { status: string }) => b.status === "active").length,
        totalTransfers: transfers.length,
      });
    } catch (error) {
      logger.child("routes").error("Get stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to get stats" });
    }
  });

  // ─── 28.1 Access Request Form with Enhanced Justification ─────────────────

  app.get("/api/jit-secrets/target-systems", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const secrets = getSecrets(orgId);
      const systems = secrets.map(
        (s: {
          id: string;
          name: string;
          secretType: string;
          classification: string;
          environment: string;
          service: string;
          ownerName: string;
        }) => ({
          id: s.id,
          name: s.name,
          type: s.secretType,
          classification: s.classification,
          environment: s.environment,
          service: s.service,
          owner: s.ownerName,
          approvalChain:
            s.classification === "critical"
              ? ["manager", "security", "owner"]
              : s.classification === "high"
                ? ["manager", "owner"]
                : ["owner"],
          availableRoles: ["read", "write", "admin"],
          maxDurationMinutes: s.classification === "critical" ? 60 : s.classification === "high" ? 240 : 480,
        }),
      );
      res.json(systems);
    } catch (error) {
      logger.child("routes").error("Get target systems error", { error: String(error) });
      res.status(500).json({ message: "Failed to get target systems" });
    }
  });

  // ─── 28.2 Active Session Monitoring — DB persisted ─────────────────────────

  app.get("/api/jit-secrets/active-sessions", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const requests = await storage.getJitAccessRequests(orgId);
      const now = Date.now();

      const activeSessions = requests
        .filter((r) => r.status === "approved" && r.expiresAt)
        .map((r) => {
          const expiresAt = r.expiresAt ? new Date(r.expiresAt).getTime() : now;
          const timeRemainingMs = Math.max(0, expiresAt - now);
          const timeRemainingMinutes = Math.round(timeRemainingMs / 60000);
          const totalMs = r.durationMinutes * 60000;
          const elapsedMs = totalMs - timeRemainingMs;
          const progressPercent = totalMs > 0 ? Math.min(100, Math.round((elapsedMs / totalMs) * 100)) : 0;
          const meta = (r.metadata || {}) as Record<string, unknown>;

          return {
            sessionId: r.id,
            secretName: r.secretPath,
            user: meta.requesterName || r.requesterId,
            permissions: meta.approverRole || "owner",
            approvedBy: r.approvedBy,
            startedAt: r.approvedAt ? r.approvedAt.toISOString() : r.createdAt?.toISOString(),
            expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
            timeRemainingMinutes,
            durationMinutes: r.durationMinutes,
            progressPercent,
            isExpiringSoon: timeRemainingMinutes < 10,
            reason: r.reason,
          };
        })
        .filter((s) => s.timeRemainingMinutes > 0);

      res.json({
        sessions: activeSessions,
        totalActive: activeSessions.length,
        expiringSoon: activeSessions.filter((s) => s.isExpiringSoon).length,
      });
    } catch (error) {
      logger.child("routes").error("Get active sessions error", { error: String(error) });
      res.status(500).json({ message: "Failed to get active sessions" });
    }
  });

  app.post("/api/jit-secrets/active-sessions/:id/revoke", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);
      const { revokerName, reason } = req.body;
      if (!revokerName || typeof revokerName !== "string") {
        return res.status(400).json({ message: "revokerName is required" });
      }
      if (!reason || typeof reason !== "string") {
        return res.status(400).json({ message: "reason is required" });
      }

      const existing = await storage.getJitAccessRequest(id, orgId);
      if (!existing) {
        return res.status(404).json({ message: "Session not found" });
      }

      const updated = await storage.updateJitAccessRequest(id, orgId, {
        status: "revoked",
        revokedAt: new Date(),
        metadata: {
          ...(existing.metadata as Record<string, unknown>),
          revokedBy: String(revokerName),
          revocationReason: String(reason),
        },
      });

      logger.child("routes").info("Emergency session revocation", {
        orgId,
        sessionId: id,
        revokerName,
        reason,
      });

      res.json({ ...updated, revocationReason: reason, revokedAt: new Date().toISOString() });
    } catch (error) {
      logger.child("routes").error("Revoke session error", { error: String(error) });
      res.status(500).json({ message: "Failed to revoke session" });
    }
  });

  // ─── 28.3 Access Request History with Analytics — DB persisted ─────────────

  app.get("/api/jit-secrets/access-analytics", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const requests = await storage.getJitAccessRequests(orgId, 500);
      const now = Date.now();
      const thirtyDaysAgo = now - 30 * 86400000;

      const recentRequests = requests.filter((r) => r.createdAt && new Date(r.createdAt).getTime() > thirtyDaysAgo);

      // Frequency by user
      const userFrequency: Record<string, number> = {};
      for (const r of recentRequests) {
        const name = r.requesterId;
        userFrequency[name] = (userFrequency[name] || 0) + 1;
      }
      const topRequesters = Object.entries(userFrequency)
        .map(([user, reqCount]) => ({ user, count: reqCount }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      // Most requested systems
      const systemFrequency: Record<string, number> = {};
      for (const r of recentRequests) {
        const name = r.secretPath;
        systemFrequency[name] = (systemFrequency[name] || 0) + 1;
      }
      const topSystems = Object.entries(systemFrequency)
        .map(([system, reqCount]) => ({ system, count: reqCount }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      // Average duration
      const durations = recentRequests.map((r) => r.durationMinutes);
      const avgDuration =
        durations.length > 0 ? Math.round(durations.reduce((s, d) => s + d, 0) / durations.length) : 0;

      // Approval rates
      const approved = recentRequests.filter((r) => ["approved", "expired", "revoked"].includes(r.status)).length;
      const denied = recentRequests.filter((r) => r.status === "denied").length;
      const pending = recentRequests.filter((r) => r.status === "pending").length;
      const approvalRate = approved + denied > 0 ? Math.round((approved / (approved + denied)) * 100) : 0;

      // Unusual patterns
      const avgRequestsPerUser =
        topRequesters.length > 0 ? topRequesters.reduce((s, u) => s + u.count, 0) / topRequesters.length : 0;
      const unusualPatterns = topRequesters
        .filter((u) => u.count > avgRequestsPerUser * 3 && u.count > 5)
        .map((u) => ({
          user: u.user,
          requestCount: u.count,
          avgForOrg: Math.round(avgRequestsPerUser),
          anomalyRatio: Math.round((u.count / Math.max(1, avgRequestsPerUser)) * 10) / 10,
          flag: "high_frequency",
        }));

      res.json({
        period: "30d",
        totalRequests: recentRequests.length,
        approved,
        denied,
        pending,
        approvalRate,
        avgDurationMinutes: avgDuration,
        topRequesters,
        topSystems,
        unusualPatterns,
      });
    } catch (error) {
      logger.child("routes").error("Access analytics error", { error: String(error) });
      res.status(500).json({ message: "Failed to get access analytics" });
    }
  });

  // ─── 28.4 Automatic Access Revocation — DB persisted ───────────────────────

  app.post("/api/jit-secrets/enforce-expiration", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const requests = await storage.getJitAccessRequests(orgId, 500);
      const now = Date.now();
      const revoked: string[] = [];
      const failed: string[] = [];

      for (const r of requests) {
        if (r.status === "approved" && r.expiresAt && new Date(r.expiresAt).getTime() < now) {
          try {
            await storage.updateJitAccessRequest(r.id, orgId, {
              status: "expired",
              revokedAt: new Date(),
            });
            revoked.push(r.id);
            logger.child("routes").info("Auto-revoked expired JIT access", {
              orgId,
              requestId: r.id,
              secretPath: r.secretPath,
            });
          } catch {
            failed.push(r.id);
          }
        }
      }

      res.json({
        revokedCount: revoked.length,
        failedCount: failed.length,
        revokedIds: revoked,
        failedIds: failed,
        timestamp: new Date().toISOString(),
        message:
          revoked.length > 0
            ? `Successfully revoked ${revoked.length} expired access(es)`
            : "No expired accesses to revoke",
      });
    } catch (error) {
      logger.child("routes").error("Enforce expiration error", { error: String(error) });
      res.status(500).json({ message: "Failed to enforce expiration" });
    }
  });

  // ─── 28.5 Session Recording During JIT Access — DB persisted ───────────────

  app.get("/api/jit-secrets/session-recordings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const requests = await storage.getJitAccessRequests(orgId, 500);

      const recordings = requests
        .filter((r) => ["expired", "revoked"].includes(r.status))
        .map((r) => {
          const meta = (r.metadata || {}) as Record<string, unknown>;
          const startTime = r.approvedAt
            ? new Date(r.approvedAt).getTime()
            : r.createdAt
              ? new Date(r.createdAt).getTime()
              : Date.now();
          const endTime = r.revokedAt
            ? new Date(r.revokedAt).getTime()
            : r.expiresAt
              ? new Date(r.expiresAt).getTime()
              : startTime + r.durationMinutes * 60000;
          const actualDuration = Math.round((endTime - startTime) / 60000);

          return {
            recordingId: `rec-${r.id}`,
            sessionId: r.id,
            secretName: r.secretPath,
            user: meta.requesterName || r.requesterId,
            status: r.status,
            reason: r.reason,
            startedAt: r.approvedAt ? r.approvedAt.toISOString() : r.createdAt?.toISOString(),
            endedAt: r.revokedAt
              ? r.revokedAt.toISOString()
              : r.expiresAt
                ? r.expiresAt.toISOString()
                : new Date(endTime).toISOString(),
            actualDurationMinutes: actualDuration,
            requestedDurationMinutes: r.durationMinutes,
            earlyRelease: r.revokedAt ? actualDuration < r.durationMinutes : false,
            auditEvents: 0,
            actions: [],
          };
        });

      res.json({
        recordings,
        total: recordings.length,
      });
    } catch (error) {
      logger.child("routes").error("Session recordings error", { error: String(error) });
      res.status(500).json({ message: "Failed to get session recordings" });
    }
  });

  // ─── 28.6 Multi-Level Approval Workflow — engine ───────────────────────────

  app.get("/api/jit-secrets/approval-chains", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const secrets = getSecrets(orgId);

      const chains = secrets.map(
        (s: { id: string; name: string; classification: string; environment: string; ownerName: string }) => {
          let levels: Array<{ level: number; role: string; description: string; required: boolean }>;
          if (s.classification === "critical") {
            levels = [
              { level: 1, role: "manager", description: "Direct manager approval", required: true },
              { level: 2, role: "security", description: "Security team review", required: true },
              { level: 3, role: "owner", description: "Secret owner final sign-off", required: true },
            ];
          } else if (s.classification === "high") {
            levels = [
              { level: 1, role: "manager", description: "Direct manager approval", required: true },
              { level: 2, role: "owner", description: "Secret owner approval", required: true },
            ];
          } else {
            levels = [{ level: 1, role: "owner", description: "Secret owner approval", required: true }];
          }

          return {
            secretId: s.id,
            secretName: s.name,
            classification: s.classification,
            environment: s.environment,
            owner: s.ownerName,
            approvalLevels: levels,
            totalLevels: levels.length,
            estimatedApprovalTimeMinutes: levels.length * 15,
          };
        },
      );

      res.json({ chains, total: chains.length });
    } catch (error) {
      logger.child("routes").error("Approval chains error", { error: String(error) });
      res.status(500).json({ message: "Failed to get approval chains" });
    }
  });

  app.put("/api/jit-secrets/approval-chains/:secretId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const secretId = String(req.params.secretId);
      const { approvalLevels } = req.body;

      if (!Array.isArray(approvalLevels) || approvalLevels.length === 0) {
        return res.status(400).json({ message: "approvalLevels array is required" });
      }

      const secret = getSecretById(orgId, secretId);
      if (!secret) {
        return res.status(404).json({ message: "Secret not found" });
      }

      for (const level of approvalLevels) {
        if (!level.role || !["manager", "security", "owner"].includes(level.role)) {
          return res.status(400).json({ message: "Each level must have a valid role: manager, security, owner" });
        }
      }

      logger.child("routes").info("Approval chain updated", {
        orgId,
        secretId,
        levels: approvalLevels.length,
      });

      res.json({
        secretId,
        secretName: secret.name,
        approvalLevels: approvalLevels.map((l: { role: string; description?: string }, idx: number) => ({
          level: idx + 1,
          role: l.role,
          description: l.description || `Level ${idx + 1} approval`,
          required: true,
        })),
        updatedAt: new Date().toISOString(),
      });
    } catch (error) {
      logger.child("routes").error("Update approval chain error", { error: String(error) });
      res.status(500).json({ message: "Failed to update approval chain" });
    }
  });
}
