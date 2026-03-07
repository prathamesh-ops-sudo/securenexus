import type { Express } from "express";
import { logger, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getSecrets,
  getSecretById,
  registerSecret,
  requestAccess,
  approveAccessRequest,
  denyAccessRequest,
  releaseAccess,
  getAccessRequests,
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
  getStats,
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
  app.get("/api/jit-secrets/secrets", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const secrets = getSecrets(orgId);
      res.json(secrets);
    } catch (error) {
      logger.child("routes").error("Get secrets error", { error: String(error) });
      res.status(500).json({ message: "Failed to get secrets" });
    }
  });

  app.get("/api/jit-secrets/secrets/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }

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

  app.get("/api/jit-secrets/access-requests", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const requests = getAccessRequests(orgId);
      res.json(requests);
    } catch (error) {
      logger.child("routes").error("Get access requests error", { error: String(error) });
      res.status(500).json({ message: "Failed to get access requests" });
    }
  });

  app.post("/api/jit-secrets/access-requests", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }

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

      const request = requestAccess(orgId, {
        secretId: String(secretId),
        requesterId: String(requesterId),
        requesterName: String(requesterName),
        reason: String(reason).trim(),
        durationMinutes,
        approverRole,
      });

      res.status(201).json(request);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("SECRET_NOT_FOUND")) {
        return res.status(404).json({ message: "Secret not found" });
      }
      if (errMsg.includes("INVALID_DURATION")) {
        return res.status(400).json({ message: "Duration must be 1-1440 minutes" });
      }
      if (errMsg.includes("REASON_TOO_SHORT")) {
        return res.status(400).json({ message: "Reason must be at least 10 characters" });
      }
      logger.child("routes").error("Request access error", { error: errMsg });
      res.status(500).json({ message: "Failed to request access" });
    }
  });

  app.post("/api/jit-secrets/access-requests/:id/approve", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const { approverName } = req.body;
      if (!approverName || typeof approverName !== "string") {
        return res.status(400).json({ message: "approverName is required" });
      }
      const request = approveAccessRequest(orgId, id, String(approverName));
      res.json(request);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("REQUEST_NOT_FOUND")) {
        return res.status(404).json({ message: "Access request not found" });
      }
      if (errMsg.includes("REQUEST_NOT_PENDING")) {
        return res.status(400).json({ message: "Request is not in pending status" });
      }
      logger.child("routes").error("Approve access error", { error: errMsg });
      res.status(500).json({ message: "Failed to approve access request" });
    }
  });

  app.post("/api/jit-secrets/access-requests/:id/deny", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const { denierName, reason } = req.body;
      if (!denierName || typeof denierName !== "string") {
        return res.status(400).json({ message: "denierName is required" });
      }
      if (!reason || typeof reason !== "string") {
        return res.status(400).json({ message: "reason is required" });
      }
      const request = denyAccessRequest(orgId, id, String(denierName), String(reason));
      res.json(request);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("REQUEST_NOT_FOUND")) {
        return res.status(404).json({ message: "Access request not found" });
      }
      if (errMsg.includes("REQUEST_NOT_PENDING")) {
        return res.status(400).json({ message: "Request is not in pending status" });
      }
      logger.child("routes").error("Deny access error", { error: errMsg });
      res.status(500).json({ message: "Failed to deny access request" });
    }
  });

  app.post("/api/jit-secrets/access-requests/:id/release", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const id = String(req.params.id);
      const { releaserName } = req.body;
      if (!releaserName || typeof releaserName !== "string") {
        return res.status(400).json({ message: "releaserName is required" });
      }
      const request = releaseAccess(orgId, id, String(releaserName));
      res.json(request);
    } catch (error) {
      const errMsg = String(error);
      if (errMsg.includes("REQUEST_NOT_FOUND")) {
        return res.status(404).json({ message: "Access request not found" });
      }
      if (errMsg.includes("REQUEST_NOT_ACTIVE")) {
        return res.status(400).json({ message: "Request is not active" });
      }
      logger.child("routes").error("Release access error", { error: errMsg });
      res.status(500).json({ message: "Failed to release access" });
    }
  });

  app.get("/api/jit-secrets/shares", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const shares = getShares(orgId);
      res.json(shares);
    } catch (error) {
      logger.child("routes").error("Get shares error", { error: String(error) });
      res.status(500).json({ message: "Failed to get shares" });
    }
  });

  app.post("/api/jit-secrets/shares", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }

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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
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

  app.post("/api/jit-secrets/break-glass", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }

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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const entries = getBreakGlassEntries(orgId);
      res.json(entries);
    } catch (error) {
      logger.child("routes").error("Get break glass error", { error: String(error) });
      res.status(500).json({ message: "Failed to get break-glass entries" });
    }
  });

  app.post("/api/jit-secrets/ownership/transfer", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }

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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }

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
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const transfers = getTransfers(orgId);
      res.json(transfers);
    } catch (error) {
      logger.child("routes").error("Get transfers error", { error: String(error) });
      res.status(500).json({ message: "Failed to get transfers" });
    }
  });

  app.get("/api/jit-secrets/audit-log", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const log = getAuditLog(orgId);
      res.json(log);
    } catch (error) {
      logger.child("routes").error("Get audit log error", { error: String(error) });
      res.status(500).json({ message: "Failed to get audit log" });
    }
  });

  app.get("/api/jit-secrets/stats", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = typeof req.query.orgId === "string" ? req.query.orgId : "__default__";
      }
      const stats = getStats(orgId);
      res.json(stats);
    } catch (error) {
      logger.child("routes").error("Get stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to get stats" });
    }
  });
}
