import { Request, Response, NextFunction } from "express";
import { storage } from "./storage";
import { ROLE_PERMISSIONS } from "@shared/schema";
import { replyUnauthenticated, replyForbidden, replyInternal, ERROR_CODES } from "./api-response";
import { logger } from "./logger";

const log = logger.child("rbac");

const ROLE_HIERARCHY: Record<string, number> = {
  owner: 4,
  admin: 3,
  analyst: 2,
  read_only: 1,
};

const READ_ONLY_ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const READ_ONLY_AUDIT_SESSION_KEY = "platformAdminReadOnlyOrganizations";
const READ_ONLY_AUDIT_DEDUPE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const READ_ONLY_AUDIT_DEDUPE_MAX = 10_000;

const readOnlyAuditInFlight = new Map<string, Promise<void>>();
const readOnlyAuditDedupe = new Map<string, number>();

function readOnlyAuditKey(req: Request, orgId: string): string | null {
  const sessionId = (req as any).sessionID;
  return typeof sessionId === "string" && sessionId ? `${sessionId}:${orgId}` : null;
}

function pruneReadOnlyAuditDedupe(now: number): void {
  for (const [key, expiresAt] of Array.from(readOnlyAuditDedupe.entries())) {
    if (expiresAt <= now) readOnlyAuditDedupe.delete(key);
  }
  if (readOnlyAuditDedupe.size <= READ_ONLY_AUDIT_DEDUPE_MAX) return;
  const oldest = Array.from(readOnlyAuditDedupe.entries()).sort((a, b) => a[1] - b[1]);
  for (const [key] of oldest.slice(0, readOnlyAuditDedupe.size - READ_ONLY_AUDIT_DEDUPE_MAX)) {
    readOnlyAuditDedupe.delete(key);
  }
}

function markReadOnlyAuditRecorded(req: Request, userId: string, orgId: string): void {
  const session = (req as any).session;
  if (session) {
    const recordedOrganizations = session[READ_ONLY_AUDIT_SESSION_KEY] || {};
    recordedOrganizations[orgId] = true;
    session[READ_ONLY_AUDIT_SESSION_KEY] = recordedOrganizations;
  }
  const now = Date.now();
  pruneReadOnlyAuditDedupe(now);
  const key = readOnlyAuditKey(req, orgId);
  if (key) readOnlyAuditDedupe.set(key, now + READ_ONLY_AUDIT_DEDUPE_TTL_MS);
}

function hasReadOnlyAuditRecorded(req: Request, orgId: string): boolean {
  const session = (req as any).session;
  if (session?.[READ_ONLY_AUDIT_SESSION_KEY]?.[orgId]) return true;
  const key = readOnlyAuditKey(req, orgId);
  if (!key) return false;
  const expiresAt = readOnlyAuditDedupe.get(key);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    readOnlyAuditDedupe.delete(key);
    return false;
  }
  return true;
}

async function auditReadOnlyPlatformContext(
  req: Request,
  userId: string,
  userName: string,
  orgId: string,
): Promise<void> {
  if (hasReadOnlyAuditRecorded(req, orgId)) return;

  const key = readOnlyAuditKey(req, orgId);
  if (!key) {
    await storage.createAuditLog({
      userId,
      userName,
      action: "platform_admin_read_only_org_context",
      resourceType: "organization",
      resourceId: orgId,
      orgId,
      details: {
        route: req.path,
        method: req.method,
        selectedWithoutMembership: true,
        readOnly: true,
      },
    });
    return;
  }
  let auditPromise = readOnlyAuditInFlight.get(key);
  if (!auditPromise) {
    auditPromise = storage
      .createAuditLog({
        userId,
        userName,
        action: "platform_admin_read_only_org_context",
        resourceType: "organization",
        resourceId: orgId,
        orgId,
        details: {
          route: req.path,
          method: req.method,
          selectedWithoutMembership: true,
          readOnly: true,
        },
      })
      .then(() => undefined);
    readOnlyAuditInFlight.set(key, auditPromise);
  }

  try {
    await auditPromise;
    markReadOnlyAuditRecorded(req, userId, orgId);
  } finally {
    if (readOnlyAuditInFlight.get(key) === auditPromise) {
      readOnlyAuditInFlight.delete(key);
    }
  }
}

export async function resolveOrgContext(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  if (!user?.id) {
    return replyUnauthenticated(res);
  }

  const userId = user.id;
  const memberships = await storage.getUserMemberships(userId);
  const activeMemberships = memberships.filter((m) => m.status === "active");
  const rawRequestedOrgId = req.headers["x-org-id"];
  const hasExplicitOrgSelection = rawRequestedOrgId !== undefined;
  const requestedOrgId =
    typeof rawRequestedOrgId === "string"
      ? rawRequestedOrgId.trim() || ""
      : rawRequestedOrgId === undefined
        ? undefined
        : "";
  const previousOrgId = (req as any).user?.orgId as string | undefined;

  if (hasExplicitOrgSelection && !requestedOrgId) {
    log.warn("Org access denied: invalid organization selector", {
      userId,
      route: req.path,
      method: req.method,
    });
    storage
      .createAuditLog({
        userId,
        userName: user.email || "unknown",
        action: "org_access_denied",
        resourceType: "organization",
        details: { route: req.path, method: req.method, reason: "invalid_org_selector" },
      })
      .catch((err) => log.warn("Failed to audit invalid org selector", { error: String(err) }));
    return replyForbidden(res, "Invalid organization selector", ERROR_CODES.ORG_ACCESS_DENIED);
  }

  if (!requestedOrgId && ((req as any).user?.isSuperAdmin || activeMemberships.length > 1)) {
    const reason = (req as any).user?.isSuperAdmin
      ? "platform_admin_requires_explicit_org"
      : "multiple_active_memberships";
    log.warn("Org access denied: explicit organization selector required", {
      userId,
      route: req.path,
      method: req.method,
      reason,
    });
    storage
      .createAuditLog({
        userId,
        userName: user.email || "unknown",
        action: "org_access_denied",
        resourceType: "organization",
        details: { route: req.path, method: req.method, reason },
      })
      .catch((err) => log.warn("Failed to audit missing organization selector", { error: String(err) }));
    return replyForbidden(
      res,
      "An explicit organization selection is required for this request.",
      ERROR_CODES.ORG_MEMBERSHIP_REQUIRED,
    );
  }

  if (!requestedOrgId && activeMemberships.length === 0) {
    (req as any).orgId = null;
    (req as any).orgRole = null;
    (req as any).membership = null;
    (req as any).orgReadOnly = false;
    return next();
  }

  let membership;
  let isReadOnlyPlatformContext = false;
  if (requestedOrgId) {
    membership = activeMemberships.find((m) => m.orgId === requestedOrgId);
    if (!membership) {
      if ((req as any).user?.isSuperAdmin) {
        const organization = await storage.getOrganization(requestedOrgId);
        if (organization && !organization.deletedAt) {
          isReadOnlyPlatformContext = true;
          log.info("Platform admin selected organization without membership", {
            userId,
            orgId: requestedOrgId,
            route: req.path,
            method: req.method,
          });
          try {
            await auditReadOnlyPlatformContext(req, userId, user.email || "unknown", requestedOrgId);
          } catch (err) {
            log.error("Failed to audit platform admin read-only org context", { error: String(err) });
            return replyInternal(res, "Unable to establish an auditable organization context");
          }
        }
      }

      if (isReadOnlyPlatformContext) {
        (req as any).orgId = requestedOrgId;
        (req as any).orgRole = "read_only";
        (req as any).membership = null;
        (req as any).orgReadOnly = true;
        if (!READ_ONLY_ALLOWED_METHODS.has(req.method.toUpperCase())) {
          log.warn("Write denied in platform admin read-only org context", {
            userId,
            orgId: requestedOrgId,
            route: req.path,
            method: req.method,
          });
          return replyForbidden(
            res,
            "Write operations are unavailable while viewing an organization read-only.",
            ERROR_CODES.READ_ONLY_CONTEXT,
          );
        }
        return next();
      }

      log.warn("Org access denied: user attempted access to non-member org", {
        userId,
        attemptedOrgId: requestedOrgId,
        route: req.path,
        method: req.method,
      });
      storage
        .createAuditLog({
          userId,
          userName: user.email || "unknown",
          action: "org_access_denied",
          resourceType: "organization",
          resourceId: requestedOrgId,
          details: { route: req.path, method: req.method },
        })
        .catch((err) => log.warn("Failed to audit org access denial", { error: String(err) }));
      return replyForbidden(res, "You do not have access to this organization", ERROR_CODES.ORG_ACCESS_DENIED);
    }
  } else {
    membership = activeMemberships[0];
  }

  if (previousOrgId && previousOrgId !== membership.orgId) {
    log.info("Org context switch detected", {
      userId,
      previousOrgId,
      newOrgId: membership.orgId,
      route: req.path,
    });
    storage
      .createAuditLog({
        userId,
        userName: user.email || "unknown",
        action: "org_context_switch",
        resourceType: "organization",
        resourceId: membership.orgId,
        details: { previousOrgId, newOrgId: membership.orgId, route: req.path },
      })
      .catch((err) => log.warn("Failed to audit org context switch", { error: String(err) }));
  }

  (req as any).orgId = membership.orgId;
  // Superadmins get owner-level permissions regardless of their org membership role
  (req as any).orgRole = (req as any).user?.isSuperAdmin ? "owner" : membership.role;
  (req as any).membership = membership;
  (req as any).orgReadOnly = false;
  next();
}

export function requireOrgId(req: Request, res: Response, next: NextFunction) {
  if ((req as any).orgReadOnly && !READ_ONLY_ALLOWED_METHODS.has(req.method.toUpperCase())) {
    return replyForbidden(
      res,
      "Write operations are unavailable while viewing an organization read-only.",
      ERROR_CODES.READ_ONLY_CONTEXT,
    );
  }
  const orgId = (req as any).orgId;
  if (!orgId || typeof orgId !== "string") {
    const userId = (req as any).user?.id || "anonymous";
    log.warn("Org context missing on org-scoped route", {
      userId,
      route: req.path,
      method: req.method,
    });
    storage
      .createAuditLog({
        userId,
        userName: (req as any).user?.email || "unknown",
        action: "org_context_missing",
        resourceType: "route",
        resourceId: req.path,
        details: { method: req.method },
      })
      .catch((err) => log.warn("Failed to audit org context missing", { error: String(err) }));
    return replyForbidden(
      res,
      "Organization context is required for this endpoint. Join or select an organization first.",
      ERROR_CODES.ORG_MEMBERSHIP_REQUIRED,
    );
  }
  next();
}

export function requireOrgRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const role = (req as any).orgRole;
    if (!role) {
      return replyForbidden(res, "No organization membership found", ERROR_CODES.ORG_MEMBERSHIP_REQUIRED);
    }
    if (!allowedRoles.includes(role)) {
      log.warn("RBAC role check failed", { userRole: role, allowedRoles, route: req.path, method: req.method });
      return replyForbidden(res, "Forbidden");
    }
    next();
  };
}

export function requireMinRole(minRole: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const role = (req as any).orgRole;
    if (!role) {
      return replyForbidden(res, "No organization membership found", ERROR_CODES.ORG_MEMBERSHIP_REQUIRED);
    }
    const userLevel = ROLE_HIERARCHY[role] || 0;
    const requiredLevel = ROLE_HIERARCHY[minRole] || 0;
    if (userLevel < requiredLevel) {
      log.warn("RBAC min-role check failed", { userRole: role, minRole, route: req.path, method: req.method });
      return replyForbidden(res, "Forbidden");
    }
    next();
  };
}

export function requirePermission(scope: string, action: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const role = (req as any).orgRole;
    if (!role) {
      return replyForbidden(res, "No organization membership found", ERROR_CODES.ORG_MEMBERSHIP_REQUIRED);
    }
    const rolePerms = ROLE_PERMISSIONS[role];
    if (!rolePerms || !rolePerms[scope] || !rolePerms[scope].includes(action)) {
      log.warn("RBAC permission check failed", { userRole: role, scope, action, route: req.path, method: req.method });
      return replyForbidden(res, "Insufficient permissions", ERROR_CODES.PERMISSION_DENIED);
    }
    next();
  };
}
