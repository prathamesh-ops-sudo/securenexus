import { Request, Response, NextFunction } from "express";
import { storage } from "./storage";
import { ROLE_PERMISSIONS } from "@shared/schema";
import {
  replyUnauthenticated,
  replyForbidden,
  ERROR_CODES,
} from "./api-response";
import { logger } from "./logger";

const log = logger.child("rbac");

const ROLE_HIERARCHY: Record<string, number> = {
  owner: 4,
  admin: 3,
  analyst: 2,
  read_only: 1,
};

export async function resolveOrgContext(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  if (!user?.id) {
    return replyUnauthenticated(res);
  }

  const userId = user.id;
  const memberships = await storage.getUserMemberships(userId);
  const activeMemberships = memberships.filter(m => m.status === "active");

  if (activeMemberships.length === 0) {
    (req as any).orgId = null;
    (req as any).orgRole = null;
    (req as any).membership = null;
    return next();
  }

  const requestedOrgId = req.headers["x-org-id"] as string | undefined;
  const previousOrgId = (req as any).user?.orgId as string | undefined;

  let membership;
  if (requestedOrgId) {
    membership = activeMemberships.find(m => m.orgId === requestedOrgId);
    if (!membership) {
      log.warn("Org access denied: user attempted access to non-member org", {
        userId,
        attemptedOrgId: requestedOrgId,
        route: req.path,
        method: req.method,
      });
      storage.createAuditLog({
        userId,
        userName: user.email || "unknown",
        action: "org_access_denied",
        resourceType: "organization",
        resourceId: requestedOrgId,
        details: { route: req.path, method: req.method },
      }).catch((err) => log.warn("Failed to audit org access denial", { error: String(err) }));
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
    storage.createAuditLog({
      userId,
      userName: user.email || "unknown",
      action: "org_context_switch",
      resourceType: "organization",
      resourceId: membership.orgId,
      details: { previousOrgId, newOrgId: membership.orgId, route: req.path },
    }).catch((err) => log.warn("Failed to audit org context switch", { error: String(err) }));
  }

  (req as any).orgId = membership.orgId;
  (req as any).orgRole = membership.role;
  (req as any).membership = membership;
  next();
}

export function requireOrgId(req: Request, res: Response, next: NextFunction) {
  const orgId = (req as any).orgId;
  if (!orgId || typeof orgId !== "string") {
    const userId = (req as any).user?.id || "anonymous";
    log.warn("Org context missing on org-scoped route", {
      userId,
      route: req.path,
      method: req.method,
    });
    storage.createAuditLog({
      userId,
      userName: (req as any).user?.email || "unknown",
      action: "org_context_missing",
      resourceType: "route",
      resourceId: req.path,
      details: { method: req.method },
    }).catch((err) => log.warn("Failed to audit org context missing", { error: String(err) }));
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
      return replyForbidden(res, `Requires one of: ${allowedRoles.join(", ")}`);
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
      return replyForbidden(res, `Requires at least ${minRole} role`);
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
      return replyForbidden(res, `Insufficient permissions: requires ${scope}:${action}`, ERROR_CODES.PERMISSION_DENIED);
    }
    next();
  };
}
