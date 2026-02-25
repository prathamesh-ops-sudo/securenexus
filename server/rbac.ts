import { Request, Response, NextFunction } from "express";
import { storage } from "./storage";
import { ROLE_PERMISSIONS } from "@shared/schema";
import {
  replyUnauthenticated,
  replyForbidden,
  ERROR_CODES,
} from "./api-response";

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

  let membership;
  if (requestedOrgId) {
    membership = activeMemberships.find(m => m.orgId === requestedOrgId);
    if (!membership) {
      return replyForbidden(res, "You do not have access to this organization", ERROR_CODES.ORG_ACCESS_DENIED);
    }
  } else {
    membership = activeMemberships[0];
  }

  (req as any).orgId = membership.orgId;
  (req as any).orgRole = membership.role;
  (req as any).membership = membership;
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
