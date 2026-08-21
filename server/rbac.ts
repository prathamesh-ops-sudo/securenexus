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
            await storage.createAuditLog({
              userId,
              userName: user.email || "unknown",
              action: "platform_admin_read_only_org_context",
              resourceType: "organization",
              resourceId: requestedOrgId,
              orgId: requestedOrgId,
              details: {
                route: req.path,
                method: req.method,
                selectedWithoutMembership: true,
                readOnly: true,
              },
            });
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
