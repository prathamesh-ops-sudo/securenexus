import type { Request, Response, NextFunction } from "express";
import { replyForbidden, replyUnauthenticated } from "../api-response";
import { logger } from "../logger";
import { storage } from "../storage";

const log = logger.child("super-admin");

export function requireSuperAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  if (!user?.id) {
    return replyUnauthenticated(res);
  }

  if (!user.isSuperAdmin) {
    log.warn("Super-admin access denied", {
      userId: user.id,
      email: user.email,
      route: req.path,
      method: req.method,
    });
    storage
      .createAuditLog({
        userId: user.id,
        userName: user.email || "unknown",
        action: "super_admin_access_denied",
        resourceType: "platform_admin",
        resourceId: req.path,
        details: { method: req.method },
      })
      .catch((err) => log.warn("Failed to audit super-admin denial", { error: String(err) }));
    return replyForbidden(res, "Platform super-admin access required");
  }

  next();
}
