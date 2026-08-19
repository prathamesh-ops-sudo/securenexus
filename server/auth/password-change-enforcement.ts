import type { NextFunction, Request, Response } from "express";
import { replyForbidden } from "../api-response";

const PASSWORD_CHANGE_ALLOWED_PATHS = new Set([
  "/api/auth/change-password",
  "/api/auth/me",
  "/api/auth/user",
  "/api/csrf-token",
  "/api/logout",
]);

export function passwordChangeRequiredMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (
    !req.isAuthenticated?.() ||
    !(req.user as { passwordChangeRequired?: boolean; passwordHash?: string | null } | undefined)
      ?.passwordChangeRequired ||
    !(req.user as { passwordHash?: string | null } | undefined)?.passwordHash ||
    PASSWORD_CHANGE_ALLOWED_PATHS.has(req.path)
  ) {
    next();
    return;
  }

  replyForbidden(res, "Password change required before using SecureNexus.", "PASSWORD_CHANGE_REQUIRED");
}
