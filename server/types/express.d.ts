/**
 * Global augmentations for Express.
 *
 * Middleware in this codebase decorates `req` with several fields that are not
 * part of `express`'s built-in types. Declaring them here removes the need for
 * `(req as any).orgId` style casts at call sites. Access is still optional —
 * handlers should guard with `requireOrgId` / `isAuthenticated` before use.
 */

import type { User as DbUser } from "@shared/models/auth";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    // Passport's `req.user` shape. Kept intentionally loose at the boundary
    // because `passport-*` strategies deserialize into arbitrary shapes; we
    // always intersect with the DB `User` row shape, which is the canonical
    // source of truth for user identity fields.
    interface User extends Partial<DbUser> {
      id?: string;
      orgId?: string | null;
      orgRole?: string | null;
      role?: string;
      email?: string | null;
      isSuperAdmin?: boolean;
    }

    interface Request {
      /** Resolved active org id from `resolveOrgContext` middleware. */
      orgId?: string | null;
      /** Resolved org role from `resolveOrgContext` middleware. */
      orgRole?: string | null;
      /** Resolved membership row from `resolveOrgContext` middleware. */
      membership?: {
        orgId: string;
        userId: string;
        role: string;
        status: string;
        customRoleId?: string | null;
      } | null;
      /** API-key auth context set by `apiKeyAuth` middleware. */
      apiKey?: {
        id: string;
        orgId: string;
        scopes: string[];
      };
      /** Correlation id set by `correlationIdMiddleware`. */
      traceId?: string;
      /** Request id set by request-lifecycle middleware. */
      requestId?: string;
    }
  }
}

export {};
