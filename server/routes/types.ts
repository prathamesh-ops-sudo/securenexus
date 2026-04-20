import type { Request } from "express";

/**
 * Express `Request` variant that exposes the authenticated user attached by
 * the `isAuthenticated` middleware stack in server/auth.
 *
 * Previously redeclared ad-hoc in multiple route modules with slightly
 * different subsets of fields (`{id, orgId, role}` vs `{id, email}`), which
 * caused drift between handlers. This is the canonical superset — every
 * field is optional so existing usages continue to typecheck unchanged.
 *
 * NOTE: Server-only type. Do NOT import from client code.
 */
export interface RequestWithUser extends Request {
  user?: {
    id?: string;
    orgId?: string;
    role?: string;
    email?: string;
    firstName?: string;
    lastName?: string;
  };
}
