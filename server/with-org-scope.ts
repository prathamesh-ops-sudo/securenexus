import { logger } from "./logger";
import type { SQL } from "drizzle-orm";
import { eq, and } from "drizzle-orm";
import type { PgColumn, PgTable } from "drizzle-orm/pg-core";

const log = logger.child("org-scope");

export class OrgScopeMissingError extends Error {
  constructor(caller: string) {
    super(`orgId is required for ${caller} but was not provided`);
    this.name = "OrgScopeMissingError";
  }
}

export function requireOrgScope(orgId: string | undefined | null, caller: string): string {
  if (!orgId || typeof orgId !== "string" || orgId.trim().length === 0) {
    log.error("Org scope missing on tenant-scoped query", { caller });
    throw new OrgScopeMissingError(caller);
  }
  return orgId;
}

export function withOrgFilter(
  orgIdColumn: PgColumn,
  orgId: string | undefined | null,
  caller: string,
  additionalConditions?: SQL[],
): SQL | undefined {
  const scoped = requireOrgScope(orgId, caller);
  const orgCondition = eq(orgIdColumn, scoped);
  if (additionalConditions && additionalConditions.length > 0) {
    return and(orgCondition, ...additionalConditions);
  }
  return orgCondition;
}
