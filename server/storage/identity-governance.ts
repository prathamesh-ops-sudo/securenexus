import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  accessReviews,
  identityEntitlements,
  type AccessReview,
  type InsertAccessReview,
  type IdentityEntitlement,
  type InsertIdentityEntitlement,
} from "@shared/schema";

// ─── Access Reviews ──────────────────────────────────────────────────────────
export async function getAccessReviews(orgId: string): Promise<AccessReview[]> {
  return db.select().from(accessReviews).where(eq(accessReviews.orgId, orgId)).orderBy(desc(accessReviews.createdAt));
}

export async function getAccessReview(id: string): Promise<AccessReview | undefined> {
  const [review] = await db.select().from(accessReviews).where(eq(accessReviews.id, id));
  return review;
}

export async function createAccessReview(data: InsertAccessReview): Promise<AccessReview> {
  const [created] = await db.insert(accessReviews).values(data).returning();
  return created;
}

export async function updateAccessReview(id: string, data: Partial<AccessReview>): Promise<AccessReview | undefined> {
  const [updated] = await db
    .update(accessReviews)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(accessReviews.id, id))
    .returning();
  return updated;
}

export async function deleteAccessReview(id: string): Promise<void> {
  await db.delete(accessReviews).where(eq(accessReviews.id, id));
}

// ─── Entitlements ────────────────────────────────────────────────────────────
export async function getIdentityEntitlements(orgId: string): Promise<IdentityEntitlement[]> {
  return db
    .select()
    .from(identityEntitlements)
    .where(eq(identityEntitlements.orgId, orgId))
    .orderBy(desc(identityEntitlements.createdAt));
}

export async function getIdentityEntitlementsByUser(orgId: string, userId: string): Promise<IdentityEntitlement[]> {
  return db
    .select()
    .from(identityEntitlements)
    .where(and(eq(identityEntitlements.orgId, orgId), eq(identityEntitlements.userId, userId)))
    .orderBy(desc(identityEntitlements.createdAt));
}

export async function getIdentityEntitlement(id: string): Promise<IdentityEntitlement | undefined> {
  const [entitlement] = await db.select().from(identityEntitlements).where(eq(identityEntitlements.id, id));
  return entitlement;
}

export async function createIdentityEntitlement(data: InsertIdentityEntitlement): Promise<IdentityEntitlement> {
  const [created] = await db.insert(identityEntitlements).values(data).returning();
  return created;
}

export async function updateIdentityEntitlement(
  id: string,
  data: Partial<IdentityEntitlement>,
): Promise<IdentityEntitlement | undefined> {
  const [updated] = await db
    .update(identityEntitlements)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(identityEntitlements.id, id))
    .returning();
  return updated;
}

export async function deleteIdentityEntitlement(id: string): Promise<void> {
  await db.delete(identityEntitlements).where(eq(identityEntitlements.id, id));
}
