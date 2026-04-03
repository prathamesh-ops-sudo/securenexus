import { type JitAccessRequest, type InsertJitAccessRequest, jitAccessRequests } from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

export async function getJitAccessRequests(orgId: string, limit = 100): Promise<JitAccessRequest[]> {
  return db
    .select()
    .from(jitAccessRequests)
    .where(eq(jitAccessRequests.orgId, orgId))
    .orderBy(desc(jitAccessRequests.createdAt))
    .limit(limit);
}

export async function getJitAccessRequest(id: string, orgId: string): Promise<JitAccessRequest | undefined> {
  const [request] = await db
    .select()
    .from(jitAccessRequests)
    .where(and(eq(jitAccessRequests.id, id), eq(jitAccessRequests.orgId, orgId)));
  return request;
}

export async function getJitAccessRequestsByRequester(
  orgId: string,
  requesterId: string,
  limit = 50,
): Promise<JitAccessRequest[]> {
  return db
    .select()
    .from(jitAccessRequests)
    .where(and(eq(jitAccessRequests.orgId, orgId), eq(jitAccessRequests.requesterId, requesterId)))
    .orderBy(desc(jitAccessRequests.createdAt))
    .limit(limit);
}

export async function createJitAccessRequest(data: InsertJitAccessRequest): Promise<JitAccessRequest> {
  const [created] = await db.insert(jitAccessRequests).values(data).returning();
  return created;
}

export async function updateJitAccessRequest(
  id: string,
  orgId: string,
  updates: Partial<InsertJitAccessRequest>,
): Promise<JitAccessRequest | undefined> {
  const [updated] = await db
    .update(jitAccessRequests)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(jitAccessRequests.id, id), eq(jitAccessRequests.orgId, orgId)))
    .returning();
  return updated;
}

export async function countJitAccessRequests(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(jitAccessRequests).where(eq(jitAccessRequests.orgId, orgId));
  return row?.total ?? 0;
}

export async function countPendingJitAccessRequests(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(jitAccessRequests)
    .where(and(eq(jitAccessRequests.orgId, orgId), eq(jitAccessRequests.status, "pending")));
  return row?.total ?? 0;
}
