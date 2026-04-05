import {
  type JitManagedSecret,
  type InsertJitManagedSecret,
  type JitSecretAccessRequest,
  type InsertJitSecretAccessRequest,
  type JitExternalShare,
  type InsertJitExternalShare,
  type JitOwnershipTransfer,
  type InsertJitOwnershipTransfer,
  type JitBreakGlassAccessEntry,
  type InsertJitBreakGlassAccessEntry,
  type JitAuditLogEntry,
  type InsertJitAuditLogEntry,
  jitManagedSecrets,
  jitSecretAccessRequests,
  jitExternalShares,
  jitOwnershipTransfers,
  jitBreakGlassAccess,
  jitAuditLog,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq, sql } from "drizzle-orm";

// ─── Managed Secrets ────────────────────────────────────────────────────────

export async function getJitManagedSecrets(orgId: string): Promise<JitManagedSecret[]> {
  return db
    .select()
    .from(jitManagedSecrets)
    .where(eq(jitManagedSecrets.orgId, orgId))
    .orderBy(desc(jitManagedSecrets.createdAt));
}

export async function getJitManagedSecret(id: string, orgId: string): Promise<JitManagedSecret | undefined> {
  const [row] = await db
    .select()
    .from(jitManagedSecrets)
    .where(and(eq(jitManagedSecrets.id, id), eq(jitManagedSecrets.orgId, orgId)));
  return row;
}

export async function createJitManagedSecret(data: InsertJitManagedSecret): Promise<JitManagedSecret> {
  const [created] = await db.insert(jitManagedSecrets).values(data).returning();
  return created;
}

export async function updateJitManagedSecret(
  id: string,
  orgId: string,
  updates: Partial<InsertJitManagedSecret>,
): Promise<JitManagedSecret | undefined> {
  const [updated] = await db
    .update(jitManagedSecrets)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(jitManagedSecrets.id, id), eq(jitManagedSecrets.orgId, orgId)))
    .returning();
  return updated;
}

export async function incrementJitSecretAccessCount(id: string, orgId: string): Promise<void> {
  await db
    .update(jitManagedSecrets)
    .set({ accessCount: sql`${jitManagedSecrets.accessCount} + 1`, updatedAt: new Date() })
    .where(and(eq(jitManagedSecrets.id, id), eq(jitManagedSecrets.orgId, orgId)));
}

export async function countJitManagedSecrets(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(jitManagedSecrets).where(eq(jitManagedSecrets.orgId, orgId));
  return row?.total ?? 0;
}

// ─── Secret Access Requests ─────────────────────────────────────────────────

export async function getJitSecretAccessRequestsList(orgId: string): Promise<JitSecretAccessRequest[]> {
  return db
    .select()
    .from(jitSecretAccessRequests)
    .where(eq(jitSecretAccessRequests.orgId, orgId))
    .orderBy(desc(jitSecretAccessRequests.createdAt));
}

export async function getJitSecretAccessRequestById(
  id: string,
  orgId: string,
): Promise<JitSecretAccessRequest | undefined> {
  const [row] = await db
    .select()
    .from(jitSecretAccessRequests)
    .where(and(eq(jitSecretAccessRequests.id, id), eq(jitSecretAccessRequests.orgId, orgId)));
  return row;
}

export async function createJitSecretAccessRequestEntry(
  data: InsertJitSecretAccessRequest,
): Promise<JitSecretAccessRequest> {
  const [created] = await db.insert(jitSecretAccessRequests).values(data).returning();
  return created;
}

export async function updateJitSecretAccessRequestEntry(
  id: string,
  orgId: string,
  updates: Partial<InsertJitSecretAccessRequest>,
): Promise<JitSecretAccessRequest | undefined> {
  const [updated] = await db
    .update(jitSecretAccessRequests)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(jitSecretAccessRequests.id, id), eq(jitSecretAccessRequests.orgId, orgId)))
    .returning();
  return updated;
}

export async function countPendingJitSecretAccessRequests(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(jitSecretAccessRequests)
    .where(and(eq(jitSecretAccessRequests.orgId, orgId), eq(jitSecretAccessRequests.status, "pending")));
  return row?.total ?? 0;
}

// ─── External Shares ────────────────────────────────────────────────────────

export async function getJitExternalSharesList(orgId: string): Promise<JitExternalShare[]> {
  return db
    .select()
    .from(jitExternalShares)
    .where(eq(jitExternalShares.orgId, orgId))
    .orderBy(desc(jitExternalShares.createdAt));
}

export async function getJitExternalShare(id: string, orgId: string): Promise<JitExternalShare | undefined> {
  const [row] = await db
    .select()
    .from(jitExternalShares)
    .where(and(eq(jitExternalShares.id, id), eq(jitExternalShares.orgId, orgId)));
  return row;
}

export async function createJitExternalShareEntry(data: InsertJitExternalShare): Promise<JitExternalShare> {
  const [created] = await db.insert(jitExternalShares).values(data).returning();
  return created;
}

export async function updateJitExternalShareEntry(
  id: string,
  orgId: string,
  updates: Partial<InsertJitExternalShare>,
): Promise<JitExternalShare | undefined> {
  const [updated] = await db
    .update(jitExternalShares)
    .set(updates)
    .where(and(eq(jitExternalShares.id, id), eq(jitExternalShares.orgId, orgId)))
    .returning();
  return updated;
}

// ─── Ownership Transfers ────────────────────────────────────────────────────

export async function getJitOwnershipTransfersList(orgId: string): Promise<JitOwnershipTransfer[]> {
  return db
    .select()
    .from(jitOwnershipTransfers)
    .where(eq(jitOwnershipTransfers.orgId, orgId))
    .orderBy(desc(jitOwnershipTransfers.createdAt));
}

export async function createJitOwnershipTransferEntry(data: InsertJitOwnershipTransfer): Promise<JitOwnershipTransfer> {
  const [created] = await db.insert(jitOwnershipTransfers).values(data).returning();
  return created;
}

// ─── Break Glass Access ─────────────────────────────────────────────────────

export async function getJitBreakGlassEntriesList(orgId: string): Promise<JitBreakGlassAccessEntry[]> {
  return db
    .select()
    .from(jitBreakGlassAccess)
    .where(eq(jitBreakGlassAccess.orgId, orgId))
    .orderBy(desc(jitBreakGlassAccess.createdAt));
}

export async function getJitBreakGlassEntry(id: string, orgId: string): Promise<JitBreakGlassAccessEntry | undefined> {
  const [row] = await db
    .select()
    .from(jitBreakGlassAccess)
    .where(and(eq(jitBreakGlassAccess.id, id), eq(jitBreakGlassAccess.orgId, orgId)));
  return row;
}

export async function createJitBreakGlassEntry(
  data: InsertJitBreakGlassAccessEntry,
): Promise<JitBreakGlassAccessEntry> {
  const [created] = await db.insert(jitBreakGlassAccess).values(data).returning();
  return created;
}

export async function updateJitBreakGlassEntry(
  id: string,
  orgId: string,
  updates: Partial<InsertJitBreakGlassAccessEntry>,
): Promise<JitBreakGlassAccessEntry | undefined> {
  const [updated] = await db
    .update(jitBreakGlassAccess)
    .set(updates)
    .where(and(eq(jitBreakGlassAccess.id, id), eq(jitBreakGlassAccess.orgId, orgId)))
    .returning();
  return updated;
}

// ─── Audit Log ──────────────────────────────────────────────────────────────

export async function getJitAuditLogEntries(orgId: string, limit = 100): Promise<JitAuditLogEntry[]> {
  return db
    .select()
    .from(jitAuditLog)
    .where(eq(jitAuditLog.orgId, orgId))
    .orderBy(desc(jitAuditLog.createdAt))
    .limit(limit);
}

export async function createJitAuditLogEntry(data: InsertJitAuditLogEntry): Promise<JitAuditLogEntry> {
  const [created] = await db.insert(jitAuditLog).values(data).returning();
  return created;
}
