import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import { findingLineageRecords, type FindingLineageRecord, type InsertFindingLineageRecord } from "@shared/schema";

export async function getFindingLineageRecords(orgId: string): Promise<FindingLineageRecord[]> {
  return db
    .select()
    .from(findingLineageRecords)
    .where(eq(findingLineageRecords.orgId, orgId))
    .orderBy(desc(findingLineageRecords.createdAt));
}

export async function getFindingLineageRecord(id: string): Promise<FindingLineageRecord | undefined> {
  const [record] = await db.select().from(findingLineageRecords).where(eq(findingLineageRecords.id, id));
  return record;
}

export async function getFindingLineageByStatus(orgId: string, status: string): Promise<FindingLineageRecord[]> {
  return db
    .select()
    .from(findingLineageRecords)
    .where(and(eq(findingLineageRecords.orgId, orgId), eq(findingLineageRecords.status, status)))
    .orderBy(desc(findingLineageRecords.createdAt));
}

export async function getFindingLineageBySeverity(orgId: string, severity: string): Promise<FindingLineageRecord[]> {
  return db
    .select()
    .from(findingLineageRecords)
    .where(and(eq(findingLineageRecords.orgId, orgId), eq(findingLineageRecords.severity, severity)))
    .orderBy(desc(findingLineageRecords.createdAt));
}

export async function createFindingLineageRecord(data: InsertFindingLineageRecord): Promise<FindingLineageRecord> {
  const [created] = await db.insert(findingLineageRecords).values(data).returning();
  return created;
}

export async function updateFindingLineageRecord(
  id: string,
  data: Partial<FindingLineageRecord>,
): Promise<FindingLineageRecord | undefined> {
  const [updated] = await db
    .update(findingLineageRecords)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(findingLineageRecords.id, id))
    .returning();
  return updated;
}

export async function deleteFindingLineageRecord(id: string): Promise<void> {
  await db.delete(findingLineageRecords).where(eq(findingLineageRecords.id, id));
}
