import {
  type EvidenceChainEntry,
  type EvidenceItem,
  type Incident,
  type InsertEvidenceChainEntry,
  type InsertEvidenceItem,
  type InsertInvestigationHypothesis,
  type InsertInvestigationTask,
  type InvestigationHypothesis,
  type InvestigationTask,
  evidenceChainEntries,
  evidenceItems,
  investigationHypotheses,
  investigationTasks,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, sql } from "drizzle-orm";

export async function getEvidenceItems(incidentId: string, orgId?: string): Promise<EvidenceItem[]> {
  const conditions: any[] = [eq(evidenceItems.incidentId, incidentId)];
  if (orgId) conditions.push(eq(evidenceItems.orgId, orgId));
  return db
    .select()
    .from(evidenceItems)
    .where(and(...conditions))
    .orderBy(desc(evidenceItems.createdAt));
}

export async function getEvidenceItem(id: string): Promise<EvidenceItem | undefined> {
  const [item] = await db.select().from(evidenceItems).where(eq(evidenceItems.id, id));
  return item;
}

export async function createEvidenceItem(item: InsertEvidenceItem): Promise<EvidenceItem> {
  const [created] = await db.insert(evidenceItems).values(item).returning();
  return created;
}

export async function deleteEvidenceItem(id: string): Promise<boolean> {
  const result = await db.delete(evidenceItems).where(eq(evidenceItems.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getHypotheses(incidentId: string, orgId?: string): Promise<InvestigationHypothesis[]> {
  const conditions: any[] = [eq(investigationHypotheses.incidentId, incidentId)];
  if (orgId) conditions.push(eq(investigationHypotheses.orgId, orgId));
  return db
    .select()
    .from(investigationHypotheses)
    .where(and(...conditions))
    .orderBy(desc(investigationHypotheses.createdAt));
}

export async function getHypothesis(id: string): Promise<InvestigationHypothesis | undefined> {
  const [hypothesis] = await db.select().from(investigationHypotheses).where(eq(investigationHypotheses.id, id));
  return hypothesis;
}

export async function createHypothesis(hypothesis: InsertInvestigationHypothesis): Promise<InvestigationHypothesis> {
  const [created] = await db.insert(investigationHypotheses).values(hypothesis).returning();
  return created;
}

export async function updateHypothesis(
  id: string,
  data: Partial<InvestigationHypothesis>,
): Promise<InvestigationHypothesis | undefined> {
  const [updated] = await db
    .update(investigationHypotheses)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(investigationHypotheses.id, id))
    .returning();
  return updated;
}

export async function deleteHypothesis(id: string): Promise<boolean> {
  const result = await db.delete(investigationHypotheses).where(eq(investigationHypotheses.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getInvestigationTasks(incidentId: string, orgId?: string): Promise<InvestigationTask[]> {
  const conditions: any[] = [eq(investigationTasks.incidentId, incidentId)];
  if (orgId) conditions.push(eq(investigationTasks.orgId, orgId));
  return db
    .select()
    .from(investigationTasks)
    .where(and(...conditions))
    .orderBy(desc(investigationTasks.createdAt));
}

export async function getInvestigationTask(id: string): Promise<InvestigationTask | undefined> {
  const [task] = await db.select().from(investigationTasks).where(eq(investigationTasks.id, id));
  return task;
}

export async function createInvestigationTask(task: InsertInvestigationTask): Promise<InvestigationTask> {
  const [created] = await db.insert(investigationTasks).values(task).returning();
  return created;
}

export async function updateInvestigationTask(
  id: string,
  data: Partial<InvestigationTask>,
): Promise<InvestigationTask | undefined> {
  const [updated] = await db
    .update(investigationTasks)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(investigationTasks.id, id))
    .returning();
  return updated;
}

export async function deleteInvestigationTask(id: string): Promise<boolean> {
  const result = await db.delete(investigationTasks).where(eq(investigationTasks.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getEvidenceChainEntries(incidentId: string, orgId?: string): Promise<EvidenceChainEntry[]> {
  const conditions = [eq(evidenceChainEntries.incidentId, incidentId)];
  if (orgId) conditions.push(eq(evidenceChainEntries.orgId, orgId));
  return db
    .select()
    .from(evidenceChainEntries)
    .where(and(...conditions))
    .orderBy(asc(evidenceChainEntries.sequenceNum));
}

export async function getEvidenceChainEntriesByOrg(
  orgId: string,
  limit: number = 100,
  offset: number = 0,
): Promise<EvidenceChainEntry[]> {
  return db
    .select()
    .from(evidenceChainEntries)
    .where(eq(evidenceChainEntries.orgId, orgId))
    .orderBy(desc(evidenceChainEntries.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function countEvidenceChainEntriesByOrg(orgId: string): Promise<number> {
  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(evidenceChainEntries)
    .where(eq(evidenceChainEntries.orgId, orgId));
  return Number(result?.count ?? 0);
}

export async function getEvidenceChainEntry(id: string): Promise<EvidenceChainEntry | undefined> {
  const [entry] = await db.select().from(evidenceChainEntries).where(eq(evidenceChainEntries.id, id));
  return entry;
}

export async function createEvidenceChainEntry(entry: InsertEvidenceChainEntry): Promise<EvidenceChainEntry> {
  const [created] = await db.insert(evidenceChainEntries).values(entry).returning();
  return created;
}

export async function getNextSequenceNum(incidentId: string): Promise<number> {
  const [result] = await db
    .select({ maxSeq: sql<number>`COALESCE(MAX(${evidenceChainEntries.sequenceNum}), 0)` })
    .from(evidenceChainEntries)
    .where(eq(evidenceChainEntries.incidentId, incidentId));
  return (result?.maxSeq ?? 0) + 1;
}

export async function getLatestChainHash(incidentId: string): Promise<string | null> {
  const [result] = await db
    .select({ hash: evidenceChainEntries.entryHash })
    .from(evidenceChainEntries)
    .where(eq(evidenceChainEntries.incidentId, incidentId))
    .orderBy(desc(evidenceChainEntries.sequenceNum))
    .limit(1);
  return result?.hash ?? null;
}

// ==========================================
// Incident Response Approvals
// ==========================================
