import {
  type AdversarialTestExecution,
  type InsertAdversarialTestExecution,
  type AdversarialTestSchedule,
  type InsertAdversarialTestSchedule,
  type AdversarialRemediation,
  type InsertAdversarialRemediation,
  adversarialTestExecutions,
  adversarialTestSchedules,
  adversarialRemediations,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ─── Executions ──────────────────────────────────────────────────────────────

export async function getAdversarialExecutions(orgId: string, limit = 100): Promise<AdversarialTestExecution[]> {
  return db
    .select()
    .from(adversarialTestExecutions)
    .where(eq(adversarialTestExecutions.orgId, orgId))
    .orderBy(desc(adversarialTestExecutions.createdAt))
    .limit(limit);
}

export async function getAdversarialExecution(
  id: string,
  orgId: string,
): Promise<AdversarialTestExecution | undefined> {
  const [row] = await db
    .select()
    .from(adversarialTestExecutions)
    .where(and(eq(adversarialTestExecutions.id, id), eq(adversarialTestExecutions.orgId, orgId)));
  return row;
}

export async function createAdversarialExecution(
  data: InsertAdversarialTestExecution,
): Promise<AdversarialTestExecution> {
  const [created] = await db.insert(adversarialTestExecutions).values(data).returning();
  return created;
}

export async function updateAdversarialExecution(
  id: string,
  orgId: string,
  updates: Partial<InsertAdversarialTestExecution>,
): Promise<AdversarialTestExecution | undefined> {
  const [updated] = await db
    .update(adversarialTestExecutions)
    .set(updates)
    .where(and(eq(adversarialTestExecutions.id, id), eq(adversarialTestExecutions.orgId, orgId)))
    .returning();
  return updated;
}

export async function countAdversarialExecutions(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(adversarialTestExecutions)
    .where(eq(adversarialTestExecutions.orgId, orgId));
  return row?.total ?? 0;
}

// ─── Schedules ───────────────────────────────────────────────────────────────

export async function getAdversarialSchedules(orgId: string): Promise<AdversarialTestSchedule[]> {
  return db
    .select()
    .from(adversarialTestSchedules)
    .where(eq(adversarialTestSchedules.orgId, orgId))
    .orderBy(desc(adversarialTestSchedules.createdAt));
}

export async function getAdversarialSchedule(id: string, orgId: string): Promise<AdversarialTestSchedule | undefined> {
  const [row] = await db
    .select()
    .from(adversarialTestSchedules)
    .where(and(eq(adversarialTestSchedules.id, id), eq(adversarialTestSchedules.orgId, orgId)));
  return row;
}

export async function createAdversarialSchedule(data: InsertAdversarialTestSchedule): Promise<AdversarialTestSchedule> {
  const [created] = await db.insert(adversarialTestSchedules).values(data).returning();
  return created;
}

export async function updateAdversarialSchedule(
  id: string,
  orgId: string,
  updates: Partial<InsertAdversarialTestSchedule>,
): Promise<AdversarialTestSchedule | undefined> {
  const [updated] = await db
    .update(adversarialTestSchedules)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(adversarialTestSchedules.id, id), eq(adversarialTestSchedules.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteAdversarialSchedule(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(adversarialTestSchedules)
    .where(and(eq(adversarialTestSchedules.id, id), eq(adversarialTestSchedules.orgId, orgId)))
    .returning();
  return result.length > 0;
}

// ─── Remediations ────────────────────────────────────────────────────────────

export async function getAdversarialRemediations(orgId: string, status?: string): Promise<AdversarialRemediation[]> {
  const base = eq(adversarialRemediations.orgId, orgId);
  const where = status ? and(base, eq(adversarialRemediations.status, status)) : base;
  return db.select().from(adversarialRemediations).where(where).orderBy(desc(adversarialRemediations.createdAt));
}

export async function getAdversarialRemediation(
  id: string,
  orgId: string,
): Promise<AdversarialRemediation | undefined> {
  const [row] = await db
    .select()
    .from(adversarialRemediations)
    .where(and(eq(adversarialRemediations.id, id), eq(adversarialRemediations.orgId, orgId)));
  return row;
}

export async function createAdversarialRemediation(
  data: InsertAdversarialRemediation,
): Promise<AdversarialRemediation> {
  const [created] = await db.insert(adversarialRemediations).values(data).returning();
  return created;
}

export async function updateAdversarialRemediation(
  id: string,
  orgId: string,
  updates: Partial<InsertAdversarialRemediation>,
): Promise<AdversarialRemediation | undefined> {
  const [updated] = await db
    .update(adversarialRemediations)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(adversarialRemediations.id, id), eq(adversarialRemediations.orgId, orgId)))
    .returning();
  return updated;
}
