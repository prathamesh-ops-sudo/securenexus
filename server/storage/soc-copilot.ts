import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  copilotTriages,
  copilotActions,
  copilotHypotheses,
  copilotFeedback,
  type CopilotTriage,
  type InsertCopilotTriage,
  type CopilotAction,
  type InsertCopilotAction,
  type CopilotHypothesis,
  type InsertCopilotHypothesis,
  type CopilotFeedbackRecord,
  type InsertCopilotFeedback,
} from "@shared/schema";

// ─── Triages ─────────────────────────────────────────────────────────────────
export async function getCopilotTriages(orgId: string): Promise<CopilotTriage[]> {
  return db
    .select()
    .from(copilotTriages)
    .where(eq(copilotTriages.orgId, orgId))
    .orderBy(desc(copilotTriages.createdAt));
}

export async function getCopilotTriage(id: string): Promise<CopilotTriage | undefined> {
  const [triage] = await db.select().from(copilotTriages).where(eq(copilotTriages.id, id));
  return triage;
}

export async function createCopilotTriage(data: InsertCopilotTriage): Promise<CopilotTriage> {
  const [created] = await db.insert(copilotTriages).values(data).returning();
  return created;
}

export async function updateCopilotTriage(
  id: string,
  data: Partial<CopilotTriage>,
): Promise<CopilotTriage | undefined> {
  const [updated] = await db
    .update(copilotTriages)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(copilotTriages.id, id))
    .returning();
  return updated;
}

// ─── Actions ─────────────────────────────────────────────────────────────────
export async function getCopilotActions(orgId: string): Promise<CopilotAction[]> {
  return db
    .select()
    .from(copilotActions)
    .where(eq(copilotActions.orgId, orgId))
    .orderBy(desc(copilotActions.createdAt));
}

export async function getCopilotActionsByTriage(orgId: string, triageId: string): Promise<CopilotAction[]> {
  return db
    .select()
    .from(copilotActions)
    .where(and(eq(copilotActions.orgId, orgId), eq(copilotActions.triageId, triageId)))
    .orderBy(desc(copilotActions.createdAt));
}

export async function getCopilotAction(id: string): Promise<CopilotAction | undefined> {
  const [action] = await db.select().from(copilotActions).where(eq(copilotActions.id, id));
  return action;
}

export async function createCopilotAction(data: InsertCopilotAction): Promise<CopilotAction> {
  const [created] = await db.insert(copilotActions).values(data).returning();
  return created;
}

export async function updateCopilotAction(
  id: string,
  data: Partial<CopilotAction>,
): Promise<CopilotAction | undefined> {
  const [updated] = await db
    .update(copilotActions)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(copilotActions.id, id))
    .returning();
  return updated;
}

// ─── Hypotheses ──────────────────────────────────────────────────────────────
export async function getCopilotHypotheses(orgId: string): Promise<CopilotHypothesis[]> {
  return db
    .select()
    .from(copilotHypotheses)
    .where(eq(copilotHypotheses.orgId, orgId))
    .orderBy(desc(copilotHypotheses.createdAt));
}

export async function getCopilotHypothesis(id: string): Promise<CopilotHypothesis | undefined> {
  const [hypothesis] = await db.select().from(copilotHypotheses).where(eq(copilotHypotheses.id, id));
  return hypothesis;
}

export async function createCopilotHypothesis(data: InsertCopilotHypothesis): Promise<CopilotHypothesis> {
  const [created] = await db.insert(copilotHypotheses).values(data).returning();
  return created;
}

export async function updateCopilotHypothesis(
  id: string,
  data: Partial<CopilotHypothesis>,
): Promise<CopilotHypothesis | undefined> {
  const [updated] = await db
    .update(copilotHypotheses)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(copilotHypotheses.id, id))
    .returning();
  return updated;
}

// ─── Feedback ────────────────────────────────────────────────────────────────
export async function getCopilotFeedback(orgId: string): Promise<CopilotFeedbackRecord[]> {
  return db
    .select()
    .from(copilotFeedback)
    .where(eq(copilotFeedback.orgId, orgId))
    .orderBy(desc(copilotFeedback.createdAt));
}

export async function createCopilotFeedbackEntry(data: InsertCopilotFeedback): Promise<CopilotFeedbackRecord> {
  const [created] = await db.insert(copilotFeedback).values(data).returning();
  return created;
}
