import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  boardSummaries,
  executiveMetrics,
  type BoardSummary,
  type InsertBoardSummary,
  type ExecutiveMetric,
  type InsertExecutiveMetric,
} from "@shared/schema";

// ─── Board Summaries ─────────────────────────────────────────────────────────
export async function getBoardSummaries(orgId: string): Promise<BoardSummary[]> {
  return db
    .select()
    .from(boardSummaries)
    .where(eq(boardSummaries.orgId, orgId))
    .orderBy(desc(boardSummaries.createdAt));
}

export async function getBoardSummary(id: string): Promise<BoardSummary | undefined> {
  const [summary] = await db.select().from(boardSummaries).where(eq(boardSummaries.id, id));
  return summary;
}

export async function createBoardSummary(data: InsertBoardSummary): Promise<BoardSummary> {
  const [created] = await db.insert(boardSummaries).values(data).returning();
  return created;
}

export async function updateBoardSummary(id: string, data: Partial<BoardSummary>): Promise<BoardSummary | undefined> {
  const [updated] = await db
    .update(boardSummaries)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(boardSummaries.id, id))
    .returning();
  return updated;
}

export async function deleteBoardSummary(id: string): Promise<void> {
  await db.delete(boardSummaries).where(eq(boardSummaries.id, id));
}

// ─── Executive Metrics ───────────────────────────────────────────────────────
export async function getExecutiveMetrics(orgId: string): Promise<ExecutiveMetric[]> {
  return db
    .select()
    .from(executiveMetrics)
    .where(eq(executiveMetrics.orgId, orgId))
    .orderBy(desc(executiveMetrics.createdAt));
}

export async function getExecutiveMetricsByCategory(orgId: string, category: string): Promise<ExecutiveMetric[]> {
  return db
    .select()
    .from(executiveMetrics)
    .where(and(eq(executiveMetrics.orgId, orgId), eq(executiveMetrics.category, category)))
    .orderBy(desc(executiveMetrics.createdAt));
}

export async function getExecutiveMetric(id: string): Promise<ExecutiveMetric | undefined> {
  const [metric] = await db.select().from(executiveMetrics).where(eq(executiveMetrics.id, id));
  return metric;
}

export async function createExecutiveMetric(data: InsertExecutiveMetric): Promise<ExecutiveMetric> {
  const [created] = await db.insert(executiveMetrics).values(data).returning();
  return created;
}

export async function updateExecutiveMetric(
  id: string,
  data: Partial<ExecutiveMetric>,
): Promise<ExecutiveMetric | undefined> {
  const [updated] = await db
    .update(executiveMetrics)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(executiveMetrics.id, id))
    .returning();
  return updated;
}

export async function deleteExecutiveMetric(id: string): Promise<void> {
  await db.delete(executiveMetrics).where(eq(executiveMetrics.id, id));
}
