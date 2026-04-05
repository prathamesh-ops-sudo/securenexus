import { db } from "../db";
import { eq, and, desc } from "drizzle-orm";
import {
  promptAbTests,
  promptQualityScores,
  type PromptAbTest,
  type InsertPromptAbTest,
  type PromptQualityScore,
  type InsertPromptQualityScore,
} from "@shared/schema";

// ─── A/B Tests ──────────────────────────────────────────────────────────────

export async function getAbTestsByPrompt(orgId: string, promptId: string): Promise<PromptAbTest[]> {
  return db
    .select()
    .from(promptAbTests)
    .where(and(eq(promptAbTests.orgId, orgId), eq(promptAbTests.promptId, promptId)))
    .orderBy(desc(promptAbTests.createdAt));
}

export async function getAbTest(id: string): Promise<PromptAbTest | undefined> {
  const [row] = await db.select().from(promptAbTests).where(eq(promptAbTests.id, id));
  return row;
}

export async function createAbTest(data: InsertPromptAbTest): Promise<PromptAbTest> {
  const [row] = await db.insert(promptAbTests).values(data).returning();
  return row;
}

export async function updateAbTest(
  id: string,
  data: Partial<Pick<PromptAbTest, "status" | "completedAt" | "results">>,
): Promise<PromptAbTest | undefined> {
  const [row] = await db.update(promptAbTests).set(data).where(eq(promptAbTests.id, id)).returning();
  return row;
}

// ─── Quality Scores ─────────────────────────────────────────────────────────

export async function getQualityScoresByPrompt(orgId: string, promptId: string): Promise<PromptQualityScore[]> {
  return db
    .select()
    .from(promptQualityScores)
    .where(and(eq(promptQualityScores.orgId, orgId), eq(promptQualityScores.promptId, promptId)))
    .orderBy(desc(promptQualityScores.createdAt));
}

export async function createQualityScore(data: InsertPromptQualityScore): Promise<PromptQualityScore> {
  const [row] = await db.insert(promptQualityScores).values(data).returning();
  return row;
}
