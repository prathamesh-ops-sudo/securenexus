import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  awarenessPrograms,
  phishingSimulations,
  type AwarenessProgram,
  type InsertAwarenessProgram,
  type PhishingSimulation,
  type InsertPhishingSimulation,
} from "@shared/schema";

// ─── Programs ────────────────────────────────────────────────────────────────
export async function getAwarenessPrograms(orgId: string): Promise<AwarenessProgram[]> {
  return db
    .select()
    .from(awarenessPrograms)
    .where(eq(awarenessPrograms.orgId, orgId))
    .orderBy(desc(awarenessPrograms.createdAt));
}

export async function getAwarenessProgram(id: string): Promise<AwarenessProgram | undefined> {
  const [program] = await db.select().from(awarenessPrograms).where(eq(awarenessPrograms.id, id));
  return program;
}

export async function createAwarenessProgram(data: InsertAwarenessProgram): Promise<AwarenessProgram> {
  const [created] = await db.insert(awarenessPrograms).values(data).returning();
  return created;
}

export async function updateAwarenessProgram(
  id: string,
  data: Partial<AwarenessProgram>,
): Promise<AwarenessProgram | undefined> {
  const [updated] = await db
    .update(awarenessPrograms)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(awarenessPrograms.id, id))
    .returning();
  return updated;
}

export async function deleteAwarenessProgram(id: string): Promise<void> {
  await db.delete(awarenessPrograms).where(eq(awarenessPrograms.id, id));
}

// ─── Phishing Simulations ────────────────────────────────────────────────────
export async function getPhishingSimulations(orgId: string): Promise<PhishingSimulation[]> {
  return db
    .select()
    .from(phishingSimulations)
    .where(eq(phishingSimulations.orgId, orgId))
    .orderBy(desc(phishingSimulations.createdAt));
}

export async function getPhishingSimulation(id: string): Promise<PhishingSimulation | undefined> {
  const [sim] = await db.select().from(phishingSimulations).where(eq(phishingSimulations.id, id));
  return sim;
}

export async function createPhishingSimulation(data: InsertPhishingSimulation): Promise<PhishingSimulation> {
  const [created] = await db.insert(phishingSimulations).values(data).returning();
  return created;
}

export async function updatePhishingSimulation(
  id: string,
  data: Partial<PhishingSimulation>,
): Promise<PhishingSimulation | undefined> {
  const [updated] = await db
    .update(phishingSimulations)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(phishingSimulations.id, id))
    .returning();
  return updated;
}

export async function deletePhishingSimulation(id: string): Promise<void> {
  await db.delete(phishingSimulations).where(eq(phishingSimulations.id, id));
}
