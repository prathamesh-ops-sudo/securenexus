import {
  type ChaosSimulation,
  type InsertChaosSimulation,
  type ChaosSchedule,
  type InsertChaosSchedule,
  chaosSimulations,
  chaosSchedules,
} from "@shared/schema";
import { db } from "../db";
import { count, desc, eq } from "drizzle-orm";

// ── Chaos Simulations ──

export async function getChaosSimulations(orgId: string): Promise<ChaosSimulation[]> {
  return db
    .select()
    .from(chaosSimulations)
    .where(eq(chaosSimulations.orgId, orgId))
    .orderBy(desc(chaosSimulations.createdAt));
}

export async function getChaosSimulation(id: string): Promise<ChaosSimulation | undefined> {
  const [sim] = await db.select().from(chaosSimulations).where(eq(chaosSimulations.id, id));
  return sim;
}

export async function createChaosSimulation(sim: InsertChaosSimulation): Promise<ChaosSimulation> {
  const [created] = await db.insert(chaosSimulations).values(sim).returning();
  return created;
}

export async function updateChaosSimulation(
  id: string,
  updates: Partial<InsertChaosSimulation>,
): Promise<ChaosSimulation | undefined> {
  const [updated] = await db
    .update(chaosSimulations)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(chaosSimulations.id, id))
    .returning();
  return updated;
}

export async function deleteChaosSimulation(id: string): Promise<boolean> {
  const result = await db.delete(chaosSimulations).where(eq(chaosSimulations.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function countChaosSimulations(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(chaosSimulations).where(eq(chaosSimulations.orgId, orgId));
  return row?.total ?? 0;
}

// ── Chaos Schedules ──

export async function getChaosSchedules(orgId: string): Promise<ChaosSchedule[]> {
  return db
    .select()
    .from(chaosSchedules)
    .where(eq(chaosSchedules.orgId, orgId))
    .orderBy(desc(chaosSchedules.createdAt));
}

export async function getChaosSchedule(id: string): Promise<ChaosSchedule | undefined> {
  const [sched] = await db.select().from(chaosSchedules).where(eq(chaosSchedules.id, id));
  return sched;
}

export async function createChaosSchedule(sched: InsertChaosSchedule): Promise<ChaosSchedule> {
  const [created] = await db.insert(chaosSchedules).values(sched).returning();
  return created;
}

export async function updateChaosSchedule(
  id: string,
  updates: Partial<InsertChaosSchedule>,
): Promise<ChaosSchedule | undefined> {
  const [updated] = await db
    .update(chaosSchedules)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(chaosSchedules.id, id))
    .returning();
  return updated;
}

export async function deleteChaosSchedule(id: string): Promise<boolean> {
  const result = await db.delete(chaosSchedules).where(eq(chaosSchedules.id, id));
  return (result.rowCount ?? 0) > 0;
}
