import {
  type CollectorInstance,
  type InsertCollectorInstance,
  type CollectorEvent,
  type InsertCollectorEvent,
  collectorInstances,
  collectorEvents,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── Collector Instances ──

export async function getCollectorInstances(orgId: string): Promise<CollectorInstance[]> {
  return db
    .select()
    .from(collectorInstances)
    .where(eq(collectorInstances.orgId, orgId))
    .orderBy(desc(collectorInstances.createdAt));
}

export async function getCollectorInstance(id: string, orgId: string): Promise<CollectorInstance | undefined> {
  const [instance] = await db
    .select()
    .from(collectorInstances)
    .where(and(eq(collectorInstances.id, id), eq(collectorInstances.orgId, orgId)));
  return instance;
}

export async function createCollectorInstance(instance: InsertCollectorInstance): Promise<CollectorInstance> {
  const [created] = await db.insert(collectorInstances).values(instance).returning();
  return created;
}

export async function updateCollectorInstance(
  id: string,
  updates: Partial<InsertCollectorInstance>,
  orgId: string,
): Promise<CollectorInstance | undefined> {
  const [updated] = await db
    .update(collectorInstances)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(collectorInstances.id, id), eq(collectorInstances.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteCollectorInstance(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(collectorInstances)
    .where(and(eq(collectorInstances.id, id), eq(collectorInstances.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countCollectorInstances(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(collectorInstances).where(eq(collectorInstances.orgId, orgId));
  return row?.total ?? 0;
}

// ── Collector Events ──

export async function getCollectorEvents(orgId: string, limit = 100, offset = 0): Promise<CollectorEvent[]> {
  return db
    .select()
    .from(collectorEvents)
    .where(eq(collectorEvents.orgId, orgId))
    .orderBy(desc(collectorEvents.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function getCollectorEventsByInstance(
  instanceId: string,
  orgId: string,
  limit = 100,
): Promise<CollectorEvent[]> {
  return db
    .select()
    .from(collectorEvents)
    .where(and(eq(collectorEvents.collectorId, instanceId), eq(collectorEvents.orgId, orgId)))
    .orderBy(desc(collectorEvents.createdAt))
    .limit(limit);
}

export async function createCollectorEvent(event: InsertCollectorEvent): Promise<CollectorEvent> {
  const [created] = await db.insert(collectorEvents).values(event).returning();
  return created;
}

export async function countCollectorEvents(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(collectorEvents).where(eq(collectorEvents.orgId, orgId));
  return row?.total ?? 0;
}
