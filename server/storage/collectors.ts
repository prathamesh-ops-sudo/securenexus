import {
  type CollectorInstance,
  type InsertCollectorInstance,
  type CollectorEvent,
  type InsertCollectorEvent,
  type CollectorScan,
  type InsertCollectorScan,
  collectorInstances,
  collectorEvents,
  collectorScans,
} from "@shared/schema";
import { db } from "../db";
import { count, desc, eq } from "drizzle-orm";

// ── Collector Instances ──

export async function getCollectorInstances(orgId: string): Promise<CollectorInstance[]> {
  return db
    .select()
    .from(collectorInstances)
    .where(eq(collectorInstances.orgId, orgId))
    .orderBy(desc(collectorInstances.createdAt));
}

export async function getCollectorInstance(id: string): Promise<CollectorInstance | undefined> {
  const [instance] = await db.select().from(collectorInstances).where(eq(collectorInstances.id, id));
  return instance;
}

export async function createCollectorInstance(instance: InsertCollectorInstance): Promise<CollectorInstance> {
  const [created] = await db.insert(collectorInstances).values(instance).returning();
  return created;
}

export async function updateCollectorInstance(
  id: string,
  updates: Partial<InsertCollectorInstance>,
): Promise<CollectorInstance | undefined> {
  const [updated] = await db
    .update(collectorInstances)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(collectorInstances.id, id))
    .returning();
  return updated;
}

export async function deleteCollectorInstance(id: string): Promise<boolean> {
  const result = await db.delete(collectorInstances).where(eq(collectorInstances.id, id));
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

export async function getCollectorEventsByInstance(instanceId: string, limit = 100): Promise<CollectorEvent[]> {
  return db
    .select()
    .from(collectorEvents)
    .where(eq(collectorEvents.collectorId, instanceId))
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

// ── Collector Scans ──

export async function getCollectorScans(orgId: string, limit = 50): Promise<CollectorScan[]> {
  return db
    .select()
    .from(collectorScans)
    .where(eq(collectorScans.orgId, orgId))
    .orderBy(desc(collectorScans.startedAt))
    .limit(limit);
}

export async function createCollectorScan(scan: InsertCollectorScan): Promise<CollectorScan> {
  const [created] = await db.insert(collectorScans).values(scan).returning();
  return created;
}

export async function updateCollectorScan(
  id: string,
  updates: Partial<InsertCollectorScan>,
): Promise<CollectorScan | undefined> {
  const [updated] = await db.update(collectorScans).set(updates).where(eq(collectorScans.id, id)).returning();
  return updated;
}
