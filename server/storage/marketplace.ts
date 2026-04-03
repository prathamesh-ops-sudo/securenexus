import {
  type MarketplaceInstance,
  type InsertMarketplaceInstance,
  type MarketplaceWebhookEvent,
  type InsertMarketplaceWebhookEvent,
  type MarketplaceDeadLetter,
  type InsertMarketplaceDeadLetter,
  type MarketplaceSyncHistoryEntry,
  type InsertMarketplaceSyncHistoryEntry,
  marketplaceInstances,
  marketplaceWebhookEvents,
  marketplaceDeadLetters,
  marketplaceSyncHistory,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── Instances ──

export async function getMarketplaceInstances(orgId: string): Promise<MarketplaceInstance[]> {
  return db
    .select()
    .from(marketplaceInstances)
    .where(eq(marketplaceInstances.orgId, orgId))
    .orderBy(desc(marketplaceInstances.installedAt));
}

export async function getMarketplaceInstance(id: string, orgId: string): Promise<MarketplaceInstance | undefined> {
  const [instance] = await db
    .select()
    .from(marketplaceInstances)
    .where(and(eq(marketplaceInstances.id, id), eq(marketplaceInstances.orgId, orgId)));
  return instance;
}

export async function createMarketplaceInstance(data: InsertMarketplaceInstance): Promise<MarketplaceInstance> {
  const [created] = await db.insert(marketplaceInstances).values(data).returning();
  return created;
}

export async function updateMarketplaceInstance(
  id: string,
  orgId: string,
  updates: Partial<InsertMarketplaceInstance>,
): Promise<MarketplaceInstance | undefined> {
  const [updated] = await db
    .update(marketplaceInstances)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(marketplaceInstances.id, id), eq(marketplaceInstances.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteMarketplaceInstance(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(marketplaceInstances)
    .where(and(eq(marketplaceInstances.id, id), eq(marketplaceInstances.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countMarketplaceInstances(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(marketplaceInstances)
    .where(eq(marketplaceInstances.orgId, orgId));
  return row?.total ?? 0;
}

// ── Webhook Events ──

export async function getMarketplaceWebhookEvents(
  orgId: string,
  instanceId?: string,
  limit = 100,
): Promise<MarketplaceWebhookEvent[]> {
  if (instanceId) {
    return db
      .select()
      .from(marketplaceWebhookEvents)
      .where(and(eq(marketplaceWebhookEvents.orgId, orgId), eq(marketplaceWebhookEvents.instanceId, instanceId)))
      .orderBy(desc(marketplaceWebhookEvents.receivedAt))
      .limit(limit);
  }
  return db
    .select()
    .from(marketplaceWebhookEvents)
    .where(eq(marketplaceWebhookEvents.orgId, orgId))
    .orderBy(desc(marketplaceWebhookEvents.receivedAt))
    .limit(limit);
}

export async function createMarketplaceWebhookEvent(
  data: InsertMarketplaceWebhookEvent,
): Promise<MarketplaceWebhookEvent> {
  const [created] = await db.insert(marketplaceWebhookEvents).values(data).returning();
  return created;
}

// ── Dead Letters ──

export async function getMarketplaceDeadLetters(
  orgId: string,
  instanceId?: string,
  limit = 50,
): Promise<MarketplaceDeadLetter[]> {
  if (instanceId) {
    return db
      .select()
      .from(marketplaceDeadLetters)
      .where(and(eq(marketplaceDeadLetters.orgId, orgId), eq(marketplaceDeadLetters.instanceId, instanceId)))
      .orderBy(desc(marketplaceDeadLetters.createdAt))
      .limit(limit);
  }
  return db
    .select()
    .from(marketplaceDeadLetters)
    .where(eq(marketplaceDeadLetters.orgId, orgId))
    .orderBy(desc(marketplaceDeadLetters.createdAt))
    .limit(limit);
}

export async function getMarketplaceDeadLetter(id: string, orgId: string): Promise<MarketplaceDeadLetter | undefined> {
  const [dl] = await db
    .select()
    .from(marketplaceDeadLetters)
    .where(and(eq(marketplaceDeadLetters.id, id), eq(marketplaceDeadLetters.orgId, orgId)));
  return dl;
}

export async function createMarketplaceDeadLetter(data: InsertMarketplaceDeadLetter): Promise<MarketplaceDeadLetter> {
  const [created] = await db.insert(marketplaceDeadLetters).values(data).returning();
  return created;
}

export async function updateMarketplaceDeadLetter(
  id: string,
  orgId: string,
  updates: Partial<InsertMarketplaceDeadLetter>,
): Promise<MarketplaceDeadLetter | undefined> {
  const [updated] = await db
    .update(marketplaceDeadLetters)
    .set(updates)
    .where(and(eq(marketplaceDeadLetters.id, id), eq(marketplaceDeadLetters.orgId, orgId)))
    .returning();
  return updated;
}

// ── Sync History ──

export async function getMarketplaceSyncHistory(
  orgId: string,
  instanceId: string,
  limit = 50,
): Promise<MarketplaceSyncHistoryEntry[]> {
  return db
    .select()
    .from(marketplaceSyncHistory)
    .where(and(eq(marketplaceSyncHistory.orgId, orgId), eq(marketplaceSyncHistory.instanceId, instanceId)))
    .orderBy(desc(marketplaceSyncHistory.startedAt))
    .limit(limit);
}

export async function createMarketplaceSyncHistoryEntry(
  data: InsertMarketplaceSyncHistoryEntry,
): Promise<MarketplaceSyncHistoryEntry> {
  const [created] = await db.insert(marketplaceSyncHistory).values(data).returning();
  return created;
}

export async function updateMarketplaceSyncHistoryEntry(
  id: string,
  updates: Partial<InsertMarketplaceSyncHistoryEntry>,
): Promise<MarketplaceSyncHistoryEntry | undefined> {
  const [updated] = await db
    .update(marketplaceSyncHistory)
    .set(updates)
    .where(eq(marketplaceSyncHistory.id, id))
    .returning();
  return updated;
}
