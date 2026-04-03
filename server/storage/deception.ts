import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  deceptionAssets,
  deceptionInteractions,
  type DeceptionAsset,
  type InsertDeceptionAsset,
  type DeceptionInteraction,
  type InsertDeceptionInteraction,
} from "@shared/schema";

// ─── Assets ──────────────────────────────────────────────────────────────────
export async function getDeceptionAssets(orgId: string): Promise<DeceptionAsset[]> {
  return db
    .select()
    .from(deceptionAssets)
    .where(eq(deceptionAssets.orgId, orgId))
    .orderBy(desc(deceptionAssets.createdAt));
}

export async function getDeceptionAsset(id: string): Promise<DeceptionAsset | undefined> {
  const [asset] = await db.select().from(deceptionAssets).where(eq(deceptionAssets.id, id));
  return asset;
}

export async function createDeceptionAsset(data: InsertDeceptionAsset): Promise<DeceptionAsset> {
  const [created] = await db.insert(deceptionAssets).values(data).returning();
  return created;
}

export async function updateDeceptionAsset(
  id: string,
  data: Partial<DeceptionAsset>,
): Promise<DeceptionAsset | undefined> {
  const [updated] = await db
    .update(deceptionAssets)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(deceptionAssets.id, id))
    .returning();
  return updated;
}

export async function deleteDeceptionAsset(id: string): Promise<void> {
  await db.delete(deceptionAssets).where(eq(deceptionAssets.id, id));
}

// ─── Interactions ────────────────────────────────────────────────────────────
export async function getDeceptionInteractions(orgId: string): Promise<DeceptionInteraction[]> {
  return db
    .select()
    .from(deceptionInteractions)
    .where(eq(deceptionInteractions.orgId, orgId))
    .orderBy(desc(deceptionInteractions.createdAt));
}

export async function getDeceptionInteractionsByAsset(orgId: string, assetId: string): Promise<DeceptionInteraction[]> {
  return db
    .select()
    .from(deceptionInteractions)
    .where(and(eq(deceptionInteractions.orgId, orgId), eq(deceptionInteractions.assetId, assetId)))
    .orderBy(desc(deceptionInteractions.createdAt));
}

export async function createDeceptionInteraction(data: InsertDeceptionInteraction): Promise<DeceptionInteraction> {
  const [created] = await db.insert(deceptionInteractions).values(data).returning();
  return created;
}
