import { db } from "../db";
import { eq, desc } from "drizzle-orm";
import { supplyChainComponents, type SupplyChainComponent, type InsertSupplyChainComponent } from "@shared/schema";

export async function getSupplyChainComponents(orgId: string): Promise<SupplyChainComponent[]> {
  return db
    .select()
    .from(supplyChainComponents)
    .where(eq(supplyChainComponents.orgId, orgId))
    .orderBy(desc(supplyChainComponents.createdAt));
}

export async function getSupplyChainComponent(id: string): Promise<SupplyChainComponent | undefined> {
  const [component] = await db.select().from(supplyChainComponents).where(eq(supplyChainComponents.id, id));
  return component;
}

export async function createSupplyChainComponent(data: InsertSupplyChainComponent): Promise<SupplyChainComponent> {
  const [created] = await db.insert(supplyChainComponents).values(data).returning();
  return created;
}

export async function updateSupplyChainComponent(
  id: string,
  data: Partial<SupplyChainComponent>,
): Promise<SupplyChainComponent | undefined> {
  const [updated] = await db
    .update(supplyChainComponents)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(supplyChainComponents.id, id))
    .returning();
  return updated;
}

export async function deleteSupplyChainComponent(id: string): Promise<void> {
  await db.delete(supplyChainComponents).where(eq(supplyChainComponents.id, id));
}
