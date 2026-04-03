import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import { ransomwareIndicators, type RansomwareIndicator, type InsertRansomwareIndicator } from "@shared/schema";

export async function getRansomwareIndicators(orgId: string): Promise<RansomwareIndicator[]> {
  return db
    .select()
    .from(ransomwareIndicators)
    .where(eq(ransomwareIndicators.orgId, orgId))
    .orderBy(desc(ransomwareIndicators.createdAt));
}

export async function getRansomwareIndicator(id: string): Promise<RansomwareIndicator | undefined> {
  const [indicator] = await db.select().from(ransomwareIndicators).where(eq(ransomwareIndicators.id, id));
  return indicator;
}

export async function getRansomwareIndicatorsByFamily(
  orgId: string,
  threatFamily: string,
): Promise<RansomwareIndicator[]> {
  return db
    .select()
    .from(ransomwareIndicators)
    .where(and(eq(ransomwareIndicators.orgId, orgId), eq(ransomwareIndicators.threatFamily, threatFamily)))
    .orderBy(desc(ransomwareIndicators.createdAt));
}

export async function createRansomwareIndicator(data: InsertRansomwareIndicator): Promise<RansomwareIndicator> {
  const [created] = await db.insert(ransomwareIndicators).values(data).returning();
  return created;
}

export async function updateRansomwareIndicator(
  id: string,
  data: Partial<RansomwareIndicator>,
): Promise<RansomwareIndicator | undefined> {
  const [updated] = await db.update(ransomwareIndicators).set(data).where(eq(ransomwareIndicators.id, id)).returning();
  return updated;
}

export async function deleteRansomwareIndicator(id: string): Promise<void> {
  await db.delete(ransomwareIndicators).where(eq(ransomwareIndicators.id, id));
}
