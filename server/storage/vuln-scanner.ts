import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import { vulnScans, type VulnScan, type InsertVulnScan } from "@shared/schema";

export async function getVulnScans(orgId: string): Promise<VulnScan[]> {
  return db.select().from(vulnScans).where(eq(vulnScans.orgId, orgId)).orderBy(desc(vulnScans.createdAt));
}

export async function getVulnScan(id: string): Promise<VulnScan | undefined> {
  const [scan] = await db.select().from(vulnScans).where(eq(vulnScans.id, id));
  return scan;
}

export async function createVulnScan(data: InsertVulnScan): Promise<VulnScan> {
  const [created] = await db.insert(vulnScans).values(data).returning();
  return created;
}

export async function updateVulnScan(id: string, data: Partial<VulnScan>): Promise<VulnScan | undefined> {
  const [updated] = await db
    .update(vulnScans)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(vulnScans.id, id))
    .returning();
  return updated;
}

export async function deleteVulnScan(id: string): Promise<void> {
  await db.delete(vulnScans).where(eq(vulnScans.id, id));
}
