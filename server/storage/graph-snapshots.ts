import { db } from "../db";
import { eq, desc } from "drizzle-orm";
import { graphSnapshots, type GraphSnapshot, type InsertGraphSnapshot } from "@shared/schema";

export async function getGraphSnapshots(orgId: string): Promise<GraphSnapshot[]> {
  return db
    .select()
    .from(graphSnapshots)
    .where(eq(graphSnapshots.orgId, orgId))
    .orderBy(desc(graphSnapshots.createdAt));
}

export async function getGraphSnapshot(id: string): Promise<GraphSnapshot | undefined> {
  const [row] = await db.select().from(graphSnapshots).where(eq(graphSnapshots.id, id));
  return row;
}

export async function createGraphSnapshot(data: InsertGraphSnapshot): Promise<GraphSnapshot> {
  const [row] = await db.insert(graphSnapshots).values(data).returning();
  return row;
}

export async function deleteGraphSnapshot(id: string): Promise<boolean> {
  const result = await db.delete(graphSnapshots).where(eq(graphSnapshots.id, id));
  return (result.rowCount ?? 0) > 0;
}
