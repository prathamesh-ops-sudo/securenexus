import {
  type TrustCenterArtifact,
  type InsertTrustCenterArtifact,
  type TrustCenterDownload,
  type InsertTrustCenterDownload,
  trustCenterArtifacts,
  trustCenterDownloadLog,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── Artifacts ──

export async function getTrustCenterArtifacts(orgId: string, category?: string): Promise<TrustCenterArtifact[]> {
  if (category) {
    return db
      .select()
      .from(trustCenterArtifacts)
      .where(and(eq(trustCenterArtifacts.orgId, orgId), eq(trustCenterArtifacts.category, category)))
      .orderBy(desc(trustCenterArtifacts.createdAt));
  }
  return db
    .select()
    .from(trustCenterArtifacts)
    .where(eq(trustCenterArtifacts.orgId, orgId))
    .orderBy(desc(trustCenterArtifacts.createdAt));
}

export async function getTrustCenterArtifact(id: string, orgId: string): Promise<TrustCenterArtifact | undefined> {
  const [artifact] = await db
    .select()
    .from(trustCenterArtifacts)
    .where(and(eq(trustCenterArtifacts.id, id), eq(trustCenterArtifacts.orgId, orgId)));
  return artifact;
}

export async function createTrustCenterArtifact(data: InsertTrustCenterArtifact): Promise<TrustCenterArtifact> {
  const [created] = await db.insert(trustCenterArtifacts).values(data).returning();
  return created;
}

export async function updateTrustCenterArtifact(
  id: string,
  orgId: string,
  updates: Partial<InsertTrustCenterArtifact>,
): Promise<TrustCenterArtifact | undefined> {
  const [updated] = await db
    .update(trustCenterArtifacts)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(trustCenterArtifacts.id, id), eq(trustCenterArtifacts.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteTrustCenterArtifact(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(trustCenterArtifacts)
    .where(and(eq(trustCenterArtifacts.id, id), eq(trustCenterArtifacts.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countTrustCenterArtifacts(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(trustCenterArtifacts)
    .where(eq(trustCenterArtifacts.orgId, orgId));
  return row?.total ?? 0;
}

// ── Download Log ──

export async function getTrustCenterDownloads(orgId: string, limit = 100): Promise<TrustCenterDownload[]> {
  return db
    .select()
    .from(trustCenterDownloadLog)
    .where(eq(trustCenterDownloadLog.orgId, orgId))
    .orderBy(desc(trustCenterDownloadLog.downloadedAt))
    .limit(limit);
}

export async function createTrustCenterDownload(data: InsertTrustCenterDownload): Promise<TrustCenterDownload> {
  const [created] = await db.insert(trustCenterDownloadLog).values(data).returning();
  return created;
}

export async function countTrustCenterDownloads(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(trustCenterDownloadLog)
    .where(eq(trustCenterDownloadLog.orgId, orgId));
  return row?.total ?? 0;
}
