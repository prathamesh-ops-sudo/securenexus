import { db } from "../db";
import { eq, desc, and, count } from "drizzle-orm";
import {
  darkWebExposures,
  darkWebMonitoringConfig,
  darkWebScanHistory,
  type DarkWebExposure,
  type InsertDarkWebExposure,
  type DarkWebMonitoringConfig,
  type InsertDarkWebMonitoringConfig,
  type DarkWebScanHistoryEntry,
  type InsertDarkWebScanHistoryEntry,
} from "@shared/schema";

// ─── Exposures ───────────────────────────────────────────────────────────────
export async function getDarkWebExposures(orgId: string): Promise<DarkWebExposure[]> {
  return db
    .select()
    .from(darkWebExposures)
    .where(eq(darkWebExposures.orgId, orgId))
    .orderBy(desc(darkWebExposures.createdAt));
}

export async function getDarkWebExposure(id: string): Promise<DarkWebExposure | undefined> {
  const [exposure] = await db.select().from(darkWebExposures).where(eq(darkWebExposures.id, id));
  return exposure;
}

export async function createDarkWebExposure(data: InsertDarkWebExposure): Promise<DarkWebExposure> {
  const [created] = await db.insert(darkWebExposures).values(data).returning();
  return created;
}

export async function updateDarkWebExposure(
  id: string,
  data: Partial<DarkWebExposure>,
): Promise<DarkWebExposure | undefined> {
  const [updated] = await db
    .update(darkWebExposures)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(darkWebExposures.id, id))
    .returning();
  return updated;
}

export async function deleteDarkWebExposure(id: string): Promise<boolean> {
  const result = await db.delete(darkWebExposures).where(eq(darkWebExposures.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function countDarkWebExposures(orgId: string): Promise<number> {
  const [result] = await db.select({ value: count() }).from(darkWebExposures).where(eq(darkWebExposures.orgId, orgId));
  return result?.value ?? 0;
}

export async function countDarkWebExposuresByStatus(orgId: string, status: string): Promise<number> {
  const [result] = await db
    .select({ value: count() })
    .from(darkWebExposures)
    .where(and(eq(darkWebExposures.orgId, orgId), eq(darkWebExposures.status, status)));
  return result?.value ?? 0;
}

// ─── Monitoring Config ───────────────────────────────────────────────────────
export async function getDarkWebMonitoringConfig(orgId: string): Promise<DarkWebMonitoringConfig | undefined> {
  const [config] = await db.select().from(darkWebMonitoringConfig).where(eq(darkWebMonitoringConfig.orgId, orgId));
  return config;
}

export async function upsertDarkWebMonitoringConfig(
  orgId: string,
  data: Partial<InsertDarkWebMonitoringConfig>,
): Promise<DarkWebMonitoringConfig> {
  const existing = await getDarkWebMonitoringConfig(orgId);
  if (existing) {
    const [updated] = await db
      .update(darkWebMonitoringConfig)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(darkWebMonitoringConfig.id, existing.id))
      .returning();
    return updated;
  }
  const [created] = await db
    .insert(darkWebMonitoringConfig)
    .values({ ...data, orgId } as InsertDarkWebMonitoringConfig)
    .returning();
  return created;
}

// ─── Scan History ────────────────────────────────────────────────────────────
export async function getDarkWebScanHistory(orgId: string, _limit?: number): Promise<DarkWebScanHistoryEntry[]> {
  return db
    .select()
    .from(darkWebScanHistory)
    .where(eq(darkWebScanHistory.orgId, orgId))
    .orderBy(desc(darkWebScanHistory.startedAt));
}

export async function createDarkWebScanHistoryEntry(
  data: InsertDarkWebScanHistoryEntry,
): Promise<DarkWebScanHistoryEntry> {
  const [created] = await db.insert(darkWebScanHistory).values(data).returning();
  return created;
}

export async function updateDarkWebScanHistoryEntry(
  id: string,
  data: Partial<DarkWebScanHistoryEntry>,
): Promise<DarkWebScanHistoryEntry | undefined> {
  const [updated] = await db.update(darkWebScanHistory).set(data).where(eq(darkWebScanHistory.id, id)).returning();
  return updated;
}
