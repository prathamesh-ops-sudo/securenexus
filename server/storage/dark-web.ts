import {
  type DarkWebExposure,
  type InsertDarkWebExposure,
  type DarkWebMonitoringConfig,
  type InsertDarkWebMonitoringConfig,
  type DarkWebScanHistoryEntry,
  type InsertDarkWebScanHistoryEntry,
  darkWebExposures,
  darkWebMonitoringConfig,
  darkWebScanHistory,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── Dark Web Exposures ──

export async function getDarkWebExposures(orgId: string): Promise<DarkWebExposure[]> {
  return db
    .select()
    .from(darkWebExposures)
    .where(eq(darkWebExposures.orgId, orgId))
    .orderBy(desc(darkWebExposures.discoveredAt));
}

export async function getDarkWebExposure(id: string): Promise<DarkWebExposure | undefined> {
  const [item] = await db.select().from(darkWebExposures).where(eq(darkWebExposures.id, id));
  return item;
}

export async function createDarkWebExposure(item: InsertDarkWebExposure): Promise<DarkWebExposure> {
  const [created] = await db.insert(darkWebExposures).values(item).returning();
  return created;
}

export async function updateDarkWebExposure(
  id: string,
  updates: Partial<InsertDarkWebExposure>,
): Promise<DarkWebExposure | undefined> {
  const [updated] = await db.update(darkWebExposures).set(updates).where(eq(darkWebExposures.id, id)).returning();
  return updated;
}

export async function deleteDarkWebExposure(id: string): Promise<boolean> {
  const result = await db.delete(darkWebExposures).where(eq(darkWebExposures.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function countDarkWebExposures(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(darkWebExposures).where(eq(darkWebExposures.orgId, orgId));
  return row?.total ?? 0;
}

export async function countDarkWebExposuresByStatus(orgId: string, status: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(darkWebExposures)
    .where(and(eq(darkWebExposures.orgId, orgId), eq(darkWebExposures.status, status)));
  return row?.total ?? 0;
}

// ── Monitoring Config ──

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
      .where(eq(darkWebMonitoringConfig.orgId, orgId))
      .returning();
    return updated;
  }
  const [created] = await db
    .insert(darkWebMonitoringConfig)
    .values({ ...data, orgId } as InsertDarkWebMonitoringConfig)
    .returning();
  return created;
}

// ── Scan History ──

export async function getDarkWebScanHistory(orgId: string, limit = 50): Promise<DarkWebScanHistoryEntry[]> {
  return db
    .select()
    .from(darkWebScanHistory)
    .where(eq(darkWebScanHistory.orgId, orgId))
    .orderBy(desc(darkWebScanHistory.startedAt))
    .limit(limit);
}

export async function createDarkWebScanHistoryEntry(
  entry: InsertDarkWebScanHistoryEntry,
): Promise<DarkWebScanHistoryEntry> {
  const [created] = await db.insert(darkWebScanHistory).values(entry).returning();
  return created;
}

export async function updateDarkWebScanHistoryEntry(
  id: string,
  updates: Partial<InsertDarkWebScanHistoryEntry>,
): Promise<DarkWebScanHistoryEntry | undefined> {
  const [updated] = await db.update(darkWebScanHistory).set(updates).where(eq(darkWebScanHistory.id, id)).returning();
  return updated;
}
