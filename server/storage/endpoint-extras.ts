import { db } from "../db";
import { eq, and, desc } from "drizzle-orm";
import {
  endpointScanSchedules,
  endpointHeartbeats,
  cspmRemediationSafetyRecords,
  endpointGroups,
  type EndpointScanSchedule,
  type InsertEndpointScanSchedule,
  type EndpointHeartbeat,
  type InsertEndpointHeartbeat,
  type CspmRemediationSafetyRecord,
  type InsertCspmRemediationSafetyRecord,
  type EndpointGroup,
  type InsertEndpointGroup,
} from "@shared/schema";

// ─── Scan Schedules ──────────────────────────────────────────────────────────

export async function getEndpointScanSchedules(orgId: string): Promise<EndpointScanSchedule[]> {
  return db.select().from(endpointScanSchedules).where(eq(endpointScanSchedules.orgId, orgId));
}

export async function getEndpointScanSchedulesByAsset(orgId: string, assetId: string): Promise<EndpointScanSchedule[]> {
  return db
    .select()
    .from(endpointScanSchedules)
    .where(and(eq(endpointScanSchedules.orgId, orgId), eq(endpointScanSchedules.assetId, assetId)));
}

export async function getEndpointScanSchedule(id: string): Promise<EndpointScanSchedule | undefined> {
  const [row] = await db.select().from(endpointScanSchedules).where(eq(endpointScanSchedules.id, id));
  return row;
}

export async function createEndpointScanSchedule(data: InsertEndpointScanSchedule): Promise<EndpointScanSchedule> {
  const [row] = await db.insert(endpointScanSchedules).values(data).returning();
  return row;
}

export async function updateEndpointScanSchedule(
  id: string,
  data: Partial<EndpointScanSchedule>,
): Promise<EndpointScanSchedule | undefined> {
  const [row] = await db.update(endpointScanSchedules).set(data).where(eq(endpointScanSchedules.id, id)).returning();
  return row;
}

export async function deleteEndpointScanSchedule(id: string): Promise<boolean> {
  const result = await db.delete(endpointScanSchedules).where(eq(endpointScanSchedules.id, id));
  return (result.rowCount ?? 0) > 0;
}

// ─── Heartbeats ──────────────────────────────────────────────────────────────

export async function getEndpointHeartbeats(orgId: string): Promise<EndpointHeartbeat[]> {
  return db.select().from(endpointHeartbeats).where(eq(endpointHeartbeats.orgId, orgId));
}

export async function getEndpointHeartbeat(id: string): Promise<EndpointHeartbeat | undefined> {
  const [row] = await db.select().from(endpointHeartbeats).where(eq(endpointHeartbeats.id, id));
  return row;
}

export async function getEndpointHeartbeatByAsset(
  orgId: string,
  assetId: string,
): Promise<EndpointHeartbeat | undefined> {
  const [row] = await db
    .select()
    .from(endpointHeartbeats)
    .where(and(eq(endpointHeartbeats.orgId, orgId), eq(endpointHeartbeats.assetId, assetId)));
  return row;
}

export async function upsertEndpointHeartbeat(data: InsertEndpointHeartbeat): Promise<EndpointHeartbeat> {
  const existing = await getEndpointHeartbeatByAsset(data.orgId, data.assetId);
  if (existing) {
    const [row] = await db
      .update(endpointHeartbeats)
      .set({ lastHeartbeat: new Date(), status: data.status || "online", metadata: data.metadata })
      .where(eq(endpointHeartbeats.id, existing.id))
      .returning();
    return row;
  }
  const [row] = await db.insert(endpointHeartbeats).values(data).returning();
  return row;
}

export async function deleteEndpointHeartbeat(id: string): Promise<boolean> {
  const result = await db.delete(endpointHeartbeats).where(eq(endpointHeartbeats.id, id));
  return (result.rowCount ?? 0) > 0;
}

// ─── CSPM Remediation Safety Records ─────────────────────────────────────────

export async function getCspmRemediationRecords(orgId: string): Promise<CspmRemediationSafetyRecord[]> {
  return db
    .select()
    .from(cspmRemediationSafetyRecords)
    .where(eq(cspmRemediationSafetyRecords.orgId, orgId))
    .orderBy(desc(cspmRemediationSafetyRecords.createdAt));
}

export async function getCspmRemediationRecord(id: string): Promise<CspmRemediationSafetyRecord | undefined> {
  const [row] = await db.select().from(cspmRemediationSafetyRecords).where(eq(cspmRemediationSafetyRecords.id, id));
  return row;
}

export async function createCspmRemediationRecord(
  data: InsertCspmRemediationSafetyRecord,
): Promise<CspmRemediationSafetyRecord> {
  const [row] = await db.insert(cspmRemediationSafetyRecords).values(data).returning();
  return row;
}

export async function updateCspmRemediationRecord(
  id: string,
  data: Partial<CspmRemediationSafetyRecord>,
): Promise<CspmRemediationSafetyRecord | undefined> {
  const [row] = await db
    .update(cspmRemediationSafetyRecords)
    .set(data)
    .where(eq(cspmRemediationSafetyRecords.id, id))
    .returning();
  return row;
}

// ─── Endpoint Groups ─────────────────────────────────────────────────────────

export async function getEndpointGroups(orgId: string): Promise<EndpointGroup[]> {
  return db.select().from(endpointGroups).where(eq(endpointGroups.orgId, orgId));
}

export async function getEndpointGroup(id: string): Promise<EndpointGroup | undefined> {
  const [row] = await db.select().from(endpointGroups).where(eq(endpointGroups.id, id));
  return row;
}

export async function createEndpointGroup(data: InsertEndpointGroup): Promise<EndpointGroup> {
  const [row] = await db.insert(endpointGroups).values(data).returning();
  return row;
}

export async function deleteEndpointGroup(id: string): Promise<boolean> {
  const result = await db.delete(endpointGroups).where(eq(endpointGroups.id, id));
  return (result.rowCount ?? 0) > 0;
}
