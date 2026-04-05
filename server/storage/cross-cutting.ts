import {
  type CrossCuttingEvidence,
  type InsertCrossCuttingEvidence,
  type CrossCuttingDriftRecord,
  type InsertCrossCuttingDriftRecord,
  type CrossCuttingOverride,
  type InsertCrossCuttingOverride,
  type CrossCuttingKillSwitch,
  type InsertCrossCuttingKillSwitch,
  type TtvMilestone,
  type InsertTtvMilestone,
  crossCuttingEvidence,
  crossCuttingDrift,
  crossCuttingOverrides,
  crossCuttingKillSwitches,
  ttvMilestones,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── Evidence ──

export async function getCrossCuttingEvidenceList(
  orgId: string,
  evidenceType?: string,
  limit = 100,
): Promise<CrossCuttingEvidence[]> {
  if (evidenceType) {
    return db
      .select()
      .from(crossCuttingEvidence)
      .where(and(eq(crossCuttingEvidence.orgId, orgId), eq(crossCuttingEvidence.evidenceType, evidenceType)))
      .orderBy(desc(crossCuttingEvidence.detectedAt))
      .limit(limit);
  }
  return db
    .select()
    .from(crossCuttingEvidence)
    .where(eq(crossCuttingEvidence.orgId, orgId))
    .orderBy(desc(crossCuttingEvidence.detectedAt))
    .limit(limit);
}

export async function getCrossCuttingEvidenceItem(
  id: string,
  orgId: string,
): Promise<CrossCuttingEvidence | undefined> {
  const [item] = await db
    .select()
    .from(crossCuttingEvidence)
    .where(and(eq(crossCuttingEvidence.id, id), eq(crossCuttingEvidence.orgId, orgId)));
  return item;
}

export async function createCrossCuttingEvidenceItem(data: InsertCrossCuttingEvidence): Promise<CrossCuttingEvidence> {
  const [created] = await db.insert(crossCuttingEvidence).values(data).returning();
  return created;
}

export async function updateCrossCuttingEvidenceItem(
  id: string,
  orgId: string,
  updates: Partial<InsertCrossCuttingEvidence>,
): Promise<CrossCuttingEvidence | undefined> {
  const [updated] = await db
    .update(crossCuttingEvidence)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(crossCuttingEvidence.id, id), eq(crossCuttingEvidence.orgId, orgId)))
    .returning();
  return updated;
}

export async function countCrossCuttingEvidence(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(crossCuttingEvidence)
    .where(eq(crossCuttingEvidence.orgId, orgId));
  return row?.total ?? 0;
}

// ── Drift ──

export async function getCrossCuttingDriftRecords(
  orgId: string,
  driftType?: string,
  limit = 100,
): Promise<CrossCuttingDriftRecord[]> {
  if (driftType) {
    return db
      .select()
      .from(crossCuttingDrift)
      .where(and(eq(crossCuttingDrift.orgId, orgId), eq(crossCuttingDrift.driftType, driftType)))
      .orderBy(desc(crossCuttingDrift.detectedAt))
      .limit(limit);
  }
  return db
    .select()
    .from(crossCuttingDrift)
    .where(eq(crossCuttingDrift.orgId, orgId))
    .orderBy(desc(crossCuttingDrift.detectedAt))
    .limit(limit);
}

export async function getCrossCuttingDriftRecord(
  id: string,
  orgId: string,
): Promise<CrossCuttingDriftRecord | undefined> {
  const [record] = await db
    .select()
    .from(crossCuttingDrift)
    .where(and(eq(crossCuttingDrift.id, id), eq(crossCuttingDrift.orgId, orgId)));
  return record;
}

export async function createCrossCuttingDriftRecord(
  data: InsertCrossCuttingDriftRecord,
): Promise<CrossCuttingDriftRecord> {
  const [created] = await db.insert(crossCuttingDrift).values(data).returning();
  return created;
}

export async function updateCrossCuttingDriftRecord(
  id: string,
  orgId: string,
  updates: Partial<InsertCrossCuttingDriftRecord>,
): Promise<CrossCuttingDriftRecord | undefined> {
  const [updated] = await db
    .update(crossCuttingDrift)
    .set(updates)
    .where(and(eq(crossCuttingDrift.id, id), eq(crossCuttingDrift.orgId, orgId)))
    .returning();
  return updated;
}

export async function countCrossCuttingDrift(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(crossCuttingDrift).where(eq(crossCuttingDrift.orgId, orgId));
  return row?.total ?? 0;
}

// ── Overrides ──

export async function getCrossCuttingOverrides(
  orgId: string,
  overrideType?: string,
  limit = 100,
): Promise<CrossCuttingOverride[]> {
  if (overrideType) {
    return db
      .select()
      .from(crossCuttingOverrides)
      .where(and(eq(crossCuttingOverrides.orgId, orgId), eq(crossCuttingOverrides.overrideType, overrideType)))
      .orderBy(desc(crossCuttingOverrides.createdAt))
      .limit(limit);
  }
  return db
    .select()
    .from(crossCuttingOverrides)
    .where(eq(crossCuttingOverrides.orgId, orgId))
    .orderBy(desc(crossCuttingOverrides.createdAt))
    .limit(limit);
}

export async function getCrossCuttingOverride(id: string, orgId: string): Promise<CrossCuttingOverride | undefined> {
  const [override] = await db
    .select()
    .from(crossCuttingOverrides)
    .where(and(eq(crossCuttingOverrides.id, id), eq(crossCuttingOverrides.orgId, orgId)));
  return override;
}

export async function createCrossCuttingOverride(data: InsertCrossCuttingOverride): Promise<CrossCuttingOverride> {
  const [created] = await db.insert(crossCuttingOverrides).values(data).returning();
  return created;
}

export async function updateCrossCuttingOverride(
  id: string,
  orgId: string,
  updates: Partial<InsertCrossCuttingOverride>,
): Promise<CrossCuttingOverride | undefined> {
  const [updated] = await db
    .update(crossCuttingOverrides)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(crossCuttingOverrides.id, id), eq(crossCuttingOverrides.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteCrossCuttingOverride(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(crossCuttingOverrides)
    .where(and(eq(crossCuttingOverrides.id, id), eq(crossCuttingOverrides.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countCrossCuttingOverrides(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(crossCuttingOverrides)
    .where(eq(crossCuttingOverrides.orgId, orgId));
  return row?.total ?? 0;
}

// ── Kill Switches ──

export async function getKillSwitchesList(orgId: string): Promise<CrossCuttingKillSwitch[]> {
  return db
    .select()
    .from(crossCuttingKillSwitches)
    .where(eq(crossCuttingKillSwitches.orgId, orgId))
    .orderBy(crossCuttingKillSwitches.featureName);
}

export async function getKillSwitchById(id: string, orgId: string): Promise<CrossCuttingKillSwitch | undefined> {
  const [row] = await db
    .select()
    .from(crossCuttingKillSwitches)
    .where(and(eq(crossCuttingKillSwitches.id, id), eq(crossCuttingKillSwitches.orgId, orgId)));
  return row;
}

export async function createKillSwitch(data: InsertCrossCuttingKillSwitch): Promise<CrossCuttingKillSwitch> {
  const [created] = await db.insert(crossCuttingKillSwitches).values(data).returning();
  return created;
}

export async function updateKillSwitch(
  id: string,
  orgId: string,
  updates: Partial<InsertCrossCuttingKillSwitch>,
): Promise<CrossCuttingKillSwitch | undefined> {
  const [updated] = await db
    .update(crossCuttingKillSwitches)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(crossCuttingKillSwitches.id, id), eq(crossCuttingKillSwitches.orgId, orgId)))
    .returning();
  return updated;
}

export async function countKillSwitches(orgId: string, state?: string): Promise<number> {
  const base = eq(crossCuttingKillSwitches.orgId, orgId);
  const where = state ? and(base, eq(crossCuttingKillSwitches.state, state)) : base;
  const [row] = await db.select({ total: count() }).from(crossCuttingKillSwitches).where(where);
  return row?.total ?? 0;
}

// ── Time-to-Value Milestones ──

export async function getTtvMilestones(orgId: string): Promise<TtvMilestone[]> {
  return db.select().from(ttvMilestones).where(eq(ttvMilestones.orgId, orgId)).orderBy(ttvMilestones.kind);
}

export async function getTtvMilestoneByKind(orgId: string, kind: string): Promise<TtvMilestone | undefined> {
  const [row] = await db
    .select()
    .from(ttvMilestones)
    .where(and(eq(ttvMilestones.orgId, orgId), eq(ttvMilestones.kind, kind)));
  return row;
}

export async function createTtvMilestone(data: InsertTtvMilestone): Promise<TtvMilestone> {
  const [created] = await db.insert(ttvMilestones).values(data).returning();
  return created;
}

export async function updateTtvMilestone(
  orgId: string,
  kind: string,
  updates: Partial<InsertTtvMilestone>,
): Promise<TtvMilestone | undefined> {
  const [updated] = await db
    .update(ttvMilestones)
    .set(updates)
    .where(and(eq(ttvMilestones.orgId, orgId), eq(ttvMilestones.kind, kind)))
    .returning();
  return updated;
}
