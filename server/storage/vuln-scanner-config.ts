import {
  type InsertVulnScanSchedule,
  type InsertVulnScanTarget,
  type VulnScanSchedule,
  type VulnScanTarget,
  vulnScanSchedules,
  vulnScanTargets,
} from "@shared/schema";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../db";

export async function getVulnScanTargets(orgId: string): Promise<VulnScanTarget[]> {
  return db
    .select()
    .from(vulnScanTargets)
    .where(eq(vulnScanTargets.orgId, orgId))
    .orderBy(desc(vulnScanTargets.createdAt));
}

export async function createVulnScanTarget(data: InsertVulnScanTarget): Promise<VulnScanTarget> {
  const [created] = await db.insert(vulnScanTargets).values(data).returning();
  return created;
}

export async function getVulnScanSchedules(orgId: string): Promise<VulnScanSchedule[]> {
  return db
    .select()
    .from(vulnScanSchedules)
    .where(eq(vulnScanSchedules.orgId, orgId))
    .orderBy(desc(vulnScanSchedules.createdAt));
}

export async function createVulnScanSchedule(data: InsertVulnScanSchedule): Promise<VulnScanSchedule> {
  const [created] = await db.insert(vulnScanSchedules).values(data).returning();
  return created;
}

export async function getVulnScanTarget(id: string, orgId: string): Promise<VulnScanTarget | undefined> {
  const [target] = await db
    .select()
    .from(vulnScanTargets)
    .where(and(eq(vulnScanTargets.id, id), eq(vulnScanTargets.orgId, orgId)));
  return target;
}

export async function getVulnScanSchedule(id: string, orgId: string): Promise<VulnScanSchedule | undefined> {
  const [schedule] = await db
    .select()
    .from(vulnScanSchedules)
    .where(and(eq(vulnScanSchedules.id, id), eq(vulnScanSchedules.orgId, orgId)));
  return schedule;
}
