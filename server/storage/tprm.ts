import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  tprmVendors,
  tprmAssessments,
  type TprmVendor,
  type InsertTprmVendor,
  type TprmAssessment,
  type InsertTprmAssessment,
} from "@shared/schema";

// ─── Vendors ─────────────────────────────────────────────────────────────────
export async function getTprmVendors(orgId: string): Promise<TprmVendor[]> {
  return db.select().from(tprmVendors).where(eq(tprmVendors.orgId, orgId)).orderBy(desc(tprmVendors.createdAt));
}

export async function getTprmVendor(id: string): Promise<TprmVendor | undefined> {
  const [vendor] = await db.select().from(tprmVendors).where(eq(tprmVendors.id, id));
  return vendor;
}

export async function createTprmVendor(data: InsertTprmVendor): Promise<TprmVendor> {
  const [created] = await db.insert(tprmVendors).values(data).returning();
  return created;
}

export async function updateTprmVendor(id: string, data: Partial<TprmVendor>): Promise<TprmVendor | undefined> {
  const [updated] = await db
    .update(tprmVendors)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(tprmVendors.id, id))
    .returning();
  return updated;
}

export async function deleteTprmVendor(id: string): Promise<void> {
  await db.delete(tprmVendors).where(eq(tprmVendors.id, id));
}

// ─── Assessments ─────────────────────────────────────────────────────────────
export async function getTprmAssessments(orgId: string): Promise<TprmAssessment[]> {
  return db
    .select()
    .from(tprmAssessments)
    .where(eq(tprmAssessments.orgId, orgId))
    .orderBy(desc(tprmAssessments.createdAt));
}

export async function getTprmAssessmentsByVendor(orgId: string, vendorId: string): Promise<TprmAssessment[]> {
  return db
    .select()
    .from(tprmAssessments)
    .where(and(eq(tprmAssessments.orgId, orgId), eq(tprmAssessments.vendorId, vendorId)))
    .orderBy(desc(tprmAssessments.createdAt));
}

export async function getTprmAssessment(id: string): Promise<TprmAssessment | undefined> {
  const [assessment] = await db.select().from(tprmAssessments).where(eq(tprmAssessments.id, id));
  return assessment;
}

export async function createTprmAssessment(data: InsertTprmAssessment): Promise<TprmAssessment> {
  const [created] = await db.insert(tprmAssessments).values(data).returning();
  return created;
}

export async function updateTprmAssessment(
  id: string,
  data: Partial<TprmAssessment>,
): Promise<TprmAssessment | undefined> {
  const [updated] = await db
    .update(tprmAssessments)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(tprmAssessments.id, id))
    .returning();
  return updated;
}

export async function deleteTprmAssessment(id: string): Promise<void> {
  await db.delete(tprmAssessments).where(eq(tprmAssessments.id, id));
}
