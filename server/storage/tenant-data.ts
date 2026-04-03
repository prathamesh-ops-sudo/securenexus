import { db } from "../db";
import { eq, and, desc } from "drizzle-orm";
import { tenantDataJobs, type TenantDataJob, type InsertTenantDataJob } from "@shared/schema";

export async function getTenantDataJobs(orgId: string): Promise<TenantDataJob[]> {
  return db
    .select()
    .from(tenantDataJobs)
    .where(eq(tenantDataJobs.orgId, orgId))
    .orderBy(desc(tenantDataJobs.createdAt));
}

export async function getTenantDataJobsByType(orgId: string, jobType: string): Promise<TenantDataJob[]> {
  return db
    .select()
    .from(tenantDataJobs)
    .where(and(eq(tenantDataJobs.orgId, orgId), eq(tenantDataJobs.jobType, jobType)))
    .orderBy(desc(tenantDataJobs.createdAt));
}

export async function getTenantDataJob(id: string): Promise<TenantDataJob | undefined> {
  const [row] = await db.select().from(tenantDataJobs).where(eq(tenantDataJobs.id, id));
  return row;
}

export async function createTenantDataJob(data: InsertTenantDataJob): Promise<TenantDataJob> {
  const [row] = await db.insert(tenantDataJobs).values(data).returning();
  return row;
}

export async function updateTenantDataJob(
  id: string,
  data: Partial<TenantDataJob>,
): Promise<TenantDataJob | undefined> {
  const [row] = await db.update(tenantDataJobs).set(data).where(eq(tenantDataJobs.id, id)).returning();
  return row;
}

export async function deleteTenantDataJob(id: string): Promise<boolean> {
  const result = await db.delete(tenantDataJobs).where(eq(tenantDataJobs.id, id));
  return (result.rowCount ?? 0) > 0;
}
