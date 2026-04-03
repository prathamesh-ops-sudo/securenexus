import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  complianceGapAssessments,
  type ComplianceGapAssessment,
  type InsertComplianceGapAssessment,
} from "@shared/schema";

export async function getComplianceGapAssessments(orgId: string): Promise<ComplianceGapAssessment[]> {
  return db
    .select()
    .from(complianceGapAssessments)
    .where(eq(complianceGapAssessments.orgId, orgId))
    .orderBy(desc(complianceGapAssessments.createdAt));
}

export async function getComplianceGapAssessment(id: string): Promise<ComplianceGapAssessment | undefined> {
  const [assessment] = await db.select().from(complianceGapAssessments).where(eq(complianceGapAssessments.id, id));
  return assessment;
}

export async function getComplianceGapsByFramework(
  orgId: string,
  frameworkId: string,
): Promise<ComplianceGapAssessment[]> {
  return db
    .select()
    .from(complianceGapAssessments)
    .where(and(eq(complianceGapAssessments.orgId, orgId), eq(complianceGapAssessments.frameworkId, frameworkId)))
    .orderBy(desc(complianceGapAssessments.createdAt));
}

export async function getComplianceGapsByStatus(orgId: string, status: string): Promise<ComplianceGapAssessment[]> {
  return db
    .select()
    .from(complianceGapAssessments)
    .where(and(eq(complianceGapAssessments.orgId, orgId), eq(complianceGapAssessments.status, status)))
    .orderBy(desc(complianceGapAssessments.createdAt));
}

export async function createComplianceGapAssessment(
  data: InsertComplianceGapAssessment,
): Promise<ComplianceGapAssessment> {
  const [created] = await db.insert(complianceGapAssessments).values(data).returning();
  return created;
}

export async function updateComplianceGapAssessment(
  id: string,
  data: Partial<ComplianceGapAssessment>,
): Promise<ComplianceGapAssessment | undefined> {
  const [updated] = await db
    .update(complianceGapAssessments)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(complianceGapAssessments.id, id))
    .returning();
  return updated;
}

export async function deleteComplianceGapAssessment(id: string): Promise<void> {
  await db.delete(complianceGapAssessments).where(eq(complianceGapAssessments.id, id));
}
