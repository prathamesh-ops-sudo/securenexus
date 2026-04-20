import {
  type InsertReportRun,
  type InsertReportSchedule,
  type InsertReportTemplate,
  type InsertReportTemplateVersion,
  type ReportRun,
  type ReportSchedule,
  type ReportTemplate,
  type ReportTemplateVersion,
  reportRuns,
  reportSchedules,
  reportTemplateVersions,
  reportTemplates,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, desc, eq, isNull, or, sql } from "drizzle-orm";

export async function getReportTemplates(orgId?: string): Promise<ReportTemplate[]> {
  if (orgId) {
    return db
      .select()
      .from(reportTemplates)
      .where(or(eq(reportTemplates.orgId, orgId), isNull(reportTemplates.orgId)))
      .orderBy(desc(reportTemplates.createdAt));
  }
  return db.select().from(reportTemplates).orderBy(desc(reportTemplates.createdAt));
}

export async function getReportTemplate(id: string): Promise<ReportTemplate | undefined> {
  const [t] = await db.select().from(reportTemplates).where(eq(reportTemplates.id, id));
  return t;
}

export async function createReportTemplate(template: InsertReportTemplate): Promise<ReportTemplate> {
  const [t] = await db.insert(reportTemplates).values(template).returning();
  return t;
}

export async function updateReportTemplate(
  id: string,
  data: Partial<ReportTemplate>,
): Promise<ReportTemplate | undefined> {
  const [t] = await db
    .update(reportTemplates)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(reportTemplates.id, id))
    .returning();
  return t;
}

export async function deleteReportTemplate(id: string): Promise<boolean> {
  const result = await db.delete(reportTemplates).where(eq(reportTemplates.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getReportSchedules(orgId?: string): Promise<ReportSchedule[]> {
  if (orgId) {
    return db
      .select()
      .from(reportSchedules)
      .where(eq(reportSchedules.orgId, orgId))
      .orderBy(desc(reportSchedules.createdAt));
  }
  return db.select().from(reportSchedules).orderBy(desc(reportSchedules.createdAt));
}

export async function getReportSchedule(id: string): Promise<ReportSchedule | undefined> {
  const [s] = await db.select().from(reportSchedules).where(eq(reportSchedules.id, id));
  return s;
}

export async function createReportSchedule(schedule: InsertReportSchedule): Promise<ReportSchedule> {
  const [s] = await db.insert(reportSchedules).values(schedule).returning();
  return s;
}

export async function updateReportSchedule(
  id: string,
  data: Partial<ReportSchedule>,
): Promise<ReportSchedule | undefined> {
  const [s] = await db
    .update(reportSchedules)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(reportSchedules.id, id))
    .returning();
  return s;
}

export async function deleteReportSchedule(id: string): Promise<boolean> {
  const result = await db.delete(reportSchedules).where(eq(reportSchedules.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getReportRuns(orgId?: string, templateId?: string, limit = 50): Promise<ReportRun[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(reportRuns.orgId, orgId));
  if (templateId) conditions.push(eq(reportRuns.templateId, templateId));
  if (conditions.length > 0) {
    return db
      .select()
      .from(reportRuns)
      .where(and(...conditions))
      .orderBy(desc(reportRuns.createdAt))
      .limit(limit);
  }
  return db.select().from(reportRuns).orderBy(desc(reportRuns.createdAt)).limit(limit);
}

export async function getReportRun(id: string): Promise<ReportRun | undefined> {
  const [r] = await db.select().from(reportRuns).where(eq(reportRuns.id, id));
  return r;
}

export async function createReportRun(run: InsertReportRun): Promise<ReportRun> {
  const [r] = await db.insert(reportRuns).values(run).returning();
  return r;
}

export async function updateReportRun(id: string, data: Partial<ReportRun>): Promise<ReportRun | undefined> {
  const [r] = await db.update(reportRuns).set(data).where(eq(reportRuns.id, id)).returning();
  return r;
}

export async function getDueSchedules(): Promise<ReportSchedule[]> {
  return db
    .select()
    .from(reportSchedules)
    .where(
      and(
        eq(reportSchedules.enabled, true),
        sql`${reportSchedules.nextRunAt} IS NOT NULL AND ${reportSchedules.nextRunAt} <= NOW()`,
      ),
    )
    .orderBy(asc(reportSchedules.nextRunAt));
}

// Suppression Rules

export async function getReportTemplateVersions(templateId: string, orgId?: string): Promise<ReportTemplateVersion[]> {
  const conditions = [eq(reportTemplateVersions.templateId, templateId)];
  if (orgId) {
    conditions.push(eq(reportTemplateVersions.orgId, orgId));
  }
  return db
    .select()
    .from(reportTemplateVersions)
    .where(and(...conditions))
    .orderBy(desc(reportTemplateVersions.version));
}

export async function getReportTemplateVersion(id: string): Promise<ReportTemplateVersion | undefined> {
  const [row] = await db.select().from(reportTemplateVersions).where(eq(reportTemplateVersions.id, id));
  return row;
}

export async function getLatestTemplateVersion(templateId: string): Promise<ReportTemplateVersion | undefined> {
  const [row] = await db
    .select()
    .from(reportTemplateVersions)
    .where(eq(reportTemplateVersions.templateId, templateId))
    .orderBy(desc(reportTemplateVersions.version))
    .limit(1);
  return row;
}

export async function createReportTemplateVersion(
  version: InsertReportTemplateVersion,
): Promise<ReportTemplateVersion> {
  const [created] = await db.insert(reportTemplateVersions).values(version).returning();
  return created;
}

export async function updateReportTemplateVersion(
  id: string,
  data: Partial<ReportTemplateVersion>,
): Promise<ReportTemplateVersion | undefined> {
  const [updated] = await db
    .update(reportTemplateVersions)
    .set(data)
    .where(eq(reportTemplateVersions.id, id))
    .returning();
  return updated;
}

// ==========================================
// Evidence Attachments
// ==========================================
