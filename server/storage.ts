import {
  type Alert, type InsertAlert, alerts,
  type Incident, type InsertIncident, incidents,
  type Organization, type InsertOrganization, organizations,
  type AuditLog, auditLogs,
  type IncidentComment, type InsertComment, incidentComments,
  type Tag, type InsertTag, tags,
  alertTags, incidentTags,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, count, ilike, or, inArray } from "drizzle-orm";

export interface IStorage {
  getAlerts(orgId?: string): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined>;
  updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined>;
  searchAlerts(query: string, orgId?: string): Promise<Alert[]>;
  getAlertsByIncident(incidentId: string): Promise<Alert[]>;

  getIncidents(orgId?: string): Promise<Incident[]>;
  getIncident(id: string): Promise<Incident | undefined>;
  createIncident(incident: InsertIncident): Promise<Incident>;
  updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined>;

  getOrganizations(): Promise<Organization[]>;
  getOrganization(id: string): Promise<Organization | undefined>;
  createOrganization(org: InsertOrganization): Promise<Organization>;

  createAuditLog(log: Partial<AuditLog>): Promise<AuditLog>;
  getAuditLogs(orgId?: string): Promise<AuditLog[]>;

  getComments(incidentId: string): Promise<IncidentComment[]>;
  createComment(comment: InsertComment): Promise<IncidentComment>;
  deleteComment(id: string): Promise<boolean>;

  getTags(): Promise<Tag[]>;
  createTag(tag: InsertTag): Promise<Tag>;
  deleteTag(id: string): Promise<boolean>;
  getAlertTags(alertId: string): Promise<Tag[]>;
  getIncidentTags(incidentId: string): Promise<Tag[]>;
  addAlertTag(alertId: string, tagId: string): Promise<void>;
  removeAlertTag(alertId: string, tagId: string): Promise<void>;
  addIncidentTag(incidentId: string, tagId: string): Promise<void>;
  removeIncidentTag(incidentId: string, tagId: string): Promise<void>;

  getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }>;
}

export class DatabaseStorage implements IStorage {
  async getAlerts(orgId?: string): Promise<Alert[]> {
    if (orgId) {
      return db.select().from(alerts).where(eq(alerts.orgId, orgId)).orderBy(desc(alerts.createdAt));
    }
    return db.select().from(alerts).orderBy(desc(alerts.createdAt));
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
    return alert;
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const [created] = await db.insert(alerts).values(alert).returning();
    return created;
  }

  async updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined> {
    const updateData: any = { status };
    if (incidentId) updateData.incidentId = incidentId;
    const [updated] = await db.update(alerts).set(updateData).where(eq(alerts.id, id)).returning();
    return updated;
  }

  async updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined> {
    const [updated] = await db.update(alerts).set(data).where(eq(alerts.id, id)).returning();
    return updated;
  }

  async searchAlerts(query: string, orgId?: string): Promise<Alert[]> {
    const searchPattern = `%${query}%`;
    const searchCondition = or(
      ilike(alerts.title, searchPattern),
      ilike(alerts.description, searchPattern),
      ilike(alerts.hostname, searchPattern),
      ilike(alerts.sourceIp, searchPattern),
    );
    if (orgId) {
      return db.select().from(alerts).where(and(eq(alerts.orgId, orgId), searchCondition)).orderBy(desc(alerts.createdAt));
    }
    return db.select().from(alerts).where(searchCondition).orderBy(desc(alerts.createdAt));
  }

  async getAlertsByIncident(incidentId: string): Promise<Alert[]> {
    return db.select().from(alerts).where(eq(alerts.incidentId, incidentId)).orderBy(desc(alerts.detectedAt));
  }

  async getIncidents(orgId?: string): Promise<Incident[]> {
    if (orgId) {
      return db.select().from(incidents).where(eq(incidents.orgId, orgId)).orderBy(desc(incidents.createdAt));
    }
    return db.select().from(incidents).orderBy(desc(incidents.createdAt));
  }

  async getIncident(id: string): Promise<Incident | undefined> {
    const [incident] = await db.select().from(incidents).where(eq(incidents.id, id));
    return incident;
  }

  async createIncident(incident: InsertIncident): Promise<Incident> {
    const [created] = await db.insert(incidents).values(incident).returning();
    return created;
  }

  async updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined> {
    const [updated] = await db.update(incidents).set({ ...data, updatedAt: new Date() }).where(eq(incidents.id, id)).returning();
    return updated;
  }

  async getOrganizations(): Promise<Organization[]> {
    return db.select().from(organizations).orderBy(desc(organizations.createdAt));
  }

  async getOrganization(id: string): Promise<Organization | undefined> {
    const [org] = await db.select().from(organizations).where(eq(organizations.id, id));
    return org;
  }

  async createOrganization(org: InsertOrganization): Promise<Organization> {
    const [created] = await db.insert(organizations).values(org).returning();
    return created;
  }

  async createAuditLog(log: Partial<AuditLog>): Promise<AuditLog> {
    const [created] = await db.insert(auditLogs).values(log as any).returning();
    return created;
  }

  async getAuditLogs(orgId?: string): Promise<AuditLog[]> {
    if (orgId) {
      return db.select().from(auditLogs).where(eq(auditLogs.orgId, orgId)).orderBy(desc(auditLogs.createdAt));
    }
    return db.select().from(auditLogs).orderBy(desc(auditLogs.createdAt));
  }

  async getComments(incidentId: string): Promise<IncidentComment[]> {
    return db.select().from(incidentComments).where(eq(incidentComments.incidentId, incidentId)).orderBy(desc(incidentComments.createdAt));
  }

  async createComment(comment: InsertComment): Promise<IncidentComment> {
    const [created] = await db.insert(incidentComments).values(comment).returning();
    return created;
  }

  async deleteComment(id: string): Promise<boolean> {
    const result = await db.delete(incidentComments).where(eq(incidentComments.id, id)).returning();
    return result.length > 0;
  }

  async getTags(): Promise<Tag[]> {
    return db.select().from(tags).orderBy(tags.name);
  }

  async createTag(tag: InsertTag): Promise<Tag> {
    const [created] = await db.insert(tags).values(tag).returning();
    return created;
  }

  async deleteTag(id: string): Promise<boolean> {
    const result = await db.delete(tags).where(eq(tags.id, id)).returning();
    return result.length > 0;
  }

  async getAlertTags(alertId: string): Promise<Tag[]> {
    const rows = await db.select({ tag: tags }).from(alertTags).innerJoin(tags, eq(alertTags.tagId, tags.id)).where(eq(alertTags.alertId, alertId));
    return rows.map(r => r.tag);
  }

  async getIncidentTags(incidentId: string): Promise<Tag[]> {
    const rows = await db.select({ tag: tags }).from(incidentTags).innerJoin(tags, eq(incidentTags.tagId, tags.id)).where(eq(incidentTags.incidentId, incidentId));
    return rows.map(r => r.tag);
  }

  async addAlertTag(alertId: string, tagId: string): Promise<void> {
    await db.insert(alertTags).values({ alertId, tagId }).onConflictDoNothing();
  }

  async removeAlertTag(alertId: string, tagId: string): Promise<void> {
    await db.delete(alertTags).where(and(eq(alertTags.alertId, alertId), eq(alertTags.tagId, tagId)));
  }

  async addIncidentTag(incidentId: string, tagId: string): Promise<void> {
    await db.insert(incidentTags).values({ incidentId, tagId }).onConflictDoNothing();
  }

  async removeIncidentTag(incidentId: string, tagId: string): Promise<void> {
    await db.delete(incidentTags).where(and(eq(incidentTags.incidentId, incidentId), eq(incidentTags.tagId, tagId)));
  }

  async getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }> {
    const conditions = orgId ? [eq(alerts.orgId, orgId)] : [];
    const incidentConditions = orgId ? [eq(incidents.orgId, orgId)] : [];

    const [totalAlertsResult] = await db.select({ count: count() }).from(alerts).where(conditions.length ? conditions[0] : undefined);
    const [criticalResult] = await db.select({ count: count() }).from(alerts).where(
      conditions.length ? and(conditions[0], eq(alerts.severity, "critical")) : eq(alerts.severity, "critical")
    );
    const [openResult] = await db.select({ count: count() }).from(incidents).where(
      incidentConditions.length ? and(incidentConditions[0], eq(incidents.status, "open")) : eq(incidents.status, "open")
    );
    const [resolvedResult] = await db.select({ count: count() }).from(incidents).where(
      incidentConditions.length ? and(incidentConditions[0], eq(incidents.status, "resolved")) : eq(incidents.status, "resolved")
    );

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const [newTodayResult] = await db.select({ count: count() }).from(alerts).where(
      conditions.length
        ? and(conditions[0], sql`${alerts.createdAt} >= ${today}`)
        : sql`${alerts.createdAt} >= ${today}`
    );
    const [escalatedResult] = await db.select({ count: count() }).from(incidents).where(
      incidentConditions.length
        ? and(incidentConditions[0], eq(incidents.escalated, true))
        : eq(incidents.escalated, true)
    );

    return {
      totalAlerts: totalAlertsResult?.count ?? 0,
      openIncidents: openResult?.count ?? 0,
      criticalAlerts: criticalResult?.count ?? 0,
      resolvedIncidents: resolvedResult?.count ?? 0,
      newAlertsToday: newTodayResult?.count ?? 0,
      escalatedIncidents: escalatedResult?.count ?? 0,
    };
  }
}

export const storage = new DatabaseStorage();
