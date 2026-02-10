import {
  type Alert, type InsertAlert, alerts,
  type Incident, type InsertIncident, incidents,
  type Organization, type InsertOrganization, organizations,
  type AuditLog, auditLogs,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, count } from "drizzle-orm";

export interface IStorage {
  getAlerts(orgId?: string): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined>;

  getIncidents(orgId?: string): Promise<Incident[]>;
  getIncident(id: string): Promise<Incident | undefined>;
  createIncident(incident: InsertIncident): Promise<Incident>;
  updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined>;

  getOrganizations(): Promise<Organization[]>;
  getOrganization(id: string): Promise<Organization | undefined>;
  createOrganization(org: InsertOrganization): Promise<Organization>;

  createAuditLog(log: Partial<AuditLog>): Promise<AuditLog>;
  getAuditLogs(orgId?: string): Promise<AuditLog[]>;

  getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
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

  async getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
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

    return {
      totalAlerts: totalAlertsResult?.count ?? 0,
      openIncidents: openResult?.count ?? 0,
      criticalAlerts: criticalResult?.count ?? 0,
      resolvedIncidents: resolvedResult?.count ?? 0,
    };
  }
}

export const storage = new DatabaseStorage();
