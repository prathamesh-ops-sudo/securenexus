import {
  type Alert, type InsertAlert, alerts,
  type Incident, type InsertIncident, incidents,
  type Organization, type InsertOrganization, organizations,
  type AuditLog, auditLogs,
  type IncidentComment, type InsertComment, incidentComments,
  type Tag, type InsertTag, tags,
  type ApiKey, type InsertApiKey, apiKeys,
  type IngestionLog, type InsertIngestionLog, ingestionLogs,
  type Connector, type InsertConnector, connectors,
  type AiFeedback, type InsertAiFeedback, aiFeedback,
  type Playbook, type InsertPlaybook, playbooks,
  type PlaybookExecution, type InsertPlaybookExecution, playbookExecutions,
  type ThreatIntelConfig, type InsertThreatIntelConfig, threatIntelConfigs,
  type CompliancePolicy, type InsertCompliancePolicy, compliancePolicies,
  type DsarRequest, type InsertDsarRequest, dsarRequests,
  type IntegrationConfig, type InsertIntegrationConfig, integrationConfigs,
  type NotificationChannel, type InsertNotificationChannel, notificationChannels,
  type ResponseAction, type InsertResponseAction, responseActions,
  type PredictiveAnomaly, type InsertPredictiveAnomaly, predictiveAnomalies,
  type AttackSurfaceAsset, type InsertAttackSurfaceAsset, attackSurfaceAssets,
  type RiskForecast, type InsertRiskForecast, riskForecasts,
  type HardeningRecommendation, type InsertHardeningRecommendation, hardeningRecommendations,
  alertTags, incidentTags,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, count, ilike, or, asc } from "drizzle-orm";
import { createHash } from "crypto";

export interface IStorage {
  getAlerts(orgId?: string): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined>;
  updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined>;
  searchAlerts(query: string, orgId?: string): Promise<Alert[]>;
  getAlertsByIncident(incidentId: string): Promise<Alert[]>;
  findAlertByDedup(orgId: string | null, source: string, sourceEventId: string): Promise<Alert | undefined>;
  upsertAlert(alert: InsertAlert): Promise<{ alert: Alert; isNew: boolean }>;

  getIncidents(orgId?: string): Promise<Incident[]>;
  getIncident(id: string): Promise<Incident | undefined>;
  createIncident(incident: InsertIncident): Promise<Incident>;
  updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined>;

  getOrganizations(): Promise<Organization[]>;
  getOrganization(id: string): Promise<Organization | undefined>;
  createOrganization(org: InsertOrganization): Promise<Organization>;

  createAuditLog(log: Partial<AuditLog>): Promise<AuditLog>;
  getAuditLogs(orgId?: string): Promise<AuditLog[]>;
  getAuditLogsByResource(resourceType: string, resourceId: string): Promise<AuditLog[]>;

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

  createApiKey(key: InsertApiKey): Promise<ApiKey>;
  getApiKeys(orgId?: string): Promise<ApiKey[]>;
  getApiKeyByHash(hash: string): Promise<ApiKey | undefined>;
  revokeApiKey(id: string): Promise<ApiKey | undefined>;
  updateApiKeyLastUsed(id: string): Promise<void>;

  createIngestionLog(log: InsertIngestionLog): Promise<IngestionLog>;
  getIngestionLogs(orgId?: string, limit?: number): Promise<IngestionLog[]>;
  getIngestionStats(orgId?: string): Promise<{
    totalIngested: number;
    totalCreated: number;
    totalDeduped: number;
    totalFailed: number;
    sourceBreakdown: { source: string; count: number; lastReceived: Date | null }[];
  }>;

  getConnectors(orgId?: string): Promise<Connector[]>;
  getConnector(id: string): Promise<Connector | undefined>;
  createConnector(connector: InsertConnector): Promise<Connector>;
  updateConnector(id: string, data: Partial<Connector>): Promise<Connector | undefined>;
  deleteConnector(id: string): Promise<boolean>;
  updateConnectorSyncStatus(id: string, data: { lastSyncAt: Date; lastSyncStatus: string; lastSyncAlerts: number; lastSyncError?: string; totalAlertsSynced?: number }): Promise<void>;

  createAiFeedback(feedback: InsertAiFeedback): Promise<AiFeedback>;
  getAiFeedback(resourceType?: string, resourceId?: string): Promise<AiFeedback[]>;

  getPlaybooks(): Promise<Playbook[]>;
  getPlaybook(id: string): Promise<Playbook | undefined>;
  createPlaybook(playbook: InsertPlaybook): Promise<Playbook>;
  updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook | undefined>;
  deletePlaybook(id: string): Promise<boolean>;

  getPlaybookExecutions(playbookId?: string, limit?: number): Promise<PlaybookExecution[]>;
  createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution>;
  updatePlaybookExecution(id: string, data: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined>;

  getThreatIntelConfigs(orgId: string): Promise<ThreatIntelConfig[]>;
  getThreatIntelConfig(orgId: string, provider: string): Promise<ThreatIntelConfig | undefined>;
  upsertThreatIntelConfig(config: InsertThreatIntelConfig): Promise<ThreatIntelConfig>;
  deleteThreatIntelConfig(orgId: string, provider: string): Promise<void>;

  getDashboardStats(orgId?: string): Promise<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }>;

  getDashboardAnalytics(orgId?: string): Promise<{
    severityDistribution: { name: string; value: number }[];
    sourceDistribution: { name: string; value: number }[];
    categoryDistribution: { name: string; value: number }[];
    statusDistribution: { name: string; value: number }[];
    alertTrend: { date: string; count: number }[];
    mttrHours: number | null;
    topMitreTactics: { name: string; value: number }[];
    connectorHealth: { name: string; type: string; status: string; lastSyncAt: string | null; lastSyncAlerts: number; lastSyncError: string | null }[];
    ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
  }>;

  getCompliancePolicy(orgId: string): Promise<CompliancePolicy | undefined>;
  upsertCompliancePolicy(policy: InsertCompliancePolicy): Promise<CompliancePolicy>;

  getDsarRequests(orgId: string): Promise<DsarRequest[]>;
  getDsarRequest(id: string): Promise<DsarRequest | undefined>;
  createDsarRequest(request: InsertDsarRequest): Promise<DsarRequest>;
  updateDsarRequest(id: string, data: Partial<DsarRequest>): Promise<DsarRequest | undefined>;

  getAuditLogCount(orgId?: string): Promise<number>;
  getOldestAuditLog(orgId?: string): Promise<AuditLog | undefined>;
  getLatestAuditLogSequence(orgId: string): Promise<{ sequenceNum: number; entryHash: string } | null>;

  getIntegrationConfigs(orgId?: string): Promise<IntegrationConfig[]>;
  getIntegrationConfig(id: string): Promise<IntegrationConfig | undefined>;
  createIntegrationConfig(config: InsertIntegrationConfig): Promise<IntegrationConfig>;
  updateIntegrationConfig(id: string, data: Partial<IntegrationConfig>): Promise<IntegrationConfig | undefined>;
  deleteIntegrationConfig(id: string): Promise<boolean>;

  getNotificationChannels(orgId?: string): Promise<NotificationChannel[]>;
  getNotificationChannel(id: string): Promise<NotificationChannel | undefined>;
  createNotificationChannel(channel: InsertNotificationChannel): Promise<NotificationChannel>;
  updateNotificationChannel(id: string, data: Partial<NotificationChannel>): Promise<NotificationChannel | undefined>;
  deleteNotificationChannel(id: string): Promise<boolean>;

  getResponseActions(orgId?: string, incidentId?: string): Promise<ResponseAction[]>;
  getResponseAction(id: string): Promise<ResponseAction | undefined>;
  createResponseAction(action: InsertResponseAction): Promise<ResponseAction>;
  updateResponseAction(id: string, data: Partial<ResponseAction>): Promise<ResponseAction | undefined>;

  // Predictive Defense
  getPredictiveAnomalies(orgId?: string): Promise<PredictiveAnomaly[]>;
  createPredictiveAnomaly(anomaly: InsertPredictiveAnomaly): Promise<PredictiveAnomaly>;
  clearPredictiveAnomalies(orgId: string): Promise<void>;
  getAttackSurfaceAssets(orgId?: string): Promise<AttackSurfaceAsset[]>;
  upsertAttackSurfaceAsset(asset: InsertAttackSurfaceAsset): Promise<AttackSurfaceAsset>;
  clearAttackSurfaceAssets(orgId: string): Promise<void>;
  getRiskForecasts(orgId?: string): Promise<RiskForecast[]>;
  createRiskForecast(forecast: InsertRiskForecast): Promise<RiskForecast>;
  clearRiskForecasts(orgId: string): Promise<void>;
  getHardeningRecommendations(orgId?: string): Promise<HardeningRecommendation[]>;
  createHardeningRecommendation(rec: InsertHardeningRecommendation): Promise<HardeningRecommendation>;
  updateHardeningRecommendation(id: string, updates: Partial<InsertHardeningRecommendation>): Promise<HardeningRecommendation | undefined>;
  clearHardeningRecommendations(orgId: string): Promise<void>;
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

  async findAlertByDedup(orgId: string | null, source: string, sourceEventId: string): Promise<Alert | undefined> {
    if (!sourceEventId) return undefined;
    const conditions = [eq(alerts.source, source), eq(alerts.sourceEventId, sourceEventId)];
    if (orgId) conditions.push(eq(alerts.orgId, orgId));
    const [existing] = await db.select().from(alerts).where(and(...conditions));
    return existing;
  }

  async upsertAlert(alert: InsertAlert): Promise<{ alert: Alert; isNew: boolean }> {
    if (alert.sourceEventId) {
      const existing = await this.findAlertByDedup(alert.orgId || null, alert.source, alert.sourceEventId);
      if (existing) {
        return { alert: existing, isNew: false };
      }
    }
    const created = await this.createAlert(alert);
    return { alert: created, isNew: true };
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
    const orgId = log.orgId || "system";
    const lastSeq = await this.getLatestAuditLogSequence(orgId);
    const sequenceNum = lastSeq ? lastSeq.sequenceNum + 1 : 1;
    const prevHash = lastSeq ? lastSeq.entryHash : "genesis";
    const entryHash = createHash("sha256").update(JSON.stringify({
      prevHash,
      action: log.action,
      userId: log.userId,
      resourceType: log.resourceType,
      resourceId: log.resourceId,
      details: log.details,
      sequenceNum,
    })).digest("hex");
    const [created] = await db.insert(auditLogs).values({
      ...log,
      sequenceNum,
      prevHash,
      entryHash,
    } as any).returning();
    return created;
  }

  async getAuditLogs(orgId?: string): Promise<AuditLog[]> {
    if (orgId) {
      return db.select().from(auditLogs).where(eq(auditLogs.orgId, orgId)).orderBy(desc(auditLogs.createdAt));
    }
    return db.select().from(auditLogs).orderBy(desc(auditLogs.createdAt));
  }

  async getAuditLogsByResource(resourceType: string, resourceId: string): Promise<AuditLog[]> {
    return db.select().from(auditLogs)
      .where(and(eq(auditLogs.resourceType, resourceType), eq(auditLogs.resourceId, resourceId)))
      .orderBy(desc(auditLogs.createdAt));
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

  async createApiKey(key: InsertApiKey): Promise<ApiKey> {
    const [created] = await db.insert(apiKeys).values(key).returning();
    return created;
  }

  async getApiKeys(orgId?: string): Promise<ApiKey[]> {
    if (orgId) {
      return db.select().from(apiKeys).where(eq(apiKeys.orgId, orgId)).orderBy(desc(apiKeys.createdAt));
    }
    return db.select().from(apiKeys).orderBy(desc(apiKeys.createdAt));
  }

  async getApiKeyByHash(hash: string): Promise<ApiKey | undefined> {
    const [key] = await db.select().from(apiKeys).where(and(eq(apiKeys.keyHash, hash), eq(apiKeys.isActive, true)));
    return key;
  }

  async revokeApiKey(id: string): Promise<ApiKey | undefined> {
    const [updated] = await db.update(apiKeys).set({ isActive: false, revokedAt: new Date() }).where(eq(apiKeys.id, id)).returning();
    return updated;
  }

  async updateApiKeyLastUsed(id: string): Promise<void> {
    await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, id));
  }

  async createIngestionLog(log: InsertIngestionLog): Promise<IngestionLog> {
    const [created] = await db.insert(ingestionLogs).values(log).returning();
    return created;
  }

  async getIngestionLogs(orgId?: string, limit = 50): Promise<IngestionLog[]> {
    if (orgId) {
      return db.select().from(ingestionLogs).where(eq(ingestionLogs.orgId, orgId)).orderBy(desc(ingestionLogs.receivedAt)).limit(limit);
    }
    return db.select().from(ingestionLogs).orderBy(desc(ingestionLogs.receivedAt)).limit(limit);
  }

  async getIngestionStats(orgId?: string): Promise<{
    totalIngested: number;
    totalCreated: number;
    totalDeduped: number;
    totalFailed: number;
    sourceBreakdown: { source: string; count: number; lastReceived: Date | null }[];
  }> {
    const conditions = orgId ? [eq(ingestionLogs.orgId, orgId)] : [];
    const condition = conditions.length ? conditions[0] : undefined;

    const [totals] = await db.select({
      totalIngested: sql<number>`COALESCE(SUM(${ingestionLogs.alertsReceived}), 0)::int`,
      totalCreated: sql<number>`COALESCE(SUM(${ingestionLogs.alertsCreated}), 0)::int`,
      totalDeduped: sql<number>`COALESCE(SUM(${ingestionLogs.alertsDeduped}), 0)::int`,
      totalFailed: sql<number>`COALESCE(SUM(${ingestionLogs.alertsFailed}), 0)::int`,
    }).from(ingestionLogs).where(condition);

    const breakdown = await db.select({
      source: ingestionLogs.source,
      count: sql<number>`COUNT(*)::int`,
      lastReceived: sql<Date | null>`MAX(${ingestionLogs.receivedAt})`,
    }).from(ingestionLogs).where(condition).groupBy(ingestionLogs.source);

    return {
      totalIngested: totals?.totalIngested ?? 0,
      totalCreated: totals?.totalCreated ?? 0,
      totalDeduped: totals?.totalDeduped ?? 0,
      totalFailed: totals?.totalFailed ?? 0,
      sourceBreakdown: breakdown,
    };
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

  async getConnectors(orgId?: string): Promise<Connector[]> {
    if (orgId) {
      return db.select().from(connectors).where(eq(connectors.orgId, orgId)).orderBy(desc(connectors.createdAt));
    }
    return db.select().from(connectors).orderBy(desc(connectors.createdAt));
  }

  async getConnector(id: string): Promise<Connector | undefined> {
    const [result] = await db.select().from(connectors).where(eq(connectors.id, id));
    return result;
  }

  async createConnector(connector: InsertConnector): Promise<Connector> {
    const [result] = await db.insert(connectors).values(connector).returning();
    return result;
  }

  async updateConnector(id: string, data: Partial<Connector>): Promise<Connector | undefined> {
    const [result] = await db.update(connectors).set({ ...data, updatedAt: new Date() }).where(eq(connectors.id, id)).returning();
    return result;
  }

  async deleteConnector(id: string): Promise<boolean> {
    const result = await db.delete(connectors).where(eq(connectors.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async updateConnectorSyncStatus(id: string, data: { lastSyncAt: Date; lastSyncStatus: string; lastSyncAlerts: number; lastSyncError?: string; totalAlertsSynced?: number }): Promise<void> {
    const updateData: any = {
      lastSyncAt: data.lastSyncAt,
      lastSyncStatus: data.lastSyncStatus,
      lastSyncAlerts: data.lastSyncAlerts,
      lastSyncError: data.lastSyncError || null,
      updatedAt: new Date(),
    };
    if (data.totalAlertsSynced !== undefined) {
      updateData.totalAlertsSynced = data.totalAlertsSynced;
    }
    await db.update(connectors).set(updateData).where(eq(connectors.id, id));
  }

  async createAiFeedback(feedback: InsertAiFeedback): Promise<AiFeedback> {
    const [created] = await db.insert(aiFeedback).values(feedback).returning();
    return created;
  }

  async getAiFeedback(resourceType?: string, resourceId?: string): Promise<AiFeedback[]> {
    const conditions = [];
    if (resourceType) conditions.push(eq(aiFeedback.resourceType, resourceType));
    if (resourceId) conditions.push(eq(aiFeedback.resourceId, resourceId));
    const condition = conditions.length > 0 ? and(...conditions) : undefined;
    return db.select().from(aiFeedback).where(condition).orderBy(desc(aiFeedback.createdAt));
  }

  async getPlaybooks(): Promise<Playbook[]> {
    return db.select().from(playbooks).orderBy(desc(playbooks.updatedAt));
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const [playbook] = await db.select().from(playbooks).where(eq(playbooks.id, id));
    return playbook;
  }

  async createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
    const [created] = await db.insert(playbooks).values(playbook).returning();
    return created;
  }

  async updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook | undefined> {
    const [updated] = await db.update(playbooks).set({ ...data, updatedAt: new Date() }).where(eq(playbooks.id, id)).returning();
    return updated;
  }

  async deletePlaybook(id: string): Promise<boolean> {
    const result = await db.delete(playbooks).where(eq(playbooks.id, id)).returning();
    return result.length > 0;
  }

  async getPlaybookExecutions(playbookId?: string, limit = 50): Promise<PlaybookExecution[]> {
    if (playbookId) {
      return db.select().from(playbookExecutions).where(eq(playbookExecutions.playbookId, playbookId)).orderBy(desc(playbookExecutions.createdAt)).limit(limit);
    }
    return db.select().from(playbookExecutions).orderBy(desc(playbookExecutions.createdAt)).limit(limit);
  }

  async createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
    const [created] = await db.insert(playbookExecutions).values(execution).returning();
    return created;
  }

  async updatePlaybookExecution(id: string, data: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
    const [updated] = await db.update(playbookExecutions).set(data).where(eq(playbookExecutions.id, id)).returning();
    return updated;
  }

  async getThreatIntelConfigs(orgId: string): Promise<ThreatIntelConfig[]> {
    return db.select().from(threatIntelConfigs).where(eq(threatIntelConfigs.orgId, orgId)).orderBy(desc(threatIntelConfigs.createdAt));
  }

  async getThreatIntelConfig(orgId: string, provider: string): Promise<ThreatIntelConfig | undefined> {
    const [config] = await db.select().from(threatIntelConfigs).where(and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider)));
    return config;
  }

  async upsertThreatIntelConfig(config: InsertThreatIntelConfig): Promise<ThreatIntelConfig> {
    const [result] = await db.insert(threatIntelConfigs).values(config).onConflictDoUpdate({
      target: [threatIntelConfigs.orgId, threatIntelConfigs.provider],
      set: {
        apiKey: config.apiKey,
        enabled: config.enabled,
        updatedAt: new Date(),
      },
    }).returning();
    return result;
  }

  async deleteThreatIntelConfig(orgId: string, provider: string): Promise<void> {
    await db.delete(threatIntelConfigs).where(and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider)));
  }

  async getDashboardAnalytics(orgId?: string): Promise<{
    severityDistribution: { name: string; value: number }[];
    sourceDistribution: { name: string; value: number }[];
    categoryDistribution: { name: string; value: number }[];
    statusDistribution: { name: string; value: number }[];
    alertTrend: { date: string; count: number }[];
    mttrHours: number | null;
    topMitreTactics: { name: string; value: number }[];
    connectorHealth: { name: string; type: string; status: string; lastSyncAt: string | null; lastSyncAlerts: number; lastSyncError: string | null }[];
    ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
  }> {
    const alertCond = orgId ? eq(alerts.orgId, orgId) : undefined;
    const incidentCond = orgId ? eq(incidents.orgId, orgId) : undefined;
    const connectorCond = orgId ? eq(connectors.orgId, orgId) : undefined;
    const ingestionCond = orgId ? eq(ingestionLogs.orgId, orgId) : undefined;

    const severityDistribution = await db
      .select({ name: alerts.severity, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.severity);

    const sourceDistribution = await db
      .select({ name: alerts.source, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.source).orderBy(sql`COUNT(*) DESC`).limit(10);

    const categoryDistribution = await db
      .select({ name: alerts.category, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.category).orderBy(sql`COUNT(*) DESC`).limit(10);

    const statusDistribution = await db
      .select({ name: alerts.status, value: sql<number>`COUNT(*)::int` })
      .from(alerts).where(alertCond).groupBy(alerts.status);

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const trendCond = alertCond
      ? and(alertCond, sql`${alerts.createdAt} >= ${sevenDaysAgo}`)
      : sql`${alerts.createdAt} >= ${sevenDaysAgo}`;
    const alertTrend = await db
      .select({
        date: sql<string>`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`,
        count: sql<number>`COUNT(*)::int`,
      })
      .from(alerts).where(trendCond)
      .groupBy(sql`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`)
      .orderBy(sql`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`);

    const mttrResult = await db
      .select({
        avgHours: sql<number | null>`AVG(EXTRACT(EPOCH FROM (${incidents.resolvedAt} - ${incidents.createdAt})) / 3600)`,
      })
      .from(incidents)
      .where(incidentCond ? and(incidentCond, sql`${incidents.resolvedAt} IS NOT NULL`) : sql`${incidents.resolvedAt} IS NOT NULL`);
    const mttrHours = mttrResult[0]?.avgHours ? Math.round(mttrResult[0].avgHours * 10) / 10 : null;

    const tacticRows = await db
      .select({ tactic: alerts.mitreTactic, value: sql<number>`COUNT(*)::int` })
      .from(alerts)
      .where(alertCond ? and(alertCond, sql`${alerts.mitreTactic} IS NOT NULL AND ${alerts.mitreTactic} != ''`) : sql`${alerts.mitreTactic} IS NOT NULL AND ${alerts.mitreTactic} != ''`)
      .groupBy(alerts.mitreTactic)
      .orderBy(sql`COUNT(*) DESC`)
      .limit(8);
    const topMitreTactics = tacticRows.map(r => ({ name: r.tactic || "Unknown", value: r.value }));

    const connectorRows = await db
      .select({
        name: connectors.name,
        type: connectors.type,
        status: connectors.status,
        lastSyncAt: connectors.lastSyncAt,
        lastSyncAlerts: connectors.lastSyncAlerts,
        lastSyncError: connectors.lastSyncError,
      })
      .from(connectors).where(connectorCond).orderBy(desc(connectors.updatedAt));
    const connectorHealth = connectorRows.map(r => ({
      name: r.name,
      type: r.type,
      status: r.status,
      lastSyncAt: r.lastSyncAt?.toISOString() || null,
      lastSyncAlerts: r.lastSyncAlerts || 0,
      lastSyncError: r.lastSyncError,
    }));

    const ingestionTrendCond = ingestionCond
      ? and(ingestionCond, sql`${ingestionLogs.receivedAt} >= ${sevenDaysAgo}`)
      : sql`${ingestionLogs.receivedAt} >= ${sevenDaysAgo}`;
    const ingestionRate = await db
      .select({
        date: sql<string>`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`,
        created: sql<number>`COALESCE(SUM(${ingestionLogs.alertsCreated}), 0)::int`,
        deduped: sql<number>`COALESCE(SUM(${ingestionLogs.alertsDeduped}), 0)::int`,
        failed: sql<number>`COALESCE(SUM(${ingestionLogs.alertsFailed}), 0)::int`,
      })
      .from(ingestionLogs).where(ingestionTrendCond)
      .groupBy(sql`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`)
      .orderBy(sql`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`);

    return {
      severityDistribution: severityDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      sourceDistribution: sourceDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      categoryDistribution: categoryDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      statusDistribution: statusDistribution.map(r => ({ name: r.name || "unknown", value: r.value })),
      alertTrend,
      mttrHours,
      topMitreTactics,
      connectorHealth,
      ingestionRate,
    };
  }
  async getCompliancePolicy(orgId: string): Promise<CompliancePolicy | undefined> {
    const [policy] = await db.select().from(compliancePolicies).where(eq(compliancePolicies.orgId, orgId));
    return policy;
  }

  async upsertCompliancePolicy(policy: InsertCompliancePolicy): Promise<CompliancePolicy> {
    const [result] = await db.insert(compliancePolicies).values(policy).onConflictDoUpdate({
      target: [compliancePolicies.orgId],
      set: {
        alertRetentionDays: policy.alertRetentionDays,
        incidentRetentionDays: policy.incidentRetentionDays,
        auditLogRetentionDays: policy.auditLogRetentionDays,
        piiMaskingEnabled: policy.piiMaskingEnabled,
        pseudonymizeExports: policy.pseudonymizeExports,
        enabledFrameworks: policy.enabledFrameworks,
        dataProcessingBasis: policy.dataProcessingBasis,
        dpoEmail: policy.dpoEmail,
        dsarSlaDays: policy.dsarSlaDays,
        updatedAt: new Date(),
      },
    }).returning();
    return result;
  }

  async getDsarRequests(orgId: string): Promise<DsarRequest[]> {
    return db.select().from(dsarRequests).where(eq(dsarRequests.orgId, orgId)).orderBy(desc(dsarRequests.createdAt));
  }

  async getDsarRequest(id: string): Promise<DsarRequest | undefined> {
    const [request] = await db.select().from(dsarRequests).where(eq(dsarRequests.id, id));
    return request;
  }

  async createDsarRequest(request: InsertDsarRequest): Promise<DsarRequest> {
    const [created] = await db.insert(dsarRequests).values(request).returning();
    return created;
  }

  async updateDsarRequest(id: string, data: Partial<DsarRequest>): Promise<DsarRequest | undefined> {
    const [updated] = await db.update(dsarRequests).set({ ...data, updatedAt: new Date() }).where(eq(dsarRequests.id, id)).returning();
    return updated;
  }

  async getAuditLogCount(orgId?: string): Promise<number> {
    const condition = orgId ? eq(auditLogs.orgId, orgId) : undefined;
    const [result] = await db.select({ count: count() }).from(auditLogs).where(condition);
    return result?.count ?? 0;
  }

  async getOldestAuditLog(orgId?: string): Promise<AuditLog | undefined> {
    const condition = orgId ? eq(auditLogs.orgId, orgId) : undefined;
    const [oldest] = await db.select().from(auditLogs).where(condition).orderBy(asc(auditLogs.createdAt)).limit(1);
    return oldest;
  }

  async getLatestAuditLogSequence(orgId: string): Promise<{ sequenceNum: number; entryHash: string } | null> {
    const [result] = await db.select({
      sequenceNum: auditLogs.sequenceNum,
      entryHash: auditLogs.entryHash,
    }).from(auditLogs).where(eq(auditLogs.orgId, orgId)).orderBy(desc(auditLogs.sequenceNum)).limit(1);
    if (!result || result.sequenceNum === null || result.entryHash === null) return null;
    return { sequenceNum: result.sequenceNum, entryHash: result.entryHash };
  }

  async getIntegrationConfigs(orgId?: string): Promise<IntegrationConfig[]> {
    if (orgId) {
      return db.select().from(integrationConfigs).where(eq(integrationConfigs.orgId, orgId)).orderBy(desc(integrationConfigs.createdAt));
    }
    return db.select().from(integrationConfigs).orderBy(desc(integrationConfigs.createdAt));
  }

  async getIntegrationConfig(id: string): Promise<IntegrationConfig | undefined> {
    const [config] = await db.select().from(integrationConfigs).where(eq(integrationConfigs.id, id));
    return config;
  }

  async createIntegrationConfig(config: InsertIntegrationConfig): Promise<IntegrationConfig> {
    const [created] = await db.insert(integrationConfigs).values(config).returning();
    return created;
  }

  async updateIntegrationConfig(id: string, data: Partial<IntegrationConfig>): Promise<IntegrationConfig | undefined> {
    const [updated] = await db.update(integrationConfigs).set({ ...data, updatedAt: new Date() }).where(eq(integrationConfigs.id, id)).returning();
    return updated;
  }

  async deleteIntegrationConfig(id: string): Promise<boolean> {
    const result = await db.delete(integrationConfigs).where(eq(integrationConfigs.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getNotificationChannels(orgId?: string): Promise<NotificationChannel[]> {
    if (orgId) {
      return db.select().from(notificationChannels).where(eq(notificationChannels.orgId, orgId)).orderBy(desc(notificationChannels.createdAt));
    }
    return db.select().from(notificationChannels).orderBy(desc(notificationChannels.createdAt));
  }

  async getNotificationChannel(id: string): Promise<NotificationChannel | undefined> {
    const [channel] = await db.select().from(notificationChannels).where(eq(notificationChannels.id, id));
    return channel;
  }

  async createNotificationChannel(channel: InsertNotificationChannel): Promise<NotificationChannel> {
    const [created] = await db.insert(notificationChannels).values(channel).returning();
    return created;
  }

  async updateNotificationChannel(id: string, data: Partial<NotificationChannel>): Promise<NotificationChannel | undefined> {
    const [updated] = await db.update(notificationChannels).set({ ...data, updatedAt: new Date() }).where(eq(notificationChannels.id, id)).returning();
    return updated;
  }

  async deleteNotificationChannel(id: string): Promise<boolean> {
    const result = await db.delete(notificationChannels).where(eq(notificationChannels.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getResponseActions(orgId?: string, incidentId?: string): Promise<ResponseAction[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(responseActions.orgId, orgId));
    if (incidentId) conditions.push(eq(responseActions.incidentId, incidentId));
    const condition = conditions.length > 0 ? and(...conditions) : undefined;
    return db.select().from(responseActions).where(condition).orderBy(desc(responseActions.createdAt)).limit(100);
  }

  async getResponseAction(id: string): Promise<ResponseAction | undefined> {
    const [action] = await db.select().from(responseActions).where(eq(responseActions.id, id));
    return action;
  }

  async createResponseAction(action: InsertResponseAction): Promise<ResponseAction> {
    const [created] = await db.insert(responseActions).values(action).returning();
    return created;
  }

  async updateResponseAction(id: string, data: Partial<ResponseAction>): Promise<ResponseAction | undefined> {
    const [updated] = await db.update(responseActions).set(data).where(eq(responseActions.id, id)).returning();
    return updated;
  }

  async getPredictiveAnomalies(orgId?: string): Promise<PredictiveAnomaly[]> {
    if (orgId) {
      return db.select().from(predictiveAnomalies).where(eq(predictiveAnomalies.orgId, orgId)).orderBy(desc(predictiveAnomalies.createdAt));
    }
    return db.select().from(predictiveAnomalies).orderBy(desc(predictiveAnomalies.createdAt));
  }

  async createPredictiveAnomaly(anomaly: InsertPredictiveAnomaly): Promise<PredictiveAnomaly> {
    const [created] = await db.insert(predictiveAnomalies).values(anomaly).returning();
    return created;
  }

  async clearPredictiveAnomalies(orgId: string): Promise<void> {
    await db.delete(predictiveAnomalies).where(eq(predictiveAnomalies.orgId, orgId));
  }

  async getAttackSurfaceAssets(orgId?: string): Promise<AttackSurfaceAsset[]> {
    if (orgId) {
      return db.select().from(attackSurfaceAssets).where(eq(attackSurfaceAssets.orgId, orgId)).orderBy(desc(attackSurfaceAssets.riskScore));
    }
    return db.select().from(attackSurfaceAssets).orderBy(desc(attackSurfaceAssets.riskScore));
  }

  async upsertAttackSurfaceAsset(asset: InsertAttackSurfaceAsset): Promise<AttackSurfaceAsset> {
    const conditions = [
      eq(attackSurfaceAssets.entityType, asset.entityType),
      eq(attackSurfaceAssets.entityValue, asset.entityValue),
    ];
    if (asset.orgId) conditions.push(eq(attackSurfaceAssets.orgId, asset.orgId));
    const [existing] = await db.select().from(attackSurfaceAssets).where(and(...conditions));
    if (existing) {
      const [updated] = await db.update(attackSurfaceAssets).set({
        ...asset,
        updatedAt: new Date(),
      }).where(eq(attackSurfaceAssets.id, existing.id)).returning();
      return updated;
    }
    const [created] = await db.insert(attackSurfaceAssets).values(asset).returning();
    return created;
  }

  async clearAttackSurfaceAssets(orgId: string): Promise<void> {
    await db.delete(attackSurfaceAssets).where(eq(attackSurfaceAssets.orgId, orgId));
  }

  async getRiskForecasts(orgId?: string): Promise<RiskForecast[]> {
    if (orgId) {
      return db.select().from(riskForecasts).where(eq(riskForecasts.orgId, orgId)).orderBy(desc(riskForecasts.probability));
    }
    return db.select().from(riskForecasts).orderBy(desc(riskForecasts.probability));
  }

  async createRiskForecast(forecast: InsertRiskForecast): Promise<RiskForecast> {
    const [created] = await db.insert(riskForecasts).values(forecast).returning();
    return created;
  }

  async clearRiskForecasts(orgId: string): Promise<void> {
    await db.delete(riskForecasts).where(eq(riskForecasts.orgId, orgId));
  }

  async getHardeningRecommendations(orgId?: string): Promise<HardeningRecommendation[]> {
    if (orgId) {
      return db.select().from(hardeningRecommendations).where(eq(hardeningRecommendations.orgId, orgId)).orderBy(desc(hardeningRecommendations.createdAt));
    }
    return db.select().from(hardeningRecommendations).orderBy(desc(hardeningRecommendations.createdAt));
  }

  async createHardeningRecommendation(rec: InsertHardeningRecommendation): Promise<HardeningRecommendation> {
    const [created] = await db.insert(hardeningRecommendations).values(rec).returning();
    return created;
  }

  async updateHardeningRecommendation(id: string, updates: Partial<InsertHardeningRecommendation>): Promise<HardeningRecommendation | undefined> {
    const [updated] = await db.update(hardeningRecommendations).set({ ...updates, updatedAt: new Date() }).where(eq(hardeningRecommendations.id, id)).returning();
    return updated;
  }

  async clearHardeningRecommendations(orgId: string): Promise<void> {
    await db.delete(hardeningRecommendations).where(eq(hardeningRecommendations.orgId, orgId));
  }
}

export const storage = new DatabaseStorage();
