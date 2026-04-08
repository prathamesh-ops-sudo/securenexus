import {
  type Alert,
  type AlertArchive,
  type AlertDailyStats as AlertDailyStat,
  type AlertDedupCluster,
  type InsertAlert,
  type InsertAlertDailyStats as InsertAlertDailyStat,
  type InsertAlertDedupCluster,
  type Tag,
  alertDailyStats,
  alertDedupClusters,
  alertTags,
  alerts,
  alertsArchive,
  tags,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, gte, ilike, inArray, lte, or, sql } from "drizzle-orm";

export async function getAlerts(orgId?: string): Promise<Alert[]> {
  if (orgId) {
    return db.select().from(alerts).where(eq(alerts.orgId, orgId)).orderBy(desc(alerts.createdAt));
  }
  return db.select().from(alerts).orderBy(desc(alerts.createdAt));
}

export async function getAlert(id: string): Promise<Alert | undefined> {
  const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
  return alert;
}

export async function createAlert(alert: InsertAlert): Promise<Alert> {
  const [created] = await db.insert(alerts).values(alert).returning();
  return created;
}

export async function updateAlertStatus(id: string, status: string, incidentId?: string): Promise<Alert | undefined> {
  const updateData: any = { status };
  if (incidentId) updateData.incidentId = incidentId;
  const [updated] = await db.update(alerts).set(updateData).where(eq(alerts.id, id)).returning();
  return updated;
}

export async function updateAlert(id: string, data: Partial<Alert>): Promise<Alert | undefined> {
  const [updated] = await db.update(alerts).set(data).where(eq(alerts.id, id)).returning();
  return updated;
}

export async function searchAlerts(query: string, orgId?: string): Promise<Alert[]> {
  const searchPattern = `%${query}%`;
  const searchCondition = or(
    ilike(alerts.title, searchPattern),
    ilike(alerts.description, searchPattern),
    ilike(alerts.hostname, searchPattern),
    ilike(alerts.sourceIp, searchPattern),
  );
  if (orgId) {
    return db
      .select()
      .from(alerts)
      .where(and(eq(alerts.orgId, orgId), searchCondition))
      .orderBy(desc(alerts.createdAt));
  }
  return db.select().from(alerts).where(searchCondition).orderBy(desc(alerts.createdAt));
}

export async function getAlertsByIncident(incidentId: string): Promise<Alert[]> {
  return db.select().from(alerts).where(eq(alerts.incidentId, incidentId)).orderBy(desc(alerts.detectedAt));
}

export async function findAlertByDedup(
  orgId: string | null,
  source: string,
  sourceEventId: string,
): Promise<Alert | undefined> {
  if (!sourceEventId) return undefined;
  const conditions = [eq(alerts.source, source), eq(alerts.sourceEventId, sourceEventId)];
  if (orgId) conditions.push(eq(alerts.orgId, orgId));
  const [existing] = await db
    .select()
    .from(alerts)
    .where(and(...conditions));
  return existing;
}

export async function upsertAlert(
  alert: InsertAlert,
  dedupWindowMinutes: number = 60,
): Promise<{ alert: Alert; isNew: boolean; isDuplicate: boolean }> {
  if (alert.sourceEventId) {
    const existing = await findAlertByDedup(alert.orgId || null, alert.source, alert.sourceEventId);
    if (existing) {
      const cutoff = new Date(Date.now() - dedupWindowMinutes * 60 * 1000);
      const alertTime = existing.ingestedAt || existing.createdAt;
      if (alertTime && alertTime >= cutoff) {
        // Within dedup window: update existing record
        const [updated] = await db
          .update(alerts)
          .set({
            occurrenceCount: sql`COALESCE(${alerts.occurrenceCount}, 1) + 1`,
            lastSeenAt: new Date(),
            status: "deduped",
          })
          .where(eq(alerts.id, existing.id))
          .returning();
        return { alert: updated, isNew: false, isDuplicate: true };
      }
      // Outside dedup window: fall through to create new alert
    }
  }
  const created = await createAlert(alert);
  return { alert: created, isNew: true, isDuplicate: false };
}

export async function getAlertsPaginated(params: {
  orgId?: string;
  offset: number;
  limit: number;
  search?: string;
}): Promise<{ items: Alert[]; total: number }> {
  const { orgId, offset, limit, search } = params;
  const searchPattern = search ? `%${search}%` : undefined;
  const textCondition = searchPattern
    ? or(
        ilike(alerts.title, searchPattern),
        ilike(alerts.description, searchPattern),
        ilike(alerts.hostname, searchPattern),
        ilike(alerts.sourceIp, searchPattern),
      )
    : undefined;

  let whereCondition: any = undefined;
  if (orgId && textCondition) {
    whereCondition = and(eq(alerts.orgId, orgId), textCondition);
  } else if (orgId) {
    whereCondition = eq(alerts.orgId, orgId);
  } else if (textCondition) {
    whereCondition = textCondition;
  }

  const totalQuery = db.select({ total: count() }).from(alerts);
  const itemsQuery = db.select().from(alerts).orderBy(desc(alerts.createdAt)).limit(limit).offset(offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getAlertsPaginatedWithSort(params: {
  orgId?: string;
  offset: number;
  limit: number;
  search?: string;
  severity?: string;
  status?: string;
  source?: string;
  suppressed?: boolean;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
}): Promise<{ items: Alert[]; total: number }> {
  const conditions: any[] = [];
  if (params.orgId) conditions.push(eq(alerts.orgId, params.orgId));
  if (params.severity) conditions.push(eq(alerts.severity, params.severity));
  if (params.status) conditions.push(eq(alerts.status, params.status));
  if (params.source) conditions.push(eq(alerts.source, params.source));
  if (typeof params.suppressed === "boolean") conditions.push(eq(alerts.suppressed, params.suppressed));
  if (params.search) {
    const pattern = `%${params.search}%`;
    conditions.push(
      or(
        ilike(alerts.title, pattern),
        ilike(alerts.description, pattern),
        ilike(alerts.hostname, pattern),
        ilike(alerts.sourceIp, pattern),
      ),
    );
  }
  const whereCondition = conditions.length > 0 ? and(...conditions) : undefined;

  const ALERT_SORT_COLUMNS: Record<string, any> = {
    createdAt: alerts.createdAt,
    detectedAt: alerts.detectedAt,
    severity: alerts.severity,
    status: alerts.status,
    title: alerts.title,
    source: alerts.source,
  };
  const sortColumn = ALERT_SORT_COLUMNS[params.sortBy || "createdAt"] || alerts.createdAt;
  const orderFn = params.sortOrder === "asc" ? asc : desc;

  const totalQuery = db.select({ total: count() }).from(alerts);
  const itemsQuery = db.select().from(alerts).orderBy(orderFn(sortColumn)).limit(params.limit).offset(params.offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);
  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getAlertTags(alertId: string): Promise<Tag[]> {
  const rows = await db
    .select({ tag: tags })
    .from(alertTags)
    .innerJoin(tags, eq(alertTags.tagId, tags.id))
    .where(eq(alertTags.alertId, alertId));
  return rows.map((r) => r.tag);
}

export async function addAlertTag(alertId: string, tagId: string): Promise<void> {
  await db.insert(alertTags).values({ alertId, tagId }).onConflictDoNothing();
}

export async function removeAlertTag(alertId: string, tagId: string): Promise<void> {
  await db.delete(alertTags).where(and(eq(alertTags.alertId, alertId), eq(alertTags.tagId, tagId)));
}

export async function getAlertDedupClusters(orgId?: string): Promise<AlertDedupCluster[]> {
  if (orgId) {
    return db
      .select()
      .from(alertDedupClusters)
      .where(eq(alertDedupClusters.orgId, orgId))
      .orderBy(desc(alertDedupClusters.createdAt));
  }
  return db.select().from(alertDedupClusters).orderBy(desc(alertDedupClusters.createdAt));
}

export async function getAlertDedupCluster(id: string): Promise<AlertDedupCluster | undefined> {
  const [cluster] = await db.select().from(alertDedupClusters).where(eq(alertDedupClusters.id, id));
  return cluster;
}

export async function createAlertDedupCluster(cluster: InsertAlertDedupCluster): Promise<AlertDedupCluster> {
  const [created] = await db.insert(alertDedupClusters).values(cluster).returning();
  return created;
}

export async function updateAlertDedupCluster(
  id: string,
  data: Partial<AlertDedupCluster>,
): Promise<AlertDedupCluster | undefined> {
  const [updated] = await db.update(alertDedupClusters).set(data).where(eq(alertDedupClusters.id, id)).returning();
  return updated;
}

// SLA Policies

export async function getAlertDailyStats(orgId: string, startDate: string, endDate: string): Promise<AlertDailyStat[]> {
  return db
    .select()
    .from(alertDailyStats)
    .where(
      and(eq(alertDailyStats.orgId, orgId), gte(alertDailyStats.date, startDate), lte(alertDailyStats.date, endDate)),
    )
    .orderBy(asc(alertDailyStats.date));
}

export async function upsertAlertDailyStat(data: InsertAlertDailyStat): Promise<AlertDailyStat> {
  const [result] = await db
    .insert(alertDailyStats)
    .values(data)
    .onConflictDoUpdate({
      target: [alertDailyStats.orgId, alertDailyStats.date],
      set: {
        totalAlerts: data.totalAlerts,
        criticalCount: data.criticalCount,
        highCount: data.highCount,
        mediumCount: data.mediumCount,
        lowCount: data.lowCount,
        infoCount: data.infoCount,
        sourceCounts: data.sourceCounts,
        categoryCounts: data.categoryCounts,
      },
    })
    .returning();
  return result;
}

export async function getArchivedAlerts(orgId: string, limit?: number, offset?: number): Promise<AlertArchive[]> {
  return db
    .select()
    .from(alertsArchive)
    .where(eq(alertsArchive.orgId, orgId))
    .orderBy(desc(alertsArchive.archivedAt))
    .limit(limit || 100)
    .offset(offset || 0);
}

export async function getArchivedAlertCount(orgId: string): Promise<number> {
  const [result] = await db.select({ count: count() }).from(alertsArchive).where(eq(alertsArchive.orgId, orgId));
  return result?.count || 0;
}

export async function archiveAlerts(orgId: string, alertIds: string[], reason: string): Promise<number> {
  const alertsToArchive = await db
    .select()
    .from(alerts)
    .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds)));
  if (alertsToArchive.length === 0) return 0;
  const archiveData = alertsToArchive.map((a) => ({
    orgId: a.orgId,
    source: a.source,
    sourceEventId: a.sourceEventId,
    category: a.category,
    severity: a.severity,
    title: a.title,
    description: a.description,
    rawData: a.rawData,
    normalizedData: a.normalizedData,
    ocsfData: a.ocsfData,
    sourceIp: a.sourceIp,
    destIp: a.destIp,
    sourcePort: a.sourcePort,
    destPort: a.destPort,
    protocol: a.protocol,
    userId: a.userId,
    hostname: a.hostname,
    fileHash: a.fileHash,
    url: a.url,
    domain: a.domain,
    mitreTactic: a.mitreTactic,
    mitreTechnique: a.mitreTechnique,
    status: a.status,
    incidentId: a.incidentId,
    correlationScore: a.correlationScore,
    correlationReason: a.correlationReason,
    correlationClusterId: a.correlationClusterId,
    suppressed: a.suppressed,
    suppressedBy: a.suppressedBy,
    suppressionRuleId: a.suppressionRuleId,
    confidenceScore: a.confidenceScore,
    confidenceSource: a.confidenceSource,
    confidenceNotes: a.confidenceNotes,
    dedupClusterId: a.dedupClusterId,
    analystNotes: a.analystNotes,
    assignedTo: a.assignedTo,
    detectedAt: a.detectedAt,
    archiveReason: reason,
  }));
  await db.insert(alertsArchive).values(archiveData);
  await db.delete(alerts).where(inArray(alerts.id, alertIds));
  return alertsToArchive.length;
}

export async function restoreArchivedAlerts(ids: string[]): Promise<number> {
  const archived = await db.select().from(alertsArchive).where(inArray(alertsArchive.id, ids));
  if (archived.length === 0) return 0;
  const restoreData = archived.map((a) => ({
    orgId: a.orgId,
    source: a.source,
    sourceEventId: a.sourceEventId,
    category: a.category,
    severity: a.severity,
    title: a.title,
    description: a.description,
    rawData: a.rawData,
    normalizedData: a.normalizedData,
    ocsfData: a.ocsfData,
    sourceIp: a.sourceIp,
    destIp: a.destIp,
    sourcePort: a.sourcePort,
    destPort: a.destPort,
    protocol: a.protocol,
    userId: a.userId,
    hostname: a.hostname,
    fileHash: a.fileHash,
    url: a.url,
    domain: a.domain,
    mitreTactic: a.mitreTactic,
    mitreTechnique: a.mitreTechnique,
    status: a.status,
    incidentId: a.incidentId,
    correlationScore: a.correlationScore,
    correlationReason: a.correlationReason,
    correlationClusterId: a.correlationClusterId,
    suppressed: a.suppressed,
    suppressedBy: a.suppressedBy,
    suppressionRuleId: a.suppressionRuleId,
    confidenceScore: a.confidenceScore,
    confidenceSource: a.confidenceSource,
    confidenceNotes: a.confidenceNotes,
    dedupClusterId: a.dedupClusterId,
    analystNotes: a.analystNotes,
    assignedTo: a.assignedTo,
    detectedAt: a.detectedAt,
  }));
  await db.insert(alerts).values(restoreData as any);
  await db.delete(alertsArchive).where(inArray(alertsArchive.id, ids));
  return archived.length;
}

export async function deleteArchivedAlerts(orgId: string, beforeDate: Date): Promise<number> {
  const result = await db
    .delete(alertsArchive)
    .where(and(eq(alertsArchive.orgId, orgId), lte(alertsArchive.archivedAt, beforeDate)))
    .returning();
  return result.length;
}

export async function bulkDeleteAlerts(
  orgId: string,
  filters: {
    sourcePattern?: string;
    severity?: string;
    titlePattern?: string;
  },
): Promise<number> {
  const conditions = [eq(alerts.orgId, orgId)];

  if (filters.sourcePattern) {
    conditions.push(ilike(alerts.source, `%${filters.sourcePattern}%`));
  }
  if (filters.severity) {
    conditions.push(eq(alerts.severity, filters.severity));
  }
  if (filters.titlePattern) {
    conditions.push(ilike(alerts.title, `%${filters.titlePattern}%`));
  }

  const result = await db
    .delete(alerts)
    .where(and(...conditions))
    .returning({ id: alerts.id });
  return result.length;
}
