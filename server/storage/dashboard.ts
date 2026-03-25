import {
  type DashboardMetricsCache,
  type InsertDashboardMetricsCache,
  alerts,
  connectors,
  dashboardMetricsCache,
  incidents,
  ingestionLogs,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq, sql } from "drizzle-orm";

export async function getDashboardStats(orgId?: string): Promise<{
  totalAlerts: number;
  openIncidents: number;
  criticalAlerts: number;
  resolvedIncidents: number;
  newAlertsToday: number;
  escalatedIncidents: number;
  alertsDeduplicatedToday: number;
  alertsSuppressedToday: number;
}> {
  const conditions = orgId ? [eq(alerts.orgId, orgId)] : [];
  const incidentConditions = orgId ? [eq(incidents.orgId, orgId)] : [];

  const [totalAlertsResult] = await db
    .select({ count: count() })
    .from(alerts)
    .where(conditions.length ? conditions[0] : undefined);
  const [criticalResult] = await db
    .select({ count: count() })
    .from(alerts)
    .where(conditions.length ? and(conditions[0], eq(alerts.severity, "critical")) : eq(alerts.severity, "critical"));
  const [openResult] = await db
    .select({ count: count() })
    .from(incidents)
    .where(
      incidentConditions.length
        ? and(incidentConditions[0], eq(incidents.status, "open"))
        : eq(incidents.status, "open"),
    );
  const [resolvedResult] = await db
    .select({ count: count() })
    .from(incidents)
    .where(
      incidentConditions.length
        ? and(incidentConditions[0], eq(incidents.status, "resolved"))
        : eq(incidents.status, "resolved"),
    );

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const [newTodayResult] = await db
    .select({ count: count() })
    .from(alerts)
    .where(
      conditions.length
        ? and(conditions[0], sql`${alerts.createdAt} >= ${today}`)
        : sql`${alerts.createdAt} >= ${today}`,
    );
  const [escalatedResult] = await db
    .select({ count: count() })
    .from(incidents)
    .where(
      incidentConditions.length
        ? and(incidentConditions[0], eq(incidents.escalated, true))
        : eq(incidents.escalated, true),
    );

  const [dedupedResult] = await db
    .select({ count: count() })
    .from(alerts)
    .where(
      conditions.length
        ? and(conditions[0], eq(alerts.status, "deduped"), sql`${alerts.createdAt} >= ${today}`)
        : and(eq(alerts.status, "deduped"), sql`${alerts.createdAt} >= ${today}`),
    );
  const [suppressedResult] = await db
    .select({ count: count() })
    .from(alerts)
    .where(
      conditions.length
        ? and(conditions[0], eq(alerts.suppressed, true), sql`${alerts.createdAt} >= ${today}`)
        : and(eq(alerts.suppressed, true), sql`${alerts.createdAt} >= ${today}`),
    );

  return {
    totalAlerts: totalAlertsResult?.count ?? 0,
    openIncidents: openResult?.count ?? 0,
    criticalAlerts: criticalResult?.count ?? 0,
    resolvedIncidents: resolvedResult?.count ?? 0,
    newAlertsToday: newTodayResult?.count ?? 0,
    escalatedIncidents: escalatedResult?.count ?? 0,
    alertsDeduplicatedToday: dedupedResult?.count ?? 0,
    alertsSuppressedToday: suppressedResult?.count ?? 0,
  };
}

export async function getDashboardAnalytics(orgId?: string): Promise<{
  severityDistribution: { name: string; value: number }[];
  sourceDistribution: { name: string; value: number }[];
  categoryDistribution: { name: string; value: number }[];
  statusDistribution: { name: string; value: number }[];
  alertTrend: { date: string; count: number }[];
  mttrHours: number | null;
  topMitreTactics: { name: string; value: number }[];
  connectorHealth: {
    name: string;
    type: string;
    status: string;
    lastSyncAt: string | null;
    lastSyncAlerts: number;
    lastSyncError: string | null;
  }[];
  ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
}> {
  const alertCond = orgId ? eq(alerts.orgId, orgId) : undefined;
  const incidentCond = orgId ? eq(incidents.orgId, orgId) : undefined;
  const connectorCond = orgId ? eq(connectors.orgId, orgId) : undefined;
  const ingestionCond = orgId ? eq(ingestionLogs.orgId, orgId) : undefined;

  const severityDistribution = await db
    .select({ name: alerts.severity, value: sql<number>`COUNT(*)::int` })
    .from(alerts)
    .where(alertCond)
    .groupBy(alerts.severity);

  const sourceDistribution = await db
    .select({ name: alerts.source, value: sql<number>`COUNT(*)::int` })
    .from(alerts)
    .where(alertCond)
    .groupBy(alerts.source)
    .orderBy(sql`COUNT(*) DESC`)
    .limit(10);

  const categoryDistribution = await db
    .select({ name: alerts.category, value: sql<number>`COUNT(*)::int` })
    .from(alerts)
    .where(alertCond)
    .groupBy(alerts.category)
    .orderBy(sql`COUNT(*) DESC`)
    .limit(10);

  const statusDistribution = await db
    .select({ name: alerts.status, value: sql<number>`COUNT(*)::int` })
    .from(alerts)
    .where(alertCond)
    .groupBy(alerts.status);

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
    .from(alerts)
    .where(trendCond)
    .groupBy(sql`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`)
    .orderBy(sql`TO_CHAR(${alerts.createdAt}, 'YYYY-MM-DD')`);

  const mttrResult = await db
    .select({
      avgHours: sql<
        number | null
      >`AVG(EXTRACT(EPOCH FROM (${incidents.resolvedAt} - ${incidents.createdAt})) / 3600)`,
    })
    .from(incidents)
    .where(
      incidentCond
        ? and(incidentCond, sql`${incidents.resolvedAt} IS NOT NULL`)
        : sql`${incidents.resolvedAt} IS NOT NULL`,
    );
  const mttrHours = mttrResult[0]?.avgHours ? Math.round(mttrResult[0].avgHours * 10) / 10 : null;

  const tacticRows = await db
    .select({ tactic: alerts.mitreTactic, value: sql<number>`COUNT(*)::int` })
    .from(alerts)
    .where(
      alertCond
        ? and(alertCond, sql`${alerts.mitreTactic} IS NOT NULL AND ${alerts.mitreTactic} != ''`)
        : sql`${alerts.mitreTactic} IS NOT NULL AND ${alerts.mitreTactic} != ''`,
    )
    .groupBy(alerts.mitreTactic)
    .orderBy(sql`COUNT(*) DESC`)
    .limit(8);
  const topMitreTactics = tacticRows.map((r) => ({ name: r.tactic || "Unknown", value: r.value }));

  const connectorRows = await db
    .select({
      name: connectors.name,
      type: connectors.type,
      status: connectors.status,
      lastSyncAt: connectors.lastSyncAt,
      lastSyncAlerts: connectors.lastSyncAlerts,
      lastSyncError: connectors.lastSyncError,
    })
    .from(connectors)
    .where(connectorCond)
    .orderBy(desc(connectors.updatedAt));
  const connectorHealth = connectorRows.map((r) => ({
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
    .from(ingestionLogs)
    .where(ingestionTrendCond)
    .groupBy(sql`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`)
    .orderBy(sql`TO_CHAR(${ingestionLogs.receivedAt}, 'YYYY-MM-DD')`);

  return {
    severityDistribution: severityDistribution.map((r) => ({ name: r.name || "unknown", value: r.value })),
    sourceDistribution: sourceDistribution.map((r) => ({ name: r.name || "unknown", value: r.value })),
    categoryDistribution: categoryDistribution.map((r) => ({ name: r.name || "unknown", value: r.value })),
    statusDistribution: statusDistribution.map((r) => ({ name: r.name || "unknown", value: r.value })),
    alertTrend,
    mttrHours,
    topMitreTactics,
    connectorHealth,
    ingestionRate,
  };
}

export async function getCachedMetrics(orgId: string, metricType: string): Promise<DashboardMetricsCache | undefined> {
  const [cached] = await db
    .select()
    .from(dashboardMetricsCache)
    .where(
      and(
        eq(dashboardMetricsCache.orgId, orgId),
        eq(dashboardMetricsCache.metricType, metricType),
        sql`${dashboardMetricsCache.expiresAt} > NOW()`,
      ),
    );
  return cached;
}

export async function upsertCachedMetrics(data: InsertDashboardMetricsCache): Promise<DashboardMetricsCache> {
  const [result] = await db
    .insert(dashboardMetricsCache)
    .values(data)
    .onConflictDoUpdate({
      target: [dashboardMetricsCache.orgId, dashboardMetricsCache.metricType],
      set: {
        payload: data.payload,
        expiresAt: data.expiresAt,
        generatedAt: sql`NOW()`,
      },
    })
    .returning();
  return result;
}

export async function clearExpiredCache(): Promise<number> {
  const result = await db
    .delete(dashboardMetricsCache)
    .where(sql`${dashboardMetricsCache.expiresAt} <= NOW()`)
    .returning();
  return result.length;
}
