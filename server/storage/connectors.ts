import {
  type Connector,
  type ConnectorHealthCheck,
  type ConnectorJobRun,
  type ConnectorSecretRotation,
  type InsertConnector,
  type InsertConnectorHealthCheck,
  type InsertConnectorJobRun,
  type InsertConnectorSecretRotation,
  connectorHealthChecks,
  connectorJobRuns,
  connectorSecretRotations,
  connectors,
  organizationMemberships,
  users,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, ilike, inArray, lte, or, sql } from "drizzle-orm";

export async function getConnectors(orgId?: string): Promise<Connector[]> {
  if (orgId) {
    return db.select().from(connectors).where(eq(connectors.orgId, orgId)).orderBy(desc(connectors.createdAt));
  }
  return db.select().from(connectors).orderBy(desc(connectors.createdAt));
}

export async function getConnectorsPaginated(params: {
  orgId?: string;
  offset: number;
  limit: number;
}): Promise<{ items: Connector[]; total: number }> {
  const { orgId, offset, limit } = params;
  const whereCondition = orgId ? eq(connectors.orgId, orgId) : undefined;

  const totalQuery = db.select({ total: count() }).from(connectors);
  const itemsQuery = db.select().from(connectors).orderBy(desc(connectors.createdAt)).limit(limit).offset(offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getConnectorsPaginatedWithSort(params: {
  orgId?: string;
  offset: number;
  limit: number;
  search?: string;
  type?: string;
  status?: string;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
}): Promise<{ items: Connector[]; total: number }> {
  const conditions: any[] = [];
  if (params.orgId) conditions.push(eq(connectors.orgId, params.orgId));
  if (params.type) conditions.push(eq(connectors.type, params.type));
  if (params.status) conditions.push(eq(connectors.status, params.status as any));
  if (params.search) {
    const pattern = `%${params.search}%`;
    conditions.push(or(ilike(connectors.name, pattern), ilike(connectors.type, pattern)));
  }
  const whereCondition = conditions.length > 0 ? and(...conditions) : undefined;

  const CONNECTOR_SORT_COLUMNS: Record<string, any> = {
    createdAt: connectors.createdAt,
    name: connectors.name,
    type: connectors.type,
    status: connectors.status,
    lastSyncAt: connectors.lastSyncAt,
  };
  const sortColumn = CONNECTOR_SORT_COLUMNS[params.sortBy || "createdAt"] || connectors.createdAt;
  const orderFn = params.sortOrder === "asc" ? asc : desc;

  const totalQuery = db.select({ total: count() }).from(connectors);
  const itemsQuery = db
    .select()
    .from(connectors)
    .orderBy(orderFn(sortColumn))
    .limit(params.limit)
    .offset(params.offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);
  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getConnector(id: string): Promise<Connector | undefined> {
  const [result] = await db.select().from(connectors).where(eq(connectors.id, id));
  return result;
}

export async function createConnector(connector: InsertConnector): Promise<Connector> {
  const [result] = await db.insert(connectors).values(connector).returning();
  return result;
}

export async function updateConnector(id: string, data: Partial<Connector>): Promise<Connector | undefined> {
  const [result] = await db
    .update(connectors)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(connectors.id, id))
    .returning();
  return result;
}

export async function deleteConnector(id: string): Promise<boolean> {
  const result = await db.delete(connectors).where(eq(connectors.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function updateConnectorSyncStatus(
  id: string,
  data: {
    lastSyncAt: Date;
    lastSyncStatus: string;
    lastSyncAlerts: number;
    lastSyncError?: string;
    totalAlertsSynced?: number;
  },
): Promise<void> {
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

export async function createConnectorJobRun(run: InsertConnectorJobRun): Promise<ConnectorJobRun> {
  const [created] = await db.insert(connectorJobRuns).values(run).returning();
  return created;
}

export async function updateConnectorJobRun(id: string, updates: Partial<ConnectorJobRun>): Promise<ConnectorJobRun> {
  const [updated] = await db.update(connectorJobRuns).set(updates).where(eq(connectorJobRuns.id, id)).returning();
  return updated;
}

export async function getConnectorJobRuns(connectorId: string, limit?: number): Promise<ConnectorJobRun[]> {
  return db
    .select()
    .from(connectorJobRuns)
    .where(eq(connectorJobRuns.connectorId, connectorId))
    .orderBy(desc(connectorJobRuns.startedAt))
    .limit(limit || 50);
}

export async function getDeadLetterJobRuns(orgId?: string): Promise<ConnectorJobRun[]> {
  const conditions = [eq(connectorJobRuns.isDeadLetter, true)];
  if (orgId) conditions.push(eq(connectorJobRuns.orgId, orgId));
  return db
    .select()
    .from(connectorJobRuns)
    .where(and(...conditions))
    .orderBy(desc(connectorJobRuns.startedAt));
}

export async function getDeadLetterJobRunsPaginated(params: {
  orgId?: string;
  offset: number;
  limit: number;
}): Promise<{ items: ConnectorJobRun[]; total: number }> {
  const conditions: any[] = [eq(connectorJobRuns.isDeadLetter, true)];
  if (params.orgId) conditions.push(eq(connectorJobRuns.orgId, params.orgId));
  const whereCondition = and(...conditions);

  const [totalRow] = await db.select({ total: count() }).from(connectorJobRuns).where(whereCondition);
  const items = await db
    .select()
    .from(connectorJobRuns)
    .where(whereCondition)
    .orderBy(desc(connectorJobRuns.startedAt))
    .limit(params.limit)
    .offset(params.offset);

  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getConnectorJobRunById(id: string): Promise<ConnectorJobRun | undefined> {
  const [run] = await db.select().from(connectorJobRuns).where(eq(connectorJobRuns.id, id)).limit(1);
  return run;
}

export async function getOrgAdminEmails(orgId: string): Promise<string[]> {
  const rows = await db
    .select({ email: users.email })
    .from(organizationMemberships)
    .innerJoin(users, eq(organizationMemberships.userId, users.id))
    .where(
      and(
        eq(organizationMemberships.orgId, orgId),
        inArray(organizationMemberships.role, ["admin", "org_admin", "owner"]),
        eq(organizationMemberships.status, "active"),
      ),
    );
  return rows.map((r) => r.email).filter(Boolean) as string[];
}

export async function getConnectorMetrics(connectorId: string): Promise<{
  avgLatencyMs: number;
  errorRate: number;
  throttleCount: number;
  totalRuns: number;
  successRate: number;
}> {
  const result = await db.execute(sql`
    SELECT
      COUNT(*) as total_runs,
      COALESCE(AVG(latency_ms), 0) as avg_latency,
      CASE WHEN COUNT(*) > 0 THEN SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)::float / COUNT(*) ELSE 0 END as error_rate,
      SUM(CASE WHEN throttled = true THEN 1 ELSE 0 END) as throttle_count,
      CASE WHEN COUNT(*) > 0 THEN SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END)::float / COUNT(*) ELSE 0 END as success_rate
    FROM (
      SELECT status, latency_ms, throttled
      FROM connector_job_runs
      WHERE connector_id = ${connectorId}
      ORDER BY started_at DESC
      LIMIT 100
    ) sub
  `);
  const row = (result as any).rows?.[0] || (result as any)[0] || {};
  return {
    totalRuns: Number(row.total_runs) || 0,
    avgLatencyMs: Number(row.avg_latency) || 0,
    errorRate: Number(row.error_rate) || 0,
    throttleCount: Number(row.throttle_count) || 0,
    successRate: Number(row.success_rate) || 0,
  };
}

export async function createConnectorHealthCheck(check: InsertConnectorHealthCheck): Promise<ConnectorHealthCheck> {
  const [created] = await db.insert(connectorHealthChecks).values(check).returning();
  return created;
}

export async function getConnectorHealthChecks(connectorId: string, limit?: number): Promise<ConnectorHealthCheck[]> {
  return db
    .select()
    .from(connectorHealthChecks)
    .where(eq(connectorHealthChecks.connectorId, connectorId))
    .orderBy(desc(connectorHealthChecks.checkedAt))
    .limit(limit || 50);
}

export async function getLatestHealthCheck(connectorId: string): Promise<ConnectorHealthCheck | undefined> {
  const [check] = await db
    .select()
    .from(connectorHealthChecks)
    .where(eq(connectorHealthChecks.connectorId, connectorId))
    .orderBy(desc(connectorHealthChecks.checkedAt))
    .limit(1);
  return check;
}

export async function getConnectorSecretRotations(connectorId?: string, orgId?: string): Promise<ConnectorSecretRotation[]> {
  const conditions = [];
  if (connectorId) conditions.push(eq(connectorSecretRotations.connectorId, connectorId));
  if (orgId) conditions.push(eq(connectorSecretRotations.orgId, orgId));
  return db
    .select()
    .from(connectorSecretRotations)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(connectorSecretRotations.createdAt));
}

export async function createConnectorSecretRotation(rotation: InsertConnectorSecretRotation): Promise<ConnectorSecretRotation> {
  const [created] = await db.insert(connectorSecretRotations).values(rotation).returning();
  return created;
}

export async function updateConnectorSecretRotation(
  id: string,
  data: Partial<ConnectorSecretRotation>,
): Promise<ConnectorSecretRotation | undefined> {
  const [updated] = await db
    .update(connectorSecretRotations)
    .set(data)
    .where(eq(connectorSecretRotations.id, id))
    .returning();
  return updated;
}

export async function getExpiringSecretRotations(daysAhead: number): Promise<ConnectorSecretRotation[]> {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() + daysAhead);
  return db
    .select()
    .from(connectorSecretRotations)
    .where(and(eq(connectorSecretRotations.status, "current"), lte(connectorSecretRotations.nextRotationDue, cutoff)))
    .orderBy(asc(connectorSecretRotations.nextRotationDue));
}
