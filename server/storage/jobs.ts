import {
  type DrDrillResult,
  type DrRunbook,
  type InsertDrDrillResult,
  type InsertDrRunbook,
  type InsertJobQueue as InsertJob,
  type InsertOutboxEvent,
  type InsertSliMetric,
  type InsertSloTarget,
  type InsertTicketSyncJob,
  type JobQueue as Job,
  type OutboxEvent,
  type SliMetric,
  type SloTarget,
  type TicketSyncJob,
  drDrillResults,
  drRunbooks,
  jobQueue,
  outboxEvents,
  sliMetrics,
  sloTargets,
  ticketSyncJobs,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, gte, isNull, lte, or, sql } from "drizzle-orm";

export async function getJobs(orgId?: string, status?: string, type?: string, limit?: number): Promise<Job[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(jobQueue.orgId, orgId));
  if (status) conditions.push(eq(jobQueue.status, status));
  if (type) conditions.push(eq(jobQueue.type, type));
  const query = db.select().from(jobQueue);
  if (conditions.length > 0) {
    return query
      .where(and(...conditions))
      .orderBy(desc(jobQueue.createdAt))
      .limit(limit || 100);
  }
  return query.orderBy(desc(jobQueue.createdAt)).limit(limit || 100);
}

export async function getJob(id: string): Promise<Job | undefined> {
  const [job] = await db.select().from(jobQueue).where(eq(jobQueue.id, id));
  return job;
}

export async function createJob(job: InsertJob): Promise<Job> {
  const [created] = await db.insert(jobQueue).values(job).returning();
  return created;
}

export async function claimNextJob(types?: string[]): Promise<Job | undefined> {
  const typesFilter =
    types && types.length > 0
      ? sql`AND type IN (${sql.join(
          types.map((t) => sql`${t}`),
          sql`, `,
        )})`
      : sql``;
  const result = await db.execute(sql`
    UPDATE job_queue
    SET status = 'running', started_at = NOW(), attempts = attempts + 1
    WHERE id = (
      SELECT id FROM job_queue
      WHERE status = 'pending' AND run_at <= NOW() ${typesFilter}
      ORDER BY priority DESC, run_at ASC
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    RETURNING *
  `);
  const rows = result.rows as any[];
  if (!rows || rows.length === 0) return undefined;
  const row = rows[0];
  return {
    id: row.id,
    orgId: row.org_id,
    type: row.type,
    status: row.status,
    payload: row.payload,
    result: row.result,
    priority: row.priority,
    runAt: row.run_at,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    lastError: row.last_error,
    createdAt: row.created_at,
  } as Job;
}

export async function updateJob(id: string, data: Partial<Job>): Promise<Job | undefined> {
  const [updated] = await db.update(jobQueue).set(data).where(eq(jobQueue.id, id)).returning();
  return updated;
}

export async function cancelJob(id: string): Promise<boolean> {
  const [updated] = await db
    .update(jobQueue)
    .set({ status: "cancelled" } as any)
    .where(eq(jobQueue.id, id))
    .returning();
  return !!updated;
}

export async function getJobStats(): Promise<{ pending: number; running: number; completed: number; failed: number }> {
  const result = await db
    .select({
      status: jobQueue.status,
      count: count(),
    })
    .from(jobQueue)
    .groupBy(jobQueue.status);
  const stats = { pending: 0, running: 0, completed: 0, failed: 0 };
  for (const row of result) {
    if (row.status in stats) {
      (stats as any)[row.status] = row.count;
    }
  }
  return stats;
}

export async function cleanupCompletedJobs(olderThanDays: number): Promise<number> {
  const result = await db
    .delete(jobQueue)
    .where(
      and(
        or(eq(jobQueue.status, "completed"), eq(jobQueue.status, "failed")),
        sql`${jobQueue.completedAt} < NOW() - INTERVAL '${sql.raw(String(olderThanDays))} days'`,
      ),
    )
    .returning();
  return result.length;
}

export async function createOutboxEvent(event: InsertOutboxEvent): Promise<OutboxEvent> {
  const [created] = await db.insert(outboxEvents).values(event).returning();
  return created;
}

export async function getPendingOutboxEvents(batchSize: number): Promise<OutboxEvent[]> {
  return db
    .select()
    .from(outboxEvents)
    .where(
      and(
        eq(outboxEvents.status, "pending"),
        or(isNull(outboxEvents.nextRetryAt), lte(outboxEvents.nextRetryAt, new Date())),
      ),
    )
    .orderBy(asc(outboxEvents.createdAt))
    .limit(batchSize);
}

export async function updateOutboxEvent(id: string, data: Partial<OutboxEvent>): Promise<OutboxEvent | undefined> {
  const [updated] = await db.update(outboxEvents).set(data).where(eq(outboxEvents.id, id)).returning();
  return updated;
}

export async function getOutboxEvent(id: string): Promise<OutboxEvent | undefined> {
  const [event] = await db.select().from(outboxEvents).where(eq(outboxEvents.id, id)).limit(1);
  return event;
}

export async function getOutboxEvents(
  orgId?: string,
  status?: string,
  limitVal?: number,
  offsetVal?: number,
): Promise<{ items: OutboxEvent[]; total: number }> {
  const conditions: any[] = [];
  if (orgId) conditions.push(eq(outboxEvents.orgId, orgId));
  if (status) conditions.push(eq(outboxEvents.status, status));
  const whereCondition = conditions.length > 0 ? and(...conditions) : undefined;

  const totalQuery = db.select({ total: count() }).from(outboxEvents);
  const itemsQuery = db
    .select()
    .from(outboxEvents)
    .orderBy(desc(outboxEvents.createdAt))
    .limit(limitVal || 50)
    .offset(offsetVal || 0);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);
  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function replayOutboxEvent(id: string): Promise<OutboxEvent | undefined> {
  const [updated] = await db
    .update(outboxEvents)
    .set({
      status: "pending",
      attempts: 0,
      lastError: null,
      nextRetryAt: null,
    })
    .where(and(eq(outboxEvents.id, id), or(eq(outboxEvents.status, "failed"), eq(outboxEvents.status, "dispatched"))))
    .returning();
  return updated;
}

export async function cleanupDispatchedOutboxEvents(olderThanDays: number): Promise<number> {
  const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
  const result = await db
    .delete(outboxEvents)
    .where(and(eq(outboxEvents.status, "dispatched"), lte(outboxEvents.createdAt, cutoff)))
    .returning();
  return result.length;
}

// ============================
// Enhanced Pagination with Filter/Sort
// ============================

export async function getSliMetrics(
  service: string,
  metric: string,
  startTime: Date,
  endTime: Date,
  labels?: Record<string, string>,
): Promise<SliMetric[]> {
  const conditions: any[] = [
    eq(sliMetrics.service, service),
    eq(sliMetrics.metric, metric),
    gte(sliMetrics.recordedAt, startTime),
    lte(sliMetrics.recordedAt, endTime),
  ];

  if (labels?.endpoint) {
    conditions.push(sql`${sliMetrics.labels} ->> 'endpoint' = ${labels.endpoint}`);
  }

  return db
    .select()
    .from(sliMetrics)
    .where(and(...conditions))
    .orderBy(asc(sliMetrics.recordedAt));
}

export async function createSliMetric(data: InsertSliMetric): Promise<SliMetric> {
  const [created] = await db.insert(sliMetrics).values(data).returning();
  return created;
}

export async function createSliMetricsBatch(data: InsertSliMetric[]): Promise<SliMetric[]> {
  if (data.length === 0) return [];
  return db.insert(sliMetrics).values(data).returning();
}

export async function cleanupOldSliMetrics(olderThanDays: number): Promise<number> {
  const result = await db
    .delete(sliMetrics)
    .where(sql`${sliMetrics.recordedAt} < NOW() - INTERVAL '${sql.raw(String(olderThanDays))} days'`)
    .returning();
  return result.length;
}

export async function getSloTargets(orgId?: string): Promise<SloTarget[]> {
  return db
    .select()
    .from(sloTargets)
    .where(orgId ? eq(sloTargets.orgId, orgId) : undefined)
    .orderBy(asc(sloTargets.service));
}

export async function getSloTarget(id: string, orgId?: string): Promise<SloTarget | undefined> {
  const [target] = await db
    .select()
    .from(sloTargets)
    .where(orgId ? and(eq(sloTargets.id, id), eq(sloTargets.orgId, orgId)) : eq(sloTargets.id, id));
  return target;
}

export async function createSloTarget(target: InsertSloTarget): Promise<SloTarget> {
  const [created] = await db.insert(sloTargets).values(target).returning();
  return created;
}

export async function updateSloTarget(
  id: string,
  data: Partial<SloTarget>,
  orgId?: string,
): Promise<SloTarget | undefined> {
  const [updated] = await db
    .update(sloTargets)
    .set({ ...data, updatedAt: new Date() })
    .where(orgId ? and(eq(sloTargets.id, id), eq(sloTargets.orgId, orgId)) : eq(sloTargets.id, id))
    .returning();
  return updated;
}

export async function deleteSloTarget(id: string, orgId?: string): Promise<boolean> {
  const result = await db
    .delete(sloTargets)
    .where(orgId ? and(eq(sloTargets.id, id), eq(sloTargets.orgId, orgId)) : eq(sloTargets.id, id))
    .returning();
  return result.length > 0;
}

export async function getDrRunbooks(orgId: string): Promise<DrRunbook[]> {
  return db.select().from(drRunbooks).where(eq(drRunbooks.orgId, orgId)).orderBy(desc(drRunbooks.createdAt));
}

export async function getDrRunbook(id: string): Promise<DrRunbook | undefined> {
  const [runbook] = await db.select().from(drRunbooks).where(eq(drRunbooks.id, id));
  return runbook;
}

export async function getDrRunbookForOrg(id: string, orgId: string): Promise<DrRunbook | undefined> {
  const [runbook] = await db
    .select()
    .from(drRunbooks)
    .where(and(eq(drRunbooks.id, id), eq(drRunbooks.orgId, orgId)));
  return runbook;
}

export async function createDrRunbook(runbook: InsertDrRunbook): Promise<DrRunbook> {
  const [created] = await db.insert(drRunbooks).values(runbook).returning();
  return created;
}

export async function updateDrRunbook(id: string, data: Partial<DrRunbook>): Promise<DrRunbook | undefined> {
  const [updated] = await db
    .update(drRunbooks)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(drRunbooks.id, id))
    .returning();
  return updated;
}

export async function deleteDrRunbook(id: string): Promise<boolean> {
  const result = await db.delete(drRunbooks).where(eq(drRunbooks.id, id)).returning();
  return result.length > 0;
}

export async function getDrDrillResults(
  orgId?: string,
  runbookId?: string,
  limit: number = 50,
): Promise<DrDrillResult[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(drDrillResults.orgId, orgId));
  if (runbookId) conditions.push(eq(drDrillResults.runbookId, runbookId));
  return db
    .select()
    .from(drDrillResults)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(drDrillResults.createdAt))
    .limit(limit);
}

export async function getDrDrillResult(id: string): Promise<DrDrillResult | undefined> {
  const [result] = await db.select().from(drDrillResults).where(eq(drDrillResults.id, id));
  return result;
}

export async function createDrDrillResult(result: InsertDrDrillResult): Promise<DrDrillResult> {
  const [created] = await db.insert(drDrillResults).values(result).returning();
  return created;
}

export async function updateDrDrillResult(
  id: string,
  data: Partial<DrDrillResult>,
): Promise<DrDrillResult | undefined> {
  const [updated] = await db.update(drDrillResults).set(data).where(eq(drDrillResults.id, id)).returning();
  return updated;
}

export async function getTicketSyncJobs(orgId?: string, integrationId?: string): Promise<TicketSyncJob[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(ticketSyncJobs.orgId, orgId));
  if (integrationId) conditions.push(eq(ticketSyncJobs.integrationId, integrationId));
  return db
    .select()
    .from(ticketSyncJobs)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(ticketSyncJobs.createdAt));
}

export async function getTicketSyncJob(id: string): Promise<TicketSyncJob | undefined> {
  const [job] = await db.select().from(ticketSyncJobs).where(eq(ticketSyncJobs.id, id));
  return job;
}

export async function createTicketSyncJob(job: InsertTicketSyncJob): Promise<TicketSyncJob> {
  const [created] = await db.insert(ticketSyncJobs).values(job).returning();
  return created;
}

export async function updateTicketSyncJob(
  id: string,
  data: Partial<TicketSyncJob>,
): Promise<TicketSyncJob | undefined> {
  const [updated] = await db
    .update(ticketSyncJobs)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(ticketSyncJobs.id, id))
    .returning();
  return updated;
}

export async function deleteTicketSyncJob(id: string): Promise<boolean> {
  const result = await db.delete(ticketSyncJobs).where(eq(ticketSyncJobs.id, id)).returning();
  return result.length > 0;
}
