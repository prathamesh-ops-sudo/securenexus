import {
  type AuditLog,
  auditLogs,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, isNull } from "drizzle-orm";
import { createHash } from "crypto";
import { currentContext } from "../logger";

export async function createAuditLog(log: Partial<AuditLog>): Promise<AuditLog> {
  const ctx = currentContext();
  const enrichedLog = {
    ...log,
    userAgent: log.userAgent ?? ctx.userAgent ?? null,
    requestId: log.requestId ?? ctx.requestId ?? null,
    impersonatedBy: log.impersonatedBy ?? ctx.impersonatedBy ?? null,
  };
  const orgId = enrichedLog.orgId ?? null;
  const lastSeq = await getLatestAuditLogSequence(orgId);
  const sequenceNum = lastSeq ? lastSeq.sequenceNum + 1 : 1;
  const prevHash = lastSeq ? lastSeq.entryHash : "genesis";
  const entryHash = createHash("sha256")
    .update(
      JSON.stringify({
        prevHash,
        action: enrichedLog.action,
        userId: enrichedLog.userId,
        resourceType: enrichedLog.resourceType,
        resourceId: enrichedLog.resourceId,
        details: enrichedLog.details,
        sequenceNum,
      }),
    )
    .digest("hex");
  const [created] = await db
    .insert(auditLogs)
    .values({
      ...enrichedLog,
      sequenceNum,
      prevHash,
      entryHash,
    } as any)
    .returning();
  return created;
}

export async function getAuditLogs(orgId?: string): Promise<AuditLog[]> {
  if (orgId) {
    return db.select().from(auditLogs).where(eq(auditLogs.orgId, orgId)).orderBy(desc(auditLogs.createdAt));
  }
  return db.select().from(auditLogs).orderBy(desc(auditLogs.createdAt));
}

export async function getAuditLogsByResource(resourceType: string, resourceId: string, orgId?: string): Promise<AuditLog[]> {
  const conditions = [eq(auditLogs.resourceType, resourceType), eq(auditLogs.resourceId, resourceId)];
  if (orgId) {
    conditions.push(eq(auditLogs.orgId, orgId));
  }
  return db
    .select()
    .from(auditLogs)
    .where(and(...conditions))
    .orderBy(desc(auditLogs.createdAt));
}

export async function getAuditLogCount(orgId?: string): Promise<number> {
  const condition = orgId ? eq(auditLogs.orgId, orgId) : undefined;
  const [result] = await db.select({ count: count() }).from(auditLogs).where(condition);
  return result?.count ?? 0;
}

export async function getOldestAuditLog(orgId?: string): Promise<AuditLog | undefined> {
  const condition = orgId ? eq(auditLogs.orgId, orgId) : undefined;
  const [oldest] = await db.select().from(auditLogs).where(condition).orderBy(asc(auditLogs.createdAt)).limit(1);
  return oldest;
}

export async function getLatestAuditLogSequence(orgId: string | null): Promise<{ sequenceNum: number; entryHash: string } | null> {
  const condition = orgId ? eq(auditLogs.orgId, orgId) : isNull(auditLogs.orgId);
  const [result] = await db
    .select({
      sequenceNum: auditLogs.sequenceNum,
      entryHash: auditLogs.entryHash,
    })
    .from(auditLogs)
    .where(condition)
    .orderBy(desc(auditLogs.sequenceNum))
    .limit(1);
  if (!result || result.sequenceNum === null || result.entryHash === null) return null;
  return { sequenceNum: result.sequenceNum, entryHash: result.entryHash };
}

export async function getAuditLogsPaginated(params: {
  orgId?: string;
  offset: number;
  limit: number;
  action?: string;
  userId?: string;
  resourceType?: string;
  sortOrder?: "asc" | "desc";
}): Promise<{ items: AuditLog[]; total: number }> {
  const conditions: any[] = [];
  if (params.orgId) conditions.push(eq(auditLogs.orgId, params.orgId));
  if (params.action) conditions.push(eq(auditLogs.action, params.action));
  if (params.userId) conditions.push(eq(auditLogs.userId, params.userId));
  if (params.resourceType) conditions.push(eq(auditLogs.resourceType, params.resourceType));
  const whereCondition = conditions.length > 0 ? and(...conditions) : undefined;

  const orderFn = params.sortOrder === "asc" ? asc : desc;

  const totalQuery = db.select({ total: count() }).from(auditLogs);
  const itemsQuery = db
    .select()
    .from(auditLogs)
    .orderBy(orderFn(auditLogs.createdAt))
    .limit(params.limit)
    .offset(params.offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);
  return { items, total: Number(totalRow?.total ?? 0) };
}
