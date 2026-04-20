import {
  type Incident,
  type IncidentComment,
  type IncidentResponseApproval,
  type IncidentSlaPolicy,
  type InsertComment,
  type InsertIncident,
  type InsertIncidentResponseApproval,
  type InsertIncidentSlaPolicy,
  type InsertPirActionItem,
  type InsertPostIncidentReview,
  type PirActionItem,
  type Playbook,
  type PostIncidentReview,
  type Tag,
  incidentComments,
  incidentResponseApprovals,
  incidentSlaPolicies,
  incidentTags,
  incidents,
  pirActionItems,
  postIncidentReviews,
  tags,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, ilike, or } from "drizzle-orm";

export async function getIncidents(orgId?: string): Promise<Incident[]> {
  if (orgId) {
    return db.select().from(incidents).where(eq(incidents.orgId, orgId)).orderBy(desc(incidents.createdAt));
  }
  return db.select().from(incidents).orderBy(desc(incidents.createdAt));
}

export async function getIncident(id: string): Promise<Incident | undefined> {
  const [incident] = await db.select().from(incidents).where(eq(incidents.id, id));
  return incident;
}

export async function createIncident(incident: InsertIncident): Promise<Incident> {
  const [created] = await db.insert(incidents).values(incident).returning();
  return created;
}

export async function updateIncident(id: string, data: Partial<Incident>): Promise<Incident | undefined> {
  const [updated] = await db
    .update(incidents)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(incidents.id, id))
    .returning();
  return updated;
}

export async function getIncidentsPaginated(params: {
  orgId?: string;
  offset: number;
  limit: number;
  queue?: string;
}): Promise<{ items: Incident[]; total: number }> {
  const { orgId, offset, limit, queue } = params;

  const conditions: any[] = [];
  if (orgId) {
    conditions.push(eq(incidents.orgId, orgId));
  }
  if (queue) {
    conditions.push(eq(incidents.status, queue));
  }

  const whereCondition = conditions.length ? and(...conditions) : undefined;

  const totalQuery = db.select({ total: count() }).from(incidents);
  const itemsQuery = db.select().from(incidents).orderBy(desc(incidents.createdAt)).limit(limit).offset(offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getIncidentsPaginatedWithSort(params: {
  orgId?: string;
  offset: number;
  limit: number;
  search?: string;
  severity?: string;
  status?: string;
  queue?: string;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
}): Promise<{ items: Incident[]; total: number }> {
  const conditions: any[] = [];
  if (params.orgId) conditions.push(eq(incidents.orgId, params.orgId));
  if (params.severity) conditions.push(eq(incidents.severity, params.severity));
  if (params.queue) conditions.push(eq(incidents.status, params.queue));
  else if (params.status) conditions.push(eq(incidents.status, params.status));
  if (params.search) {
    const pattern = `%${params.search}%`;
    conditions.push(or(ilike(incidents.title, pattern), ilike(incidents.summary, pattern)));
  }
  const whereCondition = conditions.length > 0 ? and(...conditions) : undefined;

  const INCIDENT_SORT_COLUMNS: Record<string, any> = {
    createdAt: incidents.createdAt,
    updatedAt: incidents.updatedAt,
    severity: incidents.severity,
    status: incidents.status,
    title: incidents.title,
  };
  const sortColumn = INCIDENT_SORT_COLUMNS[params.sortBy || "createdAt"] || incidents.createdAt;
  const orderFn = params.sortOrder === "asc" ? asc : desc;

  const totalQuery = db.select({ total: count() }).from(incidents);
  const itemsQuery = db.select().from(incidents).orderBy(orderFn(sortColumn)).limit(params.limit).offset(params.offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);
  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getComments(incidentId: string): Promise<IncidentComment[]> {
  return db
    .select()
    .from(incidentComments)
    .where(eq(incidentComments.incidentId, incidentId))
    .orderBy(desc(incidentComments.createdAt));
}

export async function createComment(comment: InsertComment): Promise<IncidentComment> {
  const [created] = await db.insert(incidentComments).values(comment).returning();
  return created;
}

export async function deleteComment(id: string): Promise<boolean> {
  const result = await db.delete(incidentComments).where(eq(incidentComments.id, id)).returning();
  return result.length > 0;
}

export async function getIncidentTags(incidentId: string): Promise<Tag[]> {
  const rows = await db
    .select({ tag: tags })
    .from(incidentTags)
    .innerJoin(tags, eq(incidentTags.tagId, tags.id))
    .where(eq(incidentTags.incidentId, incidentId));
  return rows.map((r) => r.tag);
}

export async function addIncidentTag(incidentId: string, tagId: string): Promise<void> {
  await db.insert(incidentTags).values({ incidentId, tagId }).onConflictDoNothing();
}

export async function removeIncidentTag(incidentId: string, tagId: string): Promise<void> {
  await db.delete(incidentTags).where(and(eq(incidentTags.incidentId, incidentId), eq(incidentTags.tagId, tagId)));
}

export async function getIncidentSlaPolicies(orgId?: string): Promise<IncidentSlaPolicy[]> {
  if (orgId) {
    return db
      .select()
      .from(incidentSlaPolicies)
      .where(eq(incidentSlaPolicies.orgId, orgId))
      .orderBy(desc(incidentSlaPolicies.createdAt));
  }
  return db.select().from(incidentSlaPolicies).orderBy(desc(incidentSlaPolicies.createdAt));
}

export async function getIncidentSlaPolicy(id: string): Promise<IncidentSlaPolicy | undefined> {
  const [policy] = await db.select().from(incidentSlaPolicies).where(eq(incidentSlaPolicies.id, id));
  return policy;
}

export async function createIncidentSlaPolicy(policy: InsertIncidentSlaPolicy): Promise<IncidentSlaPolicy> {
  const [created] = await db.insert(incidentSlaPolicies).values(policy).returning();
  return created;
}

export async function updateIncidentSlaPolicy(
  id: string,
  data: Partial<IncidentSlaPolicy>,
): Promise<IncidentSlaPolicy | undefined> {
  const [updated] = await db
    .update(incidentSlaPolicies)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(incidentSlaPolicies.id, id))
    .returning();
  return updated;
}

export async function deleteIncidentSlaPolicy(id: string): Promise<boolean> {
  const [deleted] = await db.delete(incidentSlaPolicies).where(eq(incidentSlaPolicies.id, id)).returning();
  return !!deleted;
}

// Post-Incident Reviews

export async function getPostIncidentReviews(orgId?: string, incidentId?: string): Promise<PostIncidentReview[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(postIncidentReviews.orgId, orgId));
  if (incidentId) conditions.push(eq(postIncidentReviews.incidentId, incidentId));
  if (conditions.length > 0) {
    return db
      .select()
      .from(postIncidentReviews)
      .where(and(...conditions))
      .orderBy(desc(postIncidentReviews.createdAt));
  }
  return db.select().from(postIncidentReviews).orderBy(desc(postIncidentReviews.createdAt));
}

export async function getPostIncidentReview(id: string): Promise<PostIncidentReview | undefined> {
  const [review] = await db.select().from(postIncidentReviews).where(eq(postIncidentReviews.id, id));
  return review;
}

export async function createPostIncidentReview(review: InsertPostIncidentReview): Promise<PostIncidentReview> {
  const [created] = await db.insert(postIncidentReviews).values(review).returning();
  return created;
}

export async function updatePostIncidentReview(
  id: string,
  data: Partial<PostIncidentReview>,
): Promise<PostIncidentReview | undefined> {
  const [updated] = await db
    .update(postIncidentReviews)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(postIncidentReviews.id, id))
    .returning();
  return updated;
}

export async function deletePostIncidentReview(id: string): Promise<boolean> {
  const [deleted] = await db.delete(postIncidentReviews).where(eq(postIncidentReviews.id, id)).returning();
  return !!deleted;
}

export async function getPirActionItems(reviewId: string, orgId?: string): Promise<PirActionItem[]> {
  const conditions = [eq(pirActionItems.reviewId, reviewId)];
  if (orgId) conditions.push(eq(pirActionItems.orgId, orgId));
  return db
    .select()
    .from(pirActionItems)
    .where(and(...conditions))
    .orderBy(desc(pirActionItems.createdAt));
}

export async function getPirActionItem(id: string): Promise<PirActionItem | undefined> {
  const [item] = await db.select().from(pirActionItems).where(eq(pirActionItems.id, id));
  return item;
}

export async function createPirActionItem(item: InsertPirActionItem): Promise<PirActionItem> {
  const [created] = await db.insert(pirActionItems).values(item).returning();
  return created;
}

export async function updatePirActionItem(
  id: string,
  data: Partial<PirActionItem>,
): Promise<PirActionItem | undefined> {
  const [updated] = await db.update(pirActionItems).set(data).where(eq(pirActionItems.id, id)).returning();
  return updated;
}

export async function deletePirActionItem(id: string): Promise<boolean> {
  const [deleted] = await db.delete(pirActionItems).where(eq(pirActionItems.id, id)).returning();
  return !!deleted;
}

// ==========================================
// Playbook Versions
// ==========================================

export async function getIncidentResponseApprovals(
  orgId: string,
  incidentId?: string,
  status?: string,
): Promise<IncidentResponseApproval[]> {
  const conditions = [eq(incidentResponseApprovals.orgId, orgId)];
  if (incidentId) conditions.push(eq(incidentResponseApprovals.incidentId, incidentId));
  if (status) conditions.push(eq(incidentResponseApprovals.status, status));
  return db
    .select()
    .from(incidentResponseApprovals)
    .where(and(...conditions))
    .orderBy(desc(incidentResponseApprovals.requestedAt));
}

export async function getIncidentResponseApproval(id: string): Promise<IncidentResponseApproval | undefined> {
  const [approval] = await db.select().from(incidentResponseApprovals).where(eq(incidentResponseApprovals.id, id));
  return approval;
}

export async function createIncidentResponseApproval(
  approval: InsertIncidentResponseApproval,
): Promise<IncidentResponseApproval> {
  const [created] = await db.insert(incidentResponseApprovals).values(approval).returning();
  return created;
}

export async function updateIncidentResponseApproval(
  id: string,
  data: Partial<IncidentResponseApproval>,
): Promise<IncidentResponseApproval | undefined> {
  const [updated] = await db
    .update(incidentResponseApprovals)
    .set(data)
    .where(eq(incidentResponseApprovals.id, id))
    .returning();
  return updated;
}

// ==========================================
// PIR Action Items
// ==========================================
