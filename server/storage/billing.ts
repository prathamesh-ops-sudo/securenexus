import {
  type InsertInvoice,
  type InsertPlan,
  type InsertSubscription,
  type InsertUsageMeterSnapshot,
  type Invoice,
  type Plan,
  type Subscription,
  type UsageMeterSnapshot,
  type UsageRecord,
  apiKeys,
  connectors,
  invoices,
  plans,
  playbooks,
  subscriptions,
  usageMeterSnapshots,
  usageRecords,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, sql } from "drizzle-orm";

export async function getPlans(activeOnly?: boolean): Promise<Plan[]> {
  if (activeOnly) {
    return db.select().from(plans).where(eq(plans.isActive, true)).orderBy(asc(plans.sortOrder));
  }
  return db.select().from(plans).orderBy(asc(plans.sortOrder));
}

export async function getPlan(id: string): Promise<Plan | undefined> {
  const [plan] = await db.select().from(plans).where(eq(plans.id, id));
  return plan;
}

export async function getPlanByName(name: string): Promise<Plan | undefined> {
  const [plan] = await db.select().from(plans).where(eq(plans.name, name));
  return plan;
}

export async function createPlan(plan: InsertPlan): Promise<Plan> {
  const [created] = await db.insert(plans).values(plan).returning();
  return created;
}

export async function updatePlan(id: string, data: Partial<Plan>): Promise<Plan | undefined> {
  const [updated] = await db
    .update(plans)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(plans.id, id))
    .returning();
  return updated;
}

export async function getSubscription(orgId: string): Promise<Subscription | undefined> {
  const [sub] = await db.select().from(subscriptions).where(eq(subscriptions.orgId, orgId));
  return sub;
}

export async function getSubscriptionById(id: string): Promise<Subscription | undefined> {
  const [sub] = await db.select().from(subscriptions).where(eq(subscriptions.id, id));
  return sub;
}

export async function getSubscriptionByStripeCustomerId(stripeCustomerId: string): Promise<Subscription | undefined> {
  const [sub] = await db.select().from(subscriptions).where(eq(subscriptions.stripeCustomerId, stripeCustomerId));
  return sub;
}

export async function getSubscriptionByStripeSubId(stripeSubscriptionId: string): Promise<Subscription | undefined> {
  const [sub] = await db
    .select()
    .from(subscriptions)
    .where(eq(subscriptions.stripeSubscriptionId, stripeSubscriptionId));
  return sub;
}

export async function createSubscription(sub: InsertSubscription): Promise<Subscription> {
  const [created] = await db.insert(subscriptions).values(sub).returning();
  return created;
}

export async function updateSubscription(id: string, data: Partial<Subscription>): Promise<Subscription | undefined> {
  const [updated] = await db
    .update(subscriptions)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(subscriptions.id, id))
    .returning();
  return updated;
}

export async function getInvoices(orgId: string, limit?: number): Promise<Invoice[]> {
  const query = db.select().from(invoices).where(eq(invoices.orgId, orgId)).orderBy(desc(invoices.createdAt));
  if (limit) {
    return query.limit(limit);
  }
  return query;
}

export async function getInvoiceByStripeId(stripeInvoiceId: string): Promise<Invoice | undefined> {
  const [inv] = await db.select().from(invoices).where(eq(invoices.stripeInvoiceId, stripeInvoiceId));
  return inv;
}

export async function createInvoice(invoice: InsertInvoice): Promise<Invoice> {
  const [created] = await db.insert(invoices).values(invoice).returning();
  return created;
}

export async function updateInvoice(id: string, data: Partial<Invoice>): Promise<Invoice | undefined> {
  const [updated] = await db.update(invoices).set(data).where(eq(invoices.id, id)).returning();
  return updated;
}

// Password Reset Tokens (Phase 4)

export async function getUsageRecord(orgId: string, metric: string, periodStart: Date): Promise<UsageRecord | undefined> {
  const [record] = await db
    .select()
    .from(usageRecords)
    .where(
      and(eq(usageRecords.orgId, orgId), eq(usageRecords.metric, metric), eq(usageRecords.periodStart, periodStart)),
    )
    .limit(1);
  return record;
}

export async function getUsageRecords(orgId: string, periodStart?: Date): Promise<UsageRecord[]> {
  if (periodStart) {
    return db
      .select()
      .from(usageRecords)
      .where(and(eq(usageRecords.orgId, orgId), eq(usageRecords.periodStart, periodStart)));
  }
  return db.select().from(usageRecords).where(eq(usageRecords.orgId, orgId)).orderBy(desc(usageRecords.periodStart));
}

export async function incrementUsage(orgId: string, metric: string, amount: number = 1): Promise<UsageRecord> {
  const now = new Date();
  const periodStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const periodEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));

  const [result] = await db
    .insert(usageRecords)
    .values({ orgId, metric, value: amount, periodStart, periodEnd })
    .onConflictDoUpdate({
      target: [usageRecords.orgId, usageRecords.metric, usageRecords.periodStart],
      set: {
        value: sql`${usageRecords.value} + ${amount}`,
        updatedAt: new Date(),
      },
    })
    .returning();
  return result;
}

export async function resetUsagePeriod(orgId: string, oldPeriodStart: Date, newPeriodStart: Date, newPeriodEnd: Date): Promise<void> {
  const oldRecords = await db
    .select()
    .from(usageRecords)
    .where(and(eq(usageRecords.orgId, orgId), eq(usageRecords.periodStart, oldPeriodStart)));

  for (const record of oldRecords) {
    await db
      .insert(usageRecords)
      .values({ orgId, metric: record.metric, value: 0, periodStart: newPeriodStart, periodEnd: newPeriodEnd })
      .onConflictDoNothing();
  }
}

export async function countActiveConnectors(orgId: string): Promise<number> {
  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(connectors)
    .where(eq(connectors.orgId, orgId));
  return Number(result?.count ?? 0);
}

export async function countActiveApiKeys(orgId: string): Promise<number> {
  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(apiKeys)
    .where(and(eq(apiKeys.orgId, orgId), eq(apiKeys.isActive, true)));
  return Number(result?.count ?? 0);
}

export async function countActivePlaybooks(orgId: string): Promise<number> {
  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(playbooks)
    .where(eq(playbooks.orgId, orgId));
  return Number(result?.count ?? 0);
}

export async function getUsageMeterSnapshots(orgId: string, metricType?: string): Promise<UsageMeterSnapshot[]> {
  const conditions = [eq(usageMeterSnapshots.orgId, orgId)];
  if (metricType) conditions.push(eq(usageMeterSnapshots.metricType, metricType));
  return db
    .select()
    .from(usageMeterSnapshots)
    .where(and(...conditions))
    .orderBy(desc(usageMeterSnapshots.snapshotAt))
    .limit(100);
}

export async function createUsageMeterSnapshot(data: InsertUsageMeterSnapshot): Promise<UsageMeterSnapshot> {
  const [created] = await db.insert(usageMeterSnapshots).values(data).returning();
  return created;
}
