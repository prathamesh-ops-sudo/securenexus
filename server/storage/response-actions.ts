import {
  type AutoResponsePolicy,
  type InsertAutoResponsePolicy,
  type InsertInvestigationRun,
  type InsertInvestigationStep,
  type InsertResponseAction,
  type InsertResponseActionApproval,
  type InsertResponseActionRollback,
  type InvestigationRun,
  type InvestigationStep,
  type ResponseAction,
  type ResponseActionApproval,
  type ResponseActionRollback,
  autoResponsePolicies,
  investigationRuns,
  investigationSteps,
  responseActionApprovals,
  responseActionRollbacks,
  responseActions,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, gte, inArray } from "drizzle-orm";

export async function getResponseActions(orgId?: string, incidentId?: string): Promise<ResponseAction[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(responseActions.orgId, orgId));
  if (incidentId) conditions.push(eq(responseActions.incidentId, incidentId));
  const condition = conditions.length > 0 ? and(...conditions) : undefined;
  return db.select().from(responseActions).where(condition).orderBy(desc(responseActions.createdAt)).limit(100);
}

export async function getResponseAction(id: string): Promise<ResponseAction | undefined> {
  const [action] = await db.select().from(responseActions).where(eq(responseActions.id, id));
  return action;
}

export async function createResponseAction(action: InsertResponseAction): Promise<ResponseAction> {
  const [created] = await db.insert(responseActions).values(action).returning();
  return created;
}

export async function updateResponseAction(
  id: string,
  data: Partial<ResponseAction>,
): Promise<ResponseAction | undefined> {
  const [updated] = await db.update(responseActions).set(data).where(eq(responseActions.id, id)).returning();
  return updated;
}

export async function countRecentPolicyActions(orgId: string, policyId: string, since: Date): Promise<number> {
  const [result] = await db
    .select({ count: count() })
    .from(responseActions)
    .where(
      and(
        eq(responseActions.orgId, orgId),
        eq(responseActions.policyId, policyId),
        gte(responseActions.createdAt, since),
        inArray(responseActions.status, ["completed", "failed", "approved", "unavailable"]),
      ),
    );
  return Number(result?.count ?? 0);
}

export async function getAutoResponsePolicies(orgId?: string): Promise<AutoResponsePolicy[]> {
  if (orgId) {
    return db
      .select()
      .from(autoResponsePolicies)
      .where(eq(autoResponsePolicies.orgId, orgId))
      .orderBy(desc(autoResponsePolicies.createdAt));
  }
  return db.select().from(autoResponsePolicies).orderBy(desc(autoResponsePolicies.createdAt));
}

export async function getAutoResponsePolicy(id: string): Promise<AutoResponsePolicy | null> {
  const [policy] = await db.select().from(autoResponsePolicies).where(eq(autoResponsePolicies.id, id));
  return policy || null;
}

export async function createAutoResponsePolicy(policy: InsertAutoResponsePolicy): Promise<AutoResponsePolicy> {
  const [created] = await db.insert(autoResponsePolicies).values(policy).returning();
  return created;
}

export async function updateAutoResponsePolicy(
  id: string,
  updates: Partial<AutoResponsePolicy>,
): Promise<AutoResponsePolicy | null> {
  const [updated] = await db
    .update(autoResponsePolicies)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(autoResponsePolicies.id, id))
    .returning();
  return updated || null;
}

export async function deleteAutoResponsePolicy(id: string): Promise<boolean> {
  const result = await db.delete(autoResponsePolicies).where(eq(autoResponsePolicies.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getInvestigationRuns(orgId?: string): Promise<InvestigationRun[]> {
  if (orgId) {
    return db
      .select()
      .from(investigationRuns)
      .where(eq(investigationRuns.orgId, orgId))
      .orderBy(desc(investigationRuns.createdAt));
  }
  return db.select().from(investigationRuns).orderBy(desc(investigationRuns.createdAt));
}

export async function getInvestigationRun(id: string): Promise<InvestigationRun | null> {
  const [run] = await db.select().from(investigationRuns).where(eq(investigationRuns.id, id));
  return run || null;
}

export async function createInvestigationRun(run: InsertInvestigationRun): Promise<InvestigationRun> {
  const [created] = await db.insert(investigationRuns).values(run).returning();
  return created;
}

export async function updateInvestigationRun(
  id: string,
  updates: Partial<InvestigationRun>,
): Promise<InvestigationRun | null> {
  const [updated] = await db.update(investigationRuns).set(updates).where(eq(investigationRuns.id, id)).returning();
  return updated || null;
}

export async function getInvestigationSteps(runId: string): Promise<InvestigationStep[]> {
  return db
    .select()
    .from(investigationSteps)
    .where(eq(investigationSteps.runId, runId))
    .orderBy(asc(investigationSteps.stepOrder));
}

export async function createInvestigationStep(step: InsertInvestigationStep): Promise<InvestigationStep> {
  const [created] = await db.insert(investigationSteps).values(step).returning();
  return created;
}

export async function updateInvestigationStep(
  id: string,
  updates: Partial<InvestigationStep>,
): Promise<InvestigationStep | null> {
  const [updated] = await db.update(investigationSteps).set(updates).where(eq(investigationSteps.id, id)).returning();
  return updated || null;
}

export async function getResponseActionRollbacks(orgId?: string): Promise<ResponseActionRollback[]> {
  if (orgId) {
    return db
      .select()
      .from(responseActionRollbacks)
      .where(eq(responseActionRollbacks.orgId, orgId))
      .orderBy(desc(responseActionRollbacks.createdAt));
  }
  return db.select().from(responseActionRollbacks).orderBy(desc(responseActionRollbacks.createdAt));
}

export async function getResponseActionRollback(id: string): Promise<ResponseActionRollback | null> {
  const [rollback] = await db.select().from(responseActionRollbacks).where(eq(responseActionRollbacks.id, id));
  return rollback || null;
}

export async function createResponseActionRollback(
  rollback: InsertResponseActionRollback,
): Promise<ResponseActionRollback> {
  const [created] = await db.insert(responseActionRollbacks).values(rollback).returning();
  return created;
}

export async function updateResponseActionRollback(
  id: string,
  updates: Partial<ResponseActionRollback>,
): Promise<ResponseActionRollback | null> {
  const [updated] = await db
    .update(responseActionRollbacks)
    .set(updates)
    .where(eq(responseActionRollbacks.id, id))
    .returning();
  return updated || null;
}

export async function getResponseActionApprovals(orgId?: string, status?: string): Promise<ResponseActionApproval[]> {
  const conditions = [];
  if (orgId) conditions.push(eq(responseActionApprovals.orgId, orgId));
  if (status) conditions.push(eq(responseActionApprovals.status, status));
  return db
    .select()
    .from(responseActionApprovals)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(responseActionApprovals.requestedAt));
}

export async function getResponseActionApproval(id: string): Promise<ResponseActionApproval | undefined> {
  const [approval] = await db.select().from(responseActionApprovals).where(eq(responseActionApprovals.id, id));
  return approval;
}

export async function createResponseActionApproval(
  approval: InsertResponseActionApproval,
): Promise<ResponseActionApproval> {
  const [created] = await db.insert(responseActionApprovals).values(approval).returning();
  return created;
}

export async function updateResponseActionApproval(
  id: string,
  data: Partial<ResponseActionApproval>,
): Promise<ResponseActionApproval | undefined> {
  const [updated] = await db
    .update(responseActionApprovals)
    .set(data)
    .where(eq(responseActionApprovals.id, id))
    .returning();
  return updated;
}
