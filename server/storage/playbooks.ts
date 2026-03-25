import {
  type BlastRadiusPreview,
  type InsertBlastRadiusPreview,
  type InsertPlaybook,
  type InsertPlaybookApproval,
  type InsertPlaybookExecution,
  type InsertPlaybookRollbackPlan,
  type InsertPlaybookSimulation,
  type InsertPlaybookVersion,
  type Playbook,
  type PlaybookApproval,
  type PlaybookExecution,
  type PlaybookRollbackPlan,
  type PlaybookSimulation,
  type PlaybookVersion,
  blastRadiusPreviews,
  playbookApprovals,
  playbookExecutions,
  playbookRollbackPlans,
  playbookSimulations,
  playbookVersions,
  playbooks,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq, sql } from "drizzle-orm";

export async function getPlaybooks(orgId?: string): Promise<Playbook[]> {
  if (orgId) {
    return db.select().from(playbooks).where(eq(playbooks.orgId, orgId)).orderBy(desc(playbooks.updatedAt));
  }
  return db.select().from(playbooks).orderBy(desc(playbooks.updatedAt));
}

export async function getPlaybook(id: string): Promise<Playbook | undefined> {
  const [playbook] = await db.select().from(playbooks).where(eq(playbooks.id, id));
  return playbook;
}

export async function createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
  const [created] = await db.insert(playbooks).values(playbook).returning();
  return created;
}

export async function updatePlaybook(id: string, data: Partial<Playbook>): Promise<Playbook | undefined> {
  const [updated] = await db
    .update(playbooks)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(playbooks.id, id))
    .returning();
  return updated;
}

export async function deletePlaybook(id: string): Promise<boolean> {
  const result = await db.delete(playbooks).where(eq(playbooks.id, id)).returning();
  return result.length > 0;
}

export async function getPlaybookExecutions(playbookId?: string, limit = 50): Promise<PlaybookExecution[]> {
  if (playbookId) {
    return db
      .select()
      .from(playbookExecutions)
      .where(eq(playbookExecutions.playbookId, playbookId))
      .orderBy(desc(playbookExecutions.createdAt))
      .limit(limit);
  }
  return db.select().from(playbookExecutions).orderBy(desc(playbookExecutions.createdAt)).limit(limit);
}

export async function countPlaybookExecutionsByOrg(orgId: string): Promise<number> {
  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(playbookExecutions)
    .innerJoin(playbooks, eq(playbookExecutions.playbookId, playbooks.id))
    .where(eq(playbooks.orgId, orgId));
  return Number(result?.count ?? 0);
}

export async function getPlaybookExecution(id: string): Promise<PlaybookExecution | undefined> {
  const [execution] = await db.select().from(playbookExecutions).where(eq(playbookExecutions.id, id));
  return execution;
}

export async function createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
  const [created] = await db.insert(playbookExecutions).values(execution).returning();
  return created;
}

export async function updatePlaybookExecution(id: string, data: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
  const [updated] = await db.update(playbookExecutions).set(data).where(eq(playbookExecutions.id, id)).returning();
  return updated;
}

export async function getPlaybookApprovals(status?: string): Promise<PlaybookApproval[]> {
  if (status) {
    return db
      .select()
      .from(playbookApprovals)
      .where(eq(playbookApprovals.status, status))
      .orderBy(desc(playbookApprovals.requestedAt));
  }
  return db.select().from(playbookApprovals).orderBy(desc(playbookApprovals.requestedAt));
}

export async function getPlaybookApproval(id: string): Promise<PlaybookApproval | undefined> {
  const [approval] = await db.select().from(playbookApprovals).where(eq(playbookApprovals.id, id));
  return approval;
}

export async function getPlaybookApprovalsByExecution(executionId: string): Promise<PlaybookApproval[]> {
  return db
    .select()
    .from(playbookApprovals)
    .where(eq(playbookApprovals.executionId, executionId))
    .orderBy(desc(playbookApprovals.requestedAt));
}

export async function createPlaybookApproval(approval: InsertPlaybookApproval): Promise<PlaybookApproval> {
  const [created] = await db.insert(playbookApprovals).values(approval).returning();
  return created;
}

export async function updatePlaybookApproval(id: string, data: Partial<PlaybookApproval>): Promise<PlaybookApproval | undefined> {
  const [updated] = await db.update(playbookApprovals).set(data).where(eq(playbookApprovals.id, id)).returning();
  return updated;
}

export async function getPlaybookVersions(playbookId: string, orgId?: string): Promise<PlaybookVersion[]> {
  const conditions = [eq(playbookVersions.playbookId, playbookId)];
  if (orgId) conditions.push(eq(playbookVersions.orgId, orgId));
  return db
    .select()
    .from(playbookVersions)
    .where(and(...conditions))
    .orderBy(desc(playbookVersions.version));
}

export async function getPlaybookVersion(id: string): Promise<PlaybookVersion | undefined> {
  const [version] = await db.select().from(playbookVersions).where(eq(playbookVersions.id, id));
  return version;
}

export async function getLatestPlaybookVersion(playbookId: string): Promise<PlaybookVersion | undefined> {
  const [version] = await db
    .select()
    .from(playbookVersions)
    .where(eq(playbookVersions.playbookId, playbookId))
    .orderBy(desc(playbookVersions.version))
    .limit(1);
  return version;
}

export async function createPlaybookVersion(version: InsertPlaybookVersion): Promise<PlaybookVersion> {
  const [created] = await db.insert(playbookVersions).values(version).returning();
  return created;
}

export async function updatePlaybookVersion(id: string, data: Partial<PlaybookVersion>): Promise<PlaybookVersion | undefined> {
  const [updated] = await db.update(playbookVersions).set(data).where(eq(playbookVersions.id, id)).returning();
  return updated;
}

// ==========================================
// 8.3 — Blast Radius Previews
// ==========================================

export async function getBlastRadiusPreviews(playbookId: string, orgId?: string): Promise<BlastRadiusPreview[]> {
  const conditions = [eq(blastRadiusPreviews.playbookId, playbookId)];
  if (orgId) conditions.push(eq(blastRadiusPreviews.orgId, orgId));
  return db
    .select()
    .from(blastRadiusPreviews)
    .where(and(...conditions))
    .orderBy(desc(blastRadiusPreviews.createdAt));
}

export async function getBlastRadiusPreview(id: string): Promise<BlastRadiusPreview | undefined> {
  const [preview] = await db.select().from(blastRadiusPreviews).where(eq(blastRadiusPreviews.id, id));
  return preview;
}

export async function createBlastRadiusPreview(preview: InsertBlastRadiusPreview): Promise<BlastRadiusPreview> {
  const [created] = await db.insert(blastRadiusPreviews).values(preview).returning();
  return created;
}

// ==========================================
// 8.3 — Playbook Simulations
// ==========================================

export async function getPlaybookSimulations(playbookId: string, orgId?: string): Promise<PlaybookSimulation[]> {
  const conditions = [eq(playbookSimulations.playbookId, playbookId)];
  if (orgId) conditions.push(eq(playbookSimulations.orgId, orgId));
  return db
    .select()
    .from(playbookSimulations)
    .where(and(...conditions))
    .orderBy(desc(playbookSimulations.createdAt));
}

export async function getPlaybookSimulation(id: string): Promise<PlaybookSimulation | undefined> {
  const [sim] = await db.select().from(playbookSimulations).where(eq(playbookSimulations.id, id));
  return sim;
}

export async function createPlaybookSimulation(simulation: InsertPlaybookSimulation): Promise<PlaybookSimulation> {
  const [created] = await db.insert(playbookSimulations).values(simulation).returning();
  return created;
}

export async function updatePlaybookSimulation(
  id: string,
  data: Partial<PlaybookSimulation>,
): Promise<PlaybookSimulation | undefined> {
  const [updated] = await db.update(playbookSimulations).set(data).where(eq(playbookSimulations.id, id)).returning();
  return updated;
}

// ==========================================
// 8.3 — Playbook Rollback Plans
// ==========================================

export async function getPlaybookRollbackPlans(playbookId: string, orgId?: string): Promise<PlaybookRollbackPlan[]> {
  const conditions = [eq(playbookRollbackPlans.playbookId, playbookId)];
  if (orgId) conditions.push(eq(playbookRollbackPlans.orgId, orgId));
  return db
    .select()
    .from(playbookRollbackPlans)
    .where(and(...conditions))
    .orderBy(desc(playbookRollbackPlans.createdAt));
}

export async function getPlaybookRollbackPlan(id: string): Promise<PlaybookRollbackPlan | undefined> {
  const [plan] = await db.select().from(playbookRollbackPlans).where(eq(playbookRollbackPlans.id, id));
  return plan;
}

export async function createPlaybookRollbackPlan(plan: InsertPlaybookRollbackPlan): Promise<PlaybookRollbackPlan> {
  const [created] = await db.insert(playbookRollbackPlans).values(plan).returning();
  return created;
}

export async function updatePlaybookRollbackPlan(
  id: string,
  data: Partial<PlaybookRollbackPlan>,
): Promise<PlaybookRollbackPlan | undefined> {
  const [updated] = await db
    .update(playbookRollbackPlans)
    .set(data)
    .where(eq(playbookRollbackPlans.id, id))
    .returning();
  return updated;
}

// ==========================================
// 8.4 — Report Template Versions
// ==========================================
