import {
  type AgentToolInvocation,
  type InsertAgentToolInvocation,
  type AgentToolAnomaly,
  type InsertAgentToolAnomaly,
  type AgentToolPolicy,
  type InsertAgentToolPolicy,
  type AgentTrustBoundaryRule,
  type InsertAgentTrustBoundaryRule,
  agentToolInvocations,
  agentToolAnomalies,
  agentToolPolicies,
  agentTrustBoundaryRules,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ─── Invocations ─────────────────────────────────────────────────────────────

export async function getAgentToolInvocations(
  orgId: string,
  limit = 100,
  filters?: { toolId?: string; agentId?: string; verdict?: string },
): Promise<AgentToolInvocation[]> {
  const conditions = [eq(agentToolInvocations.orgId, orgId)];
  if (filters?.toolId) conditions.push(eq(agentToolInvocations.toolId, filters.toolId));
  if (filters?.agentId) conditions.push(eq(agentToolInvocations.agentId, filters.agentId));
  if (filters?.verdict) conditions.push(eq(agentToolInvocations.verdict, filters.verdict));
  return db
    .select()
    .from(agentToolInvocations)
    .where(and(...conditions))
    .orderBy(desc(agentToolInvocations.createdAt))
    .limit(limit);
}

export async function getAgentToolInvocation(id: string, orgId: string): Promise<AgentToolInvocation | undefined> {
  const [row] = await db
    .select()
    .from(agentToolInvocations)
    .where(and(eq(agentToolInvocations.id, id), eq(agentToolInvocations.orgId, orgId)));
  return row;
}

export async function createAgentToolInvocation(data: InsertAgentToolInvocation): Promise<AgentToolInvocation> {
  const [created] = await db.insert(agentToolInvocations).values(data).returning();
  return created;
}

export async function countAgentToolInvocations(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(agentToolInvocations)
    .where(eq(agentToolInvocations.orgId, orgId));
  return row?.total ?? 0;
}

// ─── Anomalies ───────────────────────────────────────────────────────────────

export async function getAgentToolAnomalies(orgId: string, unacknowledgedOnly = false): Promise<AgentToolAnomaly[]> {
  const base = eq(agentToolAnomalies.orgId, orgId);
  const where = unacknowledgedOnly ? and(base, eq(agentToolAnomalies.acknowledged, false)) : base;
  return db.select().from(agentToolAnomalies).where(where).orderBy(desc(agentToolAnomalies.createdAt));
}

export async function acknowledgeAgentToolAnomaly(
  id: string,
  orgId: string,
  acknowledgedBy: string,
): Promise<AgentToolAnomaly | undefined> {
  const [updated] = await db
    .update(agentToolAnomalies)
    .set({ acknowledged: true, acknowledgedBy, acknowledgedAt: new Date() })
    .where(and(eq(agentToolAnomalies.id, id), eq(agentToolAnomalies.orgId, orgId)))
    .returning();
  return updated;
}

export async function createAgentToolAnomaly(data: InsertAgentToolAnomaly): Promise<AgentToolAnomaly> {
  const [created] = await db.insert(agentToolAnomalies).values(data).returning();
  return created;
}

export async function countAgentToolAnomalies(orgId: string, unacknowledgedOnly = false): Promise<number> {
  const base = eq(agentToolAnomalies.orgId, orgId);
  const where = unacknowledgedOnly ? and(base, eq(agentToolAnomalies.acknowledged, false)) : base;
  const [row] = await db.select({ total: count() }).from(agentToolAnomalies).where(where);
  return row?.total ?? 0;
}

// ─── Policies ────────────────────────────────────────────────────────────────

export async function getAgentToolPoliciesList(orgId: string): Promise<AgentToolPolicy[]> {
  return db
    .select()
    .from(agentToolPolicies)
    .where(eq(agentToolPolicies.orgId, orgId))
    .orderBy(desc(agentToolPolicies.createdAt));
}

export async function getAgentToolPolicyByTool(orgId: string, toolId: string): Promise<AgentToolPolicy | undefined> {
  const [row] = await db
    .select()
    .from(agentToolPolicies)
    .where(and(eq(agentToolPolicies.orgId, orgId), eq(agentToolPolicies.toolId, toolId)));
  return row;
}

export async function upsertAgentToolPolicy(data: InsertAgentToolPolicy): Promise<AgentToolPolicy> {
  const existing = await getAgentToolPolicyByTool(data.orgId, data.toolId);
  if (existing) {
    const [updated] = await db
      .update(agentToolPolicies)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(agentToolPolicies.id, existing.id))
      .returning();
    return updated;
  }
  const [created] = await db.insert(agentToolPolicies).values(data).returning();
  return created;
}

// ─── Trust Boundary Rules ────────────────────────────────────────────────────

export async function getAgentTrustBoundaryRulesList(orgId: string): Promise<AgentTrustBoundaryRule[]> {
  return db
    .select()
    .from(agentTrustBoundaryRules)
    .where(eq(agentTrustBoundaryRules.orgId, orgId))
    .orderBy(agentTrustBoundaryRules.priority);
}

export async function getAgentTrustBoundaryRule(
  id: string,
  orgId: string,
): Promise<AgentTrustBoundaryRule | undefined> {
  const [row] = await db
    .select()
    .from(agentTrustBoundaryRules)
    .where(and(eq(agentTrustBoundaryRules.id, id), eq(agentTrustBoundaryRules.orgId, orgId)));
  return row;
}

export async function createAgentTrustBoundaryRule(
  data: InsertAgentTrustBoundaryRule,
): Promise<AgentTrustBoundaryRule> {
  const [created] = await db.insert(agentTrustBoundaryRules).values(data).returning();
  return created;
}

export async function updateAgentTrustBoundaryRule(
  id: string,
  orgId: string,
  updates: Partial<InsertAgentTrustBoundaryRule>,
): Promise<AgentTrustBoundaryRule | undefined> {
  const [updated] = await db
    .update(agentTrustBoundaryRules)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(agentTrustBoundaryRules.id, id), eq(agentTrustBoundaryRules.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteAgentTrustBoundaryRule(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(agentTrustBoundaryRules)
    .where(and(eq(agentTrustBoundaryRules.id, id), eq(agentTrustBoundaryRules.orgId, orgId)))
    .returning();
  return result.length > 0;
}
