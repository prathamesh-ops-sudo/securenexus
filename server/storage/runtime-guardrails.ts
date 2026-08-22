import {
  type RuntimeGuardrailPolicy,
  type InsertRuntimeGuardrailPolicy,
  type RuntimeGuardrailDecision,
  type InsertRuntimeGuardrailDecision,
  type RuntimeGuardrailOverride,
  type InsertRuntimeGuardrailOverride,
  type RuntimeGuardrailSimulation,
  type InsertRuntimeGuardrailSimulation,
  runtimeGuardrailPolicies,
  runtimeGuardrailDecisions,
  runtimeGuardrailOverrides,
  runtimeGuardrailSimulations,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ─── Policies ────────────────────────────────────────────────────────────────

export async function getRuntimePolicies(orgId: string): Promise<RuntimeGuardrailPolicy[]> {
  return db
    .select()
    .from(runtimeGuardrailPolicies)
    .where(eq(runtimeGuardrailPolicies.orgId, orgId))
    .orderBy(runtimeGuardrailPolicies.priority);
}

export async function getRuntimePolicy(id: string, orgId: string): Promise<RuntimeGuardrailPolicy | undefined> {
  const [row] = await db
    .select()
    .from(runtimeGuardrailPolicies)
    .where(and(eq(runtimeGuardrailPolicies.id, id), eq(runtimeGuardrailPolicies.orgId, orgId)));
  return row;
}

export async function createRuntimePolicy(data: InsertRuntimeGuardrailPolicy): Promise<RuntimeGuardrailPolicy> {
  const [created] = await db.insert(runtimeGuardrailPolicies).values(data).returning();
  return created;
}

export async function updateRuntimePolicy(
  id: string,
  orgId: string,
  updates: Partial<InsertRuntimeGuardrailPolicy>,
): Promise<RuntimeGuardrailPolicy | undefined> {
  const [updated] = await db
    .update(runtimeGuardrailPolicies)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(runtimeGuardrailPolicies.id, id), eq(runtimeGuardrailPolicies.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteRuntimePolicy(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(runtimeGuardrailPolicies)
    .where(and(eq(runtimeGuardrailPolicies.id, id), eq(runtimeGuardrailPolicies.orgId, orgId)))
    .returning();
  return result.length > 0;
}

export async function countRuntimePolicies(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(runtimeGuardrailPolicies)
    .where(eq(runtimeGuardrailPolicies.orgId, orgId));
  return row?.total ?? 0;
}

// ─── Decisions ───────────────────────────────────────────────────────────────

export async function getRuntimeDecisions(orgId: string, limit = 100): Promise<RuntimeGuardrailDecision[]> {
  return db
    .select()
    .from(runtimeGuardrailDecisions)
    .where(eq(runtimeGuardrailDecisions.orgId, orgId))
    .orderBy(desc(runtimeGuardrailDecisions.createdAt))
    .limit(limit);
}

export async function createRuntimeDecision(data: InsertRuntimeGuardrailDecision): Promise<RuntimeGuardrailDecision> {
  const [created] = await db.insert(runtimeGuardrailDecisions).values(data).returning();
  return created;
}

export async function countRuntimeDecisions(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(runtimeGuardrailDecisions)
    .where(eq(runtimeGuardrailDecisions.orgId, orgId));
  return row?.total ?? 0;
}

export async function getRuntimeSimulations(orgId: string, limit = 100): Promise<RuntimeGuardrailSimulation[]> {
  return db
    .select()
    .from(runtimeGuardrailSimulations)
    .where(eq(runtimeGuardrailSimulations.orgId, orgId))
    .orderBy(desc(runtimeGuardrailSimulations.createdAt))
    .limit(limit);
}

export async function createRuntimeSimulation(
  data: InsertRuntimeGuardrailSimulation,
): Promise<RuntimeGuardrailSimulation> {
  const [created] = await db.insert(runtimeGuardrailSimulations).values(data).returning();
  return created;
}

// ─── Overrides ───────────────────────────────────────────────────────────────

export async function getRuntimeOverrides(orgId: string, status?: string): Promise<RuntimeGuardrailOverride[]> {
  const base = eq(runtimeGuardrailOverrides.orgId, orgId);
  const where = status ? and(base, eq(runtimeGuardrailOverrides.status, status)) : base;
  return db.select().from(runtimeGuardrailOverrides).where(where).orderBy(desc(runtimeGuardrailOverrides.createdAt));
}

export async function getRuntimeOverride(id: string, orgId: string): Promise<RuntimeGuardrailOverride | undefined> {
  const [row] = await db
    .select()
    .from(runtimeGuardrailOverrides)
    .where(and(eq(runtimeGuardrailOverrides.id, id), eq(runtimeGuardrailOverrides.orgId, orgId)));
  return row;
}

export async function createRuntimeOverride(data: InsertRuntimeGuardrailOverride): Promise<RuntimeGuardrailOverride> {
  const [created] = await db.insert(runtimeGuardrailOverrides).values(data).returning();
  return created;
}

export async function updateRuntimeOverride(
  id: string,
  orgId: string,
  updates: Partial<InsertRuntimeGuardrailOverride>,
): Promise<RuntimeGuardrailOverride | undefined> {
  const [updated] = await db
    .update(runtimeGuardrailOverrides)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(runtimeGuardrailOverrides.id, id), eq(runtimeGuardrailOverrides.orgId, orgId)))
    .returning();
  return updated;
}
