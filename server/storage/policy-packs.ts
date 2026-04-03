import { type PolicyPackActivation, type InsertPolicyPackActivation, policyPackActivations } from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

export async function getPolicyPackActivations(orgId: string): Promise<PolicyPackActivation[]> {
  return db
    .select()
    .from(policyPackActivations)
    .where(eq(policyPackActivations.orgId, orgId))
    .orderBy(desc(policyPackActivations.activatedAt));
}

export async function getPolicyPackActivation(
  orgId: string,
  packId: string,
): Promise<PolicyPackActivation | undefined> {
  const [activation] = await db
    .select()
    .from(policyPackActivations)
    .where(and(eq(policyPackActivations.orgId, orgId), eq(policyPackActivations.packId, packId)));
  return activation;
}

export async function getPolicyPackActivationById(
  id: string,
  orgId: string,
): Promise<PolicyPackActivation | undefined> {
  const [activation] = await db
    .select()
    .from(policyPackActivations)
    .where(and(eq(policyPackActivations.id, id), eq(policyPackActivations.orgId, orgId)));
  return activation;
}

export async function createPolicyPackActivation(data: InsertPolicyPackActivation): Promise<PolicyPackActivation> {
  const [created] = await db.insert(policyPackActivations).values(data).returning();
  return created;
}

export async function updatePolicyPackActivation(
  id: string,
  orgId: string,
  updates: Partial<InsertPolicyPackActivation>,
): Promise<PolicyPackActivation | undefined> {
  const [updated] = await db
    .update(policyPackActivations)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(policyPackActivations.id, id), eq(policyPackActivations.orgId, orgId)))
    .returning();
  return updated;
}

export async function deletePolicyPackActivation(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(policyPackActivations)
    .where(and(eq(policyPackActivations.id, id), eq(policyPackActivations.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countPolicyPackActivations(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(policyPackActivations)
    .where(eq(policyPackActivations.orgId, orgId));
  return row?.total ?? 0;
}
