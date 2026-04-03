import { db } from "../db";
import { eq, and, desc } from "drizzle-orm";
import {
  promptInvestigations,
  promptHistory,
  artifactApprovals,
  artifactDeployments,
  type PromptInvestigation,
  type InsertPromptInvestigation,
  type PromptHistoryEntry,
  type InsertPromptHistoryEntry,
  type ArtifactApproval,
  type InsertArtifactApproval,
  type ArtifactDeployment,
  type InsertArtifactDeployment,
} from "@shared/schema";

// ─── Investigations ──────────────────────────────────────────────────────────

export async function getPromptInvestigations(orgId: string): Promise<PromptInvestigation[]> {
  return db
    .select()
    .from(promptInvestigations)
    .where(eq(promptInvestigations.orgId, orgId))
    .orderBy(desc(promptInvestigations.createdAt));
}

export async function getPromptInvestigation(id: string): Promise<PromptInvestigation | undefined> {
  const [row] = await db.select().from(promptInvestigations).where(eq(promptInvestigations.id, id));
  return row;
}

export async function createPromptInvestigation(data: InsertPromptInvestigation): Promise<PromptInvestigation> {
  const [row] = await db.insert(promptInvestigations).values(data).returning();
  return row;
}

export async function updatePromptInvestigation(
  id: string,
  data: Partial<PromptInvestigation>,
): Promise<PromptInvestigation | undefined> {
  const [row] = await db.update(promptInvestigations).set(data).where(eq(promptInvestigations.id, id)).returning();
  return row;
}

// ─── Prompt History ──────────────────────────────────────────────────────────

export async function getPromptHistory(orgId: string): Promise<PromptHistoryEntry[]> {
  return db.select().from(promptHistory).where(eq(promptHistory.orgId, orgId)).orderBy(desc(promptHistory.usedAt));
}

export async function getPromptHistoryEntry(id: string): Promise<PromptHistoryEntry | undefined> {
  const [row] = await db.select().from(promptHistory).where(eq(promptHistory.id, id));
  return row;
}

export async function createPromptHistoryEntry(data: InsertPromptHistoryEntry): Promise<PromptHistoryEntry> {
  const [row] = await db.insert(promptHistory).values(data).returning();
  return row;
}

export async function updatePromptHistoryEntry(
  id: string,
  data: Partial<PromptHistoryEntry>,
): Promise<PromptHistoryEntry | undefined> {
  const [row] = await db.update(promptHistory).set(data).where(eq(promptHistory.id, id)).returning();
  return row;
}

// ─── Artifact Approvals ──────────────────────────────────────────────────────

export async function getArtifactApprovals(orgId: string): Promise<ArtifactApproval[]> {
  return db
    .select()
    .from(artifactApprovals)
    .where(eq(artifactApprovals.orgId, orgId))
    .orderBy(desc(artifactApprovals.requestedAt));
}

export async function getPendingArtifactApprovals(orgId: string): Promise<ArtifactApproval[]> {
  return db
    .select()
    .from(artifactApprovals)
    .where(and(eq(artifactApprovals.orgId, orgId), eq(artifactApprovals.status, "pending_approval")))
    .orderBy(desc(artifactApprovals.requestedAt));
}

export async function getArtifactApproval(id: string): Promise<ArtifactApproval | undefined> {
  const [row] = await db.select().from(artifactApprovals).where(eq(artifactApprovals.id, id));
  return row;
}

export async function createArtifactApproval(data: InsertArtifactApproval): Promise<ArtifactApproval> {
  const [row] = await db.insert(artifactApprovals).values(data).returning();
  return row;
}

export async function updateArtifactApproval(
  id: string,
  data: Partial<ArtifactApproval>,
): Promise<ArtifactApproval | undefined> {
  const [row] = await db.update(artifactApprovals).set(data).where(eq(artifactApprovals.id, id)).returning();
  return row;
}

// ─── Artifact Deployments ────────────────────────────────────────────────────

export async function getArtifactDeployments(orgId: string): Promise<ArtifactDeployment[]> {
  return db
    .select()
    .from(artifactDeployments)
    .where(eq(artifactDeployments.orgId, orgId))
    .orderBy(desc(artifactDeployments.deployedAt));
}

export async function getArtifactDeployment(id: string): Promise<ArtifactDeployment | undefined> {
  const [row] = await db.select().from(artifactDeployments).where(eq(artifactDeployments.id, id));
  return row;
}

export async function createArtifactDeployment(data: InsertArtifactDeployment): Promise<ArtifactDeployment> {
  const [row] = await db.insert(artifactDeployments).values(data).returning();
  return row;
}

export async function updateArtifactDeployment(
  id: string,
  data: Partial<ArtifactDeployment>,
): Promise<ArtifactDeployment | undefined> {
  const [row] = await db.update(artifactDeployments).set(data).where(eq(artifactDeployments.id, id)).returning();
  return row;
}
