import { db } from "../db";
import { eq, and, desc } from "drizzle-orm";
import {
  remediationFixes,
  codeOwners,
  type RemediationFix,
  type InsertRemediationFix,
  type CodeOwner,
  type InsertCodeOwner,
} from "@shared/schema";

// ─── Remediation Fixes ───────────────────────────────────────────────────────

export async function getRemediationFixes(orgId: string): Promise<RemediationFix[]> {
  return db
    .select()
    .from(remediationFixes)
    .where(eq(remediationFixes.orgId, orgId))
    .orderBy(desc(remediationFixes.createdAt));
}

export async function getRemediationFixesByStatus(orgId: string, status: string): Promise<RemediationFix[]> {
  return db
    .select()
    .from(remediationFixes)
    .where(and(eq(remediationFixes.orgId, orgId), eq(remediationFixes.status, status)))
    .orderBy(desc(remediationFixes.createdAt));
}

export async function getRemediationFix(id: string): Promise<RemediationFix | undefined> {
  const [row] = await db.select().from(remediationFixes).where(eq(remediationFixes.id, id));
  return row;
}

export async function createRemediationFix(data: InsertRemediationFix): Promise<RemediationFix> {
  const [row] = await db.insert(remediationFixes).values(data).returning();
  return row;
}

export async function updateRemediationFix(
  id: string,
  data: Partial<RemediationFix>,
): Promise<RemediationFix | undefined> {
  const [row] = await db
    .update(remediationFixes)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(remediationFixes.id, id))
    .returning();
  return row;
}

export async function deleteRemediationFix(id: string): Promise<boolean> {
  const result = await db.delete(remediationFixes).where(eq(remediationFixes.id, id));
  return (result.rowCount ?? 0) > 0;
}

// ─── Code Owners ─────────────────────────────────────────────────────────────

export async function getCodeOwnersList(orgId: string): Promise<CodeOwner[]> {
  return db.select().from(codeOwners).where(eq(codeOwners.orgId, orgId));
}

export async function getCodeOwnerById(id: string): Promise<CodeOwner | undefined> {
  const [row] = await db.select().from(codeOwners).where(eq(codeOwners.id, id));
  return row;
}

export async function createCodeOwner(data: InsertCodeOwner): Promise<CodeOwner> {
  const [row] = await db.insert(codeOwners).values(data).returning();
  return row;
}

export async function updateCodeOwner(id: string, data: Partial<CodeOwner>): Promise<CodeOwner | undefined> {
  const [row] = await db.update(codeOwners).set(data).where(eq(codeOwners.id, id)).returning();
  return row;
}

export async function deleteCodeOwner(id: string): Promise<boolean> {
  const result = await db.delete(codeOwners).where(eq(codeOwners.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function findCodeOwnerForFile(orgId: string, filePath: string): Promise<CodeOwner | undefined> {
  const owners = await getCodeOwnersList(orgId);
  for (const owner of owners) {
    const ownedFiles = (owner.filesOwned as string[]) || [];
    for (const pattern of ownedFiles) {
      if (filePath.startsWith(pattern.replace("*", "")) || filePath === pattern) {
        return owner;
      }
    }
  }
  return undefined;
}
