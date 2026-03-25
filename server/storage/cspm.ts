import {
  type CspmAccount,
  type CspmAttackPath,
  type CspmDriftBaseline,
  type CspmDriftEvent,
  type CspmDspmFinding,
  type CspmFinding,
  type CspmRemediation,
  type CspmScan,
  type InsertCspmAccount,
  type InsertCspmAttackPath,
  type InsertCspmDriftBaseline,
  type InsertCspmDriftEvent,
  type InsertCspmDspmFinding,
  type InsertCspmFinding,
  type InsertCspmRemediation,
  type InsertCspmScan,
  cspmAccounts,
  cspmAttackPaths,
  cspmDriftBaselines,
  cspmDriftEvents,
  cspmDspmFindings,
  cspmFindings,
  cspmRemediations,
  cspmScans,
} from "@shared/schema";
import { db } from "../db";
import { and, desc, eq } from "drizzle-orm";

export async function getCspmAccounts(orgId: string): Promise<CspmAccount[]> {
  return db.select().from(cspmAccounts).where(eq(cspmAccounts.orgId, orgId)).orderBy(desc(cspmAccounts.createdAt));
}

export async function getCspmAccount(id: string): Promise<CspmAccount | undefined> {
  const [account] = await db.select().from(cspmAccounts).where(eq(cspmAccounts.id, id));
  return account;
}

export async function createCspmAccount(account: InsertCspmAccount): Promise<CspmAccount> {
  const [created] = await db.insert(cspmAccounts).values(account).returning();
  return created;
}

export async function updateCspmAccount(id: string, updates: Partial<CspmAccount>): Promise<CspmAccount | null> {
  const [updated] = await db.update(cspmAccounts).set(updates).where(eq(cspmAccounts.id, id)).returning();
  return updated || null;
}

export async function deleteCspmAccount(id: string): Promise<boolean> {
  const result = await db.delete(cspmAccounts).where(eq(cspmAccounts.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getCspmScans(orgId: string, accountId?: string): Promise<CspmScan[]> {
  const conditions = [eq(cspmScans.orgId, orgId)];
  if (accountId) conditions.push(eq(cspmScans.accountId, accountId));
  return db
    .select()
    .from(cspmScans)
    .where(and(...conditions))
    .orderBy(desc(cspmScans.startedAt));
}

export async function createCspmScan(scan: InsertCspmScan): Promise<CspmScan> {
  const [created] = await db.insert(cspmScans).values(scan).returning();
  return created;
}

export async function updateCspmScan(id: string, updates: Partial<CspmScan>): Promise<CspmScan | null> {
  const [updated] = await db.update(cspmScans).set(updates).where(eq(cspmScans.id, id)).returning();
  return updated || null;
}

export async function getCspmFindings(orgId: string, scanId?: string, severity?: string): Promise<CspmFinding[]> {
  const conditions: any[] = [eq(cspmFindings.orgId, orgId)];
  if (scanId) conditions.push(eq(cspmFindings.scanId, scanId));
  if (severity) conditions.push(eq(cspmFindings.severity, severity));
  return db
    .select()
    .from(cspmFindings)
    .where(and(...conditions))
    .orderBy(desc(cspmFindings.detectedAt));
}

export async function createCspmFinding(finding: InsertCspmFinding): Promise<CspmFinding> {
  const [created] = await db.insert(cspmFindings).values(finding).returning();
  return created;
}

export async function updateCspmFinding(id: string, updates: Partial<CspmFinding>): Promise<CspmFinding | null> {
  const [updated] = await db.update(cspmFindings).set(updates).where(eq(cspmFindings.id, id)).returning();
  return updated || null;
}

// CSPM Drift Detection

export async function getCspmDriftBaselines(orgId: string, accountId?: string): Promise<CspmDriftBaseline[]> {
  const conditions = [eq(cspmDriftBaselines.orgId, orgId)];
  if (accountId) conditions.push(eq(cspmDriftBaselines.accountId, accountId));
  return db
    .select()
    .from(cspmDriftBaselines)
    .where(and(...conditions))
    .orderBy(desc(cspmDriftBaselines.snapshotAt));
}

export async function createCspmDriftBaseline(baseline: InsertCspmDriftBaseline): Promise<CspmDriftBaseline> {
  const [created] = await db.insert(cspmDriftBaselines).values(baseline).returning();
  return created;
}

export async function deleteCspmDriftBaselines(orgId: string, accountId: string): Promise<void> {
  await db
    .delete(cspmDriftBaselines)
    .where(and(eq(cspmDriftBaselines.orgId, orgId), eq(cspmDriftBaselines.accountId, accountId)));
}

export async function getCspmDriftEvents(orgId: string, accountId?: string, status?: string): Promise<CspmDriftEvent[]> {
  const conditions: ReturnType<typeof eq>[] = [eq(cspmDriftEvents.orgId, orgId)];
  if (accountId) conditions.push(eq(cspmDriftEvents.accountId, accountId));
  if (status) conditions.push(eq(cspmDriftEvents.status, status));
  return db
    .select()
    .from(cspmDriftEvents)
    .where(and(...conditions))
    .orderBy(desc(cspmDriftEvents.detectedAt));
}

export async function createCspmDriftEvent(event: InsertCspmDriftEvent): Promise<CspmDriftEvent> {
  const [created] = await db.insert(cspmDriftEvents).values(event).returning();
  return created;
}

export async function updateCspmDriftEvent(id: string, updates: Partial<CspmDriftEvent>): Promise<CspmDriftEvent | null> {
  const [updated] = await db.update(cspmDriftEvents).set(updates).where(eq(cspmDriftEvents.id, id)).returning();
  return updated || null;
}

// CSPM DSPM

export async function getCspmDspmFindings(orgId: string, accountId?: string, sensitivityLevel?: string): Promise<CspmDspmFinding[]> {
  const conditions: ReturnType<typeof eq>[] = [eq(cspmDspmFindings.orgId, orgId)];
  if (accountId) conditions.push(eq(cspmDspmFindings.accountId, accountId));
  if (sensitivityLevel) conditions.push(eq(cspmDspmFindings.sensitivityLevel, sensitivityLevel));
  return db
    .select()
    .from(cspmDspmFindings)
    .where(and(...conditions))
    .orderBy(desc(cspmDspmFindings.detectedAt));
}

export async function createCspmDspmFinding(finding: InsertCspmDspmFinding): Promise<CspmDspmFinding> {
  const [created] = await db.insert(cspmDspmFindings).values(finding).returning();
  return created;
}

export async function updateCspmDspmFinding(id: string, updates: Partial<CspmDspmFinding>): Promise<CspmDspmFinding | null> {
  const [updated] = await db.update(cspmDspmFindings).set(updates).where(eq(cspmDspmFindings.id, id)).returning();
  return updated || null;
}

// CSPM Attack Paths

export async function getCspmAttackPaths(orgId: string, severity?: string): Promise<CspmAttackPath[]> {
  const conditions: ReturnType<typeof eq>[] = [eq(cspmAttackPaths.orgId, orgId)];
  if (severity) conditions.push(eq(cspmAttackPaths.severity, severity));
  return db
    .select()
    .from(cspmAttackPaths)
    .where(and(...conditions))
    .orderBy(desc(cspmAttackPaths.detectedAt));
}

export async function createCspmAttackPath(path: InsertCspmAttackPath): Promise<CspmAttackPath> {
  const [created] = await db.insert(cspmAttackPaths).values(path).returning();
  return created;
}

export async function updateCspmAttackPath(id: string, updates: Partial<CspmAttackPath>): Promise<CspmAttackPath | null> {
  const [updated] = await db.update(cspmAttackPaths).set(updates).where(eq(cspmAttackPaths.id, id)).returning();
  return updated || null;
}

// CSPM Remediations

export async function getCspmRemediations(orgId: string, accountId?: string, status?: string): Promise<CspmRemediation[]> {
  const conditions: ReturnType<typeof eq>[] = [eq(cspmRemediations.orgId, orgId)];
  if (accountId) conditions.push(eq(cspmRemediations.accountId, accountId));
  if (status) conditions.push(eq(cspmRemediations.status, status));
  return db
    .select()
    .from(cspmRemediations)
    .where(and(...conditions))
    .orderBy(desc(cspmRemediations.executedAt));
}

export async function getCspmRemediation(id: string): Promise<CspmRemediation | undefined> {
  const [remediation] = await db.select().from(cspmRemediations).where(eq(cspmRemediations.id, id));
  return remediation;
}

export async function createCspmRemediation(remediation: InsertCspmRemediation): Promise<CspmRemediation> {
  const [created] = await db.insert(cspmRemediations).values(remediation).returning();
  return created;
}

export async function updateCspmRemediation(id: string, updates: Partial<CspmRemediation>): Promise<CspmRemediation | null> {
  const [updated] = await db.update(cspmRemediations).set(updates).where(eq(cspmRemediations.id, id)).returning();
  return updated || null;
}
