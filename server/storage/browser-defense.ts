import {
  type BrowserDefenseSession,
  type InsertBrowserDefenseSession,
  type BrowserEgressRule,
  type InsertBrowserEgressRule,
  type BrowserTrustedPath,
  type InsertBrowserTrustedPath,
  type BrowserDomEvent,
  type InsertBrowserDomEvent,
  type BrowserInjectionPattern,
  type InsertBrowserInjectionPattern,
  browserDefenseSessions,
  browserEgressRules,
  browserTrustedPaths,
  browserDomEvents,
  browserInjectionPatterns,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq, sql } from "drizzle-orm";

// ─── Sessions ────────────────────────────────────────────────────────────────

export async function getBrowserSessions(orgId: string, state?: string): Promise<BrowserDefenseSession[]> {
  const base = eq(browserDefenseSessions.orgId, orgId);
  const where = state ? and(base, eq(browserDefenseSessions.state, state)) : base;
  return db.select().from(browserDefenseSessions).where(where).orderBy(desc(browserDefenseSessions.createdAt));
}

export async function getBrowserSession(id: string, orgId: string): Promise<BrowserDefenseSession | undefined> {
  const [row] = await db
    .select()
    .from(browserDefenseSessions)
    .where(and(eq(browserDefenseSessions.id, id), eq(browserDefenseSessions.orgId, orgId)));
  return row;
}

export async function createBrowserSession(data: InsertBrowserDefenseSession): Promise<BrowserDefenseSession> {
  const [created] = await db.insert(browserDefenseSessions).values(data).returning();
  return created;
}

export async function updateBrowserSession(
  id: string,
  orgId: string,
  updates: Partial<InsertBrowserDefenseSession>,
): Promise<BrowserDefenseSession | undefined> {
  const [updated] = await db
    .update(browserDefenseSessions)
    .set(updates)
    .where(and(eq(browserDefenseSessions.id, id), eq(browserDefenseSessions.orgId, orgId)))
    .returning();
  return updated;
}

export async function countBrowserSessions(orgId: string, state?: string): Promise<number> {
  const base = eq(browserDefenseSessions.orgId, orgId);
  const where = state ? and(base, eq(browserDefenseSessions.state, state)) : base;
  const [row] = await db.select({ total: count() }).from(browserDefenseSessions).where(where);
  return row?.total ?? 0;
}

// ─── Egress Rules ────────────────────────────────────────────────────────────

export async function getBrowserEgressRules(orgId: string): Promise<BrowserEgressRule[]> {
  return db
    .select()
    .from(browserEgressRules)
    .where(eq(browserEgressRules.orgId, orgId))
    .orderBy(browserEgressRules.priority);
}

export async function getBrowserEgressRule(id: string, orgId: string): Promise<BrowserEgressRule | undefined> {
  const [row] = await db
    .select()
    .from(browserEgressRules)
    .where(and(eq(browserEgressRules.id, id), eq(browserEgressRules.orgId, orgId)));
  return row;
}

export async function createBrowserEgressRule(data: InsertBrowserEgressRule): Promise<BrowserEgressRule> {
  const [created] = await db.insert(browserEgressRules).values(data).returning();
  return created;
}

export async function updateBrowserEgressRule(
  id: string,
  orgId: string,
  updates: Partial<InsertBrowserEgressRule>,
): Promise<BrowserEgressRule | undefined> {
  const [updated] = await db
    .update(browserEgressRules)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(browserEgressRules.id, id), eq(browserEgressRules.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteBrowserEgressRule(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(browserEgressRules)
    .where(and(eq(browserEgressRules.id, id), eq(browserEgressRules.orgId, orgId)))
    .returning();
  return result.length > 0;
}

// ─── Trusted Paths ───────────────────────────────────────────────────────────

export async function getBrowserTrustedPaths(orgId: string): Promise<BrowserTrustedPath[]> {
  return db
    .select()
    .from(browserTrustedPaths)
    .where(eq(browserTrustedPaths.orgId, orgId))
    .orderBy(desc(browserTrustedPaths.createdAt));
}

export async function getBrowserTrustedPath(id: string, orgId: string): Promise<BrowserTrustedPath | undefined> {
  const [row] = await db
    .select()
    .from(browserTrustedPaths)
    .where(and(eq(browserTrustedPaths.id, id), eq(browserTrustedPaths.orgId, orgId)));
  return row;
}

export async function createBrowserTrustedPath(data: InsertBrowserTrustedPath): Promise<BrowserTrustedPath> {
  const [created] = await db.insert(browserTrustedPaths).values(data).returning();
  return created;
}

export async function updateBrowserTrustedPath(
  id: string,
  orgId: string,
  updates: Partial<InsertBrowserTrustedPath>,
): Promise<BrowserTrustedPath | undefined> {
  const [updated] = await db
    .update(browserTrustedPaths)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(browserTrustedPaths.id, id), eq(browserTrustedPaths.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteBrowserTrustedPath(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(browserTrustedPaths)
    .where(and(eq(browserTrustedPaths.id, id), eq(browserTrustedPaths.orgId, orgId)))
    .returning();
  return result.length > 0;
}

// ─── DOM Events ──────────────────────────────────────────────────────────────

export async function getBrowserDomEvents(
  orgId: string,
  filters?: { sessionId?: string; severity?: string; verdict?: string },
): Promise<BrowserDomEvent[]> {
  let where = eq(browserDomEvents.orgId, orgId);
  if (filters?.sessionId) {
    where = and(where, eq(browserDomEvents.sessionId, filters.sessionId))!;
  }
  if (filters?.severity) {
    where = and(where, eq(browserDomEvents.severity, filters.severity))!;
  }
  if (filters?.verdict) {
    where = and(where, eq(browserDomEvents.verdict, filters.verdict))!;
  }
  return db.select().from(browserDomEvents).where(where).orderBy(desc(browserDomEvents.createdAt)).limit(200);
}

export async function createBrowserDomEvent(data: InsertBrowserDomEvent): Promise<BrowserDomEvent> {
  const [created] = await db.insert(browserDomEvents).values(data).returning();
  return created;
}

// ─── Injection Patterns ──────────────────────────────────────────────────────

export async function getBrowserInjectionPatterns(orgId: string): Promise<BrowserInjectionPattern[]> {
  return db
    .select()
    .from(browserInjectionPatterns)
    .where(eq(browserInjectionPatterns.orgId, orgId))
    .orderBy(desc(browserInjectionPatterns.createdAt));
}

export async function getBrowserInjectionPattern(
  id: string,
  orgId: string,
): Promise<BrowserInjectionPattern | undefined> {
  const [row] = await db
    .select()
    .from(browserInjectionPatterns)
    .where(and(eq(browserInjectionPatterns.id, id), eq(browserInjectionPatterns.orgId, orgId)));
  return row;
}

export async function updateBrowserInjectionPattern(
  id: string,
  orgId: string,
  updates: Partial<InsertBrowserInjectionPattern>,
): Promise<BrowserInjectionPattern | undefined> {
  const [updated] = await db
    .update(browserInjectionPatterns)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(browserInjectionPatterns.id, id), eq(browserInjectionPatterns.orgId, orgId)))
    .returning();
  return updated;
}

export async function incrementInjectionPatternMatchCount(id: string, orgId: string): Promise<void> {
  await db
    .update(browserInjectionPatterns)
    .set({
      matchCount: sql`${browserInjectionPatterns.matchCount} + 1`,
      lastMatchedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(and(eq(browserInjectionPatterns.id, id), eq(browserInjectionPatterns.orgId, orgId)));
}
