import {
  type DnsEvent,
  type InsertDnsEvent,
  type DnsFinding,
  type InsertDnsFinding,
  type PassiveDnsRecord,
  type InsertPassiveDnsRecord,
  dnsEvents,
  dnsFindings,
  passiveDnsRecords,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq } from "drizzle-orm";

// ── DNS Events ──

export async function getDnsEvents(orgId: string, limit = 100, offset = 0): Promise<DnsEvent[]> {
  return db
    .select()
    .from(dnsEvents)
    .where(eq(dnsEvents.orgId, orgId))
    .orderBy(desc(dnsEvents.timestamp))
    .limit(limit)
    .offset(offset);
}

export async function createDnsEvent(event: InsertDnsEvent): Promise<DnsEvent> {
  const [created] = await db.insert(dnsEvents).values(event).returning();
  return created;
}

export async function countDnsEvents(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(dnsEvents).where(eq(dnsEvents.orgId, orgId));
  return row?.total ?? 0;
}

export async function countSuspiciousDnsEvents(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(dnsEvents)
    .where(and(eq(dnsEvents.orgId, orgId), eq(dnsEvents.isSuspicious, true)));
  return row?.total ?? 0;
}

// ── DNS Findings ──

export async function getDnsFindings(orgId: string, limit = 100): Promise<DnsFinding[]> {
  return db
    .select()
    .from(dnsFindings)
    .where(eq(dnsFindings.orgId, orgId))
    .orderBy(desc(dnsFindings.createdAt))
    .limit(limit);
}

export async function getDnsFinding(id: string): Promise<DnsFinding | undefined> {
  const [finding] = await db.select().from(dnsFindings).where(eq(dnsFindings.id, id));
  return finding;
}

export async function createDnsFinding(finding: InsertDnsFinding): Promise<DnsFinding> {
  const [created] = await db.insert(dnsFindings).values(finding).returning();
  return created;
}

export async function updateDnsFinding(
  id: string,
  updates: Partial<InsertDnsFinding>,
): Promise<DnsFinding | undefined> {
  const [updated] = await db.update(dnsFindings).set(updates).where(eq(dnsFindings.id, id)).returning();
  return updated;
}

export async function countDnsFindings(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(dnsFindings).where(eq(dnsFindings.orgId, orgId));
  return row?.total ?? 0;
}

export async function countDnsFindingsByStatus(orgId: string, status: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(dnsFindings)
    .where(and(eq(dnsFindings.orgId, orgId), eq(dnsFindings.status, status)));
  return row?.total ?? 0;
}

// ── Passive DNS Records ──

export async function getPassiveDnsRecords(orgId: string, limit = 100): Promise<PassiveDnsRecord[]> {
  return db
    .select()
    .from(passiveDnsRecords)
    .where(eq(passiveDnsRecords.orgId, orgId))
    .orderBy(desc(passiveDnsRecords.lastSeen))
    .limit(limit);
}

export async function getPassiveDnsRecordsByDomain(orgId: string, domain: string): Promise<PassiveDnsRecord[]> {
  return db
    .select()
    .from(passiveDnsRecords)
    .where(and(eq(passiveDnsRecords.orgId, orgId), eq(passiveDnsRecords.domain, domain)));
}

export async function createPassiveDnsRecord(record: InsertPassiveDnsRecord): Promise<PassiveDnsRecord> {
  const [created] = await db.insert(passiveDnsRecords).values(record).returning();
  return created;
}

export async function countPassiveDnsRecords(orgId: string): Promise<number> {
  const [row] = await db.select({ total: count() }).from(passiveDnsRecords).where(eq(passiveDnsRecords.orgId, orgId));
  return row?.total ?? 0;
}
