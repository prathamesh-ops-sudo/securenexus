import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  dnsSecurityEvents,
  dnsSecurityPolicies,
  type DnsSecurityEvent,
  type InsertDnsSecurityEvent,
  type DnsSecurityPolicy,
  type InsertDnsSecurityPolicy,
} from "@shared/schema";

// ─── Events ──────────────────────────────────────────────────────────────────
export async function getDnsSecurityEvents(orgId: string): Promise<DnsSecurityEvent[]> {
  return db
    .select()
    .from(dnsSecurityEvents)
    .where(eq(dnsSecurityEvents.orgId, orgId))
    .orderBy(desc(dnsSecurityEvents.createdAt));
}

export async function getDnsSecurityEvent(id: string): Promise<DnsSecurityEvent | undefined> {
  const [event] = await db.select().from(dnsSecurityEvents).where(eq(dnsSecurityEvents.id, id));
  return event;
}

export async function createDnsSecurityEvent(data: InsertDnsSecurityEvent): Promise<DnsSecurityEvent> {
  const [created] = await db.insert(dnsSecurityEvents).values(data).returning();
  return created;
}

// ─── Policies ────────────────────────────────────────────────────────────────
export async function getDnsSecurityPolicies(orgId: string): Promise<DnsSecurityPolicy[]> {
  return db
    .select()
    .from(dnsSecurityPolicies)
    .where(eq(dnsSecurityPolicies.orgId, orgId))
    .orderBy(desc(dnsSecurityPolicies.createdAt));
}

export async function getDnsSecurityPolicy(id: string): Promise<DnsSecurityPolicy | undefined> {
  const [policy] = await db.select().from(dnsSecurityPolicies).where(eq(dnsSecurityPolicies.id, id));
  return policy;
}

export async function createDnsSecurityPolicy(data: InsertDnsSecurityPolicy): Promise<DnsSecurityPolicy> {
  const [created] = await db.insert(dnsSecurityPolicies).values(data).returning();
  return created;
}

export async function updateDnsSecurityPolicy(
  id: string,
  data: Partial<DnsSecurityPolicy>,
): Promise<DnsSecurityPolicy | undefined> {
  const [updated] = await db
    .update(dnsSecurityPolicies)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(dnsSecurityPolicies.id, id))
    .returning();
  return updated;
}

export async function deleteDnsSecurityPolicy(id: string): Promise<void> {
  await db.delete(dnsSecurityPolicies).where(eq(dnsSecurityPolicies.id, id));
}
