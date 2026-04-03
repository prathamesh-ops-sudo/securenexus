import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import { emailSecurityEvents, type EmailSecurityEvent, type InsertEmailSecurityEvent } from "@shared/schema";

export async function getEmailSecurityEvents(orgId: string): Promise<EmailSecurityEvent[]> {
  return db
    .select()
    .from(emailSecurityEvents)
    .where(eq(emailSecurityEvents.orgId, orgId))
    .orderBy(desc(emailSecurityEvents.createdAt));
}

export async function getEmailSecurityEventsByVerdict(orgId: string, verdict: string): Promise<EmailSecurityEvent[]> {
  return db
    .select()
    .from(emailSecurityEvents)
    .where(and(eq(emailSecurityEvents.orgId, orgId), eq(emailSecurityEvents.verdict, verdict)))
    .orderBy(desc(emailSecurityEvents.createdAt));
}

export async function getEmailSecurityEvent(id: string): Promise<EmailSecurityEvent | undefined> {
  const [event] = await db.select().from(emailSecurityEvents).where(eq(emailSecurityEvents.id, id));
  return event;
}

export async function createEmailSecurityEvent(data: InsertEmailSecurityEvent): Promise<EmailSecurityEvent> {
  const [created] = await db.insert(emailSecurityEvents).values(data).returning();
  return created;
}
