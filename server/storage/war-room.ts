import {
  type InsertWarRoom,
  type InsertWarRoomActionItem,
  type InsertWarRoomHandoff,
  type InsertWarRoomMessage,
  type InsertWarRoomParticipant,
  type WarRoom as WarRoomRow,
  type WarRoomActionItem,
  type WarRoomHandoff,
  type WarRoomMessage,
  type WarRoomParticipant,
  warRoomActionItems,
  warRoomHandoffs,
  warRoomMessages,
  warRoomParticipants,
  warRooms,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, desc, eq, isNull } from "drizzle-orm";

export async function createWarRoom(room: InsertWarRoom): Promise<WarRoomRow> {
  const [created] = await db.insert(warRooms).values(room).returning();
  return created;
}

export async function getWarRooms(orgId: string, status?: string): Promise<WarRoomRow[]> {
  const conditions = [eq(warRooms.orgId, orgId)];
  if (status) conditions.push(eq(warRooms.status, status));
  return db
    .select()
    .from(warRooms)
    .where(and(...conditions))
    .orderBy(desc(warRooms.createdAt));
}

export async function getWarRoom(id: string): Promise<WarRoomRow | undefined> {
  const [room] = await db.select().from(warRooms).where(eq(warRooms.id, id));
  return room;
}

export async function updateWarRoom(id: string, data: Partial<WarRoomRow>): Promise<WarRoomRow | undefined> {
  const [updated] = await db
    .update(warRooms)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(warRooms.id, id))
    .returning();
  return updated;
}

// ─── War Room Participants ──────────────────────────────────────────────────

export async function addWarRoomParticipant(participant: InsertWarRoomParticipant): Promise<WarRoomParticipant> {
  const [created] = await db.insert(warRoomParticipants).values(participant).returning();
  return created;
}

export async function getWarRoomParticipants(warRoomId: string): Promise<WarRoomParticipant[]> {
  return db
    .select()
    .from(warRoomParticipants)
    .where(and(eq(warRoomParticipants.warRoomId, warRoomId), isNull(warRoomParticipants.leftAt)))
    .orderBy(asc(warRoomParticipants.joinedAt));
}

export async function getWarRoomParticipantByUser(warRoomId: string, userId: string): Promise<WarRoomParticipant | undefined> {
  const [p] = await db
    .select()
    .from(warRoomParticipants)
    .where(
      and(
        eq(warRoomParticipants.warRoomId, warRoomId),
        eq(warRoomParticipants.userId, userId),
        isNull(warRoomParticipants.leftAt),
      ),
    );
  return p;
}

export async function removeWarRoomParticipant(warRoomId: string, userId: string): Promise<void> {
  await db
    .update(warRoomParticipants)
    .set({ leftAt: new Date() })
    .where(
      and(
        eq(warRoomParticipants.warRoomId, warRoomId),
        eq(warRoomParticipants.userId, userId),
        isNull(warRoomParticipants.leftAt),
      ),
    );
}

// ─── War Room Messages (Timeline) ──────────────────────────────────────────

export async function createWarRoomMessage(msg: InsertWarRoomMessage): Promise<WarRoomMessage> {
  const [created] = await db.insert(warRoomMessages).values(msg).returning();
  return created;
}

export async function getWarRoomMessages(warRoomId: string, limit = 500): Promise<WarRoomMessage[]> {
  return db
    .select()
    .from(warRoomMessages)
    .where(eq(warRoomMessages.warRoomId, warRoomId))
    .orderBy(asc(warRoomMessages.createdAt))
    .limit(limit);
}

export async function getWarRoomMessagesByType(warRoomId: string, type: string): Promise<WarRoomMessage[]> {
  return db
    .select()
    .from(warRoomMessages)
    .where(and(eq(warRoomMessages.warRoomId, warRoomId), eq(warRoomMessages.type, type)))
    .orderBy(asc(warRoomMessages.createdAt));
}

// ─── War Room Action Items ────────────────────────────────────────────────

export async function createWarRoomActionItem(item: InsertWarRoomActionItem): Promise<WarRoomActionItem> {
  const [created] = await db.insert(warRoomActionItems).values(item).returning();
  return created;
}

export async function getWarRoomActionItems(warRoomId: string): Promise<WarRoomActionItem[]> {
  return db
    .select()
    .from(warRoomActionItems)
    .where(eq(warRoomActionItems.warRoomId, warRoomId))
    .orderBy(desc(warRoomActionItems.createdAt));
}

export async function getWarRoomActionItem(id: string): Promise<WarRoomActionItem | undefined> {
  const [item] = await db.select().from(warRoomActionItems).where(eq(warRoomActionItems.id, id));
  return item;
}

export async function updateWarRoomActionItem(id: string, data: Partial<WarRoomActionItem>): Promise<WarRoomActionItem | undefined> {
  const [updated] = await db.update(warRoomActionItems).set(data).where(eq(warRoomActionItems.id, id)).returning();
  return updated;
}

// ─── War Room Handoffs ────────────────────────────────────────────────────

export async function createWarRoomHandoff(handoff: InsertWarRoomHandoff): Promise<WarRoomHandoff> {
  const [created] = await db.insert(warRoomHandoffs).values(handoff).returning();
  return created;
}

export async function getWarRoomHandoffs(warRoomId: string): Promise<WarRoomHandoff[]> {
  return db
    .select()
    .from(warRoomHandoffs)
    .where(eq(warRoomHandoffs.warRoomId, warRoomId))
    .orderBy(desc(warRoomHandoffs.createdAt));
}

export async function getWarRoomHandoff(id: string): Promise<WarRoomHandoff | undefined> {
  const [h] = await db.select().from(warRoomHandoffs).where(eq(warRoomHandoffs.id, id));
  return h;
}

export async function updateWarRoomHandoff(id: string, data: Partial<WarRoomHandoff>): Promise<WarRoomHandoff | undefined> {
  const [updated] = await db.update(warRoomHandoffs).set(data).where(eq(warRoomHandoffs.id, id)).returning();
  return updated;
}
}

export const storage = new DatabaseStorage();
