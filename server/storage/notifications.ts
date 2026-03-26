import {
  type InsertNotificationChannel,
  type InsertNotificationDeliveryLog,
  type InsertNotificationUserPreferences,
  type NotificationChannel,
  type NotificationDeliveryLog,
  type NotificationUserPreferences,
  notificationChannels,
  notificationDeliveryLog,
  notificationUserPreferences,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq, isNull } from "drizzle-orm";

export async function getNotificationChannels(orgId?: string): Promise<NotificationChannel[]> {
  if (orgId) {
    return db
      .select()
      .from(notificationChannels)
      .where(eq(notificationChannels.orgId, orgId))
      .orderBy(desc(notificationChannels.createdAt));
  }
  return db.select().from(notificationChannels).orderBy(desc(notificationChannels.createdAt));
}

export async function getNotificationChannel(id: string): Promise<NotificationChannel | undefined> {
  const [channel] = await db.select().from(notificationChannels).where(eq(notificationChannels.id, id));
  return channel;
}

export async function createNotificationChannel(channel: InsertNotificationChannel): Promise<NotificationChannel> {
  const [created] = await db.insert(notificationChannels).values(channel).returning();
  return created;
}

export async function updateNotificationChannel(
  id: string,
  data: Partial<NotificationChannel>,
): Promise<NotificationChannel | undefined> {
  const [updated] = await db
    .update(notificationChannels)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(notificationChannels.id, id))
    .returning();
  return updated;
}

export async function deleteNotificationChannel(id: string): Promise<boolean> {
  const result = await db.delete(notificationChannels).where(eq(notificationChannels.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getNotificationUserPreferences(
  userId: string,
  orgId?: string | null,
): Promise<NotificationUserPreferences | undefined> {
  const conditions = [eq(notificationUserPreferences.userId, userId)];
  if (orgId != null) conditions.push(eq(notificationUserPreferences.orgId, orgId));
  else conditions.push(isNull(notificationUserPreferences.orgId));
  const [row] = await db
    .select()
    .from(notificationUserPreferences)
    .where(and(...conditions));
  return row;
}

export async function upsertNotificationUserPreferences(
  data: InsertNotificationUserPreferences,
): Promise<NotificationUserPreferences> {
  const existing = await getNotificationUserPreferences(data.userId, data.orgId ?? undefined);
  const updatePayload = {
    channelIds: data.channelIds,
    eventTypes: data.eventTypes,
    minSeverity: data.minSeverity,
    quietHoursStart: data.quietHoursStart,
    quietHoursEnd: data.quietHoursEnd,
    digestEnabled: data.digestEnabled,
    digestFrequencyHours: data.digestFrequencyHours,
    updatedAt: new Date(),
  };
  if (existing) {
    const [updated] = await db
      .update(notificationUserPreferences)
      .set(updatePayload)
      .where(eq(notificationUserPreferences.id, existing.id))
      .returning();
    return updated;
  }
  const [created] = await db
    .insert(notificationUserPreferences)
    .values({ ...data, updatedAt: new Date() })
    .returning();
  return created;
}

export async function createNotificationDeliveryLog(entry: InsertNotificationDeliveryLog): Promise<NotificationDeliveryLog> {
  const [created] = await db.insert(notificationDeliveryLog).values(entry).returning();
  return created;
}

export async function getNotificationDeliveryLog(params: {
  orgId?: string;
  channelId?: string;
  limit?: number;
  offset?: number;
}): Promise<{ items: NotificationDeliveryLog[]; total: number }> {
  const { orgId, channelId, limit = 50, offset = 0 } = params;
  const conditions = [];
  if (orgId) conditions.push(eq(notificationDeliveryLog.orgId, orgId));
  if (channelId) conditions.push(eq(notificationDeliveryLog.channelId, channelId));
  const condition = conditions.length > 0 ? and(...conditions) : undefined;
  const baseQuery = db.select().from(notificationDeliveryLog).where(condition);
  const [items, countResult] = await Promise.all([
    db
      .select()
      .from(notificationDeliveryLog)
      .where(condition)
      .orderBy(desc(notificationDeliveryLog.deliveredAt))
      .limit(Math.min(limit, 200))
      .offset(offset),
    condition
      ? db.select({ count: count() }).from(notificationDeliveryLog).where(condition)
      : db.select({ count: count() }).from(notificationDeliveryLog),
  ]);
  const total = Number(countResult[0]?.count ?? 0);
  return { items, total };
}
