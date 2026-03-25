import {
  type InsertIocEntry,
  type InsertIocFeed,
  type InsertIocMatch,
  type InsertIocMatchRule,
  type InsertIocWatchlist,
  type InsertIocWatchlistEntry,
  type IocEntry,
  type IocFeed,
  type IocMatch,
  type IocMatchRule,
  type IocWatchlist,
  type IocWatchlistEntry,
  iocEntries,
  iocFeeds,
  iocMatchRules,
  iocMatches,
  iocWatchlistEntries,
  iocWatchlists,
} from "@shared/schema";
import { db } from "../db";
import { and, desc, eq } from "drizzle-orm";

export async function getIocFeeds(orgId?: string): Promise<IocFeed[]> {
  if (orgId) {
    return db.select().from(iocFeeds).where(eq(iocFeeds.orgId, orgId)).orderBy(desc(iocFeeds.createdAt));
  }
  return db.select().from(iocFeeds).orderBy(desc(iocFeeds.createdAt));
}

export async function getIocFeed(id: string): Promise<IocFeed | undefined> {
  const [feed] = await db.select().from(iocFeeds).where(eq(iocFeeds.id, id)).limit(1);
  return feed;
}

export async function createIocFeed(feed: InsertIocFeed): Promise<IocFeed> {
  const [created] = await db.insert(iocFeeds).values(feed).returning();
  return created;
}

export async function updateIocFeed(id: string, data: Partial<IocFeed>): Promise<IocFeed | undefined> {
  const [updated] = await db
    .update(iocFeeds)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(iocFeeds.id, id))
    .returning();
  return updated;
}

export async function deleteIocFeed(id: string): Promise<boolean> {
  const result = await db.delete(iocFeeds).where(eq(iocFeeds.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getIocEntries(
  orgId?: string,
  feedId?: string,
  iocType?: string,
  status?: string,
  limit?: number,
): Promise<IocEntry[]> {
  const conditions: any[] = [];
  if (orgId) conditions.push(eq(iocEntries.orgId, orgId));
  if (feedId) conditions.push(eq(iocEntries.feedId, feedId));
  if (iocType) conditions.push(eq(iocEntries.iocType, iocType));
  if (status) conditions.push(eq(iocEntries.status, status));
  const query = db.select().from(iocEntries);
  if (conditions.length > 0) {
    return query
      .where(and(...conditions))
      .limit(limit || 500)
      .orderBy(desc(iocEntries.createdAt));
  }
  return query.limit(limit || 500).orderBy(desc(iocEntries.createdAt));
}

export async function getIocEntry(id: string): Promise<IocEntry | undefined> {
  const [entry] = await db.select().from(iocEntries).where(eq(iocEntries.id, id)).limit(1);
  return entry;
}

export async function getIocEntriesByValue(iocType: string, iocValue: string, orgId?: string): Promise<IocEntry[]> {
  const conditions: any[] = [eq(iocEntries.iocType, iocType), eq(iocEntries.iocValue, iocValue.toLowerCase())];
  if (orgId) conditions.push(eq(iocEntries.orgId, orgId));
  return db
    .select()
    .from(iocEntries)
    .where(and(...conditions));
}

export async function createIocEntry(entry: InsertIocEntry): Promise<IocEntry> {
  const [created] = await db.insert(iocEntries).values(entry).returning();
  return created;
}

export async function createIocEntries(entries: InsertIocEntry[]): Promise<IocEntry[]> {
  if (entries.length === 0) return [];
  return db.insert(iocEntries).values(entries).returning();
}

export async function updateIocEntry(id: string, data: Partial<IocEntry>): Promise<IocEntry | undefined> {
  const [updated] = await db.update(iocEntries).set(data).where(eq(iocEntries.id, id)).returning();
  return updated;
}

export async function deleteIocEntry(id: string): Promise<boolean> {
  const result = await db.delete(iocEntries).where(eq(iocEntries.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getIocWatchlists(orgId?: string): Promise<IocWatchlist[]> {
  if (orgId) {
    return db
      .select()
      .from(iocWatchlists)
      .where(eq(iocWatchlists.orgId, orgId))
      .orderBy(desc(iocWatchlists.createdAt));
  }
  return db.select().from(iocWatchlists).orderBy(desc(iocWatchlists.createdAt));
}

export async function getIocWatchlist(id: string): Promise<IocWatchlist | undefined> {
  const [watchlist] = await db.select().from(iocWatchlists).where(eq(iocWatchlists.id, id)).limit(1);
  return watchlist;
}

export async function createIocWatchlist(watchlist: InsertIocWatchlist): Promise<IocWatchlist> {
  const [created] = await db.insert(iocWatchlists).values(watchlist).returning();
  return created;
}

export async function updateIocWatchlist(id: string, data: Partial<IocWatchlist>): Promise<IocWatchlist | undefined> {
  const [updated] = await db
    .update(iocWatchlists)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(iocWatchlists.id, id))
    .returning();
  return updated;
}

export async function deleteIocWatchlist(id: string): Promise<boolean> {
  const result = await db.delete(iocWatchlists).where(eq(iocWatchlists.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function addIocToWatchlist(entry: InsertIocWatchlistEntry): Promise<IocWatchlistEntry> {
  const [created] = await db.insert(iocWatchlistEntries).values(entry).returning();
  return created;
}

export async function removeIocFromWatchlist(watchlistId: string, iocEntryId: string): Promise<boolean> {
  const result = await db
    .delete(iocWatchlistEntries)
    .where(and(eq(iocWatchlistEntries.watchlistId, watchlistId), eq(iocWatchlistEntries.iocEntryId, iocEntryId)));
  return (result.rowCount ?? 0) > 0;
}

export async function getWatchlistEntries(watchlistId: string): Promise<IocWatchlistEntry[]> {
  return db.select().from(iocWatchlistEntries).where(eq(iocWatchlistEntries.watchlistId, watchlistId));
}

export async function getIocMatchRules(orgId?: string): Promise<IocMatchRule[]> {
  if (orgId) {
    return db
      .select()
      .from(iocMatchRules)
      .where(eq(iocMatchRules.orgId, orgId))
      .orderBy(desc(iocMatchRules.createdAt));
  }
  return db.select().from(iocMatchRules).orderBy(desc(iocMatchRules.createdAt));
}

export async function getIocMatchRule(id: string): Promise<IocMatchRule | undefined> {
  const [rule] = await db.select().from(iocMatchRules).where(eq(iocMatchRules.id, id)).limit(1);
  return rule;
}

export async function createIocMatchRule(rule: InsertIocMatchRule): Promise<IocMatchRule> {
  const [created] = await db.insert(iocMatchRules).values(rule).returning();
  return created;
}

export async function updateIocMatchRule(id: string, data: Partial<IocMatchRule>): Promise<IocMatchRule | undefined> {
  const [updated] = await db
    .update(iocMatchRules)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(iocMatchRules.id, id))
    .returning();
  return updated;
}

export async function deleteIocMatchRule(id: string): Promise<boolean> {
  const result = await db.delete(iocMatchRules).where(eq(iocMatchRules.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getIocMatches(orgId?: string, alertId?: string, iocEntryId?: string, limit?: number): Promise<IocMatch[]> {
  const conditions: any[] = [];
  if (orgId) conditions.push(eq(iocMatches.orgId, orgId));
  if (alertId) conditions.push(eq(iocMatches.alertId, alertId));
  if (iocEntryId) conditions.push(eq(iocMatches.iocEntryId, iocEntryId));
  const query = db.select().from(iocMatches);
  if (conditions.length > 0) {
    return query
      .where(and(...conditions))
      .limit(limit || 200)
      .orderBy(desc(iocMatches.createdAt));
  }
  return query.limit(limit || 200).orderBy(desc(iocMatches.createdAt));
}

export async function createIocMatch(match: InsertIocMatch): Promise<IocMatch> {
  const [created] = await db.insert(iocMatches).values(match).returning();
  return created;
}
