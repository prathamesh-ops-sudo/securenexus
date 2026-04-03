import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  communityIntelFeeds,
  communityIntelIndicators,
  type CommunityIntelFeed,
  type InsertCommunityIntelFeed,
  type CommunityIntelIndicator,
  type InsertCommunityIntelIndicator,
} from "@shared/schema";

// ─── Feeds ───────────────────────────────────────────────────────────────────
export async function getCommunityIntelFeeds(orgId: string): Promise<CommunityIntelFeed[]> {
  return db
    .select()
    .from(communityIntelFeeds)
    .where(eq(communityIntelFeeds.orgId, orgId))
    .orderBy(desc(communityIntelFeeds.createdAt));
}

export async function getCommunityIntelFeed(id: string): Promise<CommunityIntelFeed | undefined> {
  const [feed] = await db.select().from(communityIntelFeeds).where(eq(communityIntelFeeds.id, id));
  return feed;
}

export async function createCommunityIntelFeed(data: InsertCommunityIntelFeed): Promise<CommunityIntelFeed> {
  const [created] = await db.insert(communityIntelFeeds).values(data).returning();
  return created;
}

export async function updateCommunityIntelFeed(
  id: string,
  data: Partial<CommunityIntelFeed>,
): Promise<CommunityIntelFeed | undefined> {
  const [updated] = await db
    .update(communityIntelFeeds)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(communityIntelFeeds.id, id))
    .returning();
  return updated;
}

export async function deleteCommunityIntelFeed(id: string): Promise<void> {
  await db.delete(communityIntelFeeds).where(eq(communityIntelFeeds.id, id));
}

// ─── Indicators ──────────────────────────────────────────────────────────────
export async function getCommunityIntelIndicators(orgId: string): Promise<CommunityIntelIndicator[]> {
  return db
    .select()
    .from(communityIntelIndicators)
    .where(eq(communityIntelIndicators.orgId, orgId))
    .orderBy(desc(communityIntelIndicators.createdAt));
}

export async function getCommunityIntelIndicatorsByFeed(
  orgId: string,
  feedId: string,
): Promise<CommunityIntelIndicator[]> {
  return db
    .select()
    .from(communityIntelIndicators)
    .where(and(eq(communityIntelIndicators.orgId, orgId), eq(communityIntelIndicators.feedId, feedId)))
    .orderBy(desc(communityIntelIndicators.createdAt));
}

export async function createCommunityIntelIndicator(
  data: InsertCommunityIntelIndicator,
): Promise<CommunityIntelIndicator> {
  const [created] = await db.insert(communityIntelIndicators).values(data).returning();
  return created;
}
