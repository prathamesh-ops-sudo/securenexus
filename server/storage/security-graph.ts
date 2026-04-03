import {
  type SecurityGraphAsset,
  type InsertSecurityGraphAsset,
  type SecurityGraphRelationship,
  type InsertSecurityGraphRelationship,
  securityGraphAssets,
  securityGraphRelationships,
} from "@shared/schema";
import { db } from "../db";
import { and, count, desc, eq, gte, lte, inArray } from "drizzle-orm";

// ── Assets ──

export async function getSecurityGraphAssets(orgId: string): Promise<SecurityGraphAsset[]> {
  return db
    .select()
    .from(securityGraphAssets)
    .where(eq(securityGraphAssets.orgId, orgId))
    .orderBy(desc(securityGraphAssets.createdAt));
}

export async function getSecurityGraphAssetsByType(orgId: string, type: string): Promise<SecurityGraphAsset[]> {
  return db
    .select()
    .from(securityGraphAssets)
    .where(and(eq(securityGraphAssets.orgId, orgId), eq(securityGraphAssets.type, type)))
    .orderBy(desc(securityGraphAssets.createdAt));
}

export async function getSecurityGraphAsset(id: string, orgId: string): Promise<SecurityGraphAsset | undefined> {
  const [asset] = await db
    .select()
    .from(securityGraphAssets)
    .where(and(eq(securityGraphAssets.id, id), eq(securityGraphAssets.orgId, orgId)));
  return asset;
}

export async function getSecurityGraphAssetByResolutionKey(
  orgId: string,
  resolutionKey: string,
): Promise<SecurityGraphAsset | undefined> {
  const [asset] = await db
    .select()
    .from(securityGraphAssets)
    .where(and(eq(securityGraphAssets.orgId, orgId), eq(securityGraphAssets.resolutionKey, resolutionKey)));
  return asset;
}

export async function createSecurityGraphAsset(data: InsertSecurityGraphAsset): Promise<SecurityGraphAsset> {
  const [created] = await db.insert(securityGraphAssets).values(data).returning();
  return created;
}

export async function updateSecurityGraphAsset(
  id: string,
  orgId: string,
  updates: Partial<InsertSecurityGraphAsset>,
): Promise<SecurityGraphAsset | undefined> {
  const [updated] = await db
    .update(securityGraphAssets)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(securityGraphAssets.id, id), eq(securityGraphAssets.orgId, orgId)))
    .returning();
  return updated;
}

export async function deleteSecurityGraphAsset(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(securityGraphAssets)
    .where(and(eq(securityGraphAssets.id, id), eq(securityGraphAssets.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countSecurityGraphAssets(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(securityGraphAssets)
    .where(eq(securityGraphAssets.orgId, orgId));
  return row?.total ?? 0;
}

// ── Relationships ──

export async function getSecurityGraphRelationships(orgId: string): Promise<SecurityGraphRelationship[]> {
  return db
    .select()
    .from(securityGraphRelationships)
    .where(eq(securityGraphRelationships.orgId, orgId))
    .orderBy(desc(securityGraphRelationships.createdAt));
}

export async function getSecurityGraphRelationship(
  id: string,
  orgId: string,
): Promise<SecurityGraphRelationship | undefined> {
  const [rel] = await db
    .select()
    .from(securityGraphRelationships)
    .where(and(eq(securityGraphRelationships.id, id), eq(securityGraphRelationships.orgId, orgId)));
  return rel;
}

export async function getSecurityGraphRelationshipsByAsset(assetId: string): Promise<SecurityGraphRelationship[]> {
  const asSource = await db
    .select()
    .from(securityGraphRelationships)
    .where(eq(securityGraphRelationships.sourceId, assetId));
  const asTarget = await db
    .select()
    .from(securityGraphRelationships)
    .where(eq(securityGraphRelationships.targetId, assetId));
  return [...asSource, ...asTarget];
}

export async function createSecurityGraphRelationship(
  data: InsertSecurityGraphRelationship,
): Promise<SecurityGraphRelationship> {
  const [created] = await db.insert(securityGraphRelationships).values(data).returning();
  return created;
}

export async function deleteSecurityGraphRelationship(id: string, orgId: string): Promise<boolean> {
  const result = await db
    .delete(securityGraphRelationships)
    .where(and(eq(securityGraphRelationships.id, id), eq(securityGraphRelationships.orgId, orgId)));
  return (result.rowCount ?? 0) > 0;
}

export async function countSecurityGraphRelationships(orgId: string): Promise<number> {
  const [row] = await db
    .select({ total: count() })
    .from(securityGraphRelationships)
    .where(eq(securityGraphRelationships.orgId, orgId));
  return row?.total ?? 0;
}
