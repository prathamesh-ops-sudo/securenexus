import { db } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  apiSecurityEndpoints,
  apiSecurityThreats,
  type ApiSecurityEndpoint,
  type InsertApiSecurityEndpoint,
  type ApiSecurityThreat,
  type InsertApiSecurityThreat,
} from "@shared/schema";

// ─── Endpoints ───────────────────────────────────────────────────────────────
export async function getApiSecurityEndpoints(orgId: string): Promise<ApiSecurityEndpoint[]> {
  return db
    .select()
    .from(apiSecurityEndpoints)
    .where(eq(apiSecurityEndpoints.orgId, orgId))
    .orderBy(desc(apiSecurityEndpoints.createdAt));
}

export async function getApiSecurityEndpoint(id: string): Promise<ApiSecurityEndpoint | undefined> {
  const [endpoint] = await db.select().from(apiSecurityEndpoints).where(eq(apiSecurityEndpoints.id, id));
  return endpoint;
}

export async function createApiSecurityEndpoint(data: InsertApiSecurityEndpoint): Promise<ApiSecurityEndpoint> {
  const [created] = await db.insert(apiSecurityEndpoints).values(data).returning();
  return created;
}

export async function updateApiSecurityEndpoint(
  id: string,
  data: Partial<ApiSecurityEndpoint>,
): Promise<ApiSecurityEndpoint | undefined> {
  const [updated] = await db
    .update(apiSecurityEndpoints)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(apiSecurityEndpoints.id, id))
    .returning();
  return updated;
}

export async function deleteApiSecurityEndpoint(id: string): Promise<void> {
  await db.delete(apiSecurityEndpoints).where(eq(apiSecurityEndpoints.id, id));
}

// ─── Threats ─────────────────────────────────────────────────────────────────
export async function getApiSecurityThreats(orgId: string): Promise<ApiSecurityThreat[]> {
  return db
    .select()
    .from(apiSecurityThreats)
    .where(eq(apiSecurityThreats.orgId, orgId))
    .orderBy(desc(apiSecurityThreats.createdAt));
}

export async function getApiSecurityThreatsByEndpoint(orgId: string, endpointId: string): Promise<ApiSecurityThreat[]> {
  return db
    .select()
    .from(apiSecurityThreats)
    .where(and(eq(apiSecurityThreats.orgId, orgId), eq(apiSecurityThreats.endpointId, endpointId)))
    .orderBy(desc(apiSecurityThreats.createdAt));
}

export async function createApiSecurityThreat(data: InsertApiSecurityThreat): Promise<ApiSecurityThreat> {
  const [created] = await db.insert(apiSecurityThreats).values(data).returning();
  return created;
}
