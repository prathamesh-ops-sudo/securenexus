import {
  type AnomalySubscription,
  type AttackSurfaceAsset,
  type ForecastQualitySnapshot,
  type HardeningRecommendation,
  type InsertAnomalySubscription,
  type InsertAttackSurfaceAsset,
  type InsertForecastQualitySnapshot,
  type InsertHardeningRecommendation,
  type InsertPredictiveAnomaly,
  type InsertRiskForecast,
  type PredictiveAnomaly,
  type RiskForecast,
  anomalySubscriptions,
  attackSurfaceAssets,
  forecastQualitySnapshots,
  hardeningRecommendations,
  predictiveAnomalies,
  riskForecasts,
} from "@shared/schema";
import { db } from "../db";
import { and, desc, eq } from "drizzle-orm";

export async function getPredictiveAnomalies(orgId?: string): Promise<PredictiveAnomaly[]> {
  if (orgId) {
    return db
      .select()
      .from(predictiveAnomalies)
      .where(eq(predictiveAnomalies.orgId, orgId))
      .orderBy(desc(predictiveAnomalies.createdAt));
  }
  return db.select().from(predictiveAnomalies).orderBy(desc(predictiveAnomalies.createdAt));
}

export async function createPredictiveAnomaly(anomaly: InsertPredictiveAnomaly): Promise<PredictiveAnomaly> {
  const [created] = await db.insert(predictiveAnomalies).values(anomaly).returning();
  return created;
}

export async function clearPredictiveAnomalies(orgId: string): Promise<void> {
  await db.delete(predictiveAnomalies).where(eq(predictiveAnomalies.orgId, orgId));
}

export async function getAttackSurfaceAssets(orgId?: string): Promise<AttackSurfaceAsset[]> {
  if (orgId) {
    return db
      .select()
      .from(attackSurfaceAssets)
      .where(eq(attackSurfaceAssets.orgId, orgId))
      .orderBy(desc(attackSurfaceAssets.riskScore));
  }
  return db.select().from(attackSurfaceAssets).orderBy(desc(attackSurfaceAssets.riskScore));
}

export async function upsertAttackSurfaceAsset(asset: InsertAttackSurfaceAsset): Promise<AttackSurfaceAsset> {
  const conditions = [
    eq(attackSurfaceAssets.entityType, asset.entityType),
    eq(attackSurfaceAssets.entityValue, asset.entityValue),
  ];
  if (asset.orgId) conditions.push(eq(attackSurfaceAssets.orgId, asset.orgId));
  const [existing] = await db
    .select()
    .from(attackSurfaceAssets)
    .where(and(...conditions));
  if (existing) {
    const [updated] = await db
      .update(attackSurfaceAssets)
      .set({
        ...asset,
        updatedAt: new Date(),
      })
      .where(eq(attackSurfaceAssets.id, existing.id))
      .returning();
    return updated;
  }
  const [created] = await db.insert(attackSurfaceAssets).values(asset).returning();
  return created;
}

export async function clearAttackSurfaceAssets(orgId: string): Promise<void> {
  await db.delete(attackSurfaceAssets).where(eq(attackSurfaceAssets.orgId, orgId));
}

export async function getRiskForecasts(orgId?: string): Promise<RiskForecast[]> {
  if (orgId) {
    return db
      .select()
      .from(riskForecasts)
      .where(eq(riskForecasts.orgId, orgId))
      .orderBy(desc(riskForecasts.probability));
  }
  return db.select().from(riskForecasts).orderBy(desc(riskForecasts.probability));
}

export async function createRiskForecast(forecast: InsertRiskForecast): Promise<RiskForecast> {
  const [created] = await db.insert(riskForecasts).values(forecast).returning();
  return created;
}

export async function clearRiskForecasts(orgId: string): Promise<void> {
  await db.delete(riskForecasts).where(eq(riskForecasts.orgId, orgId));
}

export async function getAnomalySubscriptions(orgId?: string): Promise<AnomalySubscription[]> {
  if (orgId) {
    return db
      .select()
      .from(anomalySubscriptions)
      .where(eq(anomalySubscriptions.orgId, orgId))
      .orderBy(desc(anomalySubscriptions.createdAt));
  }
  return db.select().from(anomalySubscriptions).orderBy(desc(anomalySubscriptions.createdAt));
}

export async function createAnomalySubscription(subscription: InsertAnomalySubscription): Promise<AnomalySubscription> {
  const [created] = await db.insert(anomalySubscriptions).values(subscription).returning();
  return created;
}

export async function updateAnomalySubscription(
  id: string,
  updates: Partial<AnomalySubscription>,
): Promise<AnomalySubscription | undefined> {
  const [updated] = await db
    .update(anomalySubscriptions)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(anomalySubscriptions.id, id))
    .returning();
  return updated;
}

export async function deleteAnomalySubscription(id: string): Promise<boolean> {
  const result = await db.delete(anomalySubscriptions).where(eq(anomalySubscriptions.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getForecastQualitySnapshots(orgId?: string): Promise<ForecastQualitySnapshot[]> {
  if (orgId) {
    return db
      .select()
      .from(forecastQualitySnapshots)
      .where(eq(forecastQualitySnapshots.orgId, orgId))
      .orderBy(desc(forecastQualitySnapshots.measuredAt));
  }
  return db.select().from(forecastQualitySnapshots).orderBy(desc(forecastQualitySnapshots.measuredAt));
}

export async function createForecastQualitySnapshot(snapshot: InsertForecastQualitySnapshot): Promise<ForecastQualitySnapshot> {
  const [created] = await db.insert(forecastQualitySnapshots).values(snapshot).returning();
  return created;
}

export async function getHardeningRecommendations(orgId?: string): Promise<HardeningRecommendation[]> {
  if (orgId) {
    return db
      .select()
      .from(hardeningRecommendations)
      .where(eq(hardeningRecommendations.orgId, orgId))
      .orderBy(desc(hardeningRecommendations.createdAt));
  }
  return db.select().from(hardeningRecommendations).orderBy(desc(hardeningRecommendations.createdAt));
}

export async function createHardeningRecommendation(rec: InsertHardeningRecommendation): Promise<HardeningRecommendation> {
  const [created] = await db.insert(hardeningRecommendations).values(rec).returning();
  return created;
}

export async function updateHardeningRecommendation(
  id: string,
  updates: Partial<InsertHardeningRecommendation>,
): Promise<HardeningRecommendation | undefined> {
  const [updated] = await db
    .update(hardeningRecommendations)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(hardeningRecommendations.id, id))
    .returning();
  return updated;
}

export async function clearHardeningRecommendations(orgId: string): Promise<void> {
  await db.delete(hardeningRecommendations).where(eq(hardeningRecommendations.orgId, orgId));
}
