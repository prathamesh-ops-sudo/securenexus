import {
  type Alert,
  type EndpointAsset,
  type EndpointTelemetry,
  type FeatureFlag,
  type IngestionLog,
  type InsertEndpointAsset,
  type InsertEndpointTelemetry,
  type InsertFeatureFlag,
  type InsertIngestionLog,
  type InsertIntegrationConfig,
  type InsertOutboundWebhook,
  type InsertOutboundWebhookLog,
  type InsertPostureScore,
  type InsertRunbookStep,
  type InsertRunbookTemplate,
  type InsertSavedView,
  type InsertSuppressionRule,
  type InsertTag,
  type InsertThreatIntelConfig,
  type IntegrationConfig,
  type OutboundWebhook,
  type OutboundWebhookLog,
  type PostureScore,
  type RunbookStep,
  type RunbookTemplate,
  type SavedView,
  type SuppressionRule,
  type Tag,
  type ThreatIntelConfig,
  endpointAssets,
  endpointTelemetry,
  featureFlags,
  ingestionLogs,
  integrationConfigs,
  outboundWebhookLogs,
  outboundWebhooks,
  postureScores,
  runbookSteps,
  runbookTemplates,
  savedViews,
  suppressionRules,
  tags,
  threatIntelConfigs,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, isNull, or, sql } from "drizzle-orm";

export async function getTags(): Promise<Tag[]> {
  return db.select().from(tags).orderBy(tags.name);
}

export async function createTag(tag: InsertTag): Promise<Tag> {
  const [created] = await db.insert(tags).values(tag).returning();
  return created;
}

export async function deleteTag(id: string): Promise<boolean> {
  const result = await db.delete(tags).where(eq(tags.id, id)).returning();
  return result.length > 0;
}

export async function createIngestionLog(log: InsertIngestionLog): Promise<IngestionLog> {
  const [created] = await db.insert(ingestionLogs).values(log).returning();
  return created;
}

export async function getIngestionLogs(orgId?: string, limit = 50): Promise<IngestionLog[]> {
  if (orgId) {
    return db
      .select()
      .from(ingestionLogs)
      .where(eq(ingestionLogs.orgId, orgId))
      .orderBy(desc(ingestionLogs.receivedAt))
      .limit(limit);
  }
  return db.select().from(ingestionLogs).orderBy(desc(ingestionLogs.receivedAt)).limit(limit);
}

export async function getIngestionLogsPaginated(params: {
  orgId?: string;
  offset: number;
  limit: number;
}): Promise<{ items: IngestionLog[]; total: number }> {
  const { orgId, offset, limit } = params;

  const whereCondition = orgId ? eq(ingestionLogs.orgId, orgId) : undefined;

  const totalQuery = db.select({ total: count() }).from(ingestionLogs);
  const itemsQuery = db
    .select()
    .from(ingestionLogs)
    .orderBy(desc(ingestionLogs.receivedAt))
    .limit(limit)
    .offset(offset);

  const [totalRow] = await (whereCondition ? totalQuery.where(whereCondition) : totalQuery);
  const items = await (whereCondition ? itemsQuery.where(whereCondition) : itemsQuery);

  return { items, total: Number(totalRow?.total ?? 0) };
}

export async function getIngestionStats(orgId?: string): Promise<{
  totalIngested: number;
  totalCreated: number;
  totalDeduped: number;
  totalFailed: number;
  sourceBreakdown: { source: string; count: number; lastReceived: Date | null }[];
}> {
  const conditions = orgId ? [eq(ingestionLogs.orgId, orgId)] : [];
  const condition = conditions.length ? conditions[0] : undefined;

  const [totals] = await db
    .select({
      totalIngested: sql<number>`COALESCE(SUM(${ingestionLogs.alertsReceived}), 0)::int`,
      totalCreated: sql<number>`COALESCE(SUM(${ingestionLogs.alertsCreated}), 0)::int`,
      totalDeduped: sql<number>`COALESCE(SUM(${ingestionLogs.alertsDeduped}), 0)::int`,
      totalFailed: sql<number>`COALESCE(SUM(${ingestionLogs.alertsFailed}), 0)::int`,
    })
    .from(ingestionLogs)
    .where(condition);

  const breakdown = await db
    .select({
      source: ingestionLogs.source,
      count: sql<number>`COUNT(*)::int`,
      lastReceived: sql<Date | null>`MAX(${ingestionLogs.receivedAt})`,
    })
    .from(ingestionLogs)
    .where(condition)
    .groupBy(ingestionLogs.source);

  return {
    totalIngested: totals?.totalIngested ?? 0,
    totalCreated: totals?.totalCreated ?? 0,
    totalDeduped: totals?.totalDeduped ?? 0,
    totalFailed: totals?.totalFailed ?? 0,
    sourceBreakdown: breakdown,
  };
}

export async function getThreatIntelConfigs(orgId: string): Promise<ThreatIntelConfig[]> {
  return db
    .select()
    .from(threatIntelConfigs)
    .where(eq(threatIntelConfigs.orgId, orgId))
    .orderBy(desc(threatIntelConfigs.createdAt));
}

export async function getThreatIntelConfig(orgId: string, provider: string): Promise<ThreatIntelConfig | undefined> {
  const [config] = await db
    .select()
    .from(threatIntelConfigs)
    .where(and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider)));
  return config;
}

export async function upsertThreatIntelConfig(config: InsertThreatIntelConfig): Promise<ThreatIntelConfig> {
  const [result] = await db
    .insert(threatIntelConfigs)
    .values(config)
    .onConflictDoUpdate({
      target: [threatIntelConfigs.orgId, threatIntelConfigs.provider],
      set: {
        apiKey: config.apiKey,
        enabled: config.enabled,
        updatedAt: new Date(),
      },
    })
    .returning();
  return result;
}

export async function deleteThreatIntelConfig(orgId: string, provider: string): Promise<void> {
  await db
    .delete(threatIntelConfigs)
    .where(and(eq(threatIntelConfigs.orgId, orgId), eq(threatIntelConfigs.provider, provider)));
}

export async function getIntegrationConfigs(orgId?: string): Promise<IntegrationConfig[]> {
  if (orgId) {
    return db
      .select()
      .from(integrationConfigs)
      .where(eq(integrationConfigs.orgId, orgId))
      .orderBy(desc(integrationConfigs.createdAt));
  }
  return db.select().from(integrationConfigs).orderBy(desc(integrationConfigs.createdAt));
}

export async function getIntegrationConfig(id: string): Promise<IntegrationConfig | undefined> {
  const [config] = await db.select().from(integrationConfigs).where(eq(integrationConfigs.id, id));
  return config;
}

export async function createIntegrationConfig(config: InsertIntegrationConfig): Promise<IntegrationConfig> {
  const [created] = await db.insert(integrationConfigs).values(config).returning();
  return created;
}

export async function updateIntegrationConfig(id: string, data: Partial<IntegrationConfig>): Promise<IntegrationConfig | undefined> {
  const [updated] = await db
    .update(integrationConfigs)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(integrationConfigs.id, id))
    .returning();
  return updated;
}

export async function deleteIntegrationConfig(id: string): Promise<boolean> {
  const result = await db.delete(integrationConfigs).where(eq(integrationConfigs.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getOutboundWebhooks(orgId: string): Promise<OutboundWebhook[]> {
  return db
    .select()
    .from(outboundWebhooks)
    .where(eq(outboundWebhooks.orgId, orgId))
    .orderBy(desc(outboundWebhooks.createdAt));
}

export async function getOutboundWebhook(id: string): Promise<OutboundWebhook | undefined> {
  const [webhook] = await db.select().from(outboundWebhooks).where(eq(outboundWebhooks.id, id));
  return webhook;
}

export async function createOutboundWebhook(webhook: InsertOutboundWebhook): Promise<OutboundWebhook> {
  const [created] = await db.insert(outboundWebhooks).values(webhook).returning();
  return created;
}

export async function updateOutboundWebhook(id: string, data: Partial<OutboundWebhook>): Promise<OutboundWebhook | undefined> {
  const [updated] = await db.update(outboundWebhooks).set(data).where(eq(outboundWebhooks.id, id)).returning();
  return updated;
}

export async function deleteOutboundWebhook(id: string): Promise<boolean> {
  const result = await db.delete(outboundWebhooks).where(eq(outboundWebhooks.id, id)).returning();
  return result.length > 0;
}

export async function getActiveWebhooksByEvent(orgId: string, event: string): Promise<OutboundWebhook[]> {
  return db
    .select()
    .from(outboundWebhooks)
    .where(
      and(
        eq(outboundWebhooks.orgId, orgId),
        eq(outboundWebhooks.isActive, true),
        sql`${event} = ANY(${outboundWebhooks.events})`,
      ),
    );
}

export async function getOutboundWebhookLogs(webhookId: string, limit?: number): Promise<OutboundWebhookLog[]> {
  return db
    .select()
    .from(outboundWebhookLogs)
    .where(eq(outboundWebhookLogs.webhookId, webhookId))
    .orderBy(desc(outboundWebhookLogs.deliveredAt))
    .limit(limit || 100);
}

export async function createOutboundWebhookLog(log: InsertOutboundWebhookLog): Promise<OutboundWebhookLog> {
  const [created] = await db.insert(outboundWebhookLogs).values(log).returning();
  return created;
}

export async function getSuppressionRules(orgId?: string): Promise<SuppressionRule[]> {
  if (orgId) {
    return db
      .select()
      .from(suppressionRules)
      .where(eq(suppressionRules.orgId, orgId))
      .orderBy(desc(suppressionRules.createdAt));
  }
  return db.select().from(suppressionRules).orderBy(desc(suppressionRules.createdAt));
}

export async function getSuppressionRule(id: string): Promise<SuppressionRule | undefined> {
  const [rule] = await db.select().from(suppressionRules).where(eq(suppressionRules.id, id));
  return rule;
}

export async function createSuppressionRule(rule: InsertSuppressionRule): Promise<SuppressionRule> {
  const [created] = await db.insert(suppressionRules).values(rule).returning();
  return created;
}

export async function updateSuppressionRule(id: string, data: Partial<SuppressionRule>): Promise<SuppressionRule | undefined> {
  const [updated] = await db
    .update(suppressionRules)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(suppressionRules.id, id))
    .returning();
  return updated;
}

export async function deleteSuppressionRule(id: string): Promise<boolean> {
  const [deleted] = await db.delete(suppressionRules).where(eq(suppressionRules.id, id)).returning();
  return !!deleted;
}

export async function getActiveSuppressionRules(orgId: string): Promise<SuppressionRule[]> {
  return db
    .select()
    .from(suppressionRules)
    .where(
      and(
        eq(suppressionRules.orgId, orgId),
        eq(suppressionRules.enabled, true),
        or(isNull(suppressionRules.expiresAt), sql`${suppressionRules.expiresAt} > NOW()`),
      ),
    )
    .orderBy(desc(suppressionRules.createdAt));
}

export async function incrementSuppressionMatchCount(ruleId: string): Promise<void> {
  await db
    .update(suppressionRules)
    .set({
      matchCount: sql`COALESCE(${suppressionRules.matchCount}, 0) + 1`,
      lastMatchAt: new Date(),
    })
    .where(eq(suppressionRules.id, ruleId));
}

// Alert Dedup Clusters

export async function listFeatureFlags(): Promise<FeatureFlag[]> {
  return db.select().from(featureFlags).orderBy(desc(featureFlags.createdAt));
}

export async function getFeatureFlag(key: string): Promise<FeatureFlag | undefined> {
  const [flag] = await db.select().from(featureFlags).where(eq(featureFlags.key, key));
  return flag;
}

export async function getFeatureFlagById(id: string): Promise<FeatureFlag | undefined> {
  const [flag] = await db.select().from(featureFlags).where(eq(featureFlags.id, id));
  return flag;
}

export async function createFeatureFlag(flag: InsertFeatureFlag): Promise<FeatureFlag> {
  const [created] = await db.insert(featureFlags).values(flag).returning();
  return created;
}

export async function updateFeatureFlag(key: string, data: Partial<FeatureFlag>): Promise<FeatureFlag | undefined> {
  const [updated] = await db
    .update(featureFlags)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(featureFlags.key, key))
    .returning();
  return updated;
}

export async function deleteFeatureFlag(key: string): Promise<boolean> {
  const result = await db.delete(featureFlags).where(eq(featureFlags.key, key)).returning();
  return result.length > 0;
}

// Saved Views

export async function getSavedViews(orgId: string, resourceType?: string): Promise<SavedView[]> {
  const conditions = [eq(savedViews.orgId, orgId)];
  if (resourceType) conditions.push(eq(savedViews.resourceType, resourceType));
  return db
    .select()
    .from(savedViews)
    .where(and(...conditions))
    .orderBy(desc(savedViews.updatedAt));
}

export async function getSavedView(id: string): Promise<SavedView | undefined> {
  const [view] = await db.select().from(savedViews).where(eq(savedViews.id, id));
  return view;
}

export async function createSavedView(view: InsertSavedView): Promise<SavedView> {
  const [created] = await db.insert(savedViews).values(view).returning();
  return created;
}

export async function updateSavedView(id: string, data: Partial<SavedView>): Promise<SavedView | undefined> {
  const [updated] = await db
    .update(savedViews)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(savedViews.id, id))
    .returning();
  return updated;
}

export async function deleteSavedView(id: string): Promise<boolean> {
  const result = await db.delete(savedViews).where(eq(savedViews.id, id)).returning();
  return result.length > 0;
}

// Org Security Policies

export async function getRunbookTemplates(orgId?: string, incidentType?: string): Promise<RunbookTemplate[]> {
  const conditions: any[] = [];
  if (orgId) {
    conditions.push(or(eq(runbookTemplates.orgId, orgId), isNull(runbookTemplates.orgId)));
  }
  if (incidentType) {
    conditions.push(eq(runbookTemplates.incidentType, incidentType));
  }
  if (conditions.length > 0) {
    return db
      .select()
      .from(runbookTemplates)
      .where(and(...conditions))
      .orderBy(desc(runbookTemplates.createdAt));
  }
  return db.select().from(runbookTemplates).orderBy(desc(runbookTemplates.createdAt));
}

export async function getRunbookTemplate(id: string): Promise<RunbookTemplate | undefined> {
  const [template] = await db.select().from(runbookTemplates).where(eq(runbookTemplates.id, id));
  return template;
}

export async function createRunbookTemplate(template: InsertRunbookTemplate): Promise<RunbookTemplate> {
  const [created] = await db.insert(runbookTemplates).values(template).returning();
  return created;
}

export async function updateRunbookTemplate(id: string, data: Partial<RunbookTemplate>): Promise<RunbookTemplate | undefined> {
  const [updated] = await db
    .update(runbookTemplates)
    .set({ ...data, updatedAt: new Date() })
    .where(eq(runbookTemplates.id, id))
    .returning();
  return updated;
}

export async function deleteRunbookTemplate(id: string): Promise<boolean> {
  const result = await db.delete(runbookTemplates).where(eq(runbookTemplates.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getRunbookSteps(templateId: string): Promise<RunbookStep[]> {
  return db
    .select()
    .from(runbookSteps)
    .where(eq(runbookSteps.templateId, templateId))
    .orderBy(asc(runbookSteps.stepOrder));
}

export async function createRunbookStep(step: InsertRunbookStep): Promise<RunbookStep> {
  const [created] = await db.insert(runbookSteps).values(step).returning();
  return created;
}

export async function updateRunbookStep(id: string, data: Partial<RunbookStep>): Promise<RunbookStep | undefined> {
  const [updated] = await db.update(runbookSteps).set(data).where(eq(runbookSteps.id, id)).returning();
  return updated;
}

export async function deleteRunbookStep(id: string): Promise<boolean> {
  const result = await db.delete(runbookSteps).where(eq(runbookSteps.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getEndpointAssets(orgId: string): Promise<EndpointAsset[]> {
  return db
    .select()
    .from(endpointAssets)
    .where(eq(endpointAssets.orgId, orgId))
    .orderBy(desc(endpointAssets.createdAt));
}

export async function getEndpointAsset(id: string): Promise<EndpointAsset | undefined> {
  const [asset] = await db.select().from(endpointAssets).where(eq(endpointAssets.id, id));
  return asset;
}

export async function createEndpointAsset(asset: InsertEndpointAsset): Promise<EndpointAsset> {
  const [created] = await db.insert(endpointAssets).values(asset).returning();
  return created;
}

export async function updateEndpointAsset(id: string, updates: Partial<EndpointAsset>): Promise<EndpointAsset | null> {
  const [updated] = await db.update(endpointAssets).set(updates).where(eq(endpointAssets.id, id)).returning();
  return updated || null;
}

export async function deleteEndpointAsset(id: string): Promise<boolean> {
  const result = await db.delete(endpointAssets).where(eq(endpointAssets.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function getEndpointTelemetry(assetId: string): Promise<EndpointTelemetry[]> {
  return db
    .select()
    .from(endpointTelemetry)
    .where(eq(endpointTelemetry.assetId, assetId))
    .orderBy(desc(endpointTelemetry.collectedAt));
}

export async function createEndpointTelemetry(telemetry: InsertEndpointTelemetry): Promise<EndpointTelemetry> {
  const [created] = await db.insert(endpointTelemetry).values(telemetry).returning();
  return created;
}

export async function getPostureScores(orgId: string): Promise<PostureScore[]> {
  return db
    .select()
    .from(postureScores)
    .where(eq(postureScores.orgId, orgId))
    .orderBy(desc(postureScores.generatedAt));
}

export async function createPostureScore(score: InsertPostureScore): Promise<PostureScore> {
  const [created] = await db.insert(postureScores).values(score).returning();
  return created;
}

export async function getLatestPostureScore(orgId: string): Promise<PostureScore | undefined> {
  const [score] = await db
    .select()
    .from(postureScores)
    .where(eq(postureScores.orgId, orgId))
    .orderBy(desc(postureScores.generatedAt))
    .limit(1);
  return score;
}
