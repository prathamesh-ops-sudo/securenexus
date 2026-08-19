import {
  type AiDeploymentConfig,
  type AiFeedback,
  type AiGeneratedRule,
  type AttackGraph,
  type AttackGraphEdge,
  type AttackGraphNode,
  type EngineConfig,
  type EngineDryRun,
  type EngineExplainabilityLog,
  type InsertAiDeploymentConfig,
  type InsertAiFeedback,
  type InsertAiGeneratedRule,
  type InsertAttackGraph,
  type InsertAttackGraphEdge,
  type InsertAttackGraphNode,
  type InsertEngineConfig,
  type InsertEngineDryRun,
  type InsertEngineExplainabilityLog,
  type InsertInvestigationChatMessage,
  type InvestigationChatMessage,
  aiDeploymentConfigs,
  aiFeedback,
  aiGeneratedRules,
  attackGraphEdges,
  attackGraphNodes,
  attackGraphs,
  engineConfigs,
  engineDryRuns,
  engineExplainabilityLogs,
  investigationChatMessages,
} from "@shared/schema";
import { db } from "../db";
import { and, asc, count, desc, eq, gte, sql } from "drizzle-orm";

export async function createAiFeedback(feedback: InsertAiFeedback): Promise<AiFeedback> {
  const [created] = await db.insert(aiFeedback).values(feedback).returning();
  return created;
}

export async function getAiFeedback(orgId: string, resourceType?: string, resourceId?: string): Promise<AiFeedback[]> {
  const conditions = [];
  conditions.push(eq(aiFeedback.orgId, orgId));
  if (resourceType) conditions.push(eq(aiFeedback.resourceType, resourceType));
  if (resourceId) conditions.push(eq(aiFeedback.resourceId, resourceId));
  const condition = conditions.length > 0 ? and(...conditions) : undefined;
  return db.select().from(aiFeedback).where(condition).orderBy(desc(aiFeedback.createdAt));
}

export async function countAiFeedbackByOrg(orgId: string): Promise<number> {
  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(aiFeedback)
    .where(eq(aiFeedback.orgId, orgId));
  return Number(result?.count ?? 0);
}

export async function getAiFeedbackMetrics(
  orgId?: string,
  days?: number,
): Promise<
  { date: string; avgRating: number; totalFeedback: number; negativeFeedback: number; positiveFeedback: number }[]
> {
  const d = days || 30;
  const orgCondition = orgId ? sql` AND org_id = ${orgId}` : sql``;
  const result = await db.execute(sql`
    SELECT
      date_trunc('day', created_at) as date,
      AVG(rating) as avg_rating,
      COUNT(*) as total,
      SUM(CASE WHEN rating <= 2 THEN 1 ELSE 0 END) as negative,
      SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive
    FROM ai_feedback
    WHERE created_at >= NOW() - make_interval(days => ${d})${orgCondition}
    GROUP BY 1
    ORDER BY 1
  `);
  const rows = (result as any).rows || result || [];
  return rows.map((row: any) => ({
    date: row.date ? new Date(row.date).toISOString().split("T")[0] : "",
    avgRating: Number(row.avg_rating) || 0,
    totalFeedback: Number(row.total) || 0,
    negativeFeedback: Number(row.negative) || 0,
    positiveFeedback: Number(row.positive) || 0,
  }));
}

export async function getAiFeedbackByResource(
  orgId: string,
  resourceType: string,
  resourceId: string,
): Promise<AiFeedback[]> {
  return db
    .select()
    .from(aiFeedback)
    .where(
      and(
        eq(aiFeedback.orgId, orgId),
        eq(aiFeedback.resourceType, resourceType),
        eq(aiFeedback.resourceId, resourceId),
      ),
    )
    .orderBy(desc(aiFeedback.createdAt));
}

export async function getAiDeploymentConfig(orgId: string): Promise<AiDeploymentConfig | undefined> {
  const [config] = await db.select().from(aiDeploymentConfigs).where(eq(aiDeploymentConfigs.orgId, orgId));
  return config;
}

export async function upsertAiDeploymentConfig(config: InsertAiDeploymentConfig): Promise<AiDeploymentConfig> {
  const existing = await getAiDeploymentConfig(config.orgId);
  if (existing) {
    const [updated] = await db
      .update(aiDeploymentConfigs)
      .set({ ...config, updatedAt: new Date() })
      .where(eq(aiDeploymentConfigs.orgId, config.orgId))
      .returning();
    return updated;
  }
  const [created] = await db.insert(aiDeploymentConfigs).values(config).returning();
  return created;
}

export async function createChatMessage(msg: InsertInvestigationChatMessage): Promise<InvestigationChatMessage> {
  const [created] = await db.insert(investigationChatMessages).values(msg).returning();
  return created;
}

export async function getChatThread(threadId: string, orgId: string): Promise<InvestigationChatMessage[]> {
  return db
    .select()
    .from(investigationChatMessages)
    .where(and(eq(investigationChatMessages.threadId, threadId), eq(investigationChatMessages.orgId, orgId)))
    .orderBy(asc(investigationChatMessages.createdAt));
}

export async function getChatThreadsByIncident(incidentId: string, orgId: string): Promise<InvestigationChatMessage[]> {
  return db
    .select()
    .from(investigationChatMessages)
    .where(and(eq(investigationChatMessages.incidentId, incidentId), eq(investigationChatMessages.orgId, orgId)))
    .orderBy(asc(investigationChatMessages.createdAt));
}

// ─── AI-Generated Detection Rules ──────────────────────────────────────────

export async function createAiGeneratedRule(rule: InsertAiGeneratedRule): Promise<AiGeneratedRule> {
  const [created] = await db.insert(aiGeneratedRules).values(rule).returning();
  return created;
}

export async function getAiGeneratedRulesByOrg(orgId: string, limit = 50): Promise<AiGeneratedRule[]> {
  return db
    .select()
    .from(aiGeneratedRules)
    .where(eq(aiGeneratedRules.orgId, orgId))
    .orderBy(desc(aiGeneratedRules.createdAt))
    .limit(limit);
}

export async function getAiGeneratedRulesByIncident(incidentId: string, orgId: string): Promise<AiGeneratedRule[]> {
  return db
    .select()
    .from(aiGeneratedRules)
    .where(and(eq(aiGeneratedRules.sourceIncidentId, incidentId), eq(aiGeneratedRules.orgId, orgId)))
    .orderBy(desc(aiGeneratedRules.createdAt));
}

export async function getAiGeneratedRule(id: string): Promise<AiGeneratedRule | undefined> {
  const [rule] = await db.select().from(aiGeneratedRules).where(eq(aiGeneratedRules.id, id));
  return rule;
}

export async function updateAiGeneratedRule(
  id: string,
  data: Partial<AiGeneratedRule>,
): Promise<AiGeneratedRule | undefined> {
  const [updated] = await db.update(aiGeneratedRules).set(data).where(eq(aiGeneratedRules.id, id)).returning();
  return updated;
}

// ─── War Rooms (Persistent) ─────────────────────────────────────────────────

export async function getEngineConfigs(orgId: string): Promise<EngineConfig[]> {
  return db.select().from(engineConfigs).where(eq(engineConfigs.orgId, orgId)).orderBy(asc(engineConfigs.engineName));
}

export async function getEngineConfig(orgId: string, engineName: string): Promise<EngineConfig | undefined> {
  const [row] = await db
    .select()
    .from(engineConfigs)
    .where(and(eq(engineConfigs.orgId, orgId), eq(engineConfigs.engineName, engineName)));
  return row;
}

export async function upsertEngineConfig(
  orgId: string,
  engineName: string,
  data: Partial<InsertEngineConfig>,
): Promise<EngineConfig> {
  const [result] = await db
    .insert(engineConfigs)
    .values({ orgId, engineName, ...data })
    .onConflictDoUpdate({
      target: [engineConfigs.orgId, engineConfigs.engineName],
      set: { ...data, updatedAt: new Date() },
    })
    .returning();
  return result;
}

export async function createEngineDryRun(run: InsertEngineDryRun): Promise<EngineDryRun> {
  const [created] = await db.insert(engineDryRuns).values(run).returning();
  return created;
}

export async function getEngineDryRuns(orgId: string, engineName: string, limit = 20): Promise<EngineDryRun[]> {
  return db
    .select()
    .from(engineDryRuns)
    .where(and(eq(engineDryRuns.orgId, orgId), eq(engineDryRuns.engineName, engineName)))
    .orderBy(desc(engineDryRuns.createdAt))
    .limit(limit);
}

export async function updateEngineDryRun(id: string, data: Partial<EngineDryRun>): Promise<EngineDryRun | undefined> {
  const [updated] = await db.update(engineDryRuns).set(data).where(eq(engineDryRuns.id, id)).returning();
  return updated;
}

export async function createEngineExplainabilityLog(
  log: InsertEngineExplainabilityLog,
): Promise<EngineExplainabilityLog> {
  const [created] = await db.insert(engineExplainabilityLogs).values(log).returning();
  return created;
}

export async function getEngineExplainabilityLogs(
  orgId: string,
  engineName: string,
  limit = 50,
): Promise<EngineExplainabilityLog[]> {
  return db
    .select()
    .from(engineExplainabilityLogs)
    .where(and(eq(engineExplainabilityLogs.orgId, orgId), eq(engineExplainabilityLogs.engineName, engineName)))
    .orderBy(desc(engineExplainabilityLogs.createdAt))
    .limit(limit);
}

// Attack Graph Persistence

export async function createAttackGraph(graph: InsertAttackGraph): Promise<AttackGraph> {
  const [created] = await db.insert(attackGraphs).values(graph).returning();
  return created;
}

export async function getAttackGraphsByIncident(incidentId: string, orgId: string): Promise<AttackGraph[]> {
  return db
    .select()
    .from(attackGraphs)
    .where(and(eq(attackGraphs.incidentId, incidentId), eq(attackGraphs.orgId, orgId)))
    .orderBy(desc(attackGraphs.createdAt));
}

export async function getAttackGraphsByOrg(orgId: string, limit = 50, days?: number): Promise<AttackGraph[]> {
  const conditions = [eq(attackGraphs.orgId, orgId)];
  if (days) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    conditions.push(gte(attackGraphs.createdAt, cutoff));
  }
  return db
    .select()
    .from(attackGraphs)
    .where(and(...conditions))
    .orderBy(desc(attackGraphs.createdAt))
    .limit(limit);
}

export async function getAttackGraph(id: string): Promise<AttackGraph | undefined> {
  const [graph] = await db.select().from(attackGraphs).where(eq(attackGraphs.id, id));
  return graph;
}

export async function deleteAttackGraph(id: string): Promise<boolean> {
  const result = await db.delete(attackGraphs).where(eq(attackGraphs.id, id));
  return (result.rowCount ?? 0) > 0;
}

export async function createAttackGraphNodes(nodes: InsertAttackGraphNode[]): Promise<AttackGraphNode[]> {
  if (nodes.length === 0) return [];
  return db.insert(attackGraphNodes).values(nodes).returning();
}

export async function createAttackGraphEdges(edges: InsertAttackGraphEdge[]): Promise<AttackGraphEdge[]> {
  if (edges.length === 0) return [];
  return db.insert(attackGraphEdges).values(edges).returning();
}

export async function getAttackGraphNodes(graphId: string): Promise<AttackGraphNode[]> {
  return db
    .select()
    .from(attackGraphNodes)
    .where(eq(attackGraphNodes.graphId, graphId))
    .orderBy(attackGraphNodes.depth);
}

export async function getAttackGraphEdges(graphId: string): Promise<AttackGraphEdge[]> {
  return db.select().from(attackGraphEdges).where(eq(attackGraphEdges.graphId, graphId));
}

// ─── Investigation Chat Messages ───────────────────────────────────────────
