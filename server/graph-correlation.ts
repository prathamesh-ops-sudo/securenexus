import { db } from "./db";
import { alerts, entities, alertEntities, correlationClusters, attackPaths, campaigns } from "@shared/schema";
import type { Alert, Entity, AttackPath, Campaign } from "@shared/schema";
import { eq, and, sql, desc, inArray } from "drizzle-orm";
import { createHash } from "crypto";

interface GraphNode {
  id: string;
  type: "alert" | "entity";
  data: any;
}

interface GraphEdge {
  source: string;
  target: string;
  weight: number;
  relationship: string;
}

interface AttackPathResult {
  alertIds: string[];
  entityIds: string[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  tacticsSequence: string[];
  techniquesUsed: string[];
  hopCount: number;
  confidence: number;
  timeSpanHours: number;
  firstAlertAt: Date | null;
  lastAlertAt: Date | null;
}

interface CampaignFingerprint {
  fingerprint: string;
  tacticsSequence: string[];
  entitySignature: string[];
  sourceSignature: string[];
}

const KILL_CHAIN_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact",
];

const SEVERITY_ORDER: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const MAX_CLUSTER_SIZE = 100;

export async function buildAlertEntityGraph(orgId?: string): Promise<{
  graph: Map<string, Set<string>>;
  nodeMetadata: Map<string, GraphNode>;
}> {
  const conditions = orgId ? eq(alerts.orgId, orgId) : undefined;

  const rows = await db
    .select({
      alertId: alertEntities.alertId,
      entityId: alertEntities.entityId,
      alertTitle: alerts.title,
      alertSeverity: alerts.severity,
      alertSource: alerts.source,
      alertCategory: alerts.category,
      alertMitreTactic: alerts.mitreTactic,
      alertMitreTechnique: alerts.mitreTechnique,
      alertCreatedAt: alerts.createdAt,
      alertOrgId: alerts.orgId,
      entityType: entities.type,
      entityValue: entities.value,
      entityDisplayName: entities.displayName,
      entityRiskScore: entities.riskScore,
    })
    .from(alertEntities)
    .innerJoin(alerts, eq(alertEntities.alertId, alerts.id))
    .innerJoin(entities, eq(alertEntities.entityId, entities.id))
    .where(conditions ? and(conditions) : undefined);

  const graph = new Map<string, Set<string>>();
  const nodeMetadata = new Map<string, GraphNode>();

  const ensureNode = (id: string) => {
    if (!graph.has(id)) {
      graph.set(id, new Set<string>());
    }
  };

  for (const row of rows) {
    const alertKey = `a:${row.alertId}`;
    const entityKey = `e:${row.entityId}`;

    ensureNode(alertKey);
    ensureNode(entityKey);

    graph.get(alertKey)!.add(entityKey);
    graph.get(entityKey)!.add(alertKey);

    if (!nodeMetadata.has(alertKey)) {
      nodeMetadata.set(alertKey, {
        id: alertKey,
        type: "alert",
        data: {
          alertId: row.alertId,
          title: row.alertTitle,
          severity: row.alertSeverity,
          source: row.alertSource,
          category: row.alertCategory,
          mitreTactic: row.alertMitreTactic,
          mitreTechnique: row.alertMitreTechnique,
          createdAt: row.alertCreatedAt,
          orgId: row.alertOrgId,
        },
      });
    }

    if (!nodeMetadata.has(entityKey)) {
      nodeMetadata.set(entityKey, {
        id: entityKey,
        type: "entity",
        data: {
          entityId: row.entityId,
          type: row.entityType,
          value: row.entityValue,
          displayName: row.entityDisplayName,
          riskScore: row.entityRiskScore,
        },
      });
    }
  }

  return { graph, nodeMetadata };
}

export function findAttackPaths(
  graph: Map<string, Set<string>>,
  nodeMetadata: Map<string, GraphNode>,
  maxDepth: number = 6
): AttackPathResult[] {
  const globalVisited = new Set<string>();
  const results: AttackPathResult[] = [];

  const alertNodes = Array.from(nodeMetadata.entries())
    .filter(([, meta]) => meta.type === "alert")
    .map(([key]) => key);

  for (const startNode of alertNodes) {
    if (globalVisited.has(startNode)) continue;

    const componentAlerts: string[] = [];
    const componentEntities: string[] = [];
    const componentNodes: GraphNode[] = [];
    const componentEdges: GraphEdge[] = [];
    const visited = new Set<string>();
    const queue: { node: string; depth: number }[] = [{ node: startNode, depth: 0 }];
    visited.add(startNode);

    let alertCount = 0;

    while (queue.length > 0) {
      const current = queue.shift()!;
      const meta = nodeMetadata.get(current.node);
      if (!meta) continue;

      if (meta.type === "alert") {
        alertCount++;
        componentAlerts.push(meta.data.alertId);
        if (alertCount > MAX_CLUSTER_SIZE) break;
      } else {
        componentEntities.push(meta.data.entityId);
      }
      componentNodes.push(meta);
      globalVisited.add(current.node);

      if (current.depth >= maxDepth) continue;

      const neighbors = graph.get(current.node);
      if (!neighbors) continue;

      for (const neighbor of Array.from(neighbors)) {
        if (visited.has(neighbor)) continue;
        visited.add(neighbor);

        const neighborMeta = nodeMetadata.get(neighbor);
        if (!neighborMeta) continue;

        if (neighborMeta.type === "alert" && alertCount >= MAX_CLUSTER_SIZE) continue;

        componentEdges.push({
          source: current.node,
          target: neighbor,
          weight: 1,
          relationship: meta.type === "alert" ? "alert_to_entity" : "entity_to_alert",
        });

        queue.push({ node: neighbor, depth: current.depth + 1 });
      }
    }

    if (componentAlerts.length < 2) continue;

    const alertDataList = componentAlerts
      .map((aid) => nodeMetadata.get(`a:${aid}`))
      .filter((m): m is GraphNode => m !== undefined)
      .map((m) => m.data)
      .sort((a, b) => {
        const tA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const tB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return tA - tB;
      });

    const tacticsSequence = alertDataList
      .map((a) => a.mitreTactic as string | null)
      .filter((t): t is string => t !== null);

    const techniquesUsed = Array.from(
      new Set(
        alertDataList
          .map((a) => a.mitreTechnique as string | null)
          .filter((t): t is string => t !== null)
      )
    );

    const entityDataList = componentEntities
      .map((eid) => nodeMetadata.get(`e:${eid}`))
      .filter((m): m is GraphNode => m !== undefined)
      .map((m) => m.data);

    const hopCount = Math.max(0, Math.floor(componentEdges.length / 2));

    const timestamps = alertDataList
      .map((a) => (a.createdAt ? new Date(a.createdAt).getTime() : null))
      .filter((t): t is number => t !== null);

    const firstAlertAt = timestamps.length > 0 ? new Date(Math.min(...timestamps)) : null;
    const lastAlertAt = timestamps.length > 0 ? new Date(Math.max(...timestamps)) : null;
    const timeSpanHours =
      firstAlertAt && lastAlertAt
        ? (lastAlertAt.getTime() - firstAlertAt.getTime()) / (1000 * 60 * 60)
        : 0;

    const confidence = computePathConfidence(alertDataList, entityDataList, hopCount, timeSpanHours);

    results.push({
      alertIds: componentAlerts,
      entityIds: componentEntities,
      nodes: componentNodes,
      edges: componentEdges,
      tacticsSequence,
      techniquesUsed,
      hopCount,
      confidence,
      timeSpanHours,
      firstAlertAt,
      lastAlertAt,
    });
  }

  return results;
}

export function computePathConfidence(
  alertDataList: any[],
  entityDataList: any[],
  hopCount: number,
  timeSpanHours: number
): number {
  let score = 0;

  const uniqueEntityTypes = new Set(entityDataList.map((e) => e.type));
  const entityDensityScore = Math.min(uniqueEntityTypes.size / 4, 1.0);
  score += entityDensityScore * 0.20;

  const allTactics = alertDataList
    .map((a) => a.mitreTactic as string | null)
    .filter((t): t is string => t !== null);
  const uniqueTactics = Array.from(new Set(allTactics));
  const tacticIndices = uniqueTactics
    .map((t) => KILL_CHAIN_ORDER.indexOf(t))
    .filter((i) => i >= 0)
    .sort((a, b) => a - b);

  let killChainScore = 0;
  if (tacticIndices.length >= 4) {
    let inOrder = true;
    for (let i = 1; i < tacticIndices.length; i++) {
      if (tacticIndices[i] <= tacticIndices[i - 1]) {
        inOrder = false;
        break;
      }
    }
    killChainScore = inOrder ? 1.0 : 0.8;
  } else if (uniqueTactics.length >= 3) {
    killChainScore = 0.8;
  } else if (uniqueTactics.length >= 2) {
    killChainScore = 0.5;
  }
  score += killChainScore * 0.25;

  const uniqueSources = new Set(alertDataList.map((a) => a.source));
  let sourceDiversityScore = 0.3;
  if (uniqueSources.size >= 3) {
    sourceDiversityScore = 1.0;
  } else if (uniqueSources.size >= 2) {
    sourceDiversityScore = 0.7;
  }
  score += sourceDiversityScore * 0.15;

  const severityValues = alertDataList
    .map((a) => SEVERITY_ORDER[a.severity] ?? 1)
    .sort((a, b) => a - b);
  const minSev = severityValues.length > 0 ? severityValues[0] : 0;
  const maxSev = severityValues.length > 0 ? severityValues[severityValues.length - 1] : 0;
  const severityScore = maxSev > minSev ? Math.min((maxSev - minSev) / 3, 1.0) : 0.2;
  score += severityScore * 0.15;

  const hopScore = Math.min(hopCount / 5, 1.0);
  score += hopScore * 0.10;

  const temporalScore = Math.min(timeSpanHours / (24 * 7), 1.0);
  score += temporalScore * 0.15;

  return Math.round(Math.min(score, 1.0) * 100) / 100;
}

export function generateCampaignFingerprint(
  attackPath: AttackPathResult,
  alertDataList: any[]
): CampaignFingerprint {
  const sortedTactics = Array.from(new Set(attackPath.tacticsSequence)).sort();

  const entityTypes = Array.from(
    new Set(
      attackPath.nodes
        .filter((n) => n.type === "entity")
        .map((n) => n.data.type as string)
    )
  ).sort();

  const sources = Array.from(new Set(alertDataList.map((a) => a.source as string))).sort();

  const fingerprintInput = [
    `tactics:${sortedTactics.join(",")}`,
    `entities:${entityTypes.join(",")}`,
    `sources:${sources.join(",")}`,
  ].join("|");

  const fingerprint = createHash("sha256").update(fingerprintInput).digest("hex");

  return {
    fingerprint,
    tacticsSequence: sortedTactics,
    entitySignature: entityTypes,
    sourceSignature: sources,
  };
}

export async function runGraphCorrelation(orgId?: string): Promise<{
  attackPaths: AttackPathResult[];
  campaignsCreated: number;
  clustersCreated: number;
}> {
  const { graph, nodeMetadata } = await buildAlertEntityGraph(orgId);

  const paths = findAttackPaths(graph, nodeMetadata);

  const qualifiedPaths = paths.filter((p) => p.confidence >= 0.35);

  let campaignsCreated = 0;
  let clustersCreated = 0;

  for (const path of qualifiedPaths) {
    const alertDataList = path.alertIds
      .map((aid) => nodeMetadata.get(`a:${aid}`))
      .filter((m): m is GraphNode => m !== undefined)
      .map((m) => m.data);

    const firstAlertOrgId = alertDataList.length > 0 ? alertDataList[0].orgId : orgId || null;

    const reasoningTrace = buildReasoningTrace(path, alertDataList);

    const [cluster] = await db.insert(correlationClusters).values({
      orgId: firstAlertOrgId,
      confidence: path.confidence,
      method: "graph_traversal_v2",
      sharedEntities: path.entityIds.map((eid) => {
        const meta = nodeMetadata.get(`e:${eid}`);
        return meta ? { type: meta.data.type, value: meta.data.value } : { type: "unknown", value: eid };
      }),
      reasoningTrace,
      alertIds: path.alertIds,
      status: path.confidence >= 0.65 ? "confirmed" : "pending",
    }).returning();

    clustersCreated++;

    const [attackPath] = await db.insert(attackPaths).values({
      orgId: firstAlertOrgId,
      clusterId: cluster.id,
      alertIds: path.alertIds,
      entityIds: path.entityIds,
      nodes: path.nodes,
      edges: path.edges,
      tacticsSequence: path.tacticsSequence,
      techniquesUsed: path.techniquesUsed,
      hopCount: path.hopCount,
      confidence: path.confidence,
      timeSpanHours: path.timeSpanHours,
      firstAlertAt: path.firstAlertAt,
      lastAlertAt: path.lastAlertAt,
    }).returning();

    const fp = generateCampaignFingerprint(path, alertDataList);

    const existingCampaigns = await db
      .select()
      .from(campaigns)
      .where(
        and(
          eq(campaigns.fingerprint, fp.fingerprint),
          firstAlertOrgId ? eq(campaigns.orgId, firstAlertOrgId) : sql`${campaigns.orgId} IS NULL`
        )
      )
      .limit(1);

    if (existingCampaigns.length > 0) {
      const existing = existingCampaigns[0];
      const existingClusterIds = (existing.clusterIds || []) as string[];
      const existingPathIds = (existing.attackPathIds || []) as string[];
      await db.update(campaigns)
        .set({
          clusterIds: [...existingClusterIds, cluster.id],
          attackPathIds: [...existingPathIds, attackPath.id],
          confidence: Math.max(existing.confidence, path.confidence),
          alertCount: (existing.alertCount || 0) + path.alertIds.length,
          lastSeenAt: path.lastAlertAt || new Date(),
          updatedAt: new Date(),
        })
        .where(eq(campaigns.id, existing.id));

      await db.update(attackPaths)
        .set({ campaignId: existing.id })
        .where(eq(attackPaths.id, attackPath.id));
    } else {
      const campaignName = generateCampaignName(fp, path);
      const [newCampaign] = await db.insert(campaigns).values({
        orgId: firstAlertOrgId,
        name: campaignName,
        fingerprint: fp.fingerprint,
        tacticsSequence: fp.tacticsSequence,
        entitySignature: fp.entitySignature,
        sourceSignature: fp.sourceSignature,
        clusterIds: [cluster.id],
        attackPathIds: [attackPath.id],
        confidence: path.confidence,
        alertCount: path.alertIds.length,
        status: "active",
        firstSeenAt: path.firstAlertAt || new Date(),
        lastSeenAt: path.lastAlertAt || new Date(),
      }).returning();

      await db.update(attackPaths)
        .set({ campaignId: newCampaign.id })
        .where(eq(attackPaths.id, attackPath.id));

      campaignsCreated++;
    }

    if (path.alertIds.length > 0) {
      await db.update(alerts)
        .set({
          correlationScore: path.confidence,
          correlationClusterId: cluster.id,
          correlationReason: reasoningTrace.substring(0, 500),
        })
        .where(inArray(alerts.id, path.alertIds));
    }
  }

  return {
    attackPaths: qualifiedPaths,
    campaignsCreated,
    clustersCreated,
  };
}

function buildReasoningTrace(path: AttackPathResult, alertDataList: any[]): string {
  const lines: string[] = [];
  lines.push(`GRAPH CORRELATION ANALYSIS — Confidence: ${(path.confidence * 100).toFixed(1)}%`);
  lines.push(`Method: Graph Traversal v2 (no time window constraint)`);
  lines.push(`Alerts in path: ${path.alertIds.length}`);
  lines.push(`Entities involved: ${path.entityIds.length}`);
  lines.push(`Hop count: ${path.hopCount}`);
  lines.push(`Time span: ${path.timeSpanHours.toFixed(1)} hours (${(path.timeSpanHours / 24).toFixed(1)} days)`);
  lines.push("");

  if (path.tacticsSequence.length > 0) {
    lines.push(`MITRE ATT&CK Tactics: ${Array.from(new Set(path.tacticsSequence)).join(" -> ")}`);
    if (new Set(path.tacticsSequence).size >= 3) {
      lines.push("  -> Multi-stage attack pattern detected (kill chain progression)");
    }
  }

  if (path.techniquesUsed.length > 0) {
    lines.push(`Techniques: ${path.techniquesUsed.join(", ")}`);
  }

  lines.push("");
  const uniqueSources = new Set(alertDataList.map((a) => a.source));
  lines.push(`Sources: ${Array.from(uniqueSources).join(", ")}`);

  const severities = alertDataList.map((a) => a.severity);
  const critCount = severities.filter((s: string) => s === "critical").length;
  const highCount = severities.filter((s: string) => s === "high").length;
  lines.push(`Severity: ${critCount} critical, ${highCount} high, ${severities.length - critCount - highCount} other`);

  if (path.timeSpanHours > 24 * 7) {
    lines.push("");
    lines.push("LOW AND SLOW INDICATOR: Attack spans over 7 days — potential APT campaign.");
  }

  if (path.confidence >= 0.65) {
    lines.push("");
    lines.push("RECOMMENDATION: High confidence correlation — auto-incident creation recommended.");
  }

  return lines.join("\n");
}

function generateCampaignName(fp: CampaignFingerprint, path: AttackPathResult): string {
  const tacticLabel = fp.tacticsSequence.length > 0
    ? fp.tacticsSequence.slice(0, 2).join("-")
    : "unknown";
  const entityLabel = fp.entitySignature.length > 0
    ? fp.entitySignature[0]
    : "multi";
  const dateStr = path.firstAlertAt
    ? path.firstAlertAt.toISOString().split("T")[0]
    : new Date().toISOString().split("T")[0];

  return `Campaign-${tacticLabel}-${entityLabel}-${dateStr}`;
}

export async function getAttackPaths(orgId?: string): Promise<AttackPath[]> {
  const conditions = orgId ? eq(attackPaths.orgId, orgId) : undefined;
  return db
    .select()
    .from(attackPaths)
    .where(conditions)
    .orderBy(desc(attackPaths.createdAt))
    .limit(50);
}

export async function getAttackPath(id: string): Promise<AttackPath | undefined> {
  const [result] = await db
    .select()
    .from(attackPaths)
    .where(eq(attackPaths.id, id));
  return result;
}

export async function getCampaigns(orgId?: string): Promise<Campaign[]> {
  const conditions = orgId ? eq(campaigns.orgId, orgId) : undefined;
  return db
    .select()
    .from(campaigns)
    .where(conditions)
    .orderBy(desc(campaigns.createdAt))
    .limit(50);
}

export async function getCampaign(id: string): Promise<Campaign | undefined> {
  const [result] = await db
    .select()
    .from(campaigns)
    .where(eq(campaigns.id, id));
  return result;
}
