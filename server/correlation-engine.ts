import { db } from "./db";
import { alerts, entities, alertEntities, correlationClusters, incidents, type Alert, type CorrelationCluster } from "@shared/schema";
import { eq, and, sql, gte, desc, inArray, ne } from "drizzle-orm";
import { findRelatedAlertsByEntity } from "./entity-resolver";
import { computeThreatIntelConfidenceBoost } from "./threat-enrichment";
import { logger } from "./logger";

export interface CorrelationResult {
  clusterId: string;
  confidence: number;
  method: string;
  alertIds: string[];
  sharedEntities: { type: string; value: string; count: number }[];
  reasoningTrace: string;
}

interface AlertWithEntities {
  alert: Alert;
  entityIds: string[];
  entityValues: { type: string; value: string }[];
}

const CORRELATION_CONFIG = {
  timeWindowHours: 24,
  minSharedEntities: 1,
  confidenceThresholdForIncident: 0.65,
  maxClusterSize: 50,
  weights: {
    sharedEntity: 0.25,
    temporalProximity: 0.15,
    mitreAlignment: 0.20,
    severityPattern: 0.10,
    sameSource: 0.05,
    categoryMatch: 0.15,
    killChainProgression: 0.10,
  },
};

export async function correlateAlert(alert: Alert): Promise<CorrelationResult | null> {
  const timeWindow = new Date(Date.now() - CORRELATION_CONFIG.timeWindowHours * 60 * 60 * 1000);

  const relatedByEntity = await findRelatedAlertsByEntity(alert.id, alert.orgId, 30);
  
  if (relatedByEntity.length === 0) return null;

  const relatedAlertIds = relatedByEntity.map(r => r.alertId);
  const relatedAlerts = await db.select().from(alerts)
    .where(
      and(
        inArray(alerts.id, relatedAlertIds),
        gte(alerts.createdAt, timeWindow)
      )
    )
    .orderBy(desc(alerts.createdAt))
    .limit(CORRELATION_CONFIG.maxClusterSize);

  if (relatedAlerts.length === 0) return null;

  const sharedEntityMap = new Map<string, number>();
  for (const rel of relatedByEntity) {
    for (const ent of rel.sharedEntities) {
      sharedEntityMap.set(ent, (sharedEntityMap.get(ent) || 0) + 1);
    }
  }

  const sharedEntities = Array.from(sharedEntityMap.entries()).map(([key, count]) => {
    const [type, value] = key.split(":");
    return { type, value, count };
  });

  let threatIntelBoost = 0;
  if (sharedEntities.length > 0) {
    try {
      const sharedEntityKeys = sharedEntities.map(e => `${e.type}:${e.value}`);
      const enrichedEntities = await db.select({ metadata: entities.metadata })
        .from(entities)
        .where(
          and(
            alert.orgId ? eq(entities.orgId, alert.orgId) : sql`${entities.orgId} IS NULL`,
            sql`(${entities.type} || ':' || ${entities.value}) = ANY(${sql`ARRAY[${sql.join(sharedEntityKeys.map(k => sql`${k}`), sql`, `)}]`})`
          )
        )
        .limit(20);

      threatIntelBoost = computeThreatIntelConfidenceBoost(
        enrichedEntities.map(e => e.metadata as Record<string, any> | null)
      );
    } catch (err) {
      logger.child("correlation-engine").warn("Threat intel confidence boost computation failed, defaulting to 0", { alertId: alert.id, error: String(err) });
      threatIntelBoost = 0;
    }
  }

  const confidence = Math.min(calculateConfidence(alert, relatedAlerts, sharedEntities) + threatIntelBoost, 1.0);

  if (confidence < 0.3) return null;

  const clusterAlertIds = [alert.id, ...relatedAlerts.map(a => a.id)];
  const reasoningTrace = generateReasoningTrace(alert, relatedAlerts, sharedEntities, confidence);

  const [cluster] = await db.insert(correlationClusters).values({
    orgId: alert.orgId,
    confidence,
    method: "temporal_entity_clustering_v1",
    sharedEntities: sharedEntities,
    reasoningTrace,
    alertIds: clusterAlertIds,
    status: confidence >= CORRELATION_CONFIG.confidenceThresholdForIncident ? "confirmed" : "pending",
  }).returning();

  await db.update(alerts)
    .set({ 
      correlationScore: confidence,
      correlationClusterId: cluster.id,
      correlationReason: reasoningTrace.substring(0, 500),
    })
    .where(eq(alerts.id, alert.id));

  return {
    clusterId: cluster.id,
    confidence,
    method: "temporal_entity_clustering_v1",
    alertIds: clusterAlertIds,
    sharedEntities,
    reasoningTrace,
  };
}

function calculateConfidence(
  targetAlert: Alert,
  relatedAlerts: Alert[],
  sharedEntities: { type: string; value: string; count: number }[]
): number {
  const w = CORRELATION_CONFIG.weights;
  let score = 0;

  const uniqueSharedTypes = new Set(sharedEntities.map(e => e.type));
  const entityScore = Math.min(uniqueSharedTypes.size / 4, 1.0);
  score += entityScore * w.sharedEntity;

  const now = Date.now();
  const targetTime = targetAlert.createdAt ? new Date(targetAlert.createdAt).getTime() : now;
  const avgTimeDiff = relatedAlerts.reduce((sum, a) => {
    const t = a.createdAt ? new Date(a.createdAt).getTime() : now;
    return sum + Math.abs(targetTime - t);
  }, 0) / Math.max(relatedAlerts.length, 1);
  const hoursDiff = avgTimeDiff / (1000 * 60 * 60);
  const temporalScore = Math.max(0, 1.0 - hoursDiff / CORRELATION_CONFIG.timeWindowHours);
  score += temporalScore * w.temporalProximity;

  const targetTactic = targetAlert.mitreTactic;
  const relatedTactics = new Set(relatedAlerts.map(a => a.mitreTactic).filter(Boolean));
  if (targetTactic && relatedTactics.size > 0) {
    const killChainOrder = [
      "reconnaissance", "resource-development", "initial-access", "execution",
      "persistence", "privilege-escalation", "defense-evasion", "credential-access",
      "discovery", "lateral-movement", "collection", "command-and-control",
      "exfiltration", "impact"
    ];
    const tactics = [targetTactic, ...Array.from(relatedTactics)].filter((t): t is string => t !== null);
    const indices = tactics.map(t => killChainOrder.indexOf(t)).filter(i => i >= 0);
    if (indices.length >= 2) {
      const span = Math.max(...indices) - Math.min(...indices);
      const mitreScore = span > 0 ? Math.min(span / 5, 1.0) : 0.3;
      score += mitreScore * w.mitreAlignment;
    }
  }

  const severities = [targetAlert.severity, ...relatedAlerts.map(a => a.severity)];
  const hasCritical = severities.includes("critical");
  const hasHigh = severities.includes("high");
  const severityScore = hasCritical ? 1.0 : hasHigh ? 0.7 : 0.3;
  score += severityScore * w.severityPattern;

  const sameSourceCount = relatedAlerts.filter(a => a.source === targetAlert.source).length;
  const sourceScore = sameSourceCount > 0 ? Math.min(sameSourceCount / relatedAlerts.length + 0.3, 1.0) : 0.5;
  score += sourceScore * w.sameSource;

  const targetCategory = targetAlert.category;
  const relatedCategories = new Set(relatedAlerts.map(a => a.category));
  if (targetCategory && relatedCategories.has(targetCategory)) {
    score += 0.8 * w.categoryMatch;
  } else if (relatedCategories.size > 0) {
    const attackCategories = new Set(["malware", "intrusion", "lateral_movement", "credential_access", "data_exfiltration", "privilege_escalation"]);
    const relatedAttackCats = Array.from(relatedCategories).filter(c => c && attackCategories.has(c));
    if (targetCategory && attackCategories.has(targetCategory) && relatedAttackCats.length > 0) {
      score += 0.6 * w.categoryMatch;
    }
  }

  const allTactics = [targetAlert.mitreTactic, ...relatedAlerts.map(a => a.mitreTactic)].filter(Boolean) as string[];
  const uniqueTactics = new Set(allTactics);
  if (uniqueTactics.size >= 3) {
    score += 1.0 * w.killChainProgression;
  } else if (uniqueTactics.size >= 2) {
    score += 0.6 * w.killChainProgression;
  }

  return Math.round(Math.min(score, 1.0) * 100) / 100;
}

function generateReasoningTrace(
  targetAlert: Alert,
  relatedAlerts: Alert[],
  sharedEntities: { type: string; value: string; count: number }[],
  confidence: number
): string {
  const lines: string[] = [];
  lines.push(`CORRELATION ANALYSIS — Confidence: ${(confidence * 100).toFixed(1)}%`);
  lines.push(`Method: Temporal + Entity Clustering v1`);
  lines.push(`Primary Alert: [${targetAlert.id.substring(0, 8)}] ${targetAlert.title}`);
  lines.push(`Related Alerts: ${relatedAlerts.length}`);
  lines.push("");
  
  lines.push("SHARED ENTITIES:");
  for (const ent of sharedEntities.slice(0, 10)) {
    lines.push(`  - ${ent.type}: ${ent.value} (seen in ${ent.count} related alerts)`);
  }
  lines.push("");

  const allTactics = new Set([targetAlert.mitreTactic, ...relatedAlerts.map(a => a.mitreTactic)].filter(Boolean));
  if (allTactics.size > 0) {
    lines.push(`MITRE ATT&CK Tactics: ${Array.from(allTactics).join(", ")}`);
    if (allTactics.size >= 3) {
      lines.push("  → Multi-stage attack pattern detected (kill chain progression)");
    }
  }

  const allSeverities = [targetAlert.severity, ...relatedAlerts.map(a => a.severity)];
  const critCount = allSeverities.filter(s => s === "critical").length;
  const highCount = allSeverities.filter(s => s === "high").length;
  lines.push(`Severity Distribution: ${critCount} critical, ${highCount} high, ${allSeverities.length - critCount - highCount} other`);

  const allSources = new Set([targetAlert.source, ...relatedAlerts.map(a => a.source)]);
  lines.push(`Sources: ${Array.from(allSources).join(", ")}`);

  if (confidence >= CORRELATION_CONFIG.confidenceThresholdForIncident) {
    lines.push("");
    lines.push("RECOMMENDATION: High confidence correlation — auto-incident creation recommended.");
  }

  return lines.join("\n");
}

export async function runCorrelationScan(orgId?: string): Promise<CorrelationResult[]> {
  const timeWindow = new Date(Date.now() - CORRELATION_CONFIG.timeWindowHours * 60 * 60 * 1000);
  
  const uncorrelatedAlerts = await db.select().from(alerts)
    .where(
      and(
        orgId ? eq(alerts.orgId, orgId) : undefined,
        gte(alerts.createdAt, timeWindow),
        sql`${alerts.correlationClusterId} IS NULL`,
        sql`${alerts.incidentId} IS NULL`
      )
    )
    .orderBy(desc(alerts.createdAt))
    .limit(100);

  const results: CorrelationResult[] = [];
  
  for (const alert of uncorrelatedAlerts) {
    const result = await correlateAlert(alert);
    if (result) {
      results.push(result);
    }
  }

  return results;
}

export async function getCorrelationClusters(orgId?: string): Promise<CorrelationCluster[]> {
  const conditions = orgId ? eq(correlationClusters.orgId, orgId) : undefined;
  return db.select().from(correlationClusters)
    .where(conditions)
    .orderBy(desc(correlationClusters.createdAt))
    .limit(50);
}

export async function getCorrelationCluster(id: string): Promise<CorrelationCluster | undefined> {
  const [cluster] = await db.select().from(correlationClusters).where(eq(correlationClusters.id, id));
  return cluster;
}

export async function promoteClusterToIncident(
  clusterId: string,
  title: string,
  severity: string
): Promise<{ incidentId: string }> {
  const cluster = await getCorrelationCluster(clusterId);
  if (!cluster) throw new Error("Cluster not found");

  const [incident] = await db.insert(incidents).values({
    orgId: cluster.orgId,
    title,
    severity,
    status: "investigating",
    priority: severity === "critical" ? 1 : severity === "high" ? 2 : 3,
    confidence: cluster.confidence,
    alertCount: cluster.alertIds?.length || 0,
    mitreTactics: [],
    mitreTechniques: [],
    referencedAlertIds: cluster.alertIds as string[] | undefined,
    reasoningTrace: cluster.reasoningTrace,
  }).returning();

  if (cluster.alertIds && Array.isArray(cluster.alertIds)) {
    await db.update(alerts)
      .set({ 
        incidentId: incident.id, 
        status: "correlated",
        correlationScore: cluster.confidence,
      })
      .where(inArray(alerts.id, cluster.alertIds as string[]));
  }

  await db.update(correlationClusters)
    .set({ incidentId: incident.id, status: "promoted", updatedAt: new Date() })
    .where(eq(correlationClusters.id, clusterId));

  return { incidentId: incident.id };
}
