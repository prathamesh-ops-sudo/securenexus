import { db } from "./db";
import { entities, entityAliases, alertEntities, alerts, type Alert, type Entity, type EntityAlias, type InsertEntity } from "@shared/schema";
import { eq, and, sql, inArray, desc } from "drizzle-orm";
import { logger } from "./logger";

export interface ExtractedEntity {
  type: string;
  value: string;
  role: string;
  displayName?: string;
}

export function extractEntitiesFromAlert(alert: Alert): ExtractedEntity[] {
  const extracted: ExtractedEntity[] = [];
  const seen = new Set<string>();

  const addEntity = (type: string, value: string | null | undefined, role: string, displayName?: string) => {
    if (!value || value.trim() === "") return;
    const key = `${type}:${value.toLowerCase().trim()}`;
    if (seen.has(key)) return;
    seen.add(key);
    extracted.push({ type, value: value.trim(), role, displayName });
  };

  addEntity("ip", alert.sourceIp, "source");
  addEntity("ip", alert.destIp, "target");
  addEntity("host", alert.hostname, "source");
  addEntity("domain", alert.domain, "indicator");
  addEntity("file_hash", alert.fileHash, "indicator");
  addEntity("url", alert.url, "indicator");
  addEntity("user", alert.userId, "subject");

  const normalized = alert.normalizedData as Record<string, any> | null;
  if (normalized) {
    addEntity("user", normalized.user, "subject");
    addEntity("user", normalized.username, "subject");
    addEntity("user", normalized.account_name, "subject");
    addEntity("email", normalized.email, "subject");
    addEntity("host", normalized.src_host, "source");
    addEntity("host", normalized.dest_host, "target");
    addEntity("ip", normalized.src_ip, "source");
    addEntity("ip", normalized.dest_ip, "target");
    addEntity("domain", normalized.dns_query, "indicator");
    addEntity("process", normalized.process_name, "indicator");
    addEntity("file_hash", normalized.sha256, "indicator");
    addEntity("file_hash", normalized.md5, "indicator");
  }

  const raw = alert.rawData as Record<string, any> | null;
  if (raw) {
    addEntity("user", raw.UserName, "subject");
    addEntity("user", raw.user, "subject");
    addEntity("ip", raw.src_ip || raw.source_ip || raw.srcip, "source");
    addEntity("ip", raw.dst_ip || raw.dest_ip || raw.dstip, "target");
    addEntity("host", raw.hostname || raw.host || raw.computer_name, "source");
    addEntity("domain", raw.domain || raw.query, "indicator");
    addEntity("file_hash", raw.sha256 || raw.file_hash || raw.hash, "indicator");
    addEntity("email", raw.sender || raw.recipient, "indicator");
  }

  return extracted;
}

export async function resolveAndLinkEntities(alert: Alert): Promise<Entity[]> {
  const extracted = extractEntitiesFromAlert(alert);
  if (extracted.length === 0) return [];

  const resolvedEntities: Entity[] = [];
  const enrichableTypes = new Set(["ip", "domain", "file_hash", "url"]);

  for (const ext of extracted) {
    const orgId = alert.orgId || null;

    let existing = await db.select().from(entities)
      .where(
        and(
          orgId ? eq(entities.orgId, orgId) : sql`${entities.orgId} IS NULL`,
          eq(entities.type, ext.type),
          eq(entities.value, ext.value.toLowerCase())
        )
      )
      .limit(1);

    if (existing.length === 0) {
      const aliasEntity = await resolveEntityByAlias(ext.value, orgId);
      if (aliasEntity) {
        existing = [aliasEntity];
      }
    }

    let entity: Entity;
    let isNewEntity = false;
    if (existing.length > 0) {
      const [updated] = await db.update(entities)
        .set({
          lastSeenAt: new Date(),
          alertCount: sql`${entities.alertCount} + 1`,
          riskScore: sql`GREATEST(${entities.riskScore}, ${calculateEntityRisk(alert, ext)})`,
        })
        .where(eq(entities.id, existing[0].id))
        .returning();
      entity = updated;
    } else {
      const [created] = await db.insert(entities)
        .values({
          orgId,
          type: ext.type,
          value: ext.value.toLowerCase(),
          displayName: ext.displayName || ext.value,
          metadata: {},
          alertCount: 1,
          riskScore: calculateEntityRisk(alert, ext),
        })
        .returning();
      entity = created;
      isNewEntity = true;
    }

    if (isNewEntity && enrichableTypes.has(ext.type)) {
      try {
        const { enrichEntityBackground } = await import("./threat-enrichment");
        enrichEntityBackground(entity.id);
      } catch (err) {
        logger.child("entity-resolver").warn("Background enrichment trigger failed", { error: String(err) });
      }
    }

    resolvedEntities.push(entity);

    const existingLink = await db.select().from(alertEntities)
      .where(
        and(
          eq(alertEntities.alertId, alert.id),
          eq(alertEntities.entityId, entity.id)
        )
      )
      .limit(1);

    if (existingLink.length === 0) {
      await db.insert(alertEntities).values({
        alertId: alert.id,
        entityId: entity.id,
        role: ext.role,
      });
    }
  }

  return resolvedEntities;
}

function calculateEntityRisk(alert: Alert, entity: ExtractedEntity): number {
  let risk = 0;
  const severityMap: Record<string, number> = {
    critical: 0.95,
    high: 0.75,
    medium: 0.5,
    low: 0.25,
    informational: 0.1,
  };
  risk = severityMap[alert.severity] || 0.3;

  if (entity.role === "indicator") risk = Math.min(risk + 0.1, 1.0);
  if (alert.category === "malware" || alert.category === "data_exfiltration") risk = Math.min(risk + 0.1, 1.0);

  return Math.round(risk * 100) / 100;
}

export async function getEntitiesForAlert(alertId: string): Promise<(Entity & { role: string })[]> {
  const results = await db
    .select({
      id: entities.id,
      orgId: entities.orgId,
      type: entities.type,
      value: entities.value,
      displayName: entities.displayName,
      metadata: entities.metadata,
      firstSeenAt: entities.firstSeenAt,
      lastSeenAt: entities.lastSeenAt,
      alertCount: entities.alertCount,
      riskScore: entities.riskScore,
      createdAt: entities.createdAt,
      role: alertEntities.role,
    })
    .from(alertEntities)
    .innerJoin(entities, eq(alertEntities.entityId, entities.id))
    .where(eq(alertEntities.alertId, alertId));

  return results;
}

export async function getEntitiesForIncident(incidentId: string): Promise<(Entity & { role: string; alertId: string })[]> {
  const results = await db
    .select({
      id: entities.id,
      orgId: entities.orgId,
      type: entities.type,
      value: entities.value,
      displayName: entities.displayName,
      metadata: entities.metadata,
      firstSeenAt: entities.firstSeenAt,
      lastSeenAt: entities.lastSeenAt,
      alertCount: entities.alertCount,
      riskScore: entities.riskScore,
      createdAt: entities.createdAt,
      role: alertEntities.role,
      alertId: alertEntities.alertId,
    })
    .from(alerts)
    .innerJoin(alertEntities, eq(alertEntities.alertId, alerts.id))
    .innerJoin(entities, eq(alertEntities.entityId, entities.id))
    .where(eq(alerts.incidentId, incidentId));

  return results;
}

export async function findRelatedAlertsByEntity(alertId: string, orgId?: string | null, limit: number = 20): Promise<{ alertId: string; sharedEntities: string[] }[]> {
  const alertEntityRows = await db
    .select({ entityId: alertEntities.entityId })
    .from(alertEntities)
    .where(eq(alertEntities.alertId, alertId));

  if (alertEntityRows.length === 0) return [];

  const entityIds = alertEntityRows.map(r => r.entityId);

  const related = await db
    .select({
      alertId: alertEntities.alertId,
      entityValue: entities.value,
      entityType: entities.type,
    })
    .from(alertEntities)
    .innerJoin(entities, eq(alertEntities.entityId, entities.id))
    .where(
      and(
        inArray(alertEntities.entityId, entityIds),
        sql`${alertEntities.alertId} != ${alertId}`,
        orgId ? eq(entities.orgId, orgId) : sql`${entities.orgId} IS NULL`
      )
    )
    .limit(limit * 5);

  const groupedByAlert = new Map<string, string[]>();
  for (const r of related) {
    const existing = groupedByAlert.get(r.alertId) || [];
    existing.push(`${r.entityType}:${r.entityValue}`);
    groupedByAlert.set(r.alertId, existing);
  }

  return Array.from(groupedByAlert.entries())
    .map(([aid, shared]) => ({ alertId: aid, sharedEntities: shared }))
    .sort((a, b) => b.sharedEntities.length - a.sharedEntities.length)
    .slice(0, limit);
}

export async function getEntityGraph(orgId?: string): Promise<Entity[]> {
  const conditions = orgId ? eq(entities.orgId, orgId) : undefined;
  return db.select().from(entities).where(conditions).orderBy(desc(entities.riskScore)).limit(100);
}

export async function getEntity(id: string): Promise<Entity | undefined> {
  const [entity] = await db.select().from(entities).where(eq(entities.id, id));
  return entity;
}

export async function resolveEntityByAlias(aliasValue: string, orgId?: string | null): Promise<Entity | null> {
  const result = await db
    .select({ entity: entities })
    .from(entityAliases)
    .innerJoin(entities, eq(entityAliases.entityId, entities.id))
    .where(
      and(
        eq(entityAliases.aliasValue, aliasValue.toLowerCase()),
        orgId ? eq(entities.orgId, orgId) : sql`${entities.orgId} IS NULL`
      )
    )
    .limit(1);
  return result.length > 0 ? result[0].entity : null;
}

export async function addEntityAlias(entityId: string, aliasType: string, aliasValue: string, source?: string): Promise<EntityAlias> {
  const existing = await db.select().from(entityAliases)
    .where(and(
      eq(entityAliases.entityId, entityId),
      eq(entityAliases.aliasValue, aliasValue.toLowerCase())
    ))
    .limit(1);
  if (existing.length > 0) return existing[0];

  const [alias] = await db.insert(entityAliases).values({
    entityId,
    aliasType,
    aliasValue: aliasValue.toLowerCase(),
    source: source || "auto",
  }).returning();
  return alias;
}

export async function mergeEntities(targetId: string, sourceId: string): Promise<Entity> {
  return await db.transaction(async (tx) => {
    await tx.update(alertEntities)
      .set({ entityId: targetId })
      .where(eq(alertEntities.entityId, sourceId));

    await tx.update(entityAliases)
      .set({ entityId: targetId })
      .where(eq(entityAliases.entityId, sourceId));

    const [sourceEntity] = await tx.select().from(entities).where(eq(entities.id, sourceId)).limit(1);
    if (sourceEntity) {
      const existingAlias = await tx.select().from(entityAliases)
        .where(and(eq(entityAliases.entityId, targetId), eq(entityAliases.aliasValue, sourceEntity.value.toLowerCase())))
        .limit(1);
      if (existingAlias.length === 0) {
        await tx.insert(entityAliases).values({
          entityId: targetId,
          aliasType: sourceEntity.type,
          aliasValue: sourceEntity.value.toLowerCase(),
          source: "merge",
        });
      }
    }

    const [updated] = await tx.update(entities)
      .set({
        alertCount: sql`(SELECT COUNT(DISTINCT alert_id) FROM alert_entities WHERE entity_id = ${targetId})`,
        riskScore: sql`GREATEST(${entities.riskScore}, COALESCE((SELECT risk_score FROM entities WHERE id = ${sourceId}), 0))`,
        lastSeenAt: sql`GREATEST(${entities.lastSeenAt}, COALESCE((SELECT last_seen_at FROM entities WHERE id = ${sourceId}), NOW()))`,
      })
      .where(eq(entities.id, targetId))
      .returning();

    await tx.delete(entities).where(eq(entities.id, sourceId));

    return updated;
  });
}

export async function updateEntityMetadata(entityId: string, metadata: Record<string, any>): Promise<Entity> {
  const [updated] = await db.update(entities)
    .set({
      metadata: sql`COALESCE(${entities.metadata}, '{}'::jsonb) || ${JSON.stringify(metadata)}::jsonb`,
    })
    .where(eq(entities.id, entityId))
    .returning();
  return updated;
}

export async function getEntityAliases(entityId: string): Promise<EntityAlias[]> {
  return db.select().from(entityAliases)
    .where(eq(entityAliases.entityId, entityId))
    .orderBy(entityAliases.createdAt);
}

export async function getEntityRelationships(entityId: string): Promise<{
  relatedEntityId: string;
  relatedEntityType: string;
  relatedEntityValue: string;
  relatedEntityRiskScore: number;
  sharedAlertCount: number;
  relationship: string;
}[]> {
  const alertRows = await db.select({ alertId: alertEntities.alertId })
    .from(alertEntities)
    .where(eq(alertEntities.entityId, entityId));

  if (alertRows.length === 0) return [];

  const alertIds = alertRows.map(r => r.alertId);

  const related = await db
    .select({
      entityId: entities.id,
      entityType: entities.type,
      entityValue: entities.value,
      riskScore: entities.riskScore,
      alertId: alertEntities.alertId,
      role: alertEntities.role,
    })
    .from(alertEntities)
    .innerJoin(entities, eq(alertEntities.entityId, entities.id))
    .where(
      and(
        inArray(alertEntities.alertId, alertIds),
        sql`${alertEntities.entityId} != ${entityId}`
      )
    );

  const entityMap = new Map<string, {
    type: string;
    value: string;
    riskScore: number;
    alertIds: Set<string>;
    roles: Set<string>;
  }>();

  for (const r of related) {
    const existing = entityMap.get(r.entityId);
    if (existing) {
      existing.alertIds.add(r.alertId);
      existing.roles.add(r.role);
    } else {
      entityMap.set(r.entityId, {
        type: r.entityType,
        value: r.entityValue,
        riskScore: r.riskScore || 0,
        alertIds: new Set([r.alertId]),
        roles: new Set([r.role]),
      });
    }
  }

  return Array.from(entityMap.entries())
    .map(([id, data]) => ({
      relatedEntityId: id,
      relatedEntityType: data.type,
      relatedEntityValue: data.value,
      relatedEntityRiskScore: data.riskScore,
      sharedAlertCount: data.alertIds.size,
      relationship: inferRelationship(data.roles),
    }))
    .sort((a, b) => b.sharedAlertCount - a.sharedAlertCount);
}

function inferRelationship(roles: Set<string>): string {
  if (roles.has("source") && roles.has("target")) return "attack_path";
  if (roles.has("source") && roles.has("indicator")) return "uses";
  if (roles.has("target") && roles.has("indicator")) return "targeted_by";
  if (roles.has("subject")) return "associated_with";
  return "co_occurred";
}

export async function getEntityGraphWithEdges(orgId?: string, limit: number = 80): Promise<{
  nodes: (Entity & { connections: number })[];
  edges: { source: string; target: string; weight: number; relationship: string }[];
}> {
  const conditions = orgId ? eq(entities.orgId, orgId) : undefined;
  const topEntities = await db.select().from(entities)
    .where(conditions)
    .orderBy(desc(entities.riskScore))
    .limit(limit);

  if (topEntities.length === 0) return { nodes: [], edges: [] };

  const entityIds = topEntities.map(e => e.id);

  const links = await db.select({
    entityId: alertEntities.entityId,
    alertId: alertEntities.alertId,
    role: alertEntities.role,
  }).from(alertEntities)
    .where(inArray(alertEntities.entityId, entityIds));

  const alertToEntities = new Map<string, { entityId: string; role: string }[]>();
  for (const link of links) {
    const existing = alertToEntities.get(link.alertId) || [];
    existing.push({ entityId: link.entityId, role: link.role });
    alertToEntities.set(link.alertId, existing);
  }

  const edgeMap = new Map<string, { weight: number; roles: Set<string> }>();
  const connectionCount = new Map<string, number>();

  for (const [, entityList] of Array.from(alertToEntities.entries())) {
    for (let i = 0; i < entityList.length; i++) {
      for (let j = i + 1; j < entityList.length; j++) {
        const a = entityList[i];
        const b = entityList[j];
        const key = [a.entityId, b.entityId].sort().join(":");
        const existing = edgeMap.get(key);
        if (existing) {
          existing.weight++;
          existing.roles.add(a.role);
          existing.roles.add(b.role);
        } else {
          edgeMap.set(key, { weight: 1, roles: new Set([a.role, b.role]) });
        }
        connectionCount.set(a.entityId, (connectionCount.get(a.entityId) || 0) + 1);
        connectionCount.set(b.entityId, (connectionCount.get(b.entityId) || 0) + 1);
      }
    }
  }

  const edges = Array.from(edgeMap.entries()).map(([key, data]) => {
    const [source, target] = key.split(":");
    return {
      source,
      target,
      weight: data.weight,
      relationship: inferRelationship(data.roles),
    };
  });

  const nodes = topEntities.map(e => ({
    ...e,
    connections: connectionCount.get(e.id) || 0,
  }));

  return { nodes, edges };
}

export async function getEntityAlerts(entityId: string): Promise<Alert[]> {
  const results = await db
    .select({ alert: alerts })
    .from(alertEntities)
    .innerJoin(alerts, eq(alertEntities.alertId, alerts.id))
    .where(eq(alertEntities.entityId, entityId))
    .orderBy(desc(alerts.createdAt))
    .limit(50);

  return results.map(r => r.alert);
}
