/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { getOrgId, logger, p, storage } from "./shared";
import { db } from "../db";
import * as graphSnapshotStorage from "../storage/graph-snapshots";
import {
  entities,
  alertEntities,
  alerts,
  uebaEntityScores,
  incidents,
  attackPaths,
  entityAliases,
  entityMergeHistory,
} from "@shared/schema";
import { eq, and, sql, inArray, desc, ilike, or } from "drizzle-orm";
import { getEntityGraphWithEdges, mergeEntities, addEntityAlias } from "../entity-resolver";
import { broadcastEvent } from "../event-bus";

const log = logger.child("entity-graph-advanced");

// ═══════════════════════════════════════════════════════════════════════════
// 11.4: Path finding between two entities (BFS shortest path)
// ═══════════════════════════════════════════════════════════════════════════

interface PathNode {
  entityId: string;
  type: string;
  value: string;
  displayName: string | null;
  riskScore: number;
}

interface PathEdge {
  source: string;
  target: string;
  relationship: string;
  sharedAlertCount: number;
}

interface PathResult {
  found: boolean;
  path: PathNode[];
  edges: PathEdge[];
  hops: number;
  allPaths: { path: PathNode[]; edges: PathEdge[]; hops: number }[];
}

async function findPathBetweenEntities(
  orgId: string,
  sourceId: string,
  targetId: string,
  maxDepth: number = 6,
): Promise<PathResult> {
  // Build adjacency from alert co-occurrence
  const allEntities = await db.select().from(entities).where(eq(entities.orgId, orgId)).limit(500);

  const entityMap = new Map(allEntities.map((e) => [e.id, e]));
  if (!entityMap.has(sourceId) || !entityMap.has(targetId)) {
    return { found: false, path: [], edges: [], hops: 0, allPaths: [] };
  }

  const entityIds = allEntities.map((e) => e.id);
  if (entityIds.length === 0) {
    return { found: false, path: [], edges: [], hops: 0, allPaths: [] };
  }

  const links = await db
    .select({
      entityId: alertEntities.entityId,
      alertId: alertEntities.alertId,
    })
    .from(alertEntities)
    .where(inArray(alertEntities.entityId, entityIds));

  // Build alert-to-entities map
  const alertToEntities = new Map<string, string[]>();
  for (const link of links) {
    const existing = alertToEntities.get(link.alertId) || [];
    existing.push(link.entityId);
    alertToEntities.set(link.alertId, existing);
  }

  // Build adjacency map with edge weights
  const adjacency = new Map<string, Map<string, number>>();
  for (const [, entityList] of Array.from(alertToEntities.entries())) {
    for (let i = 0; i < entityList.length; i++) {
      for (let j = i + 1; j < entityList.length; j++) {
        const a = entityList[i];
        const b = entityList[j];

        if (!adjacency.has(a)) adjacency.set(a, new Map());
        if (!adjacency.has(b)) adjacency.set(b, new Map());

        adjacency.get(a)!.set(b, (adjacency.get(a)!.get(b) || 0) + 1);
        adjacency.get(b)!.set(a, (adjacency.get(b)!.get(a) || 0) + 1);
      }
    }
  }

  // BFS for all shortest paths
  const queue: { node: string; path: string[] }[] = [{ node: sourceId, path: [sourceId] }];
  const visited = new Set<string>([sourceId]);
  const allPaths: { path: PathNode[]; edges: PathEdge[]; hops: number }[] = [];
  let shortestLength = Infinity;

  while (queue.length > 0) {
    const current = queue.shift()!;

    if (current.path.length > maxDepth + 1) break;
    if (current.path.length > shortestLength) break;

    if (current.node === targetId) {
      shortestLength = current.path.length;
      const pathNodes: PathNode[] = current.path.map((id) => {
        const e = entityMap.get(id)!;
        return {
          entityId: e.id,
          type: e.type,
          value: e.value,
          displayName: e.displayName,
          riskScore: e.riskScore || 0,
        };
      });

      const pathEdges: PathEdge[] = [];
      for (let i = 0; i < current.path.length - 1; i++) {
        const src = current.path[i];
        const tgt = current.path[i + 1];
        const weight = adjacency.get(src)?.get(tgt) || 1;
        pathEdges.push({
          source: src,
          target: tgt,
          relationship: "co_occurred",
          sharedAlertCount: weight,
        });
      }

      allPaths.push({ path: pathNodes, edges: pathEdges, hops: current.path.length - 1 });
      continue;
    }

    const neighbors = adjacency.get(current.node);
    if (!neighbors) continue;

    for (const [neighbor] of Array.from(neighbors.entries())) {
      if (visited.has(neighbor) && neighbor !== targetId) continue;
      if (current.path.includes(neighbor)) continue;
      if (!visited.has(neighbor)) visited.add(neighbor);
      queue.push({ node: neighbor, path: [...current.path, neighbor] });
    }
  }

  if (allPaths.length === 0) {
    return { found: false, path: [], edges: [], hops: 0, allPaths: [] };
  }

  return {
    found: true,
    path: allPaths[0].path,
    edges: allPaths[0].edges,
    hops: allPaths[0].hops,
    allPaths: allPaths.slice(0, 5),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 11.6: Graph Query Language
// ═══════════════════════════════════════════════════════════════════════════

interface GraphQueryResult {
  entities: {
    id: string;
    type: string;
    value: string;
    displayName: string | null;
    riskScore: number;
    alertCount: number;
    connections: number;
  }[];
  totalMatched: number;
  query: string;
}

function parseGraphQuery(query: string): {
  entityType?: string;
  riskScoreMin?: number;
  riskScoreMax?: number;
  alertCountMin?: number;
  alertCountMax?: number;
  valuePattern?: string;
  connectedToType?: string;
  lastSeenDays?: number;
} {
  const result: ReturnType<typeof parseGraphQuery> = {};

  // FIND <EntityType>
  const findMatch = query.match(/FIND\s+(\w+)/i);
  if (findMatch) {
    const typeMap: Record<string, string> = {
      user: "user",
      users: "user",
      host: "host",
      hosts: "host",
      server: "host",
      servers: "host",
      ip: "ip",
      ips: "ip",
      domain: "domain",
      domains: "domain",
      email: "email",
      emails: "email",
      url: "url",
      urls: "url",
      file_hash: "file_hash",
      hash: "file_hash",
      hashes: "file_hash",
      process: "process",
      processes: "process",
    };
    result.entityType = typeMap[findMatch[1].toLowerCase()] || findMatch[1].toLowerCase();
  }

  // WHERE conditions
  const riskGt = query.match(/riskScore\s*>\s*(\d+(?:\.\d+)?)/i);
  if (riskGt) result.riskScoreMin = parseFloat(riskGt[1]) / 100;

  const riskLt = query.match(/riskScore\s*<\s*(\d+(?:\.\d+)?)/i);
  if (riskLt) result.riskScoreMax = parseFloat(riskLt[1]) / 100;

  const riskGte = query.match(/riskScore\s*>=\s*(\d+(?:\.\d+)?)/i);
  if (riskGte) result.riskScoreMin = parseFloat(riskGte[1]) / 100;

  const alertGt = query.match(/alertCount\s*>\s*(\d+)/i);
  if (alertGt) result.alertCountMin = parseInt(alertGt[1]);

  const alertGte = query.match(/alertCount\s*>=\s*(\d+)/i);
  if (alertGte) result.alertCountMin = parseInt(alertGte[1]);

  // value LIKE / CONTAINS
  const valueMatch = query.match(/value\s+(?:LIKE|CONTAINS)\s+['"]([^'"]+)['"]/i);
  if (valueMatch) result.valuePattern = valueMatch[1];

  // CONNECTED_TO <EntityType>
  const connMatch = query.match(/CONNECTED_TO\s+(\w+)/i);
  if (connMatch) {
    const typeMap: Record<string, string> = {
      user: "user",
      host: "host",
      server: "host",
      ip: "ip",
      domain: "domain",
    };
    result.connectedToType = typeMap[connMatch[1].toLowerCase()] || connMatch[1].toLowerCase();
  }

  // lastSeen < Nd
  const lastSeenMatch = query.match(/lastSeen\s*<\s*(\d+)d/i);
  if (lastSeenMatch) result.lastSeenDays = parseInt(lastSeenMatch[1]);

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// Route Registration
// ═══════════════════════════════════════════════════════════════════════════

export function registerEntityGraphAdvancedRoutes(app: Express): void {
  // 11.4: Path finding
  app.get(
    "/api/entity-graph/path",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const source = String(req.query.source || "");
        const target = String(req.query.target || "");
        const maxDepth = Math.min(parseInt(String(req.query.maxDepth || "6")), 10);

        if (!source || !target) {
          return res.status(400).json({ message: "source and target entity IDs are required" });
        }

        const result = await findPathBetweenEntities(orgId, source, target, maxDepth);
        res.json(result);
      } catch (error) {
        log.error("Path finding error", { error: String(error) });
        res.status(500).json({ message: "Failed to find path" });
      }
    },
  );

  // 11.5: Graph snapshot — save current state
  app.post(
    "/api/entity-graph/snapshots",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, description } = req.body;
        if (!name) return res.status(400).json({ message: "Snapshot name is required" });

        const graph = await getEntityGraphWithEdges(orgId, 200);
        const userId = (req as any).user?.id || "unknown";

        const graphData = {
          nodes: graph.nodes.map((n) => ({
            id: n.id,
            type: n.type,
            value: n.value,
            displayName: n.displayName,
            riskScore: n.riskScore,
            alertCount: n.alertCount,
            connections: n.connections,
          })),
          edges: graph.edges,
        };

        const snapshot = await graphSnapshotStorage.createGraphSnapshot({
          orgId,
          name: String(name).slice(0, 200),
          description: description ? String(description).slice(0, 500) : null,
          graphData,
          nodeCount: graph.nodes.length,
          edgeCount: graph.edges.length,
          createdBy: userId,
        });

        res.status(201).json({
          id: snapshot.id,
          name: snapshot.name,
          description: snapshot.description,
          nodeCount: snapshot.nodeCount,
          edgeCount: snapshot.edgeCount,
          createdBy: snapshot.createdBy,
          createdAt: snapshot.createdAt,
        });
      } catch (error) {
        log.error("Snapshot creation error", { error: String(error) });
        res.status(500).json({ message: "Failed to create snapshot" });
      }
    },
  );

  // 11.5: List snapshots
  app.get(
    "/api/entity-graph/snapshots",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const orgSnapshots = await graphSnapshotStorage.getGraphSnapshots(orgId);
        res.json(
          orgSnapshots.map((s) => ({
            id: s.id,
            name: s.name,
            description: s.description,
            nodeCount: s.nodeCount,
            edgeCount: s.edgeCount,
            createdBy: s.createdBy,
            createdAt: s.createdAt,
          })),
        );
      } catch (error) {
        res.status(500).json({ message: "Failed to list snapshots" });
      }
    },
  );

  // 11.5: Compare snapshot with current state
  app.get(
    "/api/entity-graph/snapshots/:id/compare",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const snapshotId = String(req.params.id);
        const snapshot = await graphSnapshotStorage.getGraphSnapshot(snapshotId);
        if (!snapshot || snapshot.orgId !== orgId) return res.status(404).json({ message: "Snapshot not found" });

        const snapshotData = (snapshot.graphData as any) || { nodes: [], edges: [] };
        const currentGraph = await getEntityGraphWithEdges(orgId, 200);

        const snapshotNodeIds = new Set(snapshotData.nodes.map((n: any) => n.id));
        const currentNodeIds = new Set(currentGraph.nodes.map((n) => n.id));

        const addedNodes = currentGraph.nodes
          .filter((n) => !snapshotNodeIds.has(n.id))
          .map((n) => ({
            id: n.id,
            type: n.type,
            value: n.value,
            displayName: n.displayName,
            riskScore: n.riskScore,
          }));

        const removedNodes = snapshotData.nodes
          .filter((n: any) => !currentNodeIds.has(n.id))
          .map((n: any) => ({
            id: n.id,
            type: n.type,
            value: n.value,
            displayName: n.displayName,
            riskScore: n.riskScore,
          }));

        const riskChanges: {
          entityId: string;
          value: string;
          type: string;
          oldRisk: number;
          newRisk: number;
          change: number;
        }[] = [];

        const snapshotNodeMap = new Map(snapshotData.nodes.map((n: any) => [n.id, n]));
        for (const currentNode of currentGraph.nodes) {
          const oldNode = snapshotNodeMap.get(currentNode.id) as any;
          if (!oldNode) continue;
          const oldRisk = oldNode.riskScore || 0;
          const newRisk = currentNode.riskScore || 0;
          if (Math.abs(newRisk - oldRisk) >= 0.05) {
            riskChanges.push({
              entityId: currentNode.id,
              value: currentNode.value,
              type: currentNode.type,
              oldRisk,
              newRisk,
              change: newRisk - oldRisk,
            });
          }
        }

        // Edge diff
        const snapshotEdgeKeys = new Set(snapshotData.edges.map((e: any) => [e.source, e.target].sort().join(":")));
        const currentEdgeKeys = new Set(currentGraph.edges.map((e) => [e.source, e.target].sort().join(":")));

        const addedEdgeCount = Array.from(currentEdgeKeys).filter((k) => !snapshotEdgeKeys.has(k)).length;
        const removedEdgeCount = Array.from(snapshotEdgeKeys).filter((k) => !currentEdgeKeys.has(k)).length;

        res.json({
          snapshotId: snapshot.id,
          snapshotName: snapshot.name,
          snapshotDate: snapshot.createdAt,
          summary: {
            nodesAdded: addedNodes.length,
            nodesRemoved: removedNodes.length,
            edgesAdded: addedEdgeCount,
            edgesRemoved: removedEdgeCount,
            riskChanges: riskChanges.length,
          },
          addedNodes,
          removedNodes,
          riskChanges: riskChanges.sort((a, b) => Math.abs(b.change) - Math.abs(a.change)).slice(0, 50),
        });
      } catch (error) {
        log.error("Snapshot comparison error", { error: String(error) });
        res.status(500).json({ message: "Failed to compare snapshot" });
      }
    },
  );

  // 11.6: Graph query language
  app.post(
    "/api/entity-graph/query",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const queryStr = String(req.body.query || "").trim();
        if (!queryStr) return res.status(400).json({ message: "Query string is required" });

        const parsed = parseGraphQuery(queryStr);
        const graph = await getEntityGraphWithEdges(orgId, 500);

        let filtered = graph.nodes;

        if (parsed.entityType) {
          filtered = filtered.filter((n) => n.type === parsed.entityType);
        }
        if (parsed.riskScoreMin !== undefined) {
          filtered = filtered.filter((n) => (n.riskScore || 0) >= parsed.riskScoreMin!);
        }
        if (parsed.riskScoreMax !== undefined) {
          filtered = filtered.filter((n) => (n.riskScore || 0) < parsed.riskScoreMax!);
        }
        if (parsed.alertCountMin !== undefined) {
          filtered = filtered.filter((n) => (n.alertCount || 0) >= parsed.alertCountMin!);
        }
        if (parsed.alertCountMax !== undefined) {
          filtered = filtered.filter((n) => (n.alertCount || 0) < parsed.alertCountMax!);
        }
        if (parsed.valuePattern) {
          const pattern = parsed.valuePattern.toLowerCase();
          filtered = filtered.filter(
            (n) => n.value.toLowerCase().includes(pattern) || (n.displayName || "").toLowerCase().includes(pattern),
          );
        }
        if (parsed.lastSeenDays !== undefined) {
          const cutoff = Date.now() - parsed.lastSeenDays * 24 * 60 * 60 * 1000;
          filtered = filtered.filter((n) => {
            const lastSeen = n.lastSeenAt ? new Date(n.lastSeenAt).getTime() : 0;
            return lastSeen >= cutoff;
          });
        }
        if (parsed.connectedToType) {
          const connectedType = parsed.connectedToType;
          const nodeIds = new Set(filtered.map((n) => n.id));
          const typeNodeIds = new Set(graph.nodes.filter((n) => n.type === connectedType).map((n) => n.id));
          const connectedNodeIds = new Set<string>();

          for (const edge of graph.edges) {
            if (nodeIds.has(edge.source) && typeNodeIds.has(edge.target)) {
              connectedNodeIds.add(edge.source);
            }
            if (nodeIds.has(edge.target) && typeNodeIds.has(edge.source)) {
              connectedNodeIds.add(edge.target);
            }
          }

          filtered = filtered.filter((n) => connectedNodeIds.has(n.id));
        }

        const result: GraphQueryResult = {
          entities: filtered.slice(0, 100).map((n) => ({
            id: n.id,
            type: n.type,
            value: n.value,
            displayName: n.displayName,
            riskScore: n.riskScore || 0,
            alertCount: n.alertCount || 0,
            connections: n.connections || 0,
          })),
          totalMatched: filtered.length,
          query: queryStr,
        };

        res.json(result);
      } catch (error) {
        log.error("Graph query error", { error: String(error) });
        res.status(500).json({ message: "Failed to execute graph query" });
      }
    },
  );

  // 11.8: Create incident from graph subgraph
  app.post(
    "/api/entity-graph/create-incident",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { title, severity, entityIds, description } = req.body;

        if (!title || !severity || !entityIds || !Array.isArray(entityIds) || entityIds.length === 0) {
          return res.status(400).json({ message: "title, severity, and entityIds[] are required" });
        }

        const validSeverities = ["critical", "high", "medium", "low"];
        if (!validSeverities.includes(severity)) {
          return res.status(400).json({ message: `severity must be one of: ${validSeverities.join(", ")}` });
        }

        // Get entities to include as affected resources
        const selectedEntities = await db
          .select()
          .from(entities)
          .where(and(eq(entities.orgId, orgId), inArray(entities.id, entityIds.map(String))));

        if (selectedEntities.length === 0) {
          return res.status(404).json({ message: "No matching entities found in your org" });
        }

        // Find alerts linked to these entities
        const linkedAlerts = await db
          .select({ alertId: alertEntities.alertId })
          .from(alertEntities)
          .where(
            inArray(
              alertEntities.entityId,
              selectedEntities.map((e) => e.id),
            ),
          );

        const uniqueAlertIds = Array.from(new Set(linkedAlerts.map((l) => l.alertId)));

        // Build affected resources description
        const affectedResources = selectedEntities.map((e) => ({
          type: e.type,
          value: e.value,
          displayName: e.displayName,
          riskScore: e.riskScore,
        }));

        const userId = (req as any).user?.id || null;

        const incident = await storage.createIncident({
          orgId,
          title: String(title).slice(0, 500),
          summary:
            (description ? String(description).slice(0, 2000) + "\n\n" : "") +
            `Created from Entity Graph — ${selectedEntities.length} entities selected.\n` +
            `Affected: ${affectedResources.map((r) => `${r.type}:${r.value}`).join(", ")}`,
          severity,
          status: "open",
          assignedTo: userId,
        });

        // Link alerts to the incident
        if (uniqueAlertIds.length > 0) {
          await db
            .update(alerts)
            .set({ incidentId: incident.id })
            .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, uniqueAlertIds.slice(0, 100))));
        }

        broadcastEvent({
          type: "incident:created",
          orgId,
          data: { incidentId: incident.id, title: incident.title, source: "entity_graph" },
        });

        res.status(201).json({
          incident,
          linkedAlertCount: uniqueAlertIds.length,
          affectedResources,
        });
      } catch (error) {
        log.error("Create incident from graph error", { error: String(error) });
        res.status(500).json({ message: "Failed to create incident from graph" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 13.2: Entity search with type-ahead
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/search/typeahead",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const q = String(req.query.q || "").trim();
        if (!q || q.length < 2) {
          return res.json({ suggestions: [], recentSearches: [] });
        }

        const pattern = `%${q}%`;
        const matches = await db
          .select({
            id: entities.id,
            type: entities.type,
            value: entities.value,
            displayName: entities.displayName,
            riskScore: entities.riskScore,
            alertCount: entities.alertCount,
            lastSeenAt: entities.lastSeenAt,
          })
          .from(entities)
          .where(
            and(eq(entities.orgId, orgId), or(ilike(entities.value, pattern), ilike(entities.displayName, pattern))),
          )
          .orderBy(desc(entities.riskScore))
          .limit(15);

        // Group by type for categorized results
        const byType: Record<string, typeof matches> = {};
        for (const m of matches) {
          if (!byType[m.type]) byType[m.type] = [];
          byType[m.type].push(m);
        }

        res.json({
          suggestions: matches.map((m) => ({
            id: m.id,
            type: m.type,
            value: m.value,
            displayName: m.displayName,
            riskScore: m.riskScore || 0,
            alertCount: m.alertCount || 0,
            lastSeenAt: m.lastSeenAt,
          })),
          groupedByType: byType,
          totalMatched: matches.length,
        });
      } catch (error) {
        log.error("Typeahead search error", { error: String(error) });
        res.status(500).json({ message: "Failed to search entities" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 13.3: Entity risk scoring (dynamic, multi-factor)
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/:id/risk-score",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = p(req.params.id);

        const [entity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, entityId), eq(entities.orgId, orgId)));

        if (!entity) return res.status(404).json({ message: "Entity not found" });

        // Factor 1: Alert severity (0.30 weight)
        const entityAlertLinks = await db
          .select({ alertId: alertEntities.alertId })
          .from(alertEntities)
          .where(eq(alertEntities.entityId, entityId));

        const alertIds = entityAlertLinks.map((l) => l.alertId);
        let alertSeverityScore = 0;
        const severityBreakdown: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

        if (alertIds.length > 0) {
          const entityAlerts = await db
            .select({ severity: alerts.severity })
            .from(alerts)
            .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds.slice(0, 200))));

          for (const a of entityAlerts) {
            const sev = (a.severity || "low").toLowerCase();
            severityBreakdown[sev] = (severityBreakdown[sev] || 0) + 1;
            if (sev === "critical") alertSeverityScore += 1.0;
            else if (sev === "high") alertSeverityScore += 0.75;
            else if (sev === "medium") alertSeverityScore += 0.4;
            else alertSeverityScore += 0.1;
          }
          alertSeverityScore = Math.min(alertSeverityScore / Math.max(entityAlerts.length, 1), 1.0);
        }

        // Factor 2: UEBA anomaly score (0.25 weight)
        let uebaScore = 0;
        const [uebaRecord] = await db
          .select()
          .from(uebaEntityScores)
          .where(
            and(
              eq(uebaEntityScores.orgId, orgId),
              eq(uebaEntityScores.entityId, entity.value),
              eq(uebaEntityScores.entityType, entity.type),
            ),
          )
          .limit(1);

        if (uebaRecord) {
          uebaScore = (uebaRecord.riskScore || 0) / 100;
        }

        // Factor 3: Exposure level (0.15 weight) — based on connections count
        const graph = await getEntityGraphWithEdges(orgId, 200);
        const entityNode = graph.nodes.find((n) => n.id === entityId);
        const connectionCount = entityNode?.connections || 0;
        const exposureScore = Math.min(connectionCount / 20, 1.0);

        // Factor 4: Privilege level (0.15 weight) — inferred from entity type and metadata
        let privilegeScore = 0;
        const meta = (entity.metadata || {}) as Record<string, any>;
        if (entity.type === "user") {
          if (meta.isAdmin || meta.privileged || meta.role === "admin") privilegeScore = 1.0;
          else if (meta.role === "manager" || meta.department === "IT") privilegeScore = 0.6;
          else privilegeScore = 0.2;
        } else if (entity.type === "host" || entity.type === "ip") {
          if (meta.isServer || meta.isCritical || meta.classification === "critical") privilegeScore = 0.9;
          else if (meta.isInternal) privilegeScore = 0.4;
          else privilegeScore = 0.3;
        } else {
          privilegeScore = 0.2;
        }

        // Factor 5: Access patterns / recency (0.15 weight)
        const now = Date.now();
        const lastSeen = entity.lastSeenAt ? new Date(entity.lastSeenAt).getTime() : 0;
        const firstSeen = entity.firstSeenAt ? new Date(entity.firstSeenAt).getTime() : now;
        const daysSinceLastSeen = lastSeen > 0 ? (now - lastSeen) / (24 * 60 * 60 * 1000) : 999;
        const activeSpanDays = (now - firstSeen) / (24 * 60 * 60 * 1000);
        let accessPatternScore = 0;
        if (daysSinceLastSeen < 1) accessPatternScore = 1.0;
        else if (daysSinceLastSeen < 7) accessPatternScore = 0.7;
        else if (daysSinceLastSeen < 30) accessPatternScore = 0.4;
        else accessPatternScore = 0.1;

        // Weighted composite score
        const weights = {
          alertSeverity: 0.3,
          uebaAnomaly: 0.25,
          exposure: 0.15,
          privilege: 0.15,
          accessPattern: 0.15,
        };

        const compositeScore =
          alertSeverityScore * weights.alertSeverity +
          uebaScore * weights.uebaAnomaly +
          exposureScore * weights.exposure +
          privilegeScore * weights.privilege +
          accessPatternScore * weights.accessPattern;

        const riskLevel =
          compositeScore >= 0.8
            ? "critical"
            : compositeScore >= 0.6
              ? "high"
              : compositeScore >= 0.4
                ? "medium"
                : "low";

        // Peer comparison — same-type entities
        const peerEntities = await db
          .select({ id: entities.id, riskScore: entities.riskScore })
          .from(entities)
          .where(and(eq(entities.orgId, orgId), eq(entities.type, entity.type)))
          .limit(200);

        const peerScores = peerEntities.map((pe) => pe.riskScore || 0).sort((a, b) => a - b);
        const percentile =
          peerScores.length > 0
            ? Math.round((peerScores.filter((s) => s <= compositeScore).length / peerScores.length) * 100)
            : 50;

        res.json({
          entityId: entity.id,
          entityType: entity.type,
          entityValue: entity.value,
          compositeScore: Math.round(compositeScore * 100) / 100,
          riskLevel,
          factors: {
            alertSeverity: {
              score: Math.round(alertSeverityScore * 100) / 100,
              weight: weights.alertSeverity,
              breakdown: severityBreakdown,
            },
            uebaAnomaly: {
              score: Math.round(uebaScore * 100) / 100,
              weight: weights.uebaAnomaly,
              anomalyCount: uebaRecord?.anomalyCount || 0,
            },
            exposure: { score: Math.round(exposureScore * 100) / 100, weight: weights.exposure, connectionCount },
            privilege: { score: Math.round(privilegeScore * 100) / 100, weight: weights.privilege },
            accessPattern: {
              score: Math.round(accessPatternScore * 100) / 100,
              weight: weights.accessPattern,
              daysSinceLastSeen: Math.round(daysSinceLastSeen),
              activeSpanDays: Math.round(activeSpanDays),
            },
          },
          peerComparison: {
            percentile,
            totalPeers: peerScores.length,
            avgPeerRisk:
              peerScores.length > 0
                ? Math.round((peerScores.reduce((a, b) => a + b, 0) / peerScores.length) * 100) / 100
                : 0,
          },
          firstSeenAt: entity.firstSeenAt,
          lastSeenAt: entity.lastSeenAt,
          totalAlerts: alertIds.length,
        });
      } catch (error) {
        log.error("Entity risk scoring error", { error: String(error) });
        res.status(500).json({ message: "Failed to compute entity risk score" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 13.5: Entity deduplication suggestions
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/dedup-suggestions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const allEntities = await db.select().from(entities).where(eq(entities.orgId, orgId)).limit(500);

        const suggestions: {
          entity1: { id: string; type: string; value: string; displayName: string | null };
          entity2: { id: string; type: string; value: string; displayName: string | null };
          reason: string;
          confidence: number;
        }[] = [];

        // Check for duplicate patterns within the same type
        const byType: Record<string, typeof allEntities> = {};
        for (const e of allEntities) {
          if (!byType[e.type]) byType[e.type] = [];
          byType[e.type].push(e);
        }

        for (const [, typeEntities] of Object.entries(byType)) {
          for (let i = 0; i < typeEntities.length && i < 100; i++) {
            for (let j = i + 1; j < typeEntities.length && j < 100; j++) {
              const e1 = typeEntities[i];
              const e2 = typeEntities[j];

              let reason = "";
              let confidence = 0;

              const v1 = e1.value.toLowerCase().trim();
              const v2 = e2.value.toLowerCase().trim();

              // Exact match after normalization
              if (v1 === v2) {
                reason = "Identical values after normalization";
                confidence = 95;
              }
              // Email domain variations (john@company.com vs john@company.co.uk)
              else if (e1.type === "email" && e2.type === "email") {
                const [user1] = v1.split("@");
                const [user2] = v2.split("@");
                if (user1 === user2) {
                  reason = "Same email username, different domain";
                  confidence = 75;
                }
              }
              // User format variations (john.doe vs jdoe vs john_doe)
              else if (e1.type === "user") {
                const norm1 = v1.replace(/[._-]/g, "");
                const norm2 = v2.replace(/[._-]/g, "");
                if (norm1 === norm2) {
                  reason = "Same username after removing separators";
                  confidence = 80;
                } else if (v1.includes(v2) || v2.includes(v1)) {
                  reason = "One value is a substring of the other";
                  confidence = 60;
                }
              }
              // IP notation variations (leading zeros, IPv4-mapped IPv6)
              else if (e1.type === "ip") {
                const stripLeadingZeros = (ip: string) => ip.replace(/\b0+(\d)/g, "$1");
                if (stripLeadingZeros(v1) === stripLeadingZeros(v2)) {
                  reason = "Same IP after removing leading zeros";
                  confidence = 90;
                }
                // IPv4-mapped IPv6 (::ffff:192.168.1.1 vs 192.168.1.1)
                else if (v1.replace("::ffff:", "") === v2 || v2.replace("::ffff:", "") === v1) {
                  reason = "IPv4-mapped IPv6 match";
                  confidence = 85;
                }
              }
              // Domain variations (www.example.com vs example.com)
              else if (e1.type === "domain") {
                const strip = (d: string) => d.replace(/^www\./, "").replace(/\.$/, "");
                if (strip(v1) === strip(v2)) {
                  reason = "Same domain after stripping www prefix";
                  confidence = 90;
                }
              }
              // DisplayName match with different values
              else if (
                e1.displayName &&
                e2.displayName &&
                e1.displayName.toLowerCase() === e2.displayName.toLowerCase() &&
                v1 !== v2
              ) {
                reason = "Same display name, different values";
                confidence = 65;
              }

              if (reason && confidence >= 60) {
                suggestions.push({
                  entity1: { id: e1.id, type: e1.type, value: e1.value, displayName: e1.displayName },
                  entity2: { id: e2.id, type: e2.type, value: e2.value, displayName: e2.displayName },
                  reason,
                  confidence,
                });
              }
            }
          }
        }

        // Sort by confidence descending
        suggestions.sort((a, b) => b.confidence - a.confidence);

        res.json({
          suggestions: suggestions.slice(0, 50),
          totalFound: suggestions.length,
        });
      } catch (error) {
        log.error("Dedup suggestions error", { error: String(error) });
        res.status(500).json({ message: "Failed to find dedup suggestions" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 13.1: Entity profile — rich detail page data
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/:id/profile",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = p(req.params.id);

        const [entity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, entityId), eq(entities.orgId, orgId)));

        if (!entity) return res.status(404).json({ message: "Entity not found" });

        // Get all alerts for this entity with timeline info
        const entityAlertLinks = await db
          .select({ alertId: alertEntities.alertId })
          .from(alertEntities)
          .where(eq(alertEntities.entityId, entityId));

        const alertIds = entityAlertLinks.map((l) => l.alertId);
        let activityTimeline: { date: string; alertCount: number; maxSeverity: string }[] = [];
        const alertsByStatus: Record<string, number> = {};
        const alertsBySeverity: Record<string, number> = {};

        if (alertIds.length > 0) {
          const entityAlerts = await db
            .select()
            .from(alerts)
            .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds.slice(0, 500))))
            .orderBy(desc(alerts.createdAt));

          // Build activity timeline (daily buckets)
          const dailyMap = new Map<string, { count: number; maxSev: string }>();
          const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

          for (const a of entityAlerts) {
            const day = a.createdAt ? new Date(a.createdAt).toISOString().slice(0, 10) : "unknown";
            const sev = (a.severity || "low").toLowerCase();
            const existing = dailyMap.get(day) || { count: 0, maxSev: "low" };
            existing.count++;
            if ((sevOrder[sev] || 0) > (sevOrder[existing.maxSev] || 0)) existing.maxSev = sev;
            dailyMap.set(day, existing);

            // Status breakdown
            const status = a.status || "open";
            alertsByStatus[status] = (alertsByStatus[status] || 0) + 1;
            alertsBySeverity[sev] = (alertsBySeverity[sev] || 0) + 1;
          }

          activityTimeline = Array.from(dailyMap.entries())
            .map(([date, data]) => ({ date, alertCount: data.count, maxSeverity: data.maxSev }))
            .sort((a, b) => a.date.localeCompare(b.date))
            .slice(-90); // Last 90 days
        }

        // Get aliases
        const aliases = await db.select().from(entityAliases).where(eq(entityAliases.entityId, entityId));

        // Get associated incidents
        let associatedIncidents: {
          id: string;
          title: string;
          severity: string;
          status: string;
          createdAt: Date | null;
        }[] = [];
        if (alertIds.length > 0) {
          const incidentAlerts = await db
            .select({ incidentId: alerts.incidentId })
            .from(alerts)
            .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds.slice(0, 200))))
            .limit(200);

          const incidentIds = Array.from(new Set(incidentAlerts.map((a) => a.incidentId).filter(Boolean) as string[]));

          if (incidentIds.length > 0) {
            associatedIncidents = await db
              .select({
                id: incidents.id,
                title: incidents.title,
                severity: incidents.severity,
                status: incidents.status,
                createdAt: incidents.createdAt,
              })
              .from(incidents)
              .where(and(eq(incidents.orgId, orgId), inArray(incidents.id, incidentIds.slice(0, 50))));
          }
        }

        // Get associated attack paths
        const orgAttackPaths = await db.select().from(attackPaths).where(eq(attackPaths.orgId, orgId)).limit(100);

        const relatedPaths = orgAttackPaths.filter((ap) => {
          const nodes = (ap.nodes || []) as Array<{ data?: { id?: string; value?: string } }>;
          return nodes.some((n) => n.data?.id === entityId || n.data?.value === entity.value);
        });

        // Peer comparison
        const peerEntities = await db
          .select({ id: entities.id, value: entities.value, riskScore: entities.riskScore })
          .from(entities)
          .where(and(eq(entities.orgId, orgId), eq(entities.type, entity.type)))
          .orderBy(desc(entities.riskScore))
          .limit(50);

        const entityRank = peerEntities.findIndex((pe) => pe.id === entityId) + 1;

        res.json({
          entity: {
            id: entity.id,
            type: entity.type,
            value: entity.value,
            displayName: entity.displayName,
            riskScore: entity.riskScore || 0,
            alertCount: entity.alertCount || 0,
            metadata: entity.metadata,
            firstSeenAt: entity.firstSeenAt,
            lastSeenAt: entity.lastSeenAt,
            createdAt: entity.createdAt,
          },
          aliases: aliases.map((a) => ({
            id: a.id,
            aliasType: a.aliasType,
            aliasValue: a.aliasValue,
            source: a.source,
          })),
          activityTimeline,
          alertBreakdown: { byStatus: alertsByStatus, bySeverity: alertsBySeverity, total: alertIds.length },
          associatedIncidents,
          associatedAttackPaths: relatedPaths.map((ap) => ({
            id: ap.id,
            name: ap.campaignId || ap.clusterId || ap.id,
            severity:
              ap.confidence >= 0.8
                ? "critical"
                : ap.confidence >= 0.6
                  ? "high"
                  : ap.confidence >= 0.4
                    ? "medium"
                    : "low",
            status: ap.lastAlertAt ? "active" : "historical",
          })),
          peerComparison: {
            rank: entityRank,
            totalPeers: peerEntities.length,
            topPeers: peerEntities.slice(0, 5).map((pe) => ({
              id: pe.id,
              value: pe.value,
              riskScore: pe.riskScore || 0,
            })),
          },
        });
      } catch (error) {
        log.error("Entity profile error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch entity profile" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 13.6: Entity → Alert/Incident pivot
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/:id/pivot",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = p(req.params.id);

        const [entity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, entityId), eq(entities.orgId, orgId)));

        if (!entity) return res.status(404).json({ message: "Entity not found" });

        // Get all alerts linked to this entity
        const entityAlertLinks = await db
          .select({ alertId: alertEntities.alertId })
          .from(alertEntities)
          .where(eq(alertEntities.entityId, entityId));

        const alertIds = entityAlertLinks.map((l) => l.alertId);

        let pivotAlerts: {
          id: string;
          title: string;
          severity: string;
          status: string;
          source: string | null;
          createdAt: Date | null;
          incidentId: string | null;
        }[] = [];

        if (alertIds.length > 0) {
          pivotAlerts = await db
            .select({
              id: alerts.id,
              title: alerts.title,
              severity: alerts.severity,
              status: alerts.status,
              source: alerts.source,
              createdAt: alerts.createdAt,
              incidentId: alerts.incidentId,
            })
            .from(alerts)
            .where(and(eq(alerts.orgId, orgId), inArray(alerts.id, alertIds.slice(0, 200))))
            .orderBy(desc(alerts.createdAt));
        }

        // Get unique incidents from alerts
        const incidentIds = Array.from(new Set(pivotAlerts.map((a) => a.incidentId).filter(Boolean) as string[]));

        let pivotIncidents: {
          id: string;
          title: string;
          severity: string;
          status: string;
          createdAt: Date | null;
          alertCount: number;
        }[] = [];

        if (incidentIds.length > 0) {
          const incidentRows = await db
            .select({
              id: incidents.id,
              title: incidents.title,
              severity: incidents.severity,
              status: incidents.status,
              createdAt: incidents.createdAt,
            })
            .from(incidents)
            .where(and(eq(incidents.orgId, orgId), inArray(incidents.id, incidentIds.slice(0, 50))));

          pivotIncidents = incidentRows.map((inc) => ({
            ...inc,
            alertCount: pivotAlerts.filter((a) => a.incidentId === inc.id).length,
          }));
        }

        res.json({
          entityId: entity.id,
          entityType: entity.type,
          entityValue: entity.value,
          alerts: pivotAlerts,
          incidents: pivotIncidents,
          summary: {
            totalAlerts: pivotAlerts.length,
            totalIncidents: pivotIncidents.length,
            openAlerts: pivotAlerts.filter((a) => a.status === "open" || a.status === "new").length,
            criticalAlerts: pivotAlerts.filter((a) => a.severity === "critical").length,
            activeIncidents: pivotIncidents.filter((i) => i.status === "open" || i.status === "investigating").length,
          },
        });
      } catch (error) {
        log.error("Entity pivot error", { error: String(error) });
        res.status(500).json({ message: "Failed to get entity pivot data" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 13.7: Entity → Threat Hunting pivot (pre-populated query)
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/:id/hunt-query",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = p(req.params.id);

        const [entity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, entityId), eq(entities.orgId, orgId)));

        if (!entity) return res.status(404).json({ message: "Entity not found" });

        // Build hunting queries based on entity type
        const queries: { name: string; query: string; description: string; dataSource: string }[] = [];

        switch (entity.type) {
          case "user":
            queries.push(
              {
                name: "All user activity",
                query: `SELECT * FROM logs WHERE user = '${entity.value}' ORDER BY timestamp DESC LIMIT 1000`,
                description: `Find all activity for user ${entity.value}`,
                dataSource: "auth_logs",
              },
              {
                name: "Failed logins",
                query: `SELECT * FROM auth_logs WHERE user = '${entity.value}' AND action = 'login_failed' ORDER BY timestamp DESC`,
                description: "Find failed authentication attempts",
                dataSource: "auth_logs",
              },
              {
                name: "Privilege escalation",
                query: `SELECT * FROM logs WHERE user = '${entity.value}' AND (action LIKE '%admin%' OR action LIKE '%privilege%' OR action LIKE '%sudo%')`,
                description: "Detect privilege escalation attempts",
                dataSource: "all_logs",
              },
              {
                name: "Off-hours activity",
                query: `SELECT * FROM logs WHERE user = '${entity.value}' AND (EXTRACT(HOUR FROM timestamp) < 6 OR EXTRACT(HOUR FROM timestamp) > 22)`,
                description: "Find activity outside business hours",
                dataSource: "all_logs",
              },
            );
            break;
          case "ip":
            queries.push(
              {
                name: "All connections",
                query: `SELECT * FROM network_logs WHERE src_ip = '${entity.value}' OR dst_ip = '${entity.value}' ORDER BY timestamp DESC LIMIT 1000`,
                description: `All network connections involving ${entity.value}`,
                dataSource: "network_logs",
              },
              {
                name: "Port scanning",
                query: `SELECT dst_port, COUNT(*) as cnt FROM network_logs WHERE src_ip = '${entity.value}' GROUP BY dst_port HAVING cnt > 10 ORDER BY cnt DESC`,
                description: "Detect port scanning behavior",
                dataSource: "network_logs",
              },
              {
                name: "Data exfiltration",
                query: `SELECT * FROM network_logs WHERE src_ip = '${entity.value}' AND bytes_out > 10000000 ORDER BY bytes_out DESC`,
                description: "Find large data transfers",
                dataSource: "network_logs",
              },
              {
                name: "C2 beaconing",
                query: `SELECT dst_ip, COUNT(*) as cnt, AVG(EXTRACT(EPOCH FROM timestamp - LAG(timestamp) OVER(ORDER BY timestamp))) as avg_interval FROM network_logs WHERE src_ip = '${entity.value}' GROUP BY dst_ip HAVING cnt > 50`,
                description: "Detect regular beaconing patterns",
                dataSource: "network_logs",
              },
            );
            break;
          case "domain":
            queries.push(
              {
                name: "DNS lookups",
                query: `SELECT * FROM dns_logs WHERE query_name = '${entity.value}' OR query_name LIKE '%.${entity.value}' ORDER BY timestamp DESC LIMIT 1000`,
                description: `All DNS queries for ${entity.value}`,
                dataSource: "dns_logs",
              },
              {
                name: "HTTP requests",
                query: `SELECT * FROM proxy_logs WHERE host = '${entity.value}' ORDER BY timestamp DESC LIMIT 1000`,
                description: "All HTTP/HTTPS traffic to this domain",
                dataSource: "proxy_logs",
              },
              {
                name: "Subdomain enumeration",
                query: `SELECT DISTINCT query_name FROM dns_logs WHERE query_name LIKE '%.${entity.value}' ORDER BY query_name`,
                description: "List all observed subdomains",
                dataSource: "dns_logs",
              },
            );
            break;
          case "file_hash":
            queries.push(
              {
                name: "File executions",
                query: `SELECT * FROM process_logs WHERE file_hash = '${entity.value}' ORDER BY timestamp DESC`,
                description: `All executions of file with hash ${entity.value.slice(0, 16)}...`,
                dataSource: "endpoint_logs",
              },
              {
                name: "File downloads",
                query: `SELECT * FROM proxy_logs WHERE response_hash = '${entity.value}' ORDER BY timestamp DESC`,
                description: "Find where this file was downloaded from",
                dataSource: "proxy_logs",
              },
              {
                name: "Lateral movement",
                query: `SELECT DISTINCT hostname FROM process_logs WHERE file_hash = '${entity.value}'`,
                description: "Find all hosts where this file appeared",
                dataSource: "endpoint_logs",
              },
            );
            break;
          case "host":
            queries.push(
              {
                name: "All host activity",
                query: `SELECT * FROM logs WHERE hostname = '${entity.value}' ORDER BY timestamp DESC LIMIT 1000`,
                description: `All activity on host ${entity.value}`,
                dataSource: "all_logs",
              },
              {
                name: "Process creation",
                query: `SELECT * FROM process_logs WHERE hostname = '${entity.value}' AND event_type = 'process_create' ORDER BY timestamp DESC LIMIT 500`,
                description: "Recent process creation events",
                dataSource: "endpoint_logs",
              },
              {
                name: "Network connections",
                query: `SELECT * FROM network_logs WHERE hostname = '${entity.value}' ORDER BY timestamp DESC LIMIT 500`,
                description: "Network connections from this host",
                dataSource: "network_logs",
              },
            );
            break;
          default:
            queries.push({
              name: "Search all sources",
              query: `SELECT * FROM logs WHERE value = '${entity.value}' ORDER BY timestamp DESC LIMIT 1000`,
              description: `Search for ${entity.value} across all data sources`,
              dataSource: "all_logs",
            });
        }

        // Also build a graph query
        const graphQuery = `FIND ${entity.type.charAt(0).toUpperCase() + entity.type.slice(1)} WHERE value CONTAINS "${entity.value}"`;

        res.json({
          entityId: entity.id,
          entityType: entity.type,
          entityValue: entity.value,
          huntQueries: queries,
          graphQuery,
          huntUrl: `/threat-hunting?entity=${encodeURIComponent(entity.value)}&type=${entity.type}`,
        });
      } catch (error) {
        log.error("Entity hunt query error", { error: String(error) });
        res.status(500).json({ message: "Failed to generate hunt queries" });
      }
    },
  );

  // 11.9: UEBA anomaly overlay for graph nodes
  app.get(
    "/api/entity-graph/ueba-overlay",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        // Get all UEBA entity scores for this org
        const scores = await db
          .select()
          .from(uebaEntityScores)
          .where(eq(uebaEntityScores.orgId, orgId))
          .orderBy(desc(uebaEntityScores.riskScore))
          .limit(500);

        // Map UEBA entity IDs to graph entity IDs
        // UEBA uses entityId (e.g. username, hostname) while graph uses UUID
        // We need to match on value
        const uebaMap = new Map<
          string,
          { riskScore: number; riskLevel: string; anomalyCount: number; entityType: string }
        >();
        for (const score of scores) {
          // Key by entityId (which is the entity value in UEBA)
          uebaMap.set(`${score.entityType}:${score.entityId}`, {
            riskScore: score.riskScore || 0,
            riskLevel: score.riskLevel || "none",
            anomalyCount: score.anomalyCount || 0,
            entityType: score.entityType,
          });
        }

        // Get graph entities and match
        const graphEntities = await db
          .select({ id: entities.id, type: entities.type, value: entities.value })
          .from(entities)
          .where(eq(entities.orgId, orgId))
          .limit(500);

        const overlay: Record<string, { uebaRiskScore: number; uebaRiskLevel: string; anomalyCount: number }> = {};

        for (const entity of graphEntities) {
          const key = `${entity.type}:${entity.value}`;
          const uebaData = uebaMap.get(key);
          if (uebaData && uebaData.riskScore > 0) {
            overlay[entity.id] = {
              uebaRiskScore: uebaData.riskScore,
              uebaRiskLevel: uebaData.riskLevel,
              anomalyCount: uebaData.anomalyCount,
            };
          }
        }

        res.json({ overlay, totalScored: Object.keys(overlay).length });
      } catch (error) {
        log.error("UEBA overlay error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch UEBA overlay" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 14.1: Merge preview — side-by-side comparison
  // ═══════════════════════════════════════════════════════════════════════

  app.post(
    "/api/entities/merge-preview",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { sourceId, targetId } = req.body;
        if (!sourceId || !targetId) return res.status(400).json({ message: "sourceId and targetId required" });

        const [sourceEntity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, sourceId), eq(entities.orgId, orgId)));
        const [targetEntity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, targetId), eq(entities.orgId, orgId)));

        if (!sourceEntity) return res.status(404).json({ message: "Source entity not found" });
        if (!targetEntity) return res.status(404).json({ message: "Target entity not found" });

        // Get alert counts for each
        const sourceAlertLinks = await db
          .select({ alertId: alertEntities.alertId })
          .from(alertEntities)
          .where(eq(alertEntities.entityId, sourceId));
        const targetAlertLinks = await db
          .select({ alertId: alertEntities.alertId })
          .from(alertEntities)
          .where(eq(alertEntities.entityId, targetId));

        // Get aliases for each
        const sourceAliases = await db.select().from(entityAliases).where(eq(entityAliases.entityId, sourceId));
        const targetAliases = await db.select().from(entityAliases).where(eq(entityAliases.entityId, targetId));

        // Compute field-level conflicts
        const fields = ["displayName", "type", "value", "riskScore", "metadata", "firstSeenAt", "lastSeenAt"] as const;

        const comparison: {
          field: string;
          sourceValue: unknown;
          targetValue: unknown;
          hasConflict: boolean;
          suggestedResolution: "source" | "target" | "merge";
        }[] = [];

        for (const field of fields) {
          const sv = sourceEntity[field];
          const tv = targetEntity[field];
          const svStr = JSON.stringify(sv);
          const tvStr = JSON.stringify(tv);
          const hasConflict = svStr !== tvStr;

          let suggestedResolution: "source" | "target" | "merge" = "target";
          if (field === "riskScore") {
            suggestedResolution = (sourceEntity.riskScore || 0) > (targetEntity.riskScore || 0) ? "source" : "target";
          } else if (field === "firstSeenAt") {
            suggestedResolution =
              new Date(sourceEntity.firstSeenAt || 0) < new Date(targetEntity.firstSeenAt || 0) ? "source" : "target";
          } else if (field === "lastSeenAt") {
            suggestedResolution =
              new Date(sourceEntity.lastSeenAt || 0) > new Date(targetEntity.lastSeenAt || 0) ? "source" : "target";
          } else if (field === "metadata") {
            suggestedResolution = "merge";
          }

          comparison.push({
            field,
            sourceValue: sv,
            targetValue: tv,
            hasConflict,
            suggestedResolution,
          });
        }

        // Shared alerts (overlap)
        const sourceAlertIds = new Set(sourceAlertLinks.map((l) => l.alertId));
        const sharedAlertCount = targetAlertLinks.filter((l) => sourceAlertIds.has(l.alertId)).length;

        res.json({
          source: {
            ...sourceEntity,
            alertCount: sourceAlertLinks.length,
            aliasCount: sourceAliases.length,
            aliases: sourceAliases.map((a) => ({ type: a.aliasType, value: a.aliasValue })),
          },
          target: {
            ...targetEntity,
            alertCount: targetAlertLinks.length,
            aliasCount: targetAliases.length,
            aliases: targetAliases.map((a) => ({ type: a.aliasType, value: a.aliasValue })),
          },
          comparison,
          impact: {
            totalAlertsAfterMerge: sourceAlertLinks.length + targetAlertLinks.length - sharedAlertCount,
            totalAliasesAfterMerge: sourceAliases.length + targetAliases.length + 1,
            sharedAlertCount,
          },
        });
      } catch (error) {
        log.error("Merge preview error", { error: String(error) });
        res.status(500).json({ message: "Failed to generate merge preview" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 14.4: Cascading merge with field selection (enhanced merge endpoint)
  // ═══════════════════════════════════════════════════════════════════════

  app.post(
    "/api/entities/merge-with-preview",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { sourceId, targetId, fieldOverrides } = req.body;
        if (!sourceId || !targetId) return res.status(400).json({ message: "sourceId and targetId required" });

        // Verify both belong to this org
        const [srcCheck] = await db
          .select({ id: entities.id })
          .from(entities)
          .where(and(eq(entities.id, sourceId), eq(entities.orgId, orgId)));
        const [tgtCheck] = await db
          .select({ id: entities.id })
          .from(entities)
          .where(and(eq(entities.id, targetId), eq(entities.orgId, orgId)));
        if (!srcCheck) return res.status(404).json({ message: "Source entity not found in this org" });
        if (!tgtCheck) return res.status(404).json({ message: "Target entity not found in this org" });

        const userId = (req as any).user?.id || null;
        const merged = await mergeEntities(targetId, sourceId, userId);

        // Apply field overrides if user chose specific source values
        if (fieldOverrides && typeof fieldOverrides === "object") {
          const allowedOverrides: Record<string, boolean> = {
            displayName: true,
            riskScore: true,
            metadata: true,
          };
          const updates: Record<string, unknown> = {};
          for (const [field, value] of Object.entries(fieldOverrides)) {
            if (allowedOverrides[field]) {
              updates[field] = value;
            }
          }
          if (Object.keys(updates).length > 0) {
            await db.update(entities).set(updates).where(eq(entities.id, targetId));
          }
        }

        broadcastEvent({
          type: "entity:merged" as any,
          orgId,
          data: { targetId, sourceId, mergedEntityId: merged.id },
        });

        res.json({
          merged,
          cascadeResults: {
            alertsUpdated: true,
            aliasesUpdated: true,
            attackPathsUpdated: true,
          },
        });
      } catch (error) {
        log.error("Merge with preview error", { error: String(error) });
        res.status(500).json({ message: "Failed to merge entities" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 14.2: Merge history and undo
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/merge-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = req.query.entityId as string | undefined;

        let history;
        if (entityId) {
          history = await db
            .select()
            .from(entityMergeHistory)
            .where(
              and(
                eq(entityMergeHistory.orgId, orgId),
                or(eq(entityMergeHistory.targetEntityId, entityId), eq(entityMergeHistory.sourceEntityId, entityId)),
              ),
            )
            .orderBy(desc(entityMergeHistory.createdAt))
            .limit(100);
        } else {
          history = await db
            .select()
            .from(entityMergeHistory)
            .where(eq(entityMergeHistory.orgId, orgId))
            .orderBy(desc(entityMergeHistory.createdAt))
            .limit(100);
        }

        res.json({ history, total: history.length });
      } catch (error) {
        log.error("Merge history error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch merge history" });
      }
    },
  );

  app.post(
    "/api/entities/merge-undo/:mergeId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const mergeId = p(req.params.mergeId);
        const userId = (req as any).user?.id || null;

        const [mergeRecord] = await db
          .select()
          .from(entityMergeHistory)
          .where(and(eq(entityMergeHistory.id, mergeId), eq(entityMergeHistory.orgId, orgId)));

        if (!mergeRecord) return res.status(404).json({ message: "Merge record not found" });
        if (mergeRecord.undone) return res.status(400).json({ message: "This merge has already been undone" });

        const sourceSnapshot = mergeRecord.sourceEntitySnapshot as Record<string, unknown>;
        const targetEntityId = mergeRecord.targetEntityId;
        const sourceEntityId = mergeRecord.sourceEntityId;

        await db.transaction(async (tx) => {
          // Re-create the source entity from snapshot
          await tx.insert(entities).values({
            id: sourceEntityId,
            orgId: (sourceSnapshot.orgId as string) || orgId,
            type: sourceSnapshot.type as string,
            value: sourceSnapshot.value as string,
            displayName: (sourceSnapshot.displayName as string) || null,
            metadata: (sourceSnapshot.metadata as Record<string, unknown>) || {},
            riskScore: (sourceSnapshot.riskScore as number) || 0,
            alertCount: 0,
            firstSeenAt: sourceSnapshot.firstSeenAt ? new Date(sourceSnapshot.firstSeenAt as string) : new Date(),
            lastSeenAt: sourceSnapshot.lastSeenAt ? new Date(sourceSnapshot.lastSeenAt as string) : new Date(),
          });

          // Move back the alert links that were originally on the source entity
          const movedAlertIds = (mergeRecord.movedAlertIds || []) as string[];
          if (movedAlertIds.length > 0) {
            await tx
              .update(alertEntities)
              .set({ entityId: sourceEntityId })
              .where(and(eq(alertEntities.entityId, targetEntityId), inArray(alertEntities.alertId, movedAlertIds)));
          }

          // Move back the aliases that were originally on the source entity
          const movedAliasIds = (mergeRecord.movedAliasIds || []) as string[];
          if (movedAliasIds.length > 0) {
            await tx
              .update(entityAliases)
              .set({ entityId: sourceEntityId })
              .where(inArray(entityAliases.id, movedAliasIds));
          }

          // Remove the alias that was auto-created for the source entity's value
          await tx
            .delete(entityAliases)
            .where(
              and(
                eq(entityAliases.entityId, targetEntityId),
                eq(entityAliases.aliasValue, (sourceSnapshot.value as string).toLowerCase()),
                eq(entityAliases.source, "merge"),
              ),
            );

          // Update alert counts for both entities
          await tx
            .update(entities)
            .set({
              alertCount: sql`(SELECT COUNT(DISTINCT alert_id) FROM alert_entities WHERE entity_id = ${targetEntityId})`,
            })
            .where(eq(entities.id, targetEntityId));

          await tx
            .update(entities)
            .set({
              alertCount: sql`(SELECT COUNT(DISTINCT alert_id) FROM alert_entities WHERE entity_id = ${sourceEntityId})`,
            })
            .where(eq(entities.id, sourceEntityId));

          // Mark the merge as undone
          await tx
            .update(entityMergeHistory)
            .set({ undone: true, undoneAt: new Date(), undoneBy: userId })
            .where(eq(entityMergeHistory.id, mergeId));
        });

        broadcastEvent({
          type: "entity:merge-undone" as any,
          orgId,
          data: { mergeId, targetEntityId, sourceEntityId },
        });

        res.json({
          message: "Merge successfully undone",
          restoredEntityId: sourceEntityId,
          targetEntityId,
        });
      } catch (error) {
        log.error("Merge undo error", { error: String(error) });
        res.status(500).json({ message: "Failed to undo merge" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 14.3: Auto-suggested merges with confidence scores
  // ═══════════════════════════════════════════════════════════════════════

  app.get(
    "/api/entities/merge-suggestions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const minConfidence = parseInt(req.query.minConfidence as string, 10) || 50;
        const allEntities = await db
          .select()
          .from(entities)
          .where(eq(entities.orgId, orgId))
          .orderBy(desc(entities.alertCount))
          .limit(500);

        const suggestions: {
          id: string;
          entity1: { id: string; type: string; value: string; displayName: string | null; alertCount: number };
          entity2: { id: string; type: string; value: string; displayName: string | null; alertCount: number };
          reasons: string[];
          confidence: number;
          category: "fuzzy_name" | "shared_attribute" | "temporal_correlation" | "alias_match";
        }[] = [];

        // Group by type for comparison
        const byType: Record<string, typeof allEntities> = {};
        for (const e of allEntities) {
          if (!byType[e.type]) byType[e.type] = [];
          byType[e.type].push(e);
        }

        // Get all alert entity links for temporal correlation
        const entityIds = allEntities.map((e) => e.id);
        const allAlertLinks =
          entityIds.length > 0
            ? await db
                .select({
                  entityId: alertEntities.entityId,
                  alertId: alertEntities.alertId,
                })
                .from(alertEntities)
                .where(inArray(alertEntities.entityId, entityIds))
            : [];

        // Build entity-to-alerts map
        const entityAlertMap = new Map<string, Set<string>>();
        for (const link of allAlertLinks) {
          const set = entityAlertMap.get(link.entityId) || new Set();
          set.add(link.alertId);
          entityAlertMap.set(link.entityId, set);
        }

        let suggestionCounter = 0;

        for (const [, typeEntities] of Object.entries(byType)) {
          for (let i = 0; i < typeEntities.length && i < 150; i++) {
            for (let j = i + 1; j < typeEntities.length && j < 150; j++) {
              const e1 = typeEntities[i];
              const e2 = typeEntities[j];

              const reasons: string[] = [];
              let confidence = 0;
              let category: "fuzzy_name" | "shared_attribute" | "temporal_correlation" | "alias_match" = "fuzzy_name";

              const v1 = e1.value.toLowerCase().trim();
              const v2 = e2.value.toLowerCase().trim();

              // Fuzzy name matching — Levenshtein-like comparison
              if (v1 === v2) {
                reasons.push("Identical values after normalization");
                confidence = Math.max(confidence, 95);
              } else {
                // Simple character-level similarity
                const maxLen = Math.max(v1.length, v2.length);
                if (maxLen > 0 && maxLen < 100) {
                  let matches = 0;
                  const minLen = Math.min(v1.length, v2.length);
                  for (let k = 0; k < minLen; k++) {
                    if (v1[k] === v2[k]) matches++;
                  }
                  const similarity = matches / maxLen;
                  if (similarity >= 0.8) {
                    reasons.push(`High character similarity (${Math.round(similarity * 100)}%)`);
                    confidence = Math.max(confidence, Math.round(similarity * 90));
                    category = "fuzzy_name";
                  }
                }

                // Separator-normalized comparison
                const norm1 = v1.replace(/[._\-@]/g, "");
                const norm2 = v2.replace(/[._\-@]/g, "");
                if (norm1 === norm2 && norm1.length > 2) {
                  reasons.push("Same value after removing separators");
                  confidence = Math.max(confidence, 80);
                  category = "fuzzy_name";
                }

                // Substring match
                if (v1.length > 3 && v2.length > 3 && (v1.includes(v2) || v2.includes(v1))) {
                  reasons.push("One value is a substring of the other");
                  confidence = Math.max(confidence, 60);
                  category = "fuzzy_name";
                }

                // Domain-specific: strip www., trailing dot
                if (e1.type === "domain") {
                  const strip = (d: string) => d.replace(/^www\./, "").replace(/\.$/, "");
                  if (strip(v1) === strip(v2)) {
                    reasons.push("Same domain after stripping www prefix");
                    confidence = Math.max(confidence, 90);
                    category = "shared_attribute";
                  }
                }

                // IP-specific: leading zeros, IPv4-mapped IPv6
                if (e1.type === "ip") {
                  const stripZeros = (ip: string) => ip.replace(/\b0+(\d)/g, "$1");
                  if (stripZeros(v1) === stripZeros(v2)) {
                    reasons.push("Same IP after removing leading zeros");
                    confidence = Math.max(confidence, 90);
                    category = "shared_attribute";
                  }
                  if (v1.replace("::ffff:", "") === v2 || v2.replace("::ffff:", "") === v1) {
                    reasons.push("IPv4-mapped IPv6 match");
                    confidence = Math.max(confidence, 85);
                    category = "shared_attribute";
                  }
                  // Same subnet (/24)
                  const subnet1 = v1.split(".").slice(0, 3).join(".");
                  const subnet2 = v2.split(".").slice(0, 3).join(".");
                  if (subnet1 === subnet2 && subnet1.length > 4) {
                    reasons.push("Same /24 subnet");
                    confidence = Math.max(confidence, 40);
                    category = "shared_attribute";
                  }
                }

                // Email-specific: same username, different domain
                if (e1.type === "email") {
                  const [user1] = v1.split("@");
                  const [user2] = v2.split("@");
                  if (user1 === user2 && user1.length > 2) {
                    reasons.push("Same email username, different domain");
                    confidence = Math.max(confidence, 75);
                    category = "alias_match";
                  }
                }
              }

              // DisplayName match with different values
              if (
                e1.displayName &&
                e2.displayName &&
                e1.displayName.toLowerCase() === e2.displayName.toLowerCase() &&
                v1 !== v2
              ) {
                reasons.push("Same display name, different values");
                confidence = Math.max(confidence, 65);
                category = "shared_attribute";
              }

              // Temporal correlation — shared alerts
              const alerts1 = entityAlertMap.get(e1.id);
              const alerts2 = entityAlertMap.get(e2.id);
              if (alerts1 && alerts2 && alerts1.size > 0 && alerts2.size > 0) {
                let sharedCount = 0;
                for (const a of Array.from(alerts1)) {
                  if (alerts2.has(a)) sharedCount++;
                }
                if (sharedCount > 0) {
                  const overlapRatio = sharedCount / Math.min(alerts1.size, alerts2.size);
                  if (overlapRatio >= 0.5) {
                    reasons.push(
                      `High alert overlap (${sharedCount} shared, ${Math.round(overlapRatio * 100)}% overlap)`,
                    );
                    confidence = Math.max(confidence, Math.round(60 + overlapRatio * 30));
                    category = "temporal_correlation";
                  } else if (sharedCount >= 2) {
                    reasons.push(`${sharedCount} shared alerts`);
                    confidence = Math.max(confidence, 50);
                    category = "temporal_correlation";
                  }
                }
              }

              if (reasons.length > 0 && confidence >= minConfidence) {
                suggestionCounter++;
                suggestions.push({
                  id: `suggestion-${suggestionCounter}`,
                  entity1: {
                    id: e1.id,
                    type: e1.type,
                    value: e1.value,
                    displayName: e1.displayName,
                    alertCount: e1.alertCount || 0,
                  },
                  entity2: {
                    id: e2.id,
                    type: e2.type,
                    value: e2.value,
                    displayName: e2.displayName,
                    alertCount: e2.alertCount || 0,
                  },
                  reasons,
                  confidence,
                  category,
                });
              }
            }
          }
        }

        // Sort by confidence descending
        suggestions.sort((a, b) => b.confidence - a.confidence);

        res.json({
          suggestions: suggestions.slice(0, 100),
          totalFound: suggestions.length,
          minConfidenceUsed: minConfidence,
        });
      } catch (error) {
        log.error("Merge suggestions error", { error: String(error) });
        res.status(500).json({ message: "Failed to generate merge suggestions" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════
  // 14.5: Alias management — bulk add, delete, search by alias
  // ═══════════════════════════════════════════════════════════════════════

  app.post(
    "/api/entities/:id/aliases/bulk",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = p(req.params.id);

        // Verify entity belongs to this org
        const [entity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, entityId), eq(entities.orgId, orgId)));
        if (!entity) return res.status(404).json({ message: "Entity not found" });

        const { aliases } = req.body;
        if (!Array.isArray(aliases) || aliases.length === 0) {
          return res.status(400).json({ message: "aliases array required" });
        }

        const results: { aliasValue: string; status: "created" | "exists" | "error" }[] = [];
        for (const alias of aliases.slice(0, 50)) {
          try {
            if (!alias.aliasType || !alias.aliasValue) {
              results.push({ aliasValue: alias.aliasValue || "unknown", status: "error" });
              continue;
            }
            const created = await addEntityAlias(entityId, alias.aliasType, alias.aliasValue, alias.source || "manual");
            const isNew = created.createdAt && new Date(created.createdAt).getTime() > Date.now() - 5000;
            results.push({ aliasValue: alias.aliasValue, status: isNew ? "created" : "exists" });
          } catch {
            results.push({ aliasValue: alias.aliasValue || "unknown", status: "error" });
          }
        }

        res.json({
          entityId,
          results,
          created: results.filter((r) => r.status === "created").length,
          existing: results.filter((r) => r.status === "exists").length,
          errors: results.filter((r) => r.status === "error").length,
        });
      } catch (error) {
        log.error("Bulk alias add error", { error: String(error) });
        res.status(500).json({ message: "Failed to bulk add aliases" });
      }
    },
  );

  app.delete(
    "/api/entities/:entityId/aliases/:aliasId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityId = p(req.params.entityId);
        const aliasId = p(req.params.aliasId);

        // Verify entity belongs to this org
        const [entity] = await db
          .select()
          .from(entities)
          .where(and(eq(entities.id, entityId), eq(entities.orgId, orgId)));
        if (!entity) return res.status(404).json({ message: "Entity not found" });

        // Verify alias belongs to this entity
        const [alias] = await db
          .select()
          .from(entityAliases)
          .where(and(eq(entityAliases.id, aliasId), eq(entityAliases.entityId, entityId)));
        if (!alias) return res.status(404).json({ message: "Alias not found" });

        await db.delete(entityAliases).where(eq(entityAliases.id, aliasId));
        res.json({ message: "Alias deleted", aliasId });
      } catch (error) {
        log.error("Delete alias error", { error: String(error) });
        res.status(500).json({ message: "Failed to delete alias" });
      }
    },
  );

  app.get(
    "/api/entities/resolve-alias",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const aliasValue = ((req.query.value as string) || "").toLowerCase().trim();
        if (!aliasValue) return res.status(400).json({ message: "value query parameter required" });

        // Find entities matching this alias
        const matchingAliases = await db
          .select({
            aliasId: entityAliases.id,
            aliasType: entityAliases.aliasType,
            aliasValue: entityAliases.aliasValue,
            entityId: entities.id,
            entityType: entities.type,
            entityValue: entities.value,
            entityDisplayName: entities.displayName,
            entityRiskScore: entities.riskScore,
          })
          .from(entityAliases)
          .innerJoin(entities, eq(entityAliases.entityId, entities.id))
          .where(
            and(
              eq(entities.orgId, orgId),
              or(eq(entityAliases.aliasValue, aliasValue), ilike(entityAliases.aliasValue, `%${aliasValue}%`)),
            ),
          )
          .limit(20);

        // Also check direct entity value match
        const directMatches = await db
          .select()
          .from(entities)
          .where(
            and(
              eq(entities.orgId, orgId),
              or(eq(entities.value, aliasValue), ilike(entities.value, `%${aliasValue}%`)),
            ),
          )
          .limit(10);

        res.json({
          aliasMatches: matchingAliases,
          directMatches: directMatches.map((e) => ({
            entityId: e.id,
            entityType: e.type,
            entityValue: e.value,
            entityDisplayName: e.displayName,
            entityRiskScore: e.riskScore,
          })),
          totalResults: matchingAliases.length + directMatches.length,
        });
      } catch (error) {
        log.error("Resolve alias error", { error: String(error) });
        res.status(500).json({ message: "Failed to resolve alias" });
      }
    },
  );
}
