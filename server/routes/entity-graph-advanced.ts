import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { getOrgId, logger, p, storage } from "./shared";
import { db } from "../db";
import { entities, alertEntities, alerts, uebaEntityScores } from "@shared/schema";
import { eq, and, sql, inArray, desc } from "drizzle-orm";
import { getEntityGraphWithEdges } from "../entity-resolver";
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

        // Store snapshot in-memory for now (would be DB in production)
        const snapshot = {
          id: `snap-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          orgId,
          name: String(name).slice(0, 200),
          description: description ? String(description).slice(0, 500) : null,
          nodeCount: graph.nodes.length,
          edgeCount: graph.edges.length,
          createdBy: userId,
          createdAt: new Date().toISOString(),
          data: {
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
          },
        };

        // Store in global snapshots map (keyed by orgId)
        if (!graphSnapshots.has(orgId)) graphSnapshots.set(orgId, []);
        const orgSnapshots = graphSnapshots.get(orgId)!;
        orgSnapshots.push(snapshot);
        // Keep max 20 snapshots per org
        if (orgSnapshots.length > 20) orgSnapshots.shift();

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
        const orgSnapshots = graphSnapshots.get(orgId) || [];
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
        const orgSnapshots = graphSnapshots.get(orgId) || [];
        const snapshot = orgSnapshots.find((s) => s.id === snapshotId);
        if (!snapshot) return res.status(404).json({ message: "Snapshot not found" });

        const currentGraph = await getEntityGraphWithEdges(orgId, 200);

        const snapshotNodeIds = new Set(snapshot.data.nodes.map((n: any) => n.id));
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

        const removedNodes = snapshot.data.nodes
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

        const snapshotNodeMap = new Map(snapshot.data.nodes.map((n: any) => [n.id, n]));
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
        const snapshotEdgeKeys = new Set(snapshot.data.edges.map((e: any) => [e.source, e.target].sort().join(":")));
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
}

// In-memory snapshot storage (per org)
const graphSnapshots = new Map<
  string,
  {
    id: string;
    orgId: string;
    name: string;
    description: string | null;
    nodeCount: number;
    edgeCount: number;
    createdBy: string;
    createdAt: string;
    data: { nodes: any[]; edges: any[] };
  }[]
>();
