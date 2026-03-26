import type { InsertAttackGraphNode, InsertAttackGraphEdge } from "@shared/schema";
import { storage } from "../shared";
import { logger } from "../shared";

/**
 * Persist attack graph data from a deep investigation result to the database.
 * Extracts nodes and edges from the result's attackGraph field and stores them
 * in separate normalized tables for querying and visualization.
 */
export async function persistAttackGraph(
  result: Record<string, unknown>,
  incidentId: string,
  orgId: string,
): Promise<void> {
  const attackGraph = result.attackGraph as
    | {
        initialAccess?: unknown;
        nodes?: unknown[];
        edges?: unknown[];
        currentPosition?: string;
        objectivesAchieved?: string[];
        objectivesInProgress?: string[];
      }
    | undefined;

  if (!attackGraph || (!attackGraph.nodes?.length && !attackGraph.edges?.length)) {
    return; // No attack graph data to persist
  }

  const nodes = Array.isArray(attackGraph.nodes) ? attackGraph.nodes : [];
  const edges = Array.isArray(attackGraph.edges) ? attackGraph.edges : [];

  // Compute max depth from nodes
  let maxDepth = 0;
  for (const n of nodes) {
    const d = typeof n === "object" && n && "depth" in n ? Number((n as Record<string, unknown>).depth) || 0 : 0;
    if (d > maxDepth) maxDepth = d;
  }

  // Create the parent graph record
  const graph = await storage.createAttackGraph({
    orgId,
    incidentId,
    initialAccessDescription:
      typeof attackGraph.initialAccess === "string"
        ? attackGraph.initialAccess
        : JSON.stringify(attackGraph.initialAccess ?? null),
    currentPosition: attackGraph.currentPosition || null,
    objectivesAchieved: attackGraph.objectivesAchieved || [],
    objectivesInProgress: attackGraph.objectivesInProgress || [],
    totalNodes: nodes.length,
    totalEdges: edges.length,
    maxDepth,
    confidence: typeof result.investigationConfidence === "number" ? result.investigationConfidence : 0,
    metadata: null,
  });

  // Insert nodes
  if (nodes.length > 0) {
    const nodeRecords: InsertAttackGraphNode[] = nodes.map((n, idx) => {
      const node = (typeof n === "object" && n ? n : {}) as Record<string, unknown>;
      return {
        graphId: graph.id,
        nodeId: String(node.id || node.nodeId || `node-${idx}`),
        nodeType: String(node.type || node.nodeType || "unknown"),
        label: String(node.label || node.name || `Node ${idx}`),
        description: node.description ? String(node.description) : null,
        mitreTechnique: node.mitreTechnique || node.technique ? String(node.mitreTechnique || node.technique) : null,
        mitreTactic: node.mitreTactic || node.tactic ? String(node.mitreTactic || node.tactic) : null,
        confidence: typeof node.confidence === "number" ? node.confidence : null,
        severity: node.severity ? String(node.severity) : null,
        evidence: Array.isArray(node.evidence) ? node.evidence.map(String) : [],
        metadata: node.metadata ? (node.metadata as Record<string, unknown>) : null,
        positionX: typeof node.x === "number" ? node.x : typeof node.positionX === "number" ? node.positionX : null,
        positionY: typeof node.y === "number" ? node.y : typeof node.positionY === "number" ? node.positionY : null,
        depth: typeof node.depth === "number" ? node.depth : idx,
      };
    });
    await storage.createAttackGraphNodes(nodeRecords);
  }

  // Insert edges
  if (edges.length > 0) {
    const edgeRecords: InsertAttackGraphEdge[] = edges.map((e, idx) => {
      const edge = (typeof e === "object" && e ? e : {}) as Record<string, unknown>;
      return {
        graphId: graph.id,
        sourceNodeId: String(edge.source || edge.from || edge.sourceNodeId || `node-${idx}`),
        targetNodeId: String(edge.target || edge.to || edge.targetNodeId || `node-${idx + 1}`),
        relationship: String(edge.relationship || edge.label || edge.type || "connected"),
        technique: edge.technique ? String(edge.technique) : null,
        confidence: typeof edge.confidence === "number" ? edge.confidence : null,
        timestamp: edge.timestamp ? String(edge.timestamp) : null,
        evidence: Array.isArray(edge.evidence) ? edge.evidence.map(String) : [],
        metadata: edge.metadata ? (edge.metadata as Record<string, unknown>) : null,
      };
    });
    await storage.createAttackGraphEdges(edgeRecords);
  }

  logger.child("ai").info("Attack graph persisted", {
    graphId: graph.id,
    incidentId,
    nodes: nodes.length,
    edges: edges.length,
  });
}
