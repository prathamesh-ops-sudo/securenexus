import type { Express } from "express";
import { logger, p, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import {
  getSecurityGraph,
  getAttackPathById,
  getAssetById,
  getAssetNeighbors,
  ingestEntities,
  deleteAsset,
  deleteRelationship,
  queryGraph,
  findPaths,
} from "../security-graph-engine";
import type { IngestionPayload, GraphQuery, AssetType, RelationshipType } from "../security-graph-engine";

const VALID_ASSET_TYPES: AssetType[] = [
  "code",
  "cloud",
  "identity",
  "data",
  "network",
  "compute",
  "container",
  "endpoint",
  "saas",
  "runtime",
  "remediation",
  "vulnerability",
];

const VALID_RELATIONSHIP_TYPES: RelationshipType[] = [
  "accesses",
  "authenticates_with",
  "contains",
  "deploys_to",
  "exposes",
  "has_permission",
  "reads_from",
  "writes_to",
  "connects_to",
  "inherits_from",
  "manages",
  "depends_on",
  "runs_on",
  "can_access",
  "exposed_to",
  "owned_by",
  "fixed_by",
  "triggers",
  "mitigates",
  "scans",
];

const VALID_ENVIRONMENTS = ["production", "staging", "development", "shared"];

function validateAssetType(t: string): t is AssetType {
  return VALID_ASSET_TYPES.includes(t as AssetType);
}

function validateRelationshipType(t: string): t is RelationshipType {
  return VALID_RELATIONSHIP_TYPES.includes(t as RelationshipType);
}

function validateEnvironment(e: string): boolean {
  return VALID_ENVIRONMENTS.includes(e);
}

export function registerSecurityGraphRoutes(app: Express): void {
  app.get("/api/security-graph", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const graph = getSecurityGraph(orgId);
      res.json(graph);
    } catch (error) {
      logger.child("routes").error("Security graph error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security graph" });
    }
  });

  app.post("/api/security-graph/query", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = (req.query.orgId as string) || "__default__";
      }
      const body = req.body as GraphQuery;
      if (body.assetTypes) {
        for (const t of body.assetTypes) {
          if (!validateAssetType(t)) return res.status(400).json({ message: `Invalid asset type: ${t}` });
        }
      }
      if (body.relationshipTypes) {
        for (const t of body.relationshipTypes) {
          if (!validateRelationshipType(t)) return res.status(400).json({ message: `Invalid relationship type: ${t}` });
        }
      }
      if (body.environments) {
        for (const e of body.environments) {
          if (!validateEnvironment(e)) return res.status(400).json({ message: `Invalid environment: ${e}` });
        }
      }
      if (typeof body.minRiskScore === "number" && (body.minRiskScore < 0 || body.minRiskScore > 1)) {
        return res.status(400).json({ message: "minRiskScore must be between 0 and 1" });
      }
      if (typeof body.maxRiskScore === "number" && (body.maxRiskScore < 0 || body.maxRiskScore > 1)) {
        return res.status(400).json({ message: "maxRiskScore must be between 0 and 1" });
      }
      const result = queryGraph(orgId, body);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Security graph query error", { error: String(error) });
      res.status(500).json({ message: "Failed to query security graph" });
    }
  });

  app.post("/api/security-graph/ingest", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = (req.query.orgId as string) || "__default__";
      }
      const payload = req.body as IngestionPayload;
      if (!payload.assets && !payload.relationships) {
        return res.status(400).json({ message: "Payload must include assets or relationships" });
      }
      if (payload.assets) {
        for (const asset of payload.assets) {
          if (!asset.name || typeof asset.name !== "string")
            return res.status(400).json({ message: "Each asset must have a name" });
          if (!validateAssetType(asset.type))
            return res.status(400).json({ message: `Invalid asset type: ${asset.type}` });
          if (!asset.subType || typeof asset.subType !== "string")
            return res.status(400).json({ message: "Each asset must have a subType" });
          if (!validateEnvironment(asset.environment))
            return res.status(400).json({ message: `Invalid environment: ${asset.environment}` });
          if (typeof asset.riskScore !== "number" || asset.riskScore < 0 || asset.riskScore > 1)
            return res.status(400).json({ message: "riskScore must be a number between 0 and 1" });
        }
      }
      if (payload.relationships) {
        for (const rel of payload.relationships) {
          if (!rel.sourceResolutionKey || typeof rel.sourceResolutionKey !== "string")
            return res.status(400).json({ message: "Each relationship must have a sourceResolutionKey" });
          if (!rel.targetResolutionKey || typeof rel.targetResolutionKey !== "string")
            return res.status(400).json({ message: "Each relationship must have a targetResolutionKey" });
          if (!validateRelationshipType(rel.relationship))
            return res.status(400).json({ message: `Invalid relationship type: ${rel.relationship}` });
        }
      }
      const result = ingestEntities(orgId, payload);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Security graph ingest error", { error: String(error) });
      res.status(500).json({ message: "Failed to ingest entities" });
    }
  });

  app.post("/api/security-graph/find-paths", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = (req.query.orgId as string) || "__default__";
      }
      const { sourceId, targetId, maxDepth } = req.body as { sourceId: string; targetId: string; maxDepth?: number };
      if (!sourceId || typeof sourceId !== "string") return res.status(400).json({ message: "sourceId is required" });
      if (!targetId || typeof targetId !== "string") return res.status(400).json({ message: "targetId is required" });
      if (maxDepth !== undefined && (typeof maxDepth !== "number" || maxDepth < 1 || maxDepth > 10)) {
        return res.status(400).json({ message: "maxDepth must be between 1 and 10" });
      }
      const paths = findPaths(orgId, sourceId, targetId, maxDepth);
      res.json(paths);
    } catch (error) {
      logger.child("routes").error("Security graph find-paths error", { error: String(error) });
      res.status(500).json({ message: "Failed to find paths" });
    }
  });

  app.get("/api/security-graph/assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const asset = getAssetById(p(req.params.id), orgId);
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      res.json(asset);
    } catch (error) {
      logger.child("routes").error("Security graph asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset" });
    }
  });

  app.delete("/api/security-graph/assets/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = (req.query.orgId as string) || "__default__";
      }
      const deleted = deleteAsset(orgId, p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Asset not found" });
      res.json({ deleted: true });
    } catch (error) {
      logger.child("routes").error("Security graph delete asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete asset" });
    }
  });

  app.get("/api/security-graph/assets/:id/neighbors", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const neighbors = getAssetNeighbors(p(req.params.id), orgId);
      res.json(neighbors);
    } catch (error) {
      logger.child("routes").error("Security graph neighbors error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset neighbors" });
    }
  });

  app.get("/api/security-graph/attack-paths", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const graph = getSecurityGraph(orgId);
      res.json(graph.attackPaths);
    } catch (error) {
      logger.child("routes").error("Attack paths error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack paths" });
    }
  });

  app.get("/api/security-graph/attack-paths/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const path = getAttackPathById(p(req.params.id), orgId);
      if (!path) return res.status(404).json({ message: "Attack path not found" });
      res.json(path);
    } catch (error) {
      logger.child("routes").error("Attack path detail error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack path" });
    }
  });

  app.delete("/api/security-graph/relationships/:id", isAuthenticated, async (req, res) => {
    try {
      let orgId: string;
      try {
        orgId = getOrgId(req);
      } catch {
        orgId = (req.query.orgId as string) || "__default__";
      }
      const deleted = deleteRelationship(orgId, p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Relationship not found" });
      res.json({ deleted: true });
    } catch (error) {
      logger.child("routes").error("Security graph delete relationship error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete relationship" });
    }
  });

  app.get("/api/security-graph/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const graph = getSecurityGraph(orgId);
      res.json(graph.stats);
    } catch (error) {
      logger.child("routes").error("Security graph stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security graph stats" });
    }
  });
}
