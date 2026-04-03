import type { Express, Request, Response } from "express";
import { logger, p, getOrgId } from "./shared";
import { isAuthenticated } from "../auth";
import { storage } from "../storage";
import type { InsertSecurityGraphAsset, InsertSecurityGraphRelationship } from "@shared/schema";
import { createHash } from "crypto";

interface RequestWithUser extends Request {
  user?: { id?: string; email?: string };
}

type AssetType =
  | "code"
  | "cloud"
  | "identity"
  | "data"
  | "network"
  | "compute"
  | "container"
  | "endpoint"
  | "saas"
  | "runtime"
  | "remediation"
  | "vulnerability";

type RelationshipType =
  | "accesses"
  | "authenticates_with"
  | "contains"
  | "deploys_to"
  | "exposes"
  | "has_permission"
  | "reads_from"
  | "writes_to"
  | "connects_to"
  | "inherits_from"
  | "manages"
  | "depends_on"
  | "runs_on"
  | "can_access"
  | "exposed_to"
  | "owned_by"
  | "fixed_by"
  | "triggers"
  | "mitigates"
  | "scans";

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

const log = logger.child("security-graph");

function validateAssetType(t: string): t is AssetType {
  return VALID_ASSET_TYPES.includes(t as AssetType);
}

function validateRelationshipType(t: string): t is RelationshipType {
  return VALID_RELATIONSHIP_TYPES.includes(t as RelationshipType);
}

function validateEnvironment(e: string): boolean {
  return VALID_ENVIRONMENTS.includes(e);
}

function buildResolutionKey(name: string, type: string, subType: string): string {
  return createHash("sha256").update(`${type}:${subType}:${name}`).digest("hex").slice(0, 16);
}

interface IngestionAsset {
  name: string;
  type: AssetType;
  subType: string;
  environment: string;
  riskScore: number;
  metadata?: Record<string, unknown>;
  tags?: string[];
  owner?: string;
}

interface IngestionRelationship {
  sourceResolutionKey: string;
  targetResolutionKey: string;
  relationship: RelationshipType;
  weight?: number;
  metadata?: Record<string, unknown>;
  bidirectional?: boolean;
}

interface IngestionPayload {
  assets?: IngestionAsset[];
  relationships?: IngestionRelationship[];
}

interface GraphQuery {
  assetTypes?: AssetType[];
  relationshipTypes?: RelationshipType[];
  environments?: string[];
  minRiskScore?: number;
  maxRiskScore?: number;
}

export function registerSecurityGraphRoutes(app: Express): void {
  // Get full graph
  app.get("/api/security-graph", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const [assets, relationships] = await Promise.all([
        storage.getSecurityGraphAssets(orgId),
        storage.getSecurityGraphRelationships(orgId),
      ]);

      const typeBreakdown: Record<string, number> = {};
      const envBreakdown: Record<string, number> = {};
      let totalRisk = 0;
      for (const a of assets) {
        typeBreakdown[a.type] = (typeBreakdown[a.type] || 0) + 1;
        envBreakdown[a.environment] = (envBreakdown[a.environment] || 0) + 1;
        totalRisk += a.riskScore;
      }

      res.json({
        assets,
        relationships,
        attackPaths: [],
        stats: {
          totalAssets: assets.length,
          totalRelationships: relationships.length,
          typeBreakdown,
          environmentBreakdown: envBreakdown,
          averageRiskScore: assets.length > 0 ? totalRisk / assets.length : 0,
          highRiskAssets: assets.filter((a) => a.riskScore >= 0.7).length,
        },
      });
    } catch (error) {
      log.error("Security graph error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security graph" });
    }
  });

  // Query graph with filters
  app.post("/api/security-graph/query", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
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

      let assets = await storage.getSecurityGraphAssets(orgId);
      if (body.assetTypes) {
        assets = assets.filter((a) => body.assetTypes!.includes(a.type as AssetType));
      }
      if (body.environments) {
        assets = assets.filter((a) => body.environments!.includes(a.environment));
      }
      if (typeof body.minRiskScore === "number") {
        assets = assets.filter((a) => a.riskScore >= body.minRiskScore!);
      }
      if (typeof body.maxRiskScore === "number") {
        assets = assets.filter((a) => a.riskScore <= body.maxRiskScore!);
      }

      const assetIds = new Set(assets.map((a) => a.id));
      let relationships = await storage.getSecurityGraphRelationships(orgId);
      relationships = relationships.filter((r) => assetIds.has(r.sourceId) && assetIds.has(r.targetId));
      if (body.relationshipTypes) {
        relationships = relationships.filter((r) =>
          body.relationshipTypes!.includes(r.relationship as RelationshipType),
        );
      }

      res.json({ assets, relationships });
    } catch (error) {
      log.error("Security graph query error", { error: String(error) });
      res.status(500).json({ message: "Failed to query security graph" });
    }
  });

  // Ingest assets and relationships
  app.post("/api/security-graph/ingest", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
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

      let assetsCreated = 0;
      let assetsUpdated = 0;
      let relationshipsCreated = 0;

      // Upsert assets by resolution key
      if (payload.assets) {
        for (const asset of payload.assets) {
          const resolutionKey = buildResolutionKey(asset.name, asset.type, asset.subType);
          const existing = await storage.getSecurityGraphAssetByResolutionKey(orgId, resolutionKey);
          if (existing) {
            await storage.updateSecurityGraphAsset(existing.id, orgId, {
              name: asset.name,
              type: asset.type,
              subType: asset.subType,
              environment: asset.environment,
              riskScore: asset.riskScore,
              metadata: asset.metadata || {},
              tags: asset.tags || [],
              owner: asset.owner || null,
              lastScannedAt: new Date(),
            });
            assetsUpdated++;
          } else {
            const data: InsertSecurityGraphAsset = {
              orgId,
              name: asset.name,
              type: asset.type,
              subType: asset.subType,
              environment: asset.environment,
              riskScore: asset.riskScore,
              metadata: asset.metadata || {},
              tags: asset.tags || [],
              owner: asset.owner || null,
              resolutionKey,
              lastScannedAt: new Date(),
            };
            await storage.createSecurityGraphAsset(data);
            assetsCreated++;
          }
        }
      }

      // Create relationships by resolving keys to asset IDs
      if (payload.relationships) {
        for (const rel of payload.relationships) {
          const source = await storage.getSecurityGraphAssetByResolutionKey(orgId, rel.sourceResolutionKey);
          const target = await storage.getSecurityGraphAssetByResolutionKey(orgId, rel.targetResolutionKey);
          if (source && target) {
            const relData: InsertSecurityGraphRelationship = {
              orgId,
              sourceId: source.id,
              targetId: target.id,
              relationship: rel.relationship,
              weight: rel.weight ?? 1,
              metadata: rel.metadata || {},
              bidirectional: rel.bidirectional ?? false,
            };
            await storage.createSecurityGraphRelationship(relData);
            relationshipsCreated++;
          }
        }
      }

      res.json({ assetsCreated, assetsUpdated, relationshipsCreated });
    } catch (error) {
      log.error("Security graph ingest error", { error: String(error) });
      res.status(500).json({ message: "Failed to ingest entities" });
    }
  });

  // Find paths between two assets (BFS in app layer from DB data)
  app.post("/api/security-graph/find-paths", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const { sourceId, targetId, maxDepth } = req.body as {
        sourceId: string;
        targetId: string;
        maxDepth?: number;
      };
      if (!sourceId || typeof sourceId !== "string") return res.status(400).json({ message: "sourceId is required" });
      if (!targetId || typeof targetId !== "string") return res.status(400).json({ message: "targetId is required" });
      if (maxDepth !== undefined && (typeof maxDepth !== "number" || maxDepth < 1 || maxDepth > 10)) {
        return res.status(400).json({ message: "maxDepth must be between 1 and 10" });
      }

      const allRelationships = await storage.getSecurityGraphRelationships(orgId);
      const adjacency = new Map<string, Array<{ targetId: string; relId: string }>>();
      for (const r of allRelationships) {
        if (!adjacency.has(r.sourceId)) adjacency.set(r.sourceId, []);
        adjacency.get(r.sourceId)!.push({ targetId: r.targetId, relId: r.id });
        if (r.bidirectional) {
          if (!adjacency.has(r.targetId)) adjacency.set(r.targetId, []);
          adjacency.get(r.targetId)!.push({ targetId: r.sourceId, relId: r.id });
        }
      }

      const limit = maxDepth ?? 5;
      const paths: string[][] = [];
      const queue: string[][] = [[sourceId]];
      while (queue.length > 0 && paths.length < 10) {
        const current = queue.shift()!;
        const last = current[current.length - 1];
        if (last === targetId && current.length > 1) {
          paths.push(current);
          continue;
        }
        if (current.length > limit) continue;
        const neighbors = adjacency.get(last) || [];
        for (const n of neighbors) {
          if (!current.includes(n.targetId)) {
            queue.push([...current, n.targetId]);
          }
        }
      }

      res.json(paths);
    } catch (error) {
      log.error("Security graph find-paths error", { error: String(error) });
      res.status(500).json({ message: "Failed to find paths" });
    }
  });

  // Get single asset
  app.get("/api/security-graph/assets/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getSecurityGraphAsset(p(req.params.id), orgId);
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      res.json(asset);
    } catch (error) {
      log.error("Security graph asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset" });
    }
  });

  // Delete asset
  app.delete("/api/security-graph/assets/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const deleted = await storage.deleteSecurityGraphAsset(p(req.params.id), orgId);
      if (!deleted) return res.status(404).json({ message: "Asset not found" });
      res.json({ deleted: true });
    } catch (error) {
      log.error("Security graph delete asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete asset" });
    }
  });

  // Get asset neighbors
  app.get("/api/security-graph/assets/:id/neighbors", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const assetId = p(req.params.id);
      const asset = await storage.getSecurityGraphAsset(assetId, orgId);
      if (!asset) return res.status(404).json({ message: "Asset not found" });

      const rels = await storage.getSecurityGraphRelationshipsByAsset(assetId);
      const neighborIds = new Set<string>();
      for (const r of rels) {
        if (r.sourceId !== assetId) neighborIds.add(r.sourceId);
        if (r.targetId !== assetId) neighborIds.add(r.targetId);
      }

      const neighbors = [];
      for (const nId of neighborIds) {
        const neighbor = await storage.getSecurityGraphAsset(nId, orgId);
        if (neighbor) neighbors.push(neighbor);
      }

      res.json({ asset, neighbors, relationships: rels });
    } catch (error) {
      log.error("Security graph neighbors error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset neighbors" });
    }
  });

  // Attack paths placeholder (computed from graph data)
  app.get("/api/security-graph/attack-paths", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const assets = await storage.getSecurityGraphAssets(orgId);
      const highRisk = assets.filter((a) => a.riskScore >= 0.7);
      // Return high-risk assets as potential attack path entry points
      res.json(
        highRisk.map((a) => ({
          id: a.id,
          name: `Path via ${a.name}`,
          description: `High-risk ${a.type} asset in ${a.environment}`,
          riskScore: a.riskScore,
          entryPoint: a,
          hopCount: 1,
        })),
      );
    } catch (error) {
      log.error("Attack paths error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack paths" });
    }
  });

  // Single attack path (look up asset)
  app.get("/api/security-graph/attack-paths/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getSecurityGraphAsset(p(req.params.id), orgId);
      if (!asset) return res.status(404).json({ message: "Attack path not found" });
      const rels = await storage.getSecurityGraphRelationshipsByAsset(asset.id);
      res.json({
        id: asset.id,
        name: `Path via ${asset.name}`,
        description: `${asset.type} asset in ${asset.environment}`,
        riskScore: asset.riskScore,
        entryPoint: asset,
        edges: rels,
        hopCount: rels.length,
      });
    } catch (error) {
      log.error("Attack path detail error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack path" });
    }
  });

  // Delete relationship
  app.delete("/api/security-graph/relationships/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const deleted = await storage.deleteSecurityGraphRelationship(p(req.params.id), orgId);
      if (!deleted) return res.status(404).json({ message: "Relationship not found" });
      res.json({ deleted: true });
    } catch (error) {
      log.error("Security graph delete relationship error", { error: String(error) });
      res.status(500).json({ message: "Failed to delete relationship" });
    }
  });

  // Stats
  app.get("/api/security-graph/stats", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const [assetCount, relCount, assets] = await Promise.all([
        storage.countSecurityGraphAssets(orgId),
        storage.countSecurityGraphRelationships(orgId),
        storage.getSecurityGraphAssets(orgId),
      ]);

      const typeBreakdown: Record<string, number> = {};
      const envBreakdown: Record<string, number> = {};
      let totalRisk = 0;
      for (const a of assets) {
        typeBreakdown[a.type] = (typeBreakdown[a.type] || 0) + 1;
        envBreakdown[a.environment] = (envBreakdown[a.environment] || 0) + 1;
        totalRisk += a.riskScore;
      }

      res.json({
        totalAssets: assetCount,
        totalRelationships: relCount,
        typeBreakdown,
        environmentBreakdown: envBreakdown,
        averageRiskScore: assets.length > 0 ? totalRisk / assets.length : 0,
        highRiskAssets: assets.filter((a) => a.riskScore >= 0.7).length,
      });
    } catch (error) {
      log.error("Security graph stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security graph stats" });
    }
  });
}
