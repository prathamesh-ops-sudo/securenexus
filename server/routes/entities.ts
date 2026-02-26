import type { Express, Request, Response } from "express";
import { logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { getCorrelationCluster, getCorrelationClusters, promoteClusterToIncident, runCorrelationScan } from "../correlation-engine";
import { addEntityAlias, getEntity, getEntityAlerts, getEntityAliases, getEntityGraph, getEntityGraphWithEdges, getEntityRelationships, mergeEntities, updateEntityMetadata } from "../entity-resolver";
import { getAttackPath, getAttackPaths, getCampaign, getCampaigns, runGraphCorrelation } from "../graph-correlation";

export function registerEntitiesRoutes(app: Express): void {
  // Entity Graph Routes (Phase 7.1)
  app.get("/api/entities", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const entityList = await getEntityGraph(orgId);
      res.json(entityList);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entities" }); }
  });

  app.get("/api/entities/:id", isAuthenticated, async (req, res) => {
    try {
      const entity = await getEntity(p(req.params.id));
      if (!entity) return res.status(404).json({ message: "Entity not found" });
      res.json(entity);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entity" }); }
  });

  app.get("/api/entities/:id/alerts", isAuthenticated, async (req, res) => {
    try {
      const entityAlerts = await getEntityAlerts(p(req.params.id));
      res.json(entityAlerts);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entity alerts" }); }
  });

  // Correlation Engine Routes (Phase 7.1)
  app.get("/api/correlation/clusters", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const clusters = await getCorrelationClusters(orgId);
      res.json(clusters);
    } catch (error) { res.status(500).json({ message: "Failed to fetch correlation clusters" }); }
  });

  app.get("/api/correlation/clusters/:id", isAuthenticated, async (req, res) => {
    try {
      const cluster = await getCorrelationCluster(p(req.params.id));
      if (!cluster) return res.status(404).json({ message: "Cluster not found" });
      res.json(cluster);
    } catch (error) { res.status(500).json({ message: "Failed to fetch cluster" }); }
  });

  app.post("/api/correlation/scan", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.body.orgId as string | undefined;
      const results = await runCorrelationScan(orgId);
      res.json({ scanned: true, correlations: results.length, results });
    } catch (error) { res.status(500).json({ message: "Failed to run correlation scan" }); }
  });

  app.post("/api/correlation/clusters/:id/promote", isAuthenticated, async (req, res) => {
    try {
      const { title, severity } = req.body;
      if (!title || !severity) return res.status(400).json({ message: "Title and severity are required" });
      const result = await promoteClusterToIncident(p(req.params.id), title, severity);
      res.json(result);
    } catch (error) { logger.child("routes").error("Promote cluster error", { error: String(error) }); res.status(500).json({ message: "Failed to promote cluster" }); }
  });

  app.get("/api/entities/:id/aliases", isAuthenticated, async (req, res) => {
    try {
      const aliases = await getEntityAliases(p(req.params.id));
      res.json(aliases);
    } catch (error) { res.status(500).json({ message: "Failed to fetch aliases" }); }
  });

  app.post("/api/entities/:id/aliases", isAuthenticated, async (req, res) => {
    try {
      const { aliasType, aliasValue, source } = req.body;
      if (!aliasType || !aliasValue) return res.status(400).json({ message: "aliasType and aliasValue required" });
      const alias = await addEntityAlias(p(req.params.id), aliasType, aliasValue, source);
      res.json(alias);
    } catch (error) { res.status(500).json({ message: "Failed to add alias" }); }
  });

  app.post("/api/entities/merge", isAuthenticated, async (req, res) => {
    try {
      const { targetId, sourceId } = req.body;
      if (!targetId || !sourceId) return res.status(400).json({ message: "targetId and sourceId required" });
      const merged = await mergeEntities(targetId, sourceId);
      res.json(merged);
    } catch (error) { logger.child("routes").error("Merge entities error", { error: String(error) }); res.status(500).json({ message: "Failed to merge entities" }); }
  });

  app.patch("/api/entities/:id/metadata", isAuthenticated, async (req, res) => {
    try {
      const updated = await updateEntityMetadata(p(req.params.id), req.body);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update metadata" }); }
  });

  app.get("/api/entities/:id/relationships", isAuthenticated, async (req, res) => {
    try {
      const relationships = await getEntityRelationships(p(req.params.id));
      res.json(relationships);
    } catch (error) { res.status(500).json({ message: "Failed to fetch relationships" }); }
  });

  app.get("/api/entity-graph", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const limit = parseInt(req.query.limit as string, 10) || 80;
      const graph = await getEntityGraphWithEdges(orgId, limit);
      res.json(graph);
    } catch (error) { res.status(500).json({ message: "Failed to fetch entity graph" }); }
  });

  // Phase 2: Graph-Based Correlation Engine
  app.post("/api/correlation/graph-scan", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.body.orgId as string | undefined;
      const results = await runGraphCorrelation(orgId);
      res.json({ scanned: true, attackPaths: results.attackPaths.length, campaigns: results.campaignsCreated, results });
    } catch (error: any) {
      logger.child("routes").error("Graph correlation error", { error: String(error) });
      res.status(500).json({ message: "Failed to run graph correlation scan" });
    }
  });

  app.get("/api/attack-paths", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const paths = await getAttackPaths(orgId);
      res.json(paths);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack paths" }); }
  });

  app.get("/api/attack-paths/:id", isAuthenticated, async (req, res) => {
    try {
      const path = await getAttackPath(p(req.params.id));
      if (!path) return res.status(404).json({ message: "Attack path not found" });
      res.json(path);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack path" }); }
  });

  app.get("/api/campaigns", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const campaignList = await getCampaigns(orgId);
      res.json(campaignList);
    } catch (error) { res.status(500).json({ message: "Failed to fetch campaigns" }); }
  });

  app.get("/api/campaigns/:id", isAuthenticated, async (req, res) => {
    try {
      const campaign = await getCampaign(p(req.params.id));
      if (!campaign) return res.status(404).json({ message: "Campaign not found" });
      res.json(campaign);
    } catch (error) { res.status(500).json({ message: "Failed to fetch campaign" }); }
  });

  app.get("/api/entities/:id/enrichment", isAuthenticated, async (req, res) => {
    try {
      const { getEnrichmentForEntity } = await import("../threat-enrichment");
      const entity = await getEntity(p(req.params.id));
      if (!entity) return res.status(404).json({ message: "Entity not found" });
      const enrichment = getEnrichmentForEntity(entity.metadata as Record<string, any> | null);
      res.json({
        entityId: entity.id,
        entityType: entity.type,
        entityValue: entity.value,
        riskScore: entity.riskScore,
        enrichment,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch enrichment data" });
    }
  });

  app.post("/api/entities/:id/enrich", isAuthenticated, async (req, res) => {
    try {
      const { enrichEntity } = await import("../threat-enrichment");
      const entity = await getEntity(p(req.params.id));
      if (!entity) return res.status(404).json({ message: "Entity not found" });
      const force = req.body.force === true;
      const results = await enrichEntity(entity.id, force);
      const updatedEntity = await getEntity(entity.id);
      res.json({
        entityId: entity.id,
        entityType: entity.type,
        entityValue: entity.value,
        riskScore: updatedEntity?.riskScore ?? entity.riskScore,
        results,
        enrichedAt: new Date().toISOString(),
      });
    } catch (error) {
      logger.child("routes").error("Manual enrichment error", { error: String(error) });
      res.status(500).json({ message: "Failed to enrich entity" });
    }
  });

  // Alert Dedup Clusters
  app.get("/api/dedup-clusters", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const clusters = await storage.getAlertDedupClusters(orgId);
      res.json(clusters);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dedup clusters" });
    }
  });

  app.get("/api/dedup-clusters/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const cluster = await storage.getAlertDedupCluster(p(req.params.id));
      if (!cluster) return res.status(404).json({ message: "Dedup cluster not found" });
      if (cluster.orgId && user?.orgId && cluster.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(cluster);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch dedup cluster" });
    }
  });

  app.post("/api/dedup-clusters/scan", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const allAlerts = await storage.getAlerts(orgId);
      const clustersCreated: any[] = [];
      const processed = new Set<string>();

      for (let i = 0; i < allAlerts.length; i++) {
        if (processed.has(allAlerts[i].id)) continue;
        const baseAlert = allAlerts[i];
        const similarAlerts: typeof allAlerts = [];

        for (let j = i + 1; j < allAlerts.length; j++) {
          if (processed.has(allAlerts[j].id)) continue;
          const candidate = allAlerts[j];

          const baseTime = baseAlert.createdAt ? new Date(baseAlert.createdAt).getTime() : 0;
          const candTime = candidate.createdAt ? new Date(candidate.createdAt).getTime() : 0;
          const within24h = Math.abs(baseTime - candTime) < 24 * 60 * 60 * 1000;

          const titleMatch = within24h && baseAlert.title && candidate.title &&
            (baseAlert.title.toLowerCase().includes(candidate.title.toLowerCase().substring(0, Math.min(20, candidate.title.length))) ||
             candidate.title.toLowerCase().includes(baseAlert.title.toLowerCase().substring(0, Math.min(20, baseAlert.title.length))));

          const entityMatch = (baseAlert.sourceIp && baseAlert.sourceIp === candidate.sourceIp) ||
            (baseAlert.hostname && baseAlert.hostname === candidate.hostname) ||
            (baseAlert.domain && baseAlert.domain === candidate.domain);

          if (titleMatch || entityMatch) {
            similarAlerts.push(candidate);
          }
        }

        if (similarAlerts.length > 0) {
          const cluster = await storage.createAlertDedupCluster({
            orgId,
            canonicalAlertId: baseAlert.id,
            matchReason: `Grouped ${similarAlerts.length + 1} similar alerts`,
            matchConfidence: 0.8,
            alertCount: similarAlerts.length + 1,
          });

          await storage.updateAlert(baseAlert.id, { dedupClusterId: cluster.id });
          processed.add(baseAlert.id);
          for (const sa of similarAlerts) {
            await storage.updateAlert(sa.id, { dedupClusterId: cluster.id });
            processed.add(sa.id);
          }
          clustersCreated.push(cluster);
        }
      }

      res.json({ clustersCreated: clustersCreated.length, clusters: clustersCreated });
    } catch (error) {
      res.status(500).json({ message: "Failed to run dedup scan" });
    }
  });

}
