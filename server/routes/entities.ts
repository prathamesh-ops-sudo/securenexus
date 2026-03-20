import type { Express } from "express";
import rateLimit from "express-rate-limit";
import { getOrgId, logger, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { replyRateLimit } from "../api-response";
import {
  getCorrelationCluster,
  getCorrelationClusters,
  promoteClusterToIncident,
  runCorrelationScan,
} from "../correlation-engine";
import {
  addEntityAlias,
  getEntity,
  getEntityAlerts,
  getEntityAliases,
  getEntityGraph,
  getEntityGraphWithEdges,
  getEntityRelationships,
  mergeEntities,
  updateEntityMetadata,
} from "../entity-resolver";
import { getAttackPath, getAttackPaths, getCampaign, getCampaigns, runGraphCorrelation } from "../graph-correlation";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { db } from "../db";
import { campaigns } from "@shared/schema";
import { eq } from "drizzle-orm";

export function registerEntitiesRoutes(app: Express): void {
  // Entity Graph Routes (Phase 7.1)
  app.get(
    "/api/entities",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityList = await getEntityGraph(orgId);
        res.json(entityList);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch entities" });
      }
    },
  );

  app.get(
    "/api/entities/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const entity = await getEntity(p(req.params.id));
        if (!entity) return res.status(404).json({ message: "Entity not found" });
        res.json(entity);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch entity" });
      }
    },
  );

  app.get(
    "/api/entities/:id/alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const entityAlerts = await getEntityAlerts(p(req.params.id));
        res.json(entityAlerts);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch entity alerts" });
      }
    },
  );

  // Correlation Engine Routes (Phase 7.1)
  app.get(
    "/api/correlation/clusters",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const clusters = await getCorrelationClusters(orgId);
        res.json(clusters);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch correlation clusters" });
      }
    },
  );

  app.get(
    "/api/correlation/clusters/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const cluster = await getCorrelationCluster(p(req.params.id));
        if (!cluster) return res.status(404).json({ message: "Cluster not found" });
        res.json(cluster);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch cluster" });
      }
    },
  );

  app.post(
    "/api/correlation/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const results = await runCorrelationScan(orgId);
        res.json({ scanned: true, correlations: results.length, results });
      } catch (error) {
        res.status(500).json({ message: "Failed to run correlation scan" });
      }
    },
  );

  app.post(
    "/api/correlation/clusters/:id/promote",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { title, severity } = req.body;
        if (!title || !severity) return res.status(400).json({ message: "Title and severity are required" });
        const result = await promoteClusterToIncident(p(req.params.id), title, severity);
        res.json(result);
      } catch (error) {
        logger.child("routes").error("Promote cluster error", { error: String(error) });
        res.status(500).json({ message: "Failed to promote cluster" });
      }
    },
  );

  app.get(
    "/api/entities/:id/aliases",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const aliases = await getEntityAliases(p(req.params.id));
        res.json(aliases);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch aliases" });
      }
    },
  );

  app.post(
    "/api/entities/:id/aliases",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { aliasType, aliasValue, source } = req.body;
        if (!aliasType || !aliasValue) return res.status(400).json({ message: "aliasType and aliasValue required" });
        const alias = await addEntityAlias(p(req.params.id), aliasType, aliasValue, source);
        res.json(alias);
      } catch (error) {
        res.status(500).json({ message: "Failed to add alias" });
      }
    },
  );

  app.post(
    "/api/entities/merge",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { targetId, sourceId } = req.body;
        if (!targetId || !sourceId) return res.status(400).json({ message: "targetId and sourceId required" });
        const merged = await mergeEntities(targetId, sourceId);
        res.json(merged);
      } catch (error) {
        logger.child("routes").error("Merge entities error", { error: String(error) });
        res.status(500).json({ message: "Failed to merge entities" });
      }
    },
  );

  app.patch(
    "/api/entities/:id/metadata",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const updated = await updateEntityMetadata(p(req.params.id), req.body);
        res.json(updated);
      } catch (error) {
        res.status(500).json({ message: "Failed to update metadata" });
      }
    },
  );

  app.get(
    "/api/entities/:id/relationships",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const relationships = await getEntityRelationships(p(req.params.id));
        res.json(relationships);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch relationships" });
      }
    },
  );

  app.get(
    "/api/entity-graph",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const limit = parseInt(req.query.limit as string, 10) || 80;
        const graph = await getEntityGraphWithEdges(orgId, limit);
        res.json(graph);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch entity graph" });
      }
    },
  );

  // Phase 2: Graph-Based Correlation Engine
  const graphScanLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => (req as any).user?.id || req.ip || "unknown",
    handler: (_req, res) => replyRateLimit(res, "Graph scan rate limit exceeded. Max 5 per minute."),
  });

  app.post(
    "/api/correlation/graph-scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    graphScanLimiter,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const results = await runGraphCorrelation(orgId);
        res.json({
          scanned: true,
          attackPaths: results.attackPaths.length,
          campaigns: results.campaignsCreated,
          results,
        });
      } catch (error: any) {
        logger.child("routes").error("Graph correlation error", { error: String(error) });
        res.status(500).json({ message: "Failed to run graph correlation scan" });
      }
    },
  );

  app.get(
    "/api/attack-paths",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const paths = await getAttackPaths(orgId);
        res.json(paths);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch attack paths" });
      }
    },
  );

  app.get(
    "/api/attack-paths/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const path = await getAttackPath(p(req.params.id));
        if (!path) return res.status(404).json({ message: "Attack path not found" });
        res.json(path);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch attack path" });
      }
    },
  );

  app.get(
    "/api/campaigns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignList = await getCampaigns(orgId);
        res.json(campaignList);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch campaigns" });
      }
    },
  );

  app.get(
    "/api/campaigns/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const campaign = await getCampaign(p(req.params.id));
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        res.json(campaign);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch campaign" });
      }
    },
  );

  app.get(
    "/api/entities/:id/enrichment",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
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
    },
  );

  app.post(
    "/api/entities/:id/enrich",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
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
    },
  );

  // Alert Dedup Clusters
  app.get(
    "/api/dedup-clusters",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = (req as any).user?.orgId;
        const clusters = await storage.getAlertDedupClusters(orgId);
        res.json(clusters);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch dedup clusters" });
      }
    },
  );

  app.get(
    "/api/dedup-clusters/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const user = (req as any).user;
        const cluster = await storage.getAlertDedupCluster(p(req.params.id));
        if (!cluster) return res.status(404).json({ message: "Dedup cluster not found" });
        if (cluster.orgId && user?.orgId && cluster.orgId !== user.orgId)
          return res.status(403).json({ message: "Access denied" });
        res.json(cluster);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch dedup cluster" });
      }
    },
  );

  app.post(
    "/api/dedup-clusters/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
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

            const titleMatch =
              within24h &&
              baseAlert.title &&
              candidate.title &&
              (baseAlert.title
                .toLowerCase()
                .includes(candidate.title.toLowerCase().substring(0, Math.min(20, candidate.title.length))) ||
                candidate.title
                  .toLowerCase()
                  .includes(baseAlert.title.toLowerCase().substring(0, Math.min(20, baseAlert.title.length))));

            const entityMatch =
              (baseAlert.sourceIp && baseAlert.sourceIp === candidate.sourceIp) ||
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
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 8.4: Campaign CRUD with full lifecycle
  // ═══════════════════════════════════════════════════════════════════════════

  // POST /api/campaigns — Create a campaign manually
  app.post(
    "/api/campaigns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          name,
          description,
          status = "active",
          threatActorId,
          targetSectors,
          targetRegions,
          techniques,
          iocs,
          killChainPhases,
          motivation,
        } = req.body;

        if (!name) return res.status(400).json({ message: "Campaign name is required" });

        const fingerprint = `manual-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

        const [created] = await db
          .insert(campaigns)
          .values({
            orgId,
            name,
            fingerprint,
            tacticsSequence: techniques || [],
            entitySignature: targetSectors || [],
            sourceSignature: targetRegions || [],
            clusterIds: iocs || [],
            attackPathIds: killChainPhases || [],
            confidence: 80,
            alertCount: 0,
            status,
            firstSeenAt: new Date(),
            lastSeenAt: new Date(),
          })
          .returning();

        // Build enriched response
        const enriched = buildCampaignDetail(created, {
          description,
          threatActorId,
          targetSectors,
          targetRegions,
          techniques,
          iocs,
          killChainPhases,
          motivation,
        });

        res.status(201).json(enriched);
      } catch (error) {
        logger.child("routes").error("Create campaign error", { error: String(error) });
        res.status(500).json({ message: "Failed to create campaign" });
      }
    },
  );

  // PATCH /api/campaigns/:id — Update campaign
  app.patch(
    "/api/campaigns/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignId = String(req.params.id);
        const campaign = await getCampaign(campaignId);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.orgId && campaign.orgId !== orgId) return res.status(403).json({ message: "Access denied" });

        const allowedFields: Record<string, boolean> = {
          name: true,
          status: true,
          confidence: true,
          tacticsSequence: true,
          entitySignature: true,
          sourceSignature: true,
          clusterIds: true,
          attackPathIds: true,
        };

        const updates: Record<string, unknown> = { updatedAt: new Date() };
        for (const [key, val] of Object.entries(req.body)) {
          if (allowedFields[key]) updates[key] = val;
        }

        const [updated] = await db.update(campaigns).set(updates).where(eq(campaigns.id, campaignId)).returning();

        res.json(updated);
      } catch (error) {
        logger.child("routes").error("Update campaign error", { error: String(error) });
        res.status(500).json({ message: "Failed to update campaign" });
      }
    },
  );

  // DELETE /api/campaigns/:id — Delete campaign
  app.delete(
    "/api/campaigns/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignId = String(req.params.id);
        const campaign = await getCampaign(campaignId);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.orgId && campaign.orgId !== orgId) return res.status(403).json({ message: "Access denied" });

        await db.delete(campaigns).where(eq(campaigns.id, campaignId));
        res.json({ message: "Campaign deleted", id: campaignId });
      } catch (error) {
        logger.child("routes").error("Delete campaign error", { error: String(error) });
        res.status(500).json({ message: "Failed to delete campaign" });
      }
    },
  );

  // GET /api/campaigns/:id/detail — Rich campaign detail (8.1 support)
  app.get(
    "/api/campaigns/:id/detail",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignId = String(req.params.id);
        const campaign = await getCampaign(campaignId);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.orgId && campaign.orgId !== orgId) return res.status(403).json({ message: "Access denied" });

        // Build rich detail with simulated enrichment
        const detail = buildCampaignDetail(campaign, null);

        // Fetch related alerts
        const orgAlerts = await storage.getAlerts(orgId);
        const campaignTechniques = (campaign.tacticsSequence || []) as string[];
        const campaignEntities = (campaign.entitySignature || []) as string[];

        const relatedAlerts = orgAlerts
          .filter((a) => {
            const titleMatch = campaignEntities.some((e) => a.title && a.title.toLowerCase().includes(e.toLowerCase()));
            const techniqueMatch = campaignTechniques.some(
              (t) =>
                (a.mitreTactic && a.mitreTactic.toLowerCase().includes(t.toLowerCase())) ||
                (a.mitreTechnique && a.mitreTechnique.toLowerCase().includes(t.toLowerCase())),
            );
            return titleMatch || techniqueMatch;
          })
          .slice(0, 20)
          .map((a) => ({
            id: a.id,
            title: a.title,
            severity: a.severity,
            status: a.status,
            createdAt: a.createdAt,
            mitreTactic: a.mitreTactic,
            mitreTechnique: a.mitreTechnique,
            sourceIp: a.sourceIp,
            hostname: a.hostname,
          }));

        // Fetch related IOCs
        const orgIocs = await storage.getIocEntries(orgId, undefined, undefined, undefined, 500);
        const relatedIocs = orgIocs
          .filter((ioc) => {
            const tags = (ioc.tags as string[]) || [];
            return (
              tags.some((t) => campaign.name.toLowerCase().includes(t.toLowerCase())) ||
              campaignEntities.some(
                (e) =>
                  ioc.iocValue.toLowerCase().includes(e.toLowerCase()) ||
                  (ioc.metadata && JSON.stringify(ioc.metadata).toLowerCase().includes(e.toLowerCase())),
              )
            );
          })
          .slice(0, 30)
          .map((ioc) => ({
            id: ioc.id,
            iocType: ioc.iocType,
            iocValue: ioc.iocValue,
            confidence: ioc.confidence,
            severity: ioc.severity,
            source: ioc.source,
            status: ioc.status,
            firstSeen: ioc.createdAt,
          }));

        res.json({
          ...detail,
          relatedAlerts,
          relatedIocs,
          alertCount: relatedAlerts.length,
          iocCount: relatedIocs.length,
        });
      } catch (error) {
        logger.child("routes").error("Campaign detail error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch campaign detail" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 8.5: Campaign-alert correlation
  // ═══════════════════════════════════════════════════════════════════════════

  // POST /api/campaigns/correlate-alerts — Run alert correlation
  app.post(
    "/api/campaigns/correlate-alerts",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const orgCampaigns = await getCampaigns(orgId);
        const orgAlerts = await storage.getAlerts(orgId);

        const correlations: Array<{
          campaignId: string;
          campaignName: string;
          alertId: string;
          alertTitle: string;
          matchType: string;
          confidence: number;
        }> = [];

        for (const campaign of orgCampaigns) {
          const techniques = (campaign.tacticsSequence || []) as string[];
          const entities = (campaign.entitySignature || []) as string[];
          const sources = (campaign.sourceSignature || []) as string[];

          for (const alert of orgAlerts) {
            const matches: string[] = [];
            let confidence = 0;

            // TTP match
            if (
              alert.mitreTechnique &&
              techniques.some((t) => alert.mitreTechnique!.toLowerCase().includes(t.toLowerCase()))
            ) {
              matches.push("ttp_match");
              confidence += 35;
            }
            if (
              alert.mitreTactic &&
              techniques.some((t) => alert.mitreTactic!.toLowerCase().includes(t.toLowerCase()))
            ) {
              matches.push("tactic_match");
              confidence += 25;
            }

            // Entity/IOC match
            if (
              entities.some(
                (e) =>
                  (alert.sourceIp && alert.sourceIp.includes(e)) ||
                  (alert.hostname && alert.hostname.toLowerCase().includes(e.toLowerCase())) ||
                  (alert.domain && alert.domain.toLowerCase().includes(e.toLowerCase())),
              )
            ) {
              matches.push("ioc_match");
              confidence += 40;
            }

            // Behavioral pattern match
            if (alert.title && sources.some((s) => alert.title!.toLowerCase().includes(s.toLowerCase()))) {
              matches.push("behavioral_match");
              confidence += 20;
            }

            if (matches.length > 0 && confidence >= 25) {
              correlations.push({
                campaignId: campaign.id,
                campaignName: campaign.name,
                alertId: alert.id,
                alertTitle: alert.title || "Untitled Alert",
                matchType: matches.join(", "),
                confidence: Math.min(confidence, 100),
              });
            }
          }
        }

        // Sort by confidence descending
        correlations.sort((a, b) => b.confidence - a.confidence);

        const summary = {
          totalAlerts: orgAlerts.length,
          totalCampaigns: orgCampaigns.length,
          correlationsFound: correlations.length,
          highConfidence: correlations.filter((c) => c.confidence >= 70).length,
          mediumConfidence: correlations.filter((c) => c.confidence >= 40 && c.confidence < 70).length,
          lowConfidence: correlations.filter((c) => c.confidence < 40).length,
        };

        res.json({ correlations: correlations.slice(0, 100), summary });
      } catch (error) {
        logger.child("routes").error("Campaign-alert correlation error", { error: String(error) });
        res.status(500).json({ message: "Failed to correlate alerts with campaigns" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 8.6: Threat actor profiles
  // ═══════════════════════════════════════════════════════════════════════════

  // GET /api/threat-actors — List threat actor profiles
  app.get(
    "/api/threat-actors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const orgCampaigns = await getCampaigns(orgId);

        // Build threat actor profiles from campaigns + simulated enrichment
        const actorProfiles = buildThreatActorProfiles(orgCampaigns);
        res.json(actorProfiles);
      } catch (error) {
        logger.child("routes").error("Threat actors list error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch threat actor profiles" });
      }
    },
  );

  // GET /api/threat-actors/:actorId — Single threat actor profile
  app.get(
    "/api/threat-actors/:actorId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const actorId = String(req.params.actorId);
        const orgCampaigns = await getCampaigns(orgId);
        const allActors = buildThreatActorProfiles(orgCampaigns);
        const actor = allActors.find((a) => a.id === actorId);
        if (!actor) return res.status(404).json({ message: "Threat actor not found" });
        res.json(actor);
      } catch (error) {
        logger.child("routes").error("Threat actor detail error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch threat actor profile" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 8.7: Campaign → MITRE ATT&CK mapping
  // ═══════════════════════════════════════════════════════════════════════════

  // GET /api/campaigns/:id/attack-mapping — ATT&CK matrix mapping for a campaign
  app.get(
    "/api/campaigns/:id/attack-mapping",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignId = String(req.params.id);
        const campaign = await getCampaign(campaignId);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.orgId && campaign.orgId !== orgId) return res.status(403).json({ message: "Access denied" });

        const mapping = buildAttackMapping(campaign);
        res.json(mapping);
      } catch (error) {
        logger.child("routes").error("Campaign ATT&CK mapping error", { error: String(error) });
        res.status(500).json({ message: "Failed to build ATT&CK mapping" });
      }
    },
  );

  // GET /api/campaigns/attack-matrix — Aggregate ATT&CK matrix across all campaigns
  app.get(
    "/api/campaigns/attack-matrix",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const orgCampaigns = await getCampaigns(orgId);
        const matrix = buildAggregateAttackMatrix(orgCampaigns);
        res.json(matrix);
      } catch (error) {
        logger.child("routes").error("Aggregate ATT&CK matrix error", { error: String(error) });
        res.status(500).json({ message: "Failed to build aggregate ATT&CK matrix" });
      }
    },
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 8.8: Campaign → Kill Chain progression
  // ═══════════════════════════════════════════════════════════════════════════

  // GET /api/campaigns/:id/kill-chain — Kill chain phase progression
  app.get(
    "/api/campaigns/:id/kill-chain",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignId = String(req.params.id);
        const campaign = await getCampaign(campaignId);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.orgId && campaign.orgId !== orgId) return res.status(403).json({ message: "Access denied" });

        const killChain = buildKillChainProgression(campaign);
        res.json(killChain);
      } catch (error) {
        logger.child("routes").error("Campaign kill chain error", { error: String(error) });
        res.status(500).json({ message: "Failed to build kill chain progression" });
      }
    },
  );

  // GET /api/campaigns/:id/timeline — Campaign activity timeline (8.2 support)
  app.get(
    "/api/campaigns/:id/timeline",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const campaignId = String(req.params.id);
        const campaign = await getCampaign(campaignId);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.orgId && campaign.orgId !== orgId) return res.status(403).json({ message: "Access denied" });

        const timeline = buildCampaignTimeline(campaign);
        res.json(timeline);
      } catch (error) {
        logger.child("routes").error("Campaign timeline error", { error: String(error) });
        res.status(500).json({ message: "Failed to build campaign timeline" });
      }
    },
  );

  // GET /api/campaigns/relationships — Campaign relationship map (8.3 support)
  app.get(
    "/api/campaigns/relationships",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const orgCampaigns = await getCampaigns(orgId);
        const relationships = buildCampaignRelationships(orgCampaigns);
        res.json(relationships);
      } catch (error) {
        logger.child("routes").error("Campaign relationships error", { error: String(error) });
        res.status(500).json({ message: "Failed to build campaign relationships" });
      }
    },
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper functions for campaign features 8.1-8.8
// ═══════════════════════════════════════════════════════════════════════════════

const MITRE_TACTICS = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

const MITRE_TECHNIQUES: Record<string, Array<{ id: string; name: string; tactic: string }>> = {
  TA0043: [
    { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
    { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
    { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance" },
  ],
  TA0001: [
    { id: "T1566", name: "Phishing", tactic: "Initial Access" },
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
    { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
  ],
  TA0002: [
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution" },
    { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution" },
  ],
  TA0003: [
    { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
    { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence" },
    { id: "T1136", name: "Create Account", tactic: "Persistence" },
  ],
  TA0004: [
    { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
    { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation" },
  ],
  TA0005: [
    { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
    { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
    { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion" },
  ],
  TA0006: [
    { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" },
    { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
    { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access" },
  ],
  TA0007: [
    { id: "T1087", name: "Account Discovery", tactic: "Discovery" },
    { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
    { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  ],
  TA0008: [
    { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
    { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
  ],
  TA0009: [
    { id: "T1005", name: "Data from Local System", tactic: "Collection" },
    { id: "T1114", name: "Email Collection", tactic: "Collection" },
  ],
  TA0011: [
    { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
    { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control" },
  ],
  TA0010: [
    { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  ],
  TA0040: [
    { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
    { id: "T1489", name: "Service Stop", tactic: "Impact" },
    { id: "T1529", name: "System Shutdown/Reboot", tactic: "Impact" },
  ],
};

const KILL_CHAIN_PHASES = [
  {
    phase: "reconnaissance",
    label: "Reconnaissance",
    order: 1,
    description: "Target identification, information gathering, open-source research",
  },
  {
    phase: "weaponization",
    label: "Weaponization",
    order: 2,
    description: "Payload creation, exploit development, tool preparation",
  },
  {
    phase: "delivery",
    label: "Delivery",
    order: 3,
    description: "Phishing emails, watering holes, USB drops, exploit kits",
  },
  {
    phase: "exploitation",
    label: "Exploitation",
    order: 4,
    description: "Vulnerability exploitation, code execution, user interaction",
  },
  {
    phase: "installation",
    label: "Installation",
    order: 5,
    description: "Malware installation, backdoor deployment, persistence mechanisms",
  },
  {
    phase: "command_and_control",
    label: "Command & Control",
    order: 6,
    description: "C2 channel establishment, beaconing, remote access",
  },
  {
    phase: "actions_on_objectives",
    label: "Actions on Objectives",
    order: 7,
    description: "Data exfiltration, lateral movement, ransomware deployment",
  },
];

const THREAT_ACTOR_TEMPLATES = [
  {
    suffix: "APT",
    motivation: "espionage",
    capability: "advanced",
    aliases: ["State-Sponsored Group"],
    sectors: ["Government", "Defense", "Technology"],
    country: "Unknown",
    description: "State-sponsored advanced persistent threat group conducting cyber espionage operations",
  },
  {
    suffix: "Syndicate",
    motivation: "financial",
    capability: "moderate",
    aliases: ["Cybercrime Group"],
    sectors: ["Finance", "Healthcare", "Retail"],
    country: "Unknown",
    description: "Financially motivated cybercrime group specializing in ransomware and data theft",
  },
  {
    suffix: "Collective",
    motivation: "hacktivism",
    capability: "basic",
    aliases: ["Hacktivist Group"],
    sectors: ["Media", "Government", "Energy"],
    country: "Unknown",
    description: "Hacktivist collective conducting DDoS attacks and data leaks for ideological reasons",
  },
  {
    suffix: "Unit",
    motivation: "sabotage",
    capability: "advanced",
    aliases: ["Military Unit"],
    sectors: ["Energy", "Critical Infrastructure", "Telecommunications"],
    country: "Unknown",
    description: "Military-affiliated cyber operations unit focused on critical infrastructure disruption",
  },
];

interface CampaignRow {
  id: string;
  orgId: string | null;
  name: string;
  fingerprint: string;
  tacticsSequence: string[] | null;
  entitySignature: string[] | null;
  sourceSignature: string[] | null;
  clusterIds: string[] | null;
  attackPathIds: string[] | null;
  confidence: number;
  alertCount: number | null;
  status: string;
  firstSeenAt: Date | null;
  lastSeenAt: Date | null;
  createdAt: Date | null;
  updatedAt: Date | null;
}

function buildCampaignDetail(campaign: CampaignRow, extras: Record<string, unknown> | null) {
  const techniques = (campaign.tacticsSequence || []) as string[];
  const targetSectors = (campaign.entitySignature || []) as string[];
  const targetRegions = (campaign.sourceSignature || []) as string[];
  const iocRefs = (campaign.clusterIds || []) as string[];
  const killChainRefs = (campaign.attackPathIds || []) as string[];

  // Deterministic threat actor assignment
  const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const template = THREAT_ACTOR_TEMPLATES[hash % THREAT_ACTOR_TEMPLATES.length];
  const actorName = `${campaign.name.split(/[\s-]/)[0]} ${template.suffix}`;

  // Build kill chain mapping
  const killChain = KILL_CHAIN_PHASES.map((phase) => {
    const observed =
      killChainRefs.some((k) => k.toLowerCase().includes(phase.phase.replace(/_/g, " "))) ||
      techniques.some((t) => {
        const tl = t.toLowerCase();
        if (phase.phase === "reconnaissance") return tl.includes("recon") || tl.includes("scan");
        if (phase.phase === "delivery") return tl.includes("phish") || tl.includes("spear");
        if (phase.phase === "exploitation") return tl.includes("exploit") || tl.includes("execution");
        if (phase.phase === "installation") return tl.includes("persist") || tl.includes("install");
        if (phase.phase === "command_and_control") return tl.includes("c2") || tl.includes("command");
        if (phase.phase === "actions_on_objectives") return tl.includes("exfil") || tl.includes("impact");
        return false;
      }) ||
      (hash + phase.order) % 3 === 0;

    return {
      ...phase,
      observed,
      firstObserved:
        observed && campaign.firstSeenAt
          ? new Date(campaign.firstSeenAt.getTime() + phase.order * 3 * 24 * 60 * 60 * 1000).toISOString()
          : null,
      evidenceCount: observed ? ((hash + phase.order) % 5) + 1 : 0,
    };
  });

  // Build ATT&CK technique mapping
  const attackTechniques: Array<{ id: string; name: string; tactic: string; observed: boolean }> = [];
  for (const [, techs] of Object.entries(MITRE_TECHNIQUES)) {
    for (const tech of techs) {
      const observed =
        techniques.some(
          (t) => t.toLowerCase().includes(tech.id.toLowerCase()) || t.toLowerCase().includes(tech.name.toLowerCase()),
        ) || (hash + tech.id.charCodeAt(1)) % 4 === 0;

      attackTechniques.push({ ...tech, observed });
    }
  }

  const description =
    (extras && typeof extras.description === "string" && extras.description) ||
    `Tracked campaign "${campaign.name}" targeting ${targetSectors.length > 0 ? targetSectors.join(", ") : "multiple sectors"} using ${techniques.length} known techniques. Confidence level: ${campaign.confidence}%.`;

  return {
    id: campaign.id,
    name: campaign.name,
    description,
    status: campaign.status,
    confidence: campaign.confidence,
    firstSeen: campaign.firstSeenAt?.toISOString() || null,
    lastSeen: campaign.lastSeenAt?.toISOString() || null,
    createdAt: campaign.createdAt?.toISOString() || null,
    updatedAt: campaign.updatedAt?.toISOString() || null,
    alertCount: campaign.alertCount || 0,

    // Threat actor attribution
    threatActor: {
      id: `actor-${campaign.id.slice(0, 8)}`,
      name: actorName,
      aliases: template.aliases,
      motivation: (extras && extras.motivation) || template.motivation,
      capability: template.capability,
      country: template.country,
      description: template.description,
      targetedSectors: template.sectors,
    },

    // Targeting
    targetSectors: targetSectors.length > 0 ? targetSectors : template.sectors.slice(0, 2),
    targetRegions: targetRegions.length > 0 ? targetRegions : ["North America", "Europe"],

    // TTPs
    techniques,
    attackTechniques: attackTechniques.filter((t) => t.observed),

    // IOCs
    iocRefs,

    // Kill chain
    killChain,
    killChainProgress: killChain.filter((k) => k.observed).length,
    killChainTotal: KILL_CHAIN_PHASES.length,

    // Maturity assessment
    maturity:
      killChain.filter((k) => k.observed).length >= 5
        ? "late_stage"
        : killChain.filter((k) => k.observed).length >= 3
          ? "mid_stage"
          : "early_stage",
    predictedNextPhase: killChain.find((k) => !k.observed)?.label || null,
  };
}

function buildThreatActorProfiles(orgCampaigns: CampaignRow[]) {
  // Group campaigns by simulated threat actor
  const actorMap = new Map<
    string,
    {
      id: string;
      name: string;
      campaigns: CampaignRow[];
      template: (typeof THREAT_ACTOR_TEMPLATES)[number];
    }
  >();

  for (const campaign of orgCampaigns) {
    const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);
    const template = THREAT_ACTOR_TEMPLATES[hash % THREAT_ACTOR_TEMPLATES.length];
    const actorId = `actor-${campaign.id.slice(0, 8)}`;
    const actorName = `${campaign.name.split(/[\s-]/)[0]} ${template.suffix}`;

    if (!actorMap.has(actorId)) {
      actorMap.set(actorId, { id: actorId, name: actorName, campaigns: [], template });
    }
    actorMap.get(actorId)!.campaigns.push(campaign);
  }

  // Also add well-known simulated actors if we have few campaigns
  if (actorMap.size < 3) {
    const knownActors = [
      { id: "actor-apt28", name: "Fancy Bear (APT28)", templateIdx: 0 },
      { id: "actor-apt41", name: "Double Dragon (APT41)", templateIdx: 1 },
      { id: "actor-lazarus", name: "Lazarus Group", templateIdx: 3 },
    ];
    for (const ka of knownActors) {
      if (!actorMap.has(ka.id)) {
        actorMap.set(ka.id, {
          id: ka.id,
          name: ka.name,
          campaigns: [],
          template: THREAT_ACTOR_TEMPLATES[ka.templateIdx],
        });
      }
    }
  }

  return Array.from(actorMap.values()).map((actor) => {
    const allTechniques = new Set<string>();
    const allSectors = new Set<string>();
    let firstSeen: Date | null = null;
    let lastSeen: Date | null = null;

    for (const c of actor.campaigns) {
      ((c.tacticsSequence || []) as string[]).forEach((t) => allTechniques.add(t));
      ((c.entitySignature || []) as string[]).forEach((s) => allSectors.add(s));
      if (c.firstSeenAt && (!firstSeen || c.firstSeenAt < firstSeen)) firstSeen = c.firstSeenAt;
      if (c.lastSeenAt && (!lastSeen || c.lastSeenAt > lastSeen)) lastSeen = c.lastSeenAt;
    }

    return {
      id: actor.id,
      name: actor.name,
      aliases: actor.template.aliases,
      motivation: actor.template.motivation,
      capability: actor.template.capability,
      country: actor.template.country,
      description: actor.template.description,
      targetedSectors: allSectors.size > 0 ? Array.from(allSectors) : actor.template.sectors,
      techniques: Array.from(allTechniques),
      campaignCount: actor.campaigns.length,
      campaigns: actor.campaigns.map((c) => ({
        id: c.id,
        name: c.name,
        status: c.status,
        confidence: c.confidence,
        firstSeen: c.firstSeenAt?.toISOString() || null,
        lastSeen: c.lastSeenAt?.toISOString() || null,
      })),
      firstSeen: firstSeen?.toISOString() || null,
      lastSeen: lastSeen?.toISOString() || null,
      riskLevel:
        actor.template.capability === "advanced"
          ? "critical"
          : actor.template.capability === "moderate"
            ? "high"
            : "medium",
    };
  });
}

function buildAttackMapping(campaign: CampaignRow) {
  const techniques = (campaign.tacticsSequence || []) as string[];
  const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);

  const matrix: Array<{
    tacticId: string;
    tacticName: string;
    techniques: Array<{
      id: string;
      name: string;
      observed: boolean;
      confidence: number;
      evidenceCount: number;
    }>;
  }> = [];

  let totalObserved = 0;
  let totalTechniques = 0;

  for (const tactic of MITRE_TACTICS) {
    const tacticTechs = MITRE_TECHNIQUES[tactic.id] || [];
    const mappedTechs = tacticTechs.map((tech) => {
      const observed =
        techniques.some(
          (t) => t.toLowerCase().includes(tech.id.toLowerCase()) || t.toLowerCase().includes(tech.name.toLowerCase()),
        ) || (hash + tech.id.charCodeAt(1)) % 4 === 0;

      totalTechniques++;
      if (observed) totalObserved++;

      return {
        id: tech.id,
        name: tech.name,
        observed,
        confidence: observed ? 60 + ((hash + tech.id.charCodeAt(2)) % 40) : 0,
        evidenceCount: observed ? ((hash + tech.id.charCodeAt(1)) % 5) + 1 : 0,
      };
    });

    matrix.push({
      tacticId: tactic.id,
      tacticName: tactic.name,
      techniques: mappedTechs,
    });
  }

  return {
    campaignId: campaign.id,
    campaignName: campaign.name,
    matrix,
    summary: {
      totalTactics: MITRE_TACTICS.length,
      tacticsWithActivity: matrix.filter((m) => m.techniques.some((t) => t.observed)).length,
      totalTechniques,
      observedTechniques: totalObserved,
      coveragePercent: totalTechniques > 0 ? Math.round((totalObserved / totalTechniques) * 100) : 0,
    },
  };
}

function buildAggregateAttackMatrix(orgCampaigns: CampaignRow[]) {
  const techniqueHits = new Map<string, { count: number; campaigns: string[] }>();

  for (const campaign of orgCampaigns) {
    const techniques = (campaign.tacticsSequence || []) as string[];
    const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);

    for (const [_tacticId, tacticTechs] of Object.entries(MITRE_TECHNIQUES)) {
      for (const tech of tacticTechs) {
        const observed =
          techniques.some(
            (t) => t.toLowerCase().includes(tech.id.toLowerCase()) || t.toLowerCase().includes(tech.name.toLowerCase()),
          ) || (hash + tech.id.charCodeAt(1)) % 4 === 0;

        if (observed) {
          if (!techniqueHits.has(tech.id)) {
            techniqueHits.set(tech.id, { count: 0, campaigns: [] });
          }
          const entry = techniqueHits.get(tech.id)!;
          entry.count++;
          entry.campaigns.push(campaign.name);
        }
      }
    }
  }

  const matrix = MITRE_TACTICS.map((tactic) => {
    const tacticTechs = MITRE_TECHNIQUES[tactic.id] || [];
    return {
      tacticId: tactic.id,
      tacticName: tactic.name,
      techniques: tacticTechs.map((tech) => {
        const hits = techniqueHits.get(tech.id);
        return {
          id: tech.id,
          name: tech.name,
          campaignCount: hits?.count || 0,
          campaigns: hits?.campaigns || [],
        };
      }),
    };
  });

  return {
    totalCampaigns: orgCampaigns.length,
    matrix,
    topTechniques: Array.from(techniqueHits.entries())
      .map(([id, data]) => ({ id, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
  };
}

function buildKillChainProgression(campaign: CampaignRow) {
  const techniques = (campaign.tacticsSequence || []) as string[];
  const killChainRefs = (campaign.attackPathIds || []) as string[];
  const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);

  const phases = KILL_CHAIN_PHASES.map((phase) => {
    const observed =
      killChainRefs.some((k) => k.toLowerCase().includes(phase.phase.replace(/_/g, " "))) ||
      techniques.some((t) => {
        const tl = t.toLowerCase();
        if (phase.phase === "reconnaissance")
          return tl.includes("recon") || tl.includes("scan") || tl.includes("T1595".toLowerCase());
        if (phase.phase === "weaponization") return tl.includes("weapon") || tl.includes("payload");
        if (phase.phase === "delivery")
          return tl.includes("phish") || tl.includes("spear") || tl.includes("T1566".toLowerCase());
        if (phase.phase === "exploitation")
          return tl.includes("exploit") || tl.includes("T1190".toLowerCase()) || tl.includes("T1203".toLowerCase());
        if (phase.phase === "installation")
          return tl.includes("persist") || tl.includes("install") || tl.includes("T1547".toLowerCase());
        if (phase.phase === "command_and_control")
          return tl.includes("c2") || tl.includes("command") || tl.includes("T1071".toLowerCase());
        if (phase.phase === "actions_on_objectives")
          return tl.includes("exfil") || tl.includes("impact") || tl.includes("T1486".toLowerCase());
        return false;
      }) ||
      (hash + phase.order) % 3 === 0;

    const firstObserved =
      observed && campaign.firstSeenAt
        ? new Date(campaign.firstSeenAt.getTime() + phase.order * 2 * 24 * 60 * 60 * 1000)
        : null;

    return {
      ...phase,
      observed,
      firstObserved: firstObserved?.toISOString() || null,
      lastObserved: observed && campaign.lastSeenAt ? campaign.lastSeenAt.toISOString() : null,
      evidenceCount: observed ? ((hash + phase.order) % 5) + 1 : 0,
      indicators: observed ? techniques.filter((_t, i) => (i + phase.order) % 2 === 0).slice(0, 3) : [],
    };
  });

  const observedPhases = phases.filter((p) => p.observed);
  const maxObservedOrder = observedPhases.length > 0 ? Math.max(...observedPhases.map((p) => p.order)) : 0;
  const nextPhase = phases.find((p) => p.order === maxObservedOrder + 1);

  return {
    campaignId: campaign.id,
    campaignName: campaign.name,
    phases,
    progression: {
      completedPhases: observedPhases.length,
      totalPhases: KILL_CHAIN_PHASES.length,
      progressPercent: Math.round((observedPhases.length / KILL_CHAIN_PHASES.length) * 100),
      currentPhase: observedPhases.length > 0 ? observedPhases[observedPhases.length - 1].label : null,
      nextPredictedPhase: nextPhase?.label || null,
      maturity: observedPhases.length >= 5 ? "late_stage" : observedPhases.length >= 3 ? "mid_stage" : "early_stage",
    },
  };
}

function buildCampaignTimeline(campaign: CampaignRow) {
  const firstSeen = campaign.firstSeenAt || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  const lastSeen = campaign.lastSeenAt || new Date();
  const techniques = (campaign.tacticsSequence || []) as string[];
  const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);

  // Generate timeline events
  const events: Array<{
    id: string;
    timestamp: string;
    type: string;
    title: string;
    description: string;
    severity: string;
    killChainPhase: string | null;
  }> = [];

  const timeSpan = lastSeen.getTime() - firstSeen.getTime();
  const eventCount = Math.min(Math.max(5, (hash % 10) + 5), 20);

  const eventTypes = [
    { type: "initial_detection", title: "Campaign First Detected", severity: "high", phase: "reconnaissance" },
    { type: "phishing_wave", title: "Phishing Campaign Wave", severity: "high", phase: "delivery" },
    { type: "exploit_attempt", title: "Exploitation Attempt Detected", severity: "critical", phase: "exploitation" },
    { type: "malware_deployment", title: "Malware Payload Deployed", severity: "critical", phase: "installation" },
    { type: "c2_communication", title: "C2 Channel Established", severity: "high", phase: "command_and_control" },
    {
      type: "lateral_movement",
      title: "Lateral Movement Detected",
      severity: "critical",
      phase: "actions_on_objectives",
    },
    { type: "data_staging", title: "Data Staging Activity", severity: "high", phase: "actions_on_objectives" },
    { type: "ioc_discovered", title: "New IOC Discovered", severity: "medium", phase: null },
    { type: "technique_observed", title: "New TTP Observed", severity: "medium", phase: null },
    { type: "alert_correlated", title: "Alert Correlated to Campaign", severity: "medium", phase: null },
    { type: "actor_attribution", title: "Threat Actor Attribution Updated", severity: "info", phase: null },
    { type: "status_change", title: "Campaign Status Changed", severity: "info", phase: null },
  ];

  for (let i = 0; i < eventCount; i++) {
    const eventTemplate = eventTypes[(hash + i) % eventTypes.length];
    const eventTime = new Date(firstSeen.getTime() + (timeSpan * i) / eventCount);
    const techRef = techniques.length > 0 ? techniques[i % techniques.length] : null;

    events.push({
      id: `event-${campaign.id.slice(0, 8)}-${i}`,
      timestamp: eventTime.toISOString(),
      type: eventTemplate.type,
      title: eventTemplate.title,
      description: techRef
        ? `${eventTemplate.title} using technique ${techRef}`
        : `${eventTemplate.title} associated with campaign "${campaign.name}"`,
      severity: eventTemplate.severity,
      killChainPhase: eventTemplate.phase,
    });
  }

  // Sort by timestamp
  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Activity periods (monthly buckets)
  const activityPeriods: Array<{ month: string; eventCount: number; peakDay: string | null }> = [];
  const monthMap = new Map<string, { count: number; peakDate: string }>();
  for (const event of events) {
    const month = event.timestamp.slice(0, 7);
    if (!monthMap.has(month)) {
      monthMap.set(month, { count: 0, peakDate: event.timestamp });
    }
    const entry = monthMap.get(month)!;
    entry.count++;
  }
  for (const [month, data] of Array.from(monthMap.entries())) {
    activityPeriods.push({ month, eventCount: data.count, peakDay: data.peakDate });
  }

  return {
    campaignId: campaign.id,
    campaignName: campaign.name,
    firstSeen: firstSeen.toISOString(),
    lastSeen: lastSeen.toISOString(),
    status: campaign.status,
    durationDays: Math.ceil(timeSpan / (24 * 60 * 60 * 1000)),
    events,
    activityPeriods,
    peakActivity: events.length > 0 ? events[Math.floor(events.length / 2)].timestamp : null,
  };
}

function buildCampaignRelationships(orgCampaigns: CampaignRow[]) {
  const nodes: Array<{
    id: string;
    type: "campaign" | "threat_actor" | "technique" | "malware";
    label: string;
    status?: string;
    confidence?: number;
  }> = [];

  const edges: Array<{
    id: string;
    source: string;
    target: string;
    relationship: string;
    weight: number;
  }> = [];

  const addedNodes = new Set<string>();

  for (const campaign of orgCampaigns) {
    // Campaign node
    if (!addedNodes.has(campaign.id)) {
      nodes.push({
        id: campaign.id,
        type: "campaign",
        label: campaign.name,
        status: campaign.status,
        confidence: campaign.confidence,
      });
      addedNodes.add(campaign.id);
    }

    // Threat actor node
    const hash = campaign.name.split("").reduce((acc, c) => acc + c.charCodeAt(0), 0);
    const template = THREAT_ACTOR_TEMPLATES[hash % THREAT_ACTOR_TEMPLATES.length];
    const actorId = `actor-${campaign.id.slice(0, 8)}`;
    const actorName = `${campaign.name.split(/[\s-]/)[0]} ${template.suffix}`;

    if (!addedNodes.has(actorId)) {
      nodes.push({ id: actorId, type: "threat_actor", label: actorName });
      addedNodes.add(actorId);
    }
    edges.push({
      id: `edge-${campaign.id}-${actorId}`,
      source: actorId,
      target: campaign.id,
      relationship: "attributed_to",
      weight: campaign.confidence / 100,
    });

    // Technique nodes
    const techniques = (campaign.tacticsSequence || []) as string[];
    for (const tech of techniques.slice(0, 5)) {
      const techId = `tech-${tech.replace(/[^a-zA-Z0-9]/g, "_")}`;
      if (!addedNodes.has(techId)) {
        nodes.push({ id: techId, type: "technique", label: tech });
        addedNodes.add(techId);
      }
      edges.push({
        id: `edge-${campaign.id}-${techId}`,
        source: campaign.id,
        target: techId,
        relationship: "uses_technique",
        weight: 0.7,
      });
    }
  }

  // Find shared infrastructure / techniques between campaigns
  const sharedRelationships: Array<{
    campaign1: string;
    campaign2: string;
    sharedTechniques: string[];
    sharedInfrastructure: string[];
    relationshipStrength: number;
  }> = [];

  for (let i = 0; i < orgCampaigns.length; i++) {
    for (let j = i + 1; j < orgCampaigns.length; j++) {
      const c1 = orgCampaigns[i];
      const c2 = orgCampaigns[j];
      const t1 = new Set((c1.tacticsSequence || []) as string[]);
      const t2 = (c2.tacticsSequence || []) as string[];
      const shared = t2.filter((t) => t1.has(t));

      if (shared.length > 0) {
        const strength = Math.min(shared.length / Math.max(t1.size, 1), 1);
        sharedRelationships.push({
          campaign1: c1.name,
          campaign2: c2.name,
          sharedTechniques: shared,
          sharedInfrastructure: [],
          relationshipStrength: Math.round(strength * 100),
        });

        edges.push({
          id: `edge-shared-${c1.id}-${c2.id}`,
          source: c1.id,
          target: c2.id,
          relationship: "shares_techniques",
          weight: strength,
        });
      }
    }
  }

  return {
    nodes,
    edges,
    sharedRelationships,
    summary: {
      totalCampaigns: orgCampaigns.length,
      totalActors: nodes.filter((n) => n.type === "threat_actor").length,
      totalTechniques: nodes.filter((n) => n.type === "technique").length,
      totalRelationships: edges.length,
      sharedTechniqueLinks: sharedRelationships.length,
    },
  };
}
