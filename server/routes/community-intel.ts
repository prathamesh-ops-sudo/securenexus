import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count, ilike, or } from "drizzle-orm";
import {
  sharedIocs,
  communityFeeds,
  sharingConsents,
  communityThreatCampaigns,
  COMMUNITY_IOC_TYPES,
  IOC_SEVERITY_LEVELS,
  SHARING_CONSENT_LEVELS,
  INDUSTRY_SECTORS,
} from "../../shared/schema";
import {
  anonymizeOrgId,
  hashIocValue,
  isTlpShareable,
  meetsMinSeverity,
  DEFAULT_FEEDS,
  correlateIocsToCampaign,
  computeNetworkStats,
} from "../community-intel-engine";

const log = logger.child("community-intel");

const ALLOWED_CONSENT_FIELDS = [
  "consentLevel",
  "industrySector",
  "companySize",
  "shareIocs",
  "shareDetectionPatterns",
  "shareTelemetry",
  "receiveGlobalFeed",
  "receiveIndustryFeed",
  "autoContribute",
];

const ALLOWED_FEED_FIELDS = ["isSubscribed", "autoIngest", "filterSeverity", "filterConfidence"];

export function registerCommunityIntelRoutes(app: Express): void {
  // ==========================================================================
  // SHARING CONSENT — Get current org's sharing preferences
  // ==========================================================================

  app.get(
    "/api/community-intel/consent",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const [existing] = await db.select().from(sharingConsents).where(eq(sharingConsents.orgId, orgId)).limit(1);

        if (!existing) {
          // Return default (no consent)
          return res.json({
            consent: null,
            defaults: {
              consentLevels: [...SHARING_CONSENT_LEVELS],
              industrySectors: [...INDUSTRY_SECTORS],
            },
          });
        }

        res.json({
          consent: existing,
          defaults: {
            consentLevels: [...SHARING_CONSENT_LEVELS],
            industrySectors: [...INDUSTRY_SECTORS],
          },
        });
      } catch (error) {
        log.error("Failed to get sharing consent", { error: String(error) });
        res.status(500).json({ message: "Failed to get sharing consent" });
      }
    },
  );

  // ==========================================================================
  // SHARING CONSENT — Create or update sharing preferences
  // ==========================================================================

  app.post(
    "/api/community-intel/consent",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const anonHash = anonymizeOrgId(orgId);

        // Validate consent level
        const { consentLevel } = req.body;
        if (consentLevel && !SHARING_CONSENT_LEVELS.includes(consentLevel as any)) {
          return res.status(400).json({
            message: `consentLevel must be one of: ${SHARING_CONSENT_LEVELS.join(", ")}`,
          });
        }

        // Validate industry sector
        const { industrySector } = req.body;
        if (industrySector && !INDUSTRY_SECTORS.includes(industrySector as any)) {
          return res.status(400).json({
            message: `industrySector must be one of: ${INDUSTRY_SECTORS.join(", ")}`,
          });
        }

        // Filter allowed fields
        const updates: Record<string, unknown> = {};
        for (const key of ALLOWED_CONSENT_FIELDS) {
          if (req.body[key] !== undefined) {
            updates[key] = req.body[key];
          }
        }

        const [existing] = await db.select().from(sharingConsents).where(eq(sharingConsents.orgId, orgId)).limit(1);

        if (existing) {
          updates.consentUpdatedAt = new Date();
          if (consentLevel && consentLevel !== "none" && existing.consentLevel === "none") {
            updates.consentGrantedAt = new Date();
          }

          const [updated] = await db
            .update(sharingConsents)
            .set(updates)
            .where(eq(sharingConsents.orgId, orgId))
            .returning();

          log.info("Sharing consent updated", { orgId, consentLevel });
          return res.json(updated);
        }

        // Create new consent
        const [created] = await db
          .insert(sharingConsents)
          .values({
            orgId,
            anonymousOrgHash: anonHash,
            consentLevel: consentLevel || "none",
            industrySector: industrySector || "other",
            companySize: req.body.companySize || "medium",
            shareIocs: req.body.shareIocs ?? false,
            shareDetectionPatterns: req.body.shareDetectionPatterns ?? false,
            shareTelemetry: req.body.shareTelemetry ?? false,
            receiveGlobalFeed: req.body.receiveGlobalFeed ?? true,
            receiveIndustryFeed: req.body.receiveIndustryFeed ?? true,
            autoContribute: req.body.autoContribute ?? false,
            consentGrantedAt: consentLevel && consentLevel !== "none" ? new Date() : null,
          })
          .returning();

        log.info("Sharing consent created", { orgId, consentLevel });
        res.status(201).json(created);
      } catch (error) {
        log.error("Failed to update sharing consent", {
          error: String(error),
        });
        res.status(500).json({ message: "Failed to update sharing consent" });
      }
    },
  );

  // ==========================================================================
  // SHARE IOC — Contribute an IOC to the community network
  // ==========================================================================

  app.post(
    "/api/community-intel/iocs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Verify org has sharing consent
        const [consent] = await db.select().from(sharingConsents).where(eq(sharingConsents.orgId, orgId)).limit(1);

        if (!consent || consent.consentLevel === "none" || !consent.shareIocs) {
          return res.status(403).json({
            message: "Organization has not opted in to IOC sharing. Update sharing consent first.",
          });
        }

        const { iocType, iocValue, severity, confidence, tlpLevel, tags, threatActorRef, campaignRef, context } =
          req.body;

        if (!iocType || !COMMUNITY_IOC_TYPES.includes(iocType as (typeof COMMUNITY_IOC_TYPES)[number])) {
          return res.status(400).json({
            message: `iocType must be one of: ${COMMUNITY_IOC_TYPES.join(", ")}`,
          });
        }
        if (!iocValue || typeof iocValue !== "string") {
          return res.status(400).json({ message: "iocValue is required" });
        }
        if (severity && !IOC_SEVERITY_LEVELS.includes(severity as any)) {
          return res.status(400).json({
            message: `severity must be one of: ${IOC_SEVERITY_LEVELS.join(", ")}`,
          });
        }

        const valueHash = hashIocValue(iocValue);
        const anonHash = anonymizeOrgId(orgId);

        // Check if IOC already exists (dedup by hash)
        const [existing] = await db.select().from(sharedIocs).where(eq(sharedIocs.iocValueHash, valueHash)).limit(1);

        if (existing) {
          // Increment sighting count, add org to reporters
          const reporters = Array.isArray(existing.reportingOrgs) ? (existing.reportingOrgs as string[]) : [];
          if (!reporters.includes(anonHash)) {
            reporters.push(anonHash);
          }

          const sectors = Array.isArray(existing.industrySectors) ? (existing.industrySectors as string[]) : [];
          if (consent.industrySector && !sectors.includes(consent.industrySector)) {
            sectors.push(consent.industrySector);
          }

          const [updated] = await db
            .update(sharedIocs)
            .set({
              sightingCount: sql`${sharedIocs.sightingCount} + 1`,
              reportingOrgs: reporters,
              industrySectors: sectors,
              lastSeenAt: new Date(),
              updatedAt: new Date(),
              // Bump confidence with fixed increment per new sighting (atomic SQL)
              confidence: sql`LEAST(100, ${sharedIocs.confidence} + 5)`,
            })
            .where(eq(sharedIocs.id, existing.id))
            .returning();

          // Update consent stats (atomic increment)
          await db
            .update(sharingConsents)
            .set({
              contributedIocCount: sql`${sharingConsents.contributedIocCount} + 1`,
              lastContributedAt: new Date(),
            })
            .where(eq(sharingConsents.orgId, orgId));

          log.info("IOC sighting added", {
            iocType,
            sightingCount: updated.sightingCount,
          });
          return res.json({
            ...updated,
            message: "IOC already known — sighting count incremented",
          });
        }

        // Create new shared IOC
        const [created] = await db
          .insert(sharedIocs)
          .values({
            contributorOrgId: orgId,
            anonymousContributorHash: anonHash,
            iocType,
            iocValue,
            iocValueHash: valueHash,
            severity: severity || "medium",
            confidence: confidence ?? 70,
            tlpLevel: tlpLevel || "amber",
            tags: Array.isArray(tags) ? tags : [],
            threatActorRef: threatActorRef || null,
            campaignRef: campaignRef || null,
            context: context || null,
            industrySectors: consent.industrySector ? [consent.industrySector] : [],
            reportingOrgs: [anonHash],
          })
          .returning();

        // Update consent stats (atomic increment)
        await db
          .update(sharingConsents)
          .set({
            contributedIocCount: sql`${sharingConsents.contributedIocCount} + 1`,
            lastContributedAt: new Date(),
          })
          .where(eq(sharingConsents.orgId, orgId));

        log.info("New IOC shared", { iocType, iocId: created.id });
        res.status(201).json(created);
      } catch (error) {
        log.error("Failed to share IOC", { error: String(error) });
        res.status(500).json({ message: "Failed to share IOC" });
      }
    },
  );

  // ==========================================================================
  // LIST SHARED IOCs — Browse community IOC feed
  // ==========================================================================

  app.get(
    "/api/community-intel/iocs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Verify org has receiving enabled
        const [consent] = await db.select().from(sharingConsents).where(eq(sharingConsents.orgId, orgId)).limit(1);

        if (!consent || consent.consentLevel === "none") {
          return res.status(403).json({
            message: "Organization has not opted in to community intelligence. Update sharing consent first.",
          });
        }

        const iocType = req.query.type as string | undefined;
        const severity = req.query.severity as string | undefined;
        const q = (req.query.q as string) || "";
        const limitParam = parseInt(String(req.query.limit || "100"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(sharedIocs.isActive, true)];

        if (iocType && iocType !== "all") conditions.push(eq(sharedIocs.iocType, iocType));
        if (severity && severity !== "all") conditions.push(eq(sharedIocs.severity, severity));
        if (q) {
          conditions.push(
            or(
              ilike(sharedIocs.iocValue, `%${q}%`),
              ilike(sharedIocs.context, `%${q}%`),
              ilike(sharedIocs.threatActorRef, `%${q}%`),
            ),
          );
        }

        // Only show IOCs shareable at the org's TLP level
        // Filter out red TLP unless explicitly receiving
        conditions.push(
          or(eq(sharedIocs.tlpLevel, "white"), eq(sharedIocs.tlpLevel, "green"), eq(sharedIocs.tlpLevel, "amber")),
        );

        const iocs = await db
          .select({
            id: sharedIocs.id,
            iocType: sharedIocs.iocType,
            iocValue: sharedIocs.iocValue,
            severity: sharedIocs.severity,
            confidence: sharedIocs.confidence,
            tlpLevel: sharedIocs.tlpLevel,
            tags: sharedIocs.tags,
            threatActorRef: sharedIocs.threatActorRef,
            campaignRef: sharedIocs.campaignRef,
            context: sharedIocs.context,
            firstSeenAt: sharedIocs.firstSeenAt,
            lastSeenAt: sharedIocs.lastSeenAt,
            sightingCount: sharedIocs.sightingCount,
            industrySectors: sharedIocs.industrySectors,
            isActive: sharedIocs.isActive,
            createdAt: sharedIocs.createdAt,
            // Exclude: contributorOrgId, anonymousContributorHash, reportingOrgs (privacy)
          })
          .from(sharedIocs)
          .where(and(...(conditions as any[])))
          .orderBy(desc(sharedIocs.lastSeenAt))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(sharedIocs)
          .where(and(...(conditions as any[])));

        // Update received count
        await db.update(sharingConsents).set({ lastReceivedAt: new Date() }).where(eq(sharingConsents.orgId, orgId));

        res.json({ iocs, total });
      } catch (error) {
        log.error("Failed to list shared IOCs", { error: String(error) });
        res.status(500).json({ message: "Failed to list shared IOCs" });
      }
    },
  );

  // ==========================================================================
  // GET SINGLE SHARED IOC
  // ==========================================================================

  app.get(
    "/api/community-intel/iocs/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const iocId = String(req.params.id);

        const [ioc] = await db
          .select({
            id: sharedIocs.id,
            iocType: sharedIocs.iocType,
            iocValue: sharedIocs.iocValue,
            severity: sharedIocs.severity,
            confidence: sharedIocs.confidence,
            tlpLevel: sharedIocs.tlpLevel,
            tags: sharedIocs.tags,
            threatActorRef: sharedIocs.threatActorRef,
            campaignRef: sharedIocs.campaignRef,
            context: sharedIocs.context,
            firstSeenAt: sharedIocs.firstSeenAt,
            lastSeenAt: sharedIocs.lastSeenAt,
            sightingCount: sharedIocs.sightingCount,
            industrySectors: sharedIocs.industrySectors,
            isActive: sharedIocs.isActive,
            createdAt: sharedIocs.createdAt,
            updatedAt: sharedIocs.updatedAt,
          })
          .from(sharedIocs)
          .where(eq(sharedIocs.id, iocId))
          .limit(1);

        if (!ioc) {
          return res.status(404).json({ message: "IOC not found" });
        }

        res.json(ioc);
      } catch (error) {
        log.error("Failed to get IOC", { error: String(error) });
        res.status(500).json({ message: "Failed to get IOC" });
      }
    },
  );

  // ==========================================================================
  // COMMUNITY FEEDS — List available feeds for the org
  // ==========================================================================

  app.get(
    "/api/community-intel/feeds",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Get org's existing feed subscriptions
        const existingFeeds = await db
          .select()
          .from(communityFeeds)
          .where(eq(communityFeeds.orgId, orgId))
          .orderBy(communityFeeds.feedType, communityFeeds.feedName);

        // If no feeds exist yet, seed the default feeds for this org
        if (existingFeeds.length === 0) {
          const seeded = [];
          for (const feed of DEFAULT_FEEDS) {
            const [created] = await db
              .insert(communityFeeds)
              .values({
                orgId,
                feedName: feed.feedName,
                feedType: feed.feedType,
                industrySector: feed.industrySector,
                description: feed.description,
              })
              .returning();
            seeded.push(created);
          }
          return res.json({ feeds: seeded });
        }

        res.json({ feeds: existingFeeds });
      } catch (error) {
        log.error("Failed to list community feeds", {
          error: String(error),
        });
        res.status(500).json({ message: "Failed to list community feeds" });
      }
    },
  );

  // ==========================================================================
  // UPDATE FEED SUBSCRIPTION — Subscribe/unsubscribe, set filters
  // ==========================================================================

  app.patch(
    "/api/community-intel/feeds/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const feedId = String(req.params.id);

        const [feed] = await db
          .select()
          .from(communityFeeds)
          .where(and(eq(communityFeeds.id, feedId), eq(communityFeeds.orgId, orgId)))
          .limit(1);

        if (!feed) {
          return res.status(404).json({ message: "Feed not found" });
        }

        const updates: Record<string, unknown> = {};
        for (const key of ALLOWED_FEED_FIELDS) {
          if (req.body[key] !== undefined) {
            updates[key] = req.body[key];
          }
        }

        if (req.body.isSubscribed === true && !feed.isSubscribed) {
          updates.subscribedAt = new Date();
        }

        updates.lastUpdatedAt = new Date();

        const [updated] = await db.update(communityFeeds).set(updates).where(eq(communityFeeds.id, feedId)).returning();

        log.info("Feed subscription updated", { orgId, feedId });
        res.json(updated);
      } catch (error) {
        log.error("Failed to update feed", { error: String(error) });
        res.status(500).json({ message: "Failed to update feed" });
      }
    },
  );

  // ==========================================================================
  // COMMUNITY CAMPAIGNS — List threat campaigns correlated across customer base
  // ==========================================================================

  app.get(
    "/api/community-intel/campaigns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const status = req.query.status as string | undefined;
        const severity = req.query.severity as string | undefined;
        const limitParam = parseInt(String(req.query.limit || "50"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [];
        if (status && status !== "all") conditions.push(eq(communityThreatCampaigns.status, status));
        if (severity && severity !== "all") conditions.push(eq(communityThreatCampaigns.severity, severity));

        const campaigns =
          conditions.length > 0
            ? await db
                .select()
                .from(communityThreatCampaigns)
                .where(and(...(conditions as any[])))
                .orderBy(desc(communityThreatCampaigns.lastSeenAt))
                .limit(limit)
                .offset(offset)
            : await db
                .select()
                .from(communityThreatCampaigns)
                .orderBy(desc(communityThreatCampaigns.lastSeenAt))
                .limit(limit)
                .offset(offset);

        const [{ value: total }] =
          conditions.length > 0
            ? await db
                .select({ value: count() })
                .from(communityThreatCampaigns)
                .where(and(...(conditions as any[])))
            : await db.select({ value: count() }).from(communityThreatCampaigns);

        res.json({ campaigns, total });
      } catch (error) {
        log.error("Failed to list campaigns", { error: String(error) });
        res.status(500).json({ message: "Failed to list campaigns" });
      }
    },
  );

  // ==========================================================================
  // GET SINGLE CAMPAIGN
  // ==========================================================================

  app.get(
    "/api/community-intel/campaigns/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const campaignId = String(req.params.id);

        const [campaign] = await db
          .select()
          .from(communityThreatCampaigns)
          .where(eq(communityThreatCampaigns.id, campaignId))
          .limit(1);

        if (!campaign) {
          return res.status(404).json({ message: "Campaign not found" });
        }

        // Get linked IOCs
        const linkedIocIds = Array.isArray(campaign.iocIds) ? (campaign.iocIds as string[]) : [];

        let linkedIocs: Array<Record<string, unknown>> = [];
        if (linkedIocIds.length > 0) {
          linkedIocs = await db
            .select({
              id: sharedIocs.id,
              iocType: sharedIocs.iocType,
              iocValue: sharedIocs.iocValue,
              severity: sharedIocs.severity,
              confidence: sharedIocs.confidence,
              firstSeenAt: sharedIocs.firstSeenAt,
              lastSeenAt: sharedIocs.lastSeenAt,
              sightingCount: sharedIocs.sightingCount,
            })
            .from(sharedIocs)
            .where(or(...linkedIocIds.map((id) => eq(sharedIocs.id, id))))
            .limit(100);
        }

        res.json({ campaign, linkedIocs });
      } catch (error) {
        log.error("Failed to get campaign", { error: String(error) });
        res.status(500).json({ message: "Failed to get campaign" });
      }
    },
  );

  // ==========================================================================
  // NETWORK STATS — Aggregated community intelligence metrics
  // ==========================================================================

  app.get(
    "/api/community-intel/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Get all active IOCs for computing stats
        const allIocs = await db
          .select({
            iocType: sharedIocs.iocType,
            severity: sharedIocs.severity,
            confidence: sharedIocs.confidence,
            isActive: sharedIocs.isActive,
            industrySectors: sharedIocs.industrySectors,
            createdAt: sharedIocs.createdAt,
            anonymousContributorHash: sharedIocs.anonymousContributorHash,
          })
          .from(sharedIocs)
          .limit(10000);

        const [{ value: campaignCount }] = await db.select({ value: count() }).from(communityThreatCampaigns);

        // Get org's own consent for context
        const [consent] = await db.select().from(sharingConsents).where(eq(sharingConsents.orgId, orgId)).limit(1);

        const stats = computeNetworkStats(allIocs, Number(campaignCount));

        res.json({
          network: stats,
          orgContribution: consent
            ? {
                consentLevel: consent.consentLevel,
                contributedIocCount: consent.contributedIocCount,
                receivedIocCount: consent.receivedIocCount,
                lastContributedAt: consent.lastContributedAt,
                lastReceivedAt: consent.lastReceivedAt,
              }
            : null,
        });
      } catch (error) {
        log.error("Failed to get network stats", { error: String(error) });
        res.status(500).json({ message: "Failed to get network stats" });
      }
    },
  );

  // ==========================================================================
  // CORRELATE — Trigger campaign correlation on recent IOCs
  // ==========================================================================

  app.post(
    "/api/community-intel/correlate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        // Get recent IOCs with shared tags/actor refs for correlation
        const recentIocs = await db
          .select()
          .from(sharedIocs)
          .where(eq(sharedIocs.isActive, true))
          .orderBy(desc(sharedIocs.lastSeenAt))
          .limit(500);

        if (recentIocs.length < 3) {
          return res.json({
            message: "Not enough IOCs for campaign correlation",
            campaigns: [],
          });
        }

        // Group IOCs by shared tags for correlation
        const tagGroups = new Map<string, typeof recentIocs>();
        for (const ioc of recentIocs) {
          const tags = Array.isArray(ioc.tags) ? (ioc.tags as string[]) : [];
          for (const tag of tags) {
            if (!tagGroups.has(tag)) tagGroups.set(tag, []);
            tagGroups.get(tag)!.push(ioc);
          }
        }

        // Group by threat actor reference
        const actorGroups = new Map<string, typeof recentIocs>();
        for (const ioc of recentIocs) {
          if (ioc.threatActorRef) {
            if (!actorGroups.has(ioc.threatActorRef)) actorGroups.set(ioc.threatActorRef, []);
            actorGroups.get(ioc.threatActorRef)!.push(ioc);
          }
        }

        const newCampaigns: Array<Record<string, unknown>> = [];

        // Correlate actor-based groups first (higher confidence)
        for (const [actorRef, iocs] of Array.from(actorGroups.entries())) {
          if (iocs.length < 3) continue;

          const correlation = correlateIocsToCampaign(
            iocs.map((i: (typeof recentIocs)[number]) => ({
              tags: Array.isArray(i.tags) ? (i.tags as string[]) : [],
              threatActorRef: i.threatActorRef,
              severity: i.severity,
              industrySectors: Array.isArray(i.industrySectors) ? (i.industrySectors as string[]) : [],
              anonymousContributorHash: i.anonymousContributorHash,
            })),
          );

          if (correlation) {
            // Check if campaign for this actor already exists (dedup)
            const [existingCampaign] = await db
              .select()
              .from(communityThreatCampaigns)
              .where(eq(communityThreatCampaigns.threatActorName, correlation.threatActorName || actorRef))
              .limit(1);

            if (existingCampaign) {
              // Update existing campaign instead of creating duplicate
              const [updatedCampaign] = await db
                .update(communityThreatCampaigns)
                .set({
                  iocIds: iocs.map((i: (typeof recentIocs)[number]) => i.id),
                  iocCount: correlation.iocCount,
                  affectedOrgCount: correlation.affectedOrgCount,
                  severity: correlation.severity,
                  targetSectors: correlation.targetSectors,
                  lastSeenAt: iocs[0].lastSeenAt,
                  updatedAt: new Date(),
                })
                .where(eq(communityThreatCampaigns.id, existingCampaign.id))
                .returning();
              newCampaigns.push(updatedCampaign);
            } else {
              const [campaign] = await db
                .insert(communityThreatCampaigns)
                .values({
                  campaignName: correlation.campaignName,
                  threatActorName: correlation.threatActorName,
                  description: `Auto-correlated campaign from ${correlation.iocCount} IOCs shared by ${correlation.affectedOrgCount} organizations. Primary threat actor: ${actorRef}.`,
                  iocIds: iocs.map((i: (typeof recentIocs)[number]) => i.id),
                  iocCount: correlation.iocCount,
                  affectedOrgCount: correlation.affectedOrgCount,
                  severity: correlation.severity,
                  targetSectors: correlation.targetSectors,
                  firstSeenAt: iocs[iocs.length - 1].firstSeenAt,
                  lastSeenAt: iocs[0].lastSeenAt,
                })
                .returning();
              newCampaigns.push(campaign);
            }
          }
        }

        log.info("Campaign correlation complete", {
          newCampaigns: newCampaigns.length,
        });
        res.json({
          message: `Correlated ${newCampaigns.length} new campaigns`,
          campaigns: newCampaigns,
        });
      } catch (error) {
        log.error("Campaign correlation failed", { error: String(error) });
        res.status(500).json({ message: "Campaign correlation failed" });
      }
    },
  );

  // ==========================================================================
  // MY CONTRIBUTIONS — List IOCs contributed by this org
  // ==========================================================================

  app.get(
    "/api/community-intel/my-contributions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limitParam = parseInt(String(req.query.limit || "50"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const contributions = await db
          .select()
          .from(sharedIocs)
          .where(eq(sharedIocs.contributorOrgId, orgId))
          .orderBy(desc(sharedIocs.createdAt))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(sharedIocs)
          .where(eq(sharedIocs.contributorOrgId, orgId));

        res.json({ contributions, total });
      } catch (error) {
        log.error("Failed to list contributions", { error: String(error) });
        res.status(500).json({ message: "Failed to list contributions" });
      }
    },
  );

  // ==========================================================================
  // DEACTIVATE IOC — Mark an IOC as no longer active
  // ==========================================================================

  app.patch(
    "/api/community-intel/iocs/:id/deactivate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const iocId = String(req.params.id);

        // Only the original contributor can deactivate
        const [ioc] = await db
          .select()
          .from(sharedIocs)
          .where(and(eq(sharedIocs.id, iocId), eq(sharedIocs.contributorOrgId, orgId)))
          .limit(1);

        if (!ioc) {
          return res.status(404).json({
            message: "IOC not found or you are not the original contributor",
          });
        }

        const [updated] = await db
          .update(sharedIocs)
          .set({ isActive: false, updatedAt: new Date() })
          .where(eq(sharedIocs.id, iocId))
          .returning();

        log.info("IOC deactivated", { iocId });
        res.json(updated);
      } catch (error) {
        log.error("Failed to deactivate IOC", { error: String(error) });
        res.status(500).json({ message: "Failed to deactivate IOC" });
      }
    },
  );
}
