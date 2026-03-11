import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, validateFeedUrl } from "./shared";
import { isAuthenticated } from "../auth";
import {
  insertIocEntrySchema,
  insertIocFeedSchema,
  insertIocMatchRuleSchema,
  insertIocWatchlistSchema,
} from "@shared/schema";
import {
  getThreatIntelFeedDefinitions,
  getThreatIntelFeedStatuses,
  isThreatIntelSlugValid,
  setThreatIntelFeedEnabled,
  getThreatIntelFeedHealth,
  fetchThreatIntelFeed,
  fetchAllThreatIntelFeeds,
  getCachedThreatIntelArticles,
  getThreatIntelCategories,
} from "../threat-intel-feeds";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { enforcePlanLimit } from "../middleware/plan-enforcement";

export function registerThreatIntelRoutes(app: Express): void {
  // Threat Intel Configuration (Org-level API keys)
  app.get(
    "/api/threat-intel-configs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const configs = await storage.getThreatIntelConfigs(orgId);
        const masked = configs.map((c) => ({
          ...c,
          apiKey: c.apiKey ? `****${c.apiKey.slice(-4)}` : null,
        }));
        res.json(masked);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch threat intel configs" });
      }
    },
  );

  app.post(
    "/api/threat-intel-configs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { provider, apiKey, enabled } = req.body;
        if (!provider) return res.status(400).json({ message: "provider is required" });
        const validProviders = ["abuseipdb", "virustotal", "otx"];
        if (!validProviders.includes(provider)) {
          return res.status(400).json({ message: `Invalid provider. Valid providers: ${validProviders.join(", ")}` });
        }
        const config = await storage.upsertThreatIntelConfig({
          orgId,
          provider,
          apiKey: apiKey || null,
          enabled: enabled !== undefined ? enabled : true,
        });
        res.status(201).json({
          ...config,
          apiKey: config.apiKey ? `****${config.apiKey.slice(-4)}` : null,
        });
      } catch (error) {
        logger.child("routes").error("Error saving threat intel config", { error: String(error) });
        res.status(500).json({ message: "Failed to save threat intel config" });
      }
    },
  );

  app.delete(
    "/api/threat-intel-configs/:provider",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        await storage.deleteThreatIntelConfig(orgId, p(req.params.provider));
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete threat intel config" });
      }
    },
  );

  app.post(
    "/api/threat-intel-configs/:provider/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const provider = p(req.params.provider);
        const config = await storage.getThreatIntelConfig(orgId, provider);
        if (!config || !config.apiKey) {
          return res.status(404).json({ success: false, message: "No API key configured for this provider" });
        }

        let success = false;
        let message = "Unknown provider";

        try {
          if (provider === "abuseipdb") {
            const resp = await fetch("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90", {
              headers: { Key: config.apiKey, Accept: "application/json" },
            });
            success = resp.ok;
            message = resp.ok ? "API key is valid" : `API returned status ${resp.status}`;
          } else if (provider === "virustotal") {
            const resp = await fetch("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {
              headers: { "x-apikey": config.apiKey, Accept: "application/json" },
            });
            success = resp.ok;
            message = resp.ok ? "API key is valid" : `API returned status ${resp.status}`;
          } else if (provider === "otx") {
            const resp = await fetch("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general", {
              headers: { "X-OTX-API-KEY": config.apiKey, Accept: "application/json" },
            });
            success = resp.ok;
            message = resp.ok ? "API key is valid" : `API returned status ${resp.status}`;
          }
        } catch (err: any) {
          success = false;
          message = `Connection error: ${err.message}`;
        }

        await storage.upsertThreatIntelConfig({
          orgId,
          provider,
          apiKey: config.apiKey,
          enabled: config.enabled ?? true,
        });
        const updatedConfig = await storage.getThreatIntelConfig(orgId, provider);
        if (updatedConfig) {
          const { db: database } = await import("../db");
          const { threatIntelConfigs } = await import("@shared/schema");
          const { eq } = await import("drizzle-orm");
          await database
            .update(threatIntelConfigs)
            .set({
              lastTestedAt: new Date(),
              lastTestStatus: success ? "success" : "failed",
            })
            .where(eq(threatIntelConfigs.id, updatedConfig.id));
        }

        res.json({ success, message, testedAt: new Date().toISOString() });
      } catch (error) {
        logger.child("routes").error("Error testing threat intel config", { error: String(error) });
        res.status(500).json({ success: false, message: "Failed to test API key" });
      }
    },
  );

  // Phase 4: Threat Enrichment & Intelligence Feeds
  app.get(
    "/api/enrichment/providers",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { getProviderStatuses } = await import("../threat-enrichment");
        const orgId = getOrgId(req);
        res.json(await getProviderStatuses(orgId));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch provider statuses" });
      }
    },
  );

  // OSINT Threat Intelligence Feeds (no API keys required)
  // Static routes MUST be registered before parameterized routes to avoid shadowing
  app.get(
    "/api/osint-feeds/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const { getOsintFeedStatuses } = await import("../osint-feeds");
        res.json(getOsintFeedStatuses());
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch OSINT feed statuses" });
      }
    },
  );

  app.get(
    "/api/osint-feeds/subscriptions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const { getAllSubscriptions, getOsintFeedStatuses } = await import("../osint-feeds");
        res.json({ subscriptions: getAllSubscriptions(), statuses: getOsintFeedStatuses() });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch OSINT feed subscriptions" });
      }
    },
  );

  app.get(
    "/api/osint-feeds",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const { fetchAllOsintFeeds } = await import("../osint-feeds");
        const results = await fetchAllOsintFeeds();
        res.json(results);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch OSINT feeds" });
      }
    },
  );

  app.get(
    "/api/osint-feeds/:feedName",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { fetchOsintFeed } = await import("../osint-feeds");
        const feedName = decodeURIComponent(p(req.params.feedName));
        const result = await fetchOsintFeed(feedName);
        if (result.status === "error" && result.errorMessage?.startsWith("Unknown feed")) {
          return res.status(404).json({ message: result.errorMessage });
        }
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch OSINT feed" });
      }
    },
  );

  // Static POST routes before parameterized POST routes
  app.post(
    "/api/osint-feeds/refresh-all",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const { refreshAllFeedsWithProgress } = await import("../osint-feeds");
        const result = await refreshAllFeedsWithProgress();
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to refresh all feeds" });
      }
    },
  );

  // OSINT Feed Subscription Management (parameterized routes)
  app.post(
    "/api/osint-feeds/:feedSlug/subscribe",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { updateFeedSubscription } = await import("../osint-feeds");
        const slug = p(req.params.feedSlug);
        const result = updateFeedSubscription(slug, { enabled: true });
        if (!result) return res.status(404).json({ message: "Unknown feed slug" });
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to subscribe to feed" });
      }
    },
  );

  app.post(
    "/api/osint-feeds/:feedSlug/unsubscribe",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { updateFeedSubscription } = await import("../osint-feeds");
        const slug = p(req.params.feedSlug);
        const result = updateFeedSubscription(slug, { enabled: false });
        if (!result) return res.status(404).json({ message: "Unknown feed slug" });
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to unsubscribe from feed" });
      }
    },
  );

  app.patch(
    "/api/osint-feeds/:feedSlug/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { updateFeedSubscription } = await import("../osint-feeds");
        const slug = p(req.params.feedSlug);
        const { refreshIntervalMinutes } = req.body;
        if (refreshIntervalMinutes === undefined || typeof refreshIntervalMinutes !== "number") {
          return res.status(400).json({ message: "refreshIntervalMinutes is required and must be a number" });
        }
        if (refreshIntervalMinutes < 5 || refreshIntervalMinutes > 1440) {
          return res.status(400).json({ message: "refreshIntervalMinutes must be between 5 and 1440" });
        }
        const result = updateFeedSubscription(slug, { refreshIntervalMinutes });
        if (!result) return res.status(404).json({ message: "Unknown feed slug" });
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to update feed config" });
      }
    },
  );

  app.post(
    "/api/osint-feeds/:feedName/refresh",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { fetchOsintFeed } = await import("../osint-feeds");
        const feedName = decodeURIComponent(p(req.params.feedName));
        const result = await fetchOsintFeed(feedName, true);
        if (result.status === "error" && result.errorMessage?.startsWith("Unknown feed")) {
          return res.status(404).json({ message: result.errorMessage });
        }
        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to refresh OSINT feed" });
      }
    },
  );

  app.get(
    "/api/osint-feeds/:feedSlug/health",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { getFeedHealthHistory } = await import("../osint-feeds");
        const slug = p(req.params.feedSlug);
        const history = getFeedHealthHistory(slug);
        res.json(history);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feed health history" });
      }
    },
  );

  // Threat Intel Fusion Layer - IOC Feeds, Entries, Watchlists, Match Rules, Matches
  app.get(
    "/api/ioc-feeds",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feeds = await storage.getIocFeeds(orgId);
        res.json(feeds);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC feeds" });
      }
    },
  );

  app.get(
    "/api/ioc-feeds/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });
        res.json(feed);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC feed" });
      }
    },
  );

  app.post(
    "/api/ioc-feeds",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    enforcePlanLimit("threat_intel_feeds"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertIocFeedSchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid feed data", errors: parsed.error.flatten() });
        }
        if (parsed.data.url && !validateFeedUrl(parsed.data.url)) {
          return res
            .status(400)
            .json({ message: "Invalid feed URL. Must be http/https and not target private/internal networks." });
        }
        const feed = await storage.createIocFeed({ ...parsed.data, orgId });
        res.status(201).json(feed);
      } catch (error: any) {
        if (error.message === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to create IOC feed" });
      }
    },
  );

  app.patch(
    "/api/ioc-feeds/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getIocFeed(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });
        if (req.body.url && !validateFeedUrl(req.body.url)) {
          return res
            .status(400)
            .json({ message: "Invalid feed URL. Must be http/https and not target private/internal networks." });
        }
        const { orgId: _ignoreOrgId, ...updateData } = req.body;
        const feed = await storage.updateIocFeed(p(req.params.id), updateData);
        if (!feed) return res.status(404).json({ message: "Feed not found" });
        res.json(feed);
      } catch (error) {
        res.status(500).json({ message: "Failed to update IOC feed" });
      }
    },
  );

  app.delete(
    "/api/ioc-feeds/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getIocFeed(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });
        const deleted = await storage.deleteIocFeed(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Feed not found" });
        res.json({ message: "Feed deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete IOC feed" });
      }
    },
  );

  app.post(
    "/api/ioc-feeds/:id/ingest",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });
        const { fetchAndIngestFeed, ingestFeed } = await import("../ioc-ingestion");
        let result;
        if (req.body && req.body.data) {
          result = await ingestFeed(feed, req.body.data);
        } else {
          result = await fetchAndIngestFeed(feed);
        }
        res.json(result);
      } catch (error) {
        logger.child("routes").error("Feed ingestion error", { error: String(error) });
        res.status(500).json({ message: "Failed to ingest feed" });
      }
    },
  );

  app.get(
    "/api/ioc-entries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { feedId, iocType, status, limit } = req.query;
        const entries = await storage.getIocEntries(
          orgId,
          feedId as string | undefined,
          iocType as string | undefined,
          status as string | undefined,
          limit ? parseInt(limit as string, 10) : undefined,
        );
        res.json(entries);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC entries" });
      }
    },
  );

  app.get(
    "/api/ioc-entries/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entry = await storage.getIocEntry(p(req.params.id));
        if (!entry || entry.orgId !== orgId) return res.status(404).json({ message: "IOC entry not found" });
        res.json(entry);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC entry" });
      }
    },
  );

  app.post(
    "/api/ioc-entries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertIocEntrySchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid IOC entry data", errors: parsed.error.flatten() });
        }
        const entry = await storage.createIocEntry({ ...parsed.data, orgId });
        res.status(201).json(entry);
      } catch (error: any) {
        if (error.message === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to create IOC entry" });
      }
    },
  );

  app.patch(
    "/api/ioc-entries/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getIocEntry(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "IOC entry not found" });
        const { orgId: _ignoreOrgId, ...updateData } = req.body;
        const entry = await storage.updateIocEntry(p(req.params.id), updateData);
        if (!entry) return res.status(404).json({ message: "IOC entry not found" });
        res.json(entry);
      } catch (error) {
        res.status(500).json({ message: "Failed to update IOC entry" });
      }
    },
  );

  app.delete(
    "/api/ioc-entries/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = await storage.getIocEntry(p(req.params.id));
        if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "IOC entry not found" });
        const deleted = await storage.deleteIocEntry(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "IOC entry not found" });
        res.json({ message: "IOC entry deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete IOC entry" });
      }
    },
  );

  app.get(
    "/api/ioc-entries/search/:type/:value",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entries = await storage.getIocEntriesByValue(p(req.params.type), p(req.params.value), orgId);
        res.json(entries);
      } catch (error) {
        res.status(500).json({ message: "Failed to search IOC entries" });
      }
    },
  );

  app.get(
    "/api/ioc-watchlists",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const watchlists = await storage.getIocWatchlists(orgId);
        res.json(watchlists);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch watchlists" });
      }
    },
  );

  app.post(
    "/api/ioc-watchlists",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const parsed = insertIocWatchlistSchema.safeParse({ ...req.body, orgId, createdBy: userName });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid watchlist data", errors: parsed.error.flatten() });
        }
        const watchlist = await storage.createIocWatchlist({ ...parsed.data, orgId, createdBy: userName });
        res.status(201).json(watchlist);
      } catch (error: any) {
        if (error.message === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to create watchlist" });
      }
    },
  );

  app.patch(
    "/api/ioc-watchlists/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const existing = (await storage.getIocWatchlist)
          ? await (storage as any).getIocWatchlist(p(req.params.id))
          : null;
        if (existing && existing.orgId !== orgId) return res.status(404).json({ message: "Watchlist not found" });
        const { orgId: _ignoreOrgId, ...updateData } = req.body;
        const watchlist = await storage.updateIocWatchlist(p(req.params.id), updateData);
        if (!watchlist) return res.status(404).json({ message: "Watchlist not found" });
        res.json(watchlist);
      } catch (error) {
        res.status(500).json({ message: "Failed to update watchlist" });
      }
    },
  );

  app.delete(
    "/api/ioc-watchlists/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const watchlists = await storage.getIocWatchlists(orgId);
        const existing = watchlists.find((w: any) => w.id === p(req.params.id));
        if (!existing) return res.status(404).json({ message: "Watchlist not found" });
        const deleted = await storage.deleteIocWatchlist(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Watchlist not found" });
        res.json({ message: "Watchlist deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete watchlist" });
      }
    },
  );

  app.get(
    "/api/ioc-watchlists/:id/entries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const entries = await storage.getWatchlistEntries(p(req.params.id));
        res.json(entries);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch watchlist entries" });
      }
    },
  );

  app.post(
    "/api/ioc-watchlists/:id/entries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const user = (req as any).user;
        const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
        const entry = await storage.addIocToWatchlist({
          watchlistId: p(req.params.id),
          iocEntryId: req.body.iocEntryId,
          addedBy: userName,
        });
        res.status(201).json(entry);
      } catch (error) {
        res.status(500).json({ message: "Failed to add IOC to watchlist" });
      }
    },
  );

  app.delete(
    "/api/ioc-watchlists/:wlId/entries/:iocId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const removed = await storage.removeIocFromWatchlist(p(req.params.wlId), p(req.params.iocId));
        if (!removed) return res.status(404).json({ message: "Entry not found in watchlist" });
        res.json({ message: "IOC removed from watchlist" });
      } catch (error) {
        res.status(500).json({ message: "Failed to remove IOC from watchlist" });
      }
    },
  );

  app.get(
    "/api/ioc-match-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rules = await storage.getIocMatchRules(orgId);
        res.json(rules);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch match rules" });
      }
    },
  );

  app.post(
    "/api/ioc-match-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const parsed = insertIocMatchRuleSchema.safeParse({ ...req.body, orgId });
        if (!parsed.success) {
          return res.status(400).json({ message: "Invalid match rule data", errors: parsed.error.flatten() });
        }
        const rule = await storage.createIocMatchRule({ ...parsed.data, orgId });
        res.status(201).json(rule);
      } catch (error: any) {
        if (error.message === "ORG_CONTEXT_MISSING")
          return res.status(403).json({ message: "Organization context required" });
        res.status(500).json({ message: "Failed to create match rule" });
      }
    },
  );

  app.patch(
    "/api/ioc-match-rules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rules = await storage.getIocMatchRules(orgId);
        const existing = rules.find((r: any) => r.id === p(req.params.id));
        if (!existing) return res.status(404).json({ message: "Match rule not found" });
        const { orgId: _ignoreOrgId, ...updateData } = req.body;
        const rule = await storage.updateIocMatchRule(p(req.params.id), updateData);
        if (!rule) return res.status(404).json({ message: "Match rule not found" });
        res.json(rule);
      } catch (error) {
        res.status(500).json({ message: "Failed to update match rule" });
      }
    },
  );

  app.delete(
    "/api/ioc-match-rules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rules = await storage.getIocMatchRules(orgId);
        const existing = rules.find((r: any) => r.id === p(req.params.id));
        if (!existing) return res.status(404).json({ message: "Match rule not found" });
        const deleted = await storage.deleteIocMatchRule(p(req.params.id));
        if (!deleted) return res.status(404).json({ message: "Match rule not found" });
        res.json({ message: "Match rule deleted" });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete match rule" });
      }
    },
  );

  app.get(
    "/api/ioc-matches",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { alertId, iocEntryId, limit } = req.query;
        const matches = await storage.getIocMatches(
          orgId,
          alertId as string | undefined,
          iocEntryId as string | undefined,
          limit ? parseInt(limit as string, 10) : undefined,
        );
        res.json(matches);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC matches" });
      }
    },
  );

  app.post(
    "/api/ioc-match/alert/:alertId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const alert = await storage.getAlert(p(req.params.alertId));
        if (!alert) return res.status(404).json({ message: "Alert not found" });
        const { matchAlertAgainstIOCs, matchAlertAgainstRules } = await import("../ioc-matcher");
        const result = await matchAlertAgainstIOCs(alert, orgId);
        await matchAlertAgainstRules(alert, orgId);
        res.json(result);
      } catch (error) {
        logger.child("routes").error("IOC matching error", { error: String(error) });
        res.status(500).json({ message: "Failed to match alert against IOCs" });
      }
    },
  );

  app.get(
    "/api/ioc-stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { getIOCStats } = await import("../ioc-matcher");
        const stats = await getIOCStats(orgId);
        res.json(stats);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC stats" });
      }
    },
  );

  app.get(
    "/api/ioc-enrichment/:alertId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { enrichAlertWithIOCContext } = await import("../ioc-matcher");
        const enrichment = await enrichAlertWithIOCContext(p(req.params.alertId));
        res.json(enrichment);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch IOC enrichment" });
      }
    },
  );

  app.get(
    "/api/pir/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const review = await storage.getPostIncidentReview(p(req.params.id));
        if (!review || review.orgId !== orgId)
          return res.status(404).json({ message: "Post-incident review not found" });
        res.json(review);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch post-incident review" });
      }
    },
  );

  // ── Threat Intel News Feeds (RSS aggregation) ──
  // Static routes first to avoid shadowing by parameterized routes

  app.get(
    "/api/threat-intel-feeds/categories",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (_req: Request, res: Response) => {
      try {
        res.json(getThreatIntelCategories());
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feed categories" });
      }
    },
  );

  app.get(
    "/api/threat-intel-feeds/definitions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (_req: Request, res: Response) => {
      try {
        res.json(getThreatIntelFeedDefinitions());
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feed definitions" });
      }
    },
  );

  app.get(
    "/api/threat-intel-feeds/statuses",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        res.json(getThreatIntelFeedStatuses(orgId));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feed statuses" });
      }
    },
  );

  app.get(
    "/api/threat-intel-feeds/articles",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (req: Request, res: Response) => {
      try {
        const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 500;
        const category = req.query.category ? String(req.query.category) : undefined;
        const search = req.query.search ? String(req.query.search) : undefined;
        const feedSlug = req.query.feedSlug ? String(req.query.feedSlug) : undefined;
        if (isNaN(limit) || limit < 1 || limit > 5000) {
          return res.status(400).json({ message: "limit must be between 1 and 5000" });
        }
        const orgId = getOrgId(req);
        const articles = getCachedThreatIntelArticles({ limit, category, search, feedSlug, orgId });
        res.json({ articles, total: articles.length });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch articles" });
      }
    },
  );

  app.post(
    "/api/threat-intel-feeds/refresh-all",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const result = await fetchAllThreatIntelFeeds(true, orgId);
        const { items: _strip, ...summary } = result;
        res.json(summary);
      } catch (error) {
        logger.child("routes").error("Failed to refresh all threat intel feeds", { error: String(error) });
        res.status(500).json({ message: "Failed to refresh all threat intel feeds" });
      }
    },
  );

  // Parameterized routes after static routes
  app.get(
    "/api/threat-intel-feeds/:slug/health",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (req: Request, res: Response) => {
      try {
        const slug = p(req.params.slug);
        if (!isThreatIntelSlugValid(slug)) {
          return res.status(404).json({ message: "Unknown feed slug" });
        }
        res.json(getThreatIntelFeedHealth(slug));
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch feed health" });
      }
    },
  );

  app.post(
    "/api/threat-intel-feeds/:slug/refresh",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const slug = p(req.params.slug);
        if (!isThreatIntelSlugValid(slug)) {
          return res.status(404).json({ message: "Unknown feed slug" });
        }
        const result = await fetchThreatIntelFeed(slug, true);
        res.json({ articleCount: result.articles.length, error: result.error });
      } catch (error) {
        logger.child("routes").error("Failed to refresh feed", { error: String(error) });
        res.status(500).json({ message: "Failed to refresh feed" });
      }
    },
  );

  app.post(
    "/api/threat-intel-feeds/:slug/enable",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (req: Request, res: Response) => {
      try {
        const slug = p(req.params.slug);
        const orgId = getOrgId(req);
        if (!setThreatIntelFeedEnabled(slug, true, orgId)) {
          return res.status(404).json({ message: "Unknown feed slug" });
        }
        res.json({ slug, enabled: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to enable feed" });
      }
    },
  );

  app.post(
    "/api/threat-intel-feeds/:slug/disable",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    (req: Request, res: Response) => {
      try {
        const slug = p(req.params.slug);
        const orgId = getOrgId(req);
        if (!setThreatIntelFeedEnabled(slug, false, orgId)) {
          return res.status(404).json({ message: "Unknown feed slug" });
        }
        res.json({ slug, enabled: false });
      } catch (error) {
        res.status(500).json({ message: "Failed to disable feed" });
      }
    },
  );
}
