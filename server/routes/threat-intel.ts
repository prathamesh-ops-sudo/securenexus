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

  // ── 4.4: Feed comparison table (registered before /:id to avoid route shadowing) ──
  app.get(
    "/api/ioc-feeds/compare",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feeds = await storage.getIocFeeds(orgId);
        if (!feeds || feeds.length === 0) {
          return res.json({ feeds: [], overlapMatrix: [] });
        }

        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and, count, countDistinct, sql } = await import("drizzle-orm");

        // Get per-feed stats
        const feedStats = await Promise.all(
          feeds.map(async (feed) => {
            const [uniqueResult] = await database
              .select({ count: countDistinct(iocEntries.iocValue) })
              .from(iocEntries)
              .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.feedId, feed.id)));

            const [totalResult] = await database
              .select({ count: count() })
              .from(iocEntries)
              .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.feedId, feed.id)));

            const [fpResult] = await database
              .select({ count: count() })
              .from(iocEntries)
              .where(
                and(
                  eq(iocEntries.orgId, orgId),
                  eq(iocEntries.feedId, feed.id),
                  sql`${iocEntries.status} IN ('whitelisted', 'revoked')`,
                ),
              );

            const totalCount = totalResult?.count ?? 0;
            const fpCount = fpResult?.count ?? 0;
            const fpRate = totalCount > 0 ? Math.round((fpCount / totalCount) * 10000) / 100 : 0;

            return {
              feedId: feed.id,
              feedName: feed.name,
              feedType: feed.feedType,
              enabled: feed.enabled ?? true,
              uniqueIocs: uniqueResult?.count ?? 0,
              totalIocs: totalCount,
              fpCount,
              fpRate,
              lastFetchAt: feed.lastFetchAt,
              lastFetchStatus: feed.lastFetchStatus,
            };
          }),
        );

        // Build overlap matrix (only if <= 10 feeds to avoid N^2 explosion)
        const overlapMatrix: Array<{
          feedA: string;
          feedB: string;
          overlapCount: number;
          overlapPctA: number;
          overlapPctB: number;
        }> = [];

        if (feeds.length <= 10) {
          for (let i = 0; i < feeds.length; i++) {
            for (let j = i + 1; j < feeds.length; j++) {
              const feedA = feeds[i];
              const feedB = feeds[j];

              const [overlapResult] = await database
                .select({ count: count() })
                .from(iocEntries)
                .where(
                  and(
                    eq(iocEntries.orgId, orgId),
                    eq(iocEntries.feedId, feedA.id),
                    sql`${iocEntries.iocValue} IN (
                      SELECT ${iocEntries.iocValue} FROM ${iocEntries}
                      WHERE ${iocEntries.feedId} = ${feedB.id}
                        AND ${iocEntries.orgId} = ${orgId}
                    )`,
                  ),
                );

              const overlapCount = overlapResult?.count ?? 0;
              const statsA = feedStats.find((s) => s.feedId === feedA.id);
              const statsB = feedStats.find((s) => s.feedId === feedB.id);
              const uniqueA = statsA?.uniqueIocs ?? 0;
              const uniqueB = statsB?.uniqueIocs ?? 0;

              overlapMatrix.push({
                feedA: feedA.id,
                feedB: feedB.id,
                overlapCount,
                overlapPctA: uniqueA > 0 ? Math.round((overlapCount / uniqueA) * 10000) / 100 : 0,
                overlapPctB: uniqueB > 0 ? Math.round((overlapCount / uniqueB) * 10000) / 100 : 0,
              });
            }
          }
        }

        res.json({ feeds: feedStats, overlapMatrix });
      } catch (error) {
        logger.child("routes").error("Failed to compare feeds", { error: String(error) });
        res.status(500).json({ message: "Failed to compare feeds" });
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

  // ── 4.5: Update feed polling schedule ──
  app.patch(
    "/api/ioc-feeds/:id/schedule",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });

        const { schedule } = req.body;
        const validSchedules = ["manual", "1h", "6h", "12h", "24h"];
        if (!schedule || !validSchedules.includes(schedule)) {
          return res.status(400).json({ message: `Invalid schedule. Must be one of: ${validSchedules.join(", ")}` });
        }

        const updated = await storage.updateIocFeed(p(req.params.id), { schedule });
        if (!updated) return res.status(404).json({ message: "Feed not found" });

        // If switching to a non-manual schedule, enqueue the first poll
        if (schedule !== "manual") {
          const { scheduleJob } = await import("../job-queue");
          const intervalMs: Record<string, number> = {
            "1h": 3600000,
            "6h": 21600000,
            "12h": 43200000,
            "24h": 86400000,
          };
          const nextRun = new Date(Date.now() + (intervalMs[schedule] || 3600000));
          try {
            await scheduleJob("ioc_feed_poll", orgId, { feedId: feed.id }, nextRun);
            logger
              .child("routes")
              .info(`Scheduled next ioc_feed_poll for feed ${feed.name} at ${nextRun.toISOString()}`);
          } catch (schedErr) {
            logger.child("routes").warn(`Failed to schedule feed poll: ${String(schedErr)}`);
          }
        }

        res.json({ ...updated, message: `Schedule updated to ${schedule}` });
      } catch (error) {
        res.status(500).json({ message: "Failed to update feed schedule" });
      }
    },
  );

  // ── 4.8: Update feed authentication config ──
  app.patch(
    "/api/ioc-feeds/:id/auth",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });

        const {
          authType,
          apiKeyHeader,
          apiKeyValue,
          bearerToken,
          basicUsername,
          basicPassword,
          clientCertPem,
          clientKeyPem,
          caCertPem,
        } = req.body;
        const validAuthTypes = ["none", "api_key", "bearer", "basic", "mtls"];
        if (!authType || !validAuthTypes.includes(authType)) {
          return res.status(400).json({ message: `Invalid authType. Must be one of: ${validAuthTypes.join(", ")}` });
        }

        // Validate required fields per auth type
        if (authType === "api_key" && (!apiKeyHeader || !apiKeyValue)) {
          return res.status(400).json({ message: "api_key auth requires apiKeyHeader and apiKeyValue" });
        }
        if (authType === "bearer" && !bearerToken) {
          return res.status(400).json({ message: "bearer auth requires bearerToken" });
        }
        if (authType === "basic" && (!basicUsername || !basicPassword)) {
          return res.status(400).json({ message: "basic auth requires basicUsername and basicPassword" });
        }
        if (authType === "mtls" && (!clientCertPem || !clientKeyPem)) {
          return res.status(400).json({ message: "mtls auth requires clientCertPem and clientKeyPem" });
        }

        const existingConfig = (feed.config as Record<string, any>) || {};
        const authConfig: Record<string, any> = { authType };
        if (authType === "api_key") {
          authConfig.apiKeyHeader = apiKeyHeader;
          authConfig.apiKeyValue = apiKeyValue;
        } else if (authType === "bearer") {
          authConfig.bearerToken = bearerToken;
        } else if (authType === "basic") {
          authConfig.basicUsername = basicUsername;
          authConfig.basicPassword = basicPassword;
        } else if (authType === "mtls") {
          authConfig.clientCertPem = clientCertPem;
          authConfig.clientKeyPem = clientKeyPem;
          if (caCertPem) authConfig.caCertPem = caCertPem;
        }

        const updatedConfig = { ...existingConfig, auth: authConfig };
        const updated = await storage.updateIocFeed(p(req.params.id), { config: updatedConfig });
        if (!updated) return res.status(404).json({ message: "Feed not found" });

        // Return feed but mask sensitive auth fields
        const maskedAuth = { ...authConfig };
        if (maskedAuth.apiKeyValue) maskedAuth.apiKeyValue = "***";
        if (maskedAuth.bearerToken) maskedAuth.bearerToken = "***";
        if (maskedAuth.basicPassword) maskedAuth.basicPassword = "***";
        if (maskedAuth.clientKeyPem) maskedAuth.clientKeyPem = "***";

        res.json({ ...updated, config: { ...updatedConfig, auth: maskedAuth } });
      } catch (error) {
        res.status(500).json({ message: "Failed to update feed authentication" });
      }
    },
  );

  // ── 4.7: Parse STIX 2.1 full objects ──
  app.post(
    "/api/ioc-feeds/:id/ingest-stix-full",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });

        const { parseSTIXBundleFull, ingestFeed } = await import("../ioc-ingestion");
        const stixData = req.body.data || req.body;
        const fullResult = parseSTIXBundleFull(stixData);

        // Ingest the indicators normally
        const ingestionResult = await ingestFeed(feed, stixData);

        // Ingest STIX objects as pseudo-IOC entries for searchability
        const stixObjectEntries: any[] = [];
        const objectTypes = [
          { arr: fullResult.threatActors, type: "threat-actor" },
          { arr: fullResult.campaigns, type: "campaign" },
          { arr: fullResult.malware, type: "malware" },
          { arr: fullResult.tools, type: "tool" },
          { arr: fullResult.attackPatterns, type: "attack-pattern" },
        ];

        for (const { arr, type } of objectTypes) {
          for (const obj of arr) {
            stixObjectEntries.push({
              orgId: feed.orgId,
              feedId: feed.id,
              iocType: type,
              iocValue: obj.name,
              confidence: 80,
              severity: "medium",
              tags: obj.labels || [],
              source: "STIX 2.1",
              status: "active",
              metadata: {
                stixId: obj.stixId,
                stixType: obj.stixType,
                description: obj.description,
                aliases: obj.aliases,
                ...obj.metadata,
                relationships: fullResult.relationships
                  .filter((r) => r.sourceRef === obj.stixId || r.targetRef === obj.stixId)
                  .map((r) => ({
                    type: r.relationshipType,
                    sourceRef: r.sourceRef,
                    targetRef: r.targetRef,
                    description: r.description,
                  })),
              },
              expiresAt: null,
            });
          }
        }

        // Batch insert STIX objects
        let stixObjectsIngested = 0;
        if (stixObjectEntries.length > 0) {
          const { db: database } = await import("../db");
          const { iocEntries } = await import("@shared/schema");
          const CHUNK = 50;
          for (let i = 0; i < stixObjectEntries.length; i += CHUNK) {
            const chunk = stixObjectEntries.slice(i, i + CHUNK);
            try {
              const inserted = await database.insert(iocEntries).values(chunk).onConflictDoNothing().returning();
              stixObjectsIngested += inserted.length;
            } catch (e: any) {
              logger.child("routes").warn(`STIX object insert error: ${e.message}`);
            }
          }
        }

        res.json({
          ...ingestionResult,
          stixObjects: {
            threatActors: fullResult.threatActors.length,
            campaigns: fullResult.campaigns.length,
            malware: fullResult.malware.length,
            tools: fullResult.tools.length,
            attackPatterns: fullResult.attackPatterns.length,
            relationships: fullResult.relationships.length,
            ingested: stixObjectsIngested,
          },
        });
      } catch (error) {
        logger.child("routes").error("STIX full ingestion error", { error: String(error) });
        res.status(500).json({ message: "Failed to ingest STIX bundle" });
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
        if (!alert || alert.orgId !== orgId) return res.status(404).json({ message: "Alert not found" });
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

  // ── 4.2: Feed ingestion statistics per feed (total, 24h, 7d) ──
  app.get(
    "/api/ioc-feeds/:id/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });

        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and, gte, count } = await import("drizzle-orm");

        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

        const [totalResult] = await database
          .select({ count: count() })
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.feedId, feed.id)));

        const [last24hResult] = await database
          .select({ count: count() })
          .from(iocEntries)
          .where(
            and(eq(iocEntries.orgId, orgId), eq(iocEntries.feedId, feed.id), gte(iocEntries.createdAt, oneDayAgo)),
          );

        const [last7dResult] = await database
          .select({ count: count() })
          .from(iocEntries)
          .where(
            and(eq(iocEntries.orgId, orgId), eq(iocEntries.feedId, feed.id), gte(iocEntries.createdAt, sevenDaysAgo)),
          );

        res.json({
          feedId: feed.id,
          feedName: feed.name,
          total: totalResult?.count ?? 0,
          last24h: last24hResult?.count ?? 0,
          last7d: last7dResult?.count ?? 0,
          lastFetchAt: feed.lastFetchAt,
          lastFetchStatus: feed.lastFetchStatus,
          lastFetchCount: feed.lastFetchCount ?? 0,
        });
      } catch (error) {
        logger.child("routes").error("Failed to fetch feed stats", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch feed statistics" });
      }
    },
  );

  // ── 4.3: Feed preview — sample IOCs before enabling ──
  app.post(
    "/api/ioc-feeds/:id/preview",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const feed = await storage.getIocFeed(p(req.params.id));
        if (!feed || feed.orgId !== orgId) return res.status(404).json({ message: "Feed not found" });

        if (!feed.url) {
          return res.status(400).json({ message: "Feed has no URL configured for preview" });
        }

        // Fetch feed content without persisting
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15000);
          const response = await fetch(feed.url, {
            signal: controller.signal,
            headers: { Accept: "application/json, text/csv, text/plain, */*" },
          });
          clearTimeout(timeout);

          if (!response.ok) {
            return res.json({
              success: false,
              error: `Feed returned HTTP ${response.status}`,
              sampleIocs: [],
              totalParsed: 0,
            });
          }

          const contentType = response.headers.get("content-type") || "";
          const rawText = await response.text();

          // Parse based on feed type
          const sampleIocs: Array<{
            iocType: string;
            iocValue: string;
            confidence: number;
            severity: string;
            source: string;
          }> = [];

          if (feed.feedType === "csv" || contentType.includes("text/csv") || contentType.includes("text/plain")) {
            const lines = rawText.split("\n").filter((l) => l.trim());
            // Skip header line if it looks like a header
            const startIdx = lines.length > 0 && lines[0].toLowerCase().includes("type") ? 1 : 0;
            for (let i = startIdx; i < Math.min(lines.length, startIdx + 10); i++) {
              const parts = lines[i].split(",").map((part) => part.trim());
              if (parts.length >= 2) {
                sampleIocs.push({
                  iocType: parts[0] || "unknown",
                  iocValue: parts[1] || "",
                  confidence: parts[2] ? parseInt(parts[2], 10) || 50 : 50,
                  severity: parts[3] || "medium",
                  source: feed.name,
                });
              }
            }
          } else {
            // Try JSON parsing
            try {
              const jsonData = JSON.parse(rawText);
              const items = Array.isArray(jsonData)
                ? jsonData
                : jsonData.data
                  ? Array.isArray(jsonData.data)
                    ? jsonData.data
                    : [jsonData.data]
                  : jsonData.indicators
                    ? jsonData.indicators
                    : jsonData.objects
                      ? jsonData.objects.filter((o: Record<string, unknown>) => o.type === "indicator" || o.pattern)
                      : [jsonData];

              for (let i = 0; i < Math.min(items.length, 10); i++) {
                const item = items[i];
                sampleIocs.push({
                  iocType: item.type || item.ioc_type || item.iocType || "unknown",
                  iocValue:
                    item.value || item.ioc_value || item.iocValue || item.indicator || item.pattern || "unknown",
                  confidence: item.confidence ?? item.score ?? 50,
                  severity: item.severity || item.threat_level || "medium",
                  source: feed.name,
                });
              }
            } catch {
              // Plain text — treat each line as an IOC value
              const lines = rawText.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
              for (let i = 0; i < Math.min(lines.length, 10); i++) {
                const val = lines[i].trim();
                // Detect IOC type
                let iocType = "unknown";
                if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(val)) iocType = "ip";
                else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) iocType = "domain";
                else if (/^https?:\/\//.test(val)) iocType = "url";
                else if (/^[a-fA-F0-9]{32,}$/.test(val)) iocType = "hash";
                sampleIocs.push({
                  iocType,
                  iocValue: val,
                  confidence: 50,
                  severity: "medium",
                  source: feed.name,
                });
              }
            }
          }

          res.json({
            success: true,
            sampleIocs,
            totalParsed: sampleIocs.length,
            feedName: feed.name,
            feedType: feed.feedType,
            contentType,
          });
        } catch (fetchErr: any) {
          res.json({
            success: false,
            error: fetchErr.name === "AbortError" ? "Feed request timed out (15s)" : fetchErr.message,
            sampleIocs: [],
            totalParsed: 0,
          });
        }
      } catch (error) {
        logger.child("routes").error("Failed to preview feed", { error: String(error) });
        res.status(500).json({ message: "Failed to preview feed" });
      }
    },
  );
}
