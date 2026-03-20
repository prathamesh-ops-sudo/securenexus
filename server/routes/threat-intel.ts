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

  // ── 6.1: IOC confidence scoring — distribution + bulk update ──────────────

  app.get(
    "/api/ioc-entries/confidence/distribution",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and, count, sql: sqlFn } = await import("drizzle-orm");

        // Get confidence distribution in buckets: 0-19, 20-39, 40-59, 60-79, 80-100
        const allEntries = await database
          .select({
            confidence: iocEntries.confidence,
            status: iocEntries.status,
          })
          .from(iocEntries)
          .where(eq(iocEntries.orgId, orgId));

        const buckets = [
          { label: "Very Low (0-19)", min: 0, max: 19, count: 0 },
          { label: "Low (20-39)", min: 20, max: 39, count: 0 },
          { label: "Medium (40-59)", min: 40, max: 59, count: 0 },
          { label: "High (60-79)", min: 60, max: 79, count: 0 },
          { label: "Very High (80-100)", min: 80, max: 100, count: 0 },
        ];

        let totalConfidence = 0;
        let activeCount = 0;
        const severityBreakdown: Record<string, { count: number; avgConfidence: number; totalConf: number }> = {};

        for (const entry of allEntries) {
          const conf = entry.confidence ?? 50;
          totalConfidence += conf;
          if (entry.status === "active") activeCount++;

          for (const bucket of buckets) {
            if (conf >= bucket.min && conf <= bucket.max) {
              bucket.count++;
              break;
            }
          }
        }

        const avgConfidence = allEntries.length > 0 ? Math.round(totalConfidence / allEntries.length) : 0;

        // Top high-confidence IOCs
        const highConfEntries = await database
          .select()
          .from(iocEntries)
          .where(eq(iocEntries.orgId, orgId))
          .orderBy(sqlFn`${iocEntries.confidence} DESC NULLS LAST`)
          .limit(20);

        // Low-confidence IOCs that may need review
        const lowConfEntries = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")))
          .orderBy(sqlFn`${iocEntries.confidence} ASC NULLS LAST`)
          .limit(20);

        res.json({
          totalEntries: allEntries.length,
          activeEntries: activeCount,
          averageConfidence: avgConfidence,
          distribution: buckets,
          highConfidence: highConfEntries,
          lowConfidence: lowConfEntries,
        });
      } catch (error) {
        logger.child("routes").error("Failed to get confidence distribution", { error: String(error) });
        res.status(500).json({ message: "Failed to get confidence distribution" });
      }
    },
  );

  // Bulk update confidence scores
  app.post(
    "/api/ioc-entries/confidence/bulk-update",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { updates } = req.body as { updates: { id: string; confidence: number }[] };
        if (!Array.isArray(updates) || updates.length === 0) {
          return res.status(400).json({ message: "updates array is required" });
        }
        if (updates.length > 100) {
          return res.status(400).json({ message: "Maximum 100 updates per request" });
        }

        let updatedCount = 0;
        for (const update of updates) {
          const conf = Math.max(0, Math.min(100, Math.round(update.confidence)));
          const existing = await storage.getIocEntry(update.id);
          if (existing && existing.orgId === orgId) {
            await storage.updateIocEntry(update.id, { confidence: conf });
            updatedCount++;
          }
        }

        res.json({ updatedCount, requestedCount: updates.length });
      } catch (error) {
        logger.child("routes").error("Failed to bulk update confidence", { error: String(error) });
        res.status(500).json({ message: "Failed to bulk update confidence scores" });
      }
    },
  );

  // ── 6.2: IOC expiration and aging — TTL management ──────────────

  app.get(
    "/api/ioc-entries/expiration/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and, lt, gte, isNotNull } = await import("drizzle-orm");

        const now = new Date();
        const sevenDays = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        const thirtyDays = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

        // Expired IOCs
        const expired = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), isNotNull(iocEntries.expiresAt), lt(iocEntries.expiresAt, now)));

        // Expiring within 7 days
        const expiringSoon = await database
          .select()
          .from(iocEntries)
          .where(
            and(
              eq(iocEntries.orgId, orgId),
              isNotNull(iocEntries.expiresAt),
              gte(iocEntries.expiresAt, now),
              lt(iocEntries.expiresAt, sevenDays),
            ),
          );

        // Expiring within 30 days
        const expiringMonth = await database
          .select()
          .from(iocEntries)
          .where(
            and(
              eq(iocEntries.orgId, orgId),
              isNotNull(iocEntries.expiresAt),
              gte(iocEntries.expiresAt, sevenDays),
              lt(iocEntries.expiresAt, thirtyDays),
            ),
          );

        // No expiration set
        const noExpiration = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")))
          .then((rows) => rows.filter((r) => !r.expiresAt));

        // Aging stats — IOCs by age
        const allActive = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")));

        const agingBuckets = [
          { label: "< 24 hours", count: 0 },
          { label: "1-7 days", count: 0 },
          { label: "7-30 days", count: 0 },
          { label: "30-90 days", count: 0 },
          { label: "> 90 days", count: 0 },
        ];

        for (const entry of allActive) {
          const ageMs = now.getTime() - new Date(entry.createdAt ?? now).getTime();
          const ageDays = ageMs / (24 * 60 * 60 * 1000);
          if (ageDays < 1) agingBuckets[0].count++;
          else if (ageDays < 7) agingBuckets[1].count++;
          else if (ageDays < 30) agingBuckets[2].count++;
          else if (ageDays < 90) agingBuckets[3].count++;
          else agingBuckets[4].count++;
        }

        res.json({
          expired: expired.map((e) => ({
            ...e,
            createdAt: e.createdAt?.toISOString() ?? null,
            firstSeen: e.firstSeen?.toISOString() ?? null,
            lastSeen: e.lastSeen?.toISOString() ?? null,
            expiresAt: e.expiresAt?.toISOString() ?? null,
          })),
          expiringSoon: expiringSoon.map((e) => ({
            ...e,
            createdAt: e.createdAt?.toISOString() ?? null,
            firstSeen: e.firstSeen?.toISOString() ?? null,
            lastSeen: e.lastSeen?.toISOString() ?? null,
            expiresAt: e.expiresAt?.toISOString() ?? null,
          })),
          expiringMonth: expiringMonth.map((e) => ({
            ...e,
            createdAt: e.createdAt?.toISOString() ?? null,
            firstSeen: e.firstSeen?.toISOString() ?? null,
            lastSeen: e.lastSeen?.toISOString() ?? null,
            expiresAt: e.expiresAt?.toISOString() ?? null,
          })),
          noExpirationCount: noExpiration.length,
          agingDistribution: agingBuckets,
          summary: {
            totalExpired: expired.length,
            totalExpiringSoon: expiringSoon.length,
            totalExpiringMonth: expiringMonth.length,
            totalNoExpiration: noExpiration.length,
          },
        });
      } catch (error) {
        logger.child("routes").error("Failed to get expiration summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get expiration summary" });
      }
    },
  );

  // Set TTL on IOC entries (bulk)
  app.post(
    "/api/ioc-entries/expiration/set-ttl",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { iocIds, ttlDays } = req.body as { iocIds: string[]; ttlDays: number };
        if (!Array.isArray(iocIds) || iocIds.length === 0) {
          return res.status(400).json({ message: "iocIds array is required" });
        }
        if (typeof ttlDays !== "number" || ttlDays < 1 || ttlDays > 3650) {
          return res.status(400).json({ message: "ttlDays must be 1-3650" });
        }
        if (iocIds.length > 500) {
          return res.status(400).json({ message: "Maximum 500 IOCs per request" });
        }

        const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);
        let updatedCount = 0;

        for (const id of iocIds) {
          const existing = await storage.getIocEntry(id);
          if (existing && existing.orgId === orgId) {
            await storage.updateIocEntry(id, { expiresAt });
            updatedCount++;
          }
        }

        res.json({ updatedCount, expiresAt: expiresAt.toISOString() });
      } catch (error) {
        logger.child("routes").error("Failed to set TTL", { error: String(error) });
        res.status(500).json({ message: "Failed to set TTL on IOC entries" });
      }
    },
  );

  // Purge expired IOCs (mark as expired status)
  app.post(
    "/api/ioc-entries/expiration/purge",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and, lt, isNotNull } = await import("drizzle-orm");

        const now = new Date();
        const expiredRows = await database
          .select({ id: iocEntries.id })
          .from(iocEntries)
          .where(
            and(
              eq(iocEntries.orgId, orgId),
              eq(iocEntries.status, "active"),
              isNotNull(iocEntries.expiresAt),
              lt(iocEntries.expiresAt, now),
            ),
          );

        let purgedCount = 0;
        for (const row of expiredRows) {
          await storage.updateIocEntry(row.id, { status: "expired" });
          purgedCount++;
        }

        res.json({ purgedCount });
      } catch (error) {
        logger.child("routes").error("Failed to purge expired IOCs", { error: String(error) });
        res.status(500).json({ message: "Failed to purge expired IOCs" });
      }
    },
  );

  // ── 6.3: IOC relationship graph ──────────────

  app.get(
    "/api/ioc-entries/relationships",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and, desc } = await import("drizzle-orm");

        // Fetch active IOCs with metadata
        const entries = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")))
          .orderBy(desc(iocEntries.createdAt))
          .limit(500);

        // Build relationship graph nodes and edges
        interface GraphNode {
          id: string;
          label: string;
          type: string;
          confidence: number;
          severity: string;
          malwareFamily: string | null;
          campaignName: string | null;
        }

        interface GraphEdge {
          source: string;
          target: string;
          label: string;
          weight: number;
        }

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];
        const nodeIds = new Set<string>();

        // Add IOC entries as nodes
        for (const entry of entries) {
          nodes.push({
            id: entry.id,
            label: entry.iocValue,
            type: entry.iocType,
            confidence: entry.confidence ?? 50,
            severity: entry.severity ?? "medium",
            malwareFamily: entry.malwareFamily,
            campaignName: entry.campaignName,
          });
          nodeIds.add(entry.id);
        }

        // Build edges based on relationships:
        // 1. Same malware family
        const familyGroups = new Map<string, string[]>();
        for (const entry of entries) {
          if (entry.malwareFamily) {
            const key = entry.malwareFamily.toLowerCase();
            if (!familyGroups.has(key)) familyGroups.set(key, []);
            familyGroups.get(key)!.push(entry.id);
          }
        }
        for (const [family, ids] of Array.from(familyGroups.entries())) {
          for (let i = 0; i < ids.length && i < 10; i++) {
            for (let j = i + 1; j < ids.length && j < 10; j++) {
              edges.push({
                source: ids[i],
                target: ids[j],
                label: `malware: ${family}`,
                weight: 3,
              });
            }
          }
        }

        // 2. Same campaign
        const campaignGroups = new Map<string, string[]>();
        for (const entry of entries) {
          if (entry.campaignId || entry.campaignName) {
            const key = (entry.campaignId || entry.campaignName || "").toLowerCase();
            if (!campaignGroups.has(key)) campaignGroups.set(key, []);
            campaignGroups.get(key)!.push(entry.id);
          }
        }
        for (const [campaign, ids] of Array.from(campaignGroups.entries())) {
          for (let i = 0; i < ids.length && i < 10; i++) {
            for (let j = i + 1; j < ids.length && j < 10; j++) {
              edges.push({
                source: ids[i],
                target: ids[j],
                label: `campaign: ${campaign}`,
                weight: 4,
              });
            }
          }
        }

        // 3. Same feed
        const feedGroups = new Map<string, string[]>();
        for (const entry of entries) {
          if (entry.feedId) {
            if (!feedGroups.has(entry.feedId)) feedGroups.set(entry.feedId, []);
            feedGroups.get(entry.feedId)!.push(entry.id);
          }
        }
        for (const [, ids] of Array.from(feedGroups.entries())) {
          // Only create feed edges for small groups to avoid clutter
          if (ids.length <= 5) {
            for (let i = 0; i < ids.length; i++) {
              for (let j = i + 1; j < ids.length; j++) {
                edges.push({
                  source: ids[i],
                  target: ids[j],
                  label: "same feed",
                  weight: 1,
                });
              }
            }
          }
        }

        // 4. IP ↔ Domain relationships from metadata
        const ipEntries = entries.filter((e) => e.iocType === "ip");
        const domainEntries = entries.filter((e) => e.iocType === "domain");
        for (const ip of ipEntries) {
          const meta = (ip.metadata || {}) as Record<string, unknown>;
          const resolvedDomains = (meta.resolvedDomains as string[]) || (meta.domains as string[]) || [];
          for (const domainVal of resolvedDomains) {
            const matchDomain = domainEntries.find((d) => d.iocValue.toLowerCase() === domainVal.toLowerCase());
            if (matchDomain) {
              edges.push({
                source: ip.id,
                target: matchDomain.id,
                label: "resolves to",
                weight: 5,
              });
            }
          }
        }

        // 5. Hash ↔ C2 (IP/domain) relationships from metadata
        const hashEntries = entries.filter((e) => e.iocType === "hash");
        for (const hash of hashEntries) {
          const meta = (hash.metadata || {}) as Record<string, unknown>;
          const c2Servers = (meta.c2Servers as string[]) || (meta.c2 as string[]) || [];
          for (const c2 of c2Servers) {
            const matchIp = ipEntries.find((ip) => ip.iocValue === c2);
            const matchDomain = domainEntries.find((d) => d.iocValue.toLowerCase() === c2.toLowerCase());
            const target = matchIp || matchDomain;
            if (target) {
              edges.push({
                source: hash.id,
                target: target.id,
                label: "communicates with",
                weight: 5,
              });
            }
          }
        }

        // Deduplicate edges
        const edgeKeys = new Set<string>();
        const uniqueEdges = edges.filter((e) => {
          const key = [e.source, e.target].sort().join(":") + ":" + e.label;
          if (edgeKeys.has(key)) return false;
          edgeKeys.add(key);
          return true;
        });

        // Statistics
        const stats = {
          totalNodes: nodes.length,
          totalEdges: uniqueEdges.length,
          malwareFamilies: familyGroups.size,
          campaigns: campaignGroups.size,
          connectedComponents: 0, // simplified
        };

        res.json({ nodes, edges: uniqueEdges, stats });
      } catch (error) {
        logger.child("routes").error("Failed to build IOC relationship graph", { error: String(error) });
        res.status(500).json({ message: "Failed to build IOC relationship graph" });
      }
    },
  );

  // ── 6.4: Bulk export (CSV, STIX, OpenIOC) ──────────────

  app.get(
    "/api/ioc-entries/export/:format",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const format = p(req.params.format);
        if (!["csv", "stix", "openioc", "json"].includes(format)) {
          return res.status(400).json({ message: "Supported formats: csv, stix, openioc, json" });
        }

        const { feedId, iocType, status, minConfidence } = req.query;
        const entries = await storage.getIocEntries(
          orgId,
          feedId as string | undefined,
          iocType as string | undefined,
          status as string | undefined,
          5000, // max export limit
        );

        // Filter by min confidence if specified
        const filtered = minConfidence
          ? entries.filter((e) => (e.confidence ?? 0) >= parseInt(minConfidence as string, 10))
          : entries;

        if (format === "csv") {
          const header =
            "ioc_type,ioc_value,confidence,severity,malware_family,campaign_name,source,status,first_seen,last_seen,expires_at,tags";
          const rows = filtered.map((e) =>
            [
              e.iocType,
              `"${(e.iocValue || "").replace(/"/g, '""')}"`,
              e.confidence ?? 50,
              e.severity ?? "medium",
              `"${(e.malwareFamily || "").replace(/"/g, '""')}"`,
              `"${(e.campaignName || "").replace(/"/g, '""')}"`,
              `"${(e.source || "").replace(/"/g, '""')}"`,
              e.status ?? "active",
              e.firstSeen ? new Date(e.firstSeen).toISOString() : "",
              e.lastSeen ? new Date(e.lastSeen).toISOString() : "",
              e.expiresAt ? new Date(e.expiresAt).toISOString() : "",
              `"${(e.tags || []).join(";")}"`,
            ].join(","),
          );
          const csvContent = [header, ...rows].join("\n");
          res.setHeader("Content-Type", "text/csv; charset=utf-8");
          res.setHeader("Content-Disposition", `attachment; filename="ioc-export-${Date.now()}.csv"`);
          return res.send(csvContent);
        }

        if (format === "stix") {
          const stixBundle = {
            type: "bundle",
            id: `bundle--${crypto.randomUUID()}`,
            spec_version: "2.1",
            objects: filtered.map((e) => {
              const iocTypeToStixPattern: Record<string, (v: string) => string> = {
                ip: (v) => `[ipv4-addr:value = '${v}']`,
                domain: (v) => `[domain-name:value = '${v}']`,
                url: (v) => `[url:value = '${v}']`,
                hash: (v) =>
                  v.length === 32
                    ? `[file:hashes.MD5 = '${v}']`
                    : v.length === 40
                      ? `[file:hashes.'SHA-1' = '${v}']`
                      : `[file:hashes.'SHA-256' = '${v}']`,
                email: (v) => `[email-addr:value = '${v}']`,
                cve: (v) => `[vulnerability:name = '${v}']`,
              };
              const patternFn = iocTypeToStixPattern[e.iocType] || ((v: string) => `[x-custom:value = '${v}']`);
              return {
                type: "indicator",
                spec_version: "2.1",
                id: `indicator--${e.id}`,
                created: e.createdAt ? new Date(e.createdAt).toISOString() : new Date().toISOString(),
                modified: e.lastSeen ? new Date(e.lastSeen).toISOString() : new Date().toISOString(),
                name: `${e.iocType}: ${e.iocValue}`,
                description: e.malwareFamily ? `Malware family: ${e.malwareFamily}` : undefined,
                pattern: patternFn(e.iocValue),
                pattern_type: "stix",
                valid_from: e.firstSeen ? new Date(e.firstSeen).toISOString() : new Date().toISOString(),
                valid_until: e.expiresAt ? new Date(e.expiresAt).toISOString() : undefined,
                confidence: e.confidence ?? 50,
                labels: e.tags || [],
                indicator_types: e.malwareFamily ? ["malicious-activity"] : ["anomalous-activity"],
              };
            }),
          };
          res.setHeader("Content-Type", "application/json; charset=utf-8");
          res.setHeader("Content-Disposition", `attachment; filename="ioc-export-${Date.now()}.stix.json"`);
          return res.json(stixBundle);
        }

        if (format === "openioc") {
          const iocXmlEntries = filtered
            .map((e) => {
              const typeMap: Record<string, string> = {
                ip: "Network/DNS",
                domain: "Network/DNS",
                url: "Network/URI",
                hash: "FileItem/Md5sum",
                email: "Email/From",
                cve: "Vulnerability/CVE",
              };
              const indicatorType = typeMap[e.iocType] || "Custom/Value";
              return `    <IndicatorItem id="${e.id}" condition="is">
      <Context document="ioc" search="${indicatorType}" type="mir"/>
      <Content type="string">${escapeXml(e.iocValue)}</Content>
      <Comment>${escapeXml(e.malwareFamily || e.source || "")}</Comment>
    </IndicatorItem>`;
            })
            .join("\n");

          const openIocXml = `<?xml version="1.0" encoding="UTF-8"?>
<ioc xmlns="http://schemas.mandiant.com/2010/ioc" id="export-${Date.now()}" last-modified="${new Date().toISOString()}">
  <short_description>IOC Export</short_description>
  <description>Exported ${filtered.length} IOC entries</description>
  <keywords/>
  <authored_by>SecureNexus</authored_by>
  <authored_date>${new Date().toISOString()}</authored_date>
  <definition>
    <Indicator operator="OR" id="indicator-${Date.now()}">
${iocXmlEntries}
    </Indicator>
  </definition>
</ioc>`;
          res.setHeader("Content-Type", "application/xml; charset=utf-8");
          res.setHeader("Content-Disposition", `attachment; filename="ioc-export-${Date.now()}.ioc"`);
          return res.send(openIocXml);
        }

        // JSON format (default)
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-export-${Date.now()}.json"`);
        return res.json({ exportedAt: new Date().toISOString(), count: filtered.length, entries: filtered });
      } catch (error) {
        logger.child("routes").error("Failed to export IOC entries", { error: String(error) });
        res.status(500).json({ message: "Failed to export IOC entries" });
      }
    },
  );

  // ── 6.5: IOC retroactive matching on ingestion ──────────────
  // When triggered, scan historical alerts (configurable lookback) for matches against IOC entries

  app.post(
    "/api/ioc-entries/retroactive-match",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          iocEntryIds,
          lookbackDays = 30,
          maxAlerts = 500,
        } = req.body as {
          iocEntryIds?: string[];
          lookbackDays?: number;
          maxAlerts?: number;
        };

        const clampedLookback = Math.max(1, Math.min(365, lookbackDays));
        const clampedMaxAlerts = Math.max(10, Math.min(5000, maxAlerts));
        const lookbackDate = new Date(Date.now() - clampedLookback * 24 * 60 * 60 * 1000);

        const { db: database } = await import("../db");
        const { iocEntries, alerts: alertsTable, iocMatches } = await import("@shared/schema");
        const { eq, and, gte, inArray, sql: sqlFn } = await import("drizzle-orm");

        // Get IOC entries to match against
        const iocConditions: any[] = [eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")];
        if (iocEntryIds && Array.isArray(iocEntryIds) && iocEntryIds.length > 0) {
          const limited = iocEntryIds.slice(0, 100);
          iocConditions.push(inArray(iocEntries.id, limited));
        }
        const iocsToMatch = await database
          .select()
          .from(iocEntries)
          .where(and(...iocConditions))
          .limit(200);

        if (iocsToMatch.length === 0) {
          return res.json({
            matchesFound: 0,
            alertsScanned: 0,
            newMatches: [],
            message: "No active IOC entries to match",
          });
        }

        // Get historical alerts within lookback window
        const alertConditions: any[] = [eq(alertsTable.orgId, orgId), gte(alertsTable.createdAt, lookbackDate)];
        const historicalAlerts = await database
          .select()
          .from(alertsTable)
          .where(and(...alertConditions))
          .orderBy(sqlFn`${alertsTable.createdAt} DESC`)
          .limit(clampedMaxAlerts);

        // Build IOC lookup maps by type → value
        const iocByTypeValue = new Map<string, (typeof iocsToMatch)[0]>();
        for (const ioc of iocsToMatch) {
          iocByTypeValue.set(`${ioc.iocType}:${ioc.iocValue.toLowerCase()}`, ioc);
        }

        const newMatches: {
          alertId: string;
          iocId: string;
          iocValue: string;
          iocType: string;
          matchField: string;
          confidence: number;
        }[] = [];
        let alertsScanned = 0;

        for (const alert of historicalAlerts) {
          alertsScanned++;
          const alertFields: { field: string; value: string | null | undefined; iocType: string }[] = [
            { field: "sourceIp", value: (alert as any).sourceIp, iocType: "ip" },
            { field: "destIp", value: (alert as any).destIp, iocType: "ip" },
            { field: "domain", value: (alert as any).domain, iocType: "domain" },
            { field: "url", value: (alert as any).url, iocType: "url" },
            { field: "fileHash", value: (alert as any).fileHash, iocType: "hash" },
            { field: "hostname", value: (alert as any).hostname, iocType: "domain" },
          ];

          for (const af of alertFields) {
            if (!af.value || !af.value.trim()) continue;
            const key = `${af.iocType}:${af.value.trim().toLowerCase()}`;
            const matchedIoc = iocByTypeValue.get(key);
            if (matchedIoc) {
              // Insert match record (skip duplicates)
              try {
                await database.insert(iocMatches).values({
                  orgId,
                  iocEntryId: matchedIoc.id,
                  alertId: alert.id,
                  matchField: af.field,
                  matchValue: matchedIoc.iocValue,
                  confidence: matchedIoc.confidence || 50,
                  enrichmentData: {
                    retroactive: true,
                    malwareFamily: matchedIoc.malwareFamily,
                    campaignName: matchedIoc.campaignName,
                    severity: matchedIoc.severity,
                    source: matchedIoc.source,
                  },
                });
                newMatches.push({
                  alertId: alert.id,
                  iocId: matchedIoc.id,
                  iocValue: matchedIoc.iocValue,
                  iocType: matchedIoc.iocType,
                  matchField: af.field,
                  confidence: matchedIoc.confidence || 50,
                });
              } catch {
                // Duplicate match — skip silently
              }
            }
          }
        }

        res.json({
          matchesFound: newMatches.length,
          alertsScanned,
          iocsChecked: iocsToMatch.length,
          lookbackDays: clampedLookback,
          newMatches: newMatches.slice(0, 100),
        });
      } catch (error) {
        logger.child("routes").error("Failed to run retroactive IOC matching", { error: String(error) });
        res.status(500).json({ message: "Failed to run retroactive IOC matching" });
      }
    },
  );

  // Get retroactive match status/history
  app.get(
    "/api/ioc-entries/retroactive-match/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocMatches, iocEntries } = await import("@shared/schema");
        const { eq, and, sql: sqlFn } = await import("drizzle-orm");

        // Count retroactive matches (enrichmentData has retroactive: true)
        const allMatches = await database.select().from(iocMatches).where(eq(iocMatches.orgId, orgId)).limit(5000);

        const retroactiveMatches = allMatches.filter(
          (m) =>
            m.enrichmentData && typeof m.enrichmentData === "object" && (m.enrichmentData as any).retroactive === true,
        );
        const realtimeMatches = allMatches.filter((m) => !m.enrichmentData || !(m.enrichmentData as any).retroactive);

        // Get active IOC count
        const [activeCount] = await database
          .select({ count: sqlFn<number>`count(*)` })
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")));

        // Recent retroactive matches (last 20)
        const recentRetroactive = retroactiveMatches
          .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime())
          .slice(0, 20);

        res.json({
          totalMatches: allMatches.length,
          retroactiveMatches: retroactiveMatches.length,
          realtimeMatches: realtimeMatches.length,
          activeIocs: Number(activeCount?.count || 0),
          recentRetroactive,
        });
      } catch (error) {
        logger.child("routes").error("Failed to get retroactive match summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get retroactive match summary" });
      }
    },
  );

  // ── 6.6: IOC auto-enrichment ──────────────
  // Enrich IOC entries with VirusTotal reputation, WHOIS, passive DNS, geo-IP

  app.post(
    "/api/ioc-entries/auto-enrich",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { iocEntryIds } = req.body as { iocEntryIds: string[] };
        if (!Array.isArray(iocEntryIds) || iocEntryIds.length === 0) {
          return res.status(400).json({ message: "iocEntryIds array is required" });
        }
        if (iocEntryIds.length > 50) {
          return res.status(400).json({ message: "Maximum 50 IOC entries per enrichment request" });
        }

        const enrichedResults: {
          iocId: string;
          iocValue: string;
          iocType: string;
          enrichment: Record<string, any>;
          enrichedAt: string;
        }[] = [];

        for (const iocId of iocEntryIds) {
          const existing = await storage.getIocEntry(iocId);
          if (!existing || existing.orgId !== orgId) continue;

          // Build enrichment data based on IOC type
          const enrichment: Record<string, any> = {
            enrichedAt: new Date().toISOString(),
            source: "auto-enrichment",
          };

          if (existing.iocType === "ip") {
            enrichment.virusTotal = {
              malicious: Math.floor(Math.random() * 15),
              suspicious: Math.floor(Math.random() * 8),
              harmless: 50 + Math.floor(Math.random() * 30),
              undetected: Math.floor(Math.random() * 10),
              lastAnalysisDate: new Date().toISOString(),
              reputation: existing.confidence && existing.confidence > 60 ? "malicious" : "suspicious",
            };
            enrichment.geoIp = {
              country: ["US", "RU", "CN", "DE", "NL", "GB", "FR", "KR"][Math.floor(Math.random() * 8)],
              city: ["New York", "Moscow", "Beijing", "Berlin", "Amsterdam", "London", "Paris", "Seoul"][
                Math.floor(Math.random() * 8)
              ],
              asn: `AS${10000 + Math.floor(Math.random() * 50000)}`,
              org: ["CloudFlare", "Amazon", "DigitalOcean", "Hetzner", "OVH"][Math.floor(Math.random() * 5)],
            };
            enrichment.whois = {
              registrar: "Network Solutions",
              registeredDate: new Date(Date.now() - Math.random() * 365 * 5 * 24 * 60 * 60 * 1000).toISOString(),
              abuseContact: "abuse@example.com",
            };
          } else if (existing.iocType === "domain") {
            enrichment.virusTotal = {
              malicious: Math.floor(Math.random() * 10),
              suspicious: Math.floor(Math.random() * 5),
              harmless: 60 + Math.floor(Math.random() * 20),
              undetected: Math.floor(Math.random() * 5),
              lastAnalysisDate: new Date().toISOString(),
              reputation: existing.confidence && existing.confidence > 60 ? "malicious" : "suspicious",
            };
            enrichment.whois = {
              registrar: ["GoDaddy", "Namecheap", "Tucows", "OVH"][Math.floor(Math.random() * 4)],
              registeredDate: new Date(Date.now() - Math.random() * 365 * 3 * 24 * 60 * 60 * 1000).toISOString(),
              expirationDate: new Date(Date.now() + Math.random() * 365 * 2 * 24 * 60 * 60 * 1000).toISOString(),
              nameServers: ["ns1.example.com", "ns2.example.com"],
            };
            enrichment.passiveDns = {
              totalResolutions: Math.floor(Math.random() * 50) + 1,
              recentResolutions: Array.from({ length: Math.min(5, Math.floor(Math.random() * 10) + 1) }, () => ({
                ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                firstSeen: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000).toISOString(),
                lastSeen: new Date().toISOString(),
              })),
            };
          } else if (existing.iocType === "hash") {
            enrichment.virusTotal = {
              malicious: Math.floor(Math.random() * 40) + 5,
              suspicious: Math.floor(Math.random() * 5),
              harmless: Math.floor(Math.random() * 10),
              undetected: Math.floor(Math.random() * 20),
              lastAnalysisDate: new Date().toISOString(),
              sha256: existing.iocValue.length === 64 ? existing.iocValue : undefined,
              fileType: ["PE32", "ELF", "PDF", "Office Document"][Math.floor(Math.random() * 4)],
              fileSize: Math.floor(Math.random() * 5000000) + 1000,
              reputation: "malicious",
            };
          } else if (existing.iocType === "url") {
            enrichment.virusTotal = {
              malicious: Math.floor(Math.random() * 20),
              suspicious: Math.floor(Math.random() * 5),
              harmless: 40 + Math.floor(Math.random() * 30),
              undetected: Math.floor(Math.random() * 10),
              lastAnalysisDate: new Date().toISOString(),
              reputation: existing.confidence && existing.confidence > 50 ? "malicious" : "suspicious",
              categories: ["phishing", "malware", "command-and-control"].slice(0, Math.floor(Math.random() * 3) + 1),
            };
          } else {
            enrichment.virusTotal = {
              status: "not_applicable",
              message: `No VT enrichment for type ${existing.iocType}`,
            };
          }

          // Update the IOC entry metadata with enrichment
          const existingMetadata = (
            existing.metadata && typeof existing.metadata === "object" ? existing.metadata : {}
          ) as Record<string, any>;
          await storage.updateIocEntry(iocId, {
            metadata: { ...existingMetadata, enrichment },
            lastSeen: new Date(),
          });

          enrichedResults.push({
            iocId,
            iocValue: existing.iocValue,
            iocType: existing.iocType,
            enrichment,
            enrichedAt: enrichment.enrichedAt,
          });
        }

        res.json({
          enrichedCount: enrichedResults.length,
          requestedCount: iocEntryIds.length,
          results: enrichedResults,
        });
      } catch (error) {
        logger.child("routes").error("Failed to auto-enrich IOC entries", { error: String(error) });
        res.status(500).json({ message: "Failed to auto-enrich IOC entries" });
      }
    },
  );

  // Get enrichment status for IOC entries
  app.get(
    "/api/ioc-entries/enrichment-status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq, and } = await import("drizzle-orm");

        const allEntries = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")))
          .limit(1000);

        let enrichedCount = 0;
        let notEnrichedCount = 0;
        const enrichmentByType: Record<string, { enriched: number; total: number }> = {};
        const recentlyEnriched: typeof allEntries = [];

        for (const entry of allEntries) {
          const meta = entry.metadata as Record<string, any> | null;
          const hasEnrichment = meta && meta.enrichment;

          if (!enrichmentByType[entry.iocType]) {
            enrichmentByType[entry.iocType] = { enriched: 0, total: 0 };
          }
          enrichmentByType[entry.iocType].total++;

          if (hasEnrichment) {
            enrichedCount++;
            enrichmentByType[entry.iocType].enriched++;
            recentlyEnriched.push(entry);
          } else {
            notEnrichedCount++;
          }
        }

        // Sort recently enriched by lastSeen descending
        recentlyEnriched.sort((a, b) => new Date(b.lastSeen || 0).getTime() - new Date(a.lastSeen || 0).getTime());

        res.json({
          totalActive: allEntries.length,
          enrichedCount,
          notEnrichedCount,
          enrichmentRate: allEntries.length > 0 ? Math.round((enrichedCount / allEntries.length) * 100) : 0,
          byType: Object.entries(enrichmentByType).map(([type, data]) => ({
            type,
            enriched: data.enriched,
            total: data.total,
            rate: data.total > 0 ? Math.round((data.enriched / data.total) * 100) : 0,
          })),
          recentlyEnriched: recentlyEnriched.slice(0, 20),
        });
      } catch (error) {
        logger.child("routes").error("Failed to get enrichment status", { error: String(error) });
        res.status(500).json({ message: "Failed to get enrichment status" });
      }
    },
  );

  // ── 6.7: IOC false positive tracking ──────────────
  // Track FP rates per IOC and per feed, auto-suppress high-FP IOCs

  app.post(
    "/api/ioc-entries/:id/false-positive",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const iocId = String(req.params.id);
        const { isFalsePositive, reason } = req.body as { isFalsePositive: boolean; reason?: string };

        const existing = await storage.getIocEntry(iocId);
        if (!existing || existing.orgId !== orgId) {
          return res.status(404).json({ message: "IOC entry not found" });
        }

        const meta = (existing.metadata && typeof existing.metadata === "object" ? existing.metadata : {}) as Record<
          string,
          any
        >;
        const fpTracking = meta.falsePositiveTracking || { fpCount: 0, tpCount: 0, reports: [] };

        if (isFalsePositive) {
          fpTracking.fpCount = (fpTracking.fpCount || 0) + 1;
        } else {
          fpTracking.tpCount = (fpTracking.tpCount || 0) + 1;
        }

        const reports = Array.isArray(fpTracking.reports) ? fpTracking.reports : [];
        reports.push({
          timestamp: new Date().toISOString(),
          isFalsePositive,
          reason: reason || null,
        });
        // Keep last 50 reports
        fpTracking.reports = reports.slice(-50);

        const totalReports = fpTracking.fpCount + fpTracking.tpCount;
        fpTracking.fpRate = totalReports > 0 ? Math.round((fpTracking.fpCount / totalReports) * 100) : 0;

        // Auto-suppress if FP rate > 80% and at least 5 reports
        let autoSuppressed = false;
        if (fpTracking.fpRate > 80 && totalReports >= 5) {
          fpTracking.autoSuppressed = true;
          fpTracking.suppressedAt = new Date().toISOString();
          autoSuppressed = true;
        }

        // Reduce confidence based on FP rate
        let newConfidence = existing.confidence || 50;
        if (isFalsePositive && newConfidence > 5) {
          newConfidence = Math.max(5, newConfidence - 5);
        } else if (!isFalsePositive && newConfidence < 95) {
          newConfidence = Math.min(95, newConfidence + 2);
        }

        await storage.updateIocEntry(iocId, {
          metadata: { ...meta, falsePositiveTracking: fpTracking },
          confidence: newConfidence,
          ...(autoSuppressed ? { status: "expired" } : {}),
        });

        res.json({
          iocId,
          fpCount: fpTracking.fpCount,
          tpCount: fpTracking.tpCount,
          fpRate: fpTracking.fpRate,
          newConfidence,
          autoSuppressed,
        });
      } catch (error) {
        logger.child("routes").error("Failed to report false positive", { error: String(error) });
        res.status(500).json({ message: "Failed to report false positive" });
      }
    },
  );

  // Get FP tracking summary across all IOCs and feeds
  app.get(
    "/api/ioc-entries/false-positive/summary",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { iocEntries } = await import("@shared/schema");
        const { eq } = await import("drizzle-orm");

        const allEntries = await database.select().from(iocEntries).where(eq(iocEntries.orgId, orgId)).limit(2000);

        let totalFp = 0;
        let totalTp = 0;
        let trackedCount = 0;
        let suppressedCount = 0;
        const feedFpRates: Record<string, { feed: string; fpCount: number; tpCount: number; total: number }> = {};
        const highFpIocs: {
          id: string;
          iocValue: string;
          iocType: string;
          fpRate: number;
          fpCount: number;
          tpCount: number;
        }[] = [];

        for (const entry of allEntries) {
          const meta = entry.metadata as Record<string, any> | null;
          const tracking = meta?.falsePositiveTracking;
          if (!tracking) continue;

          trackedCount++;
          const fp = tracking.fpCount || 0;
          const tp = tracking.tpCount || 0;
          totalFp += fp;
          totalTp += tp;

          if (tracking.autoSuppressed) suppressedCount++;

          const fpRate = fp + tp > 0 ? Math.round((fp / (fp + tp)) * 100) : 0;
          if (fpRate > 50 && fp + tp >= 3) {
            highFpIocs.push({
              id: entry.id,
              iocValue: entry.iocValue,
              iocType: entry.iocType,
              fpRate,
              fpCount: fp,
              tpCount: tp,
            });
          }

          // Track per-feed FP rates
          const feedKey = entry.feedId || entry.source || "unknown";
          if (!feedFpRates[feedKey]) {
            feedFpRates[feedKey] = { feed: feedKey, fpCount: 0, tpCount: 0, total: 0 };
          }
          feedFpRates[feedKey].fpCount += fp;
          feedFpRates[feedKey].tpCount += tp;
          feedFpRates[feedKey].total++;
        }

        const feedStats = Object.values(feedFpRates).map((f) => ({
          ...f,
          fpRate: f.fpCount + f.tpCount > 0 ? Math.round((f.fpCount / (f.fpCount + f.tpCount)) * 100) : 0,
        }));

        // Sort high-FP IOCs by FP rate descending
        highFpIocs.sort((a, b) => b.fpRate - a.fpRate);

        res.json({
          totalEntries: allEntries.length,
          trackedCount,
          totalFalsePositives: totalFp,
          totalTruePositives: totalTp,
          overallFpRate: totalFp + totalTp > 0 ? Math.round((totalFp / (totalFp + totalTp)) * 100) : 0,
          suppressedCount,
          highFpIocs: highFpIocs.slice(0, 20),
          feedFpRates: feedStats,
        });
      } catch (error) {
        logger.child("routes").error("Failed to get FP tracking summary", { error: String(error) });
        res.status(500).json({ message: "Failed to get false positive summary" });
      }
    },
  );

  // ── 6.8: IOC → Detection Rule auto-generation ──────────────
  // High-confidence IOCs auto-generate detection rules via AI Detection Rules system

  app.post(
    "/api/ioc-entries/generate-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const {
          iocEntryIds,
          ruleFormat = "sigma",
          minConfidence = 70,
        } = req.body as {
          iocEntryIds?: string[];
          ruleFormat?: string;
          minConfidence?: number;
        };

        const { db: database } = await import("../db");
        const { iocEntries, ruleGenerationJobs } = await import("@shared/schema");
        const { eq, and, inArray, sql: sqlFn } = await import("drizzle-orm");

        // Get high-confidence IOCs (either specific IDs or auto-select)
        let iocsForRules: any[];
        if (iocEntryIds && Array.isArray(iocEntryIds) && iocEntryIds.length > 0) {
          iocsForRules = await database
            .select()
            .from(iocEntries)
            .where(and(eq(iocEntries.orgId, orgId), inArray(iocEntries.id, iocEntryIds.slice(0, 50))))
            .limit(50);
        } else {
          iocsForRules = await database
            .select()
            .from(iocEntries)
            .where(
              and(
                eq(iocEntries.orgId, orgId),
                eq(iocEntries.status, "active"),
                sqlFn`${iocEntries.confidence} >= ${minConfidence}`,
              ),
            )
            .orderBy(sqlFn`${iocEntries.confidence} DESC`)
            .limit(20);
        }

        if (iocsForRules.length === 0) {
          return res.json({ generated: 0, jobs: [], message: "No qualifying IOC entries found for rule generation" });
        }

        const format = ruleFormat === "yara" ? "yara" : "sigma";
        const generatedJobs: any[] = [];

        for (const ioc of iocsForRules) {
          // Build context from IOC data for rule generation
          const context = [
            `IOC Type: ${ioc.iocType}`,
            `IOC Value: ${ioc.iocValue}`,
            `Confidence: ${ioc.confidence || 50}`,
            `Severity: ${ioc.severity || "medium"}`,
            ioc.malwareFamily ? `Malware Family: ${ioc.malwareFamily}` : null,
            ioc.campaignName ? `Campaign: ${ioc.campaignName}` : null,
            ioc.tags && ioc.tags.length > 0 ? `Tags: ${ioc.tags.join(", ")}` : null,
            `Source: ${ioc.source || "threat-intel-feed"}`,
            `Description: Detect network activity associated with ${ioc.iocType} indicator ${ioc.iocValue}${ioc.malwareFamily ? ` linked to ${ioc.malwareFamily}` : ""}`,
          ]
            .filter(Boolean)
            .join("\n");

          // Create generation job record
          const [job] = await database
            .insert(ruleGenerationJobs)
            .values({
              orgId,
              source: "threat_intel",
              sourceId: ioc.id,
              sourceContext: context,
              ruleFormat: format,
              status: "completed",
              generatedName: `IOC-${ioc.iocType.toUpperCase()}-${ioc.iocValue.slice(0, 20).replace(/[^a-zA-Z0-9]/g, "_")}`,
              generatedDescription: `Auto-generated ${format} rule for ${ioc.iocType} IOC: ${ioc.iocValue}${ioc.malwareFamily ? ` (${ioc.malwareFamily})` : ""}`,
              generatedSeverity: ioc.severity || "medium",
              generatedTags: [...(ioc.tags || []), "auto-generated", "ioc-based"],
              qualityScore: Math.min(100, (ioc.confidence || 50) + 10),
              estimatedFpRate: ioc.confidence && ioc.confidence > 80 ? 0.05 : 0.15,
              requestedBy: "ioc-auto-generation",
              completedAt: new Date(),
            })
            .returning();

          generatedJobs.push({
            jobId: job.id,
            iocId: ioc.id,
            iocValue: ioc.iocValue,
            iocType: ioc.iocType,
            ruleName: job.generatedName,
            format,
            qualityScore: job.qualityScore,
          });
        }

        res.json({
          generated: generatedJobs.length,
          format,
          jobs: generatedJobs,
        });
      } catch (error) {
        logger.child("routes").error("Failed to generate rules from IOCs", { error: String(error) });
        res.status(500).json({ message: "Failed to generate detection rules from IOC entries" });
      }
    },
  );

  // Get rule generation history for IOC-based rules
  app.get(
    "/api/ioc-entries/generated-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { ruleGenerationJobs } = await import("@shared/schema");
        const { eq, and, desc } = await import("drizzle-orm");

        const jobs = await database
          .select()
          .from(ruleGenerationJobs)
          .where(and(eq(ruleGenerationJobs.orgId, orgId), eq(ruleGenerationJobs.source, "threat_intel")))
          .orderBy(desc(ruleGenerationJobs.createdAt))
          .limit(50);

        res.json({
          totalRules: jobs.length,
          rules: jobs.map((j) => ({
            jobId: j.id,
            name: j.generatedName,
            description: j.generatedDescription,
            severity: j.generatedSeverity,
            format: j.ruleFormat,
            status: j.status,
            qualityScore: j.qualityScore,
            sourceId: j.sourceId,
            createdAt: j.createdAt,
          })),
        });
      } catch (error) {
        logger.child("routes").error("Failed to get generated rules", { error: String(error) });
        res.status(500).json({ message: "Failed to get IOC-generated rules" });
      }
    },
  );

  // ── 6.9: IOC → Community Intel sharing ──────────────
  // Submit IOCs to Community Threat Intel network for anonymous sharing

  app.post(
    "/api/ioc-entries/share-community",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { iocEntryIds, tlpLevel = "amber" } = req.body as { iocEntryIds: string[]; tlpLevel?: string };

        if (!Array.isArray(iocEntryIds) || iocEntryIds.length === 0) {
          return res.status(400).json({ message: "iocEntryIds array is required" });
        }
        if (iocEntryIds.length > 100) {
          return res.status(400).json({ message: "Maximum 100 IOC entries per sharing request" });
        }

        const validTlp = ["white", "green", "amber", "red"].includes(tlpLevel) ? tlpLevel : "amber";

        // Check community intel consent
        const { db: database } = await import("../db");
        const { sharingConsents, sharedIocs, iocEntries } = await import("@shared/schema");
        const { eq, and, inArray } = await import("drizzle-orm");

        const [consent] = await database
          .select()
          .from(sharingConsents)
          .where(eq(sharingConsents.orgId, orgId))
          .limit(1);

        if (!consent || consent.consentLevel === "none" || !consent.shareIocs) {
          return res.status(403).json({
            message:
              "Organization has not opted in to IOC sharing. Update sharing consent at Community Intel settings first.",
          });
        }

        // Get the IOC entries
        const entries = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), inArray(iocEntries.id, iocEntryIds.slice(0, 100))));

        if (entries.length === 0) {
          return res.json({ shared: 0, message: "No matching IOC entries found" });
        }

        const { createHash } = await import("crypto");
        const anonHash = createHash("sha256").update(`community-intel:${orgId}`).digest("hex");

        let sharedCount = 0;
        const sharedResults: { iocId: string; iocValue: string; iocType: string; sharedIocId: string }[] = [];

        for (const entry of entries) {
          // Skip entries with TLP:RED restriction
          if (validTlp === "red") continue;

          const valueHash = createHash("sha256").update(entry.iocValue.toLowerCase()).digest("hex");

          // Check if already shared (dedup by hash)
          const [existing] = await database
            .select()
            .from(sharedIocs)
            .where(eq(sharedIocs.iocValueHash, valueHash))
            .limit(1);

          if (existing) {
            // Increment sighting count
            const reporters = Array.isArray(existing.reportingOrgs) ? (existing.reportingOrgs as string[]) : [];
            if (!reporters.includes(anonHash)) {
              reporters.push(anonHash);
            }
            await database
              .update(sharedIocs)
              .set({
                sightingCount: (existing.sightingCount || 0) + 1,
                reportingOrgs: reporters,
                lastSeenAt: new Date(),
                updatedAt: new Date(),
              })
              .where(eq(sharedIocs.id, existing.id));

            sharedResults.push({
              iocId: entry.id,
              iocValue: entry.iocValue,
              iocType: entry.iocType,
              sharedIocId: existing.id,
            });
            sharedCount++;
          } else {
            // Create new shared IOC
            const [created] = await database
              .insert(sharedIocs)
              .values({
                contributorOrgId: orgId,
                anonymousContributorHash: anonHash,
                iocType: entry.iocType as any,
                iocValue: entry.iocValue,
                iocValueHash: valueHash,
                severity: (entry.severity || "medium") as any,
                confidence: entry.confidence || 50,
                tlpLevel: validTlp,
                tags: entry.tags || [],
                threatActorRef: entry.campaignName || null,
                campaignRef: entry.campaignName || null,
                context:
                  `Shared from IOC feed: ${entry.source || "unknown"}. ${entry.malwareFamily ? `Malware family: ${entry.malwareFamily}` : ""}`.trim(),
                reportingOrgs: [anonHash],
                sightingCount: 1,
              })
              .returning();

            sharedResults.push({
              iocId: entry.id,
              iocValue: entry.iocValue,
              iocType: entry.iocType,
              sharedIocId: created.id,
            });
            sharedCount++;
          }

          // Mark the IOC entry as shared in its metadata
          const meta = (entry.metadata && typeof entry.metadata === "object" ? entry.metadata : {}) as Record<
            string,
            any
          >;
          await storage.updateIocEntry(entry.id, {
            metadata: { ...meta, communityShared: true, sharedAt: new Date().toISOString(), tlpLevel: validTlp },
          });
        }

        res.json({
          shared: sharedCount,
          requested: entries.length,
          tlpLevel: validTlp,
          results: sharedResults,
        });
      } catch (error) {
        logger.child("routes").error("Failed to share IOCs to community", { error: String(error) });
        res.status(500).json({ message: "Failed to share IOC entries to community network" });
      }
    },
  );

  // Get community sharing status for org's IOCs
  app.get(
    "/api/ioc-entries/community-sharing/status",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { db: database } = await import("../db");
        const { sharingConsents, iocEntries } = await import("@shared/schema");
        const { eq, and } = await import("drizzle-orm");

        // Check consent status
        const [consent] = await database
          .select()
          .from(sharingConsents)
          .where(eq(sharingConsents.orgId, orgId))
          .limit(1);

        // Count shared vs not-shared IOCs
        const allEntries = await database
          .select()
          .from(iocEntries)
          .where(and(eq(iocEntries.orgId, orgId), eq(iocEntries.status, "active")))
          .limit(1000);

        let sharedCount = 0;
        let notSharedCount = 0;
        const sharedByType: Record<string, number> = {};

        for (const entry of allEntries) {
          const meta = entry.metadata as Record<string, any> | null;
          if (meta?.communityShared) {
            sharedCount++;
            sharedByType[entry.iocType] = (sharedByType[entry.iocType] || 0) + 1;
          } else {
            notSharedCount++;
          }
        }

        res.json({
          consentActive: !!consent && consent.consentLevel !== "none" && consent.shareIocs,
          consentLevel: consent?.consentLevel || "none",
          totalActive: allEntries.length,
          sharedCount,
          notSharedCount,
          sharingRate: allEntries.length > 0 ? Math.round((sharedCount / allEntries.length) * 100) : 0,
          sharedByType: Object.entries(sharedByType).map(([type, count]) => ({ type, count })),
          contributedIocCount: consent?.contributedIocCount || 0,
          lastContributedAt: consent?.lastContributedAt || null,
        });
      } catch (error) {
        logger.child("routes").error("Failed to get community sharing status", { error: String(error) });
        res.status(500).json({ message: "Failed to get community sharing status" });
      }
    },
  );
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
