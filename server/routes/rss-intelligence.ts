import type { Express } from "express";
import { getOrgId, logger, sendEnvelope, strictLimiter } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";

const log = logger.child("rss-intelligence-routes");

export function registerRSSIntelligenceRoutes(app: Express): void {
  // ── Feed Registry Stats ─────────────────────────────────────────────
  app.get(
    "/api/rss-intelligence/registry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const { getFeedStats, getFeedRegistry } = await import("../rss-intelligence");
        const stats = getFeedStats();
        const registry = getFeedRegistry();

        // Sample feeds from each tier for display
        const sampleFeeds: Record<string, unknown[]> = {};
        for (const tier of ["tier1", "tier2", "tier3", "tier4", "tier5"]) {
          sampleFeeds[tier] = registry
            .filter((f) => f.tier === tier)
            .slice(0, 20)
            .map((f) => ({ url: f.url, domain: f.domain, category: f.category, pollInterval: f.pollIntervalMinutes }));
        }

        sendEnvelope(res, { ...stats, sampleFeeds });
      } catch (err) {
        log.error("Failed to get feed registry", { error: String(err) });
        res.status(500).json({ message: "Failed to get feed registry" });
      }
    },
  );

  // ── Feed States (DB-tracked polling status) ─────────────────────────
  app.get(
    "/api/rss-intelligence/feeds",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { getFeedStates } = await import("../rss-intelligence");
        const tier = req.query.tier as string | undefined;
        const category = req.query.category as string | undefined;
        const enabled = req.query.enabled === "true" ? true : req.query.enabled === "false" ? false : undefined;
        const sortBy = (req.query.sortBy as string) || "quality";
        const limit = parseInt((req.query.limit as string) || "50", 10);
        const offset = parseInt((req.query.offset as string) || "0", 10);

        const result = await getFeedStates({ tier, category, enabled, sortBy, limit, offset });
        sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to get feed states", { error: String(err) });
        res.status(500).json({ message: "Failed to get feed states" });
      }
    },
  );

  // ── Toggle Feed Enabled/Disabled ────────────────────────────────────
  app.patch(
    "/api/rss-intelligence/feeds/toggle",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const { toggleFeed } = await import("../rss-intelligence");
        const { feedUrl, enabled } = req.body;
        if (!feedUrl || typeof enabled !== "boolean") {
          return res.status(400).json({ message: "feedUrl and enabled (boolean) are required" });
        }
        const success = await toggleFeed(feedUrl, enabled);
        sendEnvelope(res, { success, feedUrl, enabled });
      } catch (err) {
        log.error("Failed to toggle feed", { error: String(err) });
        res.status(500).json({ message: "Failed to toggle feed" });
      }
    },
  );

  // ── Recent Articles ─────────────────────────────────────────────────
  app.get(
    "/api/rss-intelligence/articles",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { getRecentArticles } = await import("../rss-intelligence");
        const severity = req.query.severity as string | undefined;
        const feedTier = req.query.feedTier as string | undefined;
        const feedCategory = req.query.feedCategory as string | undefined;
        const hasIocs = req.query.hasIocs === "true";
        const hasCves = req.query.hasCves === "true";
        const limit = parseInt((req.query.limit as string) || "50", 10);
        const offset = parseInt((req.query.offset as string) || "0", 10);

        const result = await getRecentArticles({
          severity,
          feedTier,
          feedCategory,
          hasIocs: hasIocs || undefined,
          hasCves: hasCves || undefined,
          limit,
          offset,
        });
        sendEnvelope(res, result);
      } catch (err) {
        log.error("Failed to get recent articles", { error: String(err) });
        res.status(500).json({ message: "Failed to get recent articles" });
      }
    },
  );

  // ── Trending Topics ─────────────────────────────────────────────────
  app.get(
    "/api/rss-intelligence/trends",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { getTrendingTopics } = await import("../rss-intelligence");
        const days = parseInt((req.query.days as string) || "7", 10);
        const cappedDays = Math.min(Math.max(days, 1), 90);
        const trends = await getTrendingTopics(cappedDays);
        sendEnvelope(res, trends);
      } catch (err) {
        log.error("Failed to get trends", { error: String(err) });
        res.status(500).json({ message: "Failed to get trending topics" });
      }
    },
  );

  // ── Learning History ────────────────────────────────────────────────
  app.get(
    "/api/rss-intelligence/learning",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const { getLearningHistory } = await import("../rss-intelligence");
        const days = parseInt((req.query.days as string) || "30", 10);
        const cappedDays = Math.min(Math.max(days, 1), 365);
        const learning = await getLearningHistory(cappedDays);
        sendEnvelope(res, learning);
      } catch (err) {
        log.error("Failed to get learning history", { error: String(err) });
        res.status(500).json({ message: "Failed to get learning history" });
      }
    },
  );

  // ── Manual Poll Trigger ─────────────────────────────────────────────
  app.post(
    "/api/rss-intelligence/poll",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    strictLimiter,
    async (req, res) => {
      try {
        const { pollFeedBatch, getFeedsByTier, getFeedsByCategory, getFeedRegistry } =
          await import("../rss-intelligence");
        const { tier, category, feedUrls } = req.body;

        let feeds;
        if (feedUrls && Array.isArray(feedUrls)) {
          // Poll specific feeds
          const registry = getFeedRegistry();
          feeds = registry.filter((f) => feedUrls.includes(f.url));
        } else if (tier) {
          feeds = getFeedsByTier(tier);
        } else if (category) {
          feeds = getFeedsByCategory(category);
        } else {
          // Poll a small batch of tier1
          feeds = getFeedsByTier("tier1").slice(0, 20);
        }

        if (feeds.length === 0) {
          return res.status(400).json({ message: "No feeds matched the filter" });
        }

        // Cap at 50 feeds per manual poll
        const cappedFeeds = feeds.slice(0, 50);
        const results = await pollFeedBatch(cappedFeeds, 5);

        const summary = {
          polled: results.length,
          successful: results.filter((r) => r.status === "success").length,
          failed: results.filter((r) => r.status === "error").length,
          skipped: results.filter((r) => r.status === "skipped" || r.status === "rate_limited").length,
          newArticles: results.reduce((s, r) => s + r.newArticles, 0),
          iocsExtracted: results.reduce((s, r) => s + r.iocExtracted, 0),
          cvesFound: results.reduce((s, r) => s + r.cvesFound, 0),
          techniquesFound: results.reduce((s, r) => s + r.techniquesFound, 0),
          duration: results.reduce((s, r) => s + r.duration, 0),
        };

        sendEnvelope(res, { summary, results: results.slice(0, 100) });
      } catch (err) {
        log.error("Failed to poll feeds", { error: String(err) });
        res.status(500).json({ message: "Failed to poll feeds" });
      }
    },
  );

  // ── Manual RAG Index Trigger ────────────────────────────────────────
  app.post(
    "/api/rss-intelligence/index-rag",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    strictLimiter,
    async (req, res) => {
      try {
        const { indexArticlesForRAG } = await import("../rss-intelligence");
        const limit = Math.min(parseInt((req.body.limit as string) || "100", 10), 500);
        const indexed = await indexArticlesForRAG(limit);
        sendEnvelope(res, { indexed, message: `Indexed ${indexed} articles into RAG knowledge base` });
      } catch (err) {
        log.error("Failed to index articles for RAG", { error: String(err) });
        res.status(500).json({ message: "Failed to index articles for RAG" });
      }
    },
  );

  // ── Update Source Quality Scores ────────────────────────────────────
  app.post(
    "/api/rss-intelligence/update-quality",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    strictLimiter,
    async (_req, res) => {
      try {
        const { updateSourceQuality } = await import("../rss-intelligence");
        await updateSourceQuality();
        sendEnvelope(res, { message: "Source quality scores updated" });
      } catch (err) {
        log.error("Failed to update source quality", { error: String(err) });
        res.status(500).json({ message: "Failed to update source quality" });
      }
    },
  );

  // ── Full Daily Learning Run ─────────────────────────────────────────
  app.post(
    "/api/rss-intelligence/daily-learn",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    strictLimiter,
    async (_req, res) => {
      try {
        const { pollAllFeeds, indexArticlesForRAG, updateSourceQuality } = await import("../rss-intelligence");

        // Phase 1: Poll all feeds
        const pollResult = await pollAllFeeds();

        // Phase 2: Index new articles for RAG
        const indexed = await indexArticlesForRAG(200);

        // Phase 3: Update source quality
        await updateSourceQuality();

        sendEnvelope(res, {
          message: "Daily learning cycle complete",
          polling: pollResult,
          ragIndexed: indexed,
          qualityUpdated: true,
        });
      } catch (err) {
        log.error("Daily learning cycle failed", { error: String(err) });
        res.status(500).json({ message: "Daily learning cycle failed" });
      }
    },
  );

  // ── Dashboard Summary ───────────────────────────────────────────────
  app.get(
    "/api/rss-intelligence/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (_req, res) => {
      try {
        const { getFeedStats, getLearningHistory, getTrendingTopics, getFeedStates, getRecentArticles } =
          await import("../rss-intelligence");

        const [registryStats, learning, trends, topFeeds, recentHighSev] = await Promise.all([
          Promise.resolve(getFeedStats()),
          getLearningHistory(7),
          getTrendingTopics(7),
          getFeedStates({ sortBy: "quality", limit: 10 }),
          getRecentArticles({ severity: "critical", limit: 5 }),
        ]);

        sendEnvelope(res, {
          registry: registryStats,
          learning,
          trends,
          topFeeds: topFeeds.feeds,
          recentCritical: recentHighSev.articles,
        });
      } catch (err) {
        log.error("Failed to get dashboard", { error: String(err) });
        res.status(500).json({ message: "Failed to get RSS intelligence dashboard" });
      }
    },
  );
}
