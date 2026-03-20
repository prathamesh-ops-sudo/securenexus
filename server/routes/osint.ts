import type { Express } from "express";
import { getOrgId, logger, p } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { db } from "../db";
import {
  osintSources,
  osintQueries,
  osintAlertRules,
  osintAlertMatches,
  osintScheduledScans,
  osintScanSnapshots,
  osintQuotaLogs,
} from "@shared/schema";
import { eq, and, desc, sql, gte } from "drizzle-orm";
import { createHash } from "crypto";

export function registerOsintRoutes(app: Express): void {
  const log = logger.child("osint");

  // ── 5.3: OSINT Source Health Dashboard ──────────────────────────────────────

  // GET /api/osint/sources — list all configured OSINT sources with health status
  app.get(
    "/api/osint/sources",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const sources = await db
          .select()
          .from(osintSources)
          .where(eq(osintSources.orgId, orgId))
          .orderBy(desc(osintSources.createdAt));

        // Mask API key refs
        const masked = sources.map((s) => ({
          ...s,
          apiKeyRef: s.apiKeyRef ? "****" + s.apiKeyRef.slice(-4) : null,
        }));
        res.json(masked);
      } catch (error) {
        log.error("Failed to fetch OSINT sources", { error });
        res.status(500).json({ message: "Failed to fetch OSINT sources" });
      }
    },
  );

  // POST /api/osint/sources — add a new OSINT source
  app.post(
    "/api/osint/sources",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, provider, apiKeyRef, enabled, config } = req.body;
        if (!name || !provider) {
          return res.status(400).json({ message: "name and provider are required" });
        }
        const validProviders = [
          "shodan",
          "censys",
          "virustotal",
          "greynoise",
          "urlscan",
          "pastes",
          "abuseipdb",
          "spamhaus",
          "otx",
        ];
        if (!validProviders.includes(provider)) {
          return res.status(400).json({
            message: `Invalid provider. Valid: ${validProviders.join(", ")}`,
          });
        }
        const [source] = await db
          .insert(osintSources)
          .values({
            orgId,
            name,
            provider,
            apiKeyRef: apiKeyRef || null,
            enabled: enabled !== false,
            status: "unknown",
            config: config || {},
          })
          .returning();
        res.status(201).json(source);
      } catch (error) {
        log.error("Failed to create OSINT source", { error });
        res.status(500).json({ message: "Failed to create OSINT source" });
      }
    },
  );

  // PATCH /api/osint/sources/:id — update source config
  app.patch(
    "/api/osint/sources/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const allowedFields = ["name", "apiKeyRef", "enabled", "config"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) updates[field] = req.body[field];
        }
        if (Object.keys(updates).length === 0) {
          return res.status(400).json({ message: "No valid fields to update" });
        }
        updates.updatedAt = new Date();
        const [updated] = await db
          .update(osintSources)
          .set(updates)
          .where(and(eq(osintSources.id, id), eq(osintSources.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ message: "Source not found" });
        res.json(updated);
      } catch (error) {
        log.error("Failed to update OSINT source", { error });
        res.status(500).json({ message: "Failed to update OSINT source" });
      }
    },
  );

  // DELETE /api/osint/sources/:id
  app.delete(
    "/api/osint/sources/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [deleted] = await db
          .delete(osintSources)
          .where(and(eq(osintSources.id, id), eq(osintSources.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ message: "Source not found" });
        res.json({ success: true });
      } catch (error) {
        log.error("Failed to delete OSINT source", { error });
        res.status(500).json({ message: "Failed to delete OSINT source" });
      }
    },
  );

  // POST /api/osint/sources/:id/test — connectivity test for a source
  app.post(
    "/api/osint/sources/:id/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [source] = await db
          .select()
          .from(osintSources)
          .where(and(eq(osintSources.id, id), eq(osintSources.orgId, orgId)))
          .limit(1);
        if (!source) return res.status(404).json({ message: "Source not found" });

        // Simulate connectivity test based on provider
        const startMs = Date.now();
        const testResult = await simulateSourceTest(source.provider);
        const durationMs = Date.now() - startMs;

        await db
          .update(osintSources)
          .set({
            status: testResult.success ? "healthy" : "error",
            lastQueryAt: new Date(),
            lastSuccessAt: testResult.success ? new Date() : source.lastSuccessAt,
            lastErrorAt: testResult.success ? source.lastErrorAt : new Date(),
            lastErrorMessage: testResult.success ? null : (testResult.error ?? null),
            avgResponseTimeMs: durationMs,
            totalQueries: sql`${osintSources.totalQueries} + 1`,
            successfulQueries: testResult.success
              ? sql`${osintSources.successfulQueries} + 1`
              : osintSources.successfulQueries,
            failedQueries: testResult.success ? osintSources.failedQueries : sql`${osintSources.failedQueries} + 1`,
            updatedAt: new Date(),
          })
          .where(eq(osintSources.id, id));

        res.json({
          success: testResult.success,
          status: testResult.success ? "healthy" : "error",
          responseTimeMs: durationMs,
          error: testResult.error || null,
          quotaInfo: testResult.quotaInfo || null,
        });
      } catch (error) {
        log.error("Failed to test OSINT source", { error });
        res.status(500).json({ message: "Failed to test OSINT source" });
      }
    },
  );

  // GET /api/osint/sources/health — aggregated health dashboard for all sources
  app.get(
    "/api/osint/sources/health",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const sources = await db.select().from(osintSources).where(eq(osintSources.orgId, orgId));

        const summary = {
          totalSources: sources.length,
          healthy: sources.filter((s) => s.status === "healthy").length,
          degraded: sources.filter((s) => s.status === "degraded").length,
          error: sources.filter((s) => s.status === "error").length,
          unknown: sources.filter((s) => s.status === "unknown").length,
          sources: sources.map((s) => ({
            id: s.id,
            name: s.name,
            provider: s.provider,
            enabled: s.enabled,
            status: s.status,
            lastQueryAt: s.lastQueryAt,
            lastSuccessAt: s.lastSuccessAt,
            lastErrorAt: s.lastErrorAt,
            lastErrorMessage: s.lastErrorMessage,
            apiQuotaTotal: s.apiQuotaTotal,
            apiQuotaUsed: s.apiQuotaUsed,
            apiQuotaResetAt: s.apiQuotaResetAt,
            avgResponseTimeMs: s.avgResponseTimeMs,
            successRate: s.totalQueries > 0 ? Math.round((s.successfulQueries / s.totalQueries) * 100) : null,
            totalQueries: s.totalQueries,
          })),
        };
        res.json(summary);
      } catch (error) {
        log.error("Failed to fetch OSINT health dashboard", { error });
        res.status(500).json({ message: "Failed to fetch OSINT health dashboard" });
      }
    },
  );

  // ── 5.1: OSINT Query & Result Visualization ─────────────────────────────────

  // POST /api/osint/queries — run a new OSINT query
  app.post(
    "/api/osint/queries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { sourceId, queryType, queryValue } = req.body;
        if (!queryType || !queryValue) {
          return res.status(400).json({ message: "queryType and queryValue are required" });
        }
        const validTypes = ["ip_lookup", "domain_lookup", "hash_lookup", "search", "passive_dns", "cert_search"];
        if (!validTypes.includes(queryType)) {
          return res.status(400).json({
            message: `Invalid queryType. Valid: ${validTypes.join(", ")}`,
          });
        }

        // Validate source if provided
        if (sourceId) {
          const [source] = await db
            .select()
            .from(osintSources)
            .where(and(eq(osintSources.id, sourceId), eq(osintSources.orgId, orgId)))
            .limit(1);
          if (!source) return res.status(404).json({ message: "Source not found" });
        }

        const startMs = Date.now();

        // Generate simulated OSINT results with visualization data
        const queryResult = generateOsintQueryResult(queryType, queryValue);

        const durationMs = Date.now() - startMs;

        const [query] = await db
          .insert(osintQueries)
          .values({
            orgId,
            sourceId: sourceId || null,
            queryType,
            queryValue,
            status: "completed",
            resultCount: queryResult.results.length,
            results: queryResult.results,
            geoData: queryResult.geoData,
            domainGraph: queryResult.domainGraph,
            timeline: queryResult.timeline,
            durationMs,
            completedAt: new Date(),
          })
          .returning();

        // Update source stats if sourceId provided
        if (sourceId) {
          await db
            .update(osintSources)
            .set({
              lastQueryAt: new Date(),
              lastSuccessAt: new Date(),
              status: "healthy",
              totalQueries: sql`${osintSources.totalQueries} + 1`,
              successfulQueries: sql`${osintSources.successfulQueries} + 1`,
              updatedAt: new Date(),
            })
            .where(eq(osintSources.id, sourceId));
        }

        res.status(201).json(query);
      } catch (error) {
        log.error("Failed to run OSINT query", { error });
        res.status(500).json({ message: "Failed to run OSINT query" });
      }
    },
  );

  // GET /api/osint/queries — list past queries
  app.get(
    "/api/osint/queries",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const limit = Math.min(parseInt(String(req.query.limit || "50"), 10), 200);
        const offset = parseInt(String(req.query.offset || "0"), 10);

        const queries = await db
          .select()
          .from(osintQueries)
          .where(eq(osintQueries.orgId, orgId))
          .orderBy(desc(osintQueries.createdAt))
          .limit(limit)
          .offset(offset);

        res.json(queries);
      } catch (error) {
        log.error("Failed to fetch OSINT queries", { error });
        res.status(500).json({ message: "Failed to fetch OSINT queries" });
      }
    },
  );

  // GET /api/osint/queries/:id — get a specific query with full results + visualization data
  app.get(
    "/api/osint/queries/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [query] = await db
          .select()
          .from(osintQueries)
          .where(and(eq(osintQueries.id, id), eq(osintQueries.orgId, orgId)))
          .limit(1);
        if (!query) return res.status(404).json({ message: "Query not found" });
        res.json(query);
      } catch (error) {
        log.error("Failed to fetch OSINT query", { error });
        res.status(500).json({ message: "Failed to fetch OSINT query" });
      }
    },
  );

  // ── 5.2: OSINT Alert Rules ──────────────────────────────────────────────────

  // GET /api/osint/alert-rules — list all OSINT alert rules
  app.get(
    "/api/osint/alert-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rules = await db
          .select()
          .from(osintAlertRules)
          .where(eq(osintAlertRules.orgId, orgId))
          .orderBy(desc(osintAlertRules.createdAt));
        res.json(rules);
      } catch (error) {
        log.error("Failed to fetch OSINT alert rules", { error });
        res.status(500).json({ message: "Failed to fetch OSINT alert rules" });
      }
    },
  );

  // POST /api/osint/alert-rules — create a new alert rule
  app.post(
    "/api/osint/alert-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, description, sourceProvider, ruleType, conditions, actions, schedule, enabled } = req.body;
        if (!name || !ruleType) {
          return res.status(400).json({ message: "name and ruleType are required" });
        }
        const validRuleTypes = [
          "new_service",
          "paste_mention",
          "new_vuln",
          "domain_change",
          "ip_reputation_drop",
          "cert_expiry",
          "exposed_credential",
          "new_port",
        ];
        if (!validRuleTypes.includes(ruleType)) {
          return res.status(400).json({
            message: `Invalid ruleType. Valid: ${validRuleTypes.join(", ")}`,
          });
        }
        const [rule] = await db
          .insert(osintAlertRules)
          .values({
            orgId,
            name,
            description: description || null,
            sourceProvider: sourceProvider || "all",
            ruleType,
            conditions: conditions || {},
            actions: actions || {
              createAlert: true,
              alertSeverity: "high",
            },
            schedule: schedule || "hourly",
            enabled: enabled !== false,
          })
          .returning();
        res.status(201).json(rule);
      } catch (error) {
        log.error("Failed to create OSINT alert rule", { error });
        res.status(500).json({ message: "Failed to create OSINT alert rule" });
      }
    },
  );

  // PATCH /api/osint/alert-rules/:id — update a rule
  app.patch(
    "/api/osint/alert-rules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const allowedFields = [
          "name",
          "description",
          "sourceProvider",
          "ruleType",
          "conditions",
          "actions",
          "schedule",
          "enabled",
        ];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) updates[field] = req.body[field];
        }
        if (Object.keys(updates).length === 0) {
          return res.status(400).json({ message: "No valid fields to update" });
        }
        updates.updatedAt = new Date();
        const [updated] = await db
          .update(osintAlertRules)
          .set(updates)
          .where(and(eq(osintAlertRules.id, id), eq(osintAlertRules.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ message: "Rule not found" });
        res.json(updated);
      } catch (error) {
        log.error("Failed to update OSINT alert rule", { error });
        res.status(500).json({ message: "Failed to update OSINT alert rule" });
      }
    },
  );

  // DELETE /api/osint/alert-rules/:id
  app.delete(
    "/api/osint/alert-rules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [deleted] = await db
          .delete(osintAlertRules)
          .where(and(eq(osintAlertRules.id, id), eq(osintAlertRules.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ message: "Rule not found" });
        res.json({ success: true });
      } catch (error) {
        log.error("Failed to delete OSINT alert rule", { error });
        res.status(500).json({ message: "Failed to delete OSINT alert rule" });
      }
    },
  );

  // POST /api/osint/alert-rules/:id/run — manually trigger a rule evaluation
  app.post(
    "/api/osint/alert-rules/:id/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [rule] = await db
          .select()
          .from(osintAlertRules)
          .where(and(eq(osintAlertRules.id, id), eq(osintAlertRules.orgId, orgId)))
          .limit(1);
        if (!rule) return res.status(404).json({ message: "Rule not found" });

        // Simulate rule evaluation
        const matchCount = Math.floor(Math.random() * 5);
        await db
          .update(osintAlertRules)
          .set({
            lastRunAt: new Date(),
            lastMatchCount: matchCount,
            totalMatches: sql`${osintAlertRules.totalMatches} + ${matchCount}`,
            totalRuns: sql`${osintAlertRules.totalRuns} + 1`,
            updatedAt: new Date(),
          })
          .where(eq(osintAlertRules.id, id));

        res.json({
          ruleId: id,
          matchCount,
          status: "completed",
          message: matchCount > 0 ? `Found ${matchCount} new matches` : "No new matches found",
        });
      } catch (error) {
        log.error("Failed to run OSINT alert rule", { error });
        res.status(500).json({ message: "Failed to run OSINT alert rule" });
      }
    },
  );

  // GET /api/osint/alert-matches — list alert matches
  app.get(
    "/api/osint/alert-matches",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const matches = await db
          .select()
          .from(osintAlertMatches)
          .where(eq(osintAlertMatches.orgId, orgId))
          .orderBy(desc(osintAlertMatches.createdAt))
          .limit(100);
        res.json(matches);
      } catch (error) {
        log.error("Failed to fetch OSINT alert matches", { error });
        res.status(500).json({ message: "Failed to fetch OSINT alert matches" });
      }
    },
  );

  // ── 5.4: Scheduled OSINT Scans ──────────────────────────────────────────────

  // GET /api/osint/scheduled-scans — list all scheduled scans
  app.get(
    "/api/osint/scheduled-scans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const scans = await db
          .select()
          .from(osintScheduledScans)
          .where(eq(osintScheduledScans.orgId, orgId))
          .orderBy(desc(osintScheduledScans.createdAt));
        res.json(scans);
      } catch (error) {
        log.error("Failed to fetch scheduled scans", { error });
        res.status(500).json({ message: "Failed to fetch scheduled scans" });
      }
    },
  );

  // POST /api/osint/scheduled-scans — create a new scheduled scan
  app.post(
    "/api/osint/scheduled-scans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, queryType, queryValue, sourceId, schedule, enabled } = req.body;
        if (!name || !queryType || !queryValue) {
          return res.status(400).json({ message: "name, queryType, and queryValue are required" });
        }
        const validTypes = ["ip_lookup", "domain_lookup", "hash_lookup", "search", "passive_dns", "cert_search"];
        if (!validTypes.includes(queryType)) {
          return res.status(400).json({ message: `Invalid queryType. Valid: ${validTypes.join(", ")}` });
        }
        const validSchedules = ["hourly", "daily", "weekly"];
        if (schedule && !validSchedules.includes(schedule)) {
          return res.status(400).json({ message: `Invalid schedule. Valid: ${validSchedules.join(", ")}` });
        }
        // Validate source if provided
        if (sourceId) {
          const [source] = await db
            .select()
            .from(osintSources)
            .where(and(eq(osintSources.id, sourceId), eq(osintSources.orgId, orgId)))
            .limit(1);
          if (!source) return res.status(404).json({ message: "Source not found" });
        }
        const nextRunAt = computeNextRunAt(schedule || "daily");
        const [scan] = await db
          .insert(osintScheduledScans)
          .values({
            orgId,
            sourceId: sourceId || null,
            name,
            queryType,
            queryValue,
            schedule: schedule || "daily",
            enabled: enabled !== false,
            nextRunAt,
          })
          .returning();
        res.status(201).json(scan);
      } catch (error) {
        log.error("Failed to create scheduled scan", { error });
        res.status(500).json({ message: "Failed to create scheduled scan" });
      }
    },
  );

  // PATCH /api/osint/scheduled-scans/:id — update a scheduled scan
  app.patch(
    "/api/osint/scheduled-scans/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const allowedFields = ["name", "queryType", "queryValue", "sourceId", "schedule", "enabled"];
        const updates: Record<string, unknown> = {};
        for (const field of allowedFields) {
          if (req.body[field] !== undefined) updates[field] = req.body[field];
        }
        if (Object.keys(updates).length === 0) {
          return res.status(400).json({ message: "No valid fields to update" });
        }
        // If schedule changed, recompute nextRunAt
        if (updates.schedule) {
          updates.nextRunAt = computeNextRunAt(updates.schedule as string);
        }
        updates.updatedAt = new Date();
        const [updated] = await db
          .update(osintScheduledScans)
          .set(updates)
          .where(and(eq(osintScheduledScans.id, id), eq(osintScheduledScans.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ message: "Scheduled scan not found" });
        res.json(updated);
      } catch (error) {
        log.error("Failed to update scheduled scan", { error });
        res.status(500).json({ message: "Failed to update scheduled scan" });
      }
    },
  );

  // DELETE /api/osint/scheduled-scans/:id
  app.delete(
    "/api/osint/scheduled-scans/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [deleted] = await db
          .delete(osintScheduledScans)
          .where(and(eq(osintScheduledScans.id, id), eq(osintScheduledScans.orgId, orgId)))
          .returning();
        if (!deleted) return res.status(404).json({ message: "Scheduled scan not found" });
        res.json({ success: true });
      } catch (error) {
        log.error("Failed to delete scheduled scan", { error });
        res.status(500).json({ message: "Failed to delete scheduled scan" });
      }
    },
  );

  // POST /api/osint/scheduled-scans/:id/run — manually trigger a scheduled scan
  app.post(
    "/api/osint/scheduled-scans/:id/run",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [scan] = await db
          .select()
          .from(osintScheduledScans)
          .where(and(eq(osintScheduledScans.id, id), eq(osintScheduledScans.orgId, orgId)))
          .limit(1);
        if (!scan) return res.status(404).json({ message: "Scheduled scan not found" });

        // Execute the scan
        const result = await executeScheduledScan(scan, orgId, log);
        res.json(result);
      } catch (error) {
        log.error("Failed to run scheduled scan", { error });
        res.status(500).json({ message: "Failed to run scheduled scan" });
      }
    },
  );

  // ── 5.5: Scan Snapshots & Change Detection ──────────────────────────────────

  // GET /api/osint/scheduled-scans/:id/snapshots — get scan history with change detection
  app.get(
    "/api/osint/scheduled-scans/:id/snapshots",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        // Verify scan ownership
        const [scan] = await db
          .select()
          .from(osintScheduledScans)
          .where(and(eq(osintScheduledScans.id, id), eq(osintScheduledScans.orgId, orgId)))
          .limit(1);
        if (!scan) return res.status(404).json({ message: "Scheduled scan not found" });

        const limit = Math.min(parseInt(String(req.query.limit || "20"), 10), 100);
        const snapshots = await db
          .select()
          .from(osintScanSnapshots)
          .where(and(eq(osintScanSnapshots.scheduledScanId, id), eq(osintScanSnapshots.orgId, orgId)))
          .orderBy(desc(osintScanSnapshots.createdAt))
          .limit(limit);
        res.json(snapshots);
      } catch (error) {
        log.error("Failed to fetch scan snapshots", { error });
        res.status(500).json({ message: "Failed to fetch scan snapshots" });
      }
    },
  );

  // GET /api/osint/scheduled-scans/:id/trend — get trend data for a scheduled scan
  app.get(
    "/api/osint/scheduled-scans/:id/trend",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [scan] = await db
          .select()
          .from(osintScheduledScans)
          .where(and(eq(osintScheduledScans.id, id), eq(osintScheduledScans.orgId, orgId)))
          .limit(1);
        if (!scan) return res.status(404).json({ message: "Scheduled scan not found" });

        const snapshots = await db
          .select({
            id: osintScanSnapshots.id,
            resultCount: osintScanSnapshots.resultCount,
            changeScore: osintScanSnapshots.changeScore,
            unchangedCount: osintScanSnapshots.unchangedCount,
            createdAt: osintScanSnapshots.createdAt,
          })
          .from(osintScanSnapshots)
          .where(and(eq(osintScanSnapshots.scheduledScanId, id), eq(osintScanSnapshots.orgId, orgId)))
          .orderBy(desc(osintScanSnapshots.createdAt))
          .limit(50);

        res.json({
          scanId: id,
          scanName: scan.name,
          queryType: scan.queryType,
          queryValue: scan.queryValue,
          dataPoints: snapshots.reverse(),
        });
      } catch (error) {
        log.error("Failed to fetch scan trend", { error });
        res.status(500).json({ message: "Failed to fetch scan trend" });
      }
    },
  );

  // ── 5.6: API Quota Management ───────────────────────────────────────────────

  // GET /api/osint/quota — get quota usage summary for all sources
  app.get(
    "/api/osint/quota",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const sources = await db.select().from(osintSources).where(eq(osintSources.orgId, orgId));

        // Get call counts for the last 24 hours per source
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentLogs = await db
          .select({
            sourceId: osintQuotaLogs.sourceId,
            totalCalls: sql<number>`cast(sum(${osintQuotaLogs.callCount}) as int)`,
            successCalls: sql<number>`cast(count(*) filter (where ${osintQuotaLogs.success} = true) as int)`,
            failedCalls: sql<number>`cast(count(*) filter (where ${osintQuotaLogs.success} = false) as int)`,
            avgResponseTime: sql<number>`cast(avg(${osintQuotaLogs.responseTimeMs}) as int)`,
          })
          .from(osintQuotaLogs)
          .where(and(eq(osintQuotaLogs.orgId, orgId), gte(osintQuotaLogs.createdAt, oneDayAgo)))
          .groupBy(osintQuotaLogs.sourceId);

        const logMap = new Map(recentLogs.map((l) => [l.sourceId, l]));

        const quotaSummary = sources.map((s) => {
          const usage = logMap.get(s.id);
          const quotaTotal = s.apiQuotaTotal ?? 0;
          const quotaUsed = s.apiQuotaUsed ?? 0;
          const quotaPercent = quotaTotal > 0 ? Math.round((quotaUsed / quotaTotal) * 100) : 0;
          const isWarning = quotaPercent >= 80;
          const isCritical = quotaPercent >= 95;
          return {
            sourceId: s.id,
            sourceName: s.name,
            provider: s.provider,
            enabled: s.enabled,
            quotaTotal,
            quotaUsed,
            quotaRemaining: quotaTotal > 0 ? quotaTotal - quotaUsed : -1,
            quotaPercent,
            quotaResetAt: s.apiQuotaResetAt,
            isWarning,
            isCritical,
            last24h: {
              totalCalls: usage?.totalCalls ?? 0,
              successCalls: usage?.successCalls ?? 0,
              failedCalls: usage?.failedCalls ?? 0,
              avgResponseTimeMs: usage?.avgResponseTime ?? 0,
            },
          };
        });

        const warnings = quotaSummary.filter((s) => s.isWarning);
        res.json({
          sources: quotaSummary,
          totalSources: quotaSummary.length,
          totalWarnings: warnings.length,
          totalCritical: quotaSummary.filter((s) => s.isCritical).length,
          warnings: warnings.map((w) => ({
            sourceId: w.sourceId,
            sourceName: w.sourceName,
            provider: w.provider,
            quotaPercent: w.quotaPercent,
            level: w.isCritical ? "critical" : "warning",
          })),
        });
      } catch (error) {
        log.error("Failed to fetch OSINT quota summary", { error });
        res.status(500).json({ message: "Failed to fetch OSINT quota summary" });
      }
    },
  );

  // PATCH /api/osint/sources/:id/quota — update quota limits for a source
  app.patch(
    "/api/osint/sources/:id/quota",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const { apiQuotaTotal, apiQuotaUsed, apiQuotaResetAt } = req.body;
        const updates: Record<string, unknown> = {};
        if (apiQuotaTotal !== undefined) updates.apiQuotaTotal = apiQuotaTotal;
        if (apiQuotaUsed !== undefined) updates.apiQuotaUsed = apiQuotaUsed;
        if (apiQuotaResetAt !== undefined) updates.apiQuotaResetAt = apiQuotaResetAt ? new Date(apiQuotaResetAt) : null;
        if (Object.keys(updates).length === 0) {
          return res.status(400).json({ message: "No valid fields to update" });
        }
        updates.updatedAt = new Date();
        const [updated] = await db
          .update(osintSources)
          .set(updates)
          .where(and(eq(osintSources.id, id), eq(osintSources.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ message: "Source not found" });
        res.json(updated);
      } catch (error) {
        log.error("Failed to update source quota", { error });
        res.status(500).json({ message: "Failed to update source quota" });
      }
    },
  );

  // GET /api/osint/quota/logs — get recent quota usage logs
  app.get(
    "/api/osint/quota/logs",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const sourceId = req.query.sourceId ? String(req.query.sourceId) : undefined;
        const limit = Math.min(parseInt(String(req.query.limit || "100"), 10), 500);

        const conditions = [eq(osintQuotaLogs.orgId, orgId)];
        if (sourceId) {
          conditions.push(eq(osintQuotaLogs.sourceId, sourceId));
        }

        const logs = await db
          .select()
          .from(osintQuotaLogs)
          .where(and(...conditions))
          .orderBy(desc(osintQuotaLogs.createdAt))
          .limit(limit);
        res.json(logs);
      } catch (error) {
        log.error("Failed to fetch quota logs", { error });
        res.status(500).json({ message: "Failed to fetch quota logs" });
      }
    },
  );

  // POST /api/osint/sources/:id/quota/reset — reset quota counter for a source
  app.post(
    "/api/osint/sources/:id/quota/reset",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const id = p(req.params.id);
        const [updated] = await db
          .update(osintSources)
          .set({
            apiQuotaUsed: 0,
            apiQuotaResetAt: new Date(),
            updatedAt: new Date(),
          })
          .where(and(eq(osintSources.id, id), eq(osintSources.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ message: "Source not found" });
        res.json({ success: true, quotaUsed: 0, resetAt: updated.apiQuotaResetAt });
      } catch (error) {
        log.error("Failed to reset source quota", { error });
        res.status(500).json({ message: "Failed to reset source quota" });
      }
    },
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async function simulateSourceTest(provider: string): Promise<{
  success: boolean;
  error?: string;
  quotaInfo?: Record<string, unknown>;
}> {
  // Simulate API connectivity test per provider
  await new Promise((resolve) => setTimeout(resolve, 200 + Math.random() * 500));
  const providerInfo: Record<string, { quotaTotal: number; quotaUsed: number }> = {
    shodan: { quotaTotal: 100, quotaUsed: Math.floor(Math.random() * 60) },
    censys: {
      quotaTotal: 250,
      quotaUsed: Math.floor(Math.random() * 120),
    },
    virustotal: {
      quotaTotal: 500,
      quotaUsed: Math.floor(Math.random() * 250),
    },
    greynoise: {
      quotaTotal: 50,
      quotaUsed: Math.floor(Math.random() * 30),
    },
    urlscan: {
      quotaTotal: 1000,
      quotaUsed: Math.floor(Math.random() * 500),
    },
    pastes: { quotaTotal: -1, quotaUsed: 0 },
    abuseipdb: {
      quotaTotal: 1000,
      quotaUsed: Math.floor(Math.random() * 400),
    },
    spamhaus: { quotaTotal: -1, quotaUsed: 0 },
    otx: {
      quotaTotal: 10000,
      quotaUsed: Math.floor(Math.random() * 3000),
    },
  };
  const info = providerInfo[provider] || { quotaTotal: 100, quotaUsed: 0 };
  return {
    success: true,
    quotaInfo: {
      total: info.quotaTotal,
      used: info.quotaUsed,
      remaining: info.quotaTotal > 0 ? info.quotaTotal - info.quotaUsed : -1,
      resetAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    },
  };
}

interface OsintResult {
  results: Record<string, unknown>[];
  geoData: Record<string, unknown>[];
  domainGraph: Record<string, unknown>;
  timeline: Record<string, unknown>[];
}

// ── 5.4 helper: compute the next run timestamp from a schedule string ───────
function computeNextRunAt(schedule: string): Date {
  const now = Date.now();
  switch (schedule) {
    case "hourly":
      return new Date(now + 60 * 60 * 1000);
    case "daily":
      return new Date(now + 24 * 60 * 60 * 1000);
    case "weekly":
      return new Date(now + 7 * 24 * 60 * 60 * 1000);
    default:
      return new Date(now + 24 * 60 * 60 * 1000);
  }
}

function scheduleToMs(schedule: string): number {
  const map: Record<string, number> = {
    hourly: 60 * 60 * 1000,
    daily: 24 * 60 * 60 * 1000,
    weekly: 7 * 24 * 60 * 60 * 1000,
  };
  return map[schedule] || 24 * 60 * 60 * 1000;
}

// ── 5.5 helper: compute result hash for change detection ────────────────────
function computeResultHash(results: unknown[]): string {
  const sorted = JSON.stringify((results || []).map((r) => JSON.stringify(r)).sort());
  return createHash("sha256").update(sorted).digest("hex");
}

// ── 5.5 helper: diff two result sets and return new/resolved findings ───────
function diffResults(
  currentResults: Record<string, unknown>[],
  previousResults: Record<string, unknown>[],
): { newFindings: Record<string, unknown>[]; resolvedFindings: Record<string, unknown>[]; unchangedCount: number } {
  const prevKeys = new Set(previousResults.map((r) => JSON.stringify(r)));
  const currKeys = new Set(currentResults.map((r) => JSON.stringify(r)));

  const newFindings: Record<string, unknown>[] = [];
  const resolvedFindings: Record<string, unknown>[] = [];
  let unchangedCount = 0;

  for (const r of currentResults) {
    const key = JSON.stringify(r);
    if (prevKeys.has(key)) {
      unchangedCount++;
    } else {
      newFindings.push(r);
    }
  }

  for (const r of previousResults) {
    const key = JSON.stringify(r);
    if (!currKeys.has(key)) {
      resolvedFindings.push(r);
    }
  }

  return { newFindings, resolvedFindings, unchangedCount };
}

// ── 5.4+5.5+5.6: Execute a scheduled scan with change detection & quota tracking
interface ScheduledScanRecord {
  id: string;
  orgId: string | null;
  sourceId: string | null;
  name: string;
  queryType: string;
  queryValue: string;
  schedule: string;
  totalRuns: number;
  totalChangesDetected: number;
}

async function executeScheduledScan(
  scan: ScheduledScanRecord,
  orgId: string,
  log: ReturnType<typeof logger.child>,
): Promise<Record<string, unknown>> {
  const startTime = Date.now();

  // 5.6: Check quota before running
  if (scan.sourceId) {
    const [source] = await db
      .select()
      .from(osintSources)
      .where(and(eq(osintSources.id, scan.sourceId), eq(osintSources.orgId, orgId)))
      .limit(1);
    if (source && source.apiQuotaTotal && source.apiQuotaTotal > 0) {
      const used = source.apiQuotaUsed ?? 0;
      const pct = used / source.apiQuotaTotal;
      if (pct >= 0.95) {
        return {
          success: false,
          error: "API quota exhausted for this source (≥95%). Reset quota or wait for renewal.",
          quotaStatus: { used, total: source.apiQuotaTotal, percent: Math.round(pct * 100) },
        };
      }
    }
  }

  // Generate query results (simulated, same as manual queries)
  const queryResult = generateOsintQueryResult(scan.queryType, scan.queryValue);
  const durationMs = Date.now() - startTime;

  // Store as osintQuery
  const [query] = await db
    .insert(osintQueries)
    .values({
      orgId,
      sourceId: scan.sourceId || null,
      queryType: scan.queryType,
      queryValue: scan.queryValue,
      status: "completed",
      resultCount: queryResult.results.length,
      results: queryResult.results,
      geoData: queryResult.geoData,
      domainGraph: queryResult.domainGraph,
      timeline: queryResult.timeline,
      durationMs,
      completedAt: new Date(),
    })
    .returning();

  // 5.5: Change detection — compare with the most recent previous snapshot
  const currentHash = computeResultHash(queryResult.results);
  const [previousSnapshot] = await db
    .select()
    .from(osintScanSnapshots)
    .where(and(eq(osintScanSnapshots.scheduledScanId, scan.id), eq(osintScanSnapshots.orgId, orgId)))
    .orderBy(desc(osintScanSnapshots.createdAt))
    .limit(1);

  let newFindings: Record<string, unknown>[] = [];
  let resolvedFindings: Record<string, unknown>[] = [];
  let unchangedCount = queryResult.results.length;
  let changeScore = 0;

  if (previousSnapshot) {
    const prevResults = (previousSnapshot.results as Record<string, unknown>[]) || [];
    const diff = diffResults(queryResult.results, prevResults);
    newFindings = diff.newFindings;
    resolvedFindings = diff.resolvedFindings;
    unchangedCount = diff.unchangedCount;

    // Calculate change score: 0-100
    const totalItems = Math.max(queryResult.results.length, prevResults.length, 1);
    changeScore = Math.min(100, Math.round(((newFindings.length + resolvedFindings.length) / totalItems) * 100));
  }

  // Store snapshot
  const [snapshot] = await db
    .insert(osintScanSnapshots)
    .values({
      orgId,
      scheduledScanId: scan.id,
      queryId: query.id,
      resultHash: currentHash,
      resultCount: queryResult.results.length,
      results: queryResult.results,
      newFindings,
      resolvedFindings,
      unchangedCount,
      changeScore,
    })
    .returning();

  // 5.6: Increment quota usage and log the API call
  if (scan.sourceId) {
    await db
      .update(osintSources)
      .set({
        apiQuotaUsed: sql`COALESCE(${osintSources.apiQuotaUsed}, 0) + 1`,
        updatedAt: new Date(),
      })
      .where(and(eq(osintSources.id, scan.sourceId), eq(osintSources.orgId, orgId)));

    await db.insert(osintQuotaLogs).values({
      orgId,
      sourceId: scan.sourceId,
      callCount: 1,
      endpoint: `scheduled_scan:${scan.queryType}`,
      responseTimeMs: durationMs,
      success: true,
    });
  }

  // Update the scheduled scan metadata
  const changesDetected = newFindings.length + resolvedFindings.length;
  await db
    .update(osintScheduledScans)
    .set({
      lastRunAt: new Date(),
      nextRunAt: computeNextRunAt(scan.schedule),
      lastRunStatus: "completed",
      lastRunResultCount: queryResult.results.length,
      totalRuns: sql`${osintScheduledScans.totalRuns} + 1`,
      totalChangesDetected: sql`${osintScheduledScans.totalChangesDetected} + ${changesDetected}`,
      updatedAt: new Date(),
    })
    .where(eq(osintScheduledScans.id, scan.id));

  log.info(`Scheduled scan "${scan.name}" completed`, {
    scanId: scan.id,
    queryId: query.id,
    resultCount: queryResult.results.length,
    newFindings: newFindings.length,
    resolvedFindings: resolvedFindings.length,
    changeScore,
    durationMs,
  });

  return {
    success: true,
    queryId: query.id,
    snapshotId: snapshot.id,
    resultCount: queryResult.results.length,
    newFindings: newFindings.length,
    resolvedFindings: resolvedFindings.length,
    unchangedCount,
    changeScore,
    durationMs,
    hashChanged: previousSnapshot ? previousSnapshot.resultHash !== currentHash : true,
  };
}

// Export for use by osint-scan-scheduler
export { executeScheduledScan, computeNextRunAt, scheduleToMs };

function generateOsintQueryResult(queryType: string, queryValue: string): OsintResult {
  const now = Date.now();

  switch (queryType) {
    case "ip_lookup":
      return {
        results: [
          {
            ip: queryValue,
            country: "US",
            city: "San Francisco",
            asn: "AS13335",
            org: "Cloudflare Inc",
            ports: [80, 443, 8080],
            vulns: ["CVE-2024-1234"],
            lastSeen: new Date(now - 3600000).toISOString(),
          },
          {
            ip: queryValue.replace(/\d+$/, "2"),
            country: "DE",
            city: "Frankfurt",
            asn: "AS24940",
            org: "Hetzner",
            ports: [22, 80, 443],
            vulns: [],
            lastSeen: new Date(now - 86400000).toISOString(),
          },
        ],
        geoData: [
          {
            ip: queryValue,
            lat: 37.7749,
            lng: -122.4194,
            country: "US",
            city: "San Francisco",
            asn: "AS13335",
          },
          {
            ip: queryValue.replace(/\d+$/, "2"),
            lat: 50.1109,
            lng: 8.6821,
            country: "DE",
            city: "Frankfurt",
            asn: "AS24940",
          },
        ],
        domainGraph: { nodes: [], edges: [] },
        timeline: [
          {
            timestamp: new Date(now - 86400000 * 7).toISOString(),
            event: "First seen",
            source: "Shodan",
            value: queryValue,
          },
          {
            timestamp: new Date(now - 86400000 * 3).toISOString(),
            event: "Port 8080 opened",
            source: "Censys",
            value: queryValue,
          },
          {
            timestamp: new Date(now - 3600000).toISOString(),
            event: "Last scan",
            source: "Shodan",
            value: queryValue,
          },
        ],
      };

    case "domain_lookup":
      return {
        results: [
          {
            domain: queryValue,
            registrar: "Cloudflare Inc",
            createdDate: "2020-01-15",
            expiresDate: "2026-01-15",
            nameservers: ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            dnsRecords: [
              { type: "A", value: "104.26.10.5" },
              { type: "AAAA", value: "2606:4700:20::681a:a05" },
              { type: "MX", value: "mx1.example.com" },
            ],
            subdomains: ["api." + queryValue, "mail." + queryValue, "cdn." + queryValue],
            certificates: [
              {
                issuer: "Let's Encrypt",
                validFrom: "2025-06-01",
                validTo: "2025-09-01",
              },
            ],
          },
        ],
        geoData: [
          {
            ip: "104.26.10.5",
            lat: 37.7749,
            lng: -122.4194,
            country: "US",
            city: "San Francisco",
            asn: "AS13335",
          },
        ],
        domainGraph: {
          nodes: [
            { id: queryValue, label: queryValue, type: "domain" },
            {
              id: "api." + queryValue,
              label: "api." + queryValue,
              type: "subdomain",
            },
            {
              id: "mail." + queryValue,
              label: "mail." + queryValue,
              type: "subdomain",
            },
            {
              id: "cdn." + queryValue,
              label: "cdn." + queryValue,
              type: "subdomain",
            },
            { id: "104.26.10.5", label: "104.26.10.5", type: "ip" },
            {
              id: "ns1.cloudflare.com",
              label: "ns1.cloudflare.com",
              type: "nameserver",
            },
            {
              id: "mx1.example.com",
              label: "mx1.example.com",
              type: "mailserver",
            },
          ],
          edges: [
            {
              source: queryValue,
              target: "api." + queryValue,
              label: "subdomain",
            },
            {
              source: queryValue,
              target: "mail." + queryValue,
              label: "subdomain",
            },
            {
              source: queryValue,
              target: "cdn." + queryValue,
              label: "subdomain",
            },
            {
              source: queryValue,
              target: "104.26.10.5",
              label: "A record",
            },
            {
              source: queryValue,
              target: "ns1.cloudflare.com",
              label: "NS",
            },
            {
              source: queryValue,
              target: "mx1.example.com",
              label: "MX",
            },
          ],
        },
        timeline: [
          {
            timestamp: "2020-01-15T00:00:00Z",
            event: "Domain registered",
            source: "WHOIS",
            value: queryValue,
          },
          {
            timestamp: new Date(now - 86400000 * 30).toISOString(),
            event: "SSL certificate renewed",
            source: "Certificate Transparency",
            value: queryValue,
          },
          {
            timestamp: new Date(now - 86400000 * 5).toISOString(),
            event: "New subdomain discovered",
            source: "Censys",
            value: "cdn." + queryValue,
          },
          {
            timestamp: new Date(now - 3600000).toISOString(),
            event: "DNS record updated",
            source: "PassiveDNS",
            value: queryValue,
          },
        ],
      };

    case "hash_lookup":
      return {
        results: [
          {
            hash: queryValue,
            type: queryValue.length === 32 ? "MD5" : queryValue.length === 40 ? "SHA1" : "SHA256",
            detections: Math.floor(Math.random() * 30) + 5,
            totalEngines: 72,
            malwareFamily: "Emotet",
            firstSeen: new Date(now - 86400000 * 90).toISOString(),
            lastSeen: new Date(now - 86400000 * 2).toISOString(),
            tags: ["trojan", "banking", "emotet"],
            names: ["emotet.exe", "invoice_2024.doc"],
          },
        ],
        geoData: [],
        domainGraph: {
          nodes: [
            {
              id: queryValue.slice(0, 12),
              label: queryValue.slice(0, 12) + "...",
              type: "hash",
            },
            { id: "emotet", label: "Emotet", type: "malware" },
            { id: "c2-1", label: "185.45.12.3", type: "c2" },
            { id: "c2-2", label: "91.234.56.78", type: "c2" },
          ],
          edges: [
            {
              source: queryValue.slice(0, 12),
              target: "emotet",
              label: "family",
            },
            {
              source: queryValue.slice(0, 12),
              target: "c2-1",
              label: "contacts",
            },
            {
              source: queryValue.slice(0, 12),
              target: "c2-2",
              label: "contacts",
            },
          ],
        },
        timeline: [
          {
            timestamp: new Date(now - 86400000 * 90).toISOString(),
            event: "First submission",
            source: "VirusTotal",
            value: queryValue.slice(0, 16),
          },
          {
            timestamp: new Date(now - 86400000 * 45).toISOString(),
            event: "Detections increased to 25/72",
            source: "VirusTotal",
            value: queryValue.slice(0, 16),
          },
          {
            timestamp: new Date(now - 86400000 * 2).toISOString(),
            event: "Last analysis",
            source: "VirusTotal",
            value: queryValue.slice(0, 16),
          },
        ],
      };

    default:
      return {
        results: [
          {
            query: queryValue,
            type: queryType,
            message: "Search completed",
            resultCount: 0,
          },
        ],
        geoData: [],
        domainGraph: { nodes: [], edges: [] },
        timeline: [
          {
            timestamp: new Date().toISOString(),
            event: "Query executed",
            source: "OSINT",
            value: queryValue,
          },
        ],
      };
  }
}
