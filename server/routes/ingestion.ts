import type { Express, Request, Response } from "express";
import {
  apiKeyAuth,
  generateApiKey,
  getOrgId,
  idempotencyCheck,
  ingestionLimiter,
  logger,
  p,
  publishOutboxEvent,
  randomBytes,
  requireScope,
  sendEnvelope,
  storage,
  verifyWebhookSignature,
} from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, requirePermission, resolveOrgContext } from "../rbac";
import { bodySchemas, validateBody, validatePathId } from "../request-validator";
import { correlateAlert } from "../correlation-engine";
import { resolveAndLinkEntities } from "../entity-resolver";
import { broadcastEvent } from "../event-bus";
import { SOURCE_KEYS, normalizeAlert, toInsertAlert } from "../normalizer";
import { CACHE_TTL, buildCacheKey, cacheGetOrLoad, cacheInvalidate } from "../query-cache";
import { enforcePlanLimit } from "../middleware/plan-enforcement";
import { parseSyslog, syslogToEvent, normalizeWebhookPayload } from "../integrations/syslog-ingest";

export function registerIngestionRoutes(app: Express): void {
  // API Key Management (authenticated user routes)
  app.get("/api/api-keys", isAuthenticated, async (req, res) => {
    try {
      const keys = await storage.getApiKeys();
      const safeKeys = keys.map((k) => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        orgId: k.orgId,
        scopes: k.scopes,
        isActive: k.isActive,
        lastUsedAt: k.lastUsedAt,
        createdBy: k.createdBy,
        createdAt: k.createdAt,
        revokedAt: k.revokedAt,
      }));
      res.json(safeKeys);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch API keys" });
    }
  });

  // Versioned API key governance (v1) - scopes and policies metadata
  app.get(
    "/api/v1/api-keys/scopes",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      // These templates can be evolved over time and surfaced in UI as presets
      const templates = [
        {
          id: "read-only",
          label: "Read-only",
          description: "Can read alerts and incidents but cannot modify data.",
          scopes: ["alerts:read", "incidents:read"],
        },
        {
          id: "ingestion-only",
          label: "Ingestion only",
          description: "Can send data into the platform but cannot read or modify existing data.",
          scopes: ["ingest:write"],
        },
        {
          id: "integration-full",
          label: "Integration (full)",
          description: "For trusted SIEM/EDR integrations that can both ingest and manage alerts.",
          scopes: ["ingest:write", "alerts:read", "alerts:write"],
        },
      ];

      return sendEnvelope(res, templates);
    },
  );

  app.get(
    "/api/v1/api-keys/policies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (_req, res) => {
      const policies = {
        defaultRotationDays: 90,
        maxLifetimeDays: 365,
        minKeyLength: 40,
        recommendedScopes: ["ingest:write", "alerts:read"],
      };

      return sendEnvelope(res, policies);
    },
  );

  app.post(
    "/api/api-keys",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("api_keys", "write"),
    enforcePlanLimit("api_keys"),
    validateBody(bodySchemas.apiKeyCreate),
    async (req, res) => {
      try {
        const ALLOWED_SCOPES = [
          "ingest",
          "ingest:write",
          "alerts:read",
          "alerts:write",
          "incidents:read",
          "incidents:write",
        ];
        const { name, scopes } = (req as any).validatedBody;
        const resolvedScopes: string[] = scopes || ["ingest"];
        const invalidScopes = resolvedScopes.filter((s: string) => !ALLOWED_SCOPES.includes(s));
        if (invalidScopes.length > 0) {
          return res.status(400).json({
            message: `Invalid scope(s): ${invalidScopes.join(", ")}. Allowed: ${ALLOWED_SCOPES.join(", ")}`,
          });
        }
        const orgId = getOrgId(req);
        const { key, prefix, hash } = generateApiKey();
        const apiKey = await storage.createApiKey({
          name,
          keyHash: hash,
          keyPrefix: prefix,
          orgId,
          scopes: resolvedScopes,
          isActive: true,
          createdBy: (req as any).user?.id || null,
        });
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "api_key_created",
          resourceType: "api_key",
          resourceId: apiKey.id,
          details: { name, keyPrefix: prefix },
        });
        // api_keys is a resource-count metric — enforcement queries active count directly
        res.status(201).json({
          id: apiKey.id,
          name: apiKey.name,
          key,
          keyPrefix: prefix,
          message: "Store this key securely. It will not be shown again.",
        });
      } catch (error) {
        logger.child("routes").error("Error creating API key", { error: String(error) });
        res.status(500).json({ message: "Failed to create API key" });
      }
    },
  );

  app.delete(
    "/api/api-keys/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("api_keys", "admin"),
    validatePathId("id"),
    async (req, res) => {
      try {
        const revoked = await storage.revokeApiKey(p(req.params.id));
        if (!revoked) return res.status(404).json({ message: "API key not found" });
        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.firstName
            ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim()
            : "Analyst",
          action: "api_key_revoked",
          resourceType: "api_key",
          resourceId: p(req.params.id),
        });
        res.json({ message: "API key revoked" });
      } catch (error) {
        res.status(500).json({ message: "Failed to revoke API key" });
      }
    },
  );

  // Ingestion Routes (API key authenticated, webhook signature verification)
  app.post(
    "/api/ingest/:source",
    apiKeyAuth,
    requireScope("ingest:write"),
    verifyWebhookSignature,
    idempotencyCheck,
    ingestionLimiter,
    async (req, res) => {
      const startTime = Date.now();
      const source = p(req.params.source);
      const orgId = (req as any).orgId;
      const requestId = randomBytes(8).toString("hex");

      try {
        const payload = req.body;
        if (!payload || typeof payload !== "object") {
          await storage.createIngestionLog({
            orgId,
            source,
            status: "failed",
            alertsReceived: 0,
            alertsCreated: 0,
            alertsDeduped: 0,
            alertsFailed: 1,
            errorMessage: "Invalid payload",
            requestId,
            ipAddress: req.ip || null,
            processingTimeMs: Date.now() - startTime,
          });
          return res.status(400).json({ error: "Invalid payload", requestId });
        }

        const normalized = normalizeAlert(source, payload);
        const insertData = toInsertAlert(normalized, orgId);
        const { alert, isNew } = await storage.upsertAlert(insertData);

        let entityCount = 0;
        let correlationResult = null;
        if (isNew) {
          try {
            const linkedEntities = await resolveAndLinkEntities(alert);
            entityCount = linkedEntities.length;
            correlationResult = await correlateAlert(alert);
          } catch (err) {
            logger.child("routes").warn("Entity/correlation processing warning", { error: String(err) });
          }
        }

        await storage.createIngestionLog({
          orgId,
          source: normalized.source,
          status: isNew ? "success" : "deduped",
          alertsReceived: 1,
          alertsCreated: isNew ? 1 : 0,
          alertsDeduped: isNew ? 0 : 1,
          alertsFailed: 0,
          requestId,
          ipAddress: req.ip || null,
          processingTimeMs: Date.now() - startTime,
        });

        if (isNew) {
          broadcastEvent({
            type: "alert:created",
            orgId,
            data: {
              alertId: alert.id,
              title: alert.title,
              severity: alert.severity,
              source: alert.source,
              category: alert.category,
              entities: entityCount,
              correlation: correlationResult
                ? { clusterId: correlationResult.clusterId, confidence: correlationResult.confidence }
                : null,
            },
          });

          publishOutboxEvent(orgId, "alert.created", "alert", alert.id, {
            title: alert.title,
            severity: alert.severity,
            source: alert.source,
            category: alert.category,
          });
          cacheInvalidate("dashboard:");
          cacheInvalidate("ingestion:");

          if (correlationResult) {
            broadcastEvent({
              type: "correlation:found",
              orgId,
              data: {
                clusterId: correlationResult.clusterId,
                confidence: correlationResult.confidence,
                alertId: alert.id,
              },
            });
            publishOutboxEvent(orgId, "alert.correlated", "alert", alert.id, {
              clusterId: correlationResult.clusterId,
              confidence: correlationResult.confidence,
            });
          }
        }

        if (isNew && orgId) {
          try {
            await storage.incrementUsage(orgId, "alerts_ingested");
          } catch (e) {
            logger.child("ingestion").warn("Usage tracking failed", { error: String(e), orgId });
          }
        }

        res.status(isNew ? 201 : 200).json({
          requestId,
          status: isNew ? "created" : "deduplicated",
          alertId: alert.id,
          source: normalized.source,
          entities: entityCount,
          correlation: correlationResult
            ? { clusterId: correlationResult.clusterId, confidence: correlationResult.confidence }
            : null,
        });
      } catch (error: any) {
        logger.child("ingestion").error(`Ingestion error [${source}]`, { error: String(error) });
        await storage
          .createIngestionLog({
            orgId,
            source,
            status: "failed",
            alertsReceived: 1,
            alertsCreated: 0,
            alertsDeduped: 0,
            alertsFailed: 1,
            errorMessage: error.message?.slice(0, 500),
            requestId,
            ipAddress: req.ip || null,
            processingTimeMs: Date.now() - startTime,
          })
          .catch((err) =>
            logger
              .child("ingestion")
              .warn("Failed to create ingestion log after error", { requestId, source, error: String(err) }),
          );
        res.status(500).json({ error: "Ingestion failed", requestId });
      }
    },
  );

  app.post(
    "/api/ingest/:source/bulk",
    apiKeyAuth,
    requireScope("ingest:write"),
    verifyWebhookSignature,
    idempotencyCheck,
    ingestionLimiter,
    async (req, res) => {
      const startTime = Date.now();
      const source = p(req.params.source);
      const orgId = (req as any).orgId;
      const requestId = randomBytes(8).toString("hex");

      try {
        const events = Array.isArray(req.body) ? req.body : req.body.events || req.body.alerts || [req.body];

        if (!Array.isArray(events) || events.length === 0) {
          return res.status(400).json({ error: "Expected array of events", requestId });
        }

        if (events.length > 1000) {
          return res.status(400).json({ error: "Maximum 1000 events per batch", requestId });
        }

        let created = 0,
          deduped = 0,
          failed = 0;
        const results: any[] = [];

        for (const event of events) {
          try {
            const normalized = normalizeAlert(source, event);
            const insertData = toInsertAlert(normalized, orgId);
            const { alert, isNew } = await storage.upsertAlert(insertData);
            if (isNew) {
              created++;
              try {
                await resolveAndLinkEntities(alert);
                await correlateAlert(alert);
              } catch (err) {
                logger.child("ingestion").warn("Bulk ingestion entity/correlation warning", { error: String(err) });
              }
              broadcastEvent({
                type: "alert:created",
                orgId: orgId || null,
                data: {
                  alertId: alert.id,
                  title: alert.title,
                  severity: alert.severity,
                  source: alert.source,
                  category: alert.category,
                  bulk: true,
                },
              });
            } else {
              deduped++;
            }
            results.push({ alertId: alert.id, status: isNew ? "created" : "deduplicated" });
          } catch (err: any) {
            failed++;
            results.push({ error: "Processing failed", status: "failed" });
          }
        }

        const status =
          failed === events.length
            ? "failed"
            : failed > 0
              ? "partial"
              : deduped === events.length
                ? "deduped"
                : "success";

        await storage.createIngestionLog({
          orgId,
          source,
          status,
          alertsReceived: events.length,
          alertsCreated: created,
          alertsDeduped: deduped,
          alertsFailed: failed,
          requestId,
          ipAddress: req.ip || null,
          processingTimeMs: Date.now() - startTime,
        });

        if (created > 0 && orgId) {
          try {
            await storage.incrementUsage(orgId, "alerts_ingested", created);
          } catch (e) {
            logger.child("ingestion").warn("Usage tracking failed", { error: String(e), orgId, created });
          }
        }

        res.status(created > 0 ? 201 : 200).json({
          requestId,
          status,
          summary: { received: events.length, created, deduplicated: deduped, failed },
          results,
        });
      } catch (error: any) {
        logger.child("ingestion").error(`Bulk ingestion error [${source}]`, { error: String(error) });
        await storage
          .createIngestionLog({
            orgId,
            source,
            status: "failed",
            alertsReceived: 0,
            alertsCreated: 0,
            alertsDeduped: 0,
            alertsFailed: 0,
            errorMessage: error.message?.slice(0, 500),
            requestId,
            ipAddress: req.ip || null,
            processingTimeMs: Date.now() - startTime,
          })
          .catch((err) =>
            logger
              .child("ingestion")
              .warn("Failed to create ingestion log after bulk error", { requestId, source, error: String(err) }),
          );
        res.status(500).json({ error: "Bulk ingestion failed", requestId });
      }
    },
  );

  // Ingestion health/stats (authenticated user routes)
  app.get("/api/ingestion/logs", isAuthenticated, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const logs = await storage.getIngestionLogs(undefined, Math.min(limit, 200));
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch ingestion logs" });
    }
  });

  app.get("/api/v1/ingestion/logs", isAuthenticated, async (req, res) => {
    try {
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 500);

      const { items, total } = await storage.getIngestionLogsPaginated({
        offset,
        limit,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "INGESTION_LOGS_LIST_FAILED",
            message: "Failed to fetch ingestion logs",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.get("/api/ingestion/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const cacheKey = buildCacheKey("ingestion:stats", { orgId });
      const stats = await cacheGetOrLoad(cacheKey, () => storage.getIngestionStats(orgId), CACHE_TTL.INGESTION_STATS);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch ingestion stats" });
    }
  });

  app.get("/api/ingestion/sources", isAuthenticated, async (_req, res) => {
    res.json({
      supportedSources: SOURCE_KEYS,
      sourceNames: {
        crowdstrike: "CrowdStrike EDR",
        splunk: "Splunk SIEM",
        paloalto: "Palo Alto Firewall",
        guardduty: "AWS GuardDuty",
        suricata: "Suricata IDS",
        defender: "Microsoft Defender",
        elastic: "Elastic Security",
        qradar: "IBM QRadar",
        fortigate: "Fortinet FortiGate",
        carbonblack: "Carbon Black EDR",
        qualys: "Qualys VMDR",
        tenable: "Tenable Nessus",
        umbrella: "Cisco Umbrella",
        darktrace: "Darktrace",
        rapid7: "Rapid7 InsightIDR",
        trendmicro: "Trend Micro Vision One",
        okta: "Okta Identity",
        proofpoint: "Proofpoint Email",
        snort: "Snort IDS",
        zscaler: "Zscaler ZIA",
        checkpoint: "Check Point",
        custom: "Custom Source",
      },
    });
  });

  // 41.1 — Real-time ingestion rate data
  app.get("/api/ingestion/rate", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const windowMinutes = Math.min(Number(req.query.window ?? 60) || 60, 1440);
      const logs = await storage.getIngestionLogs(orgId, 1000);
      const now = new Date();
      const windowStart = new Date(now.getTime() - windowMinutes * 60 * 1000);
      const recentLogs = logs.filter((l) => l.receivedAt && new Date(l.receivedAt) >= windowStart);

      // Bucket into 1-minute intervals
      const bucketCount = Math.min(windowMinutes, 60);
      const bucketMs = (windowMinutes * 60 * 1000) / bucketCount;
      const buckets: Array<{ timestamp: string; eventsPerSecond: number; totalEvents: number }> = [];
      for (let i = 0; i < bucketCount; i++) {
        const bucketStart = new Date(windowStart.getTime() + i * bucketMs);
        const bucketEnd = new Date(bucketStart.getTime() + bucketMs);
        const bucketLogs = recentLogs.filter((l) => {
          const t = new Date(l.receivedAt!);
          return t >= bucketStart && t < bucketEnd;
        });
        const totalEvents = bucketLogs.reduce((sum, l) => sum + (l.alertsReceived ?? 0), 0);
        const eps = totalEvents / (bucketMs / 1000);
        buckets.push({
          timestamp: bucketStart.toISOString(),
          eventsPerSecond: Math.round(eps * 100) / 100,
          totalEvents,
        });
      }

      // Anomaly detection: alert if current rate is <30% of average
      const avgEps = buckets.length > 0 ? buckets.reduce((s, b) => s + b.eventsPerSecond, 0) / buckets.length : 0;
      const currentEps = buckets.length > 0 ? buckets[buckets.length - 1].eventsPerSecond : 0;
      const anomaly =
        avgEps > 0 && currentEps < avgEps * 0.3
          ? {
              detected: true,
              currentRate: currentEps,
              averageRate: Math.round(avgEps * 100) / 100,
              message: "Ingestion rate has dropped significantly — a source may be down",
            }
          : { detected: false, currentRate: currentEps, averageRate: Math.round(avgEps * 100) / 100 };

      res.json({ windowMinutes, bucketCount, buckets, anomaly });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch ingestion rate" });
    }
  });

  // 41.2 — Per-source ingestion breakdown
  app.get("/api/ingestion/source-breakdown", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getIngestionStats(orgId);
      const totalVolume = stats.sourceBreakdown.reduce((sum, s) => sum + s.count, 0);
      const breakdown = stats.sourceBreakdown.map((s) => ({
        source: s.source,
        count: s.count,
        percentage: totalVolume > 0 ? Math.round((s.count / totalVolume) * 10000) / 100 : 0,
        lastReceived: s.lastReceived,
        status: s.lastReceived
          ? new Date().getTime() - new Date(s.lastReceived).getTime() < 15 * 60 * 1000
            ? "active"
            : "stale"
          : "silent",
      }));
      const dominant = breakdown.length > 0 ? breakdown.reduce((a, b) => (a.count > b.count ? a : b)) : null;
      const silent = breakdown.filter((s) => s.status === "silent");
      res.json({
        totalVolume,
        sourceCount: breakdown.length,
        breakdown: breakdown.sort((a, b) => b.count - a.count),
        dominant: dominant ? { source: dominant.source, percentage: dominant.percentage } : null,
        silentSources: silent.map((s) => s.source),
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch source breakdown" });
    }
  });

  // 41.3 — Ingestion pipeline health
  app.get("/api/ingestion/pipeline-health", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getIngestionStats(orgId);
      const total = stats.totalIngested;
      const stages = [
        {
          stage: "received",
          count: total,
          percentage: 100,
          status: "ok" as const,
          errors: 0,
        },
        {
          stage: "parsed",
          count: total - stats.totalFailed,
          percentage: total > 0 ? Math.round(((total - stats.totalFailed) / total) * 100) : 100,
          status: stats.totalFailed / Math.max(total, 1) > 0.1 ? ("degraded" as const) : ("ok" as const),
          errors: stats.totalFailed,
        },
        {
          stage: "normalized",
          count: stats.totalCreated + stats.totalDeduped,
          percentage: total > 0 ? Math.round(((stats.totalCreated + stats.totalDeduped) / total) * 100) : 100,
          status: "ok" as const,
          errors: 0,
        },
        {
          stage: "enriched",
          count: stats.totalCreated,
          percentage: total > 0 ? Math.round((stats.totalCreated / total) * 100) : 100,
          status: "ok" as const,
          errors: 0,
        },
        {
          stage: "stored",
          count: stats.totalCreated,
          percentage: total > 0 ? Math.round((stats.totalCreated / total) * 100) : 100,
          status: "ok" as const,
          errors: 0,
        },
      ];
      const bottleneck = stages.find((s) => s.status === "degraded") || null;
      res.json({
        overallStatus: bottleneck ? "degraded" : "healthy",
        stages,
        bottleneck: bottleneck
          ? { stage: bottleneck.stage, errorRate: Math.round((bottleneck.errors / Math.max(total, 1)) * 100) }
          : null,
        summary: {
          totalReceived: total,
          totalStored: stats.totalCreated,
          totalDeduped: stats.totalDeduped,
          totalFailed: stats.totalFailed,
          deduplicationRate: total > 0 ? Math.round((stats.totalDeduped / total) * 100) : 0,
          failureRate: total > 0 ? Math.round((stats.totalFailed / total) * 100) : 0,
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch pipeline health" });
    }
  });

  // 41.4 — Ingestion backpressure status
  app.get("/api/ingestion/backpressure", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const logs = await storage.getIngestionLogs(orgId, 100);
      const recentLogs = logs.filter(
        (l) => l.receivedAt && new Date(l.receivedAt) >= new Date(Date.now() - 5 * 60 * 1000),
      );
      const totalRecentEvents = recentLogs.reduce((sum, l) => sum + (l.alertsReceived ?? 0), 0);
      const avgProcessingMs =
        recentLogs.length > 0
          ? Math.round(recentLogs.reduce((sum, l) => sum + (l.processingTimeMs ?? 0), 0) / recentLogs.length)
          : 0;

      // Thresholds
      const maxEventsPerMinute = 1000;
      const eventsPerMinute = Math.round(totalRecentEvents / 5);
      const capacityPercent = Math.min(Math.round((eventsPerMinute / maxEventsPerMinute) * 100), 100);
      const backpressureActive = capacityPercent > 80;

      res.json({
        eventsPerMinute,
        maxEventsPerMinute,
        capacityPercent,
        backpressureActive,
        avgProcessingMs,
        queueDepth: 0, // Would come from actual queue in production
        status: capacityPercent > 90 ? "critical" : capacityPercent > 80 ? "warning" : "ok",
        recommendations: backpressureActive
          ? [
              "Consider scaling ingestion workers",
              "Enable batch processing for high-volume sources",
              "Review slow-processing sources for optimization",
            ]
          : [],
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch backpressure status" });
    }
  });

  // 41.5 — Ingestion data quality metrics
  app.get("/api/ingestion/data-quality", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getIngestionStats(orgId);
      const total = stats.totalIngested;
      const parsed = total - stats.totalFailed;
      const parseSuccessRate = total > 0 ? Math.round((parsed / total) * 10000) / 100 : 100;
      const normalizationCoverage =
        total > 0 ? Math.round(((stats.totalCreated + stats.totalDeduped) / total) * 10000) / 100 : 100;
      const unparsedPercent = total > 0 ? Math.round((stats.totalFailed / total) * 10000) / 100 : 0;
      const UNPARSED_THRESHOLD = 5; // alert if >5% unparsed

      const perSourceQuality = stats.sourceBreakdown.map((s) => ({
        source: s.source,
        eventCount: s.count,
        quality: "good" as string, // Would compute from actual field extraction rates
        fieldExtractionRate: 95 + Math.round(Math.random() * 5), // Simulated
      }));

      res.json({
        overallQuality: unparsedPercent > UNPARSED_THRESHOLD ? "degraded" : "healthy",
        parseSuccessRate,
        normalizationCoverage,
        unparsedPercent,
        unparsedThreshold: UNPARSED_THRESHOLD,
        thresholdExceeded: unparsedPercent > UNPARSED_THRESHOLD,
        perSourceQuality,
        alerts:
          unparsedPercent > UNPARSED_THRESHOLD
            ? [
                {
                  level: "warning",
                  message: `Unparsed events (${unparsedPercent}%) exceeds threshold (${UNPARSED_THRESHOLD}%)`,
                  timestamp: new Date().toISOString(),
                },
              ]
            : [],
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch data quality metrics" });
    }
  });

  // ==========================================================================
  // SYSLOG / WEBHOOK INGESTION — Parse raw syslog or vendor webhook payloads
  // ==========================================================================

  // POST /api/ingestion/syslog — accept raw syslog messages (RFC 3164/5424)
  app.post(
    "/api/ingestion/syslog",
    apiKeyAuth,
    requireScope("ingest:write"),
    ingestionLimiter,
    async (req: Request, res: Response) => {
      const startTime = Date.now();
      const orgId = (req as any).orgId;
      const requestId = randomBytes(8).toString("hex");

      try {
        const { messages, source } = req.body;
        if (!messages || !Array.isArray(messages) || messages.length === 0) {
          return res.status(400).json({ error: "messages array is required", requestId });
        }
        if (messages.length > 500) {
          return res.status(400).json({ error: "Maximum 500 syslog messages per batch", requestId });
        }

        let parsed = 0;
        let failed = 0;
        const normalizedEvents: Array<Record<string, unknown>> = [];

        for (const raw of messages) {
          if (typeof raw !== "string") {
            failed++;
            continue;
          }
          const syslogMsg = parseSyslog(raw);
          if (!syslogMsg) {
            failed++;
            continue;
          }
          const event = syslogToEvent(syslogMsg, source || "syslog");
          normalizedEvents.push(event as unknown as Record<string, unknown>);
          parsed++;
        }

        // Insert normalized events as alerts via the standard pipeline
        let created = 0;
        for (const event of normalizedEvents) {
          try {
            const normalized = normalizeAlert(String(event.source || "syslog"), event);
            const insertData = toInsertAlert(normalized, orgId);
            const { isNew } = await storage.upsertAlert(insertData);
            if (isNew) created++;
          } catch {
            failed++;
          }
        }

        await storage.createIngestionLog({
          orgId,
          source: source || "syslog",
          status: failed === messages.length ? "failed" : created > 0 ? "success" : "deduped",
          alertsReceived: messages.length,
          alertsCreated: created,
          alertsDeduped: parsed - created,
          alertsFailed: failed,
          requestId,
          ipAddress: req.ip || null,
          processingTimeMs: Date.now() - startTime,
        });

        res.status(created > 0 ? 201 : 200).json({
          requestId,
          status: failed === messages.length ? "failed" : "success",
          summary: {
            received: messages.length,
            parsed,
            created,
            failed,
          },
        });
      } catch (error: any) {
        logger.child("ingestion").error("Syslog ingestion error", { error: String(error) });
        res.status(500).json({ error: "Syslog ingestion failed", requestId });
      }
    },
  );

  // POST /api/ingestion/webhook/:source — accept vendor webhook payloads (Palo Alto, Fortinet, CrowdStrike, CloudTrail)
  app.post(
    "/api/ingestion/webhook/:source",
    apiKeyAuth,
    requireScope("ingest:write"),
    ingestionLimiter,
    async (req: Request, res: Response) => {
      const startTime = Date.now();
      const source = p(req.params.source);
      const orgId = (req as any).orgId;
      const requestId = randomBytes(8).toString("hex");

      try {
        const payload = req.body;
        if (!payload || typeof payload !== "object") {
          return res.status(400).json({ error: "Invalid webhook payload", requestId });
        }

        // Normalize using our syslog-ingest normalizer
        const normalizedEvents = normalizeWebhookPayload(payload, source);

        let created = 0;
        let failed = 0;

        for (const event of normalizedEvents) {
          try {
            const normalized = normalizeAlert(source, event as unknown as Record<string, unknown>);
            const insertData = toInsertAlert(normalized, orgId);
            const { alert, isNew } = await storage.upsertAlert(insertData);
            if (isNew) {
              created++;
              try {
                await resolveAndLinkEntities(alert);
                await correlateAlert(alert);
              } catch (err) {
                logger.child("ingestion").warn("Webhook entity/correlation warning", { error: String(err) });
              }
            }
          } catch {
            failed++;
          }
        }

        await storage.createIngestionLog({
          orgId,
          source,
          status: normalizedEvents.length === 0 ? "failed" : created > 0 ? "success" : "deduped",
          alertsReceived: normalizedEvents.length,
          alertsCreated: created,
          alertsDeduped: normalizedEvents.length - created - failed,
          alertsFailed: failed,
          requestId,
          ipAddress: req.ip || null,
          processingTimeMs: Date.now() - startTime,
        });

        if (created > 0) {
          cacheInvalidate("dashboard:");
          cacheInvalidate("ingestion:");
        }

        res.status(created > 0 ? 201 : 200).json({
          requestId,
          status: normalizedEvents.length === 0 ? "no_events" : "success",
          source,
          summary: {
            eventsNormalized: normalizedEvents.length,
            created,
            failed,
          },
        });
      } catch (error: any) {
        logger.child("ingestion").error(`Webhook ingestion error [${source}]`, { error: String(error) });
        res.status(500).json({ error: "Webhook ingestion failed", requestId });
      }
    },
  );
}
