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
        const { name, scopes } = (req as any).validatedBody;
        const orgId = getOrgId(req);
        const { key, prefix, hash } = generateApiKey();
        const apiKey = await storage.createApiKey({
          name,
          keyHash: hash,
          keyPrefix: prefix,
          orgId,
          scopes: scopes || ["ingest"],
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
          storage.incrementUsage(orgId, "alerts_ingested").catch(() => {});
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
          storage.incrementUsage(orgId, "alerts_ingested", created).catch(() => {});
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
}
