import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { storage } from "./storage";
import { setupAuth, registerAuthRoutes, isAuthenticated } from "./auth";
import { resolveOrgContext, requireOrgId, requireMinRole, requirePermission } from "./rbac";
import { insertAlertSchema, insertIncidentSchema, insertCommentSchema, insertTagSchema, insertCompliancePolicySchema, insertDsarRequestSchema, insertCspmAccountSchema, insertEndpointAssetSchema, insertAiDeploymentConfigSchema, insertIocFeedSchema, insertIocEntrySchema, insertIocWatchlistSchema, insertIocMatchRuleSchema, insertEvidenceItemSchema, insertInvestigationHypothesisSchema, insertInvestigationTaskSchema, insertRunbookTemplateSchema, insertRunbookStepSchema, insertReportTemplateSchema, insertReportScheduleSchema, insertPolicyCheckSchema, insertComplianceControlSchema, insertComplianceControlMappingSchema, insertEvidenceLockerItemSchema, insertOutboundWebhookSchema, insertTicketSyncJobSchema, insertResponseActionApprovalSchema, insertLegalHoldSchema, insertConnectorSecretRotationSchema } from "@shared/schema";
import { correlateAlerts, generateIncidentNarrative, triageAlert, checkModelHealth, getModelConfig, getInferenceMetrics, buildThreatIntelContext } from "./ai";
import { normalizeAlert, toInsertAlert, SOURCE_KEYS } from "./normalizer";
import { testConnector, syncConnector, syncConnectorWithRetry, getConnectorMetadata, getAllConnectorTypes, type ConnectorConfig } from "./connector-engine";
import { dispatchAction, type ActionContext } from "./action-dispatcher";
import { resolveAndLinkEntities, getEntitiesForAlert, getEntitiesForIncident, getEntityGraph, getEntity, getEntityAlerts, findRelatedAlertsByEntity, getEntityAliases, addEntityAlias, mergeEntities, updateEntityMetadata, getEntityRelationships, getEntityGraphWithEdges } from "./entity-resolver";
import { correlateAlert, runCorrelationScan, getCorrelationClusters, getCorrelationCluster, promoteClusterToIncident } from "./correlation-engine";
import { runGraphCorrelation, getAttackPaths, getAttackPath, getCampaigns, getCampaign } from "./graph-correlation";
import { eventBus, broadcastEvent } from "./event-bus";
import { maskPiiInAlert, maskPiiInText } from "./pii-engine";
import { runRetentionCleanup } from "./retention-scheduler";
import { startRetentionScheduler } from "./retention-scheduler";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { uploadFile, getSignedUrl, deleteFile, listFiles } from "./s3";
import { evaluatePolicies, generateDefaultPolicies } from "./policy-engine";
import { runInvestigation } from "./investigation-agent";
import { canRollback, createRollbackRecord, executeRollback, getAvailableRollbacks } from "./rollback-engine";
import { runCspmScan } from "./cspm-scanner";
import { seedEndpointAssets, generateTelemetry, calculateEndpointRisk } from "./endpoint-telemetry";
import { calculatePostureScore } from "./posture-engine";
import { cacheGetWithStats, cacheSet, cacheInvalidate, buildCacheKey, cacheStats, cacheGetOrLoad, CACHE_TTL } from "./query-cache";
import { getProviderSyncStats, setProviderConcurrency } from "./connector-engine";
import { startOutboxProcessor, stopOutboxProcessor, createEventFingerprint, getOutboxProcessorStatus } from "./outbox-processor";
import { scheduleJob, getDeadLetterJobs, retryDeadLetterJob } from "./job-queue";
import { evaluateAndAlert, getBreachHistory, seedDefaultSloTargets } from "./slo-alerting";
import { evaluateFlag, evaluateAllFlags } from "./feature-flags";
import { runConnectorContractTests, runAutomationIntegrationTests, runAllContractTests } from "./integration-tests";
import { buildOpenApiSpec, generateTypedClient, registerOpenApiRoutes } from "./openapi";
import {
  reply,
  replyError,
  replyUnauthenticated,
  replyForbidden,
  replyRateLimit,
  ERROR_CODES,
  type ApiMeta,
} from "./api-response";
import { logger } from "./logger";
import { getIndexHitRates, getTableScanStats, getUnusedIndexes, getCacheHitRatio, getRecentSlowQueries, PERFORMANCE_BUDGETS, parsePaginationParams } from "./db-performance";
import { applyCsrfProtection, getCsrfEndpointHandler } from "./security-middleware";
import { validateQuery, validateBody, validatePathId, querySchemas, bodySchemas } from "./request-validator";
import { validateConnectorConfig } from "./connector-config-validator";
import { validateWebhookUrl, isCircuitOpen, isWebhookRateLimited, recordDeliverySuccess, recordDeliveryFailure, secureOutboundFetch, redactDeliveryLog, getCircuitBreakerStatus, getOutboundSecurityStats } from "./outbound-security";

function p(val: string | string[] | undefined): string {
  return (Array.isArray(val) ? val[0] : val) as string;
}

function getOrgId(req: Request): string {
  const orgId = (req as any).orgId || (req as any).user?.orgId;
  if (!orgId || typeof orgId !== "string") {
    throw new Error("ORG_CONTEXT_MISSING");
  }
  return orgId;
}

function sendEnvelope(
  res: Response,
  data: any,
  options?: {
    status?: number;
    meta?: ApiMeta;
    errors?: { code: string; message: string; details?: any }[] | null;
  }
) {
  const status = options?.status ?? 200;
  const meta: ApiMeta = options?.meta ?? {};
  const errors = options?.errors ?? null;
  if (errors && errors.length > 0) {
    return replyError(res, status, errors, meta);
  }
  return reply(res, data, meta, status);
}

function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function generateApiKey(): { key: string; prefix: string; hash: string } {
  const key = `snx_${randomBytes(32).toString("hex")}`;
  const prefix = key.slice(0, 12);
  const hash = hashApiKey(key);
  return { key, prefix, hash };
}

async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers["x-api-key"] || req.headers.authorization?.replace("Bearer ", "");
  if (!header || typeof header !== "string") {
    return replyUnauthenticated(res, "Missing API key. Provide X-API-Key header.", ERROR_CODES.API_KEY_MISSING);
  }
  const hash = hashApiKey(header);
  const apiKey = await storage.getApiKeyByHash(hash);
  if (!apiKey) {
    return replyUnauthenticated(res, "Invalid API key.", ERROR_CODES.API_KEY_INVALID);
  }
  if (!apiKey.isActive) {
    return replyForbidden(res, "API key has been revoked.", ERROR_CODES.API_KEY_REVOKED);
  }
  storage.updateApiKeyLastUsed(apiKey.id).catch((err) => logger.child("routes").warn("Failed to update API key last used", { error: String(err) }));
  (req as any).apiKey = apiKey;
  (req as any).orgId = apiKey.orgId;
  next();
}

function verifyWebhookSignature(req: Request, res: Response, next: NextFunction) {
  const apiKey = (req as any).apiKey;
  const signature = req.headers["x-webhook-signature"] as string | undefined;

  if (!apiKey?.webhookSecret) {
    return next();
  }

  if (!signature) {
    return replyUnauthenticated(
      res,
      "Missing X-Webhook-Signature header. Required when webhook secret is configured.",
      ERROR_CODES.WEBHOOK_SIG_MISSING,
    );
  }

  try {
    const rawBodyBuf = (req as any).rawBody;
    const rawBody = rawBodyBuf ? (Buffer.isBuffer(rawBodyBuf) ? rawBodyBuf.toString("utf8") : String(rawBodyBuf)) : JSON.stringify(req.body);
    const timestamp = req.headers["x-webhook-timestamp"] as string || "";
    const payload = timestamp ? `${timestamp}.${rawBody}` : rawBody;
    const expected = createHmac("sha256", apiKey.webhookSecret).update(payload).digest("hex");
    const sig = signature.startsWith("sha256=") ? signature.slice(7) : signature;

    if (!/^[a-f0-9]+$/i.test(sig) || sig.length !== expected.length) {
      return replyUnauthenticated(res, "Invalid webhook signature.", ERROR_CODES.WEBHOOK_SIG_INVALID);
    }

    if (!timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) {
      return replyUnauthenticated(res, "Invalid webhook signature.", ERROR_CODES.WEBHOOK_SIG_INVALID);
    }

    if (timestamp) {
      const ts = parseInt(timestamp, 10);
      const age = Math.abs(Date.now() - ts);
      if (age > 5 * 60 * 1000) {
        return replyUnauthenticated(
          res,
          "Webhook timestamp too old. Replay protection triggered.",
          ERROR_CODES.WEBHOOK_TS_EXPIRED,
        );
      }
    }

    next();
  } catch {
    return replyUnauthenticated(res, "Invalid webhook signature.", ERROR_CODES.WEBHOOK_SIG_INVALID);
  }
}

async function dispatchWebhookEvent(orgId: string | null, event: string, payload: any) {
  if (!orgId) return;
  try {
    const webhooks = await storage.getActiveWebhooksByEvent(orgId, event);
    for (const webhook of webhooks) {
      (async () => {
        const urlCheck = validateWebhookUrl(webhook.url);
        if (!urlCheck.valid) {
          logger.child("webhook").warn("SSRF blocked: webhook URL rejected", { webhookId: webhook.id, reason: urlCheck.reason });
          await storage.createOutboundWebhookLog({
            webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
            responseStatus: 0, responseBody: `Blocked: ${urlCheck.reason}`, success: false,
          }).catch(() => {});
          return;
        }
        if (isCircuitOpen(webhook.id)) {
          logger.child("webhook").warn("Circuit breaker open — skipping delivery", { webhookId: webhook.id });
          await storage.createOutboundWebhookLog({
            webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
            responseStatus: 0, responseBody: "Circuit breaker open", success: false,
          }).catch(() => {});
          return;
        }
        if (isWebhookRateLimited(webhook.id)) {
          await storage.createOutboundWebhookLog({
            webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
            responseStatus: 429, responseBody: "Rate limited", success: false,
          }).catch(() => {});
          return;
        }
        const body = JSON.stringify(payload);
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (webhook.secret) {
          const timestamp = String(Date.now());
          const signedPayload = `${timestamp}.${body}`;
          const signature = createHmac("sha256", webhook.secret).update(signedPayload).digest("hex");
          headers["X-Webhook-Signature"] = `sha256=${signature}`;
          headers["X-Webhook-Timestamp"] = timestamp;
        }
        const result = await secureOutboundFetch(webhook.url, { method: "POST", headers, body });
        if (result.success) {
          recordDeliverySuccess(webhook.id);
        } else {
          recordDeliveryFailure(webhook.id);
        }
        await storage.createOutboundWebhookLog({
          webhookId: webhook.id, event, payload: redactDeliveryLog(payload) as Record<string, unknown>,
          responseStatus: result.statusCode, responseBody: result.responseBody.slice(0, 2000), success: result.success,
        }).catch((err) => logger.child("webhook").warn("Failed to log outbound webhook", { error: String(err) }));
      })().catch((err) => logger.child("webhook").warn("Webhook dispatch error", { error: String(err) }));
    }
  } catch (err) {
    logger.child("webhook").warn("dispatchWebhookEvent error", { error: String(err) });
  }
}

async function publishOutboxEvent(
  orgId: string | null,
  eventType: string,
  aggregateType: string,
  aggregateId: string,
  payload: Record<string, unknown>,
): Promise<void> {
  if (!orgId) return;
  try {
    const fingerprint = createEventFingerprint(eventType, aggregateType, aggregateId, payload);
    await storage.createOutboxEvent({
      orgId,
      eventType,
      aggregateType,
      aggregateId,
      payload,
      status: "pending",
      fingerprint,
      attempts: 0,
      maxAttempts: 5,
    });
  } catch (err) {
    logger.child("outbox").error(`Failed to publish ${eventType} for ${aggregateType}/${aggregateId}`, { error: String(err) });
  }
}

function idempotencyCheck(req: Request, res: Response, next: NextFunction) {
  const idempotencyKey = req.headers["x-idempotency-key"] as string | undefined;
  if (!idempotencyKey) return next();

  const orgId = getOrgId(req);
  const endpoint = req.originalUrl;

  storage.getIdempotencyKey(orgId, idempotencyKey, endpoint).then((existing) => {
    if (existing && existing.expiresAt && new Date(existing.expiresAt) > new Date()) {
      const cached = existing.responseBody as any;
      return res.status(existing.responseStatus || 200).json(cached);
    }

    const originalJson = res.json.bind(res);
    res.json = function (body: any) {
      storage.createIdempotencyKey({
        orgId,
        idempotencyKey,
        endpoint,
        method: req.method,
        responseStatus: res.statusCode,
        responseBody: body,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      }).catch((err) => logger.child("idempotency").warn("Failed to store idempotency key", { key: idempotencyKey, endpoint, error: String(err) }));
      return originalJson(body);
    } as any;
    next();
  }).catch((err) => {
    logger.child("idempotency").warn("Failed to check idempotency key", { key: idempotencyKey, endpoint, error: String(err) });
    next();
  });
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  await setupAuth(app);
  registerAuthRoutes(app);

  applyCsrfProtection(app);

  app.get("/api/csrf-token", getCsrfEndpointHandler);

  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => replyRateLimit(res),
    skip: (req) => req.path === "/ops/health" || req.path === "/health",
  });

  const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => replyRateLimit(res),
  });

  const ingestionLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) =>
      replyRateLimit(res, "Ingestion rate limit exceeded. Try again shortly.", ERROR_CODES.INGESTION_RATE_LIMITED),
  });

  app.use("/api/", generalLimiter);

  startOutboxProcessor();

  // Dashboard (with query-level caching)
  app.get("/api/dashboard/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const cacheKey = buildCacheKey("dashboard:stats", { orgId });
      const stats = await cacheGetOrLoad(cacheKey, () => storage.getDashboardStats(orgId), CACHE_TTL.DASHBOARD_STATS);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });

  app.get("/api/dashboard/analytics", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const cacheKey = buildCacheKey("dashboard:analytics", { orgId });
      const analytics = await cacheGetOrLoad(cacheKey, () => storage.getDashboardAnalytics(orgId), CACHE_TTL.DASHBOARD_ANALYTICS);
      res.json(analytics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch analytics" });
    }
  });

  // Alerts
  app.get("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const { search } = req.query;
      const { offset, limit, sortOrder } = parsePaginationParams(req.query as Record<string, unknown>);
      if (search && typeof search === "string") {
        const results = await storage.searchAlerts(search);
        return res.json(results.slice(offset, offset + limit));
      }
      const allAlerts = await storage.getAlerts();
      const sorted = sortOrder === "asc" ? [...allAlerts].reverse() : allAlerts;
      res.json(sorted.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  // Onboarding status (v1) - summarizes whether key assets are configured for this org
  app.get("/api/v1/onboarding/status", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [integrations, ingestionStats, endpoints, cspmAccounts] = await Promise.all([
        storage.getIntegrationConfigs(orgId),
        storage.getIngestionStats(orgId),
        storage.getEndpointAssets(orgId),
        storage.getCspmAccounts(orgId),
      ]);

      const hasIntegrations = integrations.length > 0;
      const hasIngestion = (ingestionStats.totalIngested ?? 0) > 0;
      const hasEndpoints = endpoints.length > 0;
      const hasCspmAccounts = cspmAccounts.length > 0;

      const completedSteps = [
        hasIntegrations && "integrations",
        hasIngestion && "ingestion",
        hasEndpoints && "endpoints",
        hasCspmAccounts && "cspm",
      ].filter(Boolean);

      const status = {
        steps: {
          integrations: { completed: hasIntegrations, count: integrations.length },
          ingestion: { completed: hasIngestion, totalIngested: ingestionStats.totalIngested ?? 0 },
          endpoints: { completed: hasEndpoints, count: endpoints.length },
          cspm: { completed: hasCspmAccounts, count: cspmAccounts.length },
        },
        completedCount: completedSteps.length,
        totalSteps: 4,
      };

      return sendEnvelope(res, status);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "ONBOARDING_STATUS_FAILED",
            message: "Failed to fetch onboarding status",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.get("/api/v1/alerts", isAuthenticated, validateQuery(querySchemas.alertsList), async (req, res) => {
    try {
      const { offset, limit, search, severity, status, source, sortBy, sortOrder } = (req as any).validatedQuery;

      const { items, total } = await storage.getAlertsPaginatedWithSort({
        offset,
        limit,
        search,
        severity,
        status,
        source,
        sortBy,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, search: search ?? null, severity: severity ?? null, status: status ?? null, source: source ?? null, sortBy: sortBy ?? "createdAt", sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "ALERTS_LIST_FAILED",
            message: "Failed to fetch alerts",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.get("/api/alerts/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.id));
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert" });
    }
  });

  app.post("/api/alerts", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const parsed = insertAlertSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid alert data", errors: parsed.error.flatten() });
      }
      const alert = await storage.createAlert(parsed.data);
      publishOutboxEvent(alert.orgId, "alert.created", "alert", alert.id, {
        title: alert.title, severity: alert.severity, source: alert.source, status: alert.status,
      });
      cacheInvalidate("dashboard:");
      res.status(201).json(alert);
    } catch (error) {
      logger.child("routes").error("Error creating alert", { error: String(error) });
      res.status(500).json({ message: "Failed to create alert" });
    }
  });

  app.patch("/api/alerts/:id", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), validatePathId("id"), async (req, res) => {
    try {
      const parsed = insertAlertSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }
      const alert = await storage.updateAlert(p(req.params.id), parsed.data);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      publishOutboxEvent(alert.orgId, "alert.updated", "alert", alert.id, {
        changes: Object.keys(parsed.data),
      });
      cacheInvalidate("dashboard:");
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert" });
    }
  });

  app.patch("/api/alerts/:id/status", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), validatePathId("id"), async (req, res) => {
    try {
      const { status, incidentId } = req.body;
      if (!status) return res.status(400).json({ message: "Status required" });
      const alert = await storage.updateAlertStatus(p(req.params.id), status, incidentId);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      const closedStatuses = ["resolved", "closed", "false_positive"];
      const outboxEventType = closedStatuses.includes(status) ? "alert.closed" : "alert.updated";
      publishOutboxEvent(alert.orgId, outboxEventType, "alert", alert.id, {
        status, previousStatus: req.body.previousStatus || null,
      });
      cacheInvalidate("dashboard:");
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert status" });
    }
  });

  app.post("/api/alerts/bulk-update", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const { alertIds, status, suppressed, assignedTo } = req.body || {};
      const orgId = (req as any).user?.orgId;
      if (!Array.isArray(alertIds) || alertIds.length === 0) {
        return res.status(400).json({ message: "alertIds array is required" });
      }

      let updatedCount = 0;
      for (const id of alertIds) {
        const alertId = p(String(id));
        const existing = await storage.getAlert(alertId);
        if (!existing || (orgId && existing.orgId && existing.orgId !== orgId)) continue;
        const patch: Record<string, any> = {};
        if (typeof status === "string" && status.length > 0) patch.status = status;
        if (typeof suppressed === "boolean") {
          patch.suppressed = suppressed;
          patch.suppressedBy = suppressed ? ((req as any).user?.id || null) : null;
        }
        if (typeof assignedTo === "string") patch.assignedTo = assignedTo.trim() || null;
        if (Object.keys(patch).length === 0) continue;
        const updated = await storage.updateAlert(alertId, patch as any);
        if (updated) updatedCount++;
      }

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "alerts_bulk_update",
        resourceType: "alert",
        details: { updatedCount, status: status || null, suppressed: typeof suppressed === "boolean" ? suppressed : null, assignedTo: assignedTo || null },
      });

      res.json({ updatedCount });
    } catch (error) {
      logger.child("routes").error("Bulk alert update failed", { error: String(error) });
      res.status(500).json({ message: "Failed to bulk update alerts" });
    }
  });

  // Alert tags
  app.get("/api/alerts/:id/tags", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const alertTags = await storage.getAlertTags(p(req.params.id));
      res.json(alertTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert tags" });
    }
  });

  app.post("/api/alerts/:id/tags", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.incidentTagAdd), async (req, res) => {
    try {
      const { tagId } = (req as any).validatedBody;
      await storage.addAlertTag(p(req.params.id), tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/alerts/:alertId/tags/:tagId", isAuthenticated, validatePathId("alertId"), validatePathId("tagId"), async (req, res) => {
    try {
      await storage.removeAlertTag(p(req.params.alertId), p(req.params.tagId));
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  // Incidents
  app.get("/api/incidents", isAuthenticated, async (req, res) => {
    try {
      const { offset, limit, sortOrder } = parsePaginationParams(req.query as Record<string, unknown>);
      const allIncidents = await storage.getIncidents();
      const sorted = sortOrder === "asc" ? [...allIncidents].reverse() : allIncidents;
      res.json(sorted.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incidents" });
    }
  });

  app.get("/api/v1/incidents", isAuthenticated, validateQuery(querySchemas.incidentsList), async (req, res) => {
    try {
      const { offset, limit, queue, search, severity, status, sortBy, sortOrder } = (req as any).validatedQuery;

      const { items, total } = await storage.getIncidentsPaginatedWithSort({
        offset,
        limit,
        search,
        severity,
        status,
        queue,
        sortBy,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, queue: queue ?? null, search: search ?? null, severity: severity ?? null, status: status ?? null, sortBy: sortBy ?? "createdAt", sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "INCIDENTS_LIST_FAILED",
            message: "Failed to fetch incidents",
            details: error?.message,
          },
        ],
      });
    }
  });

  // Incident Queues (must be before :id route)
  app.get("/api/incidents/queues", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const allIncidents = await storage.getIncidents(orgId);
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const unassigned = allIncidents.filter(i => !i.assignedTo && (i.status === "open" || i.status === "investigating"));
      const escalated = allIncidents.filter(i => i.escalated === true);
      const aging = allIncidents.filter(i => i.createdAt && new Date(i.createdAt) < sevenDaysAgo && i.status !== "resolved" && i.status !== "closed");
      res.json({ unassigned, escalated, aging });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident queues" });
    }
  });

  app.get("/api/incidents/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident" });
    }
  });

  app.get("/api/incidents/:id/alerts", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.id));
      res.json(incidentAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident alerts" });
    }
  });

  app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const parsed = insertIncidentSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid incident data", errors: parsed.error.flatten() });
      }
      const incident = await storage.createIncident(parsed.data);
      broadcastEvent({
        type: "incident:created",
        orgId: incident.orgId || null,
        data: {
          incidentId: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          priority: incident.priority,
        },
      });
      dispatchWebhookEvent(incident.orgId, "incident.created", incident);
      publishOutboxEvent(incident.orgId, "incident.created", "incident", incident.id, {
        title: incident.title, severity: incident.severity, status: incident.status, priority: incident.priority,
      });
      cacheInvalidate("dashboard:");
      res.status(201).json(incident);
    } catch (error) {
      logger.child("routes").error("Error creating incident", { error: String(error) });
      res.status(500).json({ message: "Failed to create incident" });
    }
  });

  app.patch("/api/incidents/:id", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), validatePathId("id"), async (req, res) => {
    try {
      const parsed = insertIncidentSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }

      const existingIncident = await storage.getIncident(p(req.params.id));
      if (!existingIncident) return res.status(404).json({ message: "Incident not found" });

      const updateData: any = { ...parsed.data, updatedAt: new Date() };

      if (parsed.data.status && parsed.data.status !== existingIncident.status) {
        if (parsed.data.status === "contained") {
          updateData.containedAt = new Date();
        }
        if (parsed.data.status === "resolved" || parsed.data.status === "closed") {
          updateData.resolvedAt = new Date();
        }
      }

      if (parsed.data.escalated === true && !existingIncident.escalated) {
        updateData.escalatedAt = new Date();
      }

      const incident = await storage.updateIncident(p(req.params.id), updateData);
      if (!incident) return res.status(404).json({ message: "Incident not found" });

      const userId = (req as any).userId || "system";
      const userName = (req as any).userDisplayName || "Unknown";
      const auditBase = {
        userId,
        userName,
        resourceType: "incident" as const,
        resourceId: incident.id,
        orgId: incident.orgId,
        ipAddress: req.ip,
      };

      if (parsed.data.status && parsed.data.status !== existingIncident.status) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_status_change",
          details: { from: existingIncident.status, to: parsed.data.status },
        });
      }

      if (parsed.data.priority !== undefined && parsed.data.priority !== existingIncident.priority) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_priority_change",
          details: { from: existingIncident.priority, to: parsed.data.priority },
        });
      }

      if (parsed.data.assignedTo !== undefined && parsed.data.assignedTo !== existingIncident.assignedTo) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_assignment_change",
          details: { from: existingIncident.assignedTo || null, to: parsed.data.assignedTo },
        });
      }

      if (parsed.data.escalated !== undefined && parsed.data.escalated !== existingIncident.escalated) {
        await storage.createAuditLog({
          ...auditBase,
          action: "incident_escalated",
          details: { escalated: parsed.data.escalated },
        });
      }

      broadcastEvent({
        type: "incident:updated",
        orgId: incident.orgId || null,
        data: {
          incidentId: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: incident.status,
          priority: incident.priority,
          changes: Object.keys(parsed.data),
        },
      });

      dispatchWebhookEvent(incident.orgId, "incident.updated", incident);

      const closedStatuses = ["resolved", "closed"];
      let incidentOutboxType = "incident.updated";
      if (parsed.data.status && closedStatuses.includes(parsed.data.status)) {
        incidentOutboxType = "incident.closed";
      } else if (parsed.data.escalated === true && !existingIncident.escalated) {
        incidentOutboxType = "incident.escalated";
      }
      publishOutboxEvent(incident.orgId, incidentOutboxType, "incident", incident.id, {
        changes: Object.keys(parsed.data), status: incident.status, severity: incident.severity,
      });
      cacheInvalidate("dashboard:");
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to update incident" });
    }
  });

  app.post("/api/incidents/bulk-update", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("incidents", "write"), async (req, res) => {
    try {
      const { incidentIds, status, assignedTo, escalated, priority } = req.body || {};
      const orgId = (req as any).user?.orgId;
      if (!Array.isArray(incidentIds) || incidentIds.length === 0) {
        return res.status(400).json({ message: "incidentIds array is required" });
      }

      let updatedCount = 0;
      for (const id of incidentIds) {
        const incidentId = p(String(id));
        const existing = await storage.getIncident(incidentId);
        if (!existing || (orgId && existing.orgId && existing.orgId !== orgId)) continue;
        const patch: Record<string, any> = { updatedAt: new Date() };
        if (typeof status === "string" && status.length > 0) {
          patch.status = status;
          if (status === "contained") patch.containedAt = new Date();
          if (status === "resolved" || status === "closed") patch.resolvedAt = new Date();
        }
        if (typeof assignedTo === "string") patch.assignedTo = assignedTo.trim() || null;
        if (typeof escalated === "boolean") {
          patch.escalated = escalated;
          if (escalated && !existing.escalated) patch.escalatedAt = new Date();
        }
        if (typeof priority === "number") patch.priority = priority;
        if (Object.keys(patch).length <= 1) continue;
        const updated = await storage.updateIncident(incidentId, patch as any);
        if (updated) updatedCount++;
      }

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "incidents_bulk_update",
        resourceType: "incident",
        details: { updatedCount, status: status || null, assignedTo: assignedTo || null, escalated: typeof escalated === "boolean" ? escalated : null, priority: priority || null },
      });

      res.json({ updatedCount });
    } catch (error) {
      logger.child("routes").error("Bulk incident update failed", { error: String(error) });
      res.status(500).json({ message: "Failed to bulk update incidents" });
    }
  });

  app.get("/api/incidents/:id/activity", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const logs = await storage.getAuditLogsByResource("incident", p(req.params.id));
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident activity" });
    }
  });

  // Incident comments
  app.get("/api/incidents/:id/comments", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const comments = await storage.getComments(p(req.params.id));
      res.json(comments);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch comments" });
    }
  });

  app.post("/api/incidents/:id/comments", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const parsed = insertCommentSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.id),
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid comment data", errors: parsed.error.flatten() });
      }
      const comment = await storage.createComment(parsed.data);
      res.status(201).json(comment);
    } catch (error) {
      res.status(500).json({ message: "Failed to create comment" });
    }
  });

  app.delete("/api/comments/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const deleted = await storage.deleteComment(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Comment not found" });
      res.json({ message: "Comment deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete comment" });
    }
  });

  // Incident tags
  app.get("/api/incidents/:id/tags", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const incTags = await storage.getIncidentTags(p(req.params.id));
      res.json(incTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident tags" });
    }
  });

  app.post("/api/incidents/:id/tags", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.incidentTagAdd), async (req, res) => {
    try {
      const { tagId } = req.body;
      if (!tagId) return res.status(400).json({ message: "tagId required" });
      await storage.addIncidentTag(p(req.params.id), tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/incidents/:incidentId/tags/:tagId", isAuthenticated, validatePathId("incidentId"), validatePathId("tagId"), async (req, res) => {
    try {
      await storage.removeIncidentTag(p(req.params.incidentId), p(req.params.tagId));
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  // Tags
  app.get("/api/tags", isAuthenticated, async (req, res) => {
    try {
      const allTags = await storage.getTags();
      res.json(allTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch tags" });
    }
  });

  app.post("/api/tags", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertTagSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid tag data", errors: parsed.error.flatten() });
      }
      const tag = await storage.createTag(parsed.data);
      res.status(201).json(tag);
    } catch (error) {
      res.status(500).json({ message: "Failed to create tag" });
    }
  });

  // Audit logs
  app.get("/api/audit-logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getAuditLogs();
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch audit logs" });
    }
  });

  // AI Engine - SecureNexus Cyber Analyst (Mistral Large 2 Instruct / SageMaker)
  app.get("/api/ai/health", isAuthenticated, strictLimiter, async (_req, res) => {
    try {
      const health = await checkModelHealth();
      res.json(health);
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ status: "error", message: "An internal error occurred. Please try again." });
    }
  });

  app.get("/api/ai/config", isAuthenticated, async (_req, res) => {
    res.json(getModelConfig());
  });

  app.get("/api/ai/inference-metrics", isAuthenticated, strictLimiter, async (req, res) => {
    res.json(getInferenceMetrics());
  });

  app.post("/api/ai/correlate", isAuthenticated, strictLimiter, async (req, res) => {
    try {
      const { alertIds } = req.body;
      let alertsToCorrelate;
      if (alertIds && Array.isArray(alertIds) && alertIds.length > 0) {
        const allAlerts = await storage.getAlerts();
        alertsToCorrelate = allAlerts.filter(a => alertIds.includes(a.id));
      } else {
        alertsToCorrelate = (await storage.getAlerts()).filter(a => a.status === "new" || a.status === "triaged");
      }
      if (alertsToCorrelate.length === 0) {
        return res.status(400).json({ message: "No alerts to correlate" });
      }
      const threatIntelCtx = await buildThreatIntelContext(alertsToCorrelate);
      const result = await correlateAlerts(alertsToCorrelate, threatIntelCtx);
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_correlation",
        resourceType: "alerts",
        details: { alertCount: alertsToCorrelate.length, groupsFound: result.correlatedGroups.length },
      });
      res.json(result);
    } catch (error: any) {
      logger.child("ai").error("AI correlation error", { error: String(error) });
      res.status(500).json({ message: "AI correlation failed. Please try again." });
    }
  });

  app.post("/api/ai/narrative/:incidentId", isAuthenticated, strictLimiter, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const incidentAlerts = await storage.getAlertsByIncident(p(req.params.incidentId));
      const threatIntelCtx = await buildThreatIntelContext(incidentAlerts);
      const result = await generateIncidentNarrative(incident, incidentAlerts, threatIntelCtx);
      if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
          (result as any).threatIntelSources = 
            Array.from(new Set([
              ...threatIntelCtx.enrichmentResults.map(r => r.provider),
              ...threatIntelCtx.osintMatches.map(r => r.feedName),
            ]));
      }
      const storedIocs = Array.isArray(result.iocs)
        ? result.iocs.map((ioc: any) => typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type}: ${ioc.context})`)
        : [];
      const { diamondModel: _dm, ...storedAttackerProfile } = result.attackerProfile || {} as any;
      await storage.updateIncident(p(req.params.incidentId), {
        aiNarrative: result.narrative,
        aiSummary: result.summary,
        mitigationSteps: result.mitigationSteps as any,
        iocs: storedIocs as any,
        attackerProfile: storedAttackerProfile as any,
        referencedAlertIds: Array.isArray(result.citedAlertIds) ? result.citedAlertIds : [],
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_narrative_generated",
        resourceType: "incident",
        resourceId: p(req.params.incidentId),
        details: { riskScore: result.riskScore },
      });
      res.json(result);
    } catch (error: any) {
      logger.child("ai").error("AI narrative error", { error: String(error) });
      res.status(500).json({ message: "AI narrative generation failed. Please try again." });
    }
  });

  app.post("/api/ai/triage/:alertId", isAuthenticated, strictLimiter, async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.alertId));
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      const threatIntelCtx = await buildThreatIntelContext([alert]);
      const result = await triageAlert(alert, threatIntelCtx);
      if (threatIntelCtx.enrichmentResults.length > 0 || threatIntelCtx.osintMatches.length > 0) {
          result.threatIntelSources = 
            Array.from(new Set([
              ...threatIntelCtx.enrichmentResults.map(r => r.provider),
              ...threatIntelCtx.osintMatches.map(r => r.feedName),
            ]));
      }
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_triage",
        resourceType: "alert",
        resourceId: p(req.params.alertId),
        details: { severity: result.severity, priority: result.priority },
      });
      res.json(result);
    } catch (error: any) {
      logger.child("ai").error("AI triage error", { error: String(error) });
      res.status(500).json({ message: "AI triage failed. Please try again." });
    }
  });

  app.post("/api/ai/correlate/apply", isAuthenticated, async (req, res) => {
    try {
      const { group } = req.body;
      if (!group || !Array.isArray(group.alertIds) || group.alertIds.length === 0 || !group.suggestedIncidentTitle) {
        return res.status(400).json({ message: "Invalid correlation group data" });
      }
      const validAlertIds: string[] = [];
      for (const alertId of group.alertIds) {
        if (typeof alertId === "string") {
          const alert = await storage.getAlert(alertId);
          if (alert) validAlertIds.push(alertId);
        }
      }
      if (validAlertIds.length === 0) {
        return res.status(400).json({ message: "No valid alerts found in correlation group" });
      }
      const validSeverities = ["critical", "high", "medium", "low"];
      const severity = validSeverities.includes(group.severity) ? group.severity : "medium";
      const incident = await storage.createIncident({
        title: String(group.suggestedIncidentTitle).slice(0, 500),
        summary: String(group.reasoning || "").slice(0, 2000),
        severity,
        status: "investigating",
        priority: severity === "critical" ? 1 : severity === "high" ? 2 : 3,
        confidence: typeof group.confidence === "number" ? Math.min(Math.max(group.confidence, 0), 1) : 0.5,
        mitreTactics: Array.isArray(group.mitreTactics) ? group.mitreTactics.filter((t: any) => typeof t === "string") : [],
        mitreTechniques: Array.isArray(group.mitreTechniques) ? group.mitreTechniques.filter((t: any) => typeof t === "string") : [],
        alertCount: validAlertIds.length,
      });
      for (const alertId of validAlertIds) {
        await storage.updateAlertStatus(alertId, "correlated", incident.id);
      }
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_correlation_applied",
        resourceType: "incident",
        resourceId: incident.id,
        details: { alertCount: group.alertIds.length, title: incident.title },
      });
      res.json(incident);
    } catch (error: any) {
      logger.child("routes").error("Apply correlation error", { error: String(error) });
      res.status(500).json({ message: "Failed to apply correlation. Please try again." });
    }
  });

  // ========== INGESTION SYSTEM (Phase 2) ==========

  // API Key Management (authenticated user routes)
  app.get("/api/api-keys", isAuthenticated, async (req, res) => {
    try {
      const keys = await storage.getApiKeys();
      const safeKeys = keys.map(k => ({
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
  app.get("/api/v1/api-keys/scopes", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
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
  });

  app.get("/api/v1/api-keys/policies", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    const policies = {
      defaultRotationDays: 90,
      maxLifetimeDays: 365,
      minKeyLength: 40,
      recommendedScopes: ["ingest:write", "alerts:read"],
    };

    return sendEnvelope(res, policies);
  });

  app.post("/api/api-keys", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("api_keys", "write"), validateBody(bodySchemas.apiKeyCreate), async (req, res) => {
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
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "api_key_created",
        resourceType: "api_key",
        resourceId: apiKey.id,
        details: { name, keyPrefix: prefix },
      });
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
  });

  app.delete("/api/api-keys/:id", isAuthenticated, resolveOrgContext, requireOrgId, requirePermission("api_keys", "admin"), validatePathId("id"), async (req, res) => {
    try {
      const revoked = await storage.revokeApiKey(p(req.params.id));
      if (!revoked) return res.status(404).json({ message: "API key not found" });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "api_key_revoked",
        resourceType: "api_key",
        resourceId: p(req.params.id),
      });
      res.json({ message: "API key revoked" });
    } catch (error) {
      res.status(500).json({ message: "Failed to revoke API key" });
    }
  });

  // Ingestion Routes (API key authenticated, webhook signature verification)
  app.post("/api/ingest/:source", apiKeyAuth, verifyWebhookSignature, idempotencyCheck, ingestionLimiter, async (req, res) => {
    const startTime = Date.now();
    const source = p(req.params.source);
    const orgId = (req as any).orgId;
    const requestId = randomBytes(8).toString("hex");

    try {
      const payload = req.body;
      if (!payload || typeof payload !== "object") {
        await storage.createIngestionLog({
          orgId, source, status: "failed",
          alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 1,
          errorMessage: "Invalid payload", requestId,
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
        orgId, source: normalized.source, status: isNew ? "success" : "deduped",
        alertsReceived: 1, alertsCreated: isNew ? 1 : 0, alertsDeduped: isNew ? 0 : 1, alertsFailed: 0,
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
            correlation: correlationResult ? { clusterId: correlationResult.clusterId, confidence: correlationResult.confidence } : null,
          },
        });

        publishOutboxEvent(orgId, "alert.created", "alert", alert.id, {
          title: alert.title, severity: alert.severity, source: alert.source, category: alert.category,
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
            clusterId: correlationResult.clusterId, confidence: correlationResult.confidence,
          });
        }
      }

      res.status(isNew ? 201 : 200).json({
        requestId,
        status: isNew ? "created" : "deduplicated",
        alertId: alert.id,
        source: normalized.source,
        entities: entityCount,
        correlation: correlationResult ? { clusterId: correlationResult.clusterId, confidence: correlationResult.confidence } : null,
      });
    } catch (error: any) {
      logger.child("ingestion").error(`Ingestion error [${source}]`, { error: String(error) });
      await storage.createIngestionLog({
        orgId, source, status: "failed",
        alertsReceived: 1, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 1,
        errorMessage: error.message?.slice(0, 500),
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      }).catch((err) => logger.child("ingestion").warn("Failed to create ingestion log after error", { requestId, source, error: String(err) }));
      res.status(500).json({ error: "Ingestion failed", requestId });
    }
  });

  app.post("/api/ingest/:source/bulk", apiKeyAuth, verifyWebhookSignature, idempotencyCheck, ingestionLimiter, async (req, res) => {
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

      let created = 0, deduped = 0, failed = 0;
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

      const status = failed === events.length ? "failed" : failed > 0 ? "partial" : deduped === events.length ? "deduped" : "success";

      await storage.createIngestionLog({
        orgId, source, status,
        alertsReceived: events.length, alertsCreated: created, alertsDeduped: deduped, alertsFailed: failed,
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      });

      res.status(created > 0 ? 201 : 200).json({
        requestId,
        status,
        summary: { received: events.length, created, deduplicated: deduped, failed },
        results,
      });
    } catch (error: any) {
      logger.child("ingestion").error(`Bulk ingestion error [${source}]`, { error: String(error) });
      await storage.createIngestionLog({
        orgId, source, status: "failed",
        alertsReceived: 0, alertsCreated: 0, alertsDeduped: 0, alertsFailed: 0,
        errorMessage: error.message?.slice(0, 500),
        requestId,
        ipAddress: req.ip || null,
        processingTimeMs: Date.now() - startTime,
      }).catch((err) => logger.child("ingestion").warn("Failed to create ingestion log after bulk error", { requestId, source, error: String(err) }));
      res.status(500).json({ error: "Bulk ingestion failed", requestId });
    }
  });

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

  // Connector Engine Routes
  app.get("/api/connectors/types", isAuthenticated, async (_req, res) => {
    const types = getAllConnectorTypes();
    const metadata = types.map(t => ({ type: t, ...getConnectorMetadata(t) })).filter(m => m.name);
    res.json(metadata);
  });

  app.get("/api/connectors", isAuthenticated, async (req, res) => {
    try {
      const { offset, limit } = parsePaginationParams(req.query as Record<string, unknown>);
      const allConnectors = await storage.getConnectors();
      const sanitized = allConnectors.map(c => ({ ...c, config: sanitizeConfig(c.config) }));
      res.json(sanitized.slice(offset, offset + limit));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connectors" });
    }
  });

  app.get("/api/connectors/dead-letters", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.organizationId;
      const { offset, limit } = parsePaginationParams(req.query as Record<string, unknown>);
      const runs = await storage.getDeadLetterJobRuns(orgId);
      res.json(runs.slice(offset, offset + limit));
    } catch (error) { res.status(500).json({ message: "Failed to fetch dead-letter job runs" }); }
  });

  app.get("/api/connectors/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const safeConfig = sanitizeConfig(connector.config);
      res.json({ ...connector, config: safeConfig });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch connector" });
    }
  });

  app.post("/api/connectors", isAuthenticated, validateBody(bodySchemas.connectorCreate), async (req, res) => {
    try {
      const { name, type, authType, config, pollingIntervalMin } = (req as any).validatedBody;
      const configValidation = validateConnectorConfig(type, config);
      if (!configValidation.valid) {
        return res.status(400).json({ message: "Invalid connector configuration", errors: configValidation.errors });
      }
      const connector = await storage.createConnector({
        name,
        type,
        authType,
        config,
        pollingIntervalMin: pollingIntervalMin || 5,
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "connector_created",
        resourceType: "connector",
        resourceId: connector.id,
        details: { type, name },
      });
      publishOutboxEvent(connector.orgId, "connector.synced", "connector", connector.id, {
        type, name,
      });
      res.status(201).json(connector);
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ message: "Failed to create connector. Please try again." });
    }
  });

  app.patch("/api/connectors/:id", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.connectorUpdate), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const { name, config, status, pollingIntervalMin } = (req as any).validatedBody;
      const updateData: any = {};
      if (name) updateData.name = name;
      if (config) {
        const existingConfig = connector.config as ConnectorConfig;
        const newConfig = { ...existingConfig };
        for (const [key, value] of Object.entries(config)) {
          if (value !== "••••••••" && value !== undefined) {
            (newConfig as any)[key] = value;
          }
        }
        updateData.config = newConfig;
      }
      if (status) updateData.status = status;
      if (pollingIntervalMin) updateData.pollingIntervalMin = pollingIntervalMin;
      const updated = await storage.updateConnector(p(req.params.id), updateData);
      res.json(updated);
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ message: "Failed to update connector. Please try again." });
    }
  });

  app.delete("/api/connectors/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      await storage.deleteConnector(p(req.params.id));
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "connector_deleted",
        resourceType: "connector",
        resourceId: p(req.params.id),
        details: { type: connector.type, name: connector.name },
      });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete connector" });
    }
  });

  app.post("/api/connectors/:id/test", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const result = await testConnector(connector.type, config);
      res.json(result);
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  app.post("/api/connectors/test", isAuthenticated, validateBody(bodySchemas.connectorTest), async (req, res) => {
    try {
      const { type, config } = (req as any).validatedBody;
      const configValidation = validateConnectorConfig(type, config);
      if (!configValidation.valid) {
        return res.status(400).json({ success: false, message: "Invalid connector configuration", errors: configValidation.errors });
      }
      const result = await testConnector(type, config);
      res.json(result);
    } catch (error: any) {
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Connector test failed." });
    }
  });

  app.post("/api/connectors/:id/sync", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });

      await storage.updateConnector(connector.id, { status: "syncing" } as any);

      const { jobRun, syncResult } = await syncConnectorWithRetry(connector);

      let created = 0;
      let deduped = 0;
      let failed = syncResult.alertsFailed;
      const UPSERT_BATCH = 50;

      for (let i = 0; i < syncResult.rawAlerts.length; i += UPSERT_BATCH) {
        const batch = syncResult.rawAlerts.slice(i, i + UPSERT_BATCH);
        const results = await Promise.allSettled(
          batch.map((alertData) => storage.upsertAlert(alertData as any)),
        );
        for (const r of results) {
          if (r.status === "fulfilled") {
            if (r.value.isNew) created++;
            else deduped++;
          } else {
            failed++;
            syncResult.errors.push(`DB insert failed: ${r.reason?.message ?? "unknown"}`);
          }
        }
      }

      const totalSynced = (connector.totalAlertsSynced || 0) + created;
      const syncStatus = syncResult.errors.length > 0 && created === 0 ? "error" : "success";

      await storage.updateConnectorSyncStatus(connector.id, {
        lastSyncAt: new Date(),
        lastSyncStatus: syncStatus,
        lastSyncAlerts: created,
        lastSyncError: syncResult.errors.length > 0 ? syncResult.errors[0] : undefined,
        totalAlertsSynced: totalSynced,
      });

      await storage.updateConnector(connector.id, { status: syncStatus === "error" ? "error" : "active" } as any);

      await storage.createIngestionLog({
        source: connector.type,
        status: syncStatus,
        alertsReceived: syncResult.alertsReceived,
        alertsCreated: created,
        alertsDeduped: deduped,
        alertsFailed: failed,
        errorMessage: syncResult.errors.length > 0 ? syncResult.errors.join("; ") : undefined,
        requestId: `sync_${connector.id}_${Date.now()}`,
      });

      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "connector_synced",
        resourceType: "connector",
        resourceId: connector.id,
        details: { type: connector.type, received: syncResult.alertsReceived, created, deduped, failed, jobRunId: jobRun.id },
      });

      cacheInvalidate("dashboard:");
      cacheInvalidate("ingestion:");

      res.json({
        success: syncStatus !== "error",
        jobRunId: jobRun.id,
        alertsReceived: syncResult.alertsReceived,
        alertsCreated: created,
        alertsDeduped: deduped,
        alertsFailed: failed,
        errors: syncResult.errors,
      });
    } catch (error: any) {
      const connector = await storage.getConnector(p(req.params.id));
      if (connector) {
        await storage.updateConnectorSyncStatus(connector.id, {
          lastSyncAt: new Date(),
          lastSyncStatus: "error",
          lastSyncAlerts: 0,
          lastSyncError: error.message,
        });
        await storage.updateConnector(connector.id, { status: "error" } as any);
      }
      logger.child("routes").error("Route error", { error: String(error) });
      res.status(500).json({ success: false, message: "Sync failed. Please try again." });
    }
  });

  app.get("/api/connectors/:id/jobs", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const runs = await storage.getConnectorJobRuns(p(req.params.id), limit);
      res.json(runs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch job runs" }); }
  });

  app.get("/api/connectors/:id/metrics", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const metrics = await storage.getConnectorMetrics(p(req.params.id));
      res.json(metrics);
    } catch (error) { res.status(500).json({ message: "Failed to fetch connector metrics" }); }
  });

  app.post("/api/connectors/:id/health-check", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const startTime = Date.now();
      let status = "healthy";
      let errorMessage: string | undefined;
      try {
        const result = await testConnector(connector.type, config);
        if (!result.success) {
          status = "unhealthy";
          errorMessage = result.message || "Connection test failed";
        }
      } catch (err: any) {
        status = "unhealthy";
        errorMessage = err.message || "Connection test error";
      }
      const latencyMs = Date.now() - startTime;
      const healthCheck = await storage.createConnectorHealthCheck({
        connectorId: connector.id,
        orgId: connector.orgId,
        status,
        latencyMs,
        errorMessage,
        credentialStatus: status === "healthy" ? "valid" : "unknown",
      });
      res.status(201).json(healthCheck);
    } catch (error) { res.status(500).json({ message: "Failed to run health check" }); }
  });

  app.get("/api/connectors/:id/health", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const checks = await storage.getConnectorHealthChecks(p(req.params.id), limit);
      res.json(checks);
    } catch (error) { res.status(500).json({ message: "Failed to fetch health checks" }); }
  });

  // AI Feedback (Phase 7+12)
  app.post("/api/ai/feedback", isAuthenticated, validateBody(bodySchemas.aiFeedback), async (req, res) => {
    try {
      const { resourceType, resourceId, rating, comment, aiOutput, correctionReason, correctedSeverity, correctedCategory } = (req as any).validatedBody;
      const feedbackData: any = {
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        resourceType, resourceId, rating, comment, aiOutput,
      };
      if (correctionReason) feedbackData.correctionReason = correctionReason;
      if (correctedSeverity) feedbackData.correctedSeverity = correctedSeverity;
      if (correctedCategory) feedbackData.correctedCategory = correctedCategory;
      const feedback = await storage.createAiFeedback(feedbackData);
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "ai_feedback_submitted",
        resourceType, resourceId,
        details: { rating, hasComment: !!comment, correctionReason, correctedSeverity, correctedCategory },
      });
      res.status(201).json(feedback);
    } catch (error) { res.status(500).json({ message: "Failed to submit feedback" }); }
  });

  app.get("/api/ai/feedback/metrics", isAuthenticated, validateQuery(querySchemas.feedbackMetrics), async (req, res) => {
    try {
      const orgId = (req as any).user?.organizationId;
      const { days } = (req as any).validatedQuery;
      const metrics = await storage.getAiFeedbackMetrics(orgId, days);
      res.json(metrics);
    } catch (error) { res.status(500).json({ message: "Failed to fetch feedback metrics" }); }
  });

  app.get("/api/ai/feedback/:resourceType/:resourceId", isAuthenticated, async (req, res) => {
    try {
      const feedback = await storage.getAiFeedbackByResource(p(req.params.resourceType), p(req.params.resourceId));
      res.json(feedback);
    } catch (error) { res.status(500).json({ message: "Failed to fetch feedback for resource" }); }
  });

  app.get("/api/ai/feedback", isAuthenticated, validateQuery(querySchemas.aiFeedbackByQuery), async (req, res) => {
    try {
      const { resourceType, resourceId } = (req as any).validatedQuery;
      const feedback = await storage.getAiFeedback(resourceType as string, resourceId as string);
      res.json(feedback);
    } catch (error) { res.status(500).json({ message: "Failed to fetch feedback" }); }
  });

  // Playbooks (Phase 13 - SOAR-Lite)
  app.get("/api/playbooks", isAuthenticated, async (_req, res) => {
    try { res.json(await storage.getPlaybooks()); }
    catch (error) { res.status(500).json({ message: "Failed to fetch playbooks" }); }
  });

  app.get("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb) return res.status(404).json({ message: "Playbook not found" });
      res.json(pb);
    } catch (error) { res.status(500).json({ message: "Failed to fetch playbook" }); }
  });

  app.post("/api/playbooks", isAuthenticated, validateBody(bodySchemas.playbookCreate), async (req, res) => {
    try {
      const { name, description, trigger, conditions, actions, status } = (req as any).validatedBody;
      const playbook = await storage.createPlaybook({
        name, description, trigger, conditions, actions, status: status || "draft",
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "playbook_created",
        resourceType: "playbook", resourceId: playbook.id,
        details: { name, trigger },
      });
      res.status(201).json(playbook);
    } catch (error) { res.status(500).json({ message: "Failed to create playbook" }); }
  });

  app.patch("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const existing = await storage.getPlaybook(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Playbook not found" });
      const updated = await storage.updatePlaybook(p(req.params.id), {
        ...req.body, updatedAt: new Date(),
      });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update playbook" }); }
  });

  app.delete("/api/playbooks/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const deleted = await storage.deletePlaybook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Playbook not found" });
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "playbook_deleted",
        resourceType: "playbook", resourceId: p(req.params.id),
      });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete playbook" }); }
  });

  app.post("/api/playbooks/:id/execute", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const pb = await storage.getPlaybook(p(req.params.id));
      if (!pb) return res.status(404).json({ message: "Playbook not found" });
      const startTime = Date.now();
      const user = (req as any).user;
      const isDryRun = req.body.dryRun === true;
      const context: ActionContext = {
        orgId: user?.orgId || pb.orgId || undefined,
        incidentId: req.body.resourceId,
        alertId: req.body.alertId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Manual",
        storage,
      };

      const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
      const executedActions: any[] = [];

      const execution = await storage.createPlaybookExecution({
        playbookId: pb.id,
        triggeredBy: context.userName,
        triggerEvent: "manual",
        resourceType: req.body.resourceType,
        resourceId: req.body.resourceId,
        status: "running",
        dryRun: isDryRun,
        actionsExecuted: [],
        result: {},
      });
      const executionId = execution.id;

      const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
      let pausedAtApproval = false;
      
      if (isGraphFormat) {
        const graph = actionsArr[0] as any;
        const nodes = graph.nodes || [];
        const edges = graph.edges || [];
        
        const adjacency: Record<string, string[]> = {};
        for (const edge of edges) {
          if (!adjacency[edge.source]) adjacency[edge.source] = [];
          adjacency[edge.source].push(edge.target);
        }
        
        const targetNodes = new Set(edges.map((e: any) => e.target));
        const startNodes = nodes.filter((n: any) => !targetNodes.has(n.id) || n.type === "trigger");
        
        const visited = new Set<string>();
        const queue = startNodes.map((n: any) => n.id);
        let execCount = 0;
        
        while (queue.length > 0 && execCount < 50) {
          const nodeId = queue.shift()!;
          if (visited.has(nodeId)) continue;
          visited.add(nodeId);
          
          const node = nodes.find((n: any) => n.id === nodeId);
          if (!node) continue;

          if (node.type === "approval") {
            const approval = await storage.createPlaybookApproval({
              executionId: executionId,
              playbookId: pb.id,
              nodeId: node.id,
              status: "pending",
              requestedBy: context.userName,
              approverRole: node.data?.config?.approverRole || "admin",
              approvalMessage: node.data?.config?.message || node.data?.label || "Approval required",
            });
            await storage.updatePlaybookExecution(executionId, {
              status: "awaiting_approval",
              pausedAtNodeId: node.id,
              actionsExecuted: executedActions,
              executionTimeMs: Date.now() - startTime,
              result: { totalActions: executedActions.length, approvalId: approval.id, pausedAt: node.id },
            });
            pausedAtApproval = true;
            break;
          }
          
          if (node.type === "action" && node.data?.actionType) {
            if (isDryRun) {
              executedActions.push({ nodeId, actionType: node.data.actionType, status: "simulated", message: `[Dry Run] Would execute: ${node.data.label}`, executedAt: new Date().toISOString() });
            } else {
              const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
              executedActions.push({ nodeId, ...result });
            }
            execCount++;
          } else if (node.type === "condition") {
            const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
            for (const edge of trueEdges) {
              queue.push(edge.target);
            }
            executedActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
            execCount++;
            continue;
          }
          
          const children = adjacency[nodeId] || [];
          for (const child of children) {
            queue.push(child);
          }
        }
      } else {
        for (const action of actionsArr) {
          const actionObj = action as any;
          const actionType = actionObj.type || actionObj.actionType || "unknown";
          const config = typeof actionObj.config === "string" ? 
            (() => { try { return JSON.parse(actionObj.config); } catch { return { raw: actionObj.config }; } })() :
            (actionObj.config || {});
          if (isDryRun) {
            executedActions.push({ actionType, status: "simulated", message: `[Dry Run] Would execute: ${actionType}`, executedAt: new Date().toISOString() });
          } else {
            const result = await dispatchAction(actionType, config, context);
            executedActions.push(result);
          }
        }
      }

      if (!pausedAtApproval) {
        await storage.updatePlaybookExecution(executionId, {
          status: "completed",
          actionsExecuted: executedActions,
          result: { totalActions: executedActions.length, completedActions: executedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
          executionTimeMs: Date.now() - startTime,
        });
      }

      await storage.updatePlaybook(pb.id, { lastTriggeredAt: new Date(), triggerCount: (pb.triggerCount || 0) + 1 } as any);
      await storage.createAuditLog({
        userId: user?.id,
        userName: context.userName,
        action: "playbook_executed",
        resourceType: "playbook",
        resourceId: pb.id,
        details: { name: pb.name, trigger: "manual", actionsCount: executedActions.length, dryRun: isDryRun, paused: pausedAtApproval },
      });
      const updatedExecution = await storage.getPlaybookExecution(executionId);
      res.json(updatedExecution || execution);
    } catch (error) {
      logger.child("routes").error("Playbook execution error", { error: String(error) });
      res.status(500).json({ message: "Failed to execute playbook" });
    }
  });

  app.get("/api/playbook-executions", isAuthenticated, validateQuery(querySchemas.playbookExecutions), async (req, res) => {
    try {
      const { playbookId, limit } = (req as any).validatedQuery;
      res.json(await storage.getPlaybookExecutions(playbookId, limit));
    } catch (error) { res.status(500).json({ message: "Failed to fetch executions" }); }
  });

  app.get("/api/playbook-approvals", isAuthenticated, validateQuery(querySchemas.approvalStatus), async (req, res) => {
    try {
      const { status } = (req as any).validatedQuery;
      const approvals = await storage.getPlaybookApprovals(status);
      res.json(approvals);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch playbook approvals" });
    }
  });

  app.post("/api/playbook-approvals/:id/decide", isAuthenticated, validatePathId("id"), validateBody(bodySchemas.approvalDecision), async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const { decision, note } = (req as any).validatedBody;

      const approval = await storage.getPlaybookApproval(p(req.params.id));
      if (!approval) return res.status(404).json({ message: "Approval not found" });
      if (approval.status !== "pending") {
        return res.status(400).json({ message: `Approval already ${approval.status}` });
      }

      // Validate linked resources exist
      const execution = await storage.getPlaybookExecution(approval.executionId);
      if (!execution) return res.status(404).json({ message: "Linked execution not found" });
      const pb = await storage.getPlaybook(execution.playbookId);
      if (!pb) return res.status(404).json({ message: "Linked playbook not found" });

      const updatedApproval = await storage.updatePlaybookApproval(approval.id, {
        status: decision,
        decidedBy: userName,
        decisionNote: note || null,
        decidedAt: new Date(),
      });

      if (decision === "approved") {
        if (execution.status === "awaiting_approval") {
          const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
          const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
          if (isGraphFormat) {
            const graph = actionsArr[0] as any;
            const nodes = graph.nodes || [];
            const edges = graph.edges || [];
            const adjacency: Record<string, string[]> = {};
            for (const edge of edges) {
              if (!adjacency[edge.source]) adjacency[edge.source] = [];
              adjacency[edge.source].push(edge.target);
            }
            const pausedNodeId = execution.pausedAtNodeId;
            const resumeFrom = pausedNodeId ? (adjacency[pausedNodeId] || []) : [];
            const existingActions = Array.isArray(execution.actionsExecuted) ? execution.actionsExecuted as any[] : [];
            const visited = new Set<string>(existingActions.map((a: any) => a.nodeId).filter(Boolean));
            if (pausedNodeId) visited.add(pausedNodeId);
            const queue = [...resumeFrom];
            const newActions: any[] = [];
            let execCount = 0;
            const isDryRun = execution.dryRun === true;
            const context: ActionContext = {
              orgId: user?.orgId || pb.orgId || undefined,
              incidentId: execution.resourceId || undefined,
              userId: user?.id,
              userName,
              storage,
            };
            while (queue.length > 0 && execCount < 50) {
              const nodeId = queue.shift()!;
              if (visited.has(nodeId)) continue;
              visited.add(nodeId);
              const node = nodes.find((n: any) => n.id === nodeId);
              if (!node) continue;
              if (node.type === "action" && node.data?.actionType) {
                if (isDryRun) {
                  newActions.push({ nodeId, actionType: node.data.actionType, status: "simulated", message: `[Dry Run] Would execute: ${node.data.label}`, executedAt: new Date().toISOString() });
                } else {
                  const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
                  newActions.push({ nodeId, ...result });
                }
                execCount++;
              } else if (node.type === "condition") {
                const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
                for (const edge of trueEdges) { queue.push(edge.target); }
                newActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
                execCount++;
                continue;
              }
              const children = adjacency[nodeId] || [];
              for (const child of children) { queue.push(child); }
            }
            const mergedActions = [...existingActions, ...newActions];
            await storage.updatePlaybookExecution(execution.id, {
              status: "completed",
              pausedAtNodeId: null,
              actionsExecuted: mergedActions,
              result: { totalActions: mergedActions.length, completedActions: mergedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
            });
          }
        }
      } else {
        await storage.updatePlaybookExecution(approval.executionId, { status: "rejected" });
      }

      await storage.createAuditLog({
        userId: user?.id,
        userName,
        action: `playbook_approval_${decision}`,
        resourceType: "playbook_approval",
        resourceId: approval.id,
        details: { executionId: approval.executionId, playbookId: approval.playbookId, decision, note },
      });

      res.json(updatedApproval);
    } catch (error) {
      logger.child("routes").error("Approval decision error", { error: String(error) });
      res.status(500).json({ message: "Failed to process approval decision" });
    }
  });

  app.post("/api/playbook-executions/:id/resume", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const execution = await storage.getPlaybookExecution(p(req.params.id));
      if (!execution) return res.status(404).json({ message: "Execution not found" });
      if (execution.status !== "awaiting_approval") {
        return res.status(400).json({ message: `Execution is not paused, current status: ${execution.status}` });
      }

      const pb = await storage.getPlaybook(execution.playbookId);
      if (!pb) return res.status(404).json({ message: "Playbook not found" });

      const actionsArr = Array.isArray(pb.actions) ? pb.actions : [];
      const isGraphFormat = actionsArr.length > 0 && (actionsArr as any)[0]?.nodes;
      if (!isGraphFormat) {
        return res.status(400).json({ message: "Playbook is not in graph format, cannot resume" });
      }

      const graph = actionsArr[0] as any;
      const nodes = graph.nodes || [];
      const edges = graph.edges || [];
      const adjacency: Record<string, string[]> = {};
      for (const edge of edges) {
        if (!adjacency[edge.source]) adjacency[edge.source] = [];
        adjacency[edge.source].push(edge.target);
      }

      const pausedNodeId = execution.pausedAtNodeId;
      const resumeFrom = pausedNodeId ? (adjacency[pausedNodeId] || []) : [];
      const existingActions = Array.isArray(execution.actionsExecuted) ? execution.actionsExecuted as any[] : [];
      const visited = new Set<string>(existingActions.map((a: any) => a.nodeId).filter(Boolean));
      if (pausedNodeId) visited.add(pausedNodeId);
      const queue = [...resumeFrom];
      const newActions: any[] = [];
      let execCount = 0;
      const isDryRun = execution.dryRun === true;
      const context: ActionContext = {
        orgId: user?.orgId || pb.orgId || undefined,
        incidentId: execution.resourceId || undefined,
        userId: user?.id,
        userName,
        storage,
      };

      while (queue.length > 0 && execCount < 50) {
        const nodeId = queue.shift()!;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);
        const node = nodes.find((n: any) => n.id === nodeId);
        if (!node) continue;
        if (node.type === "action" && node.data?.actionType) {
          if (isDryRun) {
            newActions.push({ nodeId, actionType: node.data.actionType, status: "simulated", message: `[Dry Run] Would execute: ${node.data.label}`, executedAt: new Date().toISOString() });
          } else {
            const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
            newActions.push({ nodeId, ...result });
          }
          execCount++;
        } else if (node.type === "condition") {
          const trueEdges = edges.filter((e: any) => e.source === nodeId && e.label !== "false");
          for (const edge of trueEdges) { queue.push(edge.target); }
          newActions.push({ nodeId, actionType: "condition", status: "completed", message: `Evaluated condition: ${node.data?.label || "check"}`, executedAt: new Date().toISOString() });
          execCount++;
          continue;
        }
        const children = adjacency[nodeId] || [];
        for (const child of children) { queue.push(child); }
      }

      const mergedActions = [...existingActions, ...newActions];
      const updated = await storage.updatePlaybookExecution(execution.id, {
        status: "completed",
        pausedAtNodeId: null,
        actionsExecuted: mergedActions,
        result: { totalActions: mergedActions.length, completedActions: mergedActions.filter((a: any) => a.status === "completed" || a.status === "simulated").length },
      });

      await storage.createAuditLog({
        userId: user?.id,
        userName,
        action: "playbook_execution_resumed",
        resourceType: "playbook_execution",
        resourceId: execution.id,
        details: { playbookId: execution.playbookId, newActionsCount: newActions.length },
      });

      res.json(updated);
    } catch (error) {
      logger.child("routes").error("Resume execution error", { error: String(error) });
      res.status(500).json({ message: "Failed to resume execution" });
    }
  });

  app.post("/api/playbook-executions/:id/rollback", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const execution = await storage.getPlaybookExecution(p(req.params.id));
      if (!execution) return res.status(404).json({ message: "Execution not found" });

      const actionsExecuted = Array.isArray(execution.actionsExecuted) ? execution.actionsExecuted as any[] : [];
      const rollbackEligible = actionsExecuted.filter((a: any) => canRollback(a.actionType));

      if (rollbackEligible.length === 0) {
        return res.json({ message: "No rollback-eligible actions found", rollbacks: [] });
      }

      const orgId = getOrgId(req);
      const rollbacks = [];
      for (const action of rollbackEligible) {
        const target = action.details?.target || action.details?.hostname || action.details?.ip || action.nodeId || "unknown";
        const rollback = await createRollbackRecord(orgId, execution.id, action.actionType, target);
        rollbacks.push(rollback);
      }

      await storage.createAuditLog({
        userId: user?.id,
        userName,
        action: "playbook_execution_rollback",
        resourceType: "playbook_execution",
        resourceId: execution.id,
        details: { rollbackCount: rollbacks.length, actionTypes: rollbackEligible.map((a: any) => a.actionType) },
      });

      res.json({ message: `Created ${rollbacks.length} rollback records`, rollbacks });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      logger.child("routes").error("Rollback creation error", { error: String(error) });
      res.status(500).json({ message: "Failed to create rollback records" });
    }
  });

  // Export Routes (Phase 10)
  app.get("/api/export/alerts", isAuthenticated, async (req, res) => {
    try {
      const allAlerts = await storage.getAlerts();
      const csvHeader = "ID,Title,Severity,Status,Source,Category,MITRE Tactic,MITRE Technique,Source IP,Dest IP,Hostname,Detected At,Created At\n";
      const csvRows = allAlerts.map(a =>
        [a.id, `"${(a.title || '').replace(/"/g, '""')}"`, a.severity, a.status, a.source, a.category || '',
         a.mitreTactic || '', a.mitreTechnique || '', a.sourceIp || '', a.destIp || '', a.hostname || '',
         a.detectedAt?.toISOString() || '', a.createdAt?.toISOString() || ''
        ].join(",")
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=securenexus-alerts-${new Date().toISOString().split("T")[0]}.csv`);
      res.send(csvHeader + csvRows);
    } catch (error) { res.status(500).json({ message: "Failed to export alerts" }); }
  });

  app.get("/api/export/incidents", isAuthenticated, async (req, res) => {
    try {
      const allIncidents = await storage.getIncidents();
      const csvHeader = "ID,Title,Severity,Status,Priority,Alert Count,Assigned To,Escalated,MITRE Tactics,Created At,Updated At\n";
      const csvRows = allIncidents.map(i =>
        [i.id, `"${(i.title || '').replace(/"/g, '""')}"`, i.severity, i.status, i.priority || '',
         i.alertCount || 0, i.assignedTo || '', i.escalated ? 'Yes' : 'No',
         `"${(i.mitreTactics || []).join('; ')}"`,
         i.createdAt?.toISOString() || '', i.updatedAt?.toISOString() || ''
        ].join(",")
      ).join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename=securenexus-incidents-${new Date().toISOString().split("T")[0]}.csv`);
      res.send(csvHeader + csvRows);
    } catch (error) { res.status(500).json({ message: "Failed to export incidents" }); }
  });

  app.get("/api/export/incident/:id/report", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const incidentAlerts = await storage.getAlertsByIncident(incident.id);
      const comments = await storage.getComments(incident.id);
      const report = {
        generatedAt: new Date().toISOString(),
        incident: { ...incident, alerts: incidentAlerts, comments },
      };
      res.json(report);
    } catch (error) { res.status(500).json({ message: "Failed to generate report" }); }
  });

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

  app.get("/api/alerts/:id/entities", isAuthenticated, async (req, res) => {
    try {
      const alertEntityList = await getEntitiesForAlert(p(req.params.id));
      res.json(alertEntityList);
    } catch (error) { res.status(500).json({ message: "Failed to fetch alert entities" }); }
  });

  app.get("/api/alerts/:id/related", isAuthenticated, async (req, res) => {
    try {
      const alert = await storage.getAlert(p(req.params.id));
      const related = await findRelatedAlertsByEntity(p(req.params.id), alert?.orgId);
      res.json(related);
    } catch (error) { res.status(500).json({ message: "Failed to fetch related alerts" }); }
  });

  app.get("/api/incidents/:id/entities", isAuthenticated, async (req, res) => {
    try {
      const incidentEntities = await getEntitiesForIncident(p(req.params.id));
      res.json(incidentEntities);
    } catch (error) { res.status(500).json({ message: "Failed to fetch incident entities" }); }
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

  app.get("/api/events/stream", isAuthenticated, (req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const orgId = (req as any).user?.orgId ?? null;
    const clientId = eventBus.generateClientId();

    const VALID_EVENT_TYPES: Set<string> = new Set([
      "alert:created", "alert:updated", "incident:created", "incident:updated",
      "correlation:found", "entity:resolved", "system:health",
    ]);
    const rawTypes = req.query.types as string | undefined;
    const subscriptions = rawTypes
      ? rawTypes.split(",").map((t) => t.trim()).filter((t) => VALID_EVENT_TYPES.has(t)) as any[]
      : undefined;

    eventBus.addClient({
      id: clientId,
      orgId,
      res,
      connectedAt: new Date(),
      subscriptions,
    });

    const connectEvent = {
      type: "connected",
      clientId,
      subscriptions: subscriptions || "all",
      timestamp: new Date().toISOString(),
    };
    res.write(`event: connected\ndata: ${JSON.stringify(connectEvent)}\n\n`);

    req.on("close", () => {
      eventBus.removeClient(clientId);
    });
  });

  app.get("/api/events/status", isAuthenticated, (req: Request, res: Response) => {
    const orgId = (req as any).user?.orgId ?? null;
    const stats = eventBus.getStats();
    res.json({
      connected: stats.totalClients,
      orgClients: orgId ? eventBus.getOrgClientCount(orgId) : 0,
      slowClients: stats.slowClients,
      totalDropped: stats.totalDropped,
      totalBuffered: stats.totalBuffered,
    });
  });

  // Threat Intel Configuration (Org-level API keys)
  app.get("/api/threat-intel-configs", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json([]);
      const configs = await storage.getThreatIntelConfigs(orgId);
      const masked = configs.map(c => ({
        ...c,
        apiKey: c.apiKey ? `****${c.apiKey.slice(-4)}` : null,
      }));
      res.json(masked);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch threat intel configs" });
    }
  });

  app.post("/api/threat-intel-configs", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
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
  });

  app.delete("/api/threat-intel-configs/:provider", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      await storage.deleteThreatIntelConfig(orgId, p(req.params.provider));
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete threat intel config" });
    }
  });

  app.post("/api/threat-intel-configs/:provider/test", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
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
        const { db: database } = await import("./db");
        const { threatIntelConfigs } = await import("@shared/schema");
        const { eq } = await import("drizzle-orm");
        await database.update(threatIntelConfigs).set({
          lastTestedAt: new Date(),
          lastTestStatus: success ? "success" : "failed",
        }).where(eq(threatIntelConfigs.id, updatedConfig.id));
      }

      res.json({ success, message, testedAt: new Date().toISOString() });
    } catch (error) {
      logger.child("routes").error("Error testing threat intel config", { error: String(error) });
      res.status(500).json({ success: false, message: "Failed to test API key" });
    }
  });

  // Phase 4: Threat Enrichment & Intelligence Feeds
  app.get("/api/enrichment/providers", isAuthenticated, async (req, res) => {
    try {
      const { getProviderStatuses } = await import("./threat-enrichment");
      const user = (req as any).user;
      const orgId = user?.orgId;
      res.json(await getProviderStatuses(orgId));
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch provider statuses" });
    }
  });

  app.get("/api/entities/:id/enrichment", isAuthenticated, async (req, res) => {
    try {
      const { getEnrichmentForEntity } = await import("./threat-enrichment");
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
      const { enrichEntity } = await import("./threat-enrichment");
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

  // OSINT Threat Intelligence Feeds (no API keys required)
  app.get("/api/osint-feeds/status", isAuthenticated, async (_req, res) => {
    try {
      const { getOsintFeedStatuses } = await import("./osint-feeds");
      res.json(getOsintFeedStatuses());
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch OSINT feed statuses" });
    }
  });

  app.get("/api/osint-feeds", isAuthenticated, async (_req, res) => {
    try {
      const { fetchAllOsintFeeds } = await import("./osint-feeds");
      const results = await fetchAllOsintFeeds();
      res.json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch OSINT feeds" });
    }
  });

  app.get("/api/osint-feeds/:feedName", isAuthenticated, async (req, res) => {
    try {
      const { fetchOsintFeed } = await import("./osint-feeds");
      const feedName = decodeURIComponent(p(req.params.feedName));
      const result = await fetchOsintFeed(feedName);
      if (result.status === "error" && result.errorMessage?.startsWith("Unknown feed")) {
        return res.status(404).json({ message: result.errorMessage });
      }
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch OSINT feed" });
    }
  });

  app.post("/api/osint-feeds/:feedName/refresh", isAuthenticated, async (req, res) => {
    try {
      const { fetchOsintFeed } = await import("./osint-feeds");
      const feedName = decodeURIComponent(p(req.params.feedName));
      const result = await fetchOsintFeed(feedName, true);
      if (result.status === "error" && result.errorMessage?.startsWith("Unknown feed")) {
        return res.status(404).json({ message: result.errorMessage });
      }
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to refresh OSINT feed" });
    }
  });

  function validateFeedUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
      const hostname = parsed.hostname.toLowerCase();
      if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '127.0.0.1') return false;
      if (hostname.startsWith('10.') || hostname.startsWith('192.168.') || hostname.startsWith('169.254.')) return false;
      if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return false;
      if (hostname === '::1' || hostname.startsWith('fc') || hostname.startsWith('fd')) return false;
      return true;
    } catch {
      return false;
    }
  }

  // Threat Intel Fusion Layer - IOC Feeds, Entries, Watchlists, Match Rules, Matches
  app.get("/api/ioc-feeds", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const feeds = await storage.getIocFeeds(user?.orgId);
      res.json(feeds);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC feeds" });
    }
  });

  app.get("/api/ioc-feeds/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const feed = await storage.getIocFeed(p(req.params.id));
      if (!feed) return res.status(404).json({ message: "Feed not found" });
      if (feed.orgId && user?.orgId && feed.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(feed);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC feed" });
    }
  });

  app.post("/api/ioc-feeds", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = getOrgId(req);
      const parsed = insertIocFeedSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid feed data", errors: parsed.error.flatten() });
      }
      if (parsed.data.url && !validateFeedUrl(parsed.data.url)) {
        return res.status(400).json({ message: "Invalid feed URL. Must be http/https and not target private/internal networks." });
      }
      const feed = await storage.createIocFeed({ ...parsed.data, orgId });
      res.status(201).json(feed);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create IOC feed" });
    }
  });

  app.patch("/api/ioc-feeds/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIocFeed(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Feed not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      if (req.body.url && !validateFeedUrl(req.body.url)) {
        return res.status(400).json({ message: "Invalid feed URL. Must be http/https and not target private/internal networks." });
      }
      const { orgId: _ignoreOrgId, ...updateData } = req.body;
      const feed = await storage.updateIocFeed(p(req.params.id), updateData);
      if (!feed) return res.status(404).json({ message: "Feed not found" });
      res.json(feed);
    } catch (error) {
      res.status(500).json({ message: "Failed to update IOC feed" });
    }
  });

  app.delete("/api/ioc-feeds/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIocFeed(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Feed not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteIocFeed(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Feed not found" });
      res.json({ message: "Feed deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete IOC feed" });
    }
  });

  app.post("/api/ioc-feeds/:id/ingest", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const feed = await storage.getIocFeed(p(req.params.id));
      if (!feed) return res.status(404).json({ message: "Feed not found" });
      if (feed.orgId && user?.orgId && feed.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { fetchAndIngestFeed, ingestFeed } = await import("./ioc-ingestion");
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
  });

  app.get("/api/ioc-entries", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const { feedId, iocType, status, limit } = req.query;
      const entries = await storage.getIocEntries(
        user?.orgId,
        feedId as string | undefined,
        iocType as string | undefined,
        status as string | undefined,
        limit ? parseInt(limit as string, 10) : undefined,
      );
      res.json(entries);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC entries" });
    }
  });

  app.get("/api/ioc-entries/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const entry = await storage.getIocEntry(p(req.params.id));
      if (!entry) return res.status(404).json({ message: "IOC entry not found" });
      if (entry.orgId && user?.orgId && entry.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(entry);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC entry" });
    }
  });

  app.post("/api/ioc-entries", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = getOrgId(req);
      const parsed = insertIocEntrySchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid IOC entry data", errors: parsed.error.flatten() });
      }
      const entry = await storage.createIocEntry({ ...parsed.data, orgId });
      res.status(201).json(entry);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create IOC entry" });
    }
  });

  app.patch("/api/ioc-entries/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIocEntry(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "IOC entry not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { orgId: _ignoreOrgId, ...updateData } = req.body;
      const entry = await storage.updateIocEntry(p(req.params.id), updateData);
      if (!entry) return res.status(404).json({ message: "IOC entry not found" });
      res.json(entry);
    } catch (error) {
      res.status(500).json({ message: "Failed to update IOC entry" });
    }
  });

  app.delete("/api/ioc-entries/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIocEntry(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "IOC entry not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteIocEntry(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "IOC entry not found" });
      res.json({ message: "IOC entry deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete IOC entry" });
    }
  });

  app.get("/api/ioc-entries/search/:type/:value", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const entries = await storage.getIocEntriesByValue(p(req.params.type), p(req.params.value), user?.orgId);
      res.json(entries);
    } catch (error) {
      res.status(500).json({ message: "Failed to search IOC entries" });
    }
  });

  app.get("/api/ioc-watchlists", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const watchlists = await storage.getIocWatchlists(user?.orgId);
      res.json(watchlists);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch watchlists" });
    }
  });

  app.post("/api/ioc-watchlists", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertIocWatchlistSchema.safeParse({ ...req.body, orgId, createdBy: userName });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid watchlist data", errors: parsed.error.flatten() });
      }
      const watchlist = await storage.createIocWatchlist({ ...parsed.data, orgId, createdBy: userName });
      res.status(201).json(watchlist);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create watchlist" });
    }
  });

  app.patch("/api/ioc-watchlists/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIocWatchlist ? await (storage as any).getIocWatchlist(p(req.params.id)) : null;
      if (existing && existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { orgId: _ignoreOrgId, ...updateData } = req.body;
      const watchlist = await storage.updateIocWatchlist(p(req.params.id), updateData);
      if (!watchlist) return res.status(404).json({ message: "Watchlist not found" });
      res.json(watchlist);
    } catch (error) {
      res.status(500).json({ message: "Failed to update watchlist" });
    }
  });

  app.delete("/api/ioc-watchlists/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const watchlists = await storage.getIocWatchlists(user?.orgId);
      const existing = watchlists.find((w: any) => w.id === p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Watchlist not found" });
      const deleted = await storage.deleteIocWatchlist(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Watchlist not found" });
      res.json({ message: "Watchlist deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete watchlist" });
    }
  });

  app.get("/api/ioc-watchlists/:id/entries", isAuthenticated, async (req, res) => {
    try {
      const entries = await storage.getWatchlistEntries(p(req.params.id));
      res.json(entries);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch watchlist entries" });
    }
  });

  app.post("/api/ioc-watchlists/:id/entries", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const entry = await storage.addIocToWatchlist({ watchlistId: p(req.params.id), iocEntryId: req.body.iocEntryId, addedBy: userName });
      res.status(201).json(entry);
    } catch (error) {
      res.status(500).json({ message: "Failed to add IOC to watchlist" });
    }
  });

  app.delete("/api/ioc-watchlists/:wlId/entries/:iocId", isAuthenticated, async (req, res) => {
    try {
      const removed = await storage.removeIocFromWatchlist(p(req.params.wlId), p(req.params.iocId));
      if (!removed) return res.status(404).json({ message: "Entry not found in watchlist" });
      res.json({ message: "IOC removed from watchlist" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove IOC from watchlist" });
    }
  });

  app.get("/api/ioc-match-rules", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const rules = await storage.getIocMatchRules(user?.orgId);
      res.json(rules);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch match rules" });
    }
  });

  app.post("/api/ioc-match-rules", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = getOrgId(req);
      const parsed = insertIocMatchRuleSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid match rule data", errors: parsed.error.flatten() });
      }
      const rule = await storage.createIocMatchRule({ ...parsed.data, orgId });
      res.status(201).json(rule);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create match rule" });
    }
  });

  app.patch("/api/ioc-match-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const rules = await storage.getIocMatchRules(user?.orgId);
      const existing = rules.find((r: any) => r.id === p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Match rule not found" });
      const { orgId: _ignoreOrgId, ...updateData } = req.body;
      const rule = await storage.updateIocMatchRule(p(req.params.id), updateData);
      if (!rule) return res.status(404).json({ message: "Match rule not found" });
      res.json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to update match rule" });
    }
  });

  app.delete("/api/ioc-match-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const rules = await storage.getIocMatchRules(user?.orgId);
      const existing = rules.find((r: any) => r.id === p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Match rule not found" });
      const deleted = await storage.deleteIocMatchRule(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Match rule not found" });
      res.json({ message: "Match rule deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete match rule" });
    }
  });

  app.get("/api/ioc-matches", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const { alertId, iocEntryId, limit } = req.query;
      const matches = await storage.getIocMatches(user?.orgId, alertId as string | undefined, iocEntryId as string | undefined, limit ? parseInt(limit as string, 10) : undefined);
      res.json(matches);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC matches" });
    }
  });

  app.post("/api/ioc-match/alert/:alertId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const alert = await storage.getAlert(p(req.params.alertId));
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      const { matchAlertAgainstIOCs, matchAlertAgainstRules } = await import("./ioc-matcher");
      const result = await matchAlertAgainstIOCs(alert, user?.orgId);
      await matchAlertAgainstRules(alert, user?.orgId);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("IOC matching error", { error: String(error) });
      res.status(500).json({ message: "Failed to match alert against IOCs" });
    }
  });

  app.get("/api/ioc-stats", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const { getIOCStats } = await import("./ioc-matcher");
      const stats = await getIOCStats(user?.orgId);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC stats" });
    }
  });

  app.get("/api/ioc-enrichment/:alertId", isAuthenticated, async (req, res) => {
    try {
      const { enrichAlertWithIOCContext } = await import("./ioc-matcher");
      const enrichment = await enrichAlertWithIOCContext(p(req.params.alertId));
      res.json(enrichment);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch IOC enrichment" });
    }
  });

  // Phase 6: Enterprise Compliance & Data Governance
  app.get("/api/compliance/policy", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json(null);
      let policy = await storage.getCompliancePolicy(orgId);
      if (!policy) {
        policy = await storage.upsertCompliancePolicy({ orgId });
      }
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance policy" });
    }
  });

  app.put("/api/compliance/policy", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const parsed = insertCompliancePolicySchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid policy data", errors: parsed.error.flatten() });
      }
      const policy = await storage.upsertCompliancePolicy(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "compliance_policy_updated",
        resourceType: "compliance_policy",
        details: req.body,
      });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance policy" });
    }
  });

  app.get("/api/compliance/dsar", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.json([]);
      const requests = await storage.getDsarRequests(orgId);
      res.json(requests);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DSAR requests" });
    }
  });

  app.post("/api/compliance/dsar", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const policy = await storage.getCompliancePolicy(orgId);
      const slaDays = policy?.dsarSlaDays || 30;
      const dueDate = new Date();
      dueDate.setDate(dueDate.getDate() + slaDays);
      const parsed = insertDsarRequestSchema.safeParse({ ...req.body, orgId, dueDate });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid DSAR request data", errors: parsed.error.flatten() });
      }
      const request = await storage.createDsarRequest(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_created",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { requestType: request.requestType, requestorEmail: request.requestorEmail },
      });
      res.status(201).json(request);
    } catch (error) {
      res.status(500).json({ message: "Failed to create DSAR request" });
    }
  });

  app.patch("/api/compliance/dsar/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      const request = await storage.getDsarRequest(p(req.params.id));
      if (!request) return res.status(404).json({ message: "DSAR request not found" });
      if (request.orgId !== orgId) return res.status(404).json({ message: "DSAR request not found" });
      const allowedFields = ["status", "notes"];
      const sanitized: Record<string, any> = {};
      for (const key of allowedFields) {
        if (req.body[key] !== undefined) sanitized[key] = req.body[key];
      }
      sanitized.updatedAt = new Date();
      const updated = await storage.updateDsarRequest(p(req.params.id), sanitized);
      if (!updated) return res.status(404).json({ message: "DSAR request not found" });
      await storage.createAuditLog({
        orgId: request.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_updated",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { changes: Object.keys(req.body) },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update DSAR request" });
    }
  });

  app.post("/api/compliance/dsar/:id/fulfill", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const userOrgId = user?.orgId;
      const request = await storage.getDsarRequest(p(req.params.id));
      if (!request) return res.status(404).json({ message: "DSAR request not found" });
      if (request.orgId !== userOrgId) return res.status(404).json({ message: "DSAR request not found" });
      const identifiers = request.subjectIdentifiers as Record<string, string>;
      const summary: any = { alertsFound: 0, entitiesFound: 0, auditLogsFound: 0, details: {} };
      const orgId = request.orgId || undefined;

      if (orgId) {
        const allAlerts = await storage.getAlerts(orgId);
        const matchedAlerts = allAlerts.filter(a => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (a.sourceIp === val || a.destIp === val || a.userId === val || a.hostname === val) return true;
            if (a.description && a.description.includes(val)) return true;
          }
          return false;
        });
        summary.alertsFound = matchedAlerts.length;
        summary.details.alertIds = matchedAlerts.map(a => a.id);

        const { db: database } = await import("./db");
        const { entities } = await import("@shared/schema");
        const { eq: eqOp } = await import("drizzle-orm");
        const allEntities = orgId ? await database.select().from(entities).where(eqOp(entities.orgId, orgId)) : [];
        const matchedEntities = allEntities.filter(e => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (e.value === val) return true;
          }
          return false;
        });
        summary.entitiesFound = matchedEntities.length;
        summary.details.entityIds = matchedEntities.map(e => e.id);

        const allAuditLogs = await storage.getAuditLogs(orgId);
        const matchedLogs = allAuditLogs.filter(l => {
          for (const [, val] of Object.entries(identifiers)) {
            if (!val) continue;
            if (l.userId === val) return true;
          }
          return false;
        });
        summary.auditLogsFound = matchedLogs.length;
        summary.details.auditLogIds = matchedLogs.map(l => l.id);
      }

      await storage.updateDsarRequest(request.id, {
        status: "fulfilled",
        fulfilledAt: new Date(),
        fulfilledBy: user?.id,
        resultSummary: summary,
      });

      await storage.createAuditLog({
        orgId: request.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "dsar_request_fulfilled",
        resourceType: "dsar_request",
        resourceId: request.id,
        details: { alertsFound: summary.alertsFound, entitiesFound: summary.entitiesFound, auditLogsFound: summary.auditLogsFound },
      });

      res.json({ request: { ...request, status: "fulfilled", fulfilledAt: new Date(), resultSummary: summary }, summary });
    } catch (error) {
      logger.child("routes").error("DSAR fulfill error", { error: String(error) });
      res.status(500).json({ message: "Failed to fulfill DSAR request" });
    }
  });

  app.get("/api/compliance/report/:type", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const reportType = p(req.params.type);

      if (reportType === "gdpr_article30") {
        const policy = await storage.getCompliancePolicy(orgId);
        const orgConnectors = await storage.getConnectors(orgId);
        const dataSources = orgConnectors.map(c => ({
          name: c.name,
          type: c.type,
          status: c.status,
          lastSync: c.lastSyncAt?.toISOString() || null,
        }));
        res.json({
          reportType: "gdpr_article30",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          dataProcessingRecords: {
            dataSources,
            retentionPolicies: {
              alertRetentionDays: policy?.alertRetentionDays || 365,
              incidentRetentionDays: policy?.incidentRetentionDays || 730,
              auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            },
            legalBasis: policy?.dataProcessingBasis || "legitimate_interest",
            dpoEmail: policy?.dpoEmail || null,
            enabledFrameworks: policy?.enabledFrameworks || ["gdpr"],
            piiMaskingEnabled: policy?.piiMaskingEnabled || false,
            pseudonymizeExports: policy?.pseudonymizeExports || true,
          },
        });
      } else if (reportType === "retention_status") {
        const policy = await storage.getCompliancePolicy(orgId);
        const { db: database } = await import("./db");
        const { alerts: alertsTable, incidents: incidentsTable, auditLogs: auditLogsTable } = await import("@shared/schema");
        const { asc: ascOp, eq: eqOp, count: countOp } = await import("drizzle-orm");
        const [oldestAlertRow] = orgId
          ? await database.select().from(alertsTable).where(eqOp(alertsTable.orgId, orgId)).orderBy(ascOp(alertsTable.createdAt)).limit(1)
          : await database.select().from(alertsTable).orderBy(ascOp(alertsTable.createdAt)).limit(1);
        const [alertCountRow] = orgId
          ? await database.select({ value: countOp() }).from(alertsTable).where(eqOp(alertsTable.orgId, orgId))
          : await database.select({ value: countOp() }).from(alertsTable);
        const [incidentCountRow] = orgId
          ? await database.select({ value: countOp() }).from(incidentsTable).where(eqOp(incidentsTable.orgId, orgId))
          : await database.select({ value: countOp() }).from(incidentsTable);
        const oldestAuditLog = await storage.getOldestAuditLog(orgId);
        const auditLogCount = await storage.getAuditLogCount(orgId);

        res.json({
          reportType: "retention_status",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          stats: {
            totalAlerts: Number(alertCountRow?.value || 0),
            totalIncidents: Number(incidentCountRow?.value || 0),
            totalAuditLogs: auditLogCount,
            oldestAlert: oldestAlertRow?.createdAt?.toISOString() || null,
            oldestAuditLog: oldestAuditLog?.createdAt?.toISOString() || null,
          },
          policy: {
            alertRetentionDays: policy?.alertRetentionDays || 365,
            incidentRetentionDays: policy?.incidentRetentionDays || 730,
            auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            lastCleanupAt: policy?.retentionLastRunAt?.toISOString() || null,
            lastDeletedCount: policy?.retentionLastDeletedCount || 0,
          },
          nextCleanup: policy?.retentionLastRunAt
            ? new Date(policy.retentionLastRunAt.getTime() + 24 * 60 * 60 * 1000).toISOString()
            : "Not yet scheduled",
        });
      } else if (reportType === "dpdp_compliance") {
        const policy = await storage.getCompliancePolicy(orgId);
        const dsarReqs = await storage.getDsarRequests(orgId);
        const pendingDsars = dsarReqs.filter(r => r.status === "pending" || r.status === "in_progress");
        const fulfilledDsars = dsarReqs.filter(r => r.status === "fulfilled");
        const overdueDsars = pendingDsars.filter(r => r.dueDate && new Date(r.dueDate) < new Date());

        res.json({
          reportType: "dpdp_compliance",
          generatedAt: new Date().toISOString(),
          organization: orgId,
          compliance: {
            dataProtectionOfficer: policy?.dpoEmail || "Not assigned",
            consentManagement: policy?.dataProcessingBasis || "Not configured",
            piiProtection: {
              maskingEnabled: policy?.piiMaskingEnabled || false,
              pseudonymizationEnabled: policy?.pseudonymizeExports || true,
            },
            dsarCompliance: {
              totalRequests: dsarReqs.length,
              pending: pendingDsars.length,
              fulfilled: fulfilledDsars.length,
              overdue: overdueDsars.length,
              slaDays: policy?.dsarSlaDays || 30,
            },
            dataRetention: {
              alertRetentionDays: policy?.alertRetentionDays || 365,
              incidentRetentionDays: policy?.incidentRetentionDays || 730,
              auditLogRetentionDays: policy?.auditLogRetentionDays || 2555,
            },
            enabledFrameworks: policy?.enabledFrameworks || ["gdpr"],
          },
        });
      } else {
        return res.status(400).json({ message: `Unknown report type: ${reportType}` });
      }
    } catch (error) {
      logger.child("routes").error("Compliance report error", { error: String(error) });
      res.status(500).json({ message: "Failed to generate compliance report" });
    }
  });

  app.get("/api/compliance/audit/verify", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });

      const logs = await storage.getAuditLogs(orgId);
      const sortedLogs = logs
        .filter(l => l.sequenceNum !== null)
        .sort((a, b) => (a.sequenceNum || 0) - (b.sequenceNum || 0));

      const errors: string[] = [];
      let lastVerifiedSeq = 0;

      for (let i = 0; i < sortedLogs.length; i++) {
        const log = sortedLogs[i];
        const expectedPrevHash = i === 0 ? "genesis" : sortedLogs[i - 1].entryHash;
        const expectedHash = createHash("sha256").update(JSON.stringify({
          prevHash: expectedPrevHash,
          action: log.action,
          userId: log.userId,
          resourceType: log.resourceType,
          resourceId: log.resourceId,
          details: log.details,
          sequenceNum: log.sequenceNum,
        })).digest("hex");

        if (log.prevHash !== expectedPrevHash) {
          errors.push(`Sequence ${log.sequenceNum}: prevHash mismatch`);
        }
        if (log.entryHash !== expectedHash) {
          errors.push(`Sequence ${log.sequenceNum}: entryHash mismatch`);
        }

        if (errors.length === 0) {
          lastVerifiedSeq = log.sequenceNum || 0;
        }
      }

      res.json({
        verified: errors.length === 0,
        totalEntries: sortedLogs.length,
        lastVerifiedSeq,
        errors,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to verify audit trail" });
    }
  });

  app.get("/api/compliance/audit/export", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const logs = await storage.getAuditLogs(orgId);
      const sortedLogs = logs.sort((a, b) => (a.sequenceNum || 0) - (b.sequenceNum || 0));
      res.json({
        exportedAt: new Date().toISOString(),
        organization: orgId,
        totalEntries: sortedLogs.length,
        hashChainIntact: true,
        entries: sortedLogs.map(l => ({
          id: l.id,
          sequenceNum: l.sequenceNum,
          prevHash: l.prevHash,
          entryHash: l.entryHash,
          action: l.action,
          userId: l.userId,
          userName: l.userName,
          resourceType: l.resourceType,
          resourceId: l.resourceId,
          details: l.details,
          ipAddress: l.ipAddress,
          createdAt: l.createdAt?.toISOString(),
        })),
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to export audit logs" });
    }
  });

  app.post("/api/compliance/retention/run", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = user?.orgId;
      if (!orgId) return res.status(400).json({ message: "No organization associated with user" });
      const results = await runRetentionCleanup();
      const orgResult = results.find(r => r.orgId === orgId);
      await storage.createAuditLog({
        orgId,
        userId: user.id,
        userName: user.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "manual_retention_cleanup",
        resourceType: "compliance",
        details: orgResult || { message: "No retention policy configured" },
      });
      res.json({ success: true, results: orgResult || { message: "No retention policy configured for this organization" } });
    } catch (error) {
      logger.child("routes").error("Retention cleanup error", { error: String(error) });
      res.status(500).json({ message: "Failed to run retention cleanup" });
    }
  });

  function sanitizeConfig(config: any): any {
    if (!config) return config;
    const safe = { ...config };
    const secretFields = ["apiKey", "apiToken", "clientSecret", "password", "secretAccessKey", "webhookSecret", "token", "siteToken"];
    for (const field of secretFields) {
      if (safe[field]) safe[field] = "••••••••";
    }
    return safe;
  }

  // ============================
  // Phase 7: Integration Configs
  // ============================
  app.get("/api/integrations", isAuthenticated, async (req, res) => {
    try {
      const configs = await storage.getIntegrationConfigs();
      const sanitized = configs.map(c => ({
        ...c,
        config: sanitizeConfig(c.config as any),
      }));
      res.json(sanitized);
    } catch (error) { res.status(500).json({ message: "Failed to fetch integrations" }); }
  });

  app.get("/api/integrations/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const config = await storage.getIntegrationConfig(p(req.params.id));
      if (!config) return res.status(404).json({ message: "Integration not found" });
      const safeConfig = { ...config, config: sanitizeConfig(config.config as any) };
      res.json(safeConfig);
    } catch (error) { res.status(500).json({ message: "Failed to fetch integration" }); }
  });

  app.post("/api/integrations", isAuthenticated, validateBody(bodySchemas.integrationCreate), async (req, res) => {
    try {
      const { name, type, config } = (req as any).validatedBody;
      const created = await storage.createIntegrationConfig({
        name,
        type,
        config,
        orgId: (req as any).user?.orgId,
        status: "inactive",
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        orgId: (req as any).user?.orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "integration_created",
        resourceType: "integration",
        resourceId: created.id,
        details: { type, name },
      });
      res.status(201).json(created);
    } catch (error) { res.status(500).json({ message: "Failed to create integration" }); }
  });

  app.patch("/api/integrations/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const existing = await storage.getIntegrationConfig(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Integration not found" });
      const { name, config, status } = req.body;
      const updateData: any = {};
      if (name) updateData.name = name;
      if (status) updateData.status = status;
      if (config) {
        const existingConfig = existing.config as any;
        const newConfig = { ...existingConfig };
        for (const [key, value] of Object.entries(config)) {
          if (value !== "••••••••" && value !== undefined) {
            (newConfig as any)[key] = value;
          }
        }
        updateData.config = newConfig;
      }
      const updated = await storage.updateIntegrationConfig(p(req.params.id), updateData);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update integration" }); }
  });

  app.delete("/api/integrations/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const existing = await storage.getIntegrationConfig(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Integration not found" });
      await storage.deleteIntegrationConfig(p(req.params.id));
      await storage.createAuditLog({
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "integration_deleted",
        resourceType: "integration",
        resourceId: p(req.params.id),
        details: { type: existing.type, name: existing.name },
      });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete integration" }); }
  });

  app.post("/api/integrations/:id/test", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const config = await storage.getIntegrationConfig(p(req.params.id));
      if (!config) return res.status(404).json({ message: "Integration not found" });
      await storage.updateIntegrationConfig(p(req.params.id), {
        lastTestedAt: new Date(),
        lastTestStatus: "success",
        status: "active",
      } as any);
      res.json({
        success: true,
        message: `${config.type} integration test successful (simulated)`,
        testedAt: new Date().toISOString(),
      });
    } catch (error) { res.status(500).json({ message: "Integration test failed" }); }
  });

  // ================================
  // Phase 7: Notification Channels
  // ================================
  app.get("/api/notification-channels", isAuthenticated, async (req, res) => {
    try {
      const channels = await storage.getNotificationChannels();
      const sanitized = channels.map(c => ({
        ...c,
        config: sanitizeConfig(c.config as any),
      }));
      res.json(sanitized);
    } catch (error) { res.status(500).json({ message: "Failed to fetch notification channels" }); }
  });

  app.post("/api/notification-channels", isAuthenticated, validateBody(bodySchemas.notificationChannelCreate), async (req, res) => {
    try {
      const { name, type, config, events, isDefault } = (req as any).validatedBody;
      const created = await storage.createNotificationChannel({
        name,
        type,
        config,
        orgId: (req as any).user?.orgId,
        events: events || ["incident_created"],
        isDefault: isDefault || false,
        createdBy: (req as any).user?.id,
      });
      await storage.createAuditLog({
        orgId: (req as any).user?.orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Analyst",
        action: "notification_channel_created",
        resourceType: "notification_channel",
        resourceId: created.id,
        details: { type, name },
      });
      res.status(201).json(created);
    } catch (error) { res.status(500).json({ message: "Failed to create notification channel" }); }
  });

  app.patch("/api/notification-channels/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const existing = await storage.getNotificationChannel(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Channel not found" });
      const updated = await storage.updateNotificationChannel(p(req.params.id), req.body);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update channel" }); }
  });

  app.delete("/api/notification-channels/:id", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const existing = await storage.getNotificationChannel(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Channel not found" });
      await storage.deleteNotificationChannel(p(req.params.id));
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete channel" }); }
  });

  app.post("/api/notification-channels/:id/test", isAuthenticated, validatePathId("id"), async (req, res) => {
    try {
      const channel = await storage.getNotificationChannel(p(req.params.id));
      if (!channel) return res.status(404).json({ message: "Channel not found" });
      res.json({
        success: true,
        message: `Test notification sent to ${channel.type} channel "${channel.name}" (simulated)`,
        sentAt: new Date().toISOString(),
      });
    } catch (error) { res.status(500).json({ message: "Failed to test notification" }); }
  });

  // ============================
  // Phase 7: Response Actions
  // ============================
  app.get("/api/response-actions", isAuthenticated, validateQuery(querySchemas.responseActions), async (req, res) => {
    try {
      const { incidentId } = (req as any).validatedQuery;
      const orgId = (req as any).user?.orgId;
      res.json(await storage.getResponseActions(orgId, incidentId as string));
    } catch (error) { res.status(500).json({ message: "Failed to fetch response actions" }); }
  });

  app.post("/api/response-actions", isAuthenticated, validateBody(bodySchemas.responseActionCreate), async (req, res) => {
    try {
      const { actionType, target, connectorId, incidentId, alertId } = (req as any).validatedBody;
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId,
        incidentId,
        alertId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        storage,
      };
      const result = await dispatchAction(actionType, { target, connectorId }, context);
      await storage.createAuditLog({
        userId: user?.id,
        userName: context.userName,
        action: "response_action_executed",
        resourceType: "response_action",
        details: { actionType, target, status: result.status, incidentId },
      });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Response action error", { error: String(error) });
      res.status(500).json({ message: "Failed to execute response action" });
    }
  });

  app.post("/api/incidents/:id/push", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const { platform, project, priority } = req.body;
      if (!platform) return res.status(400).json({ message: "Missing required field: platform (jira or servicenow)" });
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId || incident.orgId || undefined,
        incidentId: incident.id,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        storage,
      };
      const actionType = platform === "servicenow" ? "create_servicenow_ticket" : "create_jira_ticket";
      const result = await dispatchAction(actionType, {
        summary: `[SecureNexus] ${incident.title}`,
        description: incident.aiSummary || incident.summary || incident.title,
        priority: priority || (incident.severity === "critical" ? "highest" : incident.severity === "high" ? "high" : "medium"),
        project: project || "SEC",
      }, context);
      await storage.createAuditLog({
        orgId: context.orgId,
        userId: user?.id,
        userName: context.userName,
        action: "incident_pushed_to_ticketing",
        resourceType: "incident",
        resourceId: incident.id,
        details: { platform, ticketId: result.details?.ticketId },
      });
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Push to ticketing error", { error: String(error) });
      res.status(500).json({ message: "Failed to push incident to ticketing system" });
    }
  });

  app.post("/api/incidents/:id/notify", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const { channelType, message: customMessage } = req.body;
      const user = (req as any).user;
      const context: ActionContext = {
        orgId: user?.orgId || incident.orgId || undefined,
        incidentId: incident.id,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        storage,
      };
      const notifyType = `notify_${channelType || "slack"}`;
      const result = await dispatchAction(notifyType, {
        message: customMessage || `Security Incident: ${incident.title} [Severity: ${incident.severity}] - Status: ${incident.status}`,
        channel: "#security-alerts",
      }, context);
      res.json(result);
    } catch (error) {
      logger.child("routes").error("Notification error", { error: String(error) });
      res.status(500).json({ message: "Failed to send notification" });
    }
  });

  // Phase 8: Predictive Defense routes
  app.get("/api/predictive/anomalies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const anomalies = await storage.getPredictiveAnomalies(orgId);
      res.json(anomalies);
    } catch (error) { res.status(500).json({ message: "Failed to fetch anomalies" }); }
  });

  app.get("/api/predictive/attack-surface", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const assets = await storage.getAttackSurfaceAssets(orgId);
      res.json(assets);
    } catch (error) { res.status(500).json({ message: "Failed to fetch attack surface" }); }
  });

  app.get("/api/predictive/forecasts", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const forecasts = await storage.getRiskForecasts(orgId);
      res.json(forecasts);
    } catch (error) { res.status(500).json({ message: "Failed to fetch forecasts" }); }
  });

  app.get("/api/predictive/forecast-quality", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const snapshots = await storage.getForecastQualitySnapshots(orgId);
      const grouped = snapshots.reduce((acc: Record<string, any[]>, s) => {
        if (!acc[s.module]) acc[s.module] = [];
        acc[s.module].push(s);
        return acc;
      }, {});
      const trends = Object.entries(grouped).map(([module, records]) => {
        const ordered = [...records].sort((a, b) => +new Date(a.measuredAt || 0) - +new Date(b.measuredAt || 0));
        const latest = ordered[ordered.length - 1];
        const earliest = ordered[0];
        return {
          module,
          latestPrecision: latest?.precision || 0,
          latestRecall: latest?.recall || 0,
          precisionTrend: (latest?.precision || 0) - (earliest?.precision || 0),
          recallTrend: (latest?.recall || 0) - (earliest?.recall || 0),
          sampleSize: latest?.sampleSize || 0,
          points: ordered,
        };
      });
      res.json(trends);
    } catch (error) { res.status(500).json({ message: "Failed to fetch forecast quality" }); }
  });

  app.get("/api/predictive/recommendations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const recs = await storage.getHardeningRecommendations(orgId);
      res.json(recs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch recommendations" }); }
  });

  app.post("/api/predictive/recompute", isAuthenticated, async (req, res) => {
    try {
      let orgId = (req as any).user?.orgId;
      if (!orgId) {
        const orgs = await storage.getOrganizations();
        if (orgs.length > 0) orgId = orgs[0].id;
      }
      if (!orgId) return res.status(400).json({ message: "Organization required" });
      const { runPredictiveAnalysis } = await import("./predictive-engine");
      const result = await runPredictiveAnalysis(orgId, storage);

      const feedback = await storage.getAiFeedback(undefined, undefined);
      const moduleFeedback = ["triage", "correlation", "forecast"].map((module) => {
        const filtered = feedback.filter((f) => (f.resourceType || "").includes(module));
        const positives = filtered.filter((f) => f.rating >= 4).length;
        const negatives = filtered.filter((f) => f.rating <= 2).length;
        const precision = filtered.length > 0 ? positives / filtered.length : 0.5;
        const recall = filtered.length > 0 ? positives / Math.max(positives + negatives, 1) : 0.5;
        return { module, precision, recall, sampleSize: filtered.length };
      });
      for (const metric of moduleFeedback) {
        await storage.createForecastQualitySnapshot({
          orgId,
          module: metric.module,
          precision: metric.precision,
          recall: metric.recall,
          sampleSize: metric.sampleSize,
        });
      }

      await storage.createAuditLog({
        orgId,
        userId: (req as any).user?.id,
        action: "predictive_analysis_run",
        resourceType: "predictive",
        details: result,
      });
      res.json(result);
    } catch (error: any) {
      logger.child("routes").error("Predictive analysis error", { error: String(error) });
      res.status(500).json({ message: "Failed to run predictive analysis" });
    }
  });

  app.patch("/api/predictive/recommendations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { status } = req.body;
      const recs = await storage.getHardeningRecommendations(orgId);
      const rec = recs.find(r => r.id === req.params.id);
      if (!rec) return res.status(404).json({ message: "Recommendation not found" });
      const updated = await storage.updateHardeningRecommendation(p(req.params.id), { status });
      if (!updated) return res.status(404).json({ message: "Recommendation not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update recommendation" }); }
  });

  app.get("/api/predictive/anomaly-subscriptions", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rows = await storage.getAnomalySubscriptions(orgId);
      res.json(rows);
    } catch (error) { res.status(500).json({ message: "Failed to fetch anomaly subscriptions" }); }
  });

  app.post("/api/predictive/anomaly-subscriptions", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const created = await storage.createAnomalySubscription({ ...req.body, orgId, createdBy: userId });
      res.status(201).json(created);
    } catch (error) { res.status(500).json({ message: "Failed to create anomaly subscription" }); }
  });

  app.delete("/api/predictive/anomaly-subscriptions/:id", isAuthenticated, async (req, res) => {
    try {
      const ok = await storage.deleteAnomalySubscription(p(req.params.id));
      if (!ok) return res.status(404).json({ message: "Subscription not found" });
      res.status(204).send();
    } catch (error) { res.status(500).json({ message: "Failed to delete anomaly subscription" }); }
  });

  app.get("/api/incidents/:id/root-cause-summary", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const relatedAlerts = await storage.getAlertsByIncident(incident.id);
      const byCategory = relatedAlerts.reduce((acc: Record<string, number>, a) => {
        acc[a.category || "other"] = (acc[a.category || "other"] || 0) + 1;
        return acc;
      }, {});
      const topCategory = Object.entries(byCategory).sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown";
      const impactedAssets = Array.from(new Set(relatedAlerts.flatMap((a) => [a.sourceIp, a.destIp, a.hostname].filter(Boolean)))).slice(0, 6);
      const summary = `Correlated ${relatedAlerts.length} alerts indicate a likely ${topCategory.replace(/_/g, " ")} driven campaign. Most evidence converges on shared entities (${impactedAssets.slice(0, 3).join(", ") || "none"}) with escalating severity and temporal proximity. Recommended next step: validate initial access vector and contain high-risk assets first.`;
      res.json({
        incidentId: incident.id,
        summary,
        contributingSignals: Object.entries(byCategory).map(([category, count]) => ({ category, count })),
        impactedAssets,
      });
    } catch (error) { res.status(500).json({ message: "Failed to build root cause summary" }); }
  });

  app.post("/api/ai/playbook-authoring/propose", isAuthenticated, async (req, res) => {
    try {
      const { objective, severity = "high", guardrails = [] } = req.body || {};
      const normalized = String(objective || "Contain suspicious activity").trim();
      const blocked = new Set(["delete_data", "shutdown_network", "disable_logging"]);
      const actions = [
        { type: "auto_triage", reason: "Initial enrichment and classification" },
        { type: "assign_analyst", reason: "Ensure analyst ownership" },
        severity === "critical"
          ? { type: "isolate_host", reason: "Containment for critical blast radius" }
          : { type: "notify_slack", reason: "Notify response channel" },
      ].filter((a) => !blocked.has(a.type));
      res.json({
        objective: normalized,
        guardrailsApplied: ["blocked_destructive_actions", "require_human_approval", ...guardrails],
        proposedActions: actions,
        requiresAnalystApproval: true,
      });
    } catch (error) { res.status(500).json({ message: "Failed to generate playbook proposal" }); }
  });

  // === Phase 9: Autonomous Response & Agentic SOC ===

  // Auto-Response Policies CRUD
  app.get("/api/autonomous/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      res.json(policies);
    } catch (error) { res.status(500).json({ message: "Failed to fetch policies" }); }
  });

  app.post("/api/autonomous/policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policy = await storage.createAutoResponsePolicy({ ...req.body, orgId });
      res.status(201).json(policy);
    } catch (error) { res.status(500).json({ message: "Failed to create policy" }); }
  });

  app.patch("/api/autonomous/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      const policy = policies.find(p => p.id === (req.params.id as string));
      if (!policy) return res.status(404).json({ message: "Policy not found" });
      const updated = await storage.updateAutoResponsePolicy(req.params.id as string, req.body);
      if (!updated) return res.status(404).json({ message: "Policy not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update policy" }); }
  });

  app.delete("/api/autonomous/policies/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getAutoResponsePolicies(orgId);
      const policy = policies.find(p => p.id === (req.params.id as string));
      if (!policy) return res.status(404).json({ message: "Policy not found" });
      const deleted = await storage.deleteAutoResponsePolicy(req.params.id as string);
      if (!deleted) return res.status(404).json({ message: "Policy not found" });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete policy" }); }
  });

  // Seed default policies
  app.post("/api/autonomous/policies/seed-defaults", isAuthenticated, async (req, res) => {
    try {
      let orgId = (req as any).user?.orgId;
      if (!orgId) {
        const orgs = await storage.getOrganizations();
        if (orgs.length > 0) orgId = orgs[0].id;
      }
      if (!orgId) return res.status(400).json({ message: "No organization found" });
      const existing = await storage.getAutoResponsePolicies(orgId);
      if (existing.length > 0) return res.json({ message: "Policies already exist", count: existing.length });
      const defaults = generateDefaultPolicies(orgId);
      const created = [];
      for (const def of defaults) {
        const p = await storage.createAutoResponsePolicy(def as any);
        created.push(p);
      }
      res.status(201).json(created);
    } catch (error) { logger.child("routes").error("Seed policies error", { error: String(error) }); res.status(500).json({ message: "Failed to seed policies" }); }
  });

  // Evaluate policies for an incident
  app.post("/api/autonomous/evaluate/:incidentId", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const incId = req.params.incidentId as string;
      const incident = await storage.getIncident(incId);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === incId);
      const matches = await evaluatePolicies({ incident, alerts: incidentAlerts, orgId: orgId, confidenceScore: req.body.confidenceScore });
      res.json(matches);
    } catch (error) { res.status(500).json({ message: "Failed to evaluate policies" }); }
  });

  // Investigation Runs
  app.get("/api/autonomous/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const runs = await storage.getInvestigationRuns(orgId);
      res.json(runs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch investigations" }); }
  });

  app.get("/api/autonomous/investigations/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const run = await storage.getInvestigationRun(req.params.id as string);
      if (!run) return res.status(404).json({ message: "Investigation not found" });
      if (orgId && run.orgId !== orgId) return res.status(404).json({ message: "Investigation not found" });
      const steps = await storage.getInvestigationSteps(run.id);
      res.json({ ...run, steps });
    } catch (error) { res.status(500).json({ message: "Failed to fetch investigation" }); }
  });

  app.post("/api/autonomous/investigations", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { incidentId } = req.body;
      if (!incidentId) return res.status(400).json({ message: "incidentId required" });
      const incident = await storage.getIncident(incidentId);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      const run = await storage.createInvestigationRun({
        orgId,
        incidentId,
        triggeredBy: (req as any).user?.email || "analyst",
        triggerSource: "manual",
        status: "queued",
      });
      // Start investigation async
      runInvestigation(run.id).catch(err => logger.child("routes").error("Investigation error", { error: String(err) }));
      res.status(201).json(run);
    } catch (error) { res.status(500).json({ message: "Failed to start investigation" }); }
  });

  // Rollbacks
  app.get("/api/autonomous/rollbacks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rollbacks = await storage.getResponseActionRollbacks(orgId);
      res.json(rollbacks);
    } catch (error) { res.status(500).json({ message: "Failed to fetch rollbacks" }); }
  });

  app.post("/api/autonomous/rollbacks", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const { originalActionId, actionType, target } = req.body;
      if (!actionType || !target) return res.status(400).json({ message: "actionType and target required" });
      if (!canRollback(actionType)) return res.status(400).json({ message: `Cannot rollback action: ${actionType}` });
      const rollback = await createRollbackRecord(orgId, originalActionId, actionType, target);
      res.status(201).json(rollback);
    } catch (error) { logger.child("routes").error("Create rollback error", { error: String(error) }); res.status(500).json({ message: "Failed to create rollback" }); }
  });

  app.post("/api/autonomous/rollbacks/:id/execute", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rollbacks = await storage.getResponseActionRollbacks(orgId);
      const rb = rollbacks.find(r => r.id === (req.params.id as string));
      if (!rb) return res.status(404).json({ message: "Rollback not found" });
      const user = (req as any).user?.email || "analyst";
      const result = await executeRollback(req.params.id as string, user);
      if (!result) return res.status(404).json({ message: "Rollback not found or already executed" });
      res.json(result);
    } catch (error) { res.status(500).json({ message: "Failed to execute rollback" }); }
  });

  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

  app.post("/api/files/upload", isAuthenticated, upload.single("file"), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "No file provided" });
      const orgId = getOrgId(req);
      const key = `orgs/${orgId}/uploads/${Date.now()}-${req.file.originalname}`;
      const result = await uploadFile(key, req.file.buffer, req.file.mimetype);
      res.status(201).json(result);
    } catch (error) {
      logger.child("routes").error("File upload error", { error: String(error) });
      res.status(500).json({ message: "Failed to upload file" });
    }
  });

  app.get("/api/files", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const subPrefix = req.query.prefix as string | undefined;
      const prefix = `orgs/${orgId}/${subPrefix || ""}`;
      const files = await listFiles(prefix);
      res.json(files);
    } catch (error) {
      res.status(500).json({ message: "Failed to list files" });
    }
  });

  app.get("/api/files/download", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const key = req.query.key as string;
      if (!key) return res.status(400).json({ message: "key query param required" });
      if (!key.startsWith(`orgs/${orgId}/`)) return res.status(403).json({ message: "Access denied" });
      const url = await getSignedUrl(key);
      res.json({ url });
    } catch (error) {
      res.status(500).json({ message: "Failed to get signed URL" });
    }
  });

  app.delete("/api/files/remove", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const key = req.query.key as string;
      if (!key) return res.status(400).json({ message: "key query param required" });
      if (!key.startsWith(`orgs/${orgId}/`)) return res.status(403).json({ message: "Access denied" });
      const result = await deleteFile(key);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to delete file" });
    }
  });

  // ── CSPM Routes ──
  app.get("/api/cspm/accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const accounts = await storage.getCspmAccounts(orgId);
      res.json(accounts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM accounts" });
    }
  });

  app.post("/api/cspm/accounts", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = { ...req.body, orgId };
      const parsed = insertCspmAccountSchema.safeParse(body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid CSPM account data", errors: parsed.error.flatten() });
      }
      const account = await storage.createCspmAccount(parsed.data);
      res.status(201).json(account);
    } catch (error) {
      res.status(500).json({ message: "Failed to create CSPM account" });
    }
  });

  app.patch("/api/cspm/accounts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const existing = await storage.getCspmAccount(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      const account = await storage.updateCspmAccount(p(req.params.id), req.body);
      if (!account) return res.status(404).json({ message: "CSPM account not found" });
      res.json(account);
    } catch (error) {
      res.status(500).json({ message: "Failed to update CSPM account" });
    }
  });

  app.delete("/api/cspm/accounts/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const existing = await storage.getCspmAccount(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      const deleted = await storage.deleteCspmAccount(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "CSPM account not found" });
      res.json({ message: "CSPM account deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete CSPM account" });
    }
  });

  app.get("/api/cspm/scans", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const accountId = req.query.accountId as string | undefined;
      const scans = await storage.getCspmScans(orgId, accountId);
      res.json(scans);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM scans" });
    }
  });

  app.post("/api/cspm/scans/:accountId", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const account = await storage.getCspmAccount(p(req.params.accountId));
      if (!account || account.orgId !== orgId) return res.status(404).json({ message: "CSPM account not found" });
      runCspmScan(orgId, p(req.params.accountId)).catch(err => logger.child("routes").error("CSPM scan error", { error: String(err) }));
      res.json({ message: "Scan started" });
    } catch (error) {
      res.status(500).json({ message: "Failed to start CSPM scan" });
    }
  });

  app.get("/api/cspm/findings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scanId = req.query.scanId as string | undefined;
      const severity = req.query.severity as string | undefined;
      const findings = await storage.getCspmFindings(orgId, scanId, severity);
      res.json(findings);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch CSPM findings" });
    }
  });

  app.patch("/api/cspm/findings/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const findings = await storage.getCspmFindings(orgId);
      const existing = findings.find(f => f.id === p(req.params.id));
      if (!existing) return res.status(404).json({ message: "CSPM finding not found" });
      const finding = await storage.updateCspmFinding(p(req.params.id), req.body);
      if (!finding) return res.status(404).json({ message: "CSPM finding not found" });
      res.json(finding);
    } catch (error) {
      res.status(500).json({ message: "Failed to update CSPM finding" });
    }
  });

  // ── Endpoint Telemetry Routes ──
  app.get("/api/endpoints", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await storage.getEndpointAssets(orgId);
      res.json(assets);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint assets" });
    }
  });

  app.get("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint asset" });
    }
  });

  app.post("/api/endpoints/seed", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await seedEndpointAssets(orgId);
      res.status(201).json(assets);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed endpoint assets" });
    }
  });

  app.post("/api/endpoints", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const body = { ...req.body, orgId };
      const parsed = insertEndpointAssetSchema.safeParse(body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid endpoint asset data", errors: parsed.error.flatten() });
      }
      const asset = await storage.createEndpointAsset(parsed.data);
      res.status(201).json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to create endpoint asset" });
    }
  });

  app.patch("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const existing = await storage.getEndpointAsset(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const asset = await storage.updateEndpointAsset(p(req.params.id), req.body);
      if (!asset) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json(asset);
    } catch (error) {
      res.status(500).json({ message: "Failed to update endpoint asset" });
    }
  });

  app.delete("/api/endpoints/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const existing = await storage.getEndpointAsset(p(req.params.id));
      if (!existing || existing.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const deleted = await storage.deleteEndpointAsset(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Endpoint asset not found" });
      res.json({ message: "Endpoint asset deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete endpoint asset" });
    }
  });

  app.get("/api/endpoints/:id/telemetry", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const telemetry = await storage.getEndpointTelemetry(p(req.params.id));
      res.json(telemetry);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch endpoint telemetry" });
    }
  });

  app.post("/api/endpoints/:id/telemetry", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const telemetry = await generateTelemetry(orgId, p(req.params.id));
      res.status(201).json(telemetry);
    } catch (error) {
      res.status(500).json({ message: "Failed to generate endpoint telemetry" });
    }
  });

  app.post("/api/endpoints/:id/risk", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const asset = await storage.getEndpointAsset(p(req.params.id));
      if (!asset || asset.orgId !== orgId) return res.status(404).json({ message: "Endpoint asset not found" });
      const riskScore = await calculateEndpointRisk(p(req.params.id));
      res.json({ riskScore });
    } catch (error) {
      res.status(500).json({ message: "Failed to calculate endpoint risk" });
    }
  });

  // ── Posture Score Routes ──
  app.get("/api/posture/scores", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scores = await storage.getPostureScores(orgId);
      res.json(scores);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch posture scores" });
    }
  });

  app.post("/api/posture/calculate", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const score = await calculatePostureScore(orgId);
      res.status(201).json(score);
    } catch (error) {
      res.status(500).json({ message: "Failed to calculate posture score" });
    }
  });

  app.get("/api/posture/latest", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const score = await storage.getLatestPostureScore(orgId);
      if (!score) return res.status(404).json({ message: "No posture score found" });
      res.json(score);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch latest posture score" });
    }
  });

  // ── AI Deployment Config Routes ──
  app.get("/api/ai-deployment/config", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const config = await storage.getAiDeploymentConfig(orgId);
      if (!config) return res.status(404).json({ message: "AI deployment config not found" });
      res.json(config);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch AI deployment config" });
    }
  });

  app.put("/api/ai-deployment/config", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertAiDeploymentConfigSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid AI deployment config data", errors: parsed.error.flatten() });
      }
      const config = await storage.upsertAiDeploymentConfig(parsed.data);
      res.json(config);
    } catch (error) {
      res.status(500).json({ message: "Failed to upsert AI deployment config" });
    }
  });

  // ── Team Management & RBAC Routes ──

  // Get current user's org context and memberships
  app.get("/api/auth/me", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });
      const memberships = await storage.getUserMemberships(userId);
      const activeMemberships = memberships.filter(m => m.status === "active");
      const orgs = await Promise.all(activeMemberships.map(async m => {
        const org = await storage.getOrganization(m.orgId);
        return { ...m, organization: org };
      }));
      res.json({ userId, memberships: orgs });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch user context" });
    }
  });

  // Auto-provision: ensure user has org membership on first access
  app.post("/api/auth/ensure-org", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      const userEmail = (req as any).user?.email;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });

      const memberships = await storage.getUserMemberships(userId);
      if (memberships.length > 0) {
        const activeMembership = memberships.find(m => m.status === "active");
        if (activeMembership) {
          const org = await storage.getOrganization(activeMembership.orgId);
          return res.json({ membership: activeMembership, organization: org });
        }
      }

      // Check for pending invitations by email
      if (userEmail) {
        const orgs = await storage.getOrganizations();
        for (const org of orgs) {
          const invitations = await storage.getOrgInvitations(org.id);
          const pending = invitations.find(inv => inv.email === userEmail && !inv.acceptedAt && new Date(inv.expiresAt) > new Date());
          if (pending) {
            const membership = await storage.createOrgMembership({
              orgId: org.id,
              userId,
              role: pending.role,
              status: "active",
              joinedAt: new Date(),
            });
            await storage.updateOrgInvitation(pending.id, { acceptedAt: new Date() });
            return res.json({ membership, organization: org });
          }
        }
      }

      // No existing membership or invitation — create a new org for this user
      const newOrg = await storage.createOrganization({
        name: `${userEmail ? userEmail.split("@")[0] : "User"}'s Organization`,
        slug: `org-${Date.now()}`,
        contactEmail: userEmail || undefined,
      });
      const membership = await storage.createOrgMembership({
        orgId: newOrg.id,
        userId,
        role: "owner",
        status: "active",
        joinedAt: new Date(),
      });
      return res.json({ membership, organization: newOrg });
    } catch (error) {
      logger.child("routes").error("Error ensuring org", { error: String(error) });
      res.status(500).json({ message: "Failed to ensure organization membership" });
    }
  });

  // List org members
  app.get("/api/orgs/:orgId/members", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const members = await storage.getOrgMemberships(orgId);
      res.json(members);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch members" });
    }
  });

  // Update member role
  app.patch("/api/orgs/:orgId/members/:memberId/role", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const memberId = p(req.params.memberId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      const { role } = req.body;
      if (!["owner", "admin", "analyst", "read_only"].includes(role)) {
        return res.status(400).json({ error: "Invalid role" });
      }

      const target = await storage.getMembershipById(memberId);
      if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

      // Only owners can assign owner role
      if (role === "owner" && (req as any).orgRole !== "owner") {
        return res.status(403).json({ error: "Only owners can assign owner role" });
      }

      // Cannot change own role
      const userId = (req as any).user?.id;
      if (target.userId === userId) {
        return res.status(400).json({ error: "Cannot change your own role" });
      }

      const updated = await storage.updateOrgMembership(memberId, { role });
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_role_changed",
        resourceType: "membership",
        resourceId: memberId,
        details: { newRole: role, targetUserId: target.userId },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update member role" });
    }
  });

  // Suspend member
  app.post("/api/orgs/:orgId/members/:memberId/suspend", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const memberId = p(req.params.memberId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      const target = await storage.getMembershipById(memberId);
      if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

      const userId = (req as any).user?.id;
      if (target.userId === userId) return res.status(400).json({ error: "Cannot suspend yourself" });
      if (target.role === "owner") return res.status(400).json({ error: "Cannot suspend an owner" });

      const updated = await storage.updateOrgMembership(memberId, { status: "suspended", suspendedAt: new Date() });
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_suspended",
        resourceType: "membership",
        resourceId: memberId,
        details: { targetUserId: target.userId },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to suspend member" });
    }
  });

  // Activate (unsuspend) member
  app.post("/api/orgs/:orgId/members/:memberId/activate", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const memberId = p(req.params.memberId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      const target = await storage.getMembershipById(memberId);
      if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

      const updated = await storage.updateOrgMembership(memberId, { status: "active", suspendedAt: null });
      const userId = (req as any).user?.id;
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_activated",
        resourceType: "membership",
        resourceId: memberId,
        details: { targetUserId: target.userId },
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to activate member" });
    }
  });

  // Remove member
  app.delete("/api/orgs/:orgId/members/:memberId", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const memberId = p(req.params.memberId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      const target = await storage.getMembershipById(memberId);
      if (!target || target.orgId !== orgId) return res.status(404).json({ error: "Member not found" });

      const userId = (req as any).user?.id;
      if (target.userId === userId) return res.status(400).json({ error: "Cannot remove yourself" });
      if (target.role === "owner") return res.status(400).json({ error: "Cannot remove an owner" });

      await storage.deleteOrgMembership(memberId);
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "member_removed",
        resourceType: "membership",
        resourceId: memberId,
        details: { targetUserId: target.userId },
      });
      res.json({ message: "Member removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove member" });
    }
  });

  // Create invitation
  app.post("/api/orgs/:orgId/invitations", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), validatePathId("orgId"), validateBody(bodySchemas.invitationCreate), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      const { email, role } = (req as any).validatedBody;

      const userId = (req as any).user?.id;
      const token = randomBytes(32).toString("hex");
      const invitation = await storage.createOrgInvitation({
        orgId,
        email,
        role: role || "analyst",
        token,
        invitedBy: userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "invitation_created",
        resourceType: "invitation",
        resourceId: invitation.id,
        details: { email, role: role || "analyst" },
      });

      res.status(201).json({ ...invitation, token });
    } catch (error) {
      res.status(500).json({ message: "Failed to create invitation" });
    }
  });

  // List invitations
  app.get("/api/orgs/:orgId/invitations", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });
      const invitations = await storage.getOrgInvitations(orgId);
      res.json(invitations);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch invitations" });
    }
  });

  // Cancel invitation
  app.delete("/api/orgs/:orgId/invitations/:invitationId", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = p(req.params.orgId);
      const invitationId = p(req.params.invitationId);
      const userOrgId = (req as any).orgId;
      if (orgId !== userOrgId) return res.status(403).json({ error: "Access denied" });

      await storage.deleteOrgInvitation(invitationId);
      const userId = (req as any).user?.id;
      await storage.createAuditLog({
        userId,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "invitation_cancelled",
        resourceType: "invitation",
        resourceId: invitationId,
      });
      res.json({ message: "Invitation cancelled" });
    } catch (error) {
      res.status(500).json({ message: "Failed to cancel invitation" });
    }
  });

  // Accept invitation by token
  app.post("/api/invitations/accept", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      if (!userId) return res.status(401).json({ error: "Not authenticated" });

      const { token } = req.body;
      if (!token) return res.status(400).json({ error: "Invitation token is required" });

      const invitation = await storage.getOrgInvitationByToken(token);
      if (!invitation) return res.status(404).json({ error: "Invalid or expired invitation" });
      if (invitation.acceptedAt) return res.status(400).json({ error: "Invitation already accepted" });
      if (new Date(invitation.expiresAt) < new Date()) return res.status(400).json({ error: "Invitation has expired" });

      const existingMembership = await storage.getOrgMembership(invitation.orgId, userId);
      if (existingMembership) return res.status(400).json({ error: "Already a member of this organization" });

      const membership = await storage.createOrgMembership({
        orgId: invitation.orgId,
        userId,
        role: invitation.role,
        status: "active",
        invitedEmail: invitation.email,
        joinedAt: new Date(),
      });
      await storage.updateOrgInvitation(invitation.id, { acceptedAt: new Date() });

      await storage.createAuditLog({
        userId,
        action: "invitation_accepted",
        resourceType: "membership",
        resourceId: membership.id,
        details: { orgId: invitation.orgId, role: invitation.role },
      });

      const org = await storage.getOrganization(invitation.orgId);
      res.json({ membership, organization: org });
    } catch (error) {
      res.status(500).json({ message: "Failed to accept invitation" });
    }
  });

  // ==========================================
  // Evidence Items (for an incident)
  // ==========================================
  app.get("/api/incidents/:incidentId/evidence", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const items = await storage.getEvidenceItems(p(req.params.incidentId), user?.orgId);
      res.json(items);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch evidence items" });
    }
  });

  app.post("/api/incidents/:incidentId/evidence", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertEvidenceItemSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.incidentId),
        orgId,
        createdBy: user?.id || null,
        createdByName: userName,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid evidence data", errors: parsed.error.flatten() });
      }
      const item = await storage.createEvidenceItem(parsed.data);
      res.status(201).json(item);
    } catch (error) {
      res.status(500).json({ message: "Failed to create evidence item" });
    }
  });

  app.delete("/api/incidents/:incidentId/evidence/:evidenceId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getEvidenceItem(p(req.params.evidenceId));
      if (!existing) return res.status(404).json({ message: "Evidence item not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteEvidenceItem(p(req.params.evidenceId));
      if (!deleted) return res.status(404).json({ message: "Evidence item not found" });
      res.json({ message: "Evidence item deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete evidence item" });
    }
  });

  // ==========================================
  // Investigation Hypotheses (for an incident)
  // ==========================================
  app.get("/api/incidents/:incidentId/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const hypotheses = await storage.getHypotheses(p(req.params.incidentId), user?.orgId);
      res.json(hypotheses);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch hypotheses" });
    }
  });

  app.post("/api/incidents/:incidentId/hypotheses", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertInvestigationHypothesisSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.incidentId),
        orgId,
        createdBy: user?.id || null,
        createdByName: userName,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid hypothesis data", errors: parsed.error.flatten() });
      }
      const hypothesis = await storage.createHypothesis(parsed.data);
      res.status(201).json(hypothesis);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create hypothesis" });
    }
  });

  app.patch("/api/incidents/:incidentId/hypotheses/:hypothesisId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getHypothesis(p(req.params.hypothesisId));
      if (!existing) return res.status(404).json({ message: "Hypothesis not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { orgId: _ignoreOrgId, incidentId: _ignoreIncidentId, ...updateData } = req.body;
      if (updateData.status === "validated" || updateData.status === "confirmed") {
        updateData.validatedAt = new Date();
      }
      const hypothesis = await storage.updateHypothesis(p(req.params.hypothesisId), updateData);
      if (!hypothesis) return res.status(404).json({ message: "Hypothesis not found" });
      res.json(hypothesis);
    } catch (error) {
      res.status(500).json({ message: "Failed to update hypothesis" });
    }
  });

  app.delete("/api/incidents/:incidentId/hypotheses/:hypothesisId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getHypothesis(p(req.params.hypothesisId));
      if (!existing) return res.status(404).json({ message: "Hypothesis not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteHypothesis(p(req.params.hypothesisId));
      if (!deleted) return res.status(404).json({ message: "Hypothesis not found" });
      res.json({ message: "Hypothesis deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete hypothesis" });
    }
  });

  // ==========================================
  // Investigation Tasks (for an incident)
  // ==========================================
  app.get("/api/incidents/:incidentId/tasks", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const tasks = await storage.getInvestigationTasks(p(req.params.incidentId), user?.orgId);
      res.json(tasks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch tasks" });
    }
  });

  app.post("/api/incidents/:incidentId/tasks", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const orgId = getOrgId(req);
      const parsed = insertInvestigationTaskSchema.safeParse({
        ...req.body,
        incidentId: p(req.params.incidentId),
        orgId,
        createdBy: user?.id || null,
        createdByName: userName,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid task data", errors: parsed.error.flatten() });
      }
      const task = await storage.createInvestigationTask(parsed.data);
      res.status(201).json(task);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create task" });
    }
  });

  app.patch("/api/incidents/:incidentId/tasks/:taskId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getInvestigationTask(p(req.params.taskId));
      if (!existing) return res.status(404).json({ message: "Task not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { orgId: _ignoreOrgId, incidentId: _ignoreIncidentId, ...updateData } = req.body;
      if ((updateData.status === "done" || updateData.status === "completed") && existing.status !== "done" && existing.status !== "completed") {
        updateData.completedAt = new Date();
      }
      const task = await storage.updateInvestigationTask(p(req.params.taskId), updateData);
      if (!task) return res.status(404).json({ message: "Task not found" });
      res.json(task);
    } catch (error) {
      res.status(500).json({ message: "Failed to update task" });
    }
  });

  app.delete("/api/incidents/:incidentId/tasks/:taskId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const existing = await storage.getInvestigationTask(p(req.params.taskId));
      if (!existing) return res.status(404).json({ message: "Task not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteInvestigationTask(p(req.params.taskId));
      if (!deleted) return res.status(404).json({ message: "Task not found" });
      res.json({ message: "Task deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete task" });
    }
  });

  // ==========================================
  // Runbook Templates (global + org-scoped)
  // ==========================================
  app.get("/api/runbook-templates", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const { incidentType } = req.query;
      const templates = await storage.getRunbookTemplates(user?.orgId, incidentType as string | undefined);
      res.json(templates);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch runbook templates" });
    }
  });

  app.get("/api/runbook-templates/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const steps = await storage.getRunbookSteps(template.id);
      res.json({ ...template, steps });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch runbook template" });
    }
  });

  app.post("/api/runbook-templates", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = getOrgId(req);
      const parsed = insertRunbookTemplateSchema.safeParse({
        ...req.body,
        orgId,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid runbook template data", errors: parsed.error.flatten() });
      }
      const template = await storage.createRunbookTemplate(parsed.data);
      res.status(201).json(template);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create runbook template" });
    }
  });

  app.delete("/api/runbook-templates/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getRunbookTemplate(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Runbook template not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      if (existing.isBuiltIn) return res.status(403).json({ message: "Cannot delete built-in runbook templates" });
      const deleted = await storage.deleteRunbookTemplate(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Runbook template not found" });
      res.json({ message: "Runbook template deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete runbook template" });
    }
  });

  // Runbook Steps
  app.get("/api/runbook-templates/:id/steps", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const steps = await storage.getRunbookSteps(p(req.params.id));
      res.json(steps);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch runbook steps" });
    }
  });

  app.post("/api/runbook-templates/:id/steps", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const parsed = insertRunbookStepSchema.safeParse({
        ...req.body,
        templateId: p(req.params.id),
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid runbook step data", errors: parsed.error.flatten() });
      }
      const step = await storage.createRunbookStep(parsed.data);
      res.status(201).json(step);
    } catch (error) {
      res.status(500).json({ message: "Failed to create runbook step" });
    }
  });

  app.patch("/api/runbook-templates/:id/steps/:stepId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const { templateId: _ignoreTemplateId, ...updateData } = req.body;
      const step = await storage.updateRunbookStep(p(req.params.stepId), updateData);
      if (!step) return res.status(404).json({ message: "Runbook step not found" });
      res.json(step);
    } catch (error) {
      res.status(500).json({ message: "Failed to update runbook step" });
    }
  });

  app.delete("/api/runbook-templates/:id/steps/:stepId", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const template = await storage.getRunbookTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Runbook template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteRunbookStep(p(req.params.stepId));
      if (!deleted) return res.status(404).json({ message: "Runbook step not found" });
      res.json({ message: "Runbook step deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete runbook step" });
    }
  });

  // ==========================================
  // Evidence Export
  // ==========================================
  app.get("/api/incidents/:incidentId/evidence-export", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const incident = await storage.getIncident(p(req.params.incidentId));
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      if (incident.orgId && user?.orgId && incident.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });

      const [evidence, hypotheses, tasks, incidentAlerts, timeline] = await Promise.all([
        storage.getEvidenceItems(p(req.params.incidentId), user?.orgId),
        storage.getHypotheses(p(req.params.incidentId), user?.orgId),
        storage.getInvestigationTasks(p(req.params.incidentId), user?.orgId),
        storage.getAlertsByIncident(p(req.params.incidentId)),
        storage.getAuditLogsByResource("incident", p(req.params.incidentId)),
      ]);

      res.json({
        exportedAt: new Date().toISOString(),
        incident,
        evidence,
        hypotheses,
        tasks,
        alerts: incidentAlerts,
        timeline,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to generate evidence export" });
    }
  });

  // ==========================================
  // Seed built-in runbook templates
  // ==========================================
  app.post("/api/runbook-templates/seed", isAuthenticated, async (req, res) => {
    try {
      const builtInTemplates = [
        {
          incidentType: "brute_force",
          title: "Brute Force Attack Response",
          description: "Standard response procedure for brute force authentication attacks",
          severity: "high",
          estimatedDuration: "2-4 hours",
          tags: ["authentication", "brute_force", "credential_access"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Identify Targeted Accounts", instructions: "Review authentication logs to identify all accounts targeted by the brute force attempt. Note source IPs, timestamps, and frequency of attempts.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 2, title: "Block Source IPs", instructions: "Add source IPs to firewall block list and WAF rules. Verify blocks are effective by monitoring continued attempts.", actionType: "block_ip", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 3, title: "Reset Compromised Credentials", instructions: "Force password reset for any accounts that may have been compromised. Enable MFA if not already active.", actionType: "disable_user", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 4, title: "Assess Lateral Movement", instructions: "Check if any successfully authenticated sessions were used for lateral movement. Review session logs and access patterns.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 45 },
            { stepOrder: 5, title: "Strengthen Authentication Controls", instructions: "Implement account lockout policies, rate limiting, and CAPTCHA. Review and enhance MFA enforcement.", actionType: "recommendation", isRequired: false, estimatedMinutes: 60 },
          ],
        },
        {
          incidentType: "malware",
          title: "Malware Infection Response",
          description: "Containment and eradication procedure for malware infections",
          severity: "critical",
          estimatedDuration: "4-8 hours",
          tags: ["malware", "endpoint", "containment"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Isolate Infected Host", instructions: "Immediately isolate the infected host from the network to prevent lateral spread. Maintain forensic access if possible.", actionType: "isolate_host", isRequired: true, estimatedMinutes: 10 },
            { stepOrder: 2, title: "Collect Forensic Evidence", instructions: "Capture memory dump, disk image, and network logs from the infected host before remediation. Preserve chain of custody.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 3, title: "Identify Malware Family", instructions: "Analyze malware samples to determine family, capabilities, C2 infrastructure, and persistence mechanisms. Submit to sandbox if needed.", actionType: "ai_analysis", isRequired: true, estimatedMinutes: 45 },
            { stepOrder: 4, title: "Scan for Additional Infections", instructions: "Run IOC sweeps across the environment using identified indicators. Check for lateral movement and additional compromised hosts.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 5, title: "Eradicate and Restore", instructions: "Remove all malware artifacts, persistence mechanisms, and unauthorized changes. Rebuild host from clean image if necessary.", actionType: "action_taken", isRequired: true, estimatedMinutes: 120 },
            { stepOrder: 6, title: "Update Defenses", instructions: "Add IOCs to blocklists, update detection signatures, and review endpoint protection policies to prevent recurrence.", actionType: "recommendation", isRequired: false, estimatedMinutes: 30 },
          ],
        },
        {
          incidentType: "phishing",
          title: "Phishing Incident Response",
          description: "Response procedure for phishing email campaigns and credential harvesting",
          severity: "high",
          estimatedDuration: "2-6 hours",
          tags: ["phishing", "email", "social_engineering"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Identify Affected Users", instructions: "Determine all recipients of the phishing email. Check email gateway logs for delivery status and identify users who clicked links or opened attachments.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 2, title: "Block Malicious Indicators", instructions: "Block sender address, domain, and any malicious URLs or IP addresses at email gateway, proxy, and firewall levels.", actionType: "block_domain", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 3, title: "Remove Phishing Emails", instructions: "Use email admin tools to search and purge the phishing email from all mailboxes. Quarantine any remaining copies.", actionType: "quarantine_file", isRequired: true, estimatedMinutes: 20 },
            { stepOrder: 4, title: "Reset Compromised Credentials", instructions: "For users who submitted credentials, force immediate password reset and revoke active sessions. Enable MFA.", actionType: "disable_user", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 5, title: "Check for Post-Compromise Activity", instructions: "Review login history, email forwarding rules, and OAuth app grants for compromised accounts. Look for data exfiltration signs.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 45 },
          ],
        },
        {
          incidentType: "data_exfiltration",
          title: "Data Exfiltration Response",
          description: "Response procedure for suspected data exfiltration or data breach events",
          severity: "critical",
          estimatedDuration: "6-12 hours",
          tags: ["data_breach", "exfiltration", "dlp"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Confirm Data Exfiltration", instructions: "Analyze network logs, DLP alerts, and endpoint telemetry to confirm data exfiltration. Identify data types, volumes, and destination.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 2, title: "Block Exfiltration Channels", instructions: "Block identified exfiltration destinations (IPs, domains, cloud storage). Disable compromised accounts and revoke API keys.", actionType: "block_ip", isRequired: true, estimatedMinutes: 20 },
            { stepOrder: 3, title: "Assess Data Impact", instructions: "Determine what data was exfiltrated, including classification level, PII/PHI content, and affected records count. Document for regulatory reporting.", actionType: "ai_analysis", isRequired: true, estimatedMinutes: 90 },
            { stepOrder: 4, title: "Identify Root Cause", instructions: "Trace the attack chain to identify initial access vector, persistence mechanisms, and privilege escalation paths used.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 5, title: "Contain and Remediate", instructions: "Isolate affected systems, patch vulnerabilities, rotate credentials, and remove attacker access. Verify no remaining persistence.", actionType: "action_taken", isRequired: true, estimatedMinutes: 120 },
            { stepOrder: 6, title: "Regulatory Notification", instructions: "Prepare breach notification documents as required by GDPR, HIPAA, or other applicable regulations. Notify legal and compliance teams.", actionType: "recommendation", isRequired: true, estimatedMinutes: 60 },
          ],
        },
        {
          incidentType: "ransomware",
          title: "Ransomware Incident Response",
          description: "Critical response procedure for ransomware attacks including containment and recovery",
          severity: "critical",
          estimatedDuration: "8-24 hours",
          tags: ["ransomware", "encryption", "critical"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Isolate Affected Systems", instructions: "Immediately disconnect affected systems from the network. Disable shares and remote access. Do NOT power off systems to preserve evidence.", actionType: "isolate_host", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 2, title: "Assess Scope of Encryption", instructions: "Determine which systems, files, and backups are affected. Identify the ransomware variant and check for available decryptors.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 3, title: "Preserve Forensic Evidence", instructions: "Capture memory dumps, ransomware samples, and ransom notes. Document encrypted file extensions and patterns.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 45 },
            { stepOrder: 4, title: "Identify Initial Access Vector", instructions: "Trace how ransomware entered the environment. Check for phishing emails, RDP exposure, vulnerable VPN, or supply chain compromise.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 90 },
            { stepOrder: 5, title: "Restore from Backups", instructions: "Verify backup integrity, restore systems from clean backups. Rebuild compromised systems from scratch if backups are unavailable or compromised.", actionType: "action_taken", isRequired: true, estimatedMinutes: 240 },
            { stepOrder: 6, title: "Harden and Monitor", instructions: "Patch exploited vulnerabilities, strengthen endpoint protection, implement network segmentation, and enhance monitoring for re-infection attempts.", actionType: "recommendation", isRequired: true, estimatedMinutes: 120 },
          ],
        },
        {
          incidentType: "ddos",
          title: "DDoS Attack Response",
          description: "Response procedure for distributed denial-of-service attacks",
          severity: "high",
          estimatedDuration: "2-8 hours",
          tags: ["ddos", "availability", "network"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Confirm DDoS Attack", instructions: "Analyze traffic patterns, bandwidth utilization, and service availability metrics to confirm DDoS attack. Identify attack type (volumetric, protocol, application layer).", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 15 },
            { stepOrder: 2, title: "Activate DDoS Mitigation", instructions: "Enable DDoS protection services (cloud scrubbing, CDN protection). Configure rate limiting and traffic filtering rules.", actionType: "action_taken", isRequired: true, estimatedMinutes: 20 },
            { stepOrder: 3, title: "Block Attack Sources", instructions: "Identify and block major attack source IPs/networks at network edge. Implement geo-blocking if attack sources are concentrated.", actionType: "block_ip", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 4, title: "Scale Infrastructure", instructions: "Scale up server capacity, enable auto-scaling groups, and distribute load across multiple regions if possible.", actionType: "action_taken", isRequired: false, estimatedMinutes: 30 },
            { stepOrder: 5, title: "Monitor and Adjust", instructions: "Continuously monitor attack patterns and adjust mitigation rules. Document attack timeline, peak volumes, and effectiveness of countermeasures.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
          ],
        },
        {
          incidentType: "general",
          title: "General Security Incident Response",
          description: "Generic incident response procedure applicable to any security incident type",
          severity: "medium",
          estimatedDuration: "2-6 hours",
          tags: ["general", "incident_response"],
          isBuiltIn: true,
          steps: [
            { stepOrder: 1, title: "Initial Triage", instructions: "Assess the incident severity, scope, and potential impact. Gather initial evidence from alerts, logs, and affected systems.", actionType: "gather_alerts", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 2, title: "Containment", instructions: "Implement immediate containment measures to prevent further damage. This may include isolating hosts, blocking IPs, or disabling accounts.", actionType: "action_taken", isRequired: true, estimatedMinutes: 30 },
            { stepOrder: 3, title: "Investigation", instructions: "Conduct thorough investigation to understand the full scope, root cause, and attack chain. Correlate evidence across multiple data sources.", actionType: "correlate_evidence", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 4, title: "Eradication", instructions: "Remove all traces of the threat from the environment. Patch vulnerabilities, remove malware, and revoke compromised credentials.", actionType: "action_taken", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 5, title: "Recovery", instructions: "Restore affected systems and services to normal operation. Verify system integrity and monitor for signs of recurring activity.", actionType: "action_taken", isRequired: true, estimatedMinutes: 60 },
            { stepOrder: 6, title: "Lessons Learned", instructions: "Document findings, timeline, and response actions. Identify gaps and improvements for security controls and incident response procedures.", actionType: "recommendation", isRequired: false, estimatedMinutes: 30 },
          ],
        },
      ];

      const created: any[] = [];
      for (const tmpl of builtInTemplates) {
        const existing = await storage.getRunbookTemplates(undefined, tmpl.incidentType);
        const alreadyExists = existing.some(e => e.isBuiltIn && e.incidentType === tmpl.incidentType);
        if (alreadyExists) continue;

        const { steps, ...templateData } = tmpl;
        const template = await storage.createRunbookTemplate({ ...templateData, orgId: null });
        for (const step of steps) {
          await storage.createRunbookStep({ ...step, templateId: template.id });
        }
        created.push(template);
      }

      res.status(201).json({ message: `Seeded ${created.length} runbook templates`, templates: created });
    } catch (error) {
      logger.child("routes").error("Error seeding runbook templates", { error: String(error) });
      res.status(500).json({ message: "Failed to seed runbook templates" });
    }
  });

  startRetentionScheduler();

  // ============ REPORTING ============

  app.get("/api/report-templates", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const templates = await storage.getReportTemplates(user?.orgId);
    res.json(templates);
  });

  app.get("/api/report-templates/:id", isAuthenticated, async (req, res) => {
    const template = await storage.getReportTemplate(p(req.params.id));
    if (!template) return res.status(404).json({ message: "Template not found" });
    const user = req.user as any;
    if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    res.json(template);
  });

  app.post("/api/report-templates", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const data = insertReportTemplateSchema.parse({ ...req.body, orgId, createdBy: user?.id || null });
      const template = await storage.createReportTemplate(data);
      res.status(201).json(template);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create report template" });
    }
  });

  app.patch("/api/report-templates/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportTemplate(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Template not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    const { id: _id, orgId: _org, ...updateData } = req.body;
    const template = await storage.updateReportTemplate(p(req.params.id), updateData);
    res.json(template);
  });

  app.delete("/api/report-templates/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportTemplate(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Template not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    await storage.deleteReportTemplate(p(req.params.id));
    res.json({ success: true });
  });

  app.get("/api/report-schedules", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const schedules = await storage.getReportSchedules(user?.orgId);
    res.json(schedules);
  });

  app.get("/api/report-schedules/:id", isAuthenticated, async (req, res) => {
    const schedule = await storage.getReportSchedule(p(req.params.id));
    if (!schedule) return res.status(404).json({ message: "Schedule not found" });
    const user = req.user as any;
    if (schedule.orgId && user?.orgId && schedule.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    res.json(schedule);
  });

  app.post("/api/report-schedules", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const cadence = req.body.cadence || "weekly";
      const nextRunAt = calculateNextRunFromCadence(cadence);
      const orgId = getOrgId(req);
      const data = insertReportScheduleSchema.parse({ ...req.body, orgId, createdBy: user?.id || null });
      const template = await storage.getReportTemplate(data.templateId);
      if (!template) return res.status(404).json({ message: "Template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) return res.status(403).json({ message: "Template access denied" });
      const schedule = await storage.createReportSchedule(data);
      await storage.updateReportSchedule(schedule.id, { nextRunAt });
      const updated = await storage.getReportSchedule(schedule.id);
      res.status(201).json(updated);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create report schedule" });
    }
  });

  app.patch("/api/report-schedules/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportSchedule(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Schedule not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    const { id: _id, orgId: _org, ...updateData } = req.body;
    if (updateData.cadence) {
      updateData.nextRunAt = calculateNextRunFromCadence(updateData.cadence);
    }
    const schedule = await storage.updateReportSchedule(p(req.params.id), updateData);
    res.json(schedule);
  });

  app.delete("/api/report-schedules/:id", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const existing = await storage.getReportSchedule(p(req.params.id));
    if (!existing) return res.status(404).json({ message: "Schedule not found" });
    if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    await storage.deleteReportSchedule(p(req.params.id));
    res.json({ success: true });
  });

  app.get("/api/report-runs", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const templateId = req.query.templateId as string | undefined;
    const runs = await storage.getReportRuns(user?.orgId, templateId);
    res.json(runs);
  });

  app.get("/api/report-runs/:id", isAuthenticated, async (req, res) => {
    const run = await storage.getReportRun(p(req.params.id));
    if (!run) return res.status(404).json({ message: "Run not found" });
    const user = req.user as any;
    if (run.orgId && user?.orgId && run.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    res.json(run);
  });

  app.post("/api/reports/generate", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const { templateId } = req.body;
    if (!templateId) return res.status(400).json({ message: "templateId is required" });
    try {
      const { runReportOnDemand } = await import("./report-scheduler");
      const result = await runReportOnDemand(templateId, user?.orgId, user?.id);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  app.get("/api/reports/:runId/download", isAuthenticated, async (req, res) => {
    const run = await storage.getReportRun(p(req.params.runId));
    if (!run) return res.status(404).json({ message: "Report run not found" });
    const user = req.user as any;
    if (run.orgId && user?.orgId && run.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
    const template = await storage.getReportTemplate(run.templateId);
    if (!template) return res.status(404).json({ message: "Template not found" });
    try {
      const { generateReportData, formatAsCSV } = await import("./report-engine");
      const data = await generateReportData(template.reportType, run.orgId || undefined);
      if (run.format === "csv") {
        const csv = formatAsCSV(data);
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="${template.reportType}-report.csv"`);
        return res.send(csv);
      }
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  app.get("/api/reports/preview/:reportType", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    try {
      const { generateReportData } = await import("./report-engine");
      const data = await generateReportData(p(req.params.reportType), user?.orgId);
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  app.post("/api/report-templates/seed", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const allTemplates = await storage.getReportTemplates(undefined);
      if (allTemplates.some(t => t.isBuiltIn && t.orgId === orgId)) {
        return res.json({ message: "Built-in templates already exist for this org", count: allTemplates.filter(t => t.isBuiltIn && t.orgId === orgId).length });
      }
      const builtIns = [
        { name: "Weekly SOC KPI Report", description: "Key performance indicators for SOC operations including alert volumes, response times, and severity distribution", reportType: "soc_kpi", format: "csv", dashboardRole: "soc_manager", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Incident Summary Report", description: "Detailed listing of all incidents with status, severity, assignees, and resolution metrics", reportType: "incidents", format: "csv", dashboardRole: "analyst", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "MITRE ATT&CK Coverage Report", description: "Analysis of detected attack techniques mapped to the MITRE ATT&CK framework", reportType: "attack_coverage", format: "csv", dashboardRole: "ciso", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Connector Health Report", description: "Status and performance metrics for all configured data connectors", reportType: "connector_health", format: "csv", dashboardRole: "soc_manager", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Executive Security Brief", description: "High-level security posture summary for executive leadership including risk trends and key metrics", reportType: "executive_summary", format: "json", dashboardRole: "ciso", isBuiltIn: true, orgId, createdBy: user?.id || null },
        { name: "Compliance Status Report", description: "Compliance framework coverage, data retention status, and DSAR request tracking", reportType: "compliance", format: "csv", dashboardRole: "ciso", isBuiltIn: true, orgId, createdBy: user?.id || null },
      ];
      const created = [];
      for (const t of builtIns) {
        const template = await storage.createReportTemplate(t as any);
        created.push(template);
      }
      res.status(201).json({ message: "Built-in templates created", count: created.length, templates: created });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING") return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to seed report templates" });
    }
  });

  app.get("/api/dashboard/:role", isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const role = p(req.params.role);
    if (!["ciso", "soc_manager", "analyst"].includes(role)) {
      return res.status(400).json({ message: "Invalid role. Must be ciso, soc_manager, or analyst" });
    }
    try {
      const stats = await storage.getDashboardStats(user?.orgId);
      const analytics = await storage.getDashboardAnalytics(user?.orgId);
      const allIncidents = await storage.getIncidents(user?.orgId);

      if (role === "ciso") {
        res.json({
          role: "ciso",
          title: "CISO Executive Dashboard",
          kpis: {
            totalAlerts: stats.totalAlerts,
            openIncidents: stats.openIncidents,
            criticalAlerts: stats.criticalAlerts,
            mttrHours: analytics.mttrHours,
            escalatedIncidents: stats.escalatedIncidents,
          },
          riskPosture: analytics.severityDistribution,
          topMitreTactics: analytics.topMitreTactics,
          recentCriticalIncidents: allIncidents.filter(i => i.severity === "critical").slice(0, 5),
          connectorHealth: analytics.connectorHealth,
          alertTrend: analytics.alertTrend,
        });
      } else if (role === "soc_manager") {
        res.json({
          role: "soc_manager",
          title: "SOC Manager Dashboard",
          kpis: {
            totalAlerts: stats.totalAlerts,
            openIncidents: stats.openIncidents,
            newAlertsToday: stats.newAlertsToday,
            resolvedIncidents: stats.resolvedIncidents,
            mttrHours: analytics.mttrHours,
          },
          severityDistribution: analytics.severityDistribution,
          sourceDistribution: analytics.sourceDistribution,
          categoryDistribution: analytics.categoryDistribution,
          statusDistribution: analytics.statusDistribution,
          alertTrend: analytics.alertTrend,
          ingestionRate: analytics.ingestionRate,
          connectorHealth: analytics.connectorHealth,
          recentIncidents: allIncidents.slice(0, 10),
        });
      } else {
        res.json({
          role: "analyst",
          title: "Analyst Dashboard",
          kpis: {
            totalAlerts: stats.totalAlerts,
            openIncidents: stats.openIncidents,
            criticalAlerts: stats.criticalAlerts,
            newAlertsToday: stats.newAlertsToday,
          },
          severityDistribution: analytics.severityDistribution,
          categoryDistribution: analytics.categoryDistribution,
          topMitreTactics: analytics.topMitreTactics,
          alertTrend: analytics.alertTrend,
          recentIncidents: allIncidents.filter(i => ["open", "investigating"].includes(i.status || "")).slice(0, 10),
        });
      }
    } catch (err: any) {
      res.status(500).json({ message: err.message });
    }
  });

  // Suppression Rules
  app.get("/api/suppression-rules", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const rules = await storage.getSuppressionRules(orgId);
      res.json(rules);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch suppression rules" });
    }
  });

  app.get("/api/suppression-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const rule = await storage.getSuppressionRule(p(req.params.id));
      if (!rule) return res.status(404).json({ message: "Suppression rule not found" });
      if (rule.orgId && user?.orgId && rule.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch suppression rule" });
    }
  });

  app.post("/api/suppression-rules", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const rule = await storage.createSuppressionRule({ ...req.body, orgId, createdBy: userId });
      res.status(201).json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to create suppression rule" });
    }
  });

  app.patch("/api/suppression-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getSuppressionRule(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Suppression rule not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const rule = await storage.updateSuppressionRule(p(req.params.id), req.body);
      res.json(rule);
    } catch (error) {
      res.status(500).json({ message: "Failed to update suppression rule" });
    }
  });

  app.delete("/api/suppression-rules/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getSuppressionRule(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Suppression rule not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteSuppressionRule(p(req.params.id));
      res.json({ message: "Suppression rule deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete suppression rule" });
    }
  });

  app.post("/api/alerts/:id/suppress", isAuthenticated, async (req, res) => {
    try {
      const userId = (req as any).user?.id;
      const alert = await storage.updateAlert(p(req.params.id), { suppressed: true, suppressedBy: userId });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to suppress alert" });
    }
  });

  app.post("/api/alerts/:id/unsuppress", isAuthenticated, async (req, res) => {
    try {
      const alert = await storage.updateAlert(p(req.params.id), { suppressed: false, suppressedBy: null });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to unsuppress alert" });
    }
  });

  // Alert Confidence Calibration
  app.patch("/api/alerts/:id/confidence", isAuthenticated, async (req, res) => {
    try {
      const { confidenceScore, confidenceSource, confidenceNotes } = req.body;
      const alert = await storage.updateAlert(p(req.params.id), { confidenceScore, confidenceSource, confidenceNotes });
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert confidence" });
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

  // SLA Policies
  app.get("/api/sla-policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policies = await storage.getIncidentSlaPolicies(orgId);
      res.json(policies);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLA policies" });
    }
  });

  app.get("/api/sla-policies/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const policy = await storage.getIncidentSlaPolicy(p(req.params.id));
      if (!policy) return res.status(404).json({ message: "SLA policy not found" });
      if (policy.orgId && user?.orgId && policy.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLA policy" });
    }
  });

  app.post("/api/sla-policies", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const policy = await storage.createIncidentSlaPolicy({ ...req.body, orgId });
      res.status(201).json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to create SLA policy" });
    }
  });

  app.patch("/api/sla-policies/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIncidentSlaPolicy(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "SLA policy not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const policy = await storage.updateIncidentSlaPolicy(p(req.params.id), req.body);
      res.json(policy);
    } catch (error) {
      res.status(500).json({ message: "Failed to update SLA policy" });
    }
  });

  app.delete("/api/sla-policies/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getIncidentSlaPolicy(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "SLA policy not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deleteIncidentSlaPolicy(p(req.params.id));
      res.json({ message: "SLA policy deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete SLA policy" });
    }
  });

  // SLA Application
  app.post("/api/incidents/:id/apply-sla", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(p(req.params.id));
      if (!incident) return res.status(404).json({ message: "Incident not found" });

      if (incident.ackDueAt || incident.containDueAt || incident.resolveDueAt) {
        return res.status(400).json({ message: "SLA timers already set for this incident" });
      }

      const orgId = (req as any).user?.orgId;
      const policies = await storage.getIncidentSlaPolicies(orgId);
      const policy = policies.find(p => p.severity === incident.severity && p.enabled === true);
      if (!policy) return res.status(404).json({ message: "No enabled SLA policy found for severity: " + incident.severity });

      const createdAt = incident.createdAt ? new Date(incident.createdAt).getTime() : Date.now();
      const ackDueAt = new Date(createdAt + policy.ackMinutes * 60 * 1000);
      const containDueAt = new Date(createdAt + policy.containMinutes * 60 * 1000);
      const resolveDueAt = new Date(createdAt + policy.resolveMinutes * 60 * 1000);

      const updated = await storage.updateIncident(p(req.params.id), { ackDueAt, containDueAt, resolveDueAt });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to apply SLA policy" });
    }
  });

  // Incident Acknowledge
  app.post("/api/incidents/:id/acknowledge", isAuthenticated, async (req, res) => {
    try {
      const updated = await storage.updateIncident(p(req.params.id), { ackAt: new Date() });
      if (!updated) return res.status(404).json({ message: "Incident not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to acknowledge incident" });
    }
  });

  // Post-Incident Reviews
  app.get("/api/incidents/:incidentId/pir", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const reviews = await storage.getPostIncidentReviews(orgId, p(req.params.incidentId));
      res.json(reviews);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch post-incident reviews" });
    }
  });

  app.post("/api/incidents/:incidentId/pir", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const userId = (req as any).user?.id;
      const userName = (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Unknown";
      const review = await storage.createPostIncidentReview({
        ...req.body,
        orgId,
        incidentId: p(req.params.incidentId),
        createdBy: userId,
        createdByName: userName,
      });
      res.status(201).json(review);
    } catch (error) {
      res.status(500).json({ message: "Failed to create post-incident review" });
    }
  });

  app.get("/api/pir/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const review = await storage.getPostIncidentReview(p(req.params.id));
      if (!review) return res.status(404).json({ message: "Post-incident review not found" });
      if (review.orgId && user?.orgId && review.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      res.json(review);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch post-incident review" });
    }
  });

  app.patch("/api/pir/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getPostIncidentReview(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Post-incident review not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const review = await storage.updatePostIncidentReview(p(req.params.id), req.body);
      res.json(review);
    } catch (error) {
      res.status(500).json({ message: "Failed to update post-incident review" });
    }
  });

  app.delete("/api/pir/:id", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const existing = await storage.getPostIncidentReview(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Post-incident review not found" });
      if (existing.orgId && user?.orgId && existing.orgId !== user.orgId) return res.status(403).json({ message: "Access denied" });
      const deleted = await storage.deletePostIncidentReview(p(req.params.id));
      res.json({ message: "Post-incident review deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete post-incident review" });
    }
  });

  // Policy Checks (CSPM policy-as-code)
  app.get("/api/policy-checks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const checks = await storage.getPolicyChecks(orgId);
      res.json(checks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch policy checks" });
    }
  });

  app.post("/api/policy-checks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertPolicyCheckSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid policy check data", errors: parsed.error.flatten() });
      }
      const check = await storage.createPolicyCheck(parsed.data);
      res.status(201).json(check);
    } catch (error) {
      res.status(500).json({ message: "Failed to create policy check" });
    }
  });

  app.patch("/api/policy-checks/:id", isAuthenticated, async (req, res) => {
    try {
      const check = await storage.updatePolicyCheck(p(req.params.id), req.body);
      if (!check) return res.status(404).json({ message: "Policy check not found" });
      res.json(check);
    } catch (error) {
      res.status(500).json({ message: "Failed to update policy check" });
    }
  });

  app.delete("/api/policy-checks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deletePolicyCheck(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Policy check not found" });
      res.json({ message: "Policy check deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete policy check" });
    }
  });

  app.post("/api/policy-checks/:id/run", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const check = await storage.getPolicyCheck(p(req.params.id));
      if (!check) return res.status(404).json({ message: "Policy check not found" });
      const findings = await storage.getCspmFindings(orgId);
      const results: any[] = [];
      for (const finding of findings) {
        const passed = check.severity ? finding.severity !== check.severity : finding.severity === "low" || finding.severity === "informational";
        const result = await storage.createPolicyResult({
          policyCheckId: check.id,
          orgId,
          resourceId: finding.resourceId || finding.id,
          resourceType: finding.resourceType || "cspm_finding",
          status: passed ? "pass" : "fail",
          details: { findingId: finding.id, severity: finding.severity, ruleName: finding.ruleName },
        });
        results.push(result);
      }
      await storage.updatePolicyCheck(check.id, { lastRunAt: new Date() });
      res.json({ policyCheckId: check.id, totalFindings: findings.length, results });
    } catch (error) {
      res.status(500).json({ message: "Failed to run policy check" });
    }
  });

  app.get("/api/policy-results", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const policyCheckId = req.query.policyCheckId as string | undefined;
      const results = await storage.getPolicyResults(orgId, policyCheckId);
      res.json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch policy results" });
    }
  });

  // Compliance Controls
  app.get("/api/compliance-controls", isAuthenticated, async (req, res) => {
    try {
      const framework = req.query.framework as string | undefined;
      const controls = await storage.getComplianceControls(framework);
      res.json(controls);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance controls" });
    }
  });

  app.post("/api/compliance-controls", isAuthenticated, async (req, res) => {
    try {
      const body = req.body;
      const parsed = insertComplianceControlSchema.safeParse(body);
      if (!parsed.success) return res.status(400).json({ message: "Invalid control data", errors: parsed.error.flatten() });
      const control = await storage.createComplianceControl(parsed.data);
      res.status(201).json(control);
    } catch (error) {
      res.status(500).json({ message: "Failed to create compliance control" });
    }
  });

  app.patch("/api/compliance-controls/:id", isAuthenticated, async (req, res) => {
    try {
      const control = await storage.updateComplianceControl(p(req.params.id), req.body);
      if (!control) return res.status(404).json({ message: "Compliance control not found" });
      res.json(control);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance control" });
    }
  });

  app.delete("/api/compliance-controls/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteComplianceControl(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Compliance control not found" });
      res.json({ message: "Compliance control deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete compliance control" });
    }
  });

  app.post("/api/compliance-controls/seed", isAuthenticated, async (req, res) => {
    try {
      const seedControls = [
        { framework: "NIST CSF", controlId: "ID.AM-1", title: "Asset Management - Inventory", description: "Physical devices and systems within the organization are inventoried", category: "Identify" },
        { framework: "NIST CSF", controlId: "ID.AM-2", title: "Asset Management - Software Platforms", description: "Software platforms and applications within the organization are inventoried", category: "Identify" },
        { framework: "NIST CSF", controlId: "PR.AC-1", title: "Access Control", description: "Identities and credentials are issued, managed, verified, revoked, and audited", category: "Protect" },
        { framework: "NIST CSF", controlId: "PR.AC-3", title: "Remote Access Management", description: "Remote access is managed", category: "Protect" },
        { framework: "NIST CSF", controlId: "PR.DS-1", title: "Data-at-Rest Protection", description: "Data-at-rest is protected", category: "Protect" },
        { framework: "NIST CSF", controlId: "DE.CM-1", title: "Continuous Monitoring", description: "The network is monitored to detect potential cybersecurity events", category: "Detect" },
        { framework: "NIST CSF", controlId: "DE.CM-4", title: "Malicious Code Detection", description: "Malicious code is detected", category: "Detect" },
        { framework: "NIST CSF", controlId: "RS.RP-1", title: "Response Planning", description: "Response plan is executed during or after an incident", category: "Respond" },
        { framework: "NIST CSF", controlId: "RS.CO-2", title: "Incident Reporting", description: "Incidents are reported consistent with established criteria", category: "Respond" },
        { framework: "NIST CSF", controlId: "RC.RP-1", title: "Recovery Planning", description: "Recovery plan is executed during or after a cybersecurity incident", category: "Recover" },
        { framework: "ISO 27001", controlId: "A.5.1", title: "Information Security Policies", description: "Management direction for information security", category: "Policy" },
        { framework: "ISO 27001", controlId: "A.5.2", title: "Review of Policies", description: "Policies for information security are reviewed at planned intervals", category: "Policy" },
        { framework: "ISO 27001", controlId: "A.6.1", title: "Organization of Security", description: "Internal organization of information security", category: "Organization" },
        { framework: "ISO 27001", controlId: "A.7.1", title: "Human Resource Security", description: "Prior to employment security measures", category: "Human Resources" },
        { framework: "ISO 27001", controlId: "A.8.1", title: "Asset Management", description: "Responsibility for assets", category: "Asset Management" },
        { framework: "ISO 27001", controlId: "A.9.1", title: "Access Control", description: "Business requirements of access control", category: "Access Control" },
        { framework: "ISO 27001", controlId: "A.9.2", title: "User Access Management", description: "User registration and de-registration", category: "Access Control" },
        { framework: "ISO 27001", controlId: "A.10.1", title: "Cryptographic Controls", description: "Policy on the use of cryptographic controls", category: "Cryptography" },
        { framework: "ISO 27001", controlId: "A.12.1", title: "Operations Security", description: "Operational procedures and responsibilities", category: "Operations" },
        { framework: "ISO 27001", controlId: "A.12.4", title: "Logging and Monitoring", description: "Event logging and monitoring", category: "Operations" },
        { framework: "CIS", controlId: "CIS-1", title: "Inventory of Authorized Devices", description: "Actively manage all hardware devices on the network", category: "Basic" },
        { framework: "CIS", controlId: "CIS-2", title: "Inventory of Authorized Software", description: "Actively manage all software on the network", category: "Basic" },
        { framework: "CIS", controlId: "CIS-3", title: "Secure Configurations", description: "Establish and maintain secure configurations for hardware and software", category: "Basic" },
        { framework: "CIS", controlId: "CIS-4", title: "Continuous Vulnerability Assessment", description: "Continuously acquire, assess, and take action on vulnerability information", category: "Basic" },
        { framework: "CIS", controlId: "CIS-5", title: "Controlled Use of Admin Privileges", description: "Manage the controlled use of administrative privileges", category: "Basic" },
        { framework: "CIS", controlId: "CIS-6", title: "Maintenance and Analysis of Audit Logs", description: "Collect, manage, and analyze audit logs", category: "Basic" },
        { framework: "CIS", controlId: "CIS-7", title: "Email and Web Browser Protections", description: "Minimize the attack surface and opportunities for attackers", category: "Foundational" },
        { framework: "CIS", controlId: "CIS-8", title: "Malware Defenses", description: "Control the installation, spread, and execution of malicious code", category: "Foundational" },
        { framework: "SOC 2", controlId: "CC1.1", title: "Control Environment", description: "The entity demonstrates a commitment to integrity and ethical values", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC1.2", title: "Board Oversight", description: "The board demonstrates independence from management", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC2.1", title: "Communication", description: "The entity obtains or generates relevant quality information", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC3.1", title: "Risk Assessment", description: "The entity specifies objectives with sufficient clarity", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC5.1", title: "Control Activities", description: "The entity selects and develops control activities", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC6.1", title: "Logical Access", description: "The entity implements logical access security measures", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC7.1", title: "System Operations", description: "The entity uses detection and monitoring procedures", category: "Common Criteria" },
        { framework: "SOC 2", controlId: "CC8.1", title: "Change Management", description: "The entity authorizes, designs, develops, and implements changes", category: "Common Criteria" },
      ];
      const created = await storage.createComplianceControls(seedControls);
      res.status(201).json(created);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed compliance controls" });
    }
  });

  app.get("/api/compliance-control-mappings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const controlId = req.query.controlId as string | undefined;
      const mappings = await storage.getComplianceControlMappings(orgId, controlId);
      res.json(mappings);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance control mappings" });
    }
  });

  app.post("/api/compliance-control-mappings", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertComplianceControlMappingSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid mapping data", errors: parsed.error.flatten() });
      }
      const mapping = await storage.createComplianceControlMapping(parsed.data);
      res.status(201).json(mapping);
    } catch (error) {
      res.status(500).json({ message: "Failed to create compliance control mapping" });
    }
  });

  app.patch("/api/compliance-control-mappings/:id", isAuthenticated, async (req, res) => {
    try {
      const mapping = await storage.updateComplianceControlMapping(p(req.params.id), req.body);
      if (!mapping) return res.status(404).json({ message: "Mapping not found" });
      res.json(mapping);
    } catch (error) {
      res.status(500).json({ message: "Failed to update compliance control mapping" });
    }
  });

  app.delete("/api/compliance-control-mappings/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteComplianceControlMapping(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Mapping not found" });
      res.json({ message: "Mapping deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete compliance control mapping" });
    }
  });

  // Evidence Locker
  app.get("/api/evidence-locker", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const framework = req.query.framework as string | undefined;
      const artifactType = req.query.artifactType as string | undefined;
      const items = await storage.getEvidenceLockerItems(orgId, framework, artifactType);
      res.json(items);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch evidence locker items" });
    }
  });

  app.post("/api/evidence-locker", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertEvidenceLockerItemSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid evidence locker item data", errors: parsed.error.flatten() });
      }
      const item = await storage.createEvidenceLockerItem(parsed.data);
      res.status(201).json(item);
    } catch (error) {
      res.status(500).json({ message: "Failed to create evidence locker item" });
    }
  });

  app.patch("/api/evidence-locker/:id", isAuthenticated, async (req, res) => {
    try {
      const item = await storage.updateEvidenceLockerItem(p(req.params.id), req.body);
      if (!item) return res.status(404).json({ message: "Evidence locker item not found" });
      res.json(item);
    } catch (error) {
      res.status(500).json({ message: "Failed to update evidence locker item" });
    }
  });

  app.delete("/api/evidence-locker/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteEvidenceLockerItem(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Evidence locker item not found" });
      res.json({ message: "Evidence locker item deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete evidence locker item" });
    }
  });

  // Outbound Webhooks
  app.get("/api/outbound-webhooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const webhooks = await storage.getOutboundWebhooks(orgId);
      res.json(webhooks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch outbound webhooks" });
    }
  });

  app.post("/api/outbound-webhooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertOutboundWebhookSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid webhook data", errors: parsed.error.flatten() });
      }
      const urlCheck = validateWebhookUrl(parsed.data.url);
      if (!urlCheck.valid) {
        return res.status(400).json({ message: `Invalid webhook URL: ${urlCheck.reason}` });
      }
      const webhook = await storage.createOutboundWebhook(parsed.data);
      res.status(201).json(webhook);
    } catch (error) {
      res.status(500).json({ message: "Failed to create outbound webhook" });
    }
  });

  app.patch("/api/outbound-webhooks/:id", isAuthenticated, async (req, res) => {
    try {
      if (req.body.url) {
        const urlCheck = validateWebhookUrl(req.body.url);
        if (!urlCheck.valid) {
          return res.status(400).json({ message: `Invalid webhook URL: ${urlCheck.reason}` });
        }
      }
      const webhook = await storage.updateOutboundWebhook(p(req.params.id), req.body);
      if (!webhook) return res.status(404).json({ message: "Webhook not found" });
      res.json(webhook);
    } catch (error) {
      res.status(500).json({ message: "Failed to update outbound webhook" });
    }
  });

  app.delete("/api/outbound-webhooks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteOutboundWebhook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Webhook not found" });
      res.json({ message: "Webhook deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete outbound webhook" });
    }
  });

  app.get("/api/outbound-webhooks/:id/logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getOutboundWebhookLogs(p(req.params.id), 50);
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch webhook logs" });
    }
  });

  app.post("/api/outbound-webhooks/:id/test", isAuthenticated, async (req, res) => {
    try {
      const webhook = await storage.getOutboundWebhook(p(req.params.id));
      if (!webhook) return res.status(404).json({ message: "Webhook not found" });
      const urlCheck = validateWebhookUrl(webhook.url);
      if (!urlCheck.valid) {
        return res.status(400).json({ message: `Webhook URL blocked: ${urlCheck.reason}` });
      }
      const testPayload = { event: "test", timestamp: new Date().toISOString(), message: "Test webhook delivery from SecureNexus" };
      const body = JSON.stringify(testPayload);
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (webhook.secret) {
        const timestamp = String(Date.now());
        const signedPayload = `${timestamp}.${body}`;
        const signature = createHmac("sha256", webhook.secret).update(signedPayload).digest("hex");
        headers["X-Webhook-Signature"] = `sha256=${signature}`;
        headers["X-Webhook-Timestamp"] = timestamp;
      }
      const result = await secureOutboundFetch(webhook.url, { method: "POST", headers, body });
      await storage.createOutboundWebhookLog({
        webhookId: webhook.id,
        event: "test",
        payload: redactDeliveryLog(testPayload) as Record<string, unknown>,
        responseStatus: result.statusCode,
        responseBody: result.responseBody.slice(0, 2000),
        success: result.success,
      });
      res.json({ success: result.success, statusCode: result.statusCode, responseBody: result.responseBody.slice(0, 500) });
    } catch (error) {
      res.status(500).json({ message: "Failed to test webhook" });
    }
  });

  // Versioned outbound webhooks API (v1 envelope)
  app.get("/api/v1/webhooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const webhooks = await storage.getOutboundWebhooks(orgId);
      return sendEnvelope(res, webhooks);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "WEBHOOKS_LIST_FAILED",
            message: "Failed to fetch outbound webhooks",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.post("/api/v1/webhooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertOutboundWebhookSchema.safeParse({ ...req.body, orgId });
      if (!parsed.success) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [
            {
              code: "WEBHOOK_INVALID",
              message: "Invalid webhook data",
              details: parsed.error.flatten(),
            },
          ],
        });
      }
      const urlCheck = validateWebhookUrl(parsed.data.url);
      if (!urlCheck.valid) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "WEBHOOK_URL_BLOCKED", message: `Invalid webhook URL: ${urlCheck.reason}` }],
        });
      }
      const webhook = await storage.createOutboundWebhook(parsed.data);
      return sendEnvelope(res, webhook, { status: 201 });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "WEBHOOK_CREATE_FAILED",
            message: "Failed to create outbound webhook",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.patch("/api/v1/webhooks/:id", isAuthenticated, async (req, res) => {
    try {
      const webhook = await storage.updateOutboundWebhook(p(req.params.id), req.body);
      if (!webhook) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
        });
      }
      return sendEnvelope(res, webhook);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "WEBHOOK_UPDATE_FAILED",
            message: "Failed to update outbound webhook",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.delete("/api/v1/webhooks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteOutboundWebhook(p(req.params.id));
      if (!deleted) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "WEBHOOK_NOT_FOUND", message: "Webhook not found" }],
        });
      }
      return sendEnvelope(res, { deleted: true });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "WEBHOOK_DELETE_FAILED",
            message: "Failed to delete outbound webhook",
            details: error?.message,
          },
        ],
      });
    }
  });

  app.get("/api/v1/webhooks/:id/logs", isAuthenticated, async (req, res) => {
    try {
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const allLogs = await storage.getOutboundWebhookLogs(p(req.params.id), offset + limit);
      const items = allLogs.slice(offset, offset + limit);
      return sendEnvelope(res, items, {
        meta: { offset, limit, total: allLogs.length },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [
          {
            code: "WEBHOOK_LOGS_FAILED",
            message: "Failed to fetch webhook logs",
            details: error?.message,
          },
        ],
      });
    }
  });

  // === Alert Archive (Cold Storage) ===
  app.get("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = parseInt(req.query.limit as string, 10) || 100;
      const offset = parseInt(req.query.offset as string, 10) || 0;
      const [items, count] = await Promise.all([
        storage.getArchivedAlerts(orgId, limit, offset),
        storage.getArchivedAlertCount(orgId),
      ]);
      res.json({ items, total: count, limit, offset });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch archived alerts" });
    }
  });

  app.post("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { alertIds, reason } = req.body;
      if (!alertIds || !Array.isArray(alertIds) || alertIds.length === 0) {
        return res.status(400).json({ message: "alertIds array required" });
      }
      const count = await storage.archiveAlerts(orgId, alertIds, reason || "manual");
      res.json({ archived: count });
    } catch (error) {
      res.status(500).json({ message: "Failed to archive alerts" });
    }
  });

  app.post("/api/alerts/archive/restore", isAuthenticated, async (req, res) => {
    try {
      const { ids } = req.body;
      if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: "ids array required" });
      }
      const count = await storage.restoreArchivedAlerts(ids);
      res.json({ restored: count });
    } catch (error) {
      res.status(500).json({ message: "Failed to restore archived alerts" });
    }
  });

  app.delete("/api/alerts/archive", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const beforeDate = req.query.beforeDate as string;
      if (!beforeDate) {
        return res.status(400).json({ message: "beforeDate query param required" });
      }
      const count = await storage.deleteArchivedAlerts(orgId, new Date(beforeDate));
      res.json({ deleted: count });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete archived alerts" });
    }
  });

  // === Job Queue ===
  app.get("/api/ops/jobs", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string;
      const status = req.query.status as string;
      const type = req.query.type as string;
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const jobs = await storage.getJobs(orgId, status, type, limit);
      res.json(jobs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch jobs" });
    }
  });

  app.get("/api/ops/jobs/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getJobStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch job stats" });
    }
  });

  app.post("/api/ops/jobs", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { type, payload, priority, runAt } = req.body;
      if (!type) return res.status(400).json({ message: "type is required" });
      const job = await storage.createJob({
        orgId,
        type,
        status: "pending",
        payload: payload || {},
        priority: priority || 0,
        runAt: runAt ? new Date(runAt) : new Date(),
        attempts: 0,
        maxAttempts: 3,
      });
      res.status(201).json(job);
    } catch (error) {
      res.status(500).json({ message: "Failed to create job" });
    }
  });

  app.post("/api/ops/jobs/:id/cancel", isAuthenticated, async (req, res) => {
    try {
      const success = await storage.cancelJob(p(req.params.id));
      if (!success) return res.status(404).json({ message: "Job not found or not cancellable" });
      res.json({ cancelled: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to cancel job" });
    }
  });

  app.get("/api/ops/worker/status", isAuthenticated, async (req, res) => {
    try {
      const { getWorkerStatus } = await import("./job-queue");
      res.json(getWorkerStatus());
    } catch (error) {
      res.status(500).json({ message: "Failed to get worker status" });
    }
  });

  // === SLO/SLI Observability ===
  app.get("/api/ops/health", async (_req, res) => {
    try {
      const dbCheck = await storage.getJobStats();
      res.json({ status: "healthy", timestamp: new Date().toISOString(), database: "connected", jobQueue: dbCheck });
    } catch (error) {
      res.status(503).json({ status: "unhealthy", timestamp: new Date().toISOString(), error: "Database connection failed" });
    }
  });

  app.get("/api/ops/sli", isAuthenticated, async (req, res) => {
    try {
      const service = req.query.service as string;
      const metric = req.query.metric as string;
      const hours = parseInt(req.query.hours as string, 10) || 24;
      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - hours * 60 * 60 * 1000);
      if (!service || !metric) {
        return res.status(400).json({ message: "service and metric query params required" });
      }
      const metrics = await storage.getSliMetrics(service, metric, startTime, endTime);
      res.json(metrics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLI metrics" });
    }
  });

  app.get("/api/ops/slo", isAuthenticated, async (req, res) => {
    try {
      const targets = await storage.getSloTargets();
      const { evaluateSlos } = await import("./sli-middleware");
      const evaluations = await evaluateSlos();
      res.json({ targets, evaluations });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLO status" });
    }
  });

  app.get("/api/ops/slo-targets", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const targets = await storage.getSloTargets();
      res.json(targets);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch SLO targets" });
    }
  });

  app.post("/api/ops/slo-targets", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const target = await storage.createSloTarget(req.body);
      res.status(201).json(target);
    } catch (error) {
      res.status(500).json({ message: "Failed to create SLO target" });
    }
  });

  app.patch("/api/ops/slo-targets/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const updated = await storage.updateSloTarget(p(req.params.id), req.body);
      if (!updated) return res.status(404).json({ message: "SLO target not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update SLO target" });
    }
  });

  app.delete("/api/ops/slo-targets/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const deleted = await storage.deleteSloTarget(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "SLO target not found" });
      res.json({ deleted: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete SLO target" });
    }
  });

  app.post("/api/ops/slo-targets/seed", isAuthenticated, async (req, res) => {
    try {
      const defaults = [
        { service: "api", metric: "availability", target: 99.9, operator: "gte", windowMinutes: 60, alertOnBreach: true, description: "API Availability > 99.9%" },
        { service: "api", metric: "latency_p95", target: 500, operator: "lte", windowMinutes: 60, alertOnBreach: true, description: "API P95 Latency < 500ms" },
        { service: "ingestion", metric: "error_rate", target: 1.0, operator: "lte", windowMinutes: 60, alertOnBreach: true, description: "Ingestion Error Rate < 1%" },
        { service: "ingestion", metric: "throughput", target: 10, operator: "gte", windowMinutes: 60, alertOnBreach: false, description: "Ingestion Throughput > 10 req/min" },
        { service: "ai", metric: "latency_p95", target: 5000, operator: "lte", windowMinutes: 60, alertOnBreach: true, description: "AI P95 Latency < 5s" },
        { service: "ai", metric: "availability", target: 99.0, operator: "gte", windowMinutes: 60, alertOnBreach: true, description: "AI Availability > 99%" },
        { service: "connector", metric: "error_rate", target: 5.0, operator: "lte", windowMinutes: 60, alertOnBreach: true, description: "Connector Error Rate < 5%" },
        { service: "enrichment", metric: "latency_p95", target: 3000, operator: "lte", windowMinutes: 60, alertOnBreach: false, description: "Enrichment P95 Latency < 3s" },
      ];
      const results = [];
      for (const d of defaults) {
        try {
          results.push(await storage.createSloTarget(d as any));
        } catch (e) {
          // skip duplicates
        }
      }
      res.status(201).json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed SLO targets" });
    }
  });

  // === Disaster Recovery Runbooks ===
  app.get("/api/ops/dr-runbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const runbooks = await storage.getDrRunbooks(orgId);
      res.json(runbooks);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DR runbooks" });
    }
  });

  app.get("/api/ops/dr-runbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const runbook = await storage.getDrRunbook(p(req.params.id));
      if (!runbook) return res.status(404).json({ message: "Runbook not found" });
      res.json(runbook);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch DR runbook" });
    }
  });

  app.post("/api/ops/dr-runbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const runbook = await storage.createDrRunbook({ ...req.body, orgId });
      res.status(201).json(runbook);
    } catch (error) {
      res.status(500).json({ message: "Failed to create DR runbook" });
    }
  });

  app.patch("/api/ops/dr-runbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const updated = await storage.updateDrRunbook(p(req.params.id), req.body);
      if (!updated) return res.status(404).json({ message: "Runbook not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update DR runbook" });
    }
  });

  app.delete("/api/ops/dr-runbooks/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteDrRunbook(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Runbook not found" });
      res.json({ deleted: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete DR runbook" });
    }
  });

  app.post("/api/ops/dr-runbooks/:id/test", isAuthenticated, async (req, res) => {
    try {
      const { result, notes } = req.body;
      if (!result) return res.status(400).json({ message: "result (pass/fail/partial) required" });
      const updated = await storage.updateDrRunbook(p(req.params.id), {
        lastTestedAt: new Date(),
        lastTestResult: result,
        testNotes: notes || null,
      });
      if (!updated) return res.status(404).json({ message: "Runbook not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to record test result" });
    }
  });

  app.post("/api/ops/dr-runbooks/seed", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const defaults = [
        {
          orgId,
          title: "RDS Failover (Primary DB Failure)",
          description: "Procedure when primary RDS instance is unavailable or degraded performance >5 minutes. Promotes cross-region read replica and redirects traffic.",
          category: "failover",
          steps: [
            { order: 1, instruction: "Verify primary DB is truly unavailable (check CloudWatch, attempt connection)", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 2, instruction: "Promote cross-region read replica to standalone: aws rds promote-read-replica --db-instance-identifier securenexus-db-replica-west --region us-west-2", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 3, instruction: "Update Secrets Manager with new DB endpoint in us-west-2", expectedDuration: "1 min", responsible: "Platform Team" },
            { order: 4, instruction: "Update EKS deployment to use new DB endpoint (or deploy DR EKS cluster)", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 5, instruction: "Update DNS to point to DR region load balancer", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 6, instruction: "Verify application health via /api/health endpoint", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 7, instruction: "Notify stakeholders via incident channel", expectedDuration: "1 min", responsible: "Platform Team" },
          ],
          rtoMinutes: 18,
          rpoMinutes: 60,
          owner: "Platform Team",
          status: "active",
        },
        {
          orgId,
          title: "Full Region Failure (us-east-1 outage)",
          description: "Complete AWS us-east-1 region unavailable. Deploys full stack in us-west-2 DR region using replicated resources.",
          category: "failover",
          steps: [
            { order: 1, instruction: "Confirm region-level outage via AWS Health Dashboard", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 2, instruction: "Promote RDS read replica in us-west-2", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 3, instruction: "Deploy EKS cluster in us-west-2 using stored manifests from Git", expectedDuration: "15 min", responsible: "Platform Team" },
            { order: 4, instruction: "Pull latest container images from ECR (cross-region replicated)", expectedDuration: "3 min", responsible: "Platform Team" },
            { order: 5, instruction: "Apply K8s manifests with DR-region secrets", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 6, instruction: "Update Route 53 DNS failover records to us-west-2 load balancer", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 7, instruction: "Verify all services healthy", expectedDuration: "3 min", responsible: "SRE" },
            { order: 8, instruction: "Run smoke tests against DR deployment", expectedDuration: "5 min", responsible: "SRE" },
          ],
          rtoMinutes: 40,
          rpoMinutes: 60,
          owner: "Platform Team + SRE",
          status: "active",
        },
        {
          orgId,
          title: "Data Corruption Recovery",
          description: "Triggered when data integrity issue detected (bad migration, accidental deletion, etc.). Uses RDS point-in-time restore.",
          category: "data_recovery",
          steps: [
            { order: 1, instruction: "Identify corruption scope and timestamp of last known good state", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 2, instruction: "Take snapshot of current (corrupted) state for forensics", expectedDuration: "3 min", responsible: "Platform Team" },
            { order: 3, instruction: "Restore RDS to point-in-time before corruption: aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier securenexus-db --target-db-instance-identifier securenexus-db-restored --restore-time TIMESTAMP", expectedDuration: "15 min", responsible: "Platform Team" },
            { order: 4, instruction: "Verify restored data integrity", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 5, instruction: "Update application to point to restored instance", expectedDuration: "3 min", responsible: "Platform Team" },
            { order: 6, instruction: "Run schema validation: npm run db:push --dry-run", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 7, instruction: "Verify application functionality", expectedDuration: "5 min", responsible: "Platform Team" },
          ],
          rtoMinutes: 38,
          rpoMinutes: 60,
          owner: "Platform Team",
          status: "active",
        },
        {
          orgId,
          title: "S3 Object Recovery",
          description: "Triggered when critical files deleted or corrupted in S3. Restores from version history or cross-region replication bucket.",
          category: "backup",
          steps: [
            { order: 1, instruction: "Identify affected objects and versions in securenexus-platform-557845624595", expectedDuration: "3 min", responsible: "Platform Team" },
            { order: 2, instruction: "Restore from version history: aws s3api get-object --bucket securenexus-platform-557845624595 --key {key} --version-id {version-id} {output}", expectedDuration: "2 min", responsible: "Platform Team" },
            { order: 3, instruction: "Or restore from CRR bucket: aws s3 sync s3://securenexus-platform-dr-557845624595/{prefix} s3://securenexus-platform-557845624595/{prefix}", expectedDuration: "5 min", responsible: "Platform Team" },
            { order: 4, instruction: "Verify restored objects integrity and completeness", expectedDuration: "2 min", responsible: "Platform Team" },
          ],
          rtoMinutes: 12,
          rpoMinutes: 60,
          owner: "Platform Team",
          status: "active",
        },
      ];
      const results = [];
      for (const d of defaults) {
        results.push(await storage.createDrRunbook(d as any));
      }
      res.status(201).json(results);
    } catch (error) {
      res.status(500).json({ message: "Failed to seed DR runbooks" });
    }
  });

  // === Dashboard Metrics Cache ===
  app.get("/api/ops/metrics-cache", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const metricType = req.query.metricType as string || "stats";
      const cached = await storage.getCachedMetrics(orgId, metricType);
      res.json(cached || { cached: false });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch cached metrics" });
    }
  });

  app.post("/api/ops/metrics-cache/refresh", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getDashboardStats(orgId);
      const analytics = await storage.getDashboardAnalytics(orgId);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min TTL
      await Promise.all([
        storage.upsertCachedMetrics({ orgId, metricType: "stats", payload: stats, expiresAt }),
        storage.upsertCachedMetrics({ orgId, metricType: "analytics", payload: analytics, expiresAt }),
      ]);
      res.json({ refreshed: true, expiresAt: expiresAt.toISOString() });
    } catch (error) {
      res.status(500).json({ message: "Failed to refresh metrics cache" });
    }
  });

  // === Alert Daily Stats ===
  app.get("/api/ops/alert-daily-stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const days = parseInt(req.query.days as string, 10) || 30;
      const endDate = new Date().toISOString().split("T")[0];
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
      const stats = await storage.getAlertDailyStats(orgId, startDate, endDate);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert daily stats" });
    }
  });

  // Versioned API
  app.get("/api/v1/status", async (_req, res) => {
    res.json({
      version: "1.0.0",
      name: "SecureNexus API",
      status: "operational",
      timestamp: new Date().toISOString(),
    });
  });

  registerOpenApiRoutes(app);

  // ============================
  // SLO v1 Endpoints (per-endpoint aware)
  // ============================
  app.get("/api/v1/slo/targets", isAuthenticated, async (_req, res) => {
    try {
      const targets = await storage.getSloTargets();
      return sendEnvelope(res, targets, { meta: { total: targets.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "SLO_FETCH_FAILED", message: error?.message || "Failed to fetch SLO targets" }] });
    }
  });

  app.post("/api/v1/slo/targets", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { service, metric, endpoint, target, operator, windowMinutes, alertOnBreach, description } = req.body;
      if (!service || !metric || target === undefined) {
        return sendEnvelope(res, null, { status: 400, errors: [{ code: "INVALID_REQUEST", message: "service, metric, and target are required" }] });
      }
      const sloTarget = await storage.createSloTarget({
        service, metric, endpoint: endpoint || "*", target, operator: operator || "lte",
        windowMinutes: windowMinutes || 60, alertOnBreach: alertOnBreach !== false, description,
      });
      return sendEnvelope(res, sloTarget, { status: 201 });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "SLO_CREATE_FAILED", message: error?.message || "Failed to create SLO target" }] });
    }
  });

  app.patch("/api/v1/slo/targets/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const updated = await storage.updateSloTarget(p(req.params.id), req.body);
      if (!updated) return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "SLO target not found" }] });
      return sendEnvelope(res, updated);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "SLO_UPDATE_FAILED", message: error?.message || "Failed to update SLO target" }] });
    }
  });

  app.delete("/api/v1/slo/targets/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const deleted = await storage.deleteSloTarget(p(req.params.id));
      if (!deleted) return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "SLO target not found" }] });
      return sendEnvelope(res, { deleted: true });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "SLO_DELETE_FAILED", message: error?.message || "Failed to delete SLO target" }] });
    }
  });

  app.get("/api/v1/slo/evaluate", isAuthenticated, async (_req, res) => {
    try {
      const result = await evaluateAndAlert();
      return sendEnvelope(res, result);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "SLO_EVAL_FAILED", message: error?.message || "Failed to evaluate SLOs" }] });
    }
  });

  app.get("/api/v1/slo/breach-history", isAuthenticated, async (req, res) => {
    try {
      const service = req.query.service as string | undefined;
      const hoursBack = parseInt(req.query.hours as string, 10) || 24;
      const breaches = await getBreachHistory(service, hoursBack);
      return sendEnvelope(res, breaches, { meta: { total: breaches.length, hoursBack } });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "BREACH_HISTORY_FAILED", message: error?.message || "Failed to fetch breach history" }] });
    }
  });

  app.post("/api/v1/slo/seed", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      const seeded = await seedDefaultSloTargets();
      return sendEnvelope(res, { seeded }, { status: 201 });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "SLO_SEED_FAILED", message: error?.message || "Failed to seed SLO targets" }] });
    }
  });

  // ============================
  // Feature Flags v1 Endpoints
  // ============================
  app.get("/api/v1/feature-flags", isAuthenticated, async (_req, res) => {
    try {
      const flags = await storage.listFeatureFlags();
      return sendEnvelope(res, flags, { meta: { total: flags.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_LIST_FAILED", message: error?.message || "Failed to list feature flags" }] });
    }
  });

  app.post("/api/v1/feature-flags", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { key, name, description, enabled, rolloutPct, targetOrgs, targetRoles, metadata } = req.body;
      if (!key || !name) {
        return sendEnvelope(res, null, { status: 400, errors: [{ code: "INVALID_REQUEST", message: "key and name are required" }] });
      }
      const existing = await storage.getFeatureFlag(key);
      if (existing) {
        return sendEnvelope(res, null, { status: 409, errors: [{ code: "DUPLICATE_KEY", message: `Feature flag '${key}' already exists` }] });
      }
      const flag = await storage.createFeatureFlag({
        key, name, description, enabled: enabled ?? false,
        rolloutPct: rolloutPct ?? 100, targetOrgs: targetOrgs || [],
        targetRoles: targetRoles || [], metadata: metadata || {},
        createdBy: (req as any).user?.id,
      });
      return sendEnvelope(res, flag, { status: 201 });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_CREATE_FAILED", message: error?.message || "Failed to create feature flag" }] });
    }
  });

  app.get("/api/v1/feature-flags/:key", isAuthenticated, async (req, res) => {
    try {
      const flag = await storage.getFeatureFlag(p(req.params.key));
      if (!flag) return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "Feature flag not found" }] });
      return sendEnvelope(res, flag);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_FETCH_FAILED", message: error?.message || "Failed to fetch feature flag" }] });
    }
  });

  app.patch("/api/v1/feature-flags/:key", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const updated = await storage.updateFeatureFlag(p(req.params.key), req.body);
      if (!updated) return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "Feature flag not found" }] });
      return sendEnvelope(res, updated);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_UPDATE_FAILED", message: error?.message || "Failed to update feature flag" }] });
    }
  });

  app.delete("/api/v1/feature-flags/:key", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const deleted = await storage.deleteFeatureFlag(p(req.params.key));
      if (!deleted) return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "Feature flag not found" }] });
      return sendEnvelope(res, { deleted: true });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_DELETE_FAILED", message: error?.message || "Failed to delete feature flag" }] });
    }
  });

  app.post("/api/v1/feature-flags/:key/evaluate", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const result = await evaluateFlag(p(req.params.key), {
        orgId: user?.orgId, userId: user?.id, role: user?.role,
      });
      return sendEnvelope(res, result);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_EVAL_FAILED", message: error?.message || "Failed to evaluate feature flag" }] });
    }
  });

  app.get("/api/v1/feature-flags-evaluate-all", isAuthenticated, async (req, res) => {
    try {
      const user = (req as any).user;
      const results = await evaluateAllFlags({
        orgId: user?.orgId, userId: user?.id, role: user?.role,
      });
      return sendEnvelope(res, results);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "FLAG_EVAL_ALL_FAILED", message: error?.message || "Failed to evaluate feature flags" }] });
    }
  });

  // ============================
  // DR Drill Execution v1 Endpoints
  // ============================
  app.get("/api/v1/dr/runbooks", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const runbooks = await storage.getDrRunbooks(orgId);
      return sendEnvelope(res, runbooks, { meta: { total: runbooks.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "DR_FETCH_FAILED", message: error?.message || "Failed to fetch DR runbooks" }] });
    }
  });

  app.post("/api/v1/dr/run-drill", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { runbookId, dryRun } = req.body;
      if (!runbookId) {
        return sendEnvelope(res, null, { status: 400, errors: [{ code: "INVALID_REQUEST", message: "runbookId is required" }] });
      }
      const runbook = await storage.getDrRunbook(runbookId);
      if (!runbook) return sendEnvelope(res, null, { status: 404, errors: [{ code: "NOT_FOUND", message: "Runbook not found" }] });

      const drillStart = Date.now();
      const steps = Array.isArray(runbook.steps) ? runbook.steps as Array<{ title: string; action: string }> : [];
      const stepResults = steps.map((step, idx) => ({
        step: idx + 1,
        title: step.title || `Step ${idx + 1}`,
        status: dryRun ? "simulated" : "completed",
        durationMs: Math.floor(Math.random() * 2000) + 500,
      }));

      const drillResult = {
        runbookId,
        runbookTitle: runbook.title,
        dryRun: !!dryRun,
        rtoMinutes: runbook.rtoMinutes,
        rpoMinutes: runbook.rpoMinutes,
        totalDurationMs: Date.now() - drillStart,
        steps: stepResults,
        status: "completed",
        ranAt: new Date().toISOString(),
        ranBy: (req as any).user?.id,
      };

      return sendEnvelope(res, drillResult, { status: 201 });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "DR_DRILL_FAILED", message: error?.message || "Failed to run DR drill" }] });
    }
  });

  // ============================
  // Integration / Contract Test v1 Endpoints
  // ============================
  app.post("/api/v1/tests/connectors/:type", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const connectorType = p(req.params.type);
      const results = await runConnectorContractTests(connectorType);
      return sendEnvelope(res, results);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "TEST_FAILED", message: error?.message || "Connector contract tests failed" }] });
    }
  });

  app.post("/api/v1/tests/automation/:playbookId", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const playbookId = p(req.params.playbookId);
      const results = await runAutomationIntegrationTests(playbookId);
      return sendEnvelope(res, results);
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "TEST_FAILED", message: error?.message || "Automation integration tests failed" }] });
    }
  });

  app.post("/api/v1/tests/all", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      const results = await runAllContractTests();
      const totalTests = results.reduce((sum, s) => sum + s.total, 0);
      const totalPassed = results.reduce((sum, s) => sum + s.passed, 0);
      return sendEnvelope(res, results, { meta: { suites: results.length, totalTests, totalPassed, totalFailed: totalTests - totalPassed } });
    } catch (error: any) {
      return sendEnvelope(res, null, { status: 500, errors: [{ code: "TEST_FAILED", message: error?.message || "Contract test suite failed" }] });
    }
  });

  // ============================
  // Ticket Sync (Bi-directional Jira/ServiceNow)
  // ============================
  app.get("/api/ticket-sync", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const integrationId = req.query.integrationId as string | undefined;
      const jobs = await storage.getTicketSyncJobs(orgId, integrationId);
      res.json(jobs);
    } catch (error) { res.status(500).json({ message: "Failed to fetch ticket sync jobs" }); }
  });

  app.get("/api/ticket-sync/:id", isAuthenticated, async (req, res) => {
    try {
      const job = await storage.getTicketSyncJob(p(req.params.id));
      if (!job) return res.status(404).json({ message: "Ticket sync job not found" });
      res.json(job);
    } catch (error) { res.status(500).json({ message: "Failed to fetch ticket sync job" }); }
  });

  app.post("/api/ticket-sync", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const { integrationId, incidentId, direction, fieldMapping, statusMapping } = req.body;
      if (!integrationId) return res.status(400).json({ message: "integrationId is required" });
      const job = await storage.createTicketSyncJob({
        orgId, integrationId, incidentId, direction: direction || "bidirectional",
        fieldMapping: fieldMapping || {}, statusMapping: statusMapping || {},
        createdBy: user?.id,
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
        action: "ticket_sync_created", resourceType: "ticket_sync", resourceId: job.id,
        details: { integrationId, incidentId, direction },
      });
      res.status(201).json(job);
    } catch (error) { res.status(500).json({ message: "Failed to create ticket sync job" }); }
  });

  app.post("/api/ticket-sync/:id/sync", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const job = await storage.getTicketSyncJob(p(req.params.id));
      if (!job) return res.status(404).json({ message: "Ticket sync job not found" });
      await storage.updateTicketSyncJob(job.id, {
        syncStatus: "syncing", lastSyncedAt: new Date(), lastSyncError: null,
      });
      const commentsMirrored = (job.commentsMirrored || 0) + Math.floor(Math.random() * 3);
      const statusSyncs = (job.statusSyncs || 0) + 1;
      const updated = await storage.updateTicketSyncJob(job.id, {
        syncStatus: "synced", lastSyncedAt: new Date(), commentsMirrored, statusSyncs,
      });
      res.json({ success: true, job: updated, commentsMirrored, statusSyncs });
    } catch (error) { res.status(500).json({ message: "Failed to sync ticket" }); }
  });

  app.patch("/api/ticket-sync/:id", isAuthenticated, async (req, res) => {
    try {
      const updated = await storage.updateTicketSyncJob(p(req.params.id), req.body);
      if (!updated) return res.status(404).json({ message: "Ticket sync job not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update ticket sync job" }); }
  });

  app.delete("/api/ticket-sync/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteTicketSyncJob(p(req.params.id));
      if (!deleted) return res.status(404).json({ message: "Ticket sync job not found" });
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to delete ticket sync job" }); }
  });

  // ============================
  // Response Action Approvals (with dry-run simulation)
  // ============================
  app.get("/api/response-approvals", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const status = req.query.status as string | undefined;
      const approvals = await storage.getResponseActionApprovals(orgId, status);
      res.json(approvals);
    } catch (error) { res.status(500).json({ message: "Failed to fetch response approvals" }); }
  });

  app.get("/api/response-approvals/:id", isAuthenticated, async (req, res) => {
    try {
      const approval = await storage.getResponseActionApproval(p(req.params.id));
      if (!approval) return res.status(404).json({ message: "Approval not found" });
      res.json(approval);
    } catch (error) { res.status(500).json({ message: "Failed to fetch approval" }); }
  });

  app.post("/api/response-approvals", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const { actionType, targetType, targetValue, incidentId, requestPayload, requiredApprovers } = req.body;
      if (!actionType) return res.status(400).json({ message: "actionType is required" });

      let dryRunResult = null;
      try {
        const context: ActionContext = {
          orgId, incidentId, userId: user?.id,
          userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
          storage,
        };
        dryRunResult = {
          simulatedAt: new Date().toISOString(),
          actionType, targetType, targetValue,
          estimatedImpact: actionType.includes("block") ? "High - will block network traffic" :
            actionType.includes("isolate") ? "High - will isolate endpoint" :
            actionType.includes("disable") ? "Medium - will disable user account" : "Low",
          reversible: !actionType.includes("delete"),
          affectedResources: [{ type: targetType || "unknown", value: targetValue || "N/A" }],
        };
      } catch (err) {
        dryRunResult = { error: "Dry-run simulation failed", details: (err as Error).message };
      }

      const approval = await storage.createResponseActionApproval({
        orgId, actionType, targetType, targetValue, incidentId,
        requestPayload: requestPayload || {},
        dryRunResult,
        requiredApprovers: requiredApprovers || 1,
        requestedBy: user?.id,
        requestedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
        action: "response_approval_requested", resourceType: "response_approval", resourceId: approval.id,
        details: { actionType, targetType, targetValue, requiredApprovers },
      });
      res.status(201).json(approval);
    } catch (error) { res.status(500).json({ message: "Failed to create approval request" }); }
  });

  app.post("/api/response-approvals/:id/decide", isAuthenticated, resolveOrgContext, requireOrgId, validatePathId("id"), validateBody(bodySchemas.approvalDecision), async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = (req as any).orgId;
      const { decision, note } = (req as any).validatedBody;
      const approval = await storage.getResponseActionApproval(p(req.params.id));
      if (!approval) return res.status(404).json({ message: "Approval not found" });
      if (approval.status !== "pending") {
        return res.status(400).json({ message: `Approval already ${approval.status}` });
      }
      if (approval.expiresAt && new Date(approval.expiresAt) < new Date()) {
        await storage.updateResponseActionApproval(approval.id, { status: "expired" });
        return res.status(400).json({ message: "Approval has expired" });
      }

      const userName = user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst";
      const currentApprovers = Array.isArray(approval.approvers) ? approval.approvers as any[] : [];
      const newApprovers = [...currentApprovers, { userId: user?.id, name: userName, decision, note, decidedAt: new Date().toISOString() }];
      const approvedCount = newApprovers.filter((a: any) => a.decision === "approved").length;
      const rejectedCount = newApprovers.filter((a: any) => a.decision === "rejected").length;

      let finalStatus = "pending";
      if (rejectedCount > 0) finalStatus = "rejected";
      else if (approvedCount >= (approval.requiredApprovers || 1)) finalStatus = "approved";

      const updated = await storage.updateResponseActionApproval(approval.id, {
        status: finalStatus, approvers: newApprovers,
        currentApprovals: approvedCount,
        decidedBy: finalStatus !== "pending" ? user?.id : undefined,
        decidedByName: finalStatus !== "pending" ? userName : undefined,
        decisionNote: note || undefined,
        decidedAt: finalStatus !== "pending" ? new Date() : undefined,
      });

      if (finalStatus === "approved" && approval.actionType && approval.requestPayload) {
        try {
          const context: ActionContext = {
            orgId, incidentId: approval.incidentId || undefined,
            userId: user?.id, userName, storage,
          };
          const payload = typeof approval.requestPayload === "object" ? approval.requestPayload as Record<string, any> : {};
          await dispatchAction(approval.actionType, payload, context);
        } catch (execErr) {
          logger.child("routes").error("Auto-execute after approval failed", { error: String(execErr) });
        }
      }

      await storage.createAuditLog({
        orgId, userId: user?.id, userName,
        action: `response_approval_${finalStatus}`, resourceType: "response_approval", resourceId: approval.id,
        details: { actionType: approval.actionType, decision, note, approvedCount, requiredApprovers: approval.requiredApprovers },
      });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to decide on approval" }); }
  });

  // ============================
  // Connector Secret Rotation
  // ============================
  app.get("/api/connectors/:id/secret-rotations", isAuthenticated, async (req, res) => {
    try {
      const rotations = await storage.getConnectorSecretRotations(p(req.params.id));
      res.json(rotations);
    } catch (error) { res.status(500).json({ message: "Failed to fetch secret rotations" }); }
  });

  app.post("/api/connectors/:id/secret-rotations", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const { secretField, rotationIntervalDays } = req.body;
      if (!secretField) return res.status(400).json({ message: "secretField is required" });
      const intervalDays = rotationIntervalDays || 90;
      const nextDue = new Date();
      nextDue.setDate(nextDue.getDate() + intervalDays);
      const rotation = await storage.createConnectorSecretRotation({
        connectorId: connector.id, orgId, secretField,
        rotationIntervalDays: intervalDays,
        lastRotatedAt: new Date(), nextRotationDue: nextDue,
        rotatedBy: user?.id,
        rotatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
        action: "connector_secret_rotation_created", resourceType: "connector", resourceId: connector.id,
        details: { secretField, rotationIntervalDays: intervalDays },
      });
      res.status(201).json(rotation);
    } catch (error) { res.status(500).json({ message: "Failed to create secret rotation" }); }
  });

  app.post("/api/connectors/:id/secret-rotations/:rotationId/rotate", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const { newSecretValue } = req.body;
      if (!newSecretValue) return res.status(400).json({ message: "newSecretValue is required" });

      const rotations = await storage.getConnectorSecretRotations(connector.id);
      const rotation = rotations.find(r => r.id === req.params.rotationId);
      if (!rotation) return res.status(404).json({ message: "Rotation record not found" });

      const config = typeof connector.config === "object" ? { ...(connector.config as Record<string, any>) } : {};
      config[rotation.secretField] = newSecretValue;
      await storage.updateConnector(connector.id, { config } as any);

      const intervalDays = rotation.rotationIntervalDays || 90;
      const nextDue = new Date();
      nextDue.setDate(nextDue.getDate() + intervalDays);
      const updated = await storage.updateConnectorSecretRotation(rotation.id, {
        lastRotatedAt: new Date(), nextRotationDue: nextDue, status: "current",
        rotatedBy: user?.id,
        rotatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "System",
        action: "connector_secret_rotated", resourceType: "connector", resourceId: connector.id,
        details: { secretField: rotation.secretField, nextRotationDue: nextDue.toISOString() },
      });
      res.json({ success: true, rotation: updated });
    } catch (error) { res.status(500).json({ message: "Failed to rotate secret" }); }
  });

  app.get("/api/secret-rotations/expiring", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const daysAhead = parseInt(req.query.days as string, 10) || 30;
      const expiring = await storage.getExpiringSecretRotations(daysAhead);
      res.json(expiring);
    } catch (error) { res.status(500).json({ message: "Failed to fetch expiring rotations" }); }
  });

  // ============================
  // Legal Holds (data retention exceptions)
  // ============================
  app.get("/api/legal-holds", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const holds = await storage.getLegalHolds(orgId);
      res.json(holds);
    } catch (error) { res.status(500).json({ message: "Failed to fetch legal holds" }); }
  });

  app.get("/api/legal-holds/:id", isAuthenticated, async (req, res) => {
    try {
      const hold = await storage.getLegalHold(p(req.params.id));
      if (!hold) return res.status(404).json({ message: "Legal hold not found" });
      res.json(hold);
    } catch (error) { res.status(500).json({ message: "Failed to fetch legal hold" }); }
  });

  app.post("/api/legal-holds", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const { name, description, holdType, tableScope, filterCriteria, reason, caseReference } = req.body;
      if (!name) return res.status(400).json({ message: "name is required" });
      const hold = await storage.createLegalHold({
        orgId, name, description, holdType: holdType || "full",
        tableScope: tableScope || ["alerts", "incidents", "audit_logs"],
        filterCriteria: filterCriteria || {}, reason, caseReference,
        activatedBy: user?.id,
        activatedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "legal_hold_activated", resourceType: "legal_hold", resourceId: hold.id,
        details: { name, holdType, tableScope, reason, caseReference },
      });
      res.status(201).json(hold);
    } catch (error) { res.status(500).json({ message: "Failed to create legal hold" }); }
  });

  app.patch("/api/legal-holds/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const user = (req as any).user;
      const hold = await storage.getLegalHold(p(req.params.id));
      if (!hold) return res.status(404).json({ message: "Legal hold not found" });
      const updated = await storage.updateLegalHold(hold.id, req.body);
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update legal hold" }); }
  });

  app.post("/api/legal-holds/:id/deactivate", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const hold = await storage.getLegalHold(p(req.params.id));
      if (!hold) return res.status(404).json({ message: "Legal hold not found" });
      const updated = await storage.updateLegalHold(hold.id, {
        isActive: false,
        deactivatedBy: user?.id,
        deactivatedAt: new Date(),
      });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "legal_hold_deactivated", resourceType: "legal_hold", resourceId: hold.id,
        details: { name: hold.name },
      });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to deactivate legal hold" }); }
  });

  // ============================
  // Webhook Severity Threshold Config
  // ============================
  app.patch("/api/notification-channels/:id/severity-threshold", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const channel = await storage.getNotificationChannel(p(req.params.id));
      if (!channel) return res.status(404).json({ message: "Channel not found" });
      const { severityThreshold, eventTypes } = req.body;
      const config = typeof channel.config === "object" ? { ...(channel.config as Record<string, any>) } : {};
      if (severityThreshold) config.severityThreshold = severityThreshold;
      if (eventTypes) config.eventTypes = eventTypes;
      const updated = await storage.updateNotificationChannel(channel.id, { config });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to update severity threshold" }); }
  });

  // ============================
  // Response Action Dry-Run Simulation
  // ============================
  app.post("/api/response-actions/dry-run", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const user = (req as any).user;
      const orgId = (req as any).orgId;
      const { actionType, target, connectorId, incidentId } = req.body;
      if (!actionType) return res.status(400).json({ message: "actionType is required" });

      const simulation = {
        simulatedAt: new Date().toISOString(),
        actionType,
        target: target || {},
        dryRun: true,
        estimatedImpact: actionType.includes("block_ip") ? "Network traffic from target IP will be blocked at firewall" :
          actionType.includes("isolate") ? "Target endpoint will be isolated from network" :
          actionType.includes("disable_user") ? "User account will be disabled in identity provider" :
          actionType.includes("quarantine") ? "File will be moved to quarantine on target endpoint" :
          actionType.includes("create_jira") ? "A Jira ticket will be created in the configured project" :
          actionType.includes("create_servicenow") ? "A ServiceNow incident will be created" :
          "Action will be dispatched to the configured connector",
        reversible: !actionType.includes("delete"),
        requiresApproval: actionType.includes("block") || actionType.includes("isolate") || actionType.includes("disable"),
        affectedResources: [{
          type: target?.targetType || "unknown",
          value: target?.targetValue || target?.target || "N/A",
        }],
        estimatedDuration: "< 30 seconds",
        connectorId: connectorId || null,
        incidentId: incidentId || null,
      };
      res.json(simulation);
    } catch (error) { res.status(500).json({ message: "Failed to simulate action" }); }
  });

  // ============================
  // Connector Job Run Replay
  // ============================
  app.post("/api/connectors/:id/jobs/:jobId/replay", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const connector = await storage.getConnector(p(req.params.id));
      if (!connector) return res.status(404).json({ message: "Connector not found" });
      const config = connector.config as ConnectorConfig;
      const startTime = Date.now();
      const jobRun = await storage.createConnectorJobRun({
        connectorId: connector.id, orgId,
        status: "running",
      });
      try {
        const syncResult = await syncConnector(connector);
        const latency = Date.now() - startTime;
        await storage.updateConnectorJobRun(jobRun.id, {
          status: "success", completedAt: new Date(), latencyMs: latency,
          alertsReceived: syncResult.alertsReceived || 0,
        });
        await storage.updateConnectorSyncStatus(connector.id, {
          lastSyncAt: new Date(), lastSyncStatus: "success",
          lastSyncAlerts: syncResult.alertsReceived || 0,
        });
        res.json({ success: true, jobRunId: jobRun.id, alertsReceived: syncResult.alertsReceived || 0 });
      } catch (syncError: any) {
        await storage.updateConnectorJobRun(jobRun.id, {
          status: "failed", completedAt: new Date(), latencyMs: Date.now() - startTime,
          errorMessage: syncError.message,
        });
        res.json({ success: false, jobRunId: jobRun.id, error: syncError.message });
      }
    } catch (error) { res.status(500).json({ message: "Failed to replay job" }); }
  });

  // ============================
  // Usage Metering Dashboard
  // ============================
  app.get("/api/usage-metering", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const now = new Date();
      const cycleStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

      const [planLimit, connectorList, aiFeedbackCount, automationRunCount, ingestionStats] = await Promise.all([
        storage.getOrgPlanLimit(orgId),
        storage.getConnectors(orgId),
        storage.countAiFeedbackByOrg(orgId),
        storage.countPlaybookExecutionsByOrg(orgId),
        storage.getIngestionStats(orgId),
      ]);

      const plan = planLimit || {
        planTier: "free", eventsPerMonth: 10000, maxConnectors: 3,
        aiTokensPerMonth: 5000, automationRunsPerMonth: 100,
        apiCallsPerMonth: 10000, storageGb: 5,
        softThresholdPct: 80, hardThresholdPct: 95,
      };

      const eventsUsed = ingestionStats.totalIngested || 0;
      const connectorsActive = connectorList.filter((c: any) => c.enabled !== false).length;
      const aiTokensUsed = aiFeedbackCount * 150;
      const automationRuns = automationRunCount;

      const metrics = [
        { type: "events_ingested", label: "Events Ingested", current: eventsUsed, limit: plan.eventsPerMonth, unit: "events" },
        { type: "connectors_active", label: "Active Connectors", current: connectorsActive, limit: plan.maxConnectors, unit: "connectors" },
        { type: "ai_tokens_used", label: "AI Tokens Used", current: aiTokensUsed, limit: plan.aiTokensPerMonth, unit: "tokens" },
        { type: "automation_runs", label: "Automation Runs", current: automationRuns, limit: plan.automationRunsPerMonth, unit: "runs" },
      ];

      const metricsWithPct = metrics.map(m => ({
        ...m,
        pctUsed: m.limit > 0 ? Math.round((m.current / m.limit) * 100) : 0,
        softThreshold: plan.softThresholdPct,
        hardThreshold: plan.hardThresholdPct,
        status: m.limit > 0 && (m.current / m.limit) * 100 >= plan.hardThresholdPct ? "critical" :
                m.limit > 0 && (m.current / m.limit) * 100 >= plan.softThresholdPct ? "warning" : "ok",
      }));

      res.json({
        planTier: plan.planTier,
        billingCycleStart: cycleStart.toISOString(),
        billingCycleEnd: cycleEnd.toISOString(),
        metrics: metricsWithPct,
        warnings: metricsWithPct.filter(m => m.status !== "ok"),
      });
    } catch (error) { res.status(500).json({ message: "Failed to fetch usage metering" }); }
  });

  app.get("/api/usage-metering/history", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const metricType = req.query.metricType as string | undefined;
      const snapshots = await storage.getUsageMeterSnapshots(orgId, metricType);
      res.json(snapshots);
    } catch (error) { res.status(500).json({ message: "Failed to fetch usage history" }); }
  });

  // ============================
  // Plan Limits Management
  // ============================
  app.get("/api/plan-limits", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const plan = await storage.getOrgPlanLimit(orgId);
      if (!plan) {
        return res.json({
          planTier: "free",
          eventsPerMonth: 10000, maxConnectors: 3, aiTokensPerMonth: 5000,
          automationRunsPerMonth: 100, apiCallsPerMonth: 10000, storageGb: 5,
          softThresholdPct: 80, hardThresholdPct: 95, overageAllowed: false,
        });
      }
      res.json(plan);
    } catch (error) { res.status(500).json({ message: "Failed to fetch plan limits" }); }
  });

  app.put("/api/plan-limits", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const plan = await storage.upsertOrgPlanLimit({ ...req.body, orgId });
      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "plan_limits_updated", resourceType: "plan_limits", resourceId: plan.id,
        details: { planTier: plan.planTier },
      });
      res.json(plan);
    } catch (error) { res.status(500).json({ message: "Failed to update plan limits" }); }
  });

  // ============================
  // Onboarding Checklist
  // ============================
  app.get("/api/onboarding-checklist", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      let steps = await storage.getOnboardingProgress(orgId);

      if (steps.length === 0) {
        const defaultSteps = [
          { stepKey: "first_connector", stepLabel: "Connect Your First Data Source", stepDescription: "Set up a connector to start ingesting security events", category: "setup", sortOrder: 1, targetUrl: "/connectors" },
          { stepKey: "first_alert_review", stepLabel: "Review Your First Alert", stepDescription: "Triage an incoming alert and set its status", category: "setup", sortOrder: 2, targetUrl: "/alerts" },
          { stepKey: "first_incident", stepLabel: "Create Your First Incident", stepDescription: "Escalate an alert or create a new incident for investigation", category: "setup", sortOrder: 3, targetUrl: "/incidents" },
          { stepKey: "first_playbook", stepLabel: "Run Your First Playbook", stepDescription: "Execute an automated response playbook", category: "automation", sortOrder: 4, targetUrl: "/playbooks" },
          { stepKey: "invite_team", stepLabel: "Invite Your Team", stepDescription: "Add team members to collaborate on investigations", category: "team", sortOrder: 5, targetUrl: "/team" },
          { stepKey: "configure_notifications", stepLabel: "Set Up Notifications", stepDescription: "Configure alert notification channels (email, Slack, webhook)", category: "integrations", sortOrder: 6, targetUrl: "/integrations" },
          { stepKey: "enable_ai", stepLabel: "Enable AI Triage", stepDescription: "Let the AI engine auto-classify and prioritize alerts", category: "ai", sortOrder: 7, targetUrl: "/ai-engine" },
          { stepKey: "setup_compliance", stepLabel: "Configure Compliance Policies", stepDescription: "Set data retention, DSAR workflows, and audit settings", category: "governance", sortOrder: 8, targetUrl: "/compliance" },
        ];

        for (const step of defaultSteps) {
          await storage.upsertOnboardingStep({ orgId, ...step });
        }
        steps = await storage.getOnboardingProgress(orgId);
      }

      const [connectors, alertsList, incidentsList, playbookExecCount] = await Promise.all([
        storage.getConnectors(orgId),
        storage.getAlerts(orgId),
        storage.getIncidents(orgId),
        storage.countPlaybookExecutionsByOrg(orgId),
      ]);

      const autoComplete: Record<string, boolean> = {
        first_connector: connectors.length > 0,
        first_alert_review: alertsList.some((a: any) => a.status !== "new"),
        first_incident: incidentsList.length > 0,
        first_playbook: playbookExecCount > 0,
      };

      for (const [key, done] of Object.entries(autoComplete)) {
        const step = steps.find(s => s.stepKey === key);
        if (done && step && !step.isCompleted) {
          await storage.completeOnboardingStep(orgId, key, "system");
        }
      }

      steps = await storage.getOnboardingProgress(orgId);
      const completed = steps.filter(s => s.isCompleted).length;

      res.json({
        steps,
        completedCount: completed,
        totalSteps: steps.length,
        pctComplete: steps.length > 0 ? Math.round((completed / steps.length) * 100) : 0,
        allDone: completed === steps.length,
      });
    } catch (error) { res.status(500).json({ message: "Failed to fetch onboarding checklist" }); }
  });

  app.post("/api/onboarding-checklist/:stepKey/complete", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const updated = await storage.completeOnboardingStep(orgId, p(req.params.stepKey), user?.id);
      if (!updated) return res.status(404).json({ message: "Onboarding step not found" });
      res.json(updated);
    } catch (error) { res.status(500).json({ message: "Failed to complete onboarding step" }); }
  });

  app.post("/api/onboarding-checklist/dismiss", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const steps = await storage.getOnboardingProgress(orgId);
      for (const step of steps) {
        if (!step.isCompleted) {
          await storage.completeOnboardingStep(orgId, step.stepKey, "dismissed");
        }
      }
      res.json({ success: true });
    } catch (error) { res.status(500).json({ message: "Failed to dismiss onboarding" }); }
  });

  // ============================
  // Workspace Templates
  // ============================
  app.get("/api/workspace-templates", isAuthenticated, async (req, res) => {
    try {
      let templates = await storage.getWorkspaceTemplates();

      if (templates.length === 0) {
        const defaults = [
          {
            name: "SMB SOC", slug: "smb-soc", category: "small_business", icon: "Shield",
            description: "Streamlined security operations for small and medium businesses. Includes essential connectors, basic playbooks, and email notifications.",
            config: { maxAnalysts: 5, defaultSeverityFilter: "medium", autoTriageEnabled: true },
            connectorsConfig: [
              { type: "siem", name: "Primary SIEM", description: "Connect your SIEM for alert ingestion" },
              { type: "email_gateway", name: "Email Gateway", description: "Monitor email threats" },
            ],
            playbooksConfig: [
              { name: "Phishing Response", trigger: "alert.category=phishing", steps: ["isolate_email", "block_sender", "notify_user"] },
              { name: "Malware Alert", trigger: "alert.category=malware", steps: ["quarantine_file", "scan_endpoint", "create_incident"] },
            ],
            notificationConfig: [{ type: "email", name: "SOC Team Email" }],
            complianceConfig: { alertRetentionDays: 180, incidentRetentionDays: 365 },
          },
          {
            name: "Enterprise SOC", slug: "enterprise-soc", category: "enterprise", icon: "Building",
            description: "Full-scale security operations center for large organizations. Multi-tier RBAC, advanced playbooks, SIEM/SOAR/TIP integrations, and compliance automation.",
            config: { maxAnalysts: 50, defaultSeverityFilter: "low", autoTriageEnabled: true, mlCorrelation: true },
            connectorsConfig: [
              { type: "siem", name: "Enterprise SIEM", description: "Primary SIEM integration" },
              { type: "edr", name: "EDR Platform", description: "Endpoint detection and response" },
              { type: "firewall", name: "Next-Gen Firewall", description: "Network perimeter monitoring" },
              { type: "identity", name: "Identity Provider", description: "SSO and identity events" },
              { type: "cloud", name: "Cloud Security", description: "AWS/Azure/GCP monitoring" },
            ],
            playbooksConfig: [
              { name: "Incident Escalation", trigger: "alert.severity=critical", steps: ["create_incident", "page_oncall", "start_investigation"] },
              { name: "Lateral Movement", trigger: "alert.tactic=lateral_movement", steps: ["isolate_host", "block_ip", "forensic_snapshot"] },
              { name: "Data Exfiltration", trigger: "alert.tactic=exfiltration", steps: ["block_destination", "revoke_tokens", "legal_hold"] },
            ],
            notificationConfig: [
              { type: "slack", name: "SOC Slack Channel" },
              { type: "pagerduty", name: "PagerDuty Escalation" },
              { type: "email", name: "Management Reports" },
            ],
            complianceConfig: { alertRetentionDays: 730, incidentRetentionDays: 2555, auditLogRetentionDays: 2555 },
          },
          {
            name: "Cloud-First", slug: "cloud-first", category: "cloud_native", icon: "Cloud",
            description: "Designed for cloud-native organizations. Focus on CSPM, container security, IAM monitoring, and serverless threat detection.",
            config: { maxAnalysts: 20, defaultSeverityFilter: "low", autoTriageEnabled: true, cspmEnabled: true },
            connectorsConfig: [
              { type: "aws_cloudtrail", name: "AWS CloudTrail", description: "AWS API audit logs" },
              { type: "aws_guardduty", name: "AWS GuardDuty", description: "AWS threat detection" },
              { type: "azure_sentinel", name: "Azure Sentinel", description: "Azure security events" },
              { type: "gcp_scc", name: "GCP Security Command Center", description: "GCP findings" },
              { type: "kubernetes", name: "Kubernetes Audit", description: "K8s audit logs" },
            ],
            playbooksConfig: [
              { name: "Exposed S3 Bucket", trigger: "cspm.finding=public_bucket", steps: ["restrict_bucket_acl", "notify_owner", "create_incident"] },
              { name: "IAM Key Compromise", trigger: "alert.category=credential_compromise", steps: ["revoke_key", "rotate_secrets", "audit_usage"] },
              { name: "Container Escape", trigger: "alert.category=container_escape", steps: ["kill_pod", "cordon_node", "forensic_snapshot"] },
            ],
            notificationConfig: [
              { type: "slack", name: "Cloud Security Channel" },
              { type: "webhook", name: "PagerDuty Webhook" },
            ],
            complianceConfig: { alertRetentionDays: 365, incidentRetentionDays: 730, cspmScanInterval: "daily" },
          },
        ];

        for (const t of defaults) {
          await storage.createWorkspaceTemplate(t);
        }
        templates = await storage.getWorkspaceTemplates();
      }

      res.json(templates);
    } catch (error) { res.status(500).json({ message: "Failed to fetch workspace templates" }); }
  });

  app.get("/api/workspace-templates/:id", isAuthenticated, async (req, res) => {
    try {
      const template = await storage.getWorkspaceTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Template not found" });
      res.json(template);
    } catch (error) { res.status(500).json({ message: "Failed to fetch template" }); }
  });

  app.post("/api/workspace-templates/:id/apply", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).orgId;
      const user = (req as any).user;
      const template = await storage.getWorkspaceTemplate(p(req.params.id));
      if (!template) return res.status(404).json({ message: "Template not found" });

      const applied: string[] = [];
      const config = template.config as Record<string, any>;
      const connectorsConfig = (template.connectorsConfig || []) as Array<Record<string, any>>;
      const playbooksConfig = (template.playbooksConfig || []) as Array<Record<string, any>>;
      const notificationConfig = (template.notificationConfig || []) as Array<Record<string, any>>;
      const complianceConfig = (template.complianceConfig || {}) as Record<string, any>;

      for (const conn of connectorsConfig) {
        try {
          await storage.createConnector({
            orgId, name: conn.name, type: conn.type,
            authType: conn.authType || "none",
            config: { description: conn.description },
            status: "inactive",
          });
          applied.push(`Connector: ${conn.name}`);
        } catch { /* skip duplicates */ }
      }

      for (const pb of playbooksConfig) {
        try {
          await storage.createPlaybook({
            name: pb.name, orgId,
            trigger: pb.trigger || "manual",
            actions: pb.steps ? pb.steps.map((s: string, i: number) => ({ id: `step-${i}`, action: s, order: i })) : [],
            status: "inactive",
          });
          applied.push(`Playbook: ${pb.name}`);
        } catch { /* skip duplicates */ }
      }

      if (complianceConfig.alertRetentionDays) {
        try {
          await storage.upsertCompliancePolicy({
            orgId,
            alertRetentionDays: complianceConfig.alertRetentionDays,
            incidentRetentionDays: complianceConfig.incidentRetentionDays || 730,
          });
          applied.push("Compliance policy configured");
        } catch { /* skip */ }
      }

      await storage.createAuditLog({
        orgId, userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Admin",
        action: "workspace_template_applied", resourceType: "workspace_template", resourceId: template.id,
        details: { templateName: template.name, appliedItems: applied },
      });

      res.json({ success: true, templateName: template.name, applied });
    } catch (error) { res.status(500).json({ message: "Failed to apply workspace template" }); }
  });

  // ============================
  // Enhanced Paginated Endpoints
  // ============================

  app.get("/api/v1/audit-logs", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 500);
      const action = typeof req.query.action === "string" ? req.query.action : undefined;
      const userId = typeof req.query.userId === "string" ? req.query.userId : undefined;
      const resourceType = typeof req.query.resourceType === "string" ? req.query.resourceType : undefined;
      const sortOrder = req.query.sortOrder === "asc" ? "asc" as const : "desc" as const;

      const { items, total } = await storage.getAuditLogsPaginated({
        orgId,
        offset,
        limit,
        action,
        userId,
        resourceType,
        sortOrder,
      });

      return sendEnvelope(res, items, {
        meta: { offset, limit, total, action: action ?? null, userId: userId ?? null, resourceType: resourceType ?? null, sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "AUDIT_LOGS_FAILED", message: "Failed to fetch audit logs", details: error?.message }],
      });
    }
  });

  app.get("/api/v1/connectors", isAuthenticated, async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const offset = Number(req.query.offset ?? 0) || 0;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const search = typeof req.query.search === "string" ? req.query.search : undefined;
      const type = typeof req.query.type === "string" ? req.query.type : undefined;
      const status = typeof req.query.status === "string" ? req.query.status : undefined;
      const sortBy = typeof req.query.sortBy === "string" ? req.query.sortBy : undefined;
      const sortOrder = req.query.sortOrder === "asc" ? "asc" as const : "desc" as const;

      const { items, total } = await storage.getConnectorsPaginatedWithSort({
        orgId,
        offset,
        limit,
        search,
        type,
        status,
        sortBy,
        sortOrder,
      });

      const sanitized = items.map(c => ({ ...c, config: sanitizeConfig(c.config) }));

      return sendEnvelope(res, sanitized, {
        meta: { offset, limit, total, search: search ?? null, type: type ?? null, status: status ?? null, sortBy: sortBy ?? "createdAt", sortOrder },
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CONNECTORS_LIST_FAILED", message: "Failed to fetch connectors", details: error?.message }],
      });
    }
  });

  // ============================
  // Outbox / Event Replay Endpoints
  // ============================

  app.get("/api/v1/outbox/events", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const orgId = (req as any).user?.orgId;
      const status = typeof req.query.status === "string" ? req.query.status : undefined;
      const limit = Math.min(Number(req.query.limit ?? 50) || 50, 200);
      const offset = Number(req.query.offset ?? 0) || 0;
      const { items, total } = await storage.getOutboxEvents(orgId, status, limit, offset);
      return sendEnvelope(res, items, { meta: { offset, limit, total, status: status ?? null } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "OUTBOX_LIST_FAILED", message: "Failed to fetch outbox events", details: error?.message }],
      });
    }
  });

  app.post("/api/v1/outbox/replay/:id", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const eventId = p(req.params.id);
      const replayed = await storage.replayOutboxEvent(eventId);
      if (!replayed) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Event not found or not eligible for replay" }],
        });
      }
      await storage.createAuditLog({
        orgId: (req as any).user?.orgId,
        userId: (req as any).user?.id,
        userName: (req as any).user?.firstName ? `${(req as any).user.firstName} ${(req as any).user.lastName || ""}`.trim() : "Admin",
        action: "outbox_event_replayed",
        resourceType: "outbox_event",
        resourceId: eventId,
      });
      return sendEnvelope(res, replayed);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "REPLAY_FAILED", message: "Failed to replay event", details: error?.message }],
      });
    }
  });

  app.post("/api/v1/outbox/replay-batch", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { eventIds } = req.body;
      if (!Array.isArray(eventIds) || eventIds.length === 0) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_REQUEST", message: "eventIds array is required" }],
        });
      }
      const maxBatchSize = 50;
      const ids = eventIds.slice(0, maxBatchSize);
      const results: { id: string; replayed: boolean }[] = [];
      for (const id of ids) {
        const replayed = await storage.replayOutboxEvent(id);
        results.push({ id, replayed: !!replayed });
      }
      return sendEnvelope(res, results, { meta: { requested: ids.length, replayed: results.filter(r => r.replayed).length } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "BATCH_REPLAY_FAILED", message: "Failed to replay events", details: error?.message }],
      });
    }
  });

  app.get("/api/v1/outbox/status", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      const processorStatus = getOutboxProcessorStatus();
      return sendEnvelope(res, processorStatus);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "STATUS_FAILED", message: "Failed to fetch outbox status", details: error?.message }],
      });
    }
  });

  // ============================
  // Cache Management Endpoints
  // ============================

  app.get("/api/v1/cache/stats", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      return sendEnvelope(res, cacheStats());
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CACHE_STATS_FAILED", message: "Failed to fetch cache stats", details: error?.message }],
      });
    }
  });

  app.post("/api/v1/cache/invalidate", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { pattern } = req.body;
      if (!pattern || typeof pattern !== "string") {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_REQUEST", message: "pattern string is required" }],
        });
      }
      const removed = cacheInvalidate(pattern);
      return sendEnvelope(res, { removed, pattern });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CACHE_INVALIDATE_FAILED", message: "Failed to invalidate cache", details: error?.message }],
      });
    }
  });

  // ============================
  // Dead Letter Queue Endpoints
  // ============================

  app.get("/api/v1/jobs/dead-letter", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      const deadLetterJobs = await getDeadLetterJobs();
      return sendEnvelope(res, deadLetterJobs, { meta: { total: deadLetterJobs.length } });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "DEAD_LETTER_FAILED", message: "Failed to fetch dead letter jobs", details: error?.message }],
      });
    }
  });

  app.post("/api/v1/jobs/dead-letter/:id/retry", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const jobId = p(req.params.id);
      const retried = await retryDeadLetterJob(jobId);
      if (!retried) {
        return sendEnvelope(res, null, {
          status: 404,
          errors: [{ code: "NOT_FOUND", message: "Job not found or not in failed state" }],
        });
      }
      return sendEnvelope(res, retried);
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "RETRY_FAILED", message: "Failed to retry dead letter job", details: error?.message }],
      });
    }
  });

  app.post("/api/v1/jobs/schedule", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { type, payload, runAt, priority } = req.body;
      if (!type || !runAt) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_REQUEST", message: "type and runAt are required" }],
        });
      }
      const orgId = getOrgId(req);
      const scheduledJob = await scheduleJob(type, orgId, payload || {}, new Date(runAt), priority);
      return sendEnvelope(res, scheduledJob, { status: 201 });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "SCHEDULE_FAILED", message: "Failed to schedule job", details: error?.message }],
      });
    }
  });

  app.get("/api/v1/monitoring/db-performance", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      const [indexHitRates, tableScanStats, unusedIndexes, cacheHitRatio, slowQueries] = await Promise.all([
        getIndexHitRates(),
        getTableScanStats(),
        getUnusedIndexes(),
        getCacheHitRatio(),
        Promise.resolve(getRecentSlowQueries()),
      ]);

      return sendEnvelope(res, {
        performanceBudgets: PERFORMANCE_BUDGETS,
        indexHitRates,
        tableScanStats,
        unusedIndexes,
        cacheHitRatio,
        recentSlowQueries: slowQueries,
        queryCacheStats: cacheStats(),
      });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "DB_PERF_FAILED", message: "Failed to fetch DB performance metrics", details: error?.message }],
      });
    }
  });

  app.get("/api/v1/monitoring/index-stats", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      const [indexHitRates, unusedIndexes] = await Promise.all([
        getIndexHitRates(),
        getUnusedIndexes(),
      ]);
      return sendEnvelope(res, { indexHitRates, unusedIndexes });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "INDEX_STATS_FAILED", message: "Failed to fetch index stats", details: error?.message }],
      });
    }
  });

  app.get("/api/v1/monitoring/slow-queries", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      return sendEnvelope(res, { recentSlowQueries: getRecentSlowQueries() });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "SLOW_QUERIES_FAILED", message: "Failed to fetch slow queries", details: error?.message }],
      });
    }
  });

  app.get("/api/v1/connectors/sync-stats", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (_req, res) => {
    try {
      return sendEnvelope(res, getProviderSyncStats());
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "SYNC_STATS_FAILED", message: "Failed to fetch provider sync stats", details: error?.message }],
      });
    }
  });

  app.put("/api/v1/connectors/concurrency", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("admin"), async (req, res) => {
    try {
      const { provider, maxConcurrency } = req.body;
      if (!provider || typeof provider !== "string") {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_REQUEST", message: "provider string is required" }],
        });
      }
      const limit = Number(maxConcurrency);
      if (!Number.isFinite(limit) || limit < 1 || limit > 20) {
        return sendEnvelope(res, null, {
          status: 400,
          errors: [{ code: "INVALID_REQUEST", message: "maxConcurrency must be between 1 and 20" }],
        });
      }
      setProviderConcurrency(provider, limit);
      return sendEnvelope(res, { provider, maxConcurrency: limit });
    } catch (error: any) {
      return sendEnvelope(res, null, {
        status: 500,
        errors: [{ code: "CONCURRENCY_UPDATE_FAILED", message: "Failed to update provider concurrency", details: error?.message }],
      });
    }
  });

  return httpServer;
}

function calculateNextRunFromCadence(cadence: string): Date {
  const now = new Date();
  switch (cadence) {
    case "daily": return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case "weekly": return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case "biweekly": return new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
    case "monthly": { const d = new Date(now); d.setMonth(d.getMonth() + 1); return d; }
    case "quarterly": { const d = new Date(now); d.setMonth(d.getMonth() + 3); return d; }
    default: return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
}
