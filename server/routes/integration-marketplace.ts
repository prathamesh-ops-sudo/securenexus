import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { z } from "zod";
import {
  getMarketplaceCatalog,
  getConnectorDetails,
  installConnector,
  configureInstance,
  upgradePermissions,
  getInstances,
  getInstance,
  deleteInstance,
  triggerSync,
  getSyncHistory,
  getQualityScore,
  getAllQualityScores,
  ingestWebhook,
  getWebhookEvents,
  getDeadLetterQueue,
  retryDeadLetter,
  discardDeadLetter,
  runHealthCheck,
  getHealthHistory,
  setFieldMappings,
  getFieldMappings,
  getMarketplaceStats,
  type ConnectorCategory,
  type AuthMethod,
  type SyncDirection,
  type PermissionMode,
} from "../integration-marketplace-engine";

const installSchema = z.object({
  connectorSlug: z.string().min(1).max(100),
  authMethod: z.enum(["oauth2", "service_account", "api_key", "basic", "aws_iam"]),
  syncDirection: z.enum(["inbound", "outbound", "bidirectional"]),
  config: z.record(z.unknown()).default({}),
});

const configureSchema = z.object({
  config: z.record(z.unknown()).optional(),
  syncDirection: z.enum(["inbound", "outbound", "bidirectional"]).optional(),
  syncIntervalMinutes: z.number().int().min(1).max(1440).optional(),
});

const permissionSchema = z.object({
  mode: z.enum(["read_only", "scoped_write", "full_write"]),
});

const webhookSchema = z.object({
  eventType: z.string().min(1).max(200),
  payload: z.record(z.unknown()),
  idempotencyKey: z.string().min(1).max(200),
});

const fieldMappingSchema = z.object({
  mappings: z.array(
    z.object({
      sourceField: z.string().min(1).max(200),
      targetField: z.string().min(1).max(200),
      transform: z.string().max(500).nullable().optional(),
      direction: z.enum(["inbound", "outbound", "bidirectional"]),
    }),
  ),
});

export function registerIntegrationMarketplaceRoutes(app: Express): void {
  app.get("/api/integration-marketplace/catalog", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const orgId = (req as any).orgId as string;
    const category = req.query.category as ConnectorCategory | undefined;
    const catalog = getMarketplaceCatalog(orgId, category);
    res.json(catalog);
  });

  app.get(
    "/api/integration-marketplace/catalog/:slug",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const slug = req.params.slug as string;
      const details = getConnectorDetails(slug, orgId);
      if (!details) return res.status(404).json({ message: "Connector not found" });
      res.json(details);
    },
  );

  app.get("/api/integration-marketplace/stats", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const orgId = (req as any).orgId as string;
    res.json(getMarketplaceStats(orgId));
  });

  app.post("/api/integration-marketplace/install", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const parsed = installSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
    }
    const orgId = (req as any).orgId as string;
    try {
      const instance = installConnector(
        parsed.data.connectorSlug,
        orgId,
        parsed.data.authMethod as AuthMethod,
        parsed.data.syncDirection as SyncDirection,
        parsed.data.config,
      );
      res.status(201).json(instance);
    } catch (err: unknown) {
      res.status(400).json({ message: (err as Error).message });
    }
  });

  app.get("/api/integration-marketplace/instances", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const orgId = (req as any).orgId as string;
    res.json(getInstances(orgId));
  });

  app.get(
    "/api/integration-marketplace/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = getInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Instance not found" });
      res.json(instance);
    },
  );

  app.patch(
    "/api/integration-marketplace/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const parsed = configureSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const updated = configureInstance(instanceId, orgId, parsed.data);
      if (!updated) return res.status(404).json({ message: "Instance not found" });
      res.json(updated);
    },
  );

  app.delete(
    "/api/integration-marketplace/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const deleted = deleteInstance(instanceId, orgId);
      if (!deleted) return res.status(404).json({ message: "Instance not found" });
      res.json({ success: true });
    },
  );

  app.post(
    "/api/integration-marketplace/instances/:id/permissions",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const parsed = permissionSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const updated = upgradePermissions(instanceId, orgId, parsed.data.mode as PermissionMode);
      if (!updated) return res.status(404).json({ message: "Instance not found" });
      res.json(updated);
    },
  );

  app.post(
    "/api/integration-marketplace/instances/:id/sync",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const event = triggerSync(instanceId, orgId);
      if (!event)
        return res.status(400).json({ message: "Sync failed — instance not found or permissions insufficient" });
      res.json(event);
    },
  );

  app.get(
    "/api/integration-marketplace/instances/:id/sync-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 200);
      res.json(getSyncHistory(instanceId, orgId, limit));
    },
  );

  app.get(
    "/api/integration-marketplace/instances/:id/quality",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const score = getQualityScore(instanceId, orgId);
      if (!score) return res.status(404).json({ message: "Quality score not found" });
      res.json(score);
    },
  );

  app.get(
    "/api/integration-marketplace/quality-scores",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      res.json(getAllQualityScores(orgId));
    },
  );

  app.post(
    "/api/integration-marketplace/instances/:id/webhook",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const parsed = webhookSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const event = ingestWebhook(
        instanceId,
        orgId,
        parsed.data.eventType,
        parsed.data.payload,
        parsed.data.idempotencyKey,
      );
      if (!event) return res.status(404).json({ message: "Instance not found" });
      res.json(event);
    },
  );

  app.get(
    "/api/integration-marketplace/instances/:id/webhooks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 200);
      res.json(getWebhookEvents(instanceId, orgId, limit));
    },
  );

  app.get("/api/integration-marketplace/dead-letters", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const orgId = (req as any).orgId as string;
    res.json(getDeadLetterQueue(orgId));
  });

  app.post(
    "/api/integration-marketplace/dead-letters/:id/retry",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const entryId = req.params.id as string;
      const entry = retryDeadLetter(entryId, orgId);
      if (!entry) return res.status(404).json({ message: "Dead letter entry not found" });
      res.json(entry);
    },
  );

  app.post(
    "/api/integration-marketplace/dead-letters/:id/discard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const entryId = req.params.id as string;
      const discarded = discardDeadLetter(entryId, orgId);
      if (!discarded) return res.status(404).json({ message: "Dead letter entry not found" });
      res.json({ success: true });
    },
  );

  app.post(
    "/api/integration-marketplace/instances/:id/health-check",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const check = runHealthCheck(instanceId, orgId);
      if (!check) return res.status(404).json({ message: "Instance not found" });
      res.json(check);
    },
  );

  app.get(
    "/api/integration-marketplace/instances/:id/health-history",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      res.json(getHealthHistory(instanceId, orgId, limit));
    },
  );

  app.put(
    "/api/integration-marketplace/instances/:id/field-mappings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const parsed = fieldMappingSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const normalized = parsed.data.mappings.map((m) => ({
        ...m,
        transform: m.transform ?? null,
      }));
      const mappings = setFieldMappings(instanceId, orgId, normalized);
      res.json(mappings);
    },
  );

  app.get(
    "/api/integration-marketplace/instances/:id/field-mappings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      res.json(getFieldMappings(instanceId, orgId));
    },
  );
}
