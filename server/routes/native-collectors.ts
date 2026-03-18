import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { z } from "zod";
import {
  getCollectorTemplates,
  getTemplateBySlug,
  deployCollector,
  getCollectorInstances,
  getCollectorInstance,
  updateCollectorConfig,
  deleteCollector,
  sendHeartbeat,
  ingestEvents,
  getIngestedEvents,
  triggerScan,
  getScanResults,
  getScanResult,
  getDeploymentScript,
  getDataPipelineStats,
  generateApiKey,
  type CollectorInstance,
  type CollectorType,
  type Platform,
  type DeploymentMethod,
  type CollectorStatus,
} from "../native-collectors-engine";

const REDACTED = "***REDACTED***";

function redactInstanceConfig(instance: CollectorInstance): CollectorInstance {
  const template = getTemplateBySlug(instance.templateSlug);
  if (!template) return instance;

  const secretKeys = new Set(template.configSchema.filter((f) => f.type === "secret").map((f) => f.key));
  if (secretKeys.size === 0) return instance;

  const redactedConfig: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(instance.config)) {
    redactedConfig[key] = secretKeys.has(key) ? REDACTED : value;
  }
  return { ...instance, config: redactedConfig };
}

function stripRedactedKeys(config: Record<string, unknown>, templateSlug: string): Record<string, unknown> {
  const template = getTemplateBySlug(templateSlug);
  if (!template) return config;
  const secretKeys = new Set(template.configSchema.filter((f) => f.type === "secret").map((f) => f.key));
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    if (secretKeys.has(key) && value === REDACTED) continue;
    cleaned[key] = value;
  }
  return cleaned;
}

const deploySchema = z.object({
  templateSlug: z.string().min(1).max(100),
  name: z.string().min(1).max(200),
  platform: z.enum(["linux", "windows", "macos", "docker", "kubernetes", "aws", "azure", "gcp", "any"]),
  deploymentMethod: z.enum(["script", "docker", "kubernetes", "manual", "cloud_api"]),
  config: z.record(z.unknown()).default({}),
  tags: z.array(z.string().max(50)).max(20).default([]),
});

const updateSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  config: z.record(z.unknown()).optional(),
  tags: z.array(z.string().max(50)).max(20).optional(),
  status: z.enum(["active", "degraded", "offline", "pending_install", "disabled"]).optional(),
});

const heartbeatSchema = z.object({
  hostInfo: z.object({
    hostname: z.string().min(1).max(200),
    ipAddress: z.string().min(1).max(45),
    os: z.string().min(1).max(100),
    arch: z.string().min(1).max(50),
    cpuCount: z.number().int().min(1).max(1024),
    memoryGb: z.number().min(0).max(65536),
    agentVersion: z.string().min(1).max(50),
  }),
  metrics: z
    .object({
      eventsPerSecond: z.number().min(0).optional(),
      bytesIngested: z.number().min(0).optional(),
      errorsLast24h: z.number().min(0).optional(),
      uptimePercent: z.number().min(0).max(100).optional(),
      latencyP50Ms: z.number().min(0).optional(),
      latencyP99Ms: z.number().min(0).optional(),
    })
    .default({}),
});

const ingestSchema = z.object({
  events: z
    .array(
      z.object({
        eventType: z.string().min(1).max(200),
        severity: z.enum(["info", "low", "medium", "high", "critical"]),
        source: z.string().min(1).max(200),
        rawData: z.record(z.unknown()),
        tags: z.array(z.string().max(50)).max(20).optional(),
      }),
    )
    .min(1)
    .max(1000),
});

const scanSchema = z.object({
  scanType: z.enum(["vulnerability", "asset_discovery", "compliance", "configuration"]),
  targets: z.array(z.string().min(1).max(200)).min(1).max(100),
});

export function registerNativeCollectorRoutes(app: Express): void {
  app.get("/api/native-collectors/templates", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const type = req.query.type as CollectorType | undefined;
    res.json(getCollectorTemplates(type));
  });

  app.get("/api/native-collectors/templates/:slug", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const slug = req.params.slug as string;
    const template = getTemplateBySlug(slug);
    if (!template) return res.status(404).json({ message: "Template not found" });
    res.json(template);
  });

  app.get("/api/native-collectors/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = (req as any).orgId as string;
    res.json(await getDataPipelineStats(orgId));
  });

  app.post("/api/native-collectors/deploy", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const parsed = deploySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
    }
    const orgId = (req as any).orgId as string;
    try {
      const instance = await deployCollector(
        parsed.data.templateSlug,
        orgId,
        parsed.data.name,
        parsed.data.platform as Platform,
        parsed.data.deploymentMethod as DeploymentMethod,
        parsed.data.config,
        parsed.data.tags,
      );
      res.status(201).json(redactInstanceConfig(instance));
    } catch (err: unknown) {
      res.status(400).json({ message: (err as Error).message });
    }
  });

  app.get("/api/native-collectors/instances", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = (req as any).orgId as string;
    const type = req.query.type as CollectorType | undefined;
    const instances = await getCollectorInstances(orgId, type);
    res.json(instances.map(redactInstanceConfig));
  });

  app.get(
    "/api/native-collectors/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      res.json(redactInstanceConfig(instance));
    },
  );

  app.patch(
    "/api/native-collectors/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const parsed = updateSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      const safeData = parsed.data.config
        ? { ...parsed.data, config: stripRedactedKeys(parsed.data.config, instance.templateSlug) }
        : parsed.data;
      const updated = await updateCollectorConfig(instanceId, orgId, safeData as any);
      if (!updated) return res.status(404).json({ message: "Collector not found" });
      res.json(redactInstanceConfig(updated));
    },
  );

  app.delete(
    "/api/native-collectors/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const deleted = await deleteCollector(instanceId, orgId);
      if (!deleted) return res.status(404).json({ message: "Collector not found" });
      res.json({ success: true });
    },
  );

  app.post(
    "/api/native-collectors/instances/:id/heartbeat",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const parsed = heartbeatSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const updated = await sendHeartbeat(instanceId, orgId, parsed.data.hostInfo, parsed.data.metrics);
      if (!updated) return res.status(404).json({ message: "Collector not found" });
      res.json(redactInstanceConfig(updated));
    },
  );

  app.post(
    "/api/native-collectors/instances/:id/ingest",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const parsed = ingestSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      try {
        const events = await ingestEvents(instanceId, orgId, parsed.data.events);
        res.status(201).json({ ingested: events.length, events });
      } catch (err: unknown) {
        res.status(400).json({ message: (err as Error).message });
      }
    },
  );

  app.get("/api/native-collectors/events", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = (req as any).orgId as string;
    const collectorId = req.query.collectorId as string | undefined;
    const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 200);
    res.json(await getIngestedEvents(orgId, collectorId, limit));
  });

  app.post(
    "/api/native-collectors/instances/:id/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const parsed = scanSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      try {
        const scan = await triggerScan(instanceId, orgId, parsed.data.scanType, parsed.data.targets);
        res.json(scan);
      } catch (err: unknown) {
        res.status(400).json({ message: (err as Error).message });
      }
    },
  );

  app.get("/api/native-collectors/scans", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = (req as any).orgId as string;
    const collectorId = req.query.collectorId as string | undefined;
    const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
    res.json(await getScanResults(orgId, collectorId, limit));
  });

  app.get("/api/native-collectors/scans/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = (req as any).orgId as string;
    const scanId = req.params.id as string;
    const scan = await getScanResult(scanId, orgId);
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    res.json(scan);
  });

  app.get(
    "/api/native-collectors/instances/:id/deploy-script",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      const script = getDeploymentScript(instance.templateSlug, instanceId);
      res.json({ script, templateSlug: instance.templateSlug });
    },
  );

  app.post(
    "/api/native-collectors/instances/:id/api-key",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const result = await generateApiKey(instanceId, orgId);
      if (!result) return res.status(404).json({ message: "Collector not found" });
      res.json(result);
    },
  );
}
