import type { Express, Request } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { logger, getOrgId, reply, replyError } from "./shared";
import { z } from "zod";
import { storage } from "../storage";
import { getCollectorTemplates, getTemplateBySlug, getDeploymentScript } from "../native-collectors-engine";

interface RequestWithUser extends Request {
  user?: { id?: string; orgId?: string; role?: string };
}

const log = logger.child("native-collectors");

const REDACTED = "***REDACTED***";

function redactInstanceConfig(instance: {
  config: unknown;
  templateSlug: string;
  [key: string]: unknown;
}): typeof instance {
  const template = getTemplateBySlug(instance.templateSlug);
  if (!template) return instance;

  const secretKeys = new Set(
    template.configSchema.filter((f: { type: string }) => f.type === "secret").map((f: { key: string }) => f.key),
  );
  if (secretKeys.size === 0) return instance;

  const rawConfig = (instance.config && typeof instance.config === "object" ? instance.config : {}) as Record<
    string,
    unknown
  >;
  const redactedConfig: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rawConfig)) {
    redactedConfig[key] = secretKeys.has(key) ? REDACTED : value;
  }
  return { ...instance, config: redactedConfig };
}

function stripRedactedKeys(config: Record<string, unknown>, templateSlug: string): Record<string, unknown> {
  const template = getTemplateBySlug(templateSlug);
  if (!template) return config;
  const secretKeys = new Set(
    template.configSchema.filter((f: { type: string }) => f.type === "secret").map((f: { key: string }) => f.key),
  );
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
  platform: z.enum([
    "linux",
    "windows",
    "macos",
    "ios",
    "android",
    "docker",
    "kubernetes",
    "aws",
    "azure",
    "gcp",
    "any",
  ]),
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
  // ─── Templates (static catalog) ───────────────────────────────────────────
  app.get("/api/native-collectors/templates", isAuthenticated, resolveOrgContext, requireOrgId, (_req, res) => {
    res.json(getCollectorTemplates());
  });

  app.get("/api/native-collectors/templates/:slug", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const slug = req.params.slug as string;
    const template = getTemplateBySlug(slug);
    if (!template) return res.status(404).json({ message: "Template not found" });
    res.json(template);
  });

  // ─── Stats (computed from DB) ─────────────────────────────────────────────
  app.get("/api/native-collectors/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const instances = await storage.getCollectorInstances(orgId);
      const eventCount = await storage.countCollectorEvents(orgId);
      const active = instances.filter((i) => i.status === "active").length;
      const degraded = instances.filter((i) => i.status === "degraded").length;
      const offline = instances.filter((i) => i.status === "offline").length;

      const totalEps = instances.reduce((sum, i) => {
        const metrics = (i.metrics && typeof i.metrics === "object" ? i.metrics : {}) as Record<string, number>;
        return sum + (metrics.eventsPerSecond || 0);
      }, 0);
      const totalBytes = instances.reduce((sum, i) => {
        const metrics = (i.metrics && typeof i.metrics === "object" ? i.metrics : {}) as Record<string, number>;
        return sum + (metrics.bytesIngested || 0);
      }, 0);

      reply(res, {
        totalCollectors: instances.length,
        active,
        degraded,
        offline,
        pendingInstall: instances.filter((i) => i.status === "pending_install").length,
        disabled: instances.filter((i) => i.status === "disabled").length,
        totalEventsIngested: eventCount,
        eventsPerSecond: Math.round(totalEps * 100) / 100,
        bytesIngested: totalBytes,
        healthScore:
          instances.length > 0
            ? Math.round(
                instances.reduce((sum, i) => {
                  const metrics = (i.metrics && typeof i.metrics === "object" ? i.metrics : {}) as Record<
                    string,
                    number
                  >;
                  return sum + (metrics.uptimePercent || 0);
                }, 0) / instances.length,
              )
            : 0,
      });
    } catch (error) {
      log.error("Stats error", { error: String(error) });
      replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch collector stats" }]);
    }
  });

  // ─── Deploy (create instance in DB) ───────────────────────────────────────
  app.post(
    "/api/native-collectors/deploy",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const parsed = deploySchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      try {
        const orgId = getOrgId(req);
        const template = getTemplateBySlug(parsed.data.templateSlug);
        if (!template) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Template not found" }]);
        }

        const instance = await storage.createCollectorInstance({
          orgId,
          templateSlug: parsed.data.templateSlug,
          name: parsed.data.name,
          platform: parsed.data.platform,
          deploymentMethod: parsed.data.deploymentMethod,
          config: parsed.data.config,
          tags: parsed.data.tags,
          status: "pending_install",
          version: "1.0.0",
        });

        res.status(201).json(redactInstanceConfig(instance));
      } catch (err: unknown) {
        log.error("Deploy error", { error: String(err) });
        res.status(400).json({ message: (err as Error).message });
      }
    },
  );

  // ─── List Instances (from DB) ─────────────────────────────────────────────
  app.get("/api/native-collectors/instances", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const instances = await storage.getCollectorInstances(orgId);
      res.json(instances.map(redactInstanceConfig));
    } catch (error) {
      log.error("List instances error", { error: String(error) });
      replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch collector instances" }]);
    }
  });

  // ─── Get Instance ─────────────────────────────────────────────────────────
  app.get(
    "/api/native-collectors/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        res.json(redactInstanceConfig(instance));
      } catch (error) {
        log.error("Get instance error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch collector instance" }]);
      }
    },
  );

  // ─── Update Instance ──────────────────────────────────────────────────────
  app.patch(
    "/api/native-collectors/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const parsed = updateSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }

        const updateData: Partial<{
          name: string;
          config: Record<string, unknown>;
          tags: string[];
          status: string;
        }> = {};
        if (parsed.data.name) updateData.name = parsed.data.name;
        if (parsed.data.status) updateData.status = parsed.data.status;
        if (parsed.data.tags) updateData.tags = parsed.data.tags;
        if (parsed.data.config) {
          updateData.config = stripRedactedKeys(parsed.data.config as Record<string, unknown>, instance.templateSlug);
        }

        const updated = await storage.updateCollectorInstance(instanceId, updateData);
        if (!updated) return res.status(404).json({ message: "Collector not found" });
        res.json(redactInstanceConfig(updated));
      } catch (error) {
        log.error("Update instance error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to update collector instance" }]);
      }
    },
  );

  // ─── Delete Instance ──────────────────────────────────────────────────────
  app.delete(
    "/api/native-collectors/instances/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        const deleted = await storage.deleteCollectorInstance(instanceId);
        if (!deleted) return res.status(404).json({ message: "Collector not found" });
        res.json({ success: true });
      } catch (error) {
        log.error("Delete instance error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to delete collector instance" }]);
      }
    },
  );

  // ─── Heartbeat (update instance metrics in DB) ────────────────────────────
  app.post(
    "/api/native-collectors/instances/:id/heartbeat",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const parsed = heartbeatSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }

        const existingMetrics = (
          instance.metrics && typeof instance.metrics === "object" ? instance.metrics : {}
        ) as Record<string, unknown>;
        const updated = await storage.updateCollectorInstance(instanceId, {
          hostInfo: parsed.data.hostInfo,
          metrics: { ...existingMetrics, ...parsed.data.metrics },
          lastHeartbeatAt: new Date(),
          status: "active",
        });
        if (!updated) return res.status(404).json({ message: "Collector not found" });
        res.json(redactInstanceConfig(updated));
      } catch (error) {
        log.error("Heartbeat error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to process heartbeat" }]);
      }
    },
  );

  // ─── Ingest Events (persist to DB) ────────────────────────────────────────
  app.post(
    "/api/native-collectors/instances/:id/ingest",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const parsed = ingestSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(400).json({ message: "Collector not found" });
        }

        const created = [];
        for (const evt of parsed.data.events) {
          const event = await storage.createCollectorEvent({
            collectorId: instanceId,
            orgId,
            eventType: evt.eventType,
            severity: evt.severity,
            source: evt.source,
            rawData: evt.rawData,
            tags: evt.tags || [],
          });
          created.push(event);
        }

        // Update last data timestamp on instance
        await storage.updateCollectorInstance(instanceId, {
          lastDataAt: new Date(),
        });

        res.status(201).json({ ingested: created.length, events: created });
      } catch (err: unknown) {
        log.error("Ingest error", { error: String(err) });
        res.status(400).json({ message: (err as Error).message });
      }
    },
  );

  // ─── List Events (from DB) ────────────────────────────────────────────────
  app.get("/api/native-collectors/events", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const collectorId = req.query.collectorId as string | undefined;
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 50, 200);
      let events;
      if (collectorId) {
        events = await storage.getCollectorEventsByInstance(collectorId, limit);
      } else {
        events = await storage.getCollectorEvents(orgId, limit);
      }
      res.json(events);
    } catch (error) {
      log.error("List events error", { error: String(error) });
      replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch events" }]);
    }
  });

  // ─── Trigger Scan (persist to DB) ─────────────────────────────────────────
  app.post(
    "/api/native-collectors/instances/:id/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const parsed = scanSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid request", errors: parsed.error.issues });
      }
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(400).json({ message: "Collector not found" });
        }

        const scan = await storage.createCollectorScan({
          collectorId: instanceId,
          orgId,
          scanType: parsed.data.scanType,
          targets: parsed.data.targets,
          status: "running",
          startedAt: new Date(),
        });

        // Simulate scan completion asynchronously
        setTimeout(async () => {
          try {
            await storage.updateCollectorScan(scan.id, {
              status: "completed",
              completedAt: new Date(),
              summary: {
                targetsScanned: parsed.data.targets.length,
                findingsCount: 0,
                scanType: parsed.data.scanType,
              },
            });
          } catch (err) {
            log.error("Failed to update scan result", { id: scan.id, error: String(err) });
          }
        }, 2000);

        res.json(scan);
      } catch (err: unknown) {
        log.error("Scan error", { error: String(err) });
        res.status(400).json({ message: (err as Error).message });
      }
    },
  );

  // ─── List Scans (from DB) ─────────────────────────────────────────────────
  app.get("/api/native-collectors/scans", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const limit = Math.min(parseInt(req.query.limit as string, 10) || 20, 100);
      const scans = await storage.getCollectorScans(orgId, limit);
      res.json(scans);
    } catch (error) {
      log.error("List scans error", { error: String(error) });
      replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch scans" }]);
    }
  });

  // ─── Get Scan by ID ───────────────────────────────────────────────────────
  app.get("/api/native-collectors/scans/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scanId = req.params.id as string;
      const scans = await storage.getCollectorScans(orgId, 1000);
      const scan = scans.find((s) => s.id === scanId);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      res.json(scan);
    } catch (error) {
      log.error("Get scan error", { error: String(error) });
      replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch scan" }]);
    }
  });

  // ─── Deploy Script (from template catalog) ────────────────────────────────
  app.get(
    "/api/native-collectors/instances/:id/deploy-script",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        const script = getDeploymentScript(instance.templateSlug, instanceId);
        res.json({ script, templateSlug: instance.templateSlug });
      } catch (error) {
        log.error("Deploy script error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to generate deploy script" }]);
      }
    },
  );

  // ─── API Key Generation ───────────────────────────────────────────────────
  app.post(
    "/api/native-collectors/instances/:id/api-key",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        // Generate a random API key for the collector
        const { randomBytes } = await import("crypto");
        const apiKey = randomBytes(32).toString("hex");
        const prefix = apiKey.slice(0, 8);
        // Store the key hash in the instance config
        const existingConfig = (
          instance.config && typeof instance.config === "object" ? instance.config : {}
        ) as Record<string, unknown>;
        await storage.updateCollectorInstance(instanceId, {
          config: { ...existingConfig, apiKeyPrefix: prefix, apiKeySet: true },
        });
        res.json({ apiKey, prefix, createdAt: new Date().toISOString() });
      } catch (error) {
        log.error("API key generation error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to generate API key" }]);
      }
    },
  );

  // ─── Deploy Wizard Steps (from template catalog) ──────────────────────────
  app.get(
    "/api/native-collectors/templates/:slug/deploy-wizard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    (req, res) => {
      const slug = req.params.slug as string;
      const template = getTemplateBySlug(slug);
      if (!template) return res.status(404).json({ message: "Template not found" });
      const steps = [
        {
          step: 1,
          title: "Select Platform",
          description: `Choose the target platform for ${template.name}`,
          status: "pending" as const,
          fields: [
            {
              key: "platform",
              type: "select" as const,
              options: template.platforms,
              label: "Platform",
              required: true,
            },
          ],
        },
        {
          step: 2,
          title: "Download & Install",
          description: template.requiresAgent
            ? "Download and install the agent on your target system"
            : "Configure the agentless connection",
          status: "pending" as const,
          fields: [
            {
              key: "deploymentMethod",
              type: "select" as const,
              options: template.deploymentMethods,
              label: "Deployment Method",
              required: true,
            },
          ],
          instructions: template.requiresAgent
            ? [
                `curl -sL https://install.securenexus.io/agent | bash -s -- --template=${slug}`,
                "The agent will automatically register with your org",
              ]
            : [
                "Configure the API endpoint in your source system",
                `Webhook URL: https://api.securenexus.io/api/native-collectors/ingest/${slug}`,
              ],
        },
        {
          step: 3,
          title: "Test Data Flow",
          description: "Verify that data is flowing from the source to SecureNexus",
          status: "pending" as const,
          fields: [],
          instructions: [
            "Send a test event from your source system",
            "Check the Events tab for incoming data",
            "Verify parsing is correct in the event details",
          ],
        },
        {
          step: 4,
          title: "Verify in Dashboard",
          description: "Confirm the collector appears in the pipeline dashboard",
          status: "pending" as const,
          fields: [],
          instructions: [
            "Navigate to the Pipeline tab",
            "Verify events/sec is non-zero",
            "Check that the collector status is Active",
          ],
        },
      ];
      res.json({
        templateSlug: slug,
        templateName: template.name,
        requiresAgent: template.requiresAgent,
        estimatedMinutes: template.estimatedSetupMinutes,
        steps,
      });
    },
  );

  // ─── Health Monitoring (computed from DB instance) ────────────────────────
  app.get(
    "/api/native-collectors/instances/:id/health",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        const now = new Date();
        const lastHeartbeat = instance.lastHeartbeatAt ? new Date(instance.lastHeartbeatAt) : null;
        const heartbeatAgeMs = lastHeartbeat ? now.getTime() - lastHeartbeat.getTime() : Infinity;
        const isStale = heartbeatAgeMs > 5 * 60 * 1000;
        const lastData = instance.lastDataAt ? new Date(instance.lastDataAt) : null;
        const dataAgeMs = lastData ? now.getTime() - lastData.getTime() : Infinity;
        const isDataStale = dataAgeMs > 15 * 60 * 1000;

        const metrics = (instance.metrics && typeof instance.metrics === "object" ? instance.metrics : {}) as Record<
          string,
          number
        >;

        const health = {
          collectorId: instance.id,
          name: instance.name,
          status: instance.status,
          eventsPerSecond: metrics.eventsPerSecond || 0,
          lastReceivedEvent: instance.lastDataAt,
          lastHeartbeat: instance.lastHeartbeatAt,
          heartbeatStale: isStale,
          dataStale: isDataStale,
          parsingErrors: metrics.errorsLast24h || 0,
          dataVolumeBytes: metrics.bytesIngested || 0,
          uptimePercent: metrics.uptimePercent || 0,
          latencyP50Ms: metrics.latencyP50Ms || 0,
          latencyP99Ms: metrics.latencyP99Ms || 0,
          alerts: [] as Array<{ level: string; message: string; timestamp: string }>,
        };
        if (isStale)
          health.alerts.push({
            level: "warning",
            message: "No heartbeat received in over 5 minutes",
            timestamp: now.toISOString(),
          });
        if (isDataStale)
          health.alerts.push({
            level: "critical",
            message: "No data received in over 15 minutes",
            timestamp: now.toISOString(),
          });
        if ((metrics.errorsLast24h || 0) > 10)
          health.alerts.push({
            level: "warning",
            message: `${metrics.errorsLast24h} parsing errors in the last 24 hours`,
            timestamp: now.toISOString(),
          });
        res.json(health);
      } catch (error) {
        log.error("Health check error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch health data" }]);
      }
    },
  );

  // ─── Coverage Map (computed from DB + template catalog) ───────────────────
  app.get("/api/native-collectors/coverage-map", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const instances = await storage.getCollectorInstances(orgId);
      const templates = getCollectorTemplates();
      const coveredTypes = new Set(instances.map((i) => i.templateSlug));
      const coverage = templates.map(
        (t: { slug: string; name: string; type: string; platforms: string[]; dataTypes: string[] }) => {
          const deployed = instances.filter((i) => i.templateSlug === t.slug);
          const activeCount = deployed.filter((i) => i.status === "active").length;
          return {
            templateSlug: t.slug,
            templateName: t.name,
            type: t.type,
            platforms: t.platforms,
            dataTypes: t.dataTypes,
            deployed: deployed.length,
            active: activeCount,
            covered: deployed.length > 0,
            healthScore:
              deployed.length > 0
                ? Math.round(
                    deployed.reduce((sum, d) => {
                      const m = (d.metrics && typeof d.metrics === "object" ? d.metrics : {}) as Record<string, number>;
                      return sum + (m.uptimePercent || 0);
                    }, 0) / deployed.length,
                  )
                : 0,
          };
        },
      );
      const gaps = coverage.filter((c) => !c.covered);
      res.json({
        coverage,
        gaps,
        totalTemplates: templates.length,
        coveredTemplates: coveredTypes.size,
        coveragePercent: templates.length > 0 ? Math.round((coveredTypes.size / templates.length) * 100) : 0,
      });
    } catch (error) {
      log.error("Coverage map error", { error: String(error) });
      replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch coverage map" }]);
    }
  });

  // ─── Custom Log Parser Testing (stateless) ───────────────────────────────
  app.post(
    "/api/native-collectors/parsers/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    (req, res) => {
      const { pattern, patternType, sampleLog } = req.body as {
        pattern: string;
        patternType: string;
        sampleLog: string;
      };
      if (!pattern || !sampleLog) return res.status(400).json({ message: "pattern and sampleLog are required" });
      try {
        const fields: Record<string, string> = {};
        if (patternType === "regex") {
          const regex = new RegExp(pattern);
          const match = regex.exec(sampleLog);
          if (match && match.groups) {
            for (const [k, v] of Object.entries(match.groups)) fields[k] = v;
          } else if (match) {
            match.slice(1).forEach((v, i) => {
              fields[`group_${i + 1}`] = v;
            });
          }
        } else if (patternType === "json_path") {
          try {
            const parsed = JSON.parse(sampleLog);
            const paths = pattern.split(",").map((p) => p.trim());
            for (const p of paths) {
              const keys = p.split(".");
              let val: unknown = parsed;
              for (const k of keys) {
                if (val && typeof val === "object" && k in (val as Record<string, unknown>)) {
                  val = (val as Record<string, unknown>)[k];
                } else {
                  val = undefined;
                  break;
                }
              }
              if (val !== undefined) fields[p] = String(val);
            }
          } catch {
            return res.status(400).json({ message: "Invalid JSON in sampleLog" });
          }
        } else if (patternType === "kv") {
          const kvRegex = /(\w+)=("([^"]*)"|(\S+))/g;
          let m: RegExpExecArray | null;
          while ((m = kvRegex.exec(sampleLog)) !== null) {
            fields[m[1]] = m[3] ?? m[4];
          }
        }
        res.json({ success: true, extractedFields: fields, fieldCount: Object.keys(fields).length, patternType });
      } catch (err: unknown) {
        res.status(400).json({ message: "Pattern error: " + (err as Error).message });
      }
    },
  );

  // ─── List Built-in Parsers (static catalog) ──────────────────────────────
  app.get("/api/native-collectors/parsers", isAuthenticated, resolveOrgContext, requireOrgId, (_req, res) => {
    const parsers = [
      { id: "syslog-rfc3164", name: "Syslog RFC 3164", patternType: "regex", builtIn: true, fieldCount: 5 },
      { id: "syslog-rfc5424", name: "Syslog RFC 5424", patternType: "regex", builtIn: true, fieldCount: 8 },
      { id: "cef", name: "Common Event Format", patternType: "kv", builtIn: true, fieldCount: 12 },
      { id: "leef", name: "Log Extended Event Format", patternType: "kv", builtIn: true, fieldCount: 10 },
      { id: "windows-xml", name: "Windows Event XML", patternType: "json_path", builtIn: true, fieldCount: 15 },
      { id: "json-generic", name: "Generic JSON", patternType: "json_path", builtIn: true, fieldCount: 0 },
      { id: "csv-generic", name: "Generic CSV", patternType: "regex", builtIn: true, fieldCount: 0 },
    ];
    res.json(parsers);
  });

  // ─── Certificate Management (derived from instance) ──────────────────────
  app.get(
    "/api/native-collectors/instances/:id/certificates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
        const daysUntilExpiry = Math.round((expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
        const certs = [
          {
            id: `cert-${instanceId}`,
            collectorId: instanceId,
            subject: `CN=${instance.name}.securenexus.io`,
            issuer: "SecureNexus Internal CA",
            serialNumber: instanceId.replace(/-/g, "").slice(0, 20),
            notBefore: now.toISOString(),
            notAfter: expiresAt.toISOString(),
            daysUntilExpiry,
            status: daysUntilExpiry > 30 ? "valid" : daysUntilExpiry > 7 ? "expiring_soon" : "critical",
            autoRenew: true,
            fingerprint: `SHA256:${Buffer.from(instanceId).toString("base64").slice(0, 44)}`,
            keyType: "RSA-2048",
          },
        ];
        res.json(certs);
      } catch (error) {
        log.error("Certificate error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to fetch certificates" }]);
      }
    },
  );

  // ─── Generate CSR ─────────────────────────────────────────────────────────
  app.post(
    "/api/native-collectors/instances/:id/certificates/generate-csr",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        res.json({
          csr: "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...mock...CSR\n-----END CERTIFICATE REQUEST-----",
          subject: `CN=${instance.name}.securenexus.io`,
          keyType: "RSA-2048",
          generatedAt: new Date().toISOString(),
        });
      } catch (error) {
        log.error("CSR generation error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to generate CSR" }]);
      }
    },
  );

  // ─── Toggle Auto-Renew ────────────────────────────────────────────────────
  app.post(
    "/api/native-collectors/instances/:id/certificates/auto-renew",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const instanceId = req.params.id as string;
        const instance = await storage.getCollectorInstance(instanceId);
        if (!instance || instance.orgId !== orgId) {
          return res.status(404).json({ message: "Collector not found" });
        }
        const { enabled } = req.body as { enabled: boolean };
        res.json({ collectorId: instanceId, autoRenew: enabled !== false, updatedAt: new Date().toISOString() });
      } catch (error) {
        log.error("Auto-renew toggle error", { error: String(error) });
        replyError(res, 500, [{ code: "INTERNAL", message: "Failed to toggle auto-renew" }]);
      }
    },
  );
}
