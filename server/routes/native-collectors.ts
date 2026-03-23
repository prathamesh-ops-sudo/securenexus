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

  // 39.1 — Log source deployment wizard steps
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

  // 39.2 — Log source health monitoring per collector
  app.get(
    "/api/native-collectors/instances/:id/health",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      const now = new Date();
      const lastHeartbeat = instance.lastHeartbeatAt ? new Date(instance.lastHeartbeatAt) : null;
      const heartbeatAgeMs = lastHeartbeat ? now.getTime() - lastHeartbeat.getTime() : Infinity;
      const isStale = heartbeatAgeMs > 5 * 60 * 1000; // 5 min threshold
      const lastData = instance.lastDataAt ? new Date(instance.lastDataAt) : null;
      const dataAgeMs = lastData ? now.getTime() - lastData.getTime() : Infinity;
      const isDataStale = dataAgeMs > 15 * 60 * 1000; // 15 min threshold
      const health = {
        collectorId: instance.id,
        name: instance.name,
        status: instance.status,
        eventsPerSecond: instance.metrics.eventsPerSecond,
        lastReceivedEvent: instance.lastDataAt,
        lastHeartbeat: instance.lastHeartbeatAt,
        heartbeatStale: isStale,
        dataStale: isDataStale,
        parsingErrors: instance.metrics.errorsLast24h,
        dataVolumeBytes: instance.metrics.bytesIngested,
        uptimePercent: instance.metrics.uptimePercent,
        latencyP50Ms: instance.metrics.latencyP50Ms,
        latencyP99Ms: instance.metrics.latencyP99Ms,
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
      if (instance.metrics.errorsLast24h > 10)
        health.alerts.push({
          level: "warning",
          message: `${instance.metrics.errorsLast24h} parsing errors in the last 24 hours`,
          timestamp: now.toISOString(),
        });
      res.json(health);
    },
  );

  // 39.3 — Log source coverage map
  app.get("/api/native-collectors/coverage-map", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    const orgId = (req as any).orgId as string;
    const instances = await getCollectorInstances(orgId);
    const templates = getCollectorTemplates();
    const coveredTypes = new Set(instances.map((i) => i.templateSlug));
    const coverage = templates.map((t) => {
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
            ? Math.round(deployed.reduce((sum, d) => sum + d.metrics.uptimePercent, 0) / deployed.length)
            : 0,
      };
    });
    const gaps = coverage.filter((c) => !c.covered);
    res.json({
      coverage,
      gaps,
      totalTemplates: templates.length,
      coveredTemplates: coveredTypes.size,
      coveragePercent: templates.length > 0 ? Math.round((coveredTypes.size / templates.length) * 100) : 0,
    });
  });

  // 39.4 — Custom log parser testing
  app.post("/api/native-collectors/parsers/test", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const { pattern, patternType, sampleLog } = req.body as { pattern: string; patternType: string; sampleLog: string };
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
  });

  // 39.4 — List saved custom parsers
  app.get("/api/native-collectors/parsers", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    // Return built-in parsers list
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

  // 39.5 — Certificate management for TLS log sources
  app.get(
    "/api/native-collectors/instances/:id/certificates",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      // Return mock cert info — in production would query actual cert store
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
    },
  );

  // 39.5 — Generate CSR for a collector
  app.post(
    "/api/native-collectors/instances/:id/certificates/generate-csr",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      res.json({
        csr: "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...mock...CSR\n-----END CERTIFICATE REQUEST-----",
        subject: `CN=${instance.name}.securenexus.io`,
        keyType: "RSA-2048",
        generatedAt: new Date().toISOString(),
      });
    },
  );

  // 39.5 — Toggle auto-renew for a certificate
  app.post(
    "/api/native-collectors/instances/:id/certificates/auto-renew",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const orgId = (req as any).orgId as string;
      const instanceId = req.params.id as string;
      const instance = await getCollectorInstance(instanceId, orgId);
      if (!instance) return res.status(404).json({ message: "Collector not found" });
      const { enabled } = req.body as { enabled: boolean };
      res.json({ collectorId: instanceId, autoRenew: enabled !== false, updatedAt: new Date().toISOString() });
    },
  );
}
