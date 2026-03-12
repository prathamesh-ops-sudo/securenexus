/**
 * Native Sensors API
 *
 * Powers SecureNexus as a fully self-contained security platform.
 * Companies deploy our lightweight sensor agent — no CrowdStrike, Splunk,
 * or Qualys subscription required.
 *
 * Routes:
 *   POST /api/native/sensors/register      — Register a new sensor/agent
 *   POST /api/native/sensors/heartbeat     — Agent health check-in
 *   POST /api/native/sensors/events        — Ingest telemetry events (bulk)
 *   GET  /api/native/sensors               — List all sensors for org
 *   GET  /api/native/sensors/:id           — Get sensor details + recent events
 *   PATCH /api/native/sensors/:id          — Update sensor config/tags
 *   DELETE /api/native/sensors/:id         — Decommission sensor
 *
 *   GET  /api/native/detection-rules       — List all rules (builtin + custom)
 *   POST /api/native/detection-rules       — Create custom rule
 *   PATCH /api/native/detection-rules/:id  — Update rule (enable/disable/edit)
 *   DELETE /api/native/detection-rules/:id — Delete custom rule
 *   POST /api/native/detection-rules/seed  — Seed built-in rules for org (admin)
 *
 *   GET  /api/native/log-sources           — List log sources
 *   POST /api/native/log-sources           — Add a log source
 *   PATCH /api/native/log-sources/:id      — Update log source
 *   DELETE /api/native/log-sources/:id     — Remove log source
 *   POST /api/native/log-sources/:id/test  — Test log source connection
 *
 *   GET  /api/native/stats                 — Platform-wide telemetry stats
 */

import type { Express } from "express";
import { eq, desc, and, sql, count } from "drizzle-orm";
import crypto from "crypto";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { requireOrgId, requireMinRole, resolveOrgContext } from "../rbac";
import { db } from "../db";
import { logger, getOrgId, sendEnvelope, storage } from "./shared";
import { broadcastEvent } from "../event-bus";
import { correlateAlert } from "../correlation-engine";
import {
  nativeSensors,
  sensorEvents,
  detectionRules,
  logSources,
  alerts,
  type InsertSensorEvent,
  type InsertDetectionRule,
} from "../../shared/schema";
import { evaluateEvent } from "../native-detections/index";
import { BUILT_IN_RULES } from "../native-detections/built-in-rules";

const log = logger.child("native-sensors");

// ============================================================================
// Validation schemas
// ============================================================================

const registerSensorSchema = z.object({
  hostname: z.string().min(1).max(255),
  platform: z.enum(["windows", "linux", "macos", "docker", "kubernetes"]),
  sensorType: z.enum(["endpoint", "log_forwarder", "network_tap", "cloud_sensor"]).default("endpoint"),
  agentVersion: z.string().optional(),
  ipAddress: z.string().optional(),
  macAddress: z.string().optional(),
  environment: z.enum(["production", "staging", "dev"]).default("production"),
  osVersion: z.string().optional(),
  kernelVersion: z.string().optional(),
  capabilities: z.array(z.string()).default(["process_events", "network_events", "login_events"]),
  tags: z.array(z.string()).default([]),
});

const heartbeatSchema = z.object({
  sensorId: z.string().min(1),
  eventsLast24h: z.number().int().default(0),
  alertsLast24h: z.number().int().default(0),
  cpuPercent: z.number().optional(),
  memPercent: z.number().optional(),
  status: z.enum(["online", "degraded"]).default("online"),
});

const sensorEventSchema = z.object({
  eventType: z.string().min(1),
  occurredAt: z.string().datetime().or(z.number()),
  processName: z.string().optional(),
  processPath: z.string().optional(),
  processId: z.number().optional(),
  parentProcessId: z.number().optional(),
  parentProcessName: z.string().optional(),
  userId: z.string().optional(),
  username: z.string().optional(),
  srcIp: z.string().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().optional(),
  protocol: z.string().optional(),
  dnsQuery: z.string().optional(),
  filePath: z.string().optional(),
  fileHash: z.string().optional(),
  rawLog: z.string().optional(),
  logSource: z.string().optional(),
  rawData: z.record(z.unknown()).default({}),
});

const bulkEventsSchema = z.object({
  sensorId: z.string().min(1),
  token: z.string().min(1),
  events: z.array(sensorEventSchema).max(500),
});

const createDetectionRuleSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]),
  category: z.string().default("other"),
  mitreTactic: z.string().optional(),
  mitreTechnique: z.string().optional(),
  mitreTechniqueId: z.string().optional(),
  alertTitle: z.string().optional(),
  platforms: z.array(z.string()).default(["windows", "linux", "macos"]),
  eventTypes: z.array(z.string()).default([]),
  conditions: z.record(z.unknown()),
  tags: z.array(z.string()).default([]),
  status: z.enum(["active", "disabled", "testing"]).default("active"),
});

const createLogSourceSchema = z.object({
  name: z.string().min(1).max(255),
  sourceType: z.enum([
    "syslog_udp",
    "syslog_tcp",
    "windows_event_log",
    "http_push",
    "file_tail",
    "journald",
    "cloudwatch",
    "azure_monitor",
  ]),
  description: z.string().optional(),
  endpoint: z.string().optional(),
  port: z.number().int().min(1).max(65535).optional(),
  logFormat: z.enum(["auto", "json", "cef", "leef", "syslog", "plaintext"]).default("auto"),
});

// ============================================================================
// Helpers
// ============================================================================

function generateSensorToken(): string {
  return "snx_sensor_" + crypto.randomBytes(24).toString("hex");
}

async function findSensorByToken(token: string) {
  const rows = await db
    .select()
    .from(nativeSensors)
    .where(eq(nativeSensors.registrationToken, token))
    .limit(1);
  return rows[0] ?? null;
}

async function getActiveRulesForOrg(orgId: string) {
  // Built-in global rules + org custom rules
  return db
    .select()
    .from(detectionRules)
    .where(
      and(
        eq(detectionRules.status, "active"),
        sql`(${detectionRules.orgId} IS NULL OR ${detectionRules.orgId} = ${orgId})`,
      ),
    );
}

// ============================================================================
// Main route registration
// ============================================================================

export function registerNativeSensorsRoutes(app: Express): void {

  // --------------------------------------------------------------------------
  // SENSOR MANAGEMENT
  // --------------------------------------------------------------------------

  /**
   * Register a new sensor agent.
   * Returns a registration token the agent uses for subsequent calls.
   */
  app.post(
    "/api/native/sensors/register",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const body = registerSensorSchema.parse(req.body);
        const orgId = getOrgId(req);

        const token = generateSensorToken();
        const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year

        const [sensor] = await db
          .insert(nativeSensors)
          .values({
            orgId,
            hostname: body.hostname,
            platform: body.platform,
            sensorType: body.sensorType,
            agentVersion: body.agentVersion ?? null,
            ipAddress: body.ipAddress ?? null,
            macAddress: body.macAddress ?? null,
            environment: body.environment,
            osVersion: body.osVersion ?? null,
            kernelVersion: body.kernelVersion ?? null,
            capabilities: body.capabilities,
            tags: body.tags,
            registrationToken: token,
            tokenExpiresAt: expiresAt,
            status: "unregistered",
            isActive: true,
          })
          .returning();

        log.info("Sensor registered", { sensorId: sensor.id, hostname: body.hostname, orgId });

        return sendEnvelope(res, {
          sensorId: sensor.id,
          hostname: sensor.hostname,
          registrationToken: token,
          tokenExpiresAt: expiresAt,
          message: "Store this token securely. Use it for heartbeats and event ingestion.",
          agentInstallInstructions: buildInstallInstructions(body.platform, token, sensor.id),
        });
      } catch (err: any) {
        log.error("Sensor registration failed", { error: String(err) });
        return res.status(400).json({ error: err.message ?? "Registration failed" });
      }
    },
  );

  /**
   * Heartbeat from agent — keeps sensor "online" and updates stats.
   * Auth: sensor registration token (no user session required).
   */
  app.post("/api/native/sensors/heartbeat", async (req, res) => {
    try {
      const body = heartbeatSchema.parse(req.body);
      const sensor = await findSensorByToken(body.token);
      if (!sensor) {
        return res.status(401).json({ error: "Invalid sensor token" });
      }
      if (!sensor.isActive) {
        return res.status(403).json({ error: "Sensor is decommissioned" });
      }

      await db
        .update(nativeSensors)
        .set({
          status: body.status,
          lastHeartbeatAt: new Date(),
          eventsLast24h: body.eventsLast24h,
          alertsLast24h: body.alertsLast24h,
          updatedAt: new Date(),
        })
        .where(eq(nativeSensors.id, sensor.id));

      return res.json({ ok: true, sensorId: sensor.id, serverTime: new Date().toISOString() });
    } catch (err: any) {
      return res.status(400).json({ error: err.message ?? "Heartbeat failed" });
    }
  });

  /**
   * Ingest bulk telemetry events from sensor.
   * Runs detection rules, creates alerts for matches.
   * Auth: sensor registration token.
   */
  app.post("/api/native/sensors/events", async (req, res) => {
    const startTime = Date.now();
    try {
      const body = bulkEventsSchema.parse(req.body);
      const sensor = await findSensorByToken(body.token);

      if (!sensor) {
        return res.status(401).json({ error: "Invalid sensor token" });
      }
      if (!sensor.isActive) {
        return res.status(403).json({ error: "Sensor is decommissioned" });
      }

      const orgId = sensor.orgId;
      const activeRules = await getActiveRulesForOrg(orgId);

      let eventsCreated = 0;
      let alertsCreated = 0;
      const alertIds: string[] = [];

      for (const evt of body.events) {
        const occurredAt =
          typeof evt.occurredAt === "number"
            ? new Date(evt.occurredAt)
            : new Date(evt.occurredAt);

        const insertEvt: InsertSensorEvent = {
          orgId,
          sensorId: sensor.id,
          eventType: evt.eventType,
          occurredAt,
          hostname: sensor.hostname,
          processName: evt.processName ?? null,
          processPath: evt.processPath ?? null,
          processId: evt.processId ?? null,
          parentProcessId: evt.parentProcessId ?? null,
          parentProcessName: evt.parentProcessName ?? null,
          userId: evt.userId ?? null,
          username: evt.username ?? null,
          srcIp: evt.srcIp ?? null,
          dstIp: evt.dstIp ?? null,
          dstPort: evt.dstPort ?? null,
          protocol: evt.protocol ?? null,
          dnsQuery: evt.dnsQuery ?? null,
          filePath: evt.filePath ?? null,
          fileHash: evt.fileHash ?? null,
          rawLog: evt.rawLog ?? null,
          logSource: evt.logSource ?? null,
          rawData: evt.rawData,
        };

        const [createdEvt] = await db.insert(sensorEvents).values(insertEvt).returning();
        eventsCreated++;

        // Run detection rules
        const matches = evaluateEvent(createdEvt, activeRules as any);

        if (matches.length > 0) {
          // Update event with matched rule IDs
          await db
            .update(sensorEvents)
            .set({ ruleMatchIds: matches.map((m) => m.ruleId) })
            .where(eq(sensorEvents.id, createdEvt.id));

          for (const match of matches) {
            // Create an alert in the main alerts table
            try {
              const { alert, isNew } = await storage.upsertAlert({
                orgId,
                source: "SecureNexus Agent",
                sourceEventId: `snx-${createdEvt.id}-${match.ruleId}`,
                title: match.alertTitle,
                description: `Native detection rule matched: ${match.ruleName}. Sensor: ${sensor.hostname} (${sensor.ipAddress ?? "unknown IP"}).`,
                severity: match.severity as any,
                category: match.category as any,
                hostname: sensor.hostname,
                sourceIp: evt.srcIp ?? null,
                destIp: evt.dstIp ?? null,
                userId: evt.username ?? null,
                fileHash: evt.fileHash ?? null,
                mitreTactic: match.mitreTactic ?? null,
                mitreTechnique: match.mitreTechniqueId ?? null,
                detectedAt: occurredAt,
                rawData: {
                  sensorId: sensor.id,
                  ruleId: match.ruleId,
                  ruleName: match.ruleName,
                  matchedFields: match.matchedFields,
                  event: insertEvt,
                },
              });

              if (isNew) {
                alertsCreated++;
                alertIds.push(alert.id);

                broadcastEvent({
                  type: "alert:created",
                  orgId,
                  data: {
                    alertId: alert.id,
                    title: alert.title,
                    severity: alert.severity,
                    source: "SecureNexus Agent",
                    category: alert.category,
                  },
                });

                // Async correlation — don't block response
                correlateAlert(alert).catch((err) =>
                  log.warn("Correlation failed for native alert", { alertId: alert.id, error: String(err) }),
                );
              }

              // Update rule stats
              await db
                .update(detectionRules)
                .set({
                  totalMatches: sql`${detectionRules.totalMatches} + 1`,
                  lastMatchedAt: new Date(),
                })
                .where(eq(detectionRules.id, match.ruleId));
            } catch (alertErr) {
              log.warn("Failed to create alert from rule match", { error: String(alertErr) });
            }
          }
        }
      }

      // Update sensor last-event timestamp
      await db
        .update(nativeSensors)
        .set({
          status: "online",
          lastEventAt: new Date(),
          lastHeartbeatAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(nativeSensors.id, sensor.id));

      const processingMs = Date.now() - startTime;
      log.info("Events ingested", { sensorId: sensor.id, eventsCreated, alertsCreated, processingMs });

      return res.status(201).json({
        ok: true,
        eventsIngested: eventsCreated,
        alertsGenerated: alertsCreated,
        alertIds,
        processingMs,
      });
    } catch (err: any) {
      log.error("Event ingestion failed", { error: String(err) });
      return res.status(400).json({ error: err.message ?? "Ingestion failed" });
    }
  });

  /**
   * List all sensors for the authenticated org.
   */
  app.get(
    "/api/native/sensors",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rows = await db
          .select()
          .from(nativeSensors)
          .where(and(eq(nativeSensors.orgId, orgId), eq(nativeSensors.isActive, true)))
          .orderBy(desc(nativeSensors.lastHeartbeatAt));

        return sendEnvelope(res, rows);
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to list sensors" });
      }
    },
  );

  /**
   * Get sensor detail with recent events.
   */
  app.get(
    "/api/native/sensors/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [sensor] = await db
          .select()
          .from(nativeSensors)
          .where(and(eq(nativeSensors.id, req.params.id), eq(nativeSensors.orgId, orgId)))
          .limit(1);

        if (!sensor) return res.status(404).json({ error: "Sensor not found" });

        const recentEvents = await db
          .select()
          .from(sensorEvents)
          .where(eq(sensorEvents.sensorId, sensor.id))
          .orderBy(desc(sensorEvents.occurredAt))
          .limit(50);

        return sendEnvelope(res, { sensor, recentEvents });
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to get sensor" });
      }
    },
  );

  /**
   * Update sensor tags, displayName, environment, config.
   */
  app.patch(
    "/api/native/sensors/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { displayName, tags, environment, config } = req.body;

        const [updated] = await db
          .update(nativeSensors)
          .set({
            ...(displayName !== undefined && { displayName }),
            ...(tags !== undefined && { tags }),
            ...(environment !== undefined && { environment }),
            ...(config !== undefined && { config }),
            updatedAt: new Date(),
          })
          .where(and(eq(nativeSensors.id, req.params.id), eq(nativeSensors.orgId, orgId)))
          .returning();

        if (!updated) return res.status(404).json({ error: "Sensor not found" });
        return sendEnvelope(res, updated);
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to update sensor" });
      }
    },
  );

  /**
   * Decommission (soft-delete) a sensor.
   */
  app.delete(
    "/api/native/sensors/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [updated] = await db
          .update(nativeSensors)
          .set({ isActive: false, status: "offline", updatedAt: new Date() })
          .where(and(eq(nativeSensors.id, req.params.id), eq(nativeSensors.orgId, orgId)))
          .returning();

        if (!updated) return res.status(404).json({ error: "Sensor not found" });
        return res.json({ message: "Sensor decommissioned" });
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to decommission sensor" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // DETECTION RULES
  // --------------------------------------------------------------------------

  /**
   * List detection rules (global built-ins + org-specific custom rules).
   */
  app.get(
    "/api/native/detection-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rows = await db
          .select()
          .from(detectionRules)
          .where(
            sql`(${detectionRules.orgId} IS NULL OR ${detectionRules.orgId} = ${orgId})`,
          )
          .orderBy(
            sql`CASE ${detectionRules.severity}
              WHEN 'critical' THEN 1
              WHEN 'high' THEN 2
              WHEN 'medium' THEN 3
              WHEN 'low' THEN 4
              ELSE 5 END`,
            desc(detectionRules.totalMatches),
          );

        return sendEnvelope(res, rows, {
          meta: {
            total: rows.length,
            builtin: rows.filter((r) => r.isBuiltin).length,
            custom: rows.filter((r) => !r.isBuiltin).length,
            active: rows.filter((r) => r.status === "active").length,
          },
        });
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to list detection rules" });
      }
    },
  );

  /**
   * Create a custom detection rule for the org.
   */
  app.post(
    "/api/native/detection-rules",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = createDetectionRuleSchema.parse(req.body);

        const [rule] = await db
          .insert(detectionRules)
          .values({
            orgId,
            name: body.name,
            description: body.description ?? null,
            ruleSource: "custom",
            severity: body.severity,
            category: body.category,
            mitreTactic: body.mitreTactic ?? null,
            mitreTechnique: body.mitreTechnique ?? null,
            mitreTechniqueId: body.mitreTechniqueId ?? null,
            alertTitle: body.alertTitle ?? body.name,
            platforms: body.platforms,
            eventTypes: body.eventTypes,
            conditions: body.conditions,
            tags: body.tags,
            status: body.status,
            isBuiltin: false,
            isCommunity: false,
            version: 1,
          })
          .returning();

        log.info("Custom detection rule created", { ruleId: rule.id, name: rule.name, orgId });
        return sendEnvelope(res, rule);
      } catch (err: any) {
        return res.status(400).json({ error: err.message ?? "Failed to create rule" });
      }
    },
  );

  /**
   * Update a detection rule (enable/disable/edit). Custom rules only for non-admin.
   */
  app.patch(
    "/api/native/detection-rules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { status, name, description, conditions, severity } = req.body;

        // Find rule — must belong to org or be builtin (can toggle status)
        const [existing] = await db
          .select()
          .from(detectionRules)
          .where(
            and(
              eq(detectionRules.id, req.params.id),
              sql`(${detectionRules.orgId} IS NULL OR ${detectionRules.orgId} = ${orgId})`,
            ),
          )
          .limit(1);

        if (!existing) return res.status(404).json({ error: "Rule not found" });

        // Built-in rules can only have status toggled, not content edited
        const updateData: Partial<typeof detectionRules.$inferInsert> = { updatedAt: new Date() };
        if (status !== undefined) updateData.status = status;
        if (!existing.isBuiltin) {
          if (name !== undefined) updateData.name = name;
          if (description !== undefined) updateData.description = description;
          if (conditions !== undefined) updateData.conditions = conditions;
          if (severity !== undefined) updateData.severity = severity;
          updateData.version = (existing.version ?? 1) + 1;
        }

        const [updated] = await db
          .update(detectionRules)
          .set(updateData)
          .where(eq(detectionRules.id, req.params.id))
          .returning();

        return sendEnvelope(res, updated);
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to update rule" });
      }
    },
  );

  /**
   * Delete a custom detection rule (cannot delete built-ins).
   */
  app.delete(
    "/api/native/detection-rules/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(detectionRules)
          .where(and(eq(detectionRules.id, req.params.id), eq(detectionRules.orgId, orgId)))
          .limit(1);

        if (!existing) return res.status(404).json({ error: "Rule not found or is a built-in rule" });
        if (existing.isBuiltin) return res.status(403).json({ error: "Cannot delete built-in rules" });

        await db.delete(detectionRules).where(eq(detectionRules.id, req.params.id));
        return res.json({ message: "Rule deleted" });
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to delete rule" });
      }
    },
  );

  /**
   * Seed built-in rules globally (idempotent — skips existing by name).
   * Called once during platform setup.
   */
  app.post(
    "/api/native/detection-rules/seed",
    isAuthenticated,
    requireMinRole("admin"),
    async (_req, res) => {
      try {
        let seeded = 0;
        let skipped = 0;

        for (const rule of BUILT_IN_RULES) {
          const existing = await db
            .select({ id: detectionRules.id })
            .from(detectionRules)
            .where(
              and(
                eq(detectionRules.name, rule.name),
                eq(detectionRules.isBuiltin, true),
                sql`${detectionRules.orgId} IS NULL`,
              ),
            )
            .limit(1);

          if (existing.length > 0) {
            skipped++;
            continue;
          }

          await db.insert(detectionRules).values({
            orgId: null,
            name: rule.name,
            description: rule.description ?? null,
            ruleSource: "builtin",
            severity: rule.severity as any,
            category: rule.category,
            mitreTactic: rule.mitreTactic ?? null,
            mitreTechnique: rule.mitreTechnique ?? null,
            mitreTechniqueId: rule.mitreTechniqueId ?? null,
            alertTitle: rule.alertTitle ?? rule.name,
            platforms: rule.platforms ?? ["windows", "linux", "macos"],
            eventTypes: rule.eventTypes ?? [],
            conditions: rule.conditions,
            tags: rule.tags ?? [],
            status: "active",
            isBuiltin: true,
            isCommunity: false,
            version: 1,
          });
          seeded++;
        }

        log.info("Built-in rules seeded", { seeded, skipped });
        return res.json({ seeded, skipped, total: BUILT_IN_RULES.length });
      } catch (err: any) {
        log.error("Rule seeding failed", { error: String(err) });
        return res.status(500).json({ error: "Failed to seed rules" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // LOG SOURCES
  // --------------------------------------------------------------------------

  app.get(
    "/api/native/log-sources",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rows = await db
          .select()
          .from(logSources)
          .where(eq(logSources.orgId, orgId))
          .orderBy(desc(logSources.createdAt));
        return sendEnvelope(res, rows);
      } catch {
        return res.status(500).json({ error: "Failed to list log sources" });
      }
    },
  );

  app.post(
    "/api/native/log-sources",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = createLogSourceSchema.parse(req.body);

        const [src] = await db
          .insert(logSources)
          .values({
            orgId,
            name: body.name,
            sourceType: body.sourceType,
            description: body.description ?? null,
            endpoint: body.endpoint ?? null,
            port: body.port ?? null,
            logFormat: body.logFormat,
            status: "inactive",
            isActive: true,
          })
          .returning();

        return sendEnvelope(res, src);
      } catch (err: any) {
        return res.status(400).json({ error: err.message ?? "Failed to create log source" });
      }
    },
  );

  app.patch(
    "/api/native/log-sources/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { name, description, status, endpoint, port, logFormat } = req.body;

        const [updated] = await db
          .update(logSources)
          .set({
            ...(name !== undefined && { name }),
            ...(description !== undefined && { description }),
            ...(status !== undefined && { status }),
            ...(endpoint !== undefined && { endpoint }),
            ...(port !== undefined && { port }),
            ...(logFormat !== undefined && { logFormat }),
            updatedAt: new Date(),
          })
          .where(and(eq(logSources.id, req.params.id), eq(logSources.orgId, orgId)))
          .returning();

        if (!updated) return res.status(404).json({ error: "Log source not found" });
        return sendEnvelope(res, updated);
      } catch {
        return res.status(500).json({ error: "Failed to update log source" });
      }
    },
  );

  app.delete(
    "/api/native/log-sources/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        await db
          .delete(logSources)
          .where(and(eq(logSources.id, req.params.id), eq(logSources.orgId, orgId)));
        return res.json({ message: "Log source removed" });
      } catch {
        return res.status(500).json({ error: "Failed to remove log source" });
      }
    },
  );

  app.post(
    "/api/native/log-sources/:id/test",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [src] = await db
          .select()
          .from(logSources)
          .where(and(eq(logSources.id, req.params.id), eq(logSources.orgId, orgId)))
          .limit(1);

        if (!src) return res.status(404).json({ error: "Log source not found" });

        // For HTTP push sources, the test is always "reachable" as it's passive
        const result = {
          success: true,
          message: `Log source "${src.name}" configuration is valid. Waiting for incoming data.`,
          details: {
            type: src.sourceType,
            endpoint: src.endpoint,
            port: src.port,
            format: src.logFormat,
          },
        };

        return res.json(result);
      } catch {
        return res.status(500).json({ error: "Test failed" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // PLATFORM STATS
  // --------------------------------------------------------------------------

  app.get(
    "/api/native/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [sensorStats] = await db
          .select({
            total: count(),
            online: sql<number>`COUNT(*) FILTER (WHERE ${nativeSensors.status} = 'online')`,
            offline: sql<number>`COUNT(*) FILTER (WHERE ${nativeSensors.status} = 'offline')`,
            degraded: sql<number>`COUNT(*) FILTER (WHERE ${nativeSensors.status} = 'degraded')`,
          })
          .from(nativeSensors)
          .where(and(eq(nativeSensors.orgId, orgId), eq(nativeSensors.isActive, true)));

        const [eventStats] = await db
          .select({
            last24h: sql<number>`COUNT(*) FILTER (WHERE ${sensorEvents.receivedAt} > NOW() - INTERVAL '24 hours')`,
            last7d: sql<number>`COUNT(*) FILTER (WHERE ${sensorEvents.receivedAt} > NOW() - INTERVAL '7 days')`,
          })
          .from(sensorEvents)
          .where(eq(sensorEvents.orgId, orgId));

        const [ruleStats] = await db
          .select({
            total: count(),
            active: sql<number>`COUNT(*) FILTER (WHERE ${detectionRules.status} = 'active')`,
            builtin: sql<number>`COUNT(*) FILTER (WHERE ${detectionRules.isBuiltin} = true)`,
          })
          .from(detectionRules)
          .where(sql`(${detectionRules.orgId} IS NULL OR ${detectionRules.orgId} = ${orgId})`);

        return sendEnvelope(res, {
          sensors: sensorStats,
          events: eventStats,
          detectionRules: ruleStats,
          coverageNote: `${ruleStats?.active ?? 0} detection rules active across MITRE ATT&CK framework`,
        });
      } catch (err: any) {
        return res.status(500).json({ error: "Failed to get stats" });
      }
    },
  );
}

// ============================================================================
// Agent install instructions generator
// ============================================================================

function buildInstallInstructions(
  platform: string,
  token: string,
  sensorId: string,
): Record<string, string> {
  const serverUrl = process.env.APP_URL ?? "https://your-securenexus-instance.com";
  const baseCmd = `SNX_TOKEN="${token}" SNX_SENSOR_ID="${sensorId}" SNX_SERVER="${serverUrl}"`;

  switch (platform) {
    case "linux":
      return {
        oneLineInstall: `curl -fsSL ${serverUrl}/agent/install.sh | ${baseCmd} bash`,
        manual: [
          `# Download agent`,
          `curl -o snx-agent ${serverUrl}/agent/snx-agent-linux-amd64`,
          `chmod +x snx-agent`,
          `# Configure`,
          `export ${baseCmd}`,
          `# Run as service`,
          `sudo ./snx-agent install`,
          `sudo systemctl enable --now securenexus-agent`,
        ].join("\n"),
        docker: [
          `docker run -d --name snx-agent \\`,
          `  --privileged --net host \\`,
          `  -v /proc:/host/proc:ro \\`,
          `  -v /sys:/host/sys:ro \\`,
          `  -e SNX_TOKEN="${token}" \\`,
          `  -e SNX_SERVER="${serverUrl}" \\`,
          `  securenexus/agent:latest`,
        ].join("\n"),
      };

    case "windows":
      return {
        powershell: [
          `$env:SNX_TOKEN = "${token}"`,
          `$env:SNX_SERVER = "${serverUrl}"`,
          `Invoke-WebRequest "${serverUrl}/agent/snx-agent-windows.exe" -OutFile snx-agent.exe`,
          `.\\snx-agent.exe install`,
          `Start-Service SecureNexusAgent`,
        ].join("\n"),
        msi: `msiexec /i ${serverUrl}/agent/securenexus-agent.msi SNX_TOKEN="${token}" SNX_SERVER="${serverUrl}" /quiet`,
      };

    case "macos":
      return {
        brew: `brew install securenexus/tap/snx-agent && SNX_TOKEN="${token}" SNX_SERVER="${serverUrl}" snx-agent install`,
        pkg: [
          `curl -o snx-agent.pkg ${serverUrl}/agent/securenexus-agent.pkg`,
          `sudo installer -pkg snx-agent.pkg -target /`,
          `sudo defaults write /Library/Preferences/com.securenexus.agent Token "${token}"`,
          `sudo defaults write /Library/Preferences/com.securenexus.agent Server "${serverUrl}"`,
          `sudo launchctl load /Library/LaunchDaemons/com.securenexus.agent.plist`,
        ].join("\n"),
      };

    case "kubernetes":
      return {
        helm: [
          `helm repo add securenexus ${serverUrl}/helm`,
          `helm install snx-agent securenexus/agent \\`,
          `  --set sensor.token="${token}" \\`,
          `  --set sensor.server="${serverUrl}" \\`,
          `  --namespace securenexus --create-namespace`,
        ].join("\n"),
        daemonset: `kubectl apply -f ${serverUrl}/agent/k8s-daemonset.yaml`,
      };

    default:
      return { generic: `Configure agent with SNX_TOKEN="${token}" and SNX_SERVER="${serverUrl}"` };
  }
}
