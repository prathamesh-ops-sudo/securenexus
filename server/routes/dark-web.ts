import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, count, ilike, or } from "drizzle-orm";
import {
  breachMonitoringTargets,
  darkWebExposures,
  darkWebMonitoringConfig,
  darkWebScanHistory,
  DARK_WEB_EXPOSURE_TYPES,
  DARK_WEB_SEVERITY_LEVELS,
  DARK_WEB_EXPOSURE_STATUSES,
  BREACH_MONITOR_TARGET_TYPES,
} from "../../shared/schema";
import { runDarkWebScan } from "../dark-web-monitor";
import { encryptSsoSecret, decryptSsoSecret } from "../sso-crypto";

const log = logger.child("dark-web");

/** Encrypt an API key before storing in DB. Returns null if input is null/empty. */
function encryptApiKey(key: string | null | undefined): string | null {
  if (!key) return null;
  try {
    return encryptSsoSecret(key);
  } catch (err) {
    log.error("Failed to encrypt API key", { error: String(err) });
    throw new Error("Failed to encrypt API key");
  }
}

/** Decrypt an API key read from DB. Returns null if input is null/empty. */
function decryptApiKey(ciphertext: string | null | undefined): string | null {
  if (!ciphertext) return null;
  try {
    return decryptSsoSecret(ciphertext);
  } catch (err) {
    log.warn("Failed to decrypt API key — may be stored in plaintext from before encryption was added", {
      error: String(err),
    });
    // Fallback: return as-is if it looks like a plaintext key (migration path)
    return ciphertext;
  }
}

const ALLOWED_EXPOSURE_UPDATE_FIELDS = ["status", "severity", "mitigationNotes", "assignedTo", "responseAction"];
const ALLOWED_TARGET_FIELDS = ["targetType", "targetValue", "label", "isActive"];
const ALLOWED_CONFIG_FIELDS = [
  "isEnabled",
  "scanFrequencyHours",
  "autoCreateAlerts",
  "alertSeverityThreshold",
  "notifyOnNewExposure",
  "hibpApiKey",
  "dehashedApiKey",
];

export function registerDarkWebRoutes(app: Express): void {
  // ==========================================================================
  // MONITORING CONFIG — Get org's dark web monitoring configuration
  // ==========================================================================

  app.get(
    "/api/dark-web/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const [existing] = await db
          .select()
          .from(darkWebMonitoringConfig)
          .where(eq(darkWebMonitoringConfig.orgId, orgId))
          .limit(1);

        if (!existing) {
          return res.json({
            config: null,
            defaults: {
              exposureTypes: [...DARK_WEB_EXPOSURE_TYPES],
              severityLevels: [...DARK_WEB_SEVERITY_LEVELS],
              targetTypes: [...BREACH_MONITOR_TARGET_TYPES],
            },
          });
        }

        // Redact API keys in response
        const safeConfig = {
          ...existing,
          hibpApiKey: existing.hibpApiKey ? "***configured***" : null,
          dehashedApiKey: existing.dehashedApiKey ? "***configured***" : null,
        };

        res.json({
          config: safeConfig,
          defaults: {
            exposureTypes: [...DARK_WEB_EXPOSURE_TYPES],
            severityLevels: [...DARK_WEB_SEVERITY_LEVELS],
            targetTypes: [...BREACH_MONITOR_TARGET_TYPES],
          },
        });
      } catch (error) {
        log.error("Failed to get dark web config", { error: String(error) });
        res.status(500).json({ message: "Failed to get monitoring configuration" });
      }
    },
  );

  // ==========================================================================
  // MONITORING CONFIG — Create or update monitoring configuration
  // ==========================================================================

  app.post(
    "/api/dark-web/config",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        const updates: Record<string, unknown> = {};
        for (const key of ALLOWED_CONFIG_FIELDS) {
          if (req.body[key] !== undefined) {
            updates[key] = req.body[key];
          }
        }

        if (updates.alertSeverityThreshold) {
          const threshold = updates.alertSeverityThreshold as string;
          if (!DARK_WEB_SEVERITY_LEVELS.includes(threshold as (typeof DARK_WEB_SEVERITY_LEVELS)[number])) {
            return res.status(400).json({
              message: `alertSeverityThreshold must be one of: ${DARK_WEB_SEVERITY_LEVELS.join(", ")}`,
            });
          }
        }

        const [existing] = await db
          .select()
          .from(darkWebMonitoringConfig)
          .where(eq(darkWebMonitoringConfig.orgId, orgId))
          .limit(1);

        // Encrypt API keys before storing
        if (updates.hibpApiKey) {
          updates.hibpApiKey = encryptApiKey(updates.hibpApiKey as string);
        }
        if (updates.dehashedApiKey) {
          updates.dehashedApiKey = encryptApiKey(updates.dehashedApiKey as string);
        }

        if (existing) {
          updates.updatedAt = new Date();
          const [updated] = await db
            .update(darkWebMonitoringConfig)
            .set(updates)
            .where(eq(darkWebMonitoringConfig.orgId, orgId))
            .returning();

          const safeConfig = {
            ...updated,
            hibpApiKey: updated.hibpApiKey ? "***configured***" : null,
            dehashedApiKey: updated.dehashedApiKey ? "***configured***" : null,
          };
          return res.json(safeConfig);
        }

        const [created] = await db
          .insert(darkWebMonitoringConfig)
          .values({
            orgId,
            isEnabled: (updates.isEnabled as boolean) ?? true,
            scanFrequencyHours: (updates.scanFrequencyHours as number) ?? 24,
            autoCreateAlerts: (updates.autoCreateAlerts as boolean) ?? true,
            alertSeverityThreshold: (updates.alertSeverityThreshold as string) ?? "medium",
            notifyOnNewExposure: (updates.notifyOnNewExposure as boolean) ?? true,
            hibpApiKey: (updates.hibpApiKey as string | null) ?? null,
            dehashedApiKey: (updates.dehashedApiKey as string | null) ?? null,
          })
          .returning();

        const safeConfig = {
          ...created,
          hibpApiKey: created.hibpApiKey ? "***configured***" : null,
          dehashedApiKey: created.dehashedApiKey ? "***configured***" : null,
        };

        log.info("Dark web monitoring configured", { orgId });
        res.status(201).json(safeConfig);
      } catch (error) {
        log.error("Failed to update dark web config", { error: String(error) });
        res.status(500).json({ message: "Failed to update monitoring configuration" });
      }
    },
  );

  // ==========================================================================
  // MONITORING TARGETS — List all monitoring targets
  // ==========================================================================

  app.get(
    "/api/dark-web/targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const targetType = req.query.type as string | undefined;

        const conditions: unknown[] = [eq(breachMonitoringTargets.orgId, orgId)];

        if (targetType && targetType !== "all") {
          conditions.push(eq(breachMonitoringTargets.targetType, targetType));
        }

        const targets = await db
          .select()
          .from(breachMonitoringTargets)
          .where(and(...(conditions as any[])))
          .orderBy(desc(breachMonitoringTargets.createdAt));

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(breachMonitoringTargets)
          .where(and(...(conditions as any[])));

        res.json({ targets, total });
      } catch (error) {
        log.error("Failed to list monitoring targets", { error: String(error) });
        res.status(500).json({ message: "Failed to list monitoring targets" });
      }
    },
  );

  // ==========================================================================
  // MONITORING TARGETS — Add a new monitoring target
  // ==========================================================================

  app.post(
    "/api/dark-web/targets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { targetType, targetValue, label } = req.body;

        if (!targetType || !BREACH_MONITOR_TARGET_TYPES.includes(targetType as any)) {
          return res.status(400).json({
            message: `targetType must be one of: ${BREACH_MONITOR_TARGET_TYPES.join(", ")}`,
          });
        }
        if (!targetValue || typeof targetValue !== "string" || targetValue.length < 2) {
          return res.status(400).json({ message: "targetValue is required (min 2 characters)" });
        }

        // Dedup check
        const [existing] = await db
          .select()
          .from(breachMonitoringTargets)
          .where(
            and(
              eq(breachMonitoringTargets.orgId, orgId),
              eq(breachMonitoringTargets.targetType, targetType),
              eq(breachMonitoringTargets.targetValue, targetValue),
            ),
          )
          .limit(1);

        if (existing) {
          return res.status(409).json({ message: "This target is already being monitored" });
        }

        const [created] = await db
          .insert(breachMonitoringTargets)
          .values({
            orgId,
            targetType,
            targetValue,
            label: label || null,
          })
          .returning();

        log.info("Monitoring target added", { orgId, targetType, targetValue: targetValue.slice(0, 10) + "***" });
        res.status(201).json(created);
      } catch (error) {
        log.error("Failed to add monitoring target", { error: String(error) });
        res.status(500).json({ message: "Failed to add monitoring target" });
      }
    },
  );

  // ==========================================================================
  // MONITORING TARGETS — Update a target
  // ==========================================================================

  app.patch(
    "/api/dark-web/targets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const targetId = String(req.params.id);

        const [target] = await db
          .select()
          .from(breachMonitoringTargets)
          .where(and(eq(breachMonitoringTargets.id, targetId), eq(breachMonitoringTargets.orgId, orgId)))
          .limit(1);

        if (!target) {
          return res.status(404).json({ message: "Target not found" });
        }

        const updates: Record<string, unknown> = {};
        for (const key of ALLOWED_TARGET_FIELDS) {
          if (req.body[key] !== undefined) {
            updates[key] = req.body[key];
          }
        }

        if (updates.targetType) {
          if (!BREACH_MONITOR_TARGET_TYPES.includes(updates.targetType as any)) {
            return res.status(400).json({
              message: `targetType must be one of: ${BREACH_MONITOR_TARGET_TYPES.join(", ")}`,
            });
          }
        }

        updates.updatedAt = new Date();

        const [updated] = await db
          .update(breachMonitoringTargets)
          .set(updates)
          .where(and(eq(breachMonitoringTargets.id, targetId), eq(breachMonitoringTargets.orgId, orgId)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update target", { error: String(error) });
        res.status(500).json({ message: "Failed to update target" });
      }
    },
  );

  // ==========================================================================
  // MONITORING TARGETS — Delete a target
  // ==========================================================================

  app.delete(
    "/api/dark-web/targets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const targetId = String(req.params.id);

        const [target] = await db
          .select()
          .from(breachMonitoringTargets)
          .where(and(eq(breachMonitoringTargets.id, targetId), eq(breachMonitoringTargets.orgId, orgId)))
          .limit(1);

        if (!target) {
          return res.status(404).json({ message: "Target not found" });
        }

        await db
          .delete(breachMonitoringTargets)
          .where(and(eq(breachMonitoringTargets.id, targetId), eq(breachMonitoringTargets.orgId, orgId)));

        res.json({ message: "Target deleted" });
      } catch (error) {
        log.error("Failed to delete target", { error: String(error) });
        res.status(500).json({ message: "Failed to delete target" });
      }
    },
  );

  // ==========================================================================
  // EXPOSURES — List all dark web exposures
  // ==========================================================================

  app.get(
    "/api/dark-web/exposures",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const exposureType = req.query.type as string | undefined;
        const severity = req.query.severity as string | undefined;
        const status = req.query.status as string | undefined;
        const q = (req.query.q as string) || "";
        const limitParam = parseInt(String(req.query.limit || "100"));
        const offsetParam = parseInt(String(req.query.offset || "0"));
        const limit = Math.min(Number.isNaN(limitParam) ? 100 : limitParam, 500);
        const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

        const conditions: unknown[] = [eq(darkWebExposures.orgId, orgId)];

        if (exposureType && exposureType !== "all") {
          conditions.push(eq(darkWebExposures.exposureType, exposureType));
        }
        if (severity && severity !== "all") {
          conditions.push(eq(darkWebExposures.severity, severity));
        }
        if (status && status !== "all") {
          conditions.push(eq(darkWebExposures.status, status));
        }
        if (q) {
          conditions.push(
            or(
              ilike(darkWebExposures.title, `%${q}%`),
              ilike(darkWebExposures.description, `%${q}%`),
              ilike(darkWebExposures.sourceName, `%${q}%`),
              ilike(darkWebExposures.matchedValue, `%${q}%`),
            ),
          );
        }

        const exposures = await db
          .select()
          .from(darkWebExposures)
          .where(and(...(conditions as any[])))
          .orderBy(desc(darkWebExposures.discoveredAt))
          .limit(limit)
          .offset(offset);

        const [{ value: total }] = await db
          .select({ value: count() })
          .from(darkWebExposures)
          .where(and(...(conditions as any[])));

        // Summary stats
        const [stats] = await db
          .select({
            totalExposures: count(),
            criticalCount: sql<number>`count(*) filter (where ${darkWebExposures.severity} = 'critical')`,
            highCount: sql<number>`count(*) filter (where ${darkWebExposures.severity} = 'high')`,
            newCount: sql<number>`count(*) filter (where ${darkWebExposures.status} = 'new')`,
            mitigatedCount: sql<number>`count(*) filter (where ${darkWebExposures.status} = 'mitigated')`,
          })
          .from(darkWebExposures)
          .where(eq(darkWebExposures.orgId, orgId));

        res.json({ exposures, total, stats });
      } catch (error) {
        log.error("Failed to list exposures", { error: String(error) });
        res.status(500).json({ message: "Failed to list exposures" });
      }
    },
  );

  // ==========================================================================
  // EXPOSURES — Get a single exposure
  // ==========================================================================

  app.get(
    "/api/dark-web/exposures/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const exposureId = String(req.params.id);

        const [exposure] = await db
          .select()
          .from(darkWebExposures)
          .where(and(eq(darkWebExposures.id, exposureId), eq(darkWebExposures.orgId, orgId)))
          .limit(1);

        if (!exposure) {
          return res.status(404).json({ message: "Exposure not found" });
        }

        res.json(exposure);
      } catch (error) {
        log.error("Failed to get exposure", { error: String(error) });
        res.status(500).json({ message: "Failed to get exposure" });
      }
    },
  );

  // ==========================================================================
  // EXPOSURES — Update exposure status/severity/notes
  // ==========================================================================

  app.patch(
    "/api/dark-web/exposures/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const exposureId = String(req.params.id);

        const [exposure] = await db
          .select()
          .from(darkWebExposures)
          .where(and(eq(darkWebExposures.id, exposureId), eq(darkWebExposures.orgId, orgId)))
          .limit(1);

        if (!exposure) {
          return res.status(404).json({ message: "Exposure not found" });
        }

        const updates: Record<string, unknown> = {};
        for (const key of ALLOWED_EXPOSURE_UPDATE_FIELDS) {
          if (req.body[key] !== undefined) {
            updates[key] = req.body[key];
          }
        }

        if (updates.status) {
          if (!DARK_WEB_EXPOSURE_STATUSES.includes(updates.status as any)) {
            return res.status(400).json({
              message: `status must be one of: ${DARK_WEB_EXPOSURE_STATUSES.join(", ")}`,
            });
          }
          if (updates.status === "mitigated" || updates.status === "false_positive") {
            updates.resolvedAt = new Date();
            updates.resolvedBy = (req.user as any)?.id || null;
          }
        }

        if (updates.severity) {
          if (!DARK_WEB_SEVERITY_LEVELS.includes(updates.severity as any)) {
            return res.status(400).json({
              message: `severity must be one of: ${DARK_WEB_SEVERITY_LEVELS.join(", ")}`,
            });
          }
        }

        updates.updatedAt = new Date();

        const [updated] = await db
          .update(darkWebExposures)
          .set(updates)
          .where(and(eq(darkWebExposures.id, exposureId), eq(darkWebExposures.orgId, orgId)))
          .returning();

        // Log response action if provided
        if (req.body.responseAction) {
          log.info("Credential response action taken", {
            exposureId: exposureId,
            action: String(req.body.responseAction),
            actorId: (req.user as any)?.id,
          });
        }

        // If mitigated, update config resolved count
        if (updates.status === "mitigated") {
          await db
            .update(darkWebMonitoringConfig)
            .set({
              totalExposuresResolved: sql`${darkWebMonitoringConfig.totalExposuresResolved} + 1`,
            })
            .where(eq(darkWebMonitoringConfig.orgId, orgId));
        }

        res.json(updated);
      } catch (error) {
        log.error("Failed to update exposure", { error: String(error) });
        res.status(500).json({ message: "Failed to update exposure" });
      }
    },
  );

  // ==========================================================================
  // SCAN — Trigger a manual dark web scan
  // ==========================================================================

  app.post(
    "/api/dark-web/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("compliance", "write"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Check if monitoring is configured
        const [config] = await db
          .select()
          .from(darkWebMonitoringConfig)
          .where(eq(darkWebMonitoringConfig.orgId, orgId))
          .limit(1);

        if (!config) {
          return res.status(400).json({
            message: "Dark web monitoring not configured. Set up monitoring configuration first.",
          });
        }

        // Run scan (non-blocking — return immediately)
        const result = await runDarkWebScan(orgId, "manual");

        res.json({
          message: "Scan completed",
          ...result,
        });
      } catch (error) {
        log.error("Failed to trigger scan", { error: String(error) });
        res.status(500).json({ message: "Failed to trigger scan" });
      }
    },
  );

  // ==========================================================================
  // SCAN HISTORY — List past scan results
  // ==========================================================================

  app.get(
    "/api/dark-web/scans",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const limitParam = parseInt(String(req.query.limit || "20"));
        const limit = Math.min(Number.isNaN(limitParam) ? 20 : limitParam, 100);

        const scans = await db
          .select()
          .from(darkWebScanHistory)
          .where(eq(darkWebScanHistory.orgId, orgId))
          .orderBy(desc(darkWebScanHistory.startedAt))
          .limit(limit);

        res.json({ scans });
      } catch (error) {
        log.error("Failed to list scan history", { error: String(error) });
        res.status(500).json({ message: "Failed to list scan history" });
      }
    },
  );

  // ==========================================================================
  // DASHBOARD — Get dark web monitoring dashboard summary
  // ==========================================================================

  app.get(
    "/api/dark-web/dashboard",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);

        // Get config
        const [config] = await db
          .select()
          .from(darkWebMonitoringConfig)
          .where(eq(darkWebMonitoringConfig.orgId, orgId))
          .limit(1);

        // Get target counts by type
        const targetCounts = await db
          .select({
            targetType: breachMonitoringTargets.targetType,
            count: count(),
          })
          .from(breachMonitoringTargets)
          .where(and(eq(breachMonitoringTargets.orgId, orgId), eq(breachMonitoringTargets.isActive, true)))
          .groupBy(breachMonitoringTargets.targetType);

        // Get exposure stats
        const [exposureStats] = await db
          .select({
            total: count(),
            critical: sql<number>`count(*) filter (where ${darkWebExposures.severity} = 'critical')`,
            high: sql<number>`count(*) filter (where ${darkWebExposures.severity} = 'high')`,
            medium: sql<number>`count(*) filter (where ${darkWebExposures.severity} = 'medium')`,
            low: sql<number>`count(*) filter (where ${darkWebExposures.severity} = 'low')`,
            newCount: sql<number>`count(*) filter (where ${darkWebExposures.status} = 'new')`,
            investigating: sql<number>`count(*) filter (where ${darkWebExposures.status} = 'investigating')`,
            mitigated: sql<number>`count(*) filter (where ${darkWebExposures.status} = 'mitigated')`,
          })
          .from(darkWebExposures)
          .where(eq(darkWebExposures.orgId, orgId));

        // Get exposure breakdown by type
        const exposuresByType = await db
          .select({
            exposureType: darkWebExposures.exposureType,
            count: count(),
          })
          .from(darkWebExposures)
          .where(eq(darkWebExposures.orgId, orgId))
          .groupBy(darkWebExposures.exposureType);

        // Recent exposures
        const recentExposures = await db
          .select()
          .from(darkWebExposures)
          .where(eq(darkWebExposures.orgId, orgId))
          .orderBy(desc(darkWebExposures.discoveredAt))
          .limit(5);

        // Last scan
        const [lastScan] = await db
          .select()
          .from(darkWebScanHistory)
          .where(eq(darkWebScanHistory.orgId, orgId))
          .orderBy(desc(darkWebScanHistory.startedAt))
          .limit(1);

        // Brand mention counts
        const brandMentionCount = exposuresByType
          .filter((e) => ["brand_mention", "domain_mention", "threat_actor_mention"].includes(e.exposureType))
          .reduce((sum, e) => sum + Number(e.count), 0);

        // Data source freshness summary
        const now = Date.now();
        const sourceFreshness = recentExposures.reduce(
          (acc, exp) => {
            const ageMs = now - new Date(exp.discoveredAt).getTime();
            const days = ageMs / (1000 * 60 * 60 * 24);
            if (days < 1) acc.live++;
            else if (days < 7) acc.recent++;
            else if (days < 30) acc.stale++;
            else acc.recycled++;
            return acc;
          },
          { live: 0, recent: 0, stale: 0, recycled: 0 },
        );

        // Credential validation summary
        const credentialExposures = recentExposures.filter((e) => e.exposureType === "credential_leak");
        const likelyValid = credentialExposures.filter((e) => {
          if (!e.breachDate) return false;
          const days = (now - new Date(e.breachDate).getTime()) / (1000 * 60 * 60 * 24);
          return days < 30;
        }).length;

        res.json({
          config: config
            ? {
                ...config,
                hibpApiKey: config.hibpApiKey ? "***configured***" : null,
                dehashedApiKey: config.dehashedApiKey ? "***configured***" : null,
              }
            : null,
          targetCounts,
          exposureStats: exposureStats || {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            newCount: 0,
            investigating: 0,
            mitigated: 0,
          },
          exposuresByType,
          recentExposures,
          lastScan: lastScan || null,
          brandMentionCount,
          sourceFreshness,
          credentialValidation: { likelyValid, total: credentialExposures.length },
        });
      } catch (error) {
        log.error("Failed to get dashboard", { error: String(error) });
        res.status(500).json({ message: "Failed to get dashboard" });
      }
    },
  );
}
