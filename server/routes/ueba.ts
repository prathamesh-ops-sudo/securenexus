import type { Express } from "express";
import { eq, desc, and, sql, count, gte, or, not, inArray } from "drizzle-orm";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { requireOrgId, resolveOrgContext } from "../rbac";
import { db } from "../db";
import { logger, getOrgId, sendEnvelope, storage } from "./shared";
import { broadcastEvent } from "../event-bus";
import {
  uebaBaselines,
  uebaAnomalies,
  sensorEvents,
  nativeSensors,
} from "../../shared/schema";

const log = logger.child("ueba");

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function isInternalIp(ip: string): boolean {
  if (!ip) return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^127\./.test(ip)) return true;
  if (/^::1$/.test(ip)) return true;
  return false;
}

const SUSPICIOUS_PROCESS_RE =
  /base64|certutil|mshta|regsvr32|rundll32|\\bnc\\b|powershell.*-enc|wscript|cscript|bitsadmin/i;

const ANOMALY_SCORE_WEIGHTS: Record<string, number> = {
  off_hours_login: 15,
  new_location: 25,
  new_process: 20,
  volume_anomaly: 10,
};

// ---------------------------------------------------------------------------
// computeBaseline
// ---------------------------------------------------------------------------

async function computeBaseline(
  orgId: string,
  entityType: string,
  entityId: string,
): Promise<void> {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const entityFilter =
    entityType === "user"
      ? eq(sensorEvents.username, entityId)
      : eq(sensorEvents.hostname, entityId);

  const rows = await db
    .select()
    .from(sensorEvents)
    .where(
      and(
        eq(sensorEvents.orgId, orgId),
        gte(sensorEvents.occurredAt, thirtyDaysAgo),
        entityFilter,
      ),
    );

  if (rows.length === 0) {
    // Upsert a stub baseline so the entity is tracked
    await db
      .insert(uebaBaselines)
      .values({
        orgId,
        entityType,
        entityId,
        normalLoginHours: [],
        normalLoginSources: [],
        normalProcesses: [],
        normalNetworkPeers: [],
        avgDailyEvents: 0,
        eventCount: 0,
        baselineWindowDays: 30,
        lastComputedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: [uebaBaselines.orgId, uebaBaselines.entityType, uebaBaselines.entityId],
        set: {
          normalLoginHours: [],
          normalLoginSources: [],
          normalProcesses: [],
          avgDailyEvents: 0,
          eventCount: 0,
          baselineWindowDays: 30,
          lastComputedAt: new Date(),
          updatedAt: new Date(),
        },
      });
    return;
  }

  // Unique login hours from login events
  const loginRows = rows.filter(
    (r) => r.eventType === "login_success" || r.eventType === "login_failure",
  );

  const loginHoursSet = new Set<number>();
  for (const r of loginRows) {
    if (r.occurredAt) loginHoursSet.add(new Date(r.occurredAt).getUTCHours());
  }

  const loginSourcesSet = new Set<string>();
  for (const r of loginRows) {
    if (r.srcIp) loginSourcesSet.add(r.srcIp);
  }

  // Top-20 most common processName values
  const processCounts = new Map<string, number>();
  for (const r of rows) {
    if (r.processName) {
      processCounts.set(r.processName, (processCounts.get(r.processName) ?? 0) + 1);
    }
  }
  const normalProcesses = [...processCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([name]) => name);

  const avgDailyEvents = rows.length / 30;

  await db
    .insert(uebaBaselines)
    .values({
      orgId,
      entityType,
      entityId,
      normalLoginHours: [...loginHoursSet],
      normalLoginSources: [...loginSourcesSet],
      normalProcesses,
      normalNetworkPeers: [],
      avgDailyEvents,
      eventCount: rows.length,
      baselineWindowDays: 30,
      lastComputedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: [uebaBaselines.orgId, uebaBaselines.entityType, uebaBaselines.entityId],
      set: {
        normalLoginHours: [...loginHoursSet],
        normalLoginSources: [...loginSourcesSet],
        normalProcesses,
        avgDailyEvents,
        eventCount: rows.length,
        baselineWindowDays: 30,
        lastComputedAt: new Date(),
        updatedAt: new Date(),
      },
    });
}

// ---------------------------------------------------------------------------
// detectAnomalies
// ---------------------------------------------------------------------------

async function detectAnomalies(
  orgId: string,
): Promise<{ detected: number; alertsCreated: number }> {
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

  // Load all baselines for this org
  const baselines = await db
    .select()
    .from(uebaBaselines)
    .where(eq(uebaBaselines.orgId, orgId));

  if (baselines.length === 0) return { detected: 0, alertsCreated: 0 };

  // Load last-24h events for this org
  const recentEvents = await db
    .select()
    .from(sensorEvents)
    .where(and(eq(sensorEvents.orgId, orgId), gte(sensorEvents.occurredAt, oneDayAgo)));

  let detected = 0;
  let alertsCreated = 0;

  for (const baseline of baselines) {
    const normalLoginHours = (baseline.normalLoginHours as number[]) ?? [];
    const normalLoginSources = (baseline.normalLoginSources as string[]) ?? [];
    const normalProcesses = (baseline.normalProcesses as string[]) ?? [];
    const avgDailyEvents = baseline.avgDailyEvents ?? 0;

    const entityFilter =
      baseline.entityType === "user"
        ? (e: (typeof recentEvents)[0]) => e.username === baseline.entityId
        : (e: (typeof recentEvents)[0]) => e.hostname === baseline.entityId;

    const entityEvents = recentEvents.filter(entityFilter);
    const newAnomalies: Array<{
      anomalyType: string;
      severity: string;
      score: number;
      description: string;
      evidence: Record<string, unknown>;
    }> = [];

    // --- Off-hours login ---
    const loginEvents = entityEvents.filter(
      (e) => e.eventType === "login_success" || e.eventType === "login_failure",
    );
    for (const evt of loginEvents) {
      const hour = new Date(evt.occurredAt).getUTCHours();
      if (normalLoginHours.length > 0 && !normalLoginHours.includes(hour)) {
        const severity = hour >= 2 && hour <= 5 ? "high" : "medium";
        newAnomalies.push({
          anomalyType: "off_hours_login",
          severity,
          score: ANOMALY_SCORE_WEIGHTS.off_hours_login,
          description: `Login at unusual hour ${hour}:00 UTC (normal hours: ${normalLoginHours.join(", ")})`,
          evidence: {
            hour,
            normalLoginHours,
            eventId: evt.id,
            occurredAt: evt.occurredAt,
            srcIp: evt.srcIp,
          },
        });
        break; // one anomaly per detection type per entity per cycle
      }
    }

    // --- New location ---
    for (const evt of loginEvents) {
      if (evt.srcIp && !isInternalIp(evt.srcIp)) {
        if (normalLoginSources.length > 0 && !normalLoginSources.includes(evt.srcIp)) {
          newAnomalies.push({
            anomalyType: "new_location",
            severity: "high",
            score: ANOMALY_SCORE_WEIGHTS.new_location,
            description: `Login from previously unseen external IP ${evt.srcIp}`,
            evidence: {
              srcIp: evt.srcIp,
              normalLoginSources,
              eventId: evt.id,
              occurredAt: evt.occurredAt,
            },
          });
          break;
        }
      }
    }

    // --- New process execution ---
    const processEvents = entityEvents.filter((e) => e.eventType === "process_create");
    for (const evt of processEvents) {
      if (
        evt.processName &&
        !normalProcesses.includes(evt.processName) &&
        SUSPICIOUS_PROCESS_RE.test(evt.processName)
      ) {
        newAnomalies.push({
          anomalyType: "new_process",
          severity: "high",
          score: ANOMALY_SCORE_WEIGHTS.new_process,
          description: `Suspicious process execution: ${evt.processName}`,
          evidence: {
            processName: evt.processName,
            processPath: evt.processPath,
            parentProcessName: evt.parentProcessName,
            eventId: evt.id,
            occurredAt: evt.occurredAt,
          },
        });
        break;
      }
    }

    // --- Volume anomaly ---
    if (avgDailyEvents > 10 && entityEvents.length > avgDailyEvents * 3) {
      newAnomalies.push({
        anomalyType: "volume_anomaly",
        severity: "medium",
        score: ANOMALY_SCORE_WEIGHTS.volume_anomaly,
        description: `Event volume spike: ${entityEvents.length} events in 24h vs baseline avg of ${avgDailyEvents.toFixed(1)}/day`,
        evidence: {
          todayCount: entityEvents.length,
          avgDailyEvents,
          ratio: (entityEvents.length / avgDailyEvents).toFixed(2),
        },
      });
    }

    if (newAnomalies.length === 0) continue;

    // Persist anomalies
    for (const a of newAnomalies) {
      try {
        await db.insert(uebaAnomalies).values({
          orgId,
          entityType: baseline.entityType,
          entityId: baseline.entityId,
          baselineId: baseline.id,
          anomalyType: a.anomalyType,
          severity: a.severity,
          score: a.score,
          description: a.description,
          evidence: a.evidence,
          status: "open",
          detectedAt: new Date(),
        });
        detected++;

        // Create alert for high/critical anomalies
        if (a.severity === "high" || a.severity === "critical") {
          try {
            const alert = await storage.createAlert({
              orgId,
              source: "UEBA",
              sourceEventId: `ueba-${baseline.entityType}-${baseline.entityId}-${a.anomalyType}-${Date.now()}`,
              category: "behavioral",
              severity: a.severity,
              title: `UEBA: ${a.anomalyType.replace(/_/g, " ")} detected for ${baseline.entityType} ${baseline.entityId}`,
              description: a.description,
              rawData: a.evidence as Record<string, unknown>,
              hostname:
                baseline.entityType === "host" ? baseline.entityId : undefined,
              userId: baseline.entityType === "user" ? baseline.entityId : undefined,
              mitreTactic: a.anomalyType === "new_process" ? "execution" : "initial-access",
              detectedAt: new Date(),
              status: "new",
            });

            broadcastEvent({
              type: "alert:created",
              orgId,
              data: {
                alertId: alert.id,
                severity: alert.severity,
                title: alert.title,
                source: "UEBA",
              },
            });
            alertsCreated++;
          } catch (alertErr) {
            log.warn("Failed to create alert for UEBA anomaly", {
              anomalyType: a.anomalyType,
              entityId: baseline.entityId,
              error: String(alertErr),
            });
          }
        }
      } catch (insertErr) {
        log.warn("Failed to insert UEBA anomaly", {
          anomalyType: a.anomalyType,
          entityId: baseline.entityId,
          error: String(insertErr),
        });
      }
    }

    // Update risk score on baseline
    const scoreIncrement = newAnomalies.reduce((sum, a) => sum + a.score, 0);
    const currentScore = baseline.riskScore ?? 0;
    const newScore = Math.min(100, currentScore + scoreIncrement);
    const riskReason = newAnomalies.map((a) => a.anomalyType).join(", ");

    await db
      .update(uebaBaselines)
      .set({
        riskScore: newScore,
        lastRiskReason: riskReason,
        updatedAt: new Date(),
      })
      .where(eq(uebaBaselines.id, baseline.id));
  }

  return { detected, alertsCreated };
}

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const computeBaselineBodySchema = z.object({
  entityId: z.string().min(1),
  entityType: z.enum(["user", "host", "service_account"]),
});

const runAnomalyDetectionBodySchema = z.object({}).optional();

const patchAnomalyBodySchema = z.object({
  status: z.enum(["resolved"]),
});

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export function registerUebaRoutes(app: Express): void {
  // GET /api/ueba/entities
  app.get(
    "/api/ueba/entities",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const rows = await db
          .select({
            id: uebaBaselines.id,
            orgId: uebaBaselines.orgId,
            entityType: uebaBaselines.entityType,
            entityId: uebaBaselines.entityId,
            riskScore: uebaBaselines.riskScore,
            lastRiskReason: uebaBaselines.lastRiskReason,
            eventCount: uebaBaselines.eventCount,
            avgDailyEvents: uebaBaselines.avgDailyEvents,
            lastComputedAt: uebaBaselines.lastComputedAt,
            createdAt: uebaBaselines.createdAt,
            updatedAt: uebaBaselines.updatedAt,
          })
          .from(uebaBaselines)
          .where(eq(uebaBaselines.orgId, orgId))
          .orderBy(desc(uebaBaselines.riskScore));

        // Attach open anomaly counts per entity
        const entityIds = rows.map((r) => r.entityId);

        let anomalyCounts: Array<{ entityId: string; cnt: number }> = [];
        if (entityIds.length > 0) {
          const countRows = await db
            .select({
              entityId: uebaAnomalies.entityId,
              cnt: count(uebaAnomalies.id),
            })
            .from(uebaAnomalies)
            .where(
              and(
                eq(uebaAnomalies.orgId, orgId),
                eq(uebaAnomalies.status, "open"),
                inArray(uebaAnomalies.entityId, entityIds),
              ),
            )
            .groupBy(uebaAnomalies.entityId);

          anomalyCounts = countRows.map((r) => ({ entityId: r.entityId, cnt: Number(r.cnt) }));
        }

        const anomalyCountMap = new Map(anomalyCounts.map((r) => [r.entityId, r.cnt]));

        const entities = rows.map((r) => ({
          ...r,
          anomalyCount: anomalyCountMap.get(r.entityId) ?? 0,
        }));

        return sendEnvelope(res, entities);
      } catch (err) {
        log.error("GET /api/ueba/entities error", { error: String(err) });
        return res.status(500).json({ message: "Failed to fetch UEBA entities" });
      }
    },
  );

  // GET /api/ueba/entities/:entityId
  app.get(
    "/api/ueba/entities/:entityId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { entityId } = req.params;
        const entityType = req.query.entityType as string | undefined;

        const conditions = [
          eq(uebaBaselines.orgId, orgId),
          eq(uebaBaselines.entityId, entityId),
        ];
        if (entityType) {
          conditions.push(eq(uebaBaselines.entityType, entityType));
        }

        const [baseline] = await db
          .select()
          .from(uebaBaselines)
          .where(and(...conditions))
          .limit(1);

        if (!baseline) {
          return res.status(404).json({ message: "Entity not found" });
        }

        const recentAnomalies = await db
          .select()
          .from(uebaAnomalies)
          .where(
            and(
              eq(uebaAnomalies.orgId, orgId),
              eq(uebaAnomalies.entityId, entityId),
            ),
          )
          .orderBy(desc(uebaAnomalies.detectedAt))
          .limit(50);

        return sendEnvelope(res, { baseline, recentAnomalies });
      } catch (err) {
        log.error("GET /api/ueba/entities/:entityId error", { error: String(err) });
        return res.status(500).json({ message: "Failed to fetch entity detail" });
      }
    },
  );

  // GET /api/ueba/anomalies
  app.get(
    "/api/ueba/anomalies",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const status = req.query.status as string | undefined;
        const severity = req.query.severity as string | undefined;
        const entityType = req.query.entityType as string | undefined;
        const limit = Math.min(parseInt((req.query.limit as string) ?? "50", 10), 200);
        const offset = parseInt((req.query.offset as string) ?? "0", 10);

        const conditions = [eq(uebaAnomalies.orgId, orgId)];
        if (status) conditions.push(eq(uebaAnomalies.status, status));
        if (severity) conditions.push(eq(uebaAnomalies.severity, severity));
        if (entityType) conditions.push(eq(uebaAnomalies.entityType, entityType));

        const whereClause = and(...conditions);

        const [totalRow] = await db
          .select({ total: count(uebaAnomalies.id) })
          .from(uebaAnomalies)
          .where(whereClause);

        const total = Number(totalRow?.total ?? 0);

        const items = await db
          .select()
          .from(uebaAnomalies)
          .where(whereClause)
          .orderBy(desc(uebaAnomalies.detectedAt))
          .limit(limit)
          .offset(offset);

        return sendEnvelope(res, items, {
          meta: { total, limit, offset },
        });
      } catch (err) {
        log.error("GET /api/ueba/anomalies error", { error: String(err) });
        return res.status(500).json({ message: "Failed to fetch anomalies" });
      }
    },
  );

  // PATCH /api/ueba/anomalies/:id
  app.patch(
    "/api/ueba/anomalies/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { id } = req.params;

        const parsed = patchAnomalyBodySchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({
            message: "Invalid request body",
            errors: parsed.error.flatten(),
          });
        }

        const [existing] = await db
          .select()
          .from(uebaAnomalies)
          .where(and(eq(uebaAnomalies.id, id), eq(uebaAnomalies.orgId, orgId)))
          .limit(1);

        if (!existing) {
          return res.status(404).json({ message: "Anomaly not found" });
        }

        const userId = (req as any).user?.id ?? null;

        const [updated] = await db
          .update(uebaAnomalies)
          .set({
            status: parsed.data.status,
            resolvedAt: new Date(),
            resolvedBy: userId,
          })
          .where(eq(uebaAnomalies.id, id))
          .returning();

        return sendEnvelope(res, updated);
      } catch (err) {
        log.error("PATCH /api/ueba/anomalies/:id error", { error: String(err) });
        return res.status(500).json({ message: "Failed to update anomaly" });
      }
    },
  );

  // POST /api/ueba/compute-baseline
  app.post(
    "/api/ueba/compute-baseline",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const parsed = computeBaselineBodySchema.safeParse(req.body);
        if (!parsed.success) {
          return res.status(400).json({
            message: "Invalid request body",
            errors: parsed.error.flatten(),
          });
        }

        const { entityId, entityType } = parsed.data;

        await computeBaseline(orgId, entityType, entityId);

        const [baseline] = await db
          .select()
          .from(uebaBaselines)
          .where(
            and(
              eq(uebaBaselines.orgId, orgId),
              eq(uebaBaselines.entityType, entityType),
              eq(uebaBaselines.entityId, entityId),
            ),
          )
          .limit(1);

        log.info("Baseline computed", { orgId, entityType, entityId });

        return sendEnvelope(res, baseline, { status: 200 });
      } catch (err) {
        log.error("POST /api/ueba/compute-baseline error", { error: String(err) });
        return res.status(500).json({ message: "Failed to compute baseline" });
      }
    },
  );

  // POST /api/ueba/run-anomaly-detection
  app.post(
    "/api/ueba/run-anomaly-detection",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const result = await detectAnomalies(orgId);

        log.info("Anomaly detection complete", { orgId, ...result });

        return sendEnvelope(res, result);
      } catch (err) {
        log.error("POST /api/ueba/run-anomaly-detection error", { error: String(err) });
        return res.status(500).json({ message: "Failed to run anomaly detection" });
      }
    },
  );

  // GET /api/ueba/stats
  app.get(
    "/api/ueba/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [totalEntitiesRow] = await db
          .select({ total: count(uebaBaselines.id) })
          .from(uebaBaselines)
          .where(eq(uebaBaselines.orgId, orgId));

        const [riskyEntitiesRow] = await db
          .select({ total: count(uebaBaselines.id) })
          .from(uebaBaselines)
          .where(
            and(
              eq(uebaBaselines.orgId, orgId),
              sql`${uebaBaselines.riskScore} > 70`,
            ),
          );

        const [openAnomaliesRow] = await db
          .select({ total: count(uebaAnomalies.id) })
          .from(uebaAnomalies)
          .where(
            and(eq(uebaAnomalies.orgId, orgId), eq(uebaAnomalies.status, "open")),
          );

        const topRiskyUsers = await db
          .select({
            entityId: uebaBaselines.entityId,
            entityType: uebaBaselines.entityType,
            riskScore: uebaBaselines.riskScore,
            lastRiskReason: uebaBaselines.lastRiskReason,
          })
          .from(uebaBaselines)
          .where(
            and(
              eq(uebaBaselines.orgId, orgId),
              eq(uebaBaselines.entityType, "user"),
            ),
          )
          .orderBy(desc(uebaBaselines.riskScore))
          .limit(5);

        return sendEnvelope(res, {
          totalEntities: Number(totalEntitiesRow?.total ?? 0),
          riskyEntities: Number(riskyEntitiesRow?.total ?? 0),
          openAnomalies: Number(openAnomaliesRow?.total ?? 0),
          topRiskyUsers,
        });
      } catch (err) {
        log.error("GET /api/ueba/stats error", { error: String(err) });
        return res.status(500).json({ message: "Failed to fetch UEBA stats" });
      }
    },
  );
}
