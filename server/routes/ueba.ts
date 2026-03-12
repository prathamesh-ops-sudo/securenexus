import type { Express } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { requirePermission } from "../rbac";
import { logger, getOrgId } from "./shared";
import { db } from "../db";
import { sql, eq, and, desc, ilike, or, gte, lte } from "drizzle-orm";
import {
  uebaBaselines,
  uebaAnomalies,
  uebaEntityScores,
  sensorEvents,
  UEBA_ENTITY_TYPES,
  UEBA_ANOMALY_TYPES,
} from "../../shared/schema";

const log = logger.child("ueba");

// Risk level thresholds
function riskLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "none";
}

// Anomaly risk score weights
const ANOMALY_SCORES: Record<string, number> = {
  off_hours_login: 25,
  new_geo_location: 30,
  suspicious_process: 35,
  traffic_volume_spike: 20,
  new_source_ip: 15,
  brute_force_attempt: 40,
  privilege_escalation: 45,
  data_exfiltration: 50,
};

export function registerUebaRoutes(app: Express): void {
  // ==========================================================================
  // ENTITY RISK LEADERBOARD
  // ==========================================================================

  app.get("/api/ueba/entities", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const entityType = req.query.entityType as string | undefined;
      const riskLevelFilter = req.query.riskLevel as string | undefined;
      const q = (req.query.q as string) || "";
      const limitParam = parseInt(String(req.query.limit || "50"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);
      const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

      const conditions: unknown[] = [eq(uebaEntityScores.orgId, orgId)];
      if (entityType && entityType !== "all") conditions.push(eq(uebaEntityScores.entityType, entityType));
      if (riskLevelFilter && riskLevelFilter !== "all")
        conditions.push(eq(uebaEntityScores.riskLevel, riskLevelFilter));
      if (q) {
        conditions.push(or(ilike(uebaEntityScores.entityName, `%${q}%`), ilike(uebaEntityScores.entityId, `%${q}%`)));
      }

      const entities = await db
        .select()
        .from(uebaEntityScores)
        .where(and(...(conditions as any[])))
        .orderBy(desc(uebaEntityScores.riskScore))
        .limit(limit)
        .offset(offset);

      const statsResult = await db.execute(sql`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE risk_level = 'critical') AS critical_count,
          COUNT(*) FILTER (WHERE risk_level = 'high') AS high_count,
          COUNT(*) FILTER (WHERE risk_level = 'medium') AS medium_count,
          COUNT(*) FILTER (WHERE risk_level = 'low') AS low_count,
          COALESCE(AVG(risk_score), 0) AS avg_risk_score
        FROM ueba_entity_scores
        WHERE org_id = ${orgId}
      `);
      const s = (statsResult as any).rows?.[0] || {};

      res.json({
        entities,
        stats: {
          total: parseInt(s.total || "0"),
          criticalCount: parseInt(s.critical_count || "0"),
          highCount: parseInt(s.high_count || "0"),
          mediumCount: parseInt(s.medium_count || "0"),
          lowCount: parseInt(s.low_count || "0"),
          avgRiskScore: parseFloat(parseFloat(s.avg_risk_score || "0").toFixed(1)),
        },
      });
    } catch (error) {
      log.error("Failed to list entities", { error: String(error) });
      res.status(500).json({ message: "Failed to list entities" });
    }
  });

  // ==========================================================================
  // ANOMALIES — Timeline view
  // ==========================================================================

  app.get("/api/ueba/anomalies", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const entityType = req.query.entityType as string | undefined;
      const entityId = req.query.entityId as string | undefined;
      const anomalyType = req.query.anomalyType as string | undefined;
      const severity = req.query.severity as string | undefined;
      const limitParam = parseInt(String(req.query.limit || "50"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);
      const offset = Number.isNaN(offsetParam) ? 0 : offsetParam;

      const conditions: unknown[] = [eq(uebaAnomalies.orgId, orgId)];
      if (entityType && entityType !== "all") conditions.push(eq(uebaAnomalies.entityType, entityType));
      if (entityId) conditions.push(eq(uebaAnomalies.entityId, entityId));
      if (anomalyType && anomalyType !== "all") conditions.push(eq(uebaAnomalies.anomalyType, anomalyType));
      if (severity && severity !== "all") conditions.push(eq(uebaAnomalies.severity, severity));

      const anomalies = await db
        .select()
        .from(uebaAnomalies)
        .where(and(...(conditions as any[])))
        .orderBy(desc(uebaAnomalies.createdAt))
        .limit(limit)
        .offset(offset);

      res.json({ anomalies });
    } catch (error) {
      log.error("Failed to list anomalies", { error: String(error) });
      res.status(500).json({ message: "Failed to list anomalies" });
    }
  });

  // Dismiss an anomaly
  app.patch(
    "/api/ueba/anomalies/:id/dismiss",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const anomalyId = String(req.params.id);

        const [anomaly] = await db
          .select()
          .from(uebaAnomalies)
          .where(and(eq(uebaAnomalies.id, anomalyId), eq(uebaAnomalies.orgId, orgId)))
          .limit(1);

        if (!anomaly) {
          return res.status(404).json({ message: "Anomaly not found" });
        }

        const userId = (req as any).user?.id;

        const [updated] = await db
          .update(uebaAnomalies)
          .set({ dismissed: true, dismissedBy: userId })
          .where(eq(uebaAnomalies.id, anomalyId))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to dismiss anomaly", { error: String(error) });
        res.status(500).json({ message: "Failed to dismiss anomaly" });
      }
    },
  );

  // ==========================================================================
  // BASELINES
  // ==========================================================================

  app.get("/api/ueba/baselines", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const entityType = req.query.entityType as string | undefined;
      const entityId = req.query.entityId as string | undefined;
      const limitParam = parseInt(String(req.query.limit || "50"));
      const limit = Math.min(Number.isNaN(limitParam) ? 50 : limitParam, 200);

      const conditions: unknown[] = [eq(uebaBaselines.orgId, orgId)];
      if (entityType && entityType !== "all") conditions.push(eq(uebaBaselines.entityType, entityType));
      if (entityId) conditions.push(eq(uebaBaselines.entityId, entityId));

      const baselines = await db
        .select()
        .from(uebaBaselines)
        .where(and(...(conditions as any[])))
        .orderBy(desc(uebaBaselines.lastUpdated))
        .limit(limit);

      res.json({ baselines });
    } catch (error) {
      log.error("Failed to list baselines", { error: String(error) });
      res.status(500).json({ message: "Failed to list baselines" });
    }
  });

  // ==========================================================================
  // ANALYZE — Build baselines and detect anomalies from sensor events
  // ==========================================================================

  app.post(
    "/api/ueba/analyze",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requirePermission("incidents", "write"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const windowHours = Math.min(parseInt(String(req.body.windowHours || "24")), 720);

        // Get recent sensor events for analysis
        const cutoff = new Date(Date.now() - windowHours * 60 * 60 * 1000);
        const events = await db
          .select()
          .from(sensorEvents)
          .where(and(eq(sensorEvents.orgId, orgId), gte(sensorEvents.timestamp, cutoff)))
          .orderBy(desc(sensorEvents.timestamp))
          .limit(10000);

        if (events.length === 0) {
          return res.json({ message: "No events to analyze", anomaliesCreated: 0, baselinesUpdated: 0 });
        }

        let anomaliesCreated = 0;
        let baselinesUpdated = 0;

        // Group events by user
        const userEvents = new Map<string, typeof events>();
        const hostEvents = new Map<string, typeof events>();

        for (const event of events) {
          if (event.userName) {
            const key = event.userName;
            if (!userEvents.has(key)) userEvents.set(key, []);
            userEvents.get(key)!.push(event);
          }
          if (event.sensorId) {
            const key = event.sensorId;
            if (!hostEvents.has(key)) hostEvents.set(key, []);
            hostEvents.get(key)!.push(event);
          }
        }

        // Analyze user behavior
        for (const [userName, userEvts] of Array.from(userEvents.entries())) {
          // Check for off-hours logins (2am-5am)
          const offHoursEvents = userEvts.filter((e: (typeof events)[number]) => {
            if (!e.timestamp) return false;
            const hour = new Date(e.timestamp).getUTCHours();
            return hour >= 2 && hour <= 5 && (e.eventType === "auth" || e.authAction);
          });

          if (offHoursEvents.length > 0) {
            await db.insert(uebaAnomalies).values({
              orgId,
              entityType: "user",
              entityId: userName,
              entityName: userName,
              anomalyType: "off_hours_login",
              severity: "high",
              riskScore: ANOMALY_SCORES.off_hours_login,
              description: `${offHoursEvents.length} login event(s) detected between 2-5 AM UTC`,
              details: {
                eventCount: offHoursEvents.length,
                hours: offHoursEvents.map((e: (typeof events)[number]) => e.timestamp),
              },
            });
            anomaliesCreated++;
          }

          // Check for suspicious processes
          const suspiciousPatterns = ["base64", "certutil", "mshta", "nc ", "ncat", "powershell -enc", "wget", "curl"];
          const suspiciousEvents = userEvts.filter((e: (typeof events)[number]) => {
            const cmdLine = `${e.processName || ""} ${e.processArgs || ""}`.toLowerCase();
            return suspiciousPatterns.some((p) => cmdLine.includes(p));
          });

          if (suspiciousEvents.length > 0) {
            await db.insert(uebaAnomalies).values({
              orgId,
              entityType: "user",
              entityId: userName,
              entityName: userName,
              anomalyType: "suspicious_process",
              severity: "high",
              riskScore: ANOMALY_SCORES.suspicious_process,
              description: `${suspiciousEvents.length} suspicious process execution(s) detected`,
              details: {
                processes: suspiciousEvents.map((e: (typeof events)[number]) => ({
                  name: e.processName,
                  args: e.processArgs,
                  time: e.timestamp,
                })),
              },
            });
            anomaliesCreated++;
          }

          // Update/create entity score
          const totalScore = Math.min(
            100,
            (offHoursEvents.length > 0 ? ANOMALY_SCORES.off_hours_login : 0) +
              (suspiciousEvents.length > 0 ? ANOMALY_SCORES.suspicious_process : 0),
          );

          if (totalScore > 0) {
            const [existing] = await db
              .select()
              .from(uebaEntityScores)
              .where(
                and(
                  eq(uebaEntityScores.orgId, orgId),
                  eq(uebaEntityScores.entityType, "user"),
                  eq(uebaEntityScores.entityId, userName),
                ),
              )
              .limit(1);

            if (existing) {
              const newScore = Math.min(100, existing.riskScore + totalScore);
              await db
                .update(uebaEntityScores)
                .set({
                  riskScore: newScore,
                  riskLevel: riskLevel(newScore),
                  anomalyCount: existing.anomalyCount + anomaliesCreated,
                  lastAnomalyAt: new Date(),
                  updatedAt: new Date(),
                })
                .where(eq(uebaEntityScores.id, existing.id));
            } else {
              await db.insert(uebaEntityScores).values({
                orgId,
                entityType: "user",
                entityId: userName,
                entityName: userName,
                riskScore: totalScore,
                riskLevel: riskLevel(totalScore),
                anomalyCount: anomaliesCreated,
                lastAnomalyAt: new Date(),
              });
            }
          }

          // Update baseline
          const [existingBaseline] = await db
            .select()
            .from(uebaBaselines)
            .where(
              and(
                eq(uebaBaselines.orgId, orgId),
                eq(uebaBaselines.entityType, "user"),
                eq(uebaBaselines.entityId, userName),
              ),
            )
            .limit(1);

          const knownIps = Array.from(
            new Set(userEvts.map((e: (typeof events)[number]) => e.srcIp).filter(Boolean)),
          ) as string[];
          const knownProcesses = Array.from(
            new Set(userEvts.map((e: (typeof events)[number]) => e.processName).filter(Boolean)),
          ) as string[];

          if (existingBaseline) {
            await db
              .update(uebaBaselines)
              .set({
                knownSourceIps: knownIps.slice(0, 100),
                processAllowList: knownProcesses.slice(0, 200),
                avgDailyEventVolume: userEvts.length / Math.max(1, windowHours / 24),
                lastUpdated: new Date(),
              })
              .where(eq(uebaBaselines.id, existingBaseline.id));
          } else {
            await db.insert(uebaBaselines).values({
              orgId,
              entityType: "user",
              entityId: userName,
              entityName: userName,
              knownSourceIps: knownIps.slice(0, 100),
              processAllowList: knownProcesses.slice(0, 200),
              avgDailyEventVolume: userEvts.length / Math.max(1, windowHours / 24),
              normalLoginHoursStart: 8,
              normalLoginHoursEnd: 20,
            });
          }
          baselinesUpdated++;
        }

        // Analyze host behavior — traffic volume spikes
        for (const [hostId, hostEvts] of Array.from(hostEvents.entries())) {
          const totalBytes = hostEvts.reduce(
            (sum: number, e: (typeof events)[number]) => sum + (e.bytesIn || 0) + (e.bytesOut || 0),
            0,
          );
          const avgBytesPerHour = totalBytes / Math.max(1, windowHours);

          // Flag if total bytes > 100MB in the window (rough heuristic)
          if (totalBytes > 100 * 1024 * 1024) {
            await db.insert(uebaAnomalies).values({
              orgId,
              entityType: "host",
              entityId: hostId,
              entityName: hostId,
              anomalyType: "traffic_volume_spike",
              severity: "medium",
              riskScore: ANOMALY_SCORES.traffic_volume_spike,
              description: `High network volume: ${(totalBytes / 1024 / 1024).toFixed(1)} MB in ${windowHours}h`,
              details: { totalBytes, avgBytesPerHour, eventCount: hostEvts.length },
            });
            anomaliesCreated++;
          }
        }

        log.info(`UEBA analysis complete: ${anomaliesCreated} anomalies, ${baselinesUpdated} baselines`, { orgId });

        res.json({
          anomaliesCreated,
          baselinesUpdated,
          eventsAnalyzed: events.length,
          windowHours,
        });
      } catch (error) {
        log.error("UEBA analysis failed", { error: String(error) });
        res.status(500).json({ message: "UEBA analysis failed" });
      }
    },
  );

  // ==========================================================================
  // ENTITY DETAIL — anomaly history for a specific entity
  // ==========================================================================

  app.get(
    "/api/ueba/entities/:entityType/:entityId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const entityType = String(req.params.entityType);
        const entityId = String(req.params.entityId);

        const [score] = await db
          .select()
          .from(uebaEntityScores)
          .where(
            and(
              eq(uebaEntityScores.orgId, orgId),
              eq(uebaEntityScores.entityType, entityType),
              eq(uebaEntityScores.entityId, entityId),
            ),
          )
          .limit(1);

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

        const anomalies = await db
          .select()
          .from(uebaAnomalies)
          .where(
            and(
              eq(uebaAnomalies.orgId, orgId),
              eq(uebaAnomalies.entityType, entityType),
              eq(uebaAnomalies.entityId, entityId),
            ),
          )
          .orderBy(desc(uebaAnomalies.createdAt))
          .limit(50);

        res.json({ score, baseline, anomalies });
      } catch (error) {
        log.error("Failed to get entity detail", { error: String(error) });
        res.status(500).json({ message: "Failed to get entity detail" });
      }
    },
  );
}
