import type { Express, Request, Response } from "express";
import { getOrgId, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { CACHE_TTL, buildCacheKey, cacheGetOrLoad } from "../query-cache";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { pool } from "../db";
import { logger } from "../logger";
import { isDashboardRole } from "./dashboard-role";
export { isDashboardRole } from "./dashboard-role";

const log = logger.child("dashboard-routes");

export function registerDashboardRoutes(app: Express): void {
  // Dashboard (with query-level caching)
  // Supports ?range=1h|4h|24h|7d|30d (default 24h)
  app.get("/api/dashboard/stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const range = String(req.query.range || "24h");
      const cacheKey = buildCacheKey("dashboard:stats", { orgId, range });
      const stats = await cacheGetOrLoad(cacheKey, () => storage.getDashboardStats(orgId), CACHE_TTL.DASHBOARD_STATS);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });

  app.get("/api/dashboard/analytics", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const range = String(req.query.range || "24h");
      const cacheKey = buildCacheKey("dashboard:analytics", { orgId, range });
      const analytics = await cacheGetOrLoad(
        cacheKey,
        () => storage.getDashboardAnalytics(orgId),
        CACHE_TTL.DASHBOARD_ANALYTICS,
      );
      res.json(analytics);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch analytics" });
    }
  });

  // Operational metrics from metrics rollup tables (MTTD, MTTR, throughput trends)
  app.get(
    "/api/dashboard/operational-metrics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const cacheKey = buildCacheKey("dashboard:operational-metrics", { orgId });
        const data = await cacheGetOrLoad(
          cacheKey,
          async () => {
            // Pull MTTD/MTTR from hourly rollup if available, otherwise compute from incidents
            const [mttrResult, mttdResult, throughputResult, trendResult] = await Promise.all([
              // MTTR: avg time from incident open to resolved (last 30 days)
              pool.query(
                `
              SELECT AVG(EXTRACT(EPOCH FROM (i.resolved_at - i.created_at)) / 3600)::numeric(10,2) AS mttr_hours
              FROM incidents i
              WHERE i.org_id = $1
                AND i.status = 'resolved'
                AND i.resolved_at IS NOT NULL
                AND i.created_at >= NOW() - INTERVAL '30 days'
            `,
                [orgId],
              ),
              // MTTD: avg time from alert created to first investigation (triage)
              // incidents use referenced_alert_ids (text[]) not a single alert_id FK
              pool.query(
                `
              SELECT AVG(EXTRACT(EPOCH FROM (sub.incident_created - sub.first_alert_created)) / 60)::numeric(10,1) AS mttd_minutes
              FROM (
                SELECT i.created_at AS incident_created, MIN(a.created_at) AS first_alert_created
                FROM incidents i
                CROSS JOIN LATERAL unnest(i.referenced_alert_ids) AS ref_id
                JOIN alerts a ON a.id = ref_id AND a.org_id = $1
                WHERE i.org_id = $1
                  AND i.created_at >= NOW() - INTERVAL '30 days'
                GROUP BY i.id, i.created_at
              ) sub
            `,
                [orgId],
              ),
              // Throughput: alerts processed per hour (last 24h)
              pool.query(
                `
              SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE status = 'resolved' OR status = 'closed')::int AS resolved
              FROM alerts
              WHERE org_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
            `,
                [orgId],
              ),
              // Daily trend for last 7 days from metrics rollup (if available)
              pool.query(`
              SELECT day::text AS date,
                avg_value AS "avgValue",
                sample_count AS "sampleCount"
              FROM sli_metrics_daily
              WHERE service = 'incidents' AND metric = 'mttr_hours'
                AND day >= NOW() - INTERVAL '7 days'
              ORDER BY day ASC
              LIMIT 7
            `),
            ]);

            const mttrHours = mttrResult.rows[0]?.mttr_hours != null ? Number(mttrResult.rows[0].mttr_hours) : null;
            const mttdMinutes =
              mttdResult.rows[0]?.mttd_minutes != null ? Number(mttdResult.rows[0].mttd_minutes) : null;
            const alertsProcessed24h = throughputResult.rows[0]?.total ?? 0;
            const alertsResolved24h = throughputResult.rows[0]?.resolved ?? 0;
            const mttrTrend = trendResult.rows.map((r: { date: string; avgValue: number; sampleCount: number }) => ({
              date: r.date,
              avgValue: Number(r.avgValue),
              sampleCount: Number(r.sampleCount),
            }));

            return {
              mttrHours,
              mttdMinutes,
              alertsProcessed24h,
              alertsResolved24h,
              resolutionRate:
                alertsProcessed24h > 0 ? Math.round((alertsResolved24h / alertsProcessed24h) * 100) : null,
              mttrTrend,
            };
          },
          CACHE_TTL.DASHBOARD_STATS,
        );
        res.json(data);
      } catch (err) {
        log.error("Failed to fetch operational metrics", { error: String(err) });
        res.status(500).json({ message: "Failed to fetch operational metrics" });
      }
    },
  );

  app.get(
    "/api/dashboard/:role",
    (req, res, next) => {
      const roleParam = typeof req.params.role === "string" ? req.params.role : "";
      if (!isDashboardRole(roleParam)) {
        next("route");
        return;
      }
      next();
    },
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      const user = req.user as { orgId?: string; role?: string };
      const role = p(req.params.role);
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
            recentCriticalIncidents: allIncidents.filter((i) => i.severity === "critical").slice(0, 5),
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
            recentIncidents: allIncidents
              .filter((i) => ["open", "investigating"].includes(i.status || ""))
              .slice(0, 10),
          });
        }
      } catch (err: unknown) {
        res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
      }
    },
  );
}
