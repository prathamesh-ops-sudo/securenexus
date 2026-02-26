import type { Express, Request, Response } from "express";
import { getOrgId, p, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { CACHE_TTL, buildCacheKey, cacheGetOrLoad } from "../query-cache";

export function registerDashboardRoutes(app: Express): void {
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

}
