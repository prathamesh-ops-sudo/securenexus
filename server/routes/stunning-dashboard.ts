import type { Express } from "express";
import { getOrgId, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { logger } from "../logger";
import { resolveOrgContext, requireOrgId } from "../rbac";

const log = logger.child("stunning-dashboard");

interface AchievementDef {
  id: string;
  title: string;
  description: string;
  icon: string;
  progress: number;
  maxProgress: number;
  unlocked: boolean;
  rarity: "common" | "rare" | "epic" | "legendary";
}

export function registerStunningDashboardRoutes(app: Express): void {
  app.get("/api/dashboard/stunning-stats", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const alerts = await storage.getAlerts(orgId);
      const incidents = await storage.getIncidents(orgId);

      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);

      const alertsToday = alerts.filter((a) => a.createdAt !== null && new Date(a.createdAt) >= today).length;
      const alertsYesterday = alerts.filter(
        (a) => a.createdAt !== null && new Date(a.createdAt) >= yesterday && new Date(a.createdAt) < today,
      ).length;
      const alertsChange =
        alertsYesterday === 0 ? 0 : Math.round(((alertsToday - alertsYesterday) / alertsYesterday) * 100);

      const threatsToday = alerts.filter(
        (a) =>
          a.createdAt !== null &&
          new Date(a.createdAt) >= today &&
          (a.severity === "critical" || a.severity === "high"),
      ).length;
      const threatsYesterday = alerts.filter(
        (a) =>
          a.createdAt !== null &&
          new Date(a.createdAt) >= yesterday &&
          new Date(a.createdAt) < today &&
          (a.severity === "critical" || a.severity === "high"),
      ).length;
      const threatsChange =
        threatsYesterday === 0 ? 0 : Math.round(((threatsToday - threatsYesterday) / threatsYesterday) * 100);

      const incidentsResolvedToday = incidents.filter(
        (i) => i.status === "resolved" && i.updatedAt !== null && new Date(i.updatedAt) >= today,
      ).length;
      const incidentsResolvedYesterday = incidents.filter(
        (i) =>
          i.status === "resolved" &&
          i.updatedAt !== null &&
          new Date(i.updatedAt) >= yesterday &&
          new Date(i.updatedAt) < today,
      ).length;
      const incidentsChange =
        incidentsResolvedYesterday === 0
          ? 0
          : Math.round(((incidentsResolvedToday - incidentsResolvedYesterday) / incidentsResolvedYesterday) * 100);

      let securityScore = 100;
      const criticalAlerts = alerts.filter((a) => a.severity === "critical").length;
      securityScore -= Math.min(criticalAlerts * 5, 30);
      const highAlerts = alerts.filter((a) => a.severity === "high").length;
      securityScore -= Math.min(highAlerts * 2, 20);
      const openIncidents = incidents.filter((i) => i.status === "open").length;
      securityScore -= Math.min(openIncidents * 3, 15);
      securityScore += Math.min(incidentsResolvedToday * 2, 10);
      securityScore = Math.max(0, Math.min(100, securityScore));

      // Calculate actual streak from audit logs (login events)
      // For now, derive from whether user has alerts in consecutive recent days
      let dailyStreak = 0;
      const msPerDay = 24 * 60 * 60 * 1000;
      for (let d = 0; d < 365; d++) {
        const dayStart = new Date(today.getTime() - d * msPerDay);
        const dayEnd = new Date(dayStart.getTime() + msPerDay);
        const hasActivity =
          alerts.some(
            (a) => a.createdAt !== null && new Date(a.createdAt) >= dayStart && new Date(a.createdAt) < dayEnd,
          ) ||
          incidents.some(
            (i) => i.updatedAt !== null && new Date(i.updatedAt) >= dayStart && new Date(i.updatedAt) < dayEnd,
          );
        if (hasActivity) {
          dailyStreak++;
        } else {
          break;
        }
      }

      const dailyInsight = generateDailyInsight(securityScore, criticalAlerts, openIncidents);

      const achievements = calculateAchievements({
        alertsCount: alerts.length,
        incidentsResolved: incidents.filter((i) => i.status === "resolved").length,
        criticalBlocked: criticalAlerts,
        streak: dailyStreak,
      });

      // Team rank is not meaningful without multi-user activity tracking
      // Return null to signal the frontend to hide the gamification widget
      const teamRank = null;
      const teamSize = null;

      log.info("Fetched stunning dashboard stats", { orgId, securityScore });

      return res.json({
        securityScore,
        scoreChange: null,
        alertsToday,
        alertsChange,
        threatsBlocked: threatsToday,
        threatsChange,
        incidentsResolved: incidentsResolvedToday,
        incidentsChange,
        dailyStreak,
        achievements,
        dailyInsight,
        teamRank,
        teamSize,
      });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : "Unknown error";
      log.error("Failed to fetch stunning dashboard stats", { error: msg });
      return res.status(500).json({ error: "Failed to fetch dashboard stats" });
    }
  });
}

function generateDailyInsight(
  securityScore: number,
  criticalAlerts: number,
  openIncidents: number,
): { type: string; title: string; description: string; action?: { label: string; url: string } } {
  const insights: {
    type: string;
    title: string;
    description: string;
    action?: { label: string; url: string };
  }[] = [];

  if (securityScore >= 90) {
    insights.push({
      type: "positive",
      title: "Excellent Security Posture!",
      description: "Your security score is exceptional. Keep up the great work!",
    });
  }

  if (criticalAlerts > 3) {
    insights.push({
      type: "warning",
      title: "Multiple Critical Alerts Detected",
      description: `You have ${criticalAlerts} critical alerts requiring immediate attention.`,
      action: { label: "View Critical Alerts", url: "/alerts?severity=critical" },
    });
  }

  if (openIncidents > 5) {
    insights.push({
      type: "warning",
      title: "High Open Incident Count",
      description: `${openIncidents} incidents are currently open. Consider prioritizing resolution.`,
      action: { label: "View Incidents", url: "/incidents?status=open" },
    });
  }

  if (insights.length === 0) {
    insights.push({
      type: "neutral",
      title: "Security Operations Normal",
      description: "All systems are operating within normal parameters. Continue monitoring.",
    });
  }

  // Return the most relevant insight (highest priority) instead of random
  // Priority: warning > neutral > positive
  const priorityOrder: Record<string, number> = { warning: 0, neutral: 1, positive: 2 };
  insights.sort((a, b) => (priorityOrder[a.type] ?? 99) - (priorityOrder[b.type] ?? 99));
  return insights[0];
}

function calculateAchievements(stats: {
  alertsCount: number;
  incidentsResolved: number;
  criticalBlocked: number;
  streak: number;
}): AchievementDef[] {
  const achievements: AchievementDef[] = [
    {
      id: "first_triage",
      title: "First Steps",
      description: "Triage your first alert",
      icon: "target",
      progress: Math.min(stats.alertsCount, 1),
      maxProgress: 1,
      unlocked: stats.alertsCount >= 1,
      rarity: "common",
    },
    {
      id: "triage_master",
      title: "Triage Master",
      description: "Triage 100 alerts",
      icon: "medal",
      progress: Math.min(stats.alertsCount, 100),
      maxProgress: 100,
      unlocked: stats.alertsCount >= 100,
      rarity: "rare",
    },
    {
      id: "alert_legend",
      title: "Alert Legend",
      description: "Triage 1,000 alerts",
      icon: "crown",
      progress: Math.min(stats.alertsCount, 1000),
      maxProgress: 1000,
      unlocked: stats.alertsCount >= 1000,
      rarity: "epic",
    },
    {
      id: "first_responder",
      title: "First Responder",
      description: "Resolve your first incident",
      icon: "siren",
      progress: Math.min(stats.incidentsResolved, 1),
      maxProgress: 1,
      unlocked: stats.incidentsResolved >= 1,
      rarity: "common",
    },
    {
      id: "incident_hero",
      title: "Incident Hero",
      description: "Resolve 50 incidents",
      icon: "shield",
      progress: Math.min(stats.incidentsResolved, 50),
      maxProgress: 50,
      unlocked: stats.incidentsResolved >= 50,
      rarity: "epic",
    },
    {
      id: "threat_blocker",
      title: "Threat Blocker",
      description: "Block 10 critical threats",
      icon: "shield-check",
      progress: Math.min(stats.criticalBlocked, 10),
      maxProgress: 10,
      unlocked: stats.criticalBlocked >= 10,
      rarity: "rare",
    },
    {
      id: "guardian",
      title: "Security Guardian",
      description: "Block 100 critical threats",
      icon: "swords",
      progress: Math.min(stats.criticalBlocked, 100),
      maxProgress: 100,
      unlocked: stats.criticalBlocked >= 100,
      rarity: "legendary",
    },
    {
      id: "consistent",
      title: "Consistent Defender",
      description: "Login 7 days in a row",
      icon: "flame",
      progress: Math.min(stats.streak, 7),
      maxProgress: 7,
      unlocked: stats.streak >= 7,
      rarity: "rare",
    },
    {
      id: "dedicated",
      title: "Dedicated Guardian",
      description: "Login 30 days in a row",
      icon: "gem",
      progress: Math.min(stats.streak, 30),
      maxProgress: 30,
      unlocked: stats.streak >= 30,
      rarity: "epic",
    },
    {
      id: "unstoppable",
      title: "Unstoppable Force",
      description: "Login 100 days in a row",
      icon: "star",
      progress: Math.min(stats.streak, 100),
      maxProgress: 100,
      unlocked: stats.streak >= 100,
      rarity: "legendary",
    },
  ];

  const rarityOrder: Record<string, number> = { legendary: 0, epic: 1, rare: 2, common: 3 };
  return achievements.sort((a, b) => {
    if (a.unlocked !== b.unlocked) return a.unlocked ? -1 : 1;
    const ra = rarityOrder[a.rarity] ?? 4;
    const rb = rarityOrder[b.rarity] ?? 4;
    if (ra !== rb) return ra - rb;
    return b.progress / b.maxProgress - a.progress / a.maxProgress;
  });
}
