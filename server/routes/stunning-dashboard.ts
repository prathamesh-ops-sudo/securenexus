import type { Express } from "express";
import { requireAuth } from "../middleware/auth";
import { storage } from "../storage";
import { logger } from "../logger";

const log = logger.child("stunning-dashboard");

/**
 * Stunning Dashboard API
 * 
 * Provides gamified, psychologically engaging metrics:
 * - Security score (0-100)
 * - Daily streak counter
 * - Achievement system
 * - Daily insights (new every day)
 * - Team leaderboard
 * - Threat statistics
 */

export function registerStunningDashboardRoutes(app: Express): void {
  
  /**
   * GET /api/dashboard/stunning-stats
   * Get all dashboard statistics for addictive UI
   */
  app.get("/api/dashboard/stunning-stats", requireAuth, async (req, res) => {
    try {
      const orgId = req.user?.orgId;
      const userId = req.user?.id;
      
      if (!orgId) return res.status(403).json({ error: "No organization context" });

      // Get alerts
      const alerts = await storage.getAlerts(orgId);
      const incidents = await storage.getIncidents(orgId);
      
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
      const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);

      // Today's alerts
      const alertsToday = alerts.filter(a => new Date(a.createdAt) >= today).length;
      const alertsYesterday = alerts.filter(a => 
        new Date(a.createdAt) >= yesterday && new Date(a.createdAt) < today
      ).length;
      const alertsChange = alertsYesterday === 0 ? 0 : 
        Math.round(((alertsToday - alertsYesterday) / alertsYesterday) * 100);

      // Threats blocked (critical + high severity)
      const threatsToday = alerts.filter(a =>
        new Date(a.createdAt) >= today &&
        (a.severity === "critical" || a.severity === "high")
      ).length;
      const threatsYesterday = alerts.filter(a =>
        new Date(a.createdAt) >= yesterday && new Date(a.createdAt) < today &&
        (a.severity === "critical" || a.severity === "high")
      ).length;
      const threatsChange = threatsYesterday === 0 ? 0 :
        Math.round(((threatsToday - threatsYesterday) / threatsYesterday) * 100);

      // Incidents resolved
      const incidentsResolvedToday = incidents.filter(i =>
        i.status === "resolved" &&
        new Date(i.updatedAt) >= today
      ).length;
      const incidentsResolvedYesterday = incidents.filter(i =>
        i.status === "resolved" &&
        new Date(i.updatedAt) >= yesterday && new Date(i.updatedAt) < today
      ).length;
      const incidentsChange = incidentsResolvedYesterday === 0 ? 0 :
        Math.round(((incidentsResolvedToday - incidentsResolvedYesterday) / incidentsResolvedYesterday) * 100);

      // Calculate security score (0-100)
      let securityScore = 100;
      
      // Deduct for critical alerts
      const criticalAlerts = alerts.filter(a => a.severity === "critical").length;
      securityScore -= Math.min(criticalAlerts * 5, 30);
      
      // Deduct for high alerts
      const highAlerts = alerts.filter(a => a.severity === "high").length;
      securityScore -= Math.min(highAlerts * 2, 20);
      
      // Deduct for open incidents
      const openIncidents = incidents.filter(i => i.status === "open").length;
      securityScore -= Math.min(openIncidents * 3, 15);
      
      // Bonus for resolved incidents
      securityScore += Math.min(incidentsResolvedToday * 2, 10);
      
      securityScore = Math.max(0, Math.min(100, securityScore));

      // Daily streak (mock for now - would track actual user login history)
      const dailyStreak = 7; // TODO: Track actual streak from user login history

      // Generate daily insight
      const dailyInsight = generateDailyInsight(alerts, incidents, securityScore);

      // Get achievements
      const achievements = await calculateAchievements(orgId, userId, {
        alertsCount: alerts.length,
        incidentsResolved: incidents.filter(i => i.status === "resolved").length,
        criticalBlocked: alerts.filter(a => a.severity === "critical").length,
        streak: dailyStreak,
      });

      // Team leaderboard (mock for now)
      const teamRank = Math.floor(Math.random() * 5) + 1;
      const teamSize = 10;

      const response = {
        securityScore,
        scoreChange: 2, // Mock improvement
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
      };

      log.info("Fetched stunning dashboard stats", { orgId, securityScore });

      return res.json(response);
    } catch (error: any) {
      log.error("Failed to fetch stunning dashboard stats", { error: error.message });
      return res.status(500).json({ error: "Failed to fetch dashboard stats" });
    }
  });
}

/**
 * Generate daily insight based on current security posture
 */
function generateDailyInsight(alerts: any[], incidents: any[], securityScore: number): any {
  const insights = [];

  // Positive insights
  if (securityScore >= 90) {
    insights.push({
      type: "positive",
      title: "Excellent Security Posture! 🎉",
      description: "Your security score is exceptional. Keep up the great work!",
    });
  }

  if (incidents.filter(i => i.status === "resolved").length > 5) {
    insights.push({
      type: "positive",
      title: "Great Incident Response!",
      description: "You've resolved multiple incidents efficiently. Your team is doing amazing work!",
    });
  }

  // Warning insights
  const criticalAlerts = alerts.filter(a => a.severity === "critical").length;
  if (criticalAlerts > 3) {
    insights.push({
      type: "warning",
      title: "⚠️ Multiple Critical Alerts Detected",
      description: `You have ${criticalAlerts} critical alerts requiring immediate attention.`,
      action: {
        label: "View Critical Alerts",
        url: "/alerts?severity=critical",
      },
    });
  }

  const openIncidents = incidents.filter(i => i.status === "open").length;
  if (openIncidents > 5) {
    insights.push({
      type: "warning",
      title: "High Open Incident Count",
      description: `${openIncidents} incidents are currently open. Consider prioritizing resolution.`,
      action: {
        label: "View Incidents",
        url: "/incidents?status=open",
      },
    });
  }

  // Neutral/informative insights
  if (insights.length === 0) {
    insights.push({
      type: "neutral",
      title: "Security Operations Normal",
      description: "All systems are operating within normal parameters. Continue monitoring.",
    });
  }

  // Return random insight
  return insights[Math.floor(Math.random() * insights.length)];
}

/**
 * Calculate user achievements
 */
async function calculateAchievements(
  orgId: string,
  userId: string | undefined,
  stats: {
    alertsCount: number;
    incidentsResolved: number;
    criticalBlocked: number;
    streak: number;
  }
): Promise<any[]> {
  const achievements = [
    // Alert Triage Achievements
    {
      id: "first_triage",
      title: "First Steps",
      description: "Triage your first alert",
      icon: "🎯",
      progress: Math.min(stats.alertsCount, 1),
      maxProgress: 1,
      unlocked: stats.alertsCount >= 1,
      rarity: "common",
    },
    {
      id: "triage_master",
      title: "Triage Master",
      description: "Triage 100 alerts",
      icon: "🎖️",
      progress: Math.min(stats.alertsCount, 100),
      maxProgress: 100,
      unlocked: stats.alertsCount >= 100,
      rarity: "rare",
    },
    {
      id: "alert_legend",
      title: "Alert Legend",
      description: "Triage 1,000 alerts",
      icon: "👑",
      progress: Math.min(stats.alertsCount, 1000),
      maxProgress: 1000,
      unlocked: stats.alertsCount >= 1000,
      rarity: "epic",
    },

    // Incident Response Achievements
    {
      id: "first_responder",
      title: "First Responder",
      description: "Resolve your first incident",
      icon: "🚨",
      progress: Math.min(stats.incidentsResolved, 1),
      maxProgress: 1,
      unlocked: stats.incidentsResolved >= 1,
      rarity: "common",
    },
    {
      id: "incident_hero",
      title: "Incident Hero",
      description: "Resolve 50 incidents",
      icon: "🦸",
      progress: Math.min(stats.incidentsResolved, 50),
      maxProgress: 50,
      unlocked: stats.incidentsResolved >= 50,
      rarity: "epic",
    },

    // Threat Blocking Achievements
    {
      id: "threat_blocker",
      title: "Threat Blocker",
      description: "Block 10 critical threats",
      icon: "🛡️",
      progress: Math.min(stats.criticalBlocked, 10),
      maxProgress: 10,
      unlocked: stats.criticalBlocked >= 10,
      rarity: "rare",
    },
    {
      id: "guardian",
      title: "Security Guardian",
      description: "Block 100 critical threats",
      icon: "⚔️",
      progress: Math.min(stats.criticalBlocked, 100),
      maxProgress: 100,
      unlocked: stats.criticalBlocked >= 100,
      rarity: "legendary",
    },

    // Streak Achievements
    {
      id: "consistent",
      title: "Consistent Defender",
      description: "Login 7 days in a row",
      icon: "🔥",
      progress: Math.min(stats.streak, 7),
      maxProgress: 7,
      unlocked: stats.streak >= 7,
      rarity: "rare",
    },
    {
      id: "dedicated",
      title: "Dedicated Guardian",
      description: "Login 30 days in a row",
      icon: "💎",
      progress: Math.min(stats.streak, 30),
      maxProgress: 30,
      unlocked: stats.streak >= 30,
      rarity: "epic",
    },
    {
      id: "unstoppable",
      title: "Unstoppable Force",
      description: "Login 100 days in a row",
      icon: "⭐",
      progress: Math.min(stats.streak, 100),
      maxProgress: 100,
      unlocked: stats.streak >= 100,
      rarity: "legendary",
    },
  ];

  // Sort: unlocked first, then by rarity, then by progress
  return achievements.sort((a, b) => {
    if (a.unlocked !== b.unlocked) return a.unlocked ? -1 : 1;
    
    const rarityOrder = { legendary: 0, epic: 1, rare: 2, common: 3 };
    if (rarityOrder[a.rarity as keyof typeof rarityOrder] !== rarityOrder[b.rarity as keyof typeof rarityOrder]) {
      return rarityOrder[a.rarity as keyof typeof rarityOrder] - rarityOrder[b.rarity as keyof typeof rarityOrder];
    }
    
    return (b.progress / b.maxProgress) - (a.progress / a.maxProgress);
  });
}
