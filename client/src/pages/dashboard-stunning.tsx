import { useQuery } from "@tanstack/react-query";
import { useState, useEffect, useMemo } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Shield,
  AlertTriangle,
  Zap,
  Target,
  TrendingUp,
  TrendingDown,
  Award,
  Flame,
  Star,
  Trophy,
  Clock,
  Activity,
  CheckCircle2,
  XCircle,
  Sparkles,
  ArrowUpRight,
  ArrowDownRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import confetti from "canvas-confetti";

/**
 * VISUALLY STUNNING & ADDICTIVE DASHBOARD
 * 
 * Psychology hooks:
 * - Gamification (streaks, achievements, score)
 * - Progress visualization (rings, bars)
 * - Celebration animations (confetti)
 * - Personalization (good morning, name)
 * - Daily insights (new every day)
 * - FOMO triggers (threats blocked today)
 * - Social proof (team leaderboard)
 * - Variable rewards (random insights)
 * - Micro-interactions (smooth animations)
 */

interface DashboardStats {
  securityScore: number;
  scoreChange: number;
  alertsToday: number;
  alertsChange: number;
  threatsBlocked: number;
  threatsChange: number;
  incidentsResolved: number;
  incidentsChange: number;
  dailyStreak: number;
  achievements: Achievement[];
  dailyInsight: DailyInsight;
  teamRank: number;
  teamSize: number;
}

interface Achievement {
  id: string;
  title: string;
  description: string;
  icon: string;
  progress: number;
  maxProgress: number;
  unlocked: boolean;
  unlockedAt?: string;
  rarity: "common" | "rare" | "epic" | "legendary";
}

interface DailyInsight {
  type: "positive" | "warning" | "neutral";
  title: string;
  description: string;
  action?: {
    label: string;
    url: string;
  };
}

const GREETING_MESSAGES = [
  "Good morning",
  "Welcome back",
  "Great to see you",
  "Ready to secure",
  "Let's make today secure",
];

const RARITY_COLORS = {
  common: "from-slate-400 to-slate-600",
  rare: "from-blue-400 to-blue-600",
  epic: "from-purple-400 to-purple-600",
  legendary: "from-amber-400 to-amber-600",
};

const RARITY_BG = {
  common: "bg-slate-500/10",
  rare: "bg-blue-500/10",
  epic: "bg-purple-500/10",
  legendary: "bg-amber-500/10",
};

export default function StunningDashboard() {
  usePageTitle("Dashboard");
  const [userName] = useState("Security Hero"); // TODO: Get from user context
  const [greeting, setGreeting] = useState("");
  const [celebrationShown, setCelebrationShown] = useState(false);

  // Get greeting based on time
  useEffect(() => {
    const hour = new Date().getHours();
    if (hour < 12) setGreeting("Good morning");
    else if (hour < 18) setGreeting("Good afternoon");
    else setGreeting("Good evening");
  }, []);

  // Fetch dashboard data
  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/dashboard/stunning-stats"],
  });

  // Show celebration on achievement unlock
  useEffect(() => {
    if (!celebrationShown && stats?.achievements.some(a => a.unlocked && !a.unlockedAt)) {
      confetti({
        particleCount: 100,
        spread: 70,
        origin: { y: 0.6 }
      });
      setCelebrationShown(true);
    }
  }, [stats, celebrationShown]);

  const securityScoreColor = useMemo(() => {
    if (!stats) return "text-slate-400";
    if (stats.securityScore >= 90) return "text-emerald-500";
    if (stats.securityScore >= 70) return "text-blue-500";
    if (stats.securityScore >= 50) return "text-yellow-500";
    return "text-red-500";
  }, [stats?.securityScore]);

  const securityScoreGradient = useMemo(() => {
    if (!stats) return "from-slate-400 to-slate-600";
    if (stats.securityScore >= 90) return "from-emerald-400 to-emerald-600";
    if (stats.securityScore >= 70) return "from-blue-400 to-blue-600";
    if (stats.securityScore >= 50) return "from-yellow-400 to-yellow-600";
    return "from-red-400 to-red-600";
  }, [stats?.securityScore]);

  if (isLoading) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6">
      {/* Hero Section with Greeting */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-2"
      >
        <h1 className="text-4xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
          {greeting}, {userName}! 🎯
        </h1>
        <p className="text-slate-400 text-lg">
          {stats?.dailyInsight.title || "Your security posture is looking strong"}
        </p>
      </motion.div>

      {/* Security Score Hero Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="border-0 bg-gradient-to-br from-slate-900 to-slate-800 shadow-2xl overflow-hidden relative">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 via-purple-500/10 to-pink-500/10" />
          <CardContent className="pt-8 pb-8 relative">
            <div className="grid md:grid-cols-3 gap-8 items-center">
              {/* Security Score Circle */}
              <div className="flex justify-center">
                <div className="relative">
                  <svg className="w-48 h-48 -rotate-90">
                    {/* Background circle */}
                    <circle
                      cx="96"
                      cy="96"
                      r="88"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="12"
                      className="text-slate-800"
                    />
                    {/* Progress circle */}
                    <motion.circle
                      cx="96"
                      cy="96"
                      r="88"
                      fill="none"
                      stroke="url(#gradient)"
                      strokeWidth="12"
                      strokeLinecap="round"
                      strokeDasharray={`${2 * Math.PI * 88}`}
                      initial={{ strokeDashoffset: 2 * Math.PI * 88 }}
                      animate={{
                        strokeDashoffset: 2 * Math.PI * 88 * (1 - (stats?.securityScore || 0) / 100)
                      }}
                      transition={{ duration: 1.5, ease: "easeOut" }}
                    />
                    <defs>
                      <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#3b82f6" />
                        <stop offset="50%" stopColor="#8b5cf6" />
                        <stop offset="100%" stopColor="#ec4899" />
                      </linearGradient>
                    </defs>
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ delay: 0.5, type: "spring" }}
                      className={cn("text-6xl font-bold", securityScoreColor)}
                    >
                      {stats?.securityScore || 0}
                    </motion.div>
                    <div className="text-slate-400 text-sm font-medium">Security Score</div>
                  </div>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="md:col-span-2 grid grid-cols-2 gap-4">
                <StatCard
                  icon={<Shield className="w-5 h-5" />}
                  label="Threats Blocked"
                  value={stats?.threatsBlocked || 0}
                  change={stats?.threatsChange || 0}
                  trend={stats && stats.threatsChange > 0 ? "up" : "down"}
                  color="emerald"
                />
                <StatCard
                  icon={<AlertTriangle className="w-5 h-5" />}
                  label="Active Alerts"
                  value={stats?.alertsToday || 0}
                  change={stats?.alertsChange || 0}
                  trend={stats && stats.alertsChange < 0 ? "down" : "up"}
                  color="amber"
                />
                <StatCard
                  icon={<CheckCircle2 className="w-5 h-5" />}
                  label="Incidents Resolved"
                  value={stats?.incidentsResolved || 0}
                  change={stats?.incidentsChange || 0}
                  trend={stats && stats.incidentsChange > 0 ? "up" : "down"}
                  color="blue"
                />
                <StatCard
                  icon={<Flame className="w-5 h-5" />}
                  label="Daily Streak"
                  value={`${stats?.dailyStreak || 0}d`}
                  change={1}
                  trend="up"
                  color="orange"
                  showFire
                />
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <div className="grid md:grid-cols-3 gap-6">
        {/* Daily Insight */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="md:col-span-2"
        >
          <Card className="border-0 bg-gradient-to-br from-slate-900 to-slate-800 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-yellow-400" />
                <span className="bg-gradient-to-r from-yellow-400 to-orange-400 bg-clip-text text-transparent">
                  Daily Security Insight
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <p className="text-slate-300 text-lg">
                  {stats?.dailyInsight.description || "Everything is looking secure today!"}
                </p>
                {stats?.dailyInsight.action && (
                  <button className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white rounded-lg font-medium transition-all transform hover:scale-105">
                    {stats.dailyInsight.action.label}
                  </button>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Team Leaderboard */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="border-0 bg-gradient-to-br from-slate-900 to-slate-800 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Trophy className="w-5 h-5 text-amber-400" />
                <span>Team Rank</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-center h-32">
                <div className="text-center">
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ delay: 0.5, type: "spring" }}
                    className="text-6xl font-bold bg-gradient-to-r from-amber-400 to-orange-400 bg-clip-text text-transparent"
                  >
                    #{stats?.teamRank || 1}
                  </motion.div>
                  <div className="text-slate-400 text-sm mt-2">
                    out of {stats?.teamSize || 1} analysts
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Achievements Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
          <Award className="w-6 h-6 text-purple-400" />
          Recent Achievements
        </h2>
        <div className="grid md:grid-cols-4 gap-4">
          {stats?.achievements.slice(0, 4).map((achievement, i) => (
            <motion.div
              key={achievement.id}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.5 + i * 0.1 }}
            >
              <AchievementCard achievement={achievement} />
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}

// Stat Card Component
function StatCard({
  icon,
  label,
  value,
  change,
  trend,
  color,
  showFire
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  change: number;
  trend: "up" | "down";
  color: "emerald" | "amber" | "blue" | "orange";
  showFire?: boolean;
}) {
  const colorClasses = {
    emerald: "from-emerald-500/20 to-emerald-600/20 text-emerald-400",
    amber: "from-amber-500/20 to-amber-600/20 text-amber-400",
    blue: "from-blue-500/20 to-blue-600/20 text-blue-400",
    orange: "from-orange-500/20 to-orange-600/20 text-orange-400",
  };

  return (
    <div className={cn("relative p-4 rounded-xl bg-gradient-to-br", colorClasses[color])}>
      <div className="flex items-start justify-between mb-2">
        <div className="p-2 rounded-lg bg-white/10 backdrop-blur-sm">
          {icon}
        </div>
        {showFire && (
          <Flame className="w-5 h-5 text-orange-400 animate-pulse" />
        )}
      </div>
      <div className="mt-2">
        <div className="text-2xl font-bold text-white">{value}</div>
        <div className="text-xs text-slate-300 mt-1">{label}</div>
        <div className="flex items-center gap-1 mt-2">
          {trend === "up" ? (
            <ArrowUpRight className="w-4 h-4" />
          ) : (
            <ArrowDownRight className="w-4 h-4" />
          )}
          <span className="text-sm font-medium">
            {Math.abs(change)}%
          </span>
        </div>
      </div>
    </div>
  );
}

// Achievement Card Component
function AchievementCard({ achievement }: { achievement: Achievement }) {
  const isUnlocked = achievement.unlocked;
  const progressPercentage = (achievement.progress / achievement.maxProgress) * 100;

  return (
    <Card className={cn(
      "border-0 h-full transition-all cursor-pointer hover:scale-105",
      isUnlocked ? RARITY_BG[achievement.rarity] : "bg-slate-900/50 grayscale"
    )}>
      <CardContent className="p-6">
        <div className="flex flex-col items-center text-center space-y-3">
          {/* Icon */}
          <div className={cn(
            "text-6xl relative",
            isUnlocked ? "" : "opacity-30"
          )}>
            {achievement.icon}
            {isUnlocked && (
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring" }}
                className="absolute -top-1 -right-1"
              >
                <CheckCircle2 className="w-6 h-6 text-emerald-400 bg-slate-900 rounded-full" />
              </motion.div>
            )}
          </div>

          {/* Title */}
          <div>
            <h3 className={cn(
              "font-bold text-sm",
              isUnlocked ? "text-white" : "text-slate-500"
            )}>
              {achievement.title}
            </h3>
            <Badge className={cn("mt-1 text-xs", isUnlocked ? "bg-gradient-to-r " + RARITY_COLORS[achievement.rarity] : "")}>
              {achievement.rarity}
            </Badge>
          </div>

          {/* Progress */}
          {!isUnlocked && (
            <div className="w-full space-y-1">
              <Progress value={progressPercentage} className="h-2" />
              <div className="text-xs text-slate-500">
                {achievement.progress}/{achievement.maxProgress}
              </div>
            </div>
          )}

          {/* Description */}
          <p className={cn(
            "text-xs",
            isUnlocked ? "text-slate-400" : "text-slate-600"
          )}>
            {achievement.description}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

// Loading Skeleton
function DashboardSkeleton() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6 animate-pulse">
      <div className="h-20 bg-slate-800 rounded-lg" />
      <div className="h-64 bg-slate-800 rounded-lg" />
      <div className="grid md:grid-cols-3 gap-6">
        <div className="md:col-span-2 h-48 bg-slate-800 rounded-lg" />
        <div className="h-48 bg-slate-800 rounded-lg" />
      </div>
      <div className="grid md:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="h-48 bg-slate-800 rounded-lg" />
        ))}
      </div>
    </div>
  );
}
