import { useQuery } from "@tanstack/react-query";
import { useState, useEffect, useMemo } from "react";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Flame,
  Trophy,
  Sparkles,
  Award,
  ArrowUpRight,
  ArrowDownRight,
  Target,
  Crown,
  Siren,
  ShieldCheck,
  Swords,
  Gem,
  Star,
  Medal,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { Link } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import confetti from "canvas-confetti";

interface DashboardStats {
  securityScore: number;
  scoreChange: number | null;
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

const RARITY_COLORS: Record<string, string> = {
  common: "from-slate-400 to-slate-600",
  rare: "from-blue-400 to-blue-600",
  epic: "from-purple-400 to-purple-600",
  legendary: "from-amber-400 to-amber-600",
};

const RARITY_BG: Record<string, string> = {
  common: "bg-slate-500/10",
  rare: "bg-blue-500/10",
  epic: "bg-purple-500/10",
  legendary: "bg-amber-500/10",
};

const ICON_MAP: Record<string, React.ElementType> = {
  target: Target,
  medal: Medal,
  crown: Crown,
  siren: Siren,
  shield: Shield,
  "shield-check": ShieldCheck,
  swords: Swords,
  flame: Flame,
  gem: Gem,
  star: Star,
};

export default function StunningDashboard() {
  usePageTitle("Dashboard");
  const [greeting, setGreeting] = useState("");
  const [celebrationShown, setCelebrationShown] = useState(false);

  useEffect(() => {
    const hour = new Date().getHours();
    if (hour < 12) setGreeting("Good morning");
    else if (hour < 18) setGreeting("Good afternoon");
    else setGreeting("Good evening");
  }, []);

  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/dashboard/stunning-stats"],
  });

  useEffect(() => {
    if (!celebrationShown && stats?.achievements.some((a) => a.unlocked)) {
      confetti({
        particleCount: 100,
        spread: 70,
        origin: { y: 0.6 },
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

  if (isLoading) {
    return <DashboardSkeleton />;
  }

  return (
    <div data-testid="dashboard-stunning-page" className="min-h-screen p-6 space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="space-y-2">
        <h1 className="text-3xl font-bold bg-gradient-to-r from-foreground to-muted-foreground bg-clip-text text-transparent">
          {greeting}, Security Hero!
        </h1>
        <p className="text-muted-foreground text-lg">
          {stats?.dailyInsight.title || "Your security posture is looking strong"}
        </p>
      </motion.div>

      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.1 }}>
        <Card
          data-testid="dashboard-stunning-card-1"
          className="border-0 bg-gradient-to-br from-card to-card/80 shadow-2xl overflow-hidden relative"
        >
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5" />
          <CardContent className="pt-8 pb-8 relative">
            <div className="grid md:grid-cols-3 gap-8 items-center">
              <div className="flex justify-center">
                <div className="relative">
                  <svg className="w-48 h-48 -rotate-90" aria-hidden="true">
                    <circle
                      cx="96"
                      cy="96"
                      r="88"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="12"
                      className="text-muted/30"
                    />
                    <motion.circle
                      cx="96"
                      cy="96"
                      r="88"
                      fill="none"
                      stroke="url(#scoreGradient)"
                      strokeWidth="12"
                      strokeLinecap="round"
                      strokeDasharray={`${2 * Math.PI * 88}`}
                      initial={{ strokeDashoffset: 2 * Math.PI * 88 }}
                      animate={{
                        strokeDashoffset: 2 * Math.PI * 88 * (1 - (stats?.securityScore || 0) / 100),
                      }}
                      transition={{ duration: 1.5, ease: "easeOut" }}
                    />
                    <defs>
                      <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="100%">
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
                    <div className="text-muted-foreground text-sm font-medium">Security Score</div>
                  </div>
                </div>
              </div>

              <div className="md:col-span-2 grid grid-cols-2 gap-4">
                <GamifiedStatCard
                  icon={<Shield className="w-5 h-5" />}
                  label="Threats Blocked"
                  value={stats?.threatsBlocked || 0}
                  change={stats?.threatsChange || 0}
                  trend={stats && stats.threatsChange > 0 ? "up" : "down"}
                  color="emerald"
                />
                <GamifiedStatCard
                  icon={<AlertTriangle className="w-5 h-5" />}
                  label="Active Alerts"
                  value={stats?.alertsToday || 0}
                  change={stats?.alertsChange || 0}
                  trend={stats && stats.alertsChange < 0 ? "down" : "up"}
                  color="amber"
                />
                <GamifiedStatCard
                  icon={<CheckCircle2 className="w-5 h-5" />}
                  label="Incidents Resolved"
                  value={stats?.incidentsResolved || 0}
                  change={stats?.incidentsChange || 0}
                  trend={stats && stats.incidentsChange > 0 ? "up" : "down"}
                  color="blue"
                />
                <GamifiedStatCard
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
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="md:col-span-2"
        >
          <Card
            data-testid="dashboard-stunning-card-2"
            className="border-0 bg-gradient-to-br from-card to-card/80 h-full"
          >
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
                <p className="text-muted-foreground text-lg">
                  {stats?.dailyInsight.description || "Everything is looking secure today!"}
                </p>
                {stats?.dailyInsight.action && (
                  <Link href={stats.dailyInsight.action.url}>
                    <button className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white rounded-lg font-medium transition-all transform hover:scale-105">
                      {stats.dailyInsight.action.label}
                    </button>
                  </Link>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}>
          <Card
            data-testid="dashboard-stunning-card-3"
            className="border-0 bg-gradient-to-br from-card to-card/80 h-full"
          >
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
                  <div className="text-muted-foreground text-sm mt-2">out of {stats?.teamSize || 1} analysts</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
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

function GamifiedStatCard({
  icon,
  label,
  value,
  change,
  trend,
  color,
  showFire,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  change: number;
  trend: "up" | "down";
  color: "emerald" | "amber" | "blue" | "orange";
  showFire?: boolean;
}) {
  const colorClasses: Record<string, string> = {
    emerald: "from-emerald-500/20 to-emerald-600/20 text-emerald-400",
    amber: "from-amber-500/20 to-amber-600/20 text-amber-400",
    blue: "from-blue-500/20 to-blue-600/20 text-blue-400",
    orange: "from-orange-500/20 to-orange-600/20 text-orange-400",
  };

  return (
    <div className={cn("relative p-4 rounded-xl bg-gradient-to-br", colorClasses[color])}>
      <div className="flex items-start justify-between mb-2">
        <div className="p-2 rounded-lg bg-white/10 backdrop-blur-sm">{icon}</div>
        {showFire && <Flame className="w-5 h-5 text-orange-400 animate-pulse" />}
      </div>
      <div className="mt-2">
        <div className="text-2xl font-bold text-foreground">{value}</div>
        <div className="text-xs text-muted-foreground mt-1">{label}</div>
        <div className="flex items-center gap-1 mt-2">
          {trend === "up" ? <ArrowUpRight className="w-4 h-4" /> : <ArrowDownRight className="w-4 h-4" />}
          <span className="text-sm font-medium">{Math.abs(change)}%</span>
        </div>
      </div>
    </div>
  );
}

function AchievementCard({ achievement }: { achievement: Achievement }) {
  const isUnlocked = achievement.unlocked;
  const progressPercentage = (achievement.progress / achievement.maxProgress) * 100;
  const IconComponent = ICON_MAP[achievement.icon] || Star;

  return (
    <Card
      className={cn(
        "border-0 h-full transition-all cursor-pointer hover:scale-105",
        isUnlocked ? RARITY_BG[achievement.rarity] || "bg-slate-500/10" : "bg-card/50 grayscale",
      )}
    >
      <CardContent className="p-6">
        <div className="flex flex-col items-center text-center space-y-3">
          <div className={cn("relative", isUnlocked ? "" : "opacity-30")}>
            <IconComponent className="w-12 h-12" />
            {isUnlocked && (
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring" }}
                className="absolute -top-1 -right-1"
              >
                <CheckCircle2 className="w-5 h-5 text-emerald-400 bg-card rounded-full" />
              </motion.div>
            )}
          </div>

          <div>
            <h3 className={cn("font-bold text-sm", isUnlocked ? "text-foreground" : "text-muted-foreground")}>
              {achievement.title}
            </h3>
            <Badge
              className={cn(
                "mt-1 text-xs",
                isUnlocked ? "bg-gradient-to-r " + (RARITY_COLORS[achievement.rarity] || "") : "",
              )}
            >
              {achievement.rarity}
            </Badge>
          </div>

          {!isUnlocked && (
            <div className="w-full space-y-1">
              <Progress value={progressPercentage} className="h-2" />
              <div className="text-xs text-muted-foreground">
                {achievement.progress}/{achievement.maxProgress}
              </div>
            </div>
          )}

          <p className={cn("text-xs", isUnlocked ? "text-muted-foreground" : "text-muted-foreground/50")}>
            {achievement.description}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function DashboardSkeleton() {
  return (
    <div className="min-h-screen p-6 space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-10 w-80" />
        <Skeleton className="h-6 w-64" />
      </div>
      <Skeleton className="h-64 w-full rounded-lg" />
      <div className="grid md:grid-cols-3 gap-6">
        <Skeleton className="md:col-span-2 h-48 rounded-lg" />
        <Skeleton className="h-48 rounded-lg" />
      </div>
      <div className="grid md:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-48 rounded-lg" />
        ))}
      </div>
    </div>
  );
}
