import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  BarChart3,
  Zap,
  Brain,
  Plug,
  Activity,
  AlertTriangle,
  Shield,
  Users,
  Database,
  Clock,
  ArrowUpRight,
  TrendingUp,
  TrendingDown,
  Minus,
  Crown,
  Sparkles,
  Loader2,
  Check,
  X,
  Gauge,
  CalendarDays,
  DollarSign,
  Rocket,
  HardDrive,
  Info,
  Lock,
  Unlock,
  Gift,
  Star,
  Timer,
  ArrowRight,
  CheckCircle2,
  Table2,
} from "lucide-react";

interface PlanLimits {
  users: number;
  dataSources: number;
  retentionDays: number;
  automationRunsPerMonth: number;
  aiTokensPerMonth: number;
  apiCallsPerMonth: number;
  storageGb: number;
  eventsPerMonth: number;
  burstAllowancePct: number;
}

interface PlanTier {
  id: string;
  name: string;
  displayName: string;
  description: string;
  monthlyPriceCents: number;
  annualPriceCents: number;
  limits: PlanLimits;
  features: string[];
  recommended?: boolean;
  badge?: string;
}

interface UsageSnapshot {
  metric: string;
  label: string;
  current: number;
  limit: number;
  unit: string;
  pctUsed: number;
  softThreshold: number;
  hardThreshold: number;
  status: "ok" | "warning" | "critical";
}

interface CurrentPlanData {
  plan: PlanTier;
  billingCycle: "monthly" | "annual";
  billingCycleStart: string;
  billingCycleEnd: string;
  metrics: UsageSnapshot[];
  quotaAlerts: UsageSnapshot[];
}

interface UsageForecast {
  metric: string;
  label: string;
  currentUsage: number;
  limit: number;
  dailyRate: number;
  projectedHitDate: string | null;
  daysUntilLimit: number | null;
  trend: "increasing" | "stable" | "decreasing";
  confidence: number;
}

interface RecommendationReason {
  metric: string;
  label: string;
  currentUsage: number;
  currentLimit: number;
  upgradedLimit: number;
  pctUsed: number;
  severity: "info" | "warning" | "critical";
}

interface UpgradeRecommendation {
  currentTier: string;
  recommendedTier: string;
  reasons: RecommendationReason[];
  estimatedMonthlySavings: number;
  roiProjection: {
    currentCostCents: number;
    projectedCostCents: number;
    additionalCapacity: string[];
    paybackPeriodDays: number;
  };
}

interface BurstEntry {
  metric: string;
  activatedAt: string;
  expiresAt: string;
  extraCapacityPct: number;
}

interface BurstStatus {
  enabled: boolean;
  burstAllowancePct: number;
  activeBursts: BurstEntry[];
  remainingBurstBudget: number;
}

function statusColor(status: string) {
  if (status === "critical") return "text-red-500";
  if (status === "warning") return "text-yellow-500";
  return "text-green-500";
}

function statusBg(status: string) {
  if (status === "critical") return "bg-red-500/10 border-red-500/30";
  if (status === "warning") return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-emerald-500/10 border-emerald-500/30";
}

function progressColor(pct: number) {
  if (pct >= 95) return "bg-red-500";
  if (pct >= 80) return "bg-yellow-500";
  return "bg-emerald-500";
}

function metricIcon(metric: string) {
  switch (metric) {
    case "users":
      return <Users className="h-5 w-5" />;
    case "dataSources":
      return <Plug className="h-5 w-5" />;
    case "eventsPerMonth":
      return <Activity className="h-5 w-5" />;
    case "automationRunsPerMonth":
      return <Zap className="h-5 w-5" />;
    case "aiTokensPerMonth":
      return <Brain className="h-5 w-5" />;
    case "apiCallsPerMonth":
      return <BarChart3 className="h-5 w-5" />;
    case "storageGb":
      return <HardDrive className="h-5 w-5" />;
    case "retentionDays":
      return <Clock className="h-5 w-5" />;
    default:
      return <Database className="h-5 w-5" />;
  }
}

function trendIcon(trend: string) {
  if (trend === "increasing") return <TrendingUp className="h-4 w-4 text-red-400" />;
  if (trend === "decreasing") return <TrendingDown className="h-4 w-4 text-green-400" />;
  return <Minus className="h-4 w-4 text-muted-foreground" />;
}

function formatNumber(n: number): string {
  if (n === -1) return "Unlimited";
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatCents(cents: number, annual?: boolean): string {
  if (cents === 0) return "Free";
  const dollars = cents / 100;
  return `$${dollars.toLocaleString()}${annual ? "/yr" : "/mo"}`;
}

function tierBadge(tier: string) {
  const styles: Record<string, string> = {
    free: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    starter: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    professional: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    enterprise: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  };
  return styles[tier] || styles.free;
}

function tierGradient(tier: string) {
  const gradients: Record<string, string> = {
    free: "from-zinc-500/20 to-zinc-600/5",
    starter: "from-blue-500/20 to-blue-600/5",
    professional: "from-purple-500/20 to-purple-600/5",
    enterprise: "from-amber-500/20 to-amber-600/5",
  };
  return gradients[tier] || gradients.free;
}

function PlanBrowserTab() {
  const [isAnnual, setIsAnnual] = useState(false);

  const { data: plans, isLoading } = useQuery<PlanTier[]>({
    queryKey: ["/api/tiered-packaging/plans"],
  });

  const { data: currentPlan } = useQuery<CurrentPlanData>({
    queryKey: ["/api/tiered-packaging/current-plan"],
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-96 rounded-lg" />
        ))}
      </div>
    );
  }

  if (!plans || plans.length === 0) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Shield className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground">No plans available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold">Choose Your Plan</h3>
          <p className="text-sm text-muted-foreground">
            Transparent limits. No hidden fees. Upgrade or downgrade anytime.
          </p>
          {/* 92.1 — plan comparison hint */}
          <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-1">
            <Table2 className="h-2.5 w-2.5" />
            Scroll down for detailed feature comparison across all tiers
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-sm ${!isAnnual ? "font-semibold text-foreground" : "text-muted-foreground"}`}>
            Monthly
          </span>
          <Switch checked={isAnnual} onCheckedChange={setIsAnnual} aria-label="Toggle annual billing" />
          <span className={`text-sm ${isAnnual ? "font-semibold text-foreground" : "text-muted-foreground"}`}>
            Annual
          </span>
          {isAnnual && (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/20 text-xs">
              Save ~20%
            </Badge>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {plans.map((plan) => {
          const isCurrent = currentPlan?.plan.id === plan.id;
          const price = isAnnual ? plan.annualPriceCents : plan.monthlyPriceCents;
          const isEnterprise = plan.id === "enterprise";

          return (
            <Card
              key={plan.id}
              className={`glass relative overflow-hidden transition-all hover:border-primary/30 ${
                plan.recommended ? "border-primary/50 ring-1 ring-primary/20" : ""
              } ${isCurrent ? "border-emerald-500/50" : ""}`}
            >
              {plan.recommended && (
                <div className="absolute top-0 right-0 px-3 py-1 bg-primary text-primary-foreground text-xs font-medium rounded-bl-lg">
                  {plan.badge}
                </div>
              )}
              {isEnterprise && !plan.recommended && (
                <div className="absolute top-0 right-0 px-3 py-1 bg-amber-500 text-black text-xs font-medium rounded-bl-lg">
                  {plan.badge}
                </div>
              )}
              <div className={`absolute inset-0 bg-gradient-to-b ${tierGradient(plan.id)} pointer-events-none`} />
              <CardHeader className="relative">
                <div className="flex items-center gap-2 mb-1">
                  <CardTitle className="text-lg">{plan.displayName}</CardTitle>
                  {isCurrent && (
                    <Badge
                      variant="outline"
                      className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20 text-xs"
                    >
                      Current
                    </Badge>
                  )}
                </div>
                <CardDescription className="text-xs leading-relaxed">{plan.description}</CardDescription>
                <div className="mt-3">
                  {isEnterprise ? (
                    <p className="text-2xl font-bold">Custom</p>
                  ) : (
                    <div>
                      <p className="text-2xl font-bold">{formatCents(price, isAnnual)}</p>
                      {isAnnual && plan.monthlyPriceCents > 0 && (
                        <p className="text-xs text-muted-foreground line-through">
                          {formatCents(plan.monthlyPriceCents * 12, true)}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent className="relative space-y-4">
                <div className="space-y-2 text-sm">
                  <p className="font-medium text-xs uppercase tracking-wider text-muted-foreground">Limits</p>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                    <div className="flex items-center gap-1.5">
                      <Users className="h-3 w-3 text-muted-foreground" />
                      <span>{formatNumber(plan.limits.users)} users</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Plug className="h-3 w-3 text-muted-foreground" />
                      <span>{formatNumber(plan.limits.dataSources)} sources</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Clock className="h-3 w-3 text-muted-foreground" />
                      <span>{plan.limits.retentionDays}d retention</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Activity className="h-3 w-3 text-muted-foreground" />
                      <span>{formatNumber(plan.limits.eventsPerMonth)} events</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Brain className="h-3 w-3 text-muted-foreground" />
                      <span>{formatNumber(plan.limits.aiTokensPerMonth)} AI</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Zap className="h-3 w-3 text-muted-foreground" />
                      <span>{formatNumber(plan.limits.automationRunsPerMonth)} runs</span>
                    </div>
                  </div>
                </div>

                <div className="border-t border-border/50 pt-3 space-y-1.5">
                  <p className="font-medium text-xs uppercase tracking-wider text-muted-foreground">Features</p>
                  {plan.features.map((f) => (
                    <div key={f} className="flex items-start gap-2 text-xs">
                      <Check className="h-3 w-3 text-emerald-500 mt-0.5 shrink-0" />
                      <span>{f}</span>
                    </div>
                  ))}
                </div>

                <div className="pt-2">
                  {isEnterprise ? (
                    <Button variant="outline" className="w-full" size="sm">
                      Contact Sales
                    </Button>
                  ) : isCurrent ? (
                    <Button variant="outline" className="w-full" size="sm" disabled>
                      Current Plan
                    </Button>
                  ) : (
                    <Button className="w-full" size="sm">
                      {price === 0 ? "Get Started" : "Upgrade"}
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card className="glass border-dashed">
        <CardContent className="py-4">
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Info className="h-4 w-4 shrink-0" />
            <span>
              All plans include SSL encryption, SOC 2 compliance, and 99.9% uptime SLA. Enterprise plans come with
              custom SLAs and dedicated infrastructure.
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function UsageMetersTab() {
  const {
    data: currentPlan,
    isLoading,
    isError,
    refetch,
  } = useQuery<CurrentPlanData>({
    queryKey: ["/api/tiered-packaging/current-plan"],
    refetchInterval: 60000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-32 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load usage data</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
          Try Again
        </Button>
      </div>
    );
  }

  if (!currentPlan) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Activity className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground">No usage data available yet</p>
        </CardContent>
      </Card>
    );
  }

  const cycleStart = new Date(currentPlan.billingCycleStart).toLocaleDateString();
  const cycleEnd = new Date(currentPlan.billingCycleEnd).toLocaleDateString();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold">Current Usage</h3>
            <Badge variant="outline" className={tierBadge(currentPlan.plan.id)}>
              {currentPlan.plan.displayName}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            <CalendarDays className="h-3.5 w-3.5 inline mr-1" />
            {cycleStart} — {cycleEnd}
          </p>
        </div>
        {currentPlan.quotaAlerts.length > 0 && (
          <Badge variant="outline" className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 gap-1">
            <AlertTriangle className="h-3 w-3" />
            {currentPlan.quotaAlerts.length} alert{currentPlan.quotaAlerts.length > 1 ? "s" : ""}
          </Badge>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {currentPlan.metrics.map((m) => (
          <Card key={m.metric} className={`glass border ${statusBg(m.status)}`}>
            <CardContent className="pt-5 pb-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-lg ${statusBg(m.status)}`}>{metricIcon(m.metric)}</div>
                  <div>
                    <p className="font-medium text-sm">{m.label}</p>
                    <p className="text-xs text-muted-foreground">{m.unit}</p>
                  </div>
                </div>
                <Badge variant="outline" className={`text-xs ${statusBg(m.status)} ${statusColor(m.status)}`}>
                  {m.status === "critical" ? "Over limit" : m.status === "warning" ? "Approaching" : "OK"}
                </Badge>
              </div>
              <div className="space-y-2">
                <div className="flex items-end justify-between">
                  <span className="text-2xl font-bold">{formatNumber(m.current)}</span>
                  <span className="text-sm text-muted-foreground">/ {formatNumber(m.limit)}</span>
                </div>
                {m.limit !== -1 && (
                  <>
                    <div className="relative h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`absolute inset-y-0 left-0 rounded-full transition-all ${progressColor(m.pctUsed)}`}
                        style={{ width: `${Math.min(m.pctUsed, 100)}%` }}
                      />
                      <div
                        className="absolute inset-y-0 w-px bg-yellow-500/50"
                        style={{ left: `${m.softThreshold}%` }}
                      />
                      <div className="absolute inset-y-0 w-px bg-red-500/50" style={{ left: `${m.hardThreshold}%` }} />
                    </div>
                    <p className="text-xs text-muted-foreground text-right">{m.pctUsed}% used</p>
                  </>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {currentPlan.quotaAlerts.length > 0 && (
        <Card className="glass border border-yellow-500/30 bg-yellow-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-yellow-400">
              <AlertTriangle className="h-4 w-4" />
              Quota Alerts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {currentPlan.quotaAlerts.map((a) => (
                <li key={a.metric} className="flex items-center justify-between text-sm">
                  <span>
                    {a.label}: {formatNumber(a.current)} / {formatNumber(a.limit)}
                  </span>
                  <span className={`font-medium ${statusColor(a.status)}`}>{a.pctUsed}%</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function ForecastTab() {
  const { data: forecasts, isLoading } = useQuery<UsageForecast[]>({
    queryKey: ["/api/tiered-packaging/usage-forecast"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-24 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (!forecasts || forecasts.length === 0) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <TrendingUp className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground">Not enough data to generate forecasts</p>
          <p className="text-xs text-muted-foreground mt-1">Forecasts improve as usage data accumulates</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">Usage Forecast</h3>
        <p className="text-sm text-muted-foreground">Projected usage based on current consumption patterns</p>
      </div>

      <div className="space-y-3">
        {forecasts.map((f) => (
          <Card key={f.metric} className="glass">
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10">{metricIcon(f.metric)}</div>
                  <div>
                    <p className="font-medium text-sm">{f.label}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatNumber(f.currentUsage)} / {formatNumber(f.limit)} used
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-right">
                  <div className="flex items-center gap-1.5">
                    {trendIcon(f.trend)}
                    <span className="text-xs text-muted-foreground capitalize">{f.trend}</span>
                  </div>
                  <div>
                    <p className="text-sm font-medium">
                      {f.dailyRate > 0 ? `~${formatNumber(Math.round(f.dailyRate))}/day` : "No activity"}
                    </p>
                    <p className="text-xs text-muted-foreground">{f.confidence}% confidence</p>
                  </div>
                  <div>
                    {f.daysUntilLimit !== null ? (
                      <div>
                        <p
                          className={`text-sm font-medium ${f.daysUntilLimit <= 7 ? "text-red-500" : f.daysUntilLimit <= 14 ? "text-yellow-500" : "text-green-500"}`}
                        >
                          {f.daysUntilLimit}d remaining
                        </p>
                        <p className="text-xs text-muted-foreground">
                          ~{new Date(f.projectedHitDate!).toLocaleDateString()}
                        </p>
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">Within budget</p>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function UpgradeRecommendationsTab() {
  const { data: recommendation, isLoading } = useQuery<UpgradeRecommendation | null>({
    queryKey: ["/api/tiered-packaging/upgrade-recommendation"],
  });

  if (isLoading) {
    return <Skeleton className="h-64 w-full rounded-lg" />;
  }

  if (!recommendation) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Sparkles className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground font-medium">You're all set!</p>
          <p className="text-xs text-muted-foreground mt-1">
            Your current plan comfortably covers your usage. No upgrade needed.
          </p>
        </CardContent>
      </Card>
    );
  }

  const currentTierDisplay = recommendation.currentTier.charAt(0).toUpperCase() + recommendation.currentTier.slice(1);
  const recommendedTierDisplay =
    recommendation.recommendedTier.charAt(0).toUpperCase() + recommendation.recommendedTier.slice(1);

  return (
    <div className="space-y-6">
      <Card className="glass border-primary/30 bg-primary/5">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-full bg-primary/10">
              <Rocket className="h-6 w-6 text-primary" />
            </div>
            <div>
              <CardTitle className="text-lg">Upgrade to {recommendedTierDisplay}</CardTitle>
              <CardDescription>
                Based on your usage patterns, upgrading from {currentTierDisplay} would give you more headroom
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="glass">
              <CardContent className="py-4 text-center">
                <DollarSign className="h-5 w-5 mx-auto mb-2 text-muted-foreground" />
                <p className="text-xs text-muted-foreground">Current Cost</p>
                <p className="text-lg font-bold">{formatCents(recommendation.roiProjection.currentCostCents)}</p>
              </CardContent>
            </Card>
            <Card className="glass">
              <CardContent className="py-4 text-center">
                <ArrowUpRight className="h-5 w-5 mx-auto mb-2 text-primary" />
                <p className="text-xs text-muted-foreground">Upgraded Cost</p>
                <p className="text-lg font-bold">{formatCents(recommendation.roiProjection.projectedCostCents)}</p>
              </CardContent>
            </Card>
            <Card className="glass">
              <CardContent className="py-4 text-center">
                <CalendarDays className="h-5 w-5 mx-auto mb-2 text-green-500" />
                <p className="text-xs text-muted-foreground">ROI Payback</p>
                <p className="text-lg font-bold">{recommendation.roiProjection.paybackPeriodDays} days</p>
              </CardContent>
            </Card>
          </div>

          <div>
            <p className="text-sm font-medium mb-3">Why upgrade?</p>
            <div className="space-y-2">
              {recommendation.reasons.map((r) => (
                <div
                  key={r.metric}
                  className={`flex items-center justify-between p-3 rounded-lg border ${
                    r.severity === "critical"
                      ? "bg-red-500/5 border-red-500/20"
                      : r.severity === "warning"
                        ? "bg-yellow-500/5 border-yellow-500/20"
                        : "bg-blue-500/5 border-blue-500/20"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {metricIcon(r.metric)}
                    <div>
                      <p className="text-sm font-medium">{r.label}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatNumber(r.currentUsage)} / {formatNumber(r.currentLimit)} ({r.pctUsed}% used)
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <Badge
                      variant="outline"
                      className={
                        r.severity === "critical"
                          ? "bg-red-500/10 text-red-400 border-red-500/20"
                          : r.severity === "warning"
                            ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                            : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                      }
                    >
                      {r.severity}
                    </Badge>
                    <p className="text-xs text-muted-foreground mt-1">New limit: {formatNumber(r.upgradedLimit)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {recommendation.roiProjection.additionalCapacity.length > 0 && (
            <div>
              <p className="text-sm font-medium mb-2">Additional Capacity</p>
              <div className="flex flex-wrap gap-2">
                {recommendation.roiProjection.additionalCapacity.map((cap) => (
                  <Badge key={cap} variant="outline" className="bg-primary/5 text-xs">
                    {cap}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <Button className="w-full gap-2">
            <Crown className="h-4 w-4" />
            Upgrade to {recommendedTierDisplay}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function BurstControlsTab() {
  const { toast } = useToast();
  const { data: burstStatus, isLoading } = useQuery<BurstStatus>({
    queryKey: ["/api/tiered-packaging/burst-status"],
  });

  const burstMutation = useMutation({
    mutationFn: async (params: { metric: string; extraCapacityPct: number; durationHours: number }) => {
      const res = await apiRequest("POST", "/api/tiered-packaging/burst-activate", params);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Burst capacity activated" });
      queryClient.invalidateQueries({ queryKey: ["/api/tiered-packaging/burst-status"] });
    },
    onError: () => {
      toast({ title: "Failed to activate burst", variant: "destructive" });
    },
  });

  if (isLoading) {
    return <Skeleton className="h-48 w-full rounded-lg" />;
  }

  if (!burstStatus) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Gauge className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground">Burst capacity data unavailable</p>
        </CardContent>
      </Card>
    );
  }

  if (!burstStatus.enabled) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Gauge className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground font-medium">Burst Capacity Not Available</p>
          <p className="text-xs text-muted-foreground mt-1">
            Upgrade to Starter or higher to unlock temporary burst capacity
          </p>
          <Button variant="outline" size="sm" className="mt-4 gap-1">
            <ArrowUpRight className="h-3 w-3" />
            View Plans
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">Burst Capacity Controls</h3>
        <p className="text-sm text-muted-foreground">Temporarily increase limits when you need extra headroom</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="glass">
          <CardContent className="py-4 text-center">
            <Gauge className="h-5 w-5 mx-auto mb-2 text-primary" />
            <p className="text-xs text-muted-foreground">Total Burst Budget</p>
            <p className="text-lg font-bold">{burstStatus.burstAllowancePct}%</p>
          </CardContent>
        </Card>
        <Card className="glass">
          <CardContent className="py-4 text-center">
            <Activity className="h-5 w-5 mx-auto mb-2 text-green-500" />
            <p className="text-xs text-muted-foreground">Remaining Budget</p>
            <p className="text-lg font-bold">{burstStatus.remainingBurstBudget}%</p>
          </CardContent>
        </Card>
        <Card className="glass">
          <CardContent className="py-4 text-center">
            <Zap className="h-5 w-5 mx-auto mb-2 text-yellow-500" />
            <p className="text-xs text-muted-foreground">Active Bursts</p>
            <p className="text-lg font-bold">{burstStatus.activeBursts.length}</p>
          </CardContent>
        </Card>
      </div>

      {burstStatus.activeBursts.length > 0 && (
        <Card className="glass">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Active Burst Sessions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {burstStatus.activeBursts.map((b, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 rounded-lg border border-border/50 bg-primary/5"
                >
                  <div className="flex items-center gap-2">
                    {metricIcon(b.metric)}
                    <div>
                      <p className="text-sm font-medium">{b.metric}</p>
                      <p className="text-xs text-muted-foreground">+{b.extraCapacityPct}% capacity</p>
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    <p>Expires: {new Date(b.expiresAt).toLocaleString()}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {burstStatus.remainingBurstBudget > 0 && (
        <Card className="glass">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Quick Burst Activation</CardTitle>
            <CardDescription className="text-xs">
              Activate temporary capacity increase for a specific metric
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {["eventsPerMonth", "aiTokensPerMonth", "automationRunsPerMonth", "apiCallsPerMonth"].map((metric) => (
                <Button
                  key={metric}
                  variant="outline"
                  size="sm"
                  className="justify-start gap-2"
                  disabled={burstMutation.isPending}
                  onClick={() =>
                    burstMutation.mutate({
                      metric,
                      extraCapacityPct: Math.min(10, burstStatus.remainingBurstBudget),
                      durationHours: 24,
                    })
                  }
                >
                  {burstMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : metricIcon(metric)}
                  <span className="text-xs">
                    +{Math.min(10, burstStatus.remainingBurstBudget)}% {metric.replace(/PerMonth|perMonth/g, "")} (24h)
                  </span>
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function TieredPackagingPage() {
  return (
    <div className="flex-1 p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Plans & Packaging</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Transparent limits, real-time usage tracking, and intelligent upgrade recommendations
        </p>
      </div>

      <Tabs defaultValue="plans" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5 max-w-2xl">
          <TabsTrigger value="plans" className="gap-1.5 text-xs">
            <Shield className="h-3.5 w-3.5" />
            Plans
          </TabsTrigger>
          <TabsTrigger value="usage" className="gap-1.5 text-xs">
            <BarChart3 className="h-3.5 w-3.5" />
            Usage
          </TabsTrigger>
          <TabsTrigger value="forecast" className="gap-1.5 text-xs">
            <TrendingUp className="h-3.5 w-3.5" />
            Forecast
          </TabsTrigger>
          <TabsTrigger value="recommendations" className="gap-1.5 text-xs">
            <Sparkles className="h-3.5 w-3.5" />
            Upgrade
          </TabsTrigger>
          <TabsTrigger value="burst" className="gap-1.5 text-xs">
            <Gauge className="h-3.5 w-3.5" />
            Burst
          </TabsTrigger>
        </TabsList>

        <TabsContent value="plans">
          <PlanBrowserTab />

          {/* 92.4 — feature gating explanation */}
          <Card className="mt-4 glass">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Lock className="h-4 w-4 text-muted-foreground" />
                Feature Gating
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-muted-foreground">
                <div className="flex items-start gap-2">
                  <Unlock className="h-3.5 w-3.5 text-emerald-500 mt-0.5 shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Soft Gates</p>
                    <p>Features available with usage warnings. Exceeding limits triggers upgrade prompts.</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <Lock className="h-3.5 w-3.5 text-yellow-500 mt-0.5 shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Hard Gates</p>
                    <p>Features locked until plan upgrade. New operations blocked at limit.</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <Star className="h-3.5 w-3.5 text-purple-500 mt-0.5 shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Enterprise Only</p>
                    <p>Custom SLAs, dedicated support, and unlimited resources.</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* 92.3 — enterprise contact card */}
          <Card className="mt-4 glass border-amber-500/20">
            <CardContent className="py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Crown className="h-5 w-5 text-amber-400" />
                <div>
                  <p className="text-sm font-medium">Need custom pricing for your enterprise?</p>
                  <p className="text-xs text-muted-foreground">
                    Dedicated account manager, custom SLAs, and volume discounts
                  </p>
                </div>
              </div>
              <Button variant="outline" size="sm" className="border-amber-500/30 text-amber-400">
                <ArrowRight className="h-3.5 w-3.5 mr-1" />
                Contact Sales
              </Button>
            </CardContent>
          </Card>

          {/* 92.5 — trial management info */}
          <Card className="mt-4 glass">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Timer className="h-4 w-4 text-muted-foreground" />
                Trial Management
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-muted-foreground space-y-1.5">
                <div className="flex items-center gap-2">
                  <Gift className="h-3 w-3 text-blue-400" />
                  <span>14-day free trial on all paid plans. No credit card required.</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                  <span>Full feature access during trial period with production-level limits.</span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="h-3 w-3 text-yellow-500" />
                  <span>Automatic downgrade to Free plan after trial expires. No surprise charges.</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="usage">
          <UsageMetersTab />
        </TabsContent>
        <TabsContent value="forecast">
          <ForecastTab />
        </TabsContent>
        <TabsContent value="recommendations">
          <UpgradeRecommendationsTab />
        </TabsContent>
        <TabsContent value="burst">
          <BurstControlsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
