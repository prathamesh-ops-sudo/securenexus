import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  DollarSign,
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  Settings2,
  BarChart3,
  Loader2,
  Zap,
  Clock,
  Shield,
  TrendingDown,
  PieChart,
  ShieldAlert,
  ArrowRightLeft,
  Target,
  Info,
  ArrowUpRight,
  ChevronRight,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface BudgetUsage {
  totalSpent: number;
  monthlyLimit: number;
  dailySpend: number;
  requestCount: number;
  tokenCount: number;
  modelBreakdown: { model: string; cost: number; requests: number; tokens: number }[];
  featureBreakdown: { feature: string; cost: number; requests: number }[];
}

interface BudgetAlert {
  id: string;
  type: string;
  message: string;
  threshold: number;
  currentValue: number;
  createdAt: string;
}

// ── 36.1: Burn-Down Chart Data ──
interface BurnDownData {
  monthlyLimit: number;
  totalSpent: number;
  remaining: number;
  dailyAvgSpend: number;
  projectedTotal: number;
  exhaustionDate: string | null;
  exhaustionDay: number | null;
  daysRemaining: number;
  dailyPoints: { day: number; consumed: number; remaining: number; projected: number }[];
}

// ── 36.2: Budget Alert Thresholds ──
interface BudgetThresholdData {
  thresholds: { level: number; label: string; breached: boolean; currentPct: number }[];
  currentPct: number;
  monthlyLimit: number;
  currentSpend: number;
}

// ── 36.3: Budget Allocation ──
interface BudgetAllocation {
  monthlyLimit: number;
  allocations: { useCase: string; allocatedPct: number; allocatedUsd: number; actualUsd: number; actualPct: number }[];
}

// ── 36.4: Cost Breakdown ──
interface CostBreakdown {
  avgCostPerInvocation: number;
  dailySpend: number;
  dailyInvocations: number;
  operations: {
    operation: string;
    avgCost: number;
    avgTokens: number;
    estimatedMonthlyCount: number;
    estimatedMonthlyCost: number;
  }[];
}

// ── 36.5: Enforcement Status ──
interface EnforcementStatus {
  enforcementLevel: string;
  actions: string[];
  budgetPct: number;
  invocationPct: number;
  monthlyLimit: number;
  currentSpend: number;
  invocationCap: number;
  currentInvocations: number;
}

// ── 36.1: Burn-Down Chart Component ──
function BurnDownChart({ data }: { data: BurnDownData }) {
  const maxVal = data.monthlyLimit;
  const barWidth = 100 / data.dailyPoints.length;
  const today = new Date().getDate();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <TrendingDown className="h-5 w-5" /> Budget Burn-Down
        </CardTitle>
        <CardDescription>
          Budget consumed vs. remaining over the month
          {data.exhaustionDate && (
            <span className="text-destructive ml-2">
              Budget exhaustion projected: {new Date(data.exhaustionDate).toLocaleDateString()}
            </span>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-4 mb-4">
          <div className="text-center">
            <p className="text-2xl font-bold">${data.totalSpent.toFixed(2)}</p>
            <p className="text-xs text-muted-foreground">Spent This Month</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-green-500">${data.remaining.toFixed(2)}</p>
            <p className="text-xs text-muted-foreground">Remaining</p>
          </div>
          <div className="text-center">
            <p className={`text-2xl font-bold ${data.projectedTotal > data.monthlyLimit ? "text-destructive" : ""}`}>
              ${data.projectedTotal.toFixed(2)}
            </p>
            <p className="text-xs text-muted-foreground">Projected Total</p>
          </div>
        </div>
        <div className="relative h-40 bg-muted/30 rounded-lg overflow-hidden flex items-end">
          {data.dailyPoints.map((pt) => {
            const consumedH = maxVal > 0 ? (pt.consumed / maxVal) * 100 : 0;
            const projectedH = maxVal > 0 ? (pt.projected / maxVal) * 100 : 0;
            const isToday = pt.day === today;
            const isFuture = pt.day > today;
            return (
              <div
                key={pt.day}
                className="relative flex flex-col justify-end"
                style={{ width: `${barWidth}%`, height: "100%" }}
                title={`Day ${pt.day}: $${pt.consumed.toFixed(2)} consumed`}
              >
                {isFuture && (
                  <div
                    className="absolute bottom-0 w-full bg-blue-500/20 border-t border-blue-500/30 rounded-t-sm"
                    style={{ height: `${Math.min(projectedH, 100)}%` }}
                  />
                )}
                <div
                  className={`w-full rounded-t-sm ${isToday ? "bg-primary" : isFuture ? "bg-transparent" : "bg-primary/60"}`}
                  style={{ height: `${Math.min(consumedH, 100)}%` }}
                />
              </div>
            );
          })}
          {/* Budget limit line */}
          <div className="absolute top-0 left-0 right-0 border-t-2 border-dashed border-destructive/50" />
        </div>
        <div className="flex justify-between text-xs text-muted-foreground mt-1">
          <span>Day 1</span>
          <span>Today (Day {today})</span>
          <span>Day {data.dailyPoints.length}</span>
        </div>
        <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-primary/60" /> Consumed
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-blue-500/20" /> Projected
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded border-t-2 border-dashed border-destructive/50" /> Budget Limit
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 36.2: Alert Thresholds Component ──
function AlertThresholdsPanel({ data }: { data: BudgetThresholdData }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <Target className="h-5 w-5" /> Alert Thresholds
        </CardTitle>
        <CardDescription>
          Current spend: ${data.currentSpend.toFixed(2)} of ${data.monthlyLimit} ({data.currentPct}%)
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {data.thresholds.map((t) => (
          <div key={t.level} className="flex items-center justify-between p-3 rounded-lg border">
            <div className="flex items-center gap-3">
              {t.breached ? (
                <AlertTriangle className={`h-5 w-5 ${t.level >= 90 ? "text-destructive" : "text-yellow-500"}`} />
              ) : (
                <Shield className="h-5 w-5 text-green-500" />
              )}
              <div>
                <p className="font-medium text-sm">{t.label}</p>
                <p className="text-xs text-muted-foreground">Alert when {t.level}% of budget is consumed</p>
              </div>
            </div>
            <Badge variant={t.breached ? (t.level >= 90 ? "destructive" : "secondary") : "outline"}>
              {t.breached ? "BREACHED" : "OK"}
            </Badge>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ── 36.3: Budget Allocation Component ──
function BudgetAllocationPanel({ data }: { data: BudgetAllocation }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <PieChart className="h-5 w-5" /> Budget Allocation
        </CardTitle>
        <CardDescription>Allocated vs. actual spend by use case (monthly limit: ${data.monthlyLimit})</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {data.allocations.map((a) => {
            const overBudget = a.actualUsd > a.allocatedUsd && a.allocatedUsd > 0;
            return (
              <div key={a.useCase} className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{a.useCase}</span>
                  <span className="text-xs text-muted-foreground">
                    ${a.actualUsd.toFixed(2)} / ${a.allocatedUsd.toFixed(2)} ({a.allocatedPct}%)
                  </span>
                </div>
                <div className="relative h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`absolute left-0 top-0 h-full rounded-full ${overBudget ? "bg-destructive" : "bg-primary"}`}
                    style={{ width: `${Math.min((a.actualUsd / Math.max(a.allocatedUsd, 1)) * 100, 100)}%` }}
                  />
                </div>
                {overBudget && (
                  <p className="text-xs text-destructive flex items-center gap-1">
                    <AlertTriangle className="h-3 w-3" />
                    Over budget by ${(a.actualUsd - a.allocatedUsd).toFixed(2)}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ── 36.4: Cost Breakdown Component ──
function CostBreakdownPanel({ data }: { data: CostBreakdown }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <BarChart3 className="h-5 w-5" /> Cost Per Operation
        </CardTitle>
        <CardDescription>
          Average cost per AI operation type (avg: ${data.avgCostPerInvocation.toFixed(4)}/invocation)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2 font-medium">Operation</th>
                <th className="text-right py-2 font-medium">Avg Cost</th>
                <th className="text-right py-2 font-medium">Avg Tokens</th>
                <th className="text-right py-2 font-medium">Monthly Count</th>
                <th className="text-right py-2 font-medium">Monthly Cost</th>
              </tr>
            </thead>
            <tbody>
              {data.operations.map((op) => (
                <tr key={op.operation} className="border-b">
                  <td className="py-2 font-medium">{op.operation}</td>
                  <td className="text-right py-2 font-mono text-xs">${op.avgCost.toFixed(4)}</td>
                  <td className="text-right py-2 text-muted-foreground">{op.avgTokens.toLocaleString()}</td>
                  <td className="text-right py-2 text-muted-foreground">{op.estimatedMonthlyCount.toLocaleString()}</td>
                  <td className="text-right py-2 font-mono">${op.estimatedMonthlyCost.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 36.5: Enforcement Status Component ──
function EnforcementStatusPanel({ data }: { data: EnforcementStatus }) {
  const levelColors: Record<string, string> = {
    normal: "text-green-500",
    warning: "text-yellow-500",
    degraded: "text-orange-500",
    hard_limit: "text-destructive",
  };
  const levelLabels: Record<string, string> = {
    normal: "Normal Operations",
    warning: "Warning — Approaching Limit",
    degraded: "Degraded — Non-Critical Features Reduced",
    hard_limit: "Hard Limit — Budget Exhausted",
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <ShieldAlert className="h-5 w-5" /> Budget Enforcement
        </CardTitle>
        <CardDescription>Current enforcement level and active actions</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3 p-4 rounded-lg border">
          <Activity className={`h-6 w-6 ${levelColors[data.enforcementLevel] || ""}`} />
          <div>
            <p className={`text-lg font-bold ${levelColors[data.enforcementLevel] || ""}`}>
              {levelLabels[data.enforcementLevel] || data.enforcementLevel}
            </p>
            <p className="text-xs text-muted-foreground">
              Budget: {data.budgetPct}% used &middot; Invocations: {data.invocationPct}% of cap
            </p>
          </div>
        </div>
        <div>
          <p className="text-sm font-medium mb-2">Active Actions:</p>
          <ul className="space-y-1">
            {data.actions.map((action, i) => (
              <li key={i} className="flex items-center gap-2 text-sm text-muted-foreground">
                <ChevronRight className="h-3 w-3" />
                {action}
              </li>
            ))}
          </ul>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 rounded border">
            <p className="text-xs text-muted-foreground">Budget</p>
            <p className="font-bold">
              ${data.currentSpend.toFixed(2)} / ${data.monthlyLimit}
            </p>
          </div>
          <div className="p-3 rounded border">
            <p className="text-xs text-muted-foreground">Invocations</p>
            <p className="font-bold">
              {data.currentInvocations.toLocaleString()} / {data.invocationCap.toLocaleString()}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function AiBudgetControlsPage() {
  usePageTitle("AI Budget Controls");
  const { toast } = useToast();
  const [newLimit, setNewLimit] = useState("");

  const {
    data: usage,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<BudgetUsage>({
    queryKey: ["/api/ai/budget-usage"],
    queryFn: () => apiRequest("GET", "/api/ai/budget-usage").then((r) => r.json()),
  });

  const { data: alerts } = useQuery<BudgetAlert[]>({
    queryKey: ["/api/ai/budget-alerts"],
    queryFn: () => apiRequest("GET", "/api/ai/budget-alerts").then((r) => r.json()),
  });

  const { data: burnDown } = useQuery<BurnDownData>({
    queryKey: ["/api/ai/budget/burn-down"],
    queryFn: () => apiRequest("GET", "/api/ai/budget/burn-down").then((r) => r.json()),
  });

  const { data: thresholds } = useQuery<BudgetThresholdData>({
    queryKey: ["/api/ai/budget/thresholds"],
    queryFn: () => apiRequest("GET", "/api/ai/budget/thresholds").then((r) => r.json()),
  });

  const { data: allocation } = useQuery<BudgetAllocation>({
    queryKey: ["/api/ai/budget/allocation"],
    queryFn: () => apiRequest("GET", "/api/ai/budget/allocation").then((r) => r.json()),
  });

  const { data: costBreakdown } = useQuery<CostBreakdown>({
    queryKey: ["/api/ai/budget/cost-breakdown"],
    queryFn: () => apiRequest("GET", "/api/ai/budget/cost-breakdown").then((r) => r.json()),
  });

  const { data: enforcement } = useQuery<EnforcementStatus>({
    queryKey: ["/api/ai/budget/enforcement"],
    queryFn: () => apiRequest("GET", "/api/ai/budget/enforcement").then((r) => r.json()),
  });

  const updateLimitMutation = useMutation({
    mutationFn: (limit: number) => apiRequest("PATCH", "/api/ai/budget-config", { monthlyLimit: limit }),
    onSuccess: () => {
      toast({ title: "Budget limit updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/ai/budget-usage"] });
      setNewLimit("");
    },
    onError: () => toast({ title: "Failed to update limit", variant: "destructive" }),
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (isError || !usage) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load AI budget data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const pct = usage.monthlyLimit > 0 ? Math.round((usage.totalSpent / usage.monthlyLimit) * 100) : 0;
  const alertList = Array.isArray(alerts) ? alerts : [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <DollarSign className="h-6 w-6" /> AI Budget Controls
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor and control AI spending across models and features
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <DollarSign className="h-5 w-5 text-primary" />
              <div>
                <p className="text-2xl font-bold">${usage.totalSpent.toFixed(2)}</p>
                <p className="text-xs text-muted-foreground">Monthly Spend</p>
              </div>
            </div>
            <Progress value={Math.min(pct, 100)} className="mt-2" />
            <p className="text-xs text-muted-foreground mt-1">
              {pct}% of ${usage.monthlyLimit} limit
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">${usage.dailySpend.toFixed(2)}</p>
                <p className="text-xs text-muted-foreground">Today&apos;s Spend</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-yellow-500" />
              <div>
                <p className="text-2xl font-bold">{usage.requestCount.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">API Requests</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{(usage.tokenCount / 1000).toFixed(0)}K</p>
                <p className="text-xs text-muted-foreground">Tokens Used</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 36.1: Burn-Down Chart */}
      {burnDown && <BurnDownChart data={burnDown} />}

      {/* 36.5: Enforcement Status */}
      {enforcement && <EnforcementStatusPanel data={enforcement} />}

      <Tabs defaultValue="models">
        <TabsList className="flex-wrap">
          <TabsTrigger value="models">By Model</TabsTrigger>
          <TabsTrigger value="features">By Feature</TabsTrigger>
          <TabsTrigger value="thresholds">Thresholds</TabsTrigger>
          <TabsTrigger value="allocation">Allocation</TabsTrigger>
          <TabsTrigger value="cost-breakdown">Cost Breakdown</TabsTrigger>
          <TabsTrigger value="alerts">Alerts ({alertList.length})</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="models" className="space-y-3">
          {(usage.modelBreakdown || []).length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No model usage data yet</p>
              </CardContent>
            </Card>
          ) : (
            (usage.modelBreakdown || []).map((m) => (
              <Card key={m.model}>
                <CardContent className="py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Zap className="h-4 w-4 text-primary" />
                    <div>
                      <p className="font-medium text-sm">{m.model}</p>
                      <p className="text-xs text-muted-foreground">
                        {m.requests.toLocaleString()} requests &middot; {(m.tokens / 1000).toFixed(0)}K tokens
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="font-bold">${m.cost.toFixed(2)}</p>
                    <p className="text-xs text-muted-foreground">
                      {usage.totalSpent > 0 ? Math.round((m.cost / usage.totalSpent) * 100) : 0}% of total
                    </p>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="features" className="space-y-3">
          {(usage.featureBreakdown || []).length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Settings2 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No feature usage data yet</p>
              </CardContent>
            </Card>
          ) : (
            (usage.featureBreakdown || []).map((f) => (
              <Card key={f.feature}>
                <CardContent className="py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Shield className="h-4 w-4 text-primary" />
                    <div>
                      <p className="font-medium text-sm">{f.feature}</p>
                      <p className="text-xs text-muted-foreground">{f.requests.toLocaleString()} requests</p>
                    </div>
                  </div>
                  <p className="font-bold">${f.cost.toFixed(2)}</p>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* 36.2: Alert Thresholds Tab */}
        <TabsContent value="thresholds" className="space-y-3">
          {thresholds ? (
            <AlertThresholdsPanel data={thresholds} />
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Target className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">Loading threshold data...</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* 36.3: Allocation Tab */}
        <TabsContent value="allocation" className="space-y-3">
          {allocation ? (
            <BudgetAllocationPanel data={allocation} />
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <PieChart className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">Loading allocation data...</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* 36.4: Cost Breakdown Tab */}
        <TabsContent value="cost-breakdown" className="space-y-3">
          {costBreakdown ? (
            <CostBreakdownPanel data={costBreakdown} />
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">Loading cost data...</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="alerts" className="space-y-3">
          {alertList.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <AlertTriangle className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No budget alerts</p>
              </CardContent>
            </Card>
          ) : (
            alertList.map((a) => (
              <Card key={a.id}>
                <CardContent className="py-3 flex items-center gap-3">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  <div className="flex-1">
                    <p className="font-medium text-sm">{a.message}</p>
                    <p className="text-xs text-muted-foreground">
                      <Clock className="inline h-3 w-3 mr-1" />
                      {new Date(a.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <Badge variant="outline">{a.type}</Badge>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="settings">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Budget Configuration</CardTitle>
              <CardDescription>Set monthly spending limits for AI features</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label>Monthly Spend Limit ($)</Label>
                <div className="flex gap-2 mt-1">
                  <Input
                    type="number"
                    placeholder={String(usage.monthlyLimit)}
                    value={newLimit}
                    onChange={(e) => setNewLimit(e.target.value)}
                    min={0}
                  />
                  <Button
                    onClick={() => {
                      const val = parseFloat(newLimit);
                      if (!isNaN(val) && val > 0) updateLimitMutation.mutate(val);
                    }}
                    disabled={!newLimit || updateLimitMutation.isPending}
                  >
                    {updateLimitMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Settings2 className="mr-2 h-4 w-4" />
                    )}
                    Update
                  </Button>
                </div>
              </div>
              <div className="text-sm text-muted-foreground">
                Current limit: <span className="font-medium">${usage.monthlyLimit}</span> &middot; Current spend:{" "}
                <span className="font-medium">${usage.totalSpent.toFixed(2)}</span>
              </div>
            </CardContent>
          </Card>
          {/* 36.6: Budget Rollover */}
          <Card className="mt-4">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <ArrowRightLeft className="h-5 w-5" /> Budget Rollover & Adjustment
              </CardTitle>
              <CardDescription>Roll over unused budget or make mid-month adjustments</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-lg border">
                  <p className="text-xs text-muted-foreground mb-1">Unused This Month</p>
                  <p className="text-xl font-bold text-green-500">
                    ${Math.max(usage.monthlyLimit - usage.totalSpent, 0).toFixed(2)}
                  </p>
                </div>
                <div className="p-4 rounded-lg border">
                  <p className="text-xs text-muted-foreground mb-1">Current Monthly Limit</p>
                  <p className="text-xl font-bold">${usage.monthlyLimit}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 p-3 rounded-md bg-muted/50">
                <Info className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                <p className="text-xs text-muted-foreground">
                  Rollover adds unused budget from the current month to your new monthly limit. Budget adjustments are
                  recorded in the audit log.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
