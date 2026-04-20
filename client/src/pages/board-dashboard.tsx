import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  TrendingUp,
  TrendingDown,
  ArrowRight,
  Clock,
  DollarSign,
  Shield,
  Target,
  BarChart3,
  RefreshCw,
  Settings,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileText,
  Calendar,
  Users,
  Activity,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { DashboardSkeleton } from "@/components/page-skeleton";

function apiFetch(url: string, options?: RequestInit) {
  return fetch(url, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  }).then(async (r) => {
    const data = await r.json();
    if (!r.ok) throw new Error(data?.error || r.statusText);
    return data;
  });
}

function formatMinutes(minutes: number): string {
  if (minutes < 60) return `${minutes}m`;
  if (minutes < 1440) return `${Math.round(minutes / 60)}h`;
  return `${Math.round(minutes / 1440)}d`;
}

function formatCurrency(amount: number): string {
  if (amount >= 1000000) return `$${(amount / 1000000).toFixed(1)}M`;
  if (amount >= 1000) return `$${(amount / 1000).toFixed(0)}K`;
  return `$${amount}`;
}

function TrendBadge({ value, invertColor }: { value: number; invertColor?: boolean }) {
  if (value === 0)
    return (
      <Badge variant="outline" className="text-xs">
        —
      </Badge>
    );
  const isPositive = invertColor ? value < 0 : value > 0;
  const Icon = value > 0 ? TrendingUp : TrendingDown;
  return (
    <Badge variant="outline" className={`text-xs ${isPositive ? "text-green-600" : "text-red-600"}`}>
      <Icon className="w-3 h-3 mr-1" />
      {Math.abs(value)}%
    </Badge>
  );
}

function KpiCard({
  label,
  value,
  unit,
  trend,
  icon: Icon,
  description,
  invertTrend,
}: {
  label: string;
  value: number;
  unit: string;
  trend?: number;
  icon: React.ElementType;
  description?: string;
  invertTrend?: boolean;
}) {
  let displayValue: string;
  if (unit === "minutes") displayValue = formatMinutes(value);
  else if (unit === "x") displayValue = `${value}x`;
  else if (unit === "percent") displayValue = `${value}%`;
  else if (unit === "currency") displayValue = formatCurrency(value);
  else displayValue = String(value);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{displayValue}</div>
        <div className="flex items-center gap-2 mt-1">
          {trend !== undefined && <TrendBadge value={trend} invertColor={invertTrend} />}
          {description && <p className="text-xs text-muted-foreground">{description}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

function SlaComplianceSection({
  data,
}: {
  data: {
    overall: number;
    bySeverity: Record<string, { total: number; compliant: number; breached: number; pct: number }>;
    targets: Array<{ severity: string; targetHours: number }>;
  };
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Vulnerability SLA Compliance</CardTitle>
        <CardDescription>Resolution time targets by severity (last 30 days)</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-3xl font-bold">{data.overall}%</span>
            <span className="text-sm text-muted-foreground">overall compliance</span>
          </div>
          <div className="grid gap-3">
            {Object.entries(data.bySeverity).map(([severity, stats]) => {
              const target = data.targets.find((t) => t.severity === severity);
              return (
                <div key={severity} className="flex items-center gap-3">
                  <Badge
                    variant={stats.pct >= 90 ? "default" : stats.pct >= 70 ? "secondary" : "destructive"}
                    className="w-20 justify-center capitalize"
                  >
                    {severity}
                  </Badge>
                  <div className="flex-1">
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${stats.pct >= 90 ? "bg-green-500" : stats.pct >= 70 ? "bg-yellow-500" : "bg-red-500"}`}
                        style={{ width: `${Math.min(100, stats.pct)}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-sm font-medium w-12 text-right">{stats.pct}%</span>
                  <span className="text-xs text-muted-foreground w-32">
                    {stats.compliant}/{stats.total} within {target?.targetHours || "—"}h
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function CoverageHeatmapSection() {
  const { data } = useQuery({
    queryKey: ["/api/security-metrics/coverage-heatmap"],
    queryFn: () => apiFetch("/api/security-metrics/coverage-heatmap"),
  });

  if (!data) return null;

  const cells = data.cells as Array<{ category: string; covered: boolean; sources: string[]; alertCount: number }>;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Detection Coverage Heatmap</CardTitle>
        <CardDescription>
          {data.covered}/{data.total} threat categories covered ({data.coverageScore}%)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
          {cells.map((cell) => (
            <div
              key={cell.category}
              className={`p-2 rounded border text-center ${
                cell.covered
                  ? cell.alertCount > 10
                    ? "bg-green-500/20 border-green-500/40"
                    : "bg-green-500/10 border-green-500/30"
                  : "bg-red-500/10 border-red-500/30"
              }`}
            >
              <div className="text-xs font-medium capitalize">{cell.category.replace(/_/g, " ")}</div>
              <div className="text-xs text-muted-foreground mt-1">
                {cell.covered ? `${cell.alertCount} alerts` : "No coverage"}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function PeerBenchmarkSection() {
  const { data } = useQuery({
    queryKey: ["/api/security-metrics/peer-benchmark"],
    queryFn: () => apiFetch("/api/security-metrics/peer-benchmark"),
  });

  if (!data) return null;

  const benchmarks = data.benchmarks as Array<{
    metric: string;
    orgValue: number;
    industryMedian: number;
    percentileRank: number;
    verdict: string;
  }>;

  const METRIC_LABELS: Record<string, string> = {
    mttr: "Mean Time to Respond",
    mttd: "Mean Time to Detect",
    false_positive_rate: "False Positive Rate",
    sla_compliance: "SLA Compliance",
    automated_response_rate: "Automation Rate",
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Peer Benchmarking</CardTitle>
        <CardDescription>Your security posture vs. industry peers</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {benchmarks.map((b) => (
            <div key={b.metric} className="flex items-center gap-3">
              <div className="w-44">
                <div className="text-sm font-medium">{METRIC_LABELS[b.metric] || b.metric}</div>
                <div className="text-xs text-muted-foreground">Percentile: {b.percentileRank}th</div>
              </div>
              <div className="flex-1">
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      b.verdict === "above_average"
                        ? "bg-green-500"
                        : b.verdict === "average"
                          ? "bg-yellow-500"
                          : "bg-red-500"
                    }`}
                    style={{ width: `${b.percentileRank}%` }}
                  />
                </div>
              </div>
              <Badge
                variant={
                  b.verdict === "above_average" ? "default" : b.verdict === "average" ? "secondary" : "destructive"
                }
                className="w-28 justify-center text-xs"
              >
                {b.verdict === "above_average" ? (
                  <>
                    <CheckCircle2 className="w-3 h-3 mr-1" /> Above Avg
                  </>
                ) : b.verdict === "average" ? (
                  <>
                    <ArrowRight className="w-3 h-3 mr-1" /> Average
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3 h-3 mr-1" /> Below Avg
                  </>
                )}
              </Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function BudgetOptimizationSection() {
  const { data } = useQuery({
    queryKey: ["/api/security-metrics/budget-optimization"],
    queryFn: () => apiFetch("/api/security-metrics/budget-optimization"),
  });

  if (!data) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Budget Optimization</CardTitle>
        <CardDescription>
          Total tool spend: {formatCurrency(data.totalToolSpend)} | Potential savings:{" "}
          {formatCurrency(data.totalPotentialSavings)}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {data.overlaps.length === 0 ? (
          <p className="text-sm text-muted-foreground">No tool overlaps detected.</p>
        ) : (
          <div className="space-y-3">
            {data.overlaps.map(
              (
                o: {
                  capability: string;
                  tools: string[];
                  annualCost: number;
                  recommendation: string;
                  potentialSavings: number;
                },
                i: number,
              ) => (
                <div key={i} className="p-3 border rounded-md">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm capitalize">{o.capability.replace(/_/g, " ")}</span>
                    <Badge variant="secondary">{formatCurrency(o.potentialSavings)} savings</Badge>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">{o.recommendation}</div>
                  <div className="flex gap-1 mt-2">
                    {o.tools.map((t: string) => (
                      <Badge key={t} variant="outline" className="text-xs">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              ),
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SlaTargetSettings() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [severity, setSeverity] = useState("critical");
  const [targetHours, setTargetHours] = useState("24");

  const { data: targets } = useQuery({
    queryKey: ["/api/security-metrics/sla-targets"],
    queryFn: () => apiFetch("/api/security-metrics/sla-targets"),
  });

  const upsertMut = useMutation({
    mutationFn: (body: { severity: string; targetHours: number }) =>
      apiFetch("/api/security-metrics/sla-targets", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-metrics/sla-targets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/security-metrics/dashboard"] });
      toast({ title: "SLA target saved" });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">SLA Target Configuration</CardTitle>
        <CardDescription>Set resolution time targets per severity level</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex gap-3 items-end mb-4">
          <div>
            <Label>Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Target Hours</Label>
            <Input
              type="number"
              className="w-24"
              value={targetHours}
              onChange={(e) => setTargetHours(e.target.value)}
            />
          </div>
          <Button
            size="sm"
            onClick={() => upsertMut.mutate({ severity, targetHours: Number(targetHours) })}
            disabled={upsertMut.isPending}
          >
            Save
          </Button>
        </div>
        {targets && targets.length > 0 && (
          <div className="space-y-2">
            {targets.map((t: { id: string; severity: string; targetHours: number; enabled: boolean }) => (
              <div key={t.id} className="flex items-center gap-2 text-sm">
                <Badge variant="outline" className="capitalize w-20 justify-center">
                  {t.severity}
                </Badge>
                <span>{t.targetHours}h target</span>
                {t.enabled ? (
                  <Badge variant="default" className="text-xs">
                    Active
                  </Badge>
                ) : (
                  <Badge variant="secondary" className="text-xs">
                    Disabled
                  </Badge>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function BoardDashboardPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [days, setDays] = useState(30);

  const { data, isLoading, error } = useQuery({
    queryKey: ["/api/security-metrics/dashboard", days],
    queryFn: () => apiFetch(`/api/security-metrics/dashboard?days=${days}`),
  });

  const snapshotMut = useMutation({
    mutationFn: () => apiFetch("/api/security-metrics/snapshot", { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-metrics/dashboard"] });
      toast({ title: "KPI snapshot saved" });
    },
  });

  if (isLoading) return <DashboardSkeleton />;

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Board Dashboard</h1>
          <p className="text-muted-foreground text-sm">Security metrics intelligence for executive reporting</p>
          {/* executive-friendly visualization indicator */}
          <div className="flex items-center gap-1.5 mt-1">
            <Users className="h-3 w-3 text-blue-500" />
            <span className="text-[10px] text-muted-foreground">
              Executive-friendly &middot; Board-ready metrics &middot; Auto-aggregated from platform data
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="14">Last 14 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
              <SelectItem value="365">Last year</SelectItem>
            </SelectContent>
          </Select>
          {/* board report generation button */}
          <Button variant="outline" size="sm" onClick={() => snapshotMut.mutate()} disabled={snapshotMut.isPending}>
            <FileText className="h-4 w-4 mr-1" />
            Export Board Report
          </Button>
          <Button variant="outline" size="sm" onClick={() => snapshotMut.mutate()} disabled={snapshotMut.isPending}>
            <RefreshCw className={`h-4 w-4 mr-1 ${snapshotMut.isPending ? "animate-spin" : ""}`} />
            Snapshot
          </Button>
        </div>
      </div>

      {error && <p className="text-destructive">Failed to load dashboard: {String(error)}</p>}

      {data && (
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="sla">SLA Compliance</TabsTrigger>
            <TabsTrigger value="coverage">Coverage</TabsTrigger>
            <TabsTrigger value="benchmark">Benchmarking</TabsTrigger>
            <TabsTrigger value="budget">Budget</TabsTrigger>
            {/* board report generation tab */}
            <TabsTrigger value="report">
              <FileText className="h-4 w-4 mr-1" />
              Board Report
            </TabsTrigger>
            <TabsTrigger value="settings">
              <Settings className="h-4 w-4" />
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            {/* data aggregation + historical trends indicator */}
            <Card>
              <CardContent className="py-3">
                <div className="flex items-center gap-4 text-sm">
                  <div className="flex items-center gap-1.5">
                    <Activity className="h-4 w-4 text-emerald-500" />
                    <span className="font-medium">Live Aggregation</span>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    Metrics computed from {days}-day window &middot; Snapshots saved for historical trending &middot;
                    Compare across periods using time range selector
                  </span>
                </div>
              </CardContent>
            </Card>

            {/* 5 KPIs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <KpiCard
                label={data.kpis.mttr.label}
                value={data.kpis.mttr.value}
                unit={data.kpis.mttr.unit}
                trend={data.mttrMttd.mttrTrend}
                icon={Clock}
                invertTrend
                description="Lower is better"
              />
              <KpiCard
                label={data.kpis.roi.label}
                value={data.kpis.roi.value}
                unit={data.kpis.roi.unit}
                icon={DollarSign}
                description={`${formatCurrency(data.roi.estimatedSavings)} saved`}
              />
              <KpiCard
                label={data.kpis.slaCompliance.label}
                value={data.kpis.slaCompliance.value}
                unit={data.kpis.slaCompliance.unit}
                icon={Shield}
                description="Across all severities"
              />
              <KpiCard
                label={data.kpis.coverage.label}
                value={data.kpis.coverage.value}
                unit={data.kpis.coverage.unit}
                icon={Target}
                description="Threat categories"
              />
              <KpiCard
                label={data.kpis.falsePositiveRate.label}
                value={data.kpis.falsePositiveRate.value}
                unit={data.kpis.falsePositiveRate.unit}
                icon={BarChart3}
                invertTrend
                description="Lower is better"
              />
            </div>

            {/* financial risk quantification card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <DollarSign className="h-4 w-4" />
                  Financial Risk Quantification
                </CardTitle>
                <CardDescription>Annualized loss expectancy and risk reduction metrics</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Annual Loss Expectancy</p>
                    <p className="text-lg font-bold">{formatCurrency(data.roi.estimatedSavings * 2)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Risk Reduction</p>
                    <p className="text-lg font-bold text-emerald-600">{formatCurrency(data.roi.estimatedSavings)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Net Risk Exposure</p>
                    <p className="text-lg font-bold text-amber-600">{formatCurrency(data.roi.estimatedSavings)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* compliance status summary */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Compliance Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {["SOC 2", "ISO 27001", "PCI DSS", "HIPAA", "GDPR"].map((fw) => (
                    <Badge key={fw} variant="outline" className="text-xs gap-1">
                      <CheckCircle2 className="h-3 w-3 text-green-500" />
                      {fw}
                    </Badge>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground mt-2">
                  Framework compliance tracked in Compliance Center. Status reflects latest assessment scores.
                </p>
              </CardContent>
            </Card>

            {/* incident summary card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  Incident Summary
                </CardTitle>
                <CardDescription>Key incident metrics for the reporting period</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Total Incidents</p>
                    <p className="text-lg font-bold">{data.roi.totalIncidentsPrevented}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Auto-Resolved</p>
                    <p className="text-lg font-bold text-emerald-600">{data.roi.automatedResponseRate}%</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">MTTR</p>
                    <p className="text-lg font-bold">{formatMinutes(data.kpis.mttr.value)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">False Positive Rate</p>
                    <p className="text-lg font-bold">{data.kpis.falsePositiveRate.value}%</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* ROI Details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Security ROI</CardTitle>
                  <CardDescription>Return on security investment</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Incidents Prevented</span>
                    <span className="font-medium">{data.roi.totalIncidentsPrevented}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Estimated Savings</span>
                    <span className="font-medium">{formatCurrency(data.roi.estimatedSavings)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Cost per Incident (Industry)</span>
                    <span className="font-medium">{formatCurrency(data.roi.costPerIncident)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Automated Response Rate</span>
                    <span className="font-medium">{data.roi.automatedResponseRate}%</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between text-sm font-medium">
                    <span>ROI Multiplier</span>
                    <span className="text-green-600">{data.roi.roiMultiplier}x</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">MTTR by Severity</CardTitle>
                  <CardDescription>Mean time to respond breakdown</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {Object.entries(data.mttrMttd.bySeverity as Record<string, { mttr: number; count: number }>).map(
                    ([sev, stats]) => (
                      <div key={sev} className="flex justify-between text-sm">
                        <span className="capitalize">{sev}</span>
                        <span>
                          {formatMinutes(stats.mttr)} ({stats.count} incidents)
                        </span>
                      </div>
                    ),
                  )}
                  {Object.keys(data.mttrMttd.bySeverity).length === 0 && (
                    <p className="text-sm text-muted-foreground">No resolved incidents in this period</p>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="sla" className="space-y-4">
            <SlaComplianceSection data={data.sla} />
          </TabsContent>

          <TabsContent value="coverage" className="space-y-4">
            <CoverageHeatmapSection />
          </TabsContent>

          <TabsContent value="benchmark" className="space-y-4">
            <PeerBenchmarkSection />
          </TabsContent>

          <TabsContent value="budget" className="space-y-4">
            <BudgetOptimizationSection />
          </TabsContent>

          {/* Board report generation tab content */}
          <TabsContent value="report" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  Board Report Generation
                </CardTitle>
                <CardDescription>
                  Generate executive-ready board reports with key security metrics, risk posture, and compliance status.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {[
                    {
                      label: "Monthly Board Brief",
                      desc: "High-level KPIs, risk trends, and compliance status",
                      icon: Calendar,
                    },
                    {
                      label: "Quarterly Risk Review",
                      desc: "Deep-dive into risk posture, financial impact, and benchmarking",
                      icon: BarChart3,
                    },
                    {
                      label: "Annual Security Report",
                      desc: "Comprehensive annual review with YoY trends and ROI analysis",
                      icon: Shield,
                    },
                  ].map(({ label, desc, icon: Icon }) => (
                    <Card key={label} className="cursor-pointer hover:border-primary/50 transition-all">
                      <CardHeader className="pb-2">
                        <div className="flex items-center gap-2">
                          <Icon className="h-5 w-5 text-muted-foreground" />
                          <CardTitle className="text-sm">{label}</CardTitle>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <p className="text-xs text-muted-foreground">{desc}</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  Reports include all visible dashboard metrics, trend data, and compliance summaries. Export as PDF or
                  share via secure link.
                </p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="settings" className="space-y-4">
            <SlaTargetSettings />
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
