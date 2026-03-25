import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  BarChart3,
  Database,
  Clock,
  RefreshCw,
  Play,
  Settings2,
  TrendingUp,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Activity,
  Layers,
  Calendar,
  ArrowUpDown,
  Info,
  Timer,
  Trash2,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface MetricsStats {
  raw: { count: number; oldest: string | null; newest: string | null };
  hourly: { count: number; oldest: string | null };
  daily: { count: number; oldest: string | null };
  serviceCount: number;
}

interface RollupConfig {
  rawRetentionDays: number;
  hourlyRetentionDays: number;
  dailyRetentionDays: number;
}

interface TopMetric {
  service: string;
  metric: string;
  totalSamples: number;
  overallAvg: number;
  overallMax: number;
  overallMin: number;
}

interface RollupResult {
  hourly: {
    hoursProcessed: number;
    rowsInserted: number;
    errors: string[];
  };
  daily: {
    daysProcessed: number;
    rowsInserted: number;
    errors: string[];
  };
  retention: {
    rawDeleted: number;
    hourlyDeleted: number;
    dailyDeleted: number;
    errors: string[];
  };
}

interface MetricDataPoint {
  id: string;
  service: string;
  metric: string;
  timestamp: string;
  value?: number;
  minValue?: number;
  maxValue?: number;
  avgValue?: number;
  p50Value?: number;
  p95Value?: number;
  p99Value?: number;
  sampleCount?: number;
}

function formatNumber(n: number | null | undefined): string {
  if (n == null) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n % 1 === 0 ? String(n) : n.toFixed(2);
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "—";
  }
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return "—";
  }
}

function StatsCards({ stats }: { stats: MetricsStats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Raw Metrics</span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{formatNumber(stats.raw.count)}</p>
          <p className="text-[10px] text-muted-foreground mt-1">
            {stats.raw.newest ? `Latest: ${relativeTime(stats.raw.newest)}` : "No data"}
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <Clock className="h-4 w-4 text-blue-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Hourly Rollups
            </span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{formatNumber(stats.hourly.count)}</p>
          <p className="text-[10px] text-muted-foreground mt-1">
            {stats.hourly.oldest ? `Since: ${formatDate(stats.hourly.oldest)}` : "No data"}
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <Calendar className="h-4 w-4 text-violet-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Daily Rollups
            </span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{formatNumber(stats.daily.count)}</p>
          <p className="text-[10px] text-muted-foreground mt-1">
            {stats.daily.oldest ? `Since: ${formatDate(stats.daily.oldest)}` : "No data"}
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="h-4 w-4 text-emerald-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Services</span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{stats.serviceCount}</p>
          <p className="text-[10px] text-muted-foreground mt-1">Unique services tracked</p>
        </CardContent>
      </Card>
    </div>
  );
}

function RetentionConfig({ config }: { config: RollupConfig }) {
  const items = [
    {
      label: "Raw Metrics",
      days: config.rawRetentionDays,
      icon: Activity,
      color: "text-cyan-400",
      desc: "Individual metric samples",
    },
    {
      label: "Hourly Rollups",
      days: config.hourlyRetentionDays,
      icon: Clock,
      color: "text-blue-400",
      desc: "Hourly aggregated statistics",
    },
    {
      label: "Daily Rollups",
      days: config.dailyRetentionDays,
      icon: Calendar,
      color: "text-violet-400",
      desc: "Daily aggregated statistics",
    },
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Settings2 className="h-4 w-4 text-muted-foreground" />
          Retention Policy
        </CardTitle>
        <CardDescription className="text-xs">Data retention periods for each aggregation tier</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.label} className="flex items-center justify-between p-2.5 rounded-lg border bg-muted/20">
                <div className="flex items-center gap-2.5">
                  <Icon className={`h-4 w-4 ${item.color}`} />
                  <div>
                    <p className="text-xs font-medium">{item.label}</p>
                    <p className="text-[10px] text-muted-foreground">{item.desc}</p>
                  </div>
                </div>
                <Badge variant="outline" className="text-xs tabular-nums">
                  {item.days} days
                </Badge>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function TopMetricsTable({ metrics }: { metrics: TopMetric[] }) {
  if (!metrics.length) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <BarChart3 className="h-8 w-8 mb-2 opacity-30" />
        <p className="text-sm">No metrics data in the last 24 hours</p>
      </div>
    );
  }

  return (
    <ScrollArea className="h-[400px]">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-background z-10">
          <tr className="border-b">
            <th className="text-left py-2 px-2 font-medium text-muted-foreground">Service</th>
            <th className="text-left py-2 px-2 font-medium text-muted-foreground">Metric</th>
            <th className="text-right py-2 px-2 font-medium text-muted-foreground">Samples</th>
            <th className="text-right py-2 px-2 font-medium text-muted-foreground">Avg</th>
            <th className="text-right py-2 px-2 font-medium text-muted-foreground">Min</th>
            <th className="text-right py-2 px-2 font-medium text-muted-foreground">Max</th>
          </tr>
        </thead>
        <tbody>
          {metrics.map((m, i) => (
            <tr
              key={`${m.service}-${m.metric}`}
              className={`border-b border-border/30 ${i % 2 === 0 ? "" : "bg-muted/10"}`}
            >
              <td className="py-2 px-2">
                <Badge variant="outline" className="text-[10px] font-mono">
                  {m.service}
                </Badge>
              </td>
              <td className="py-2 px-2 font-mono">{m.metric}</td>
              <td className="py-2 px-2 text-right tabular-nums font-medium">{formatNumber(m.totalSamples)}</td>
              <td className="py-2 px-2 text-right tabular-nums">{formatNumber(m.overallAvg)}</td>
              <td className="py-2 px-2 text-right tabular-nums text-muted-foreground">{formatNumber(m.overallMin)}</td>
              <td className="py-2 px-2 text-right tabular-nums text-muted-foreground">{formatNumber(m.overallMax)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </ScrollArea>
  );
}

function MetricsBrowser() {
  const { data: servicesData } = useQuery<{ services: string[] }>({
    queryKey: ["/api/metrics-rollup/services"],
  });

  const [selectedService, setSelectedService] = useState<string>("");
  const [selectedMetric, setSelectedMetric] = useState<string>("");
  const [granularity, setGranularity] = useState<string>("hourly");

  const { data: metricsListData } = useQuery<{
    metrics: { service: string; metric: string }[];
  }>({
    queryKey: ["/api/metrics-rollup/metrics", selectedService],
    queryFn: async () => {
      const url = selectedService
        ? `/api/metrics-rollup/metrics?service=${encodeURIComponent(selectedService)}`
        : "/api/metrics-rollup/metrics";
      const res = await apiRequest("GET", url);
      if (!res.ok) throw new Error("Failed to fetch metrics");
      return await res.json();
    },
  });

  const filteredMetrics = metricsListData?.metrics;

  const { data: metricsData, isLoading: dataLoading } = useQuery<{
    granularity: string;
    service: string;
    metric: string;
    count: number;
    data: MetricDataPoint[];
  }>({
    queryKey: ["/api/metrics-rollup/data", selectedService, selectedMetric, granularity],
    queryFn: async () => {
      const params = new URLSearchParams({
        service: selectedService,
        metric: selectedMetric,
        granularity,
        limit: "200",
      });
      const res = await apiRequest("GET", `/api/metrics-rollup/data?${params.toString()}`);
      if (!res.ok) throw new Error("Failed to fetch data");
      return await res.json();
    },
    enabled: !!selectedService && !!selectedMetric,
  });

  const dataPoints = metricsData?.data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-end gap-3 flex-wrap">
        <div className="space-y-1 min-w-[180px]">
          <Label className="text-xs">Service</Label>
          <Select
            value={selectedService}
            onValueChange={(v) => {
              setSelectedService(v);
              setSelectedMetric("");
            }}
          >
            <SelectTrigger className="h-8 text-xs">
              <SelectValue placeholder="Select service" />
            </SelectTrigger>
            <SelectContent>
              {(servicesData?.services ?? []).map((s) => (
                <SelectItem key={s} value={s} className="text-xs">
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1 min-w-[200px]">
          <Label className="text-xs">Metric</Label>
          <Select value={selectedMetric} onValueChange={setSelectedMetric}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue placeholder="Select metric" />
            </SelectTrigger>
            <SelectContent>
              {(filteredMetrics ?? []).map((m) => (
                <SelectItem key={`${m.service}-${m.metric}`} value={m.metric} className="text-xs">
                  {m.metric}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1 min-w-[140px]">
          <Label className="text-xs">Granularity</Label>
          <Select value={granularity} onValueChange={setGranularity}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="raw" className="text-xs">
                Raw
              </SelectItem>
              <SelectItem value="hourly" className="text-xs">
                Hourly
              </SelectItem>
              <SelectItem value="daily" className="text-xs">
                Daily
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {!selectedService || !selectedMetric ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <Database className="h-10 w-10 mb-3 opacity-30" />
          <p className="text-sm">Select a service and metric to browse historical data</p>
        </div>
      ) : dataLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : dataPoints.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <BarChart3 className="h-10 w-10 mb-3 opacity-30" />
          <p className="text-sm">No data found for this selection</p>
          <p className="text-xs mt-1">Try a different time range or granularity</p>
        </div>
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">
                {selectedService} / {selectedMetric}
              </CardTitle>
              <Badge variant="outline" className="text-[10px]">
                {dataPoints.length} points · {granularity}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px]">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-background z-10">
                  <tr className="border-b">
                    <th className="text-left py-2 px-2 font-medium text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Timestamp
                      </div>
                    </th>
                    {granularity === "raw" ? (
                      <th className="text-right py-2 px-2 font-medium text-muted-foreground">Value</th>
                    ) : (
                      <>
                        <th className="text-right py-2 px-2 font-medium text-muted-foreground">Avg</th>
                        <th className="text-right py-2 px-2 font-medium text-muted-foreground">Min</th>
                        <th className="text-right py-2 px-2 font-medium text-muted-foreground">Max</th>
                        <th className="text-right py-2 px-2 font-medium text-muted-foreground">P95</th>
                        <th className="text-right py-2 px-2 font-medium text-muted-foreground">P99</th>
                        <th className="text-right py-2 px-2 font-medium text-muted-foreground">Samples</th>
                      </>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {dataPoints.map((dp, i) => (
                    <tr key={dp.id} className={`border-b border-border/30 ${i % 2 === 0 ? "" : "bg-muted/10"}`}>
                      <td className="py-1.5 px-2 font-mono text-muted-foreground">{formatDate(dp.timestamp)}</td>
                      {granularity === "raw" ? (
                        <td className="py-1.5 px-2 text-right tabular-nums font-medium">{formatNumber(dp.value)}</td>
                      ) : (
                        <>
                          <td className="py-1.5 px-2 text-right tabular-nums font-medium">
                            {formatNumber(dp.avgValue)}
                          </td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-muted-foreground">
                            {formatNumber(dp.minValue)}
                          </td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-muted-foreground">
                            {formatNumber(dp.maxValue)}
                          </td>
                          <td className="py-1.5 px-2 text-right tabular-nums">{formatNumber(dp.p95Value)}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums">{formatNumber(dp.p99Value)}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums">{formatNumber(dp.sampleCount)}</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function MetricsRollupPage() {
  usePageTitle("Metrics Rollup");
  const { toast } = useToast();

  const {
    data: statsData,
    isLoading: statsLoading,
    isError: statsError,
    refetch: refetchStats,
  } = useQuery<MetricsStats>({
    queryKey: ["/api/metrics-rollup/stats"],
  });

  const { data: configData } = useQuery<{ rollupConfig: RollupConfig }>({
    queryKey: ["/api/metrics-rollup/config"],
  });

  const { data: topMetricsData, isLoading: topLoading } = useQuery<{
    period: string;
    metrics: TopMetric[];
  }>({
    queryKey: ["/api/metrics-rollup/top-metrics"],
  });

  const runRollupMutation = useMutation({
    mutationFn: async (recovery: boolean) => {
      const url = recovery ? "/api/metrics-rollup/run?recovery=true" : "/api/metrics-rollup/run";
      const res = await apiRequest("POST", url, {});
      if (!res.ok) throw new Error("Rollup failed");
      const json = await res.json();
      return (json.data ?? json) as RollupResult;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({
        queryKey: ["/api/metrics-rollup/stats"],
      });
      queryClient.invalidateQueries({
        queryKey: ["/api/metrics-rollup/top-metrics"],
      });
      const totalInserted = data.hourly.rowsInserted + data.daily.rowsInserted;
      const totalPruned = data.retention.rawDeleted + data.retention.hourlyDeleted + data.retention.dailyDeleted;
      toast({
        title: "Rollup complete",
        description: `${totalInserted} rows aggregated, ${totalPruned} rows pruned`,
      });
    },
    onError: (err: Error) => {
      toast({
        title: "Rollup failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  if (statsLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" role="status" aria-label="Loading metrics rollup">
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full rounded-lg" />
          ))}
        </div>
        <Skeleton className="h-[400px] w-full rounded-lg" />
      </div>
    );
  }

  if (statsError) {
    return (
      <div className="p-4 md:p-6 max-w-7xl mx-auto">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <AlertTriangle className="h-10 w-10 mb-3 text-destructive" />
            <p className="text-sm font-medium">Failed to load metrics rollup data</p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchStats()}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div
      className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto"
      aria-label="Metrics Rollup Dashboard"
      data-testid="page-metrics-rollup"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Metrics Rollup</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Time-series aggregation status, retention policy, and historical metrics browser
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => runRollupMutation.mutate(false)}
                  disabled={runRollupMutation.isPending}
                  data-testid="button-run-rollup"
                >
                  {runRollupMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                  ) : (
                    <Play className="h-3.5 w-3.5 mr-1.5" />
                  )}
                  Run Rollup
                </Button>
              </TooltipTrigger>
              <TooltipContent className="text-xs">
                Trigger hourly + daily aggregation and retention pruning
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => runRollupMutation.mutate(true)}
                  disabled={runRollupMutation.isPending}
                  data-testid="button-recovery-rollup"
                >
                  {runRollupMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                  ) : (
                    <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
                  )}
                  Recovery
                </Button>
              </TooltipTrigger>
              <TooltipContent className="text-xs">Full re-aggregation with extended lookback window</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>

      {statsData && <StatsCards stats={statsData} />}

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview" className="text-xs">
            <TrendingUp className="h-3 w-3 mr-1" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="browser" className="text-xs">
            <Database className="h-3 w-3 mr-1" />
            Metrics Browser
          </TabsTrigger>
          <TabsTrigger value="config" className="text-xs">
            <Settings2 className="h-3 w-3 mr-1" />
            Configuration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                  Top Metrics (24h)
                </CardTitle>
                <CardDescription className="text-xs">
                  Most active metrics by sample count in the last 24 hours
                </CardDescription>
              </CardHeader>
              <CardContent>
                {topLoading ? (
                  <div className="space-y-2">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <Skeleton key={i} className="h-8 w-full" />
                    ))}
                  </div>
                ) : (
                  <TopMetricsTable metrics={topMetricsData?.metrics ?? []} />
                )}
              </CardContent>
            </Card>

            <div className="space-y-4">
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ArrowUpDown className="h-4 w-4 text-muted-foreground" />
                    Aggregation Pipeline
                  </CardTitle>
                  <CardDescription className="text-xs">How metrics flow through the rollup tiers</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {[
                      {
                        label: "Raw Ingestion",
                        desc: "Individual metric samples collected per-request",
                        icon: Activity,
                        color: "text-cyan-400",
                        bg: "bg-cyan-500/10",
                      },
                      {
                        label: "Hourly Aggregation",
                        desc: "min/max/avg/p50/p95/p99 per service+metric per hour",
                        icon: Clock,
                        color: "text-blue-400",
                        bg: "bg-blue-500/10",
                      },
                      {
                        label: "Daily Aggregation",
                        desc: "Weighted averages from hourly data per day",
                        icon: Calendar,
                        color: "text-violet-400",
                        bg: "bg-violet-500/10",
                      },
                      {
                        label: "Retention Pruning",
                        desc: "Batch-delete expired data beyond retention window",
                        icon: Trash2,
                        color: "text-amber-400",
                        bg: "bg-amber-500/10",
                      },
                    ].map((step, i) => {
                      const Icon = step.icon;
                      return (
                        <div key={step.label} className={`flex items-center gap-3 p-2.5 rounded-lg border ${step.bg}`}>
                          <div
                            className={`flex items-center justify-center h-7 w-7 rounded-full border ${step.color} ${step.bg}`}
                          >
                            <Icon className="h-3.5 w-3.5" />
                          </div>
                          <div className="flex-1">
                            <p className="text-xs font-medium">
                              {i + 1}. {step.label}
                            </p>
                            <p className="text-[10px] text-muted-foreground">{step.desc}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              {runRollupMutation.isSuccess && runRollupMutation.data && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <SuccessIcon size={16} color="#22c55e" />
                      Last Rollup Result
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-3 gap-3 text-center">
                      <div className="p-2 rounded-lg bg-muted/30 border">
                        <p className="text-lg font-bold tabular-nums">{runRollupMutation.data.hourly.rowsInserted}</p>
                        <p className="text-[10px] text-muted-foreground">Hourly rows</p>
                      </div>
                      <div className="p-2 rounded-lg bg-muted/30 border">
                        <p className="text-lg font-bold tabular-nums">{runRollupMutation.data.daily.rowsInserted}</p>
                        <p className="text-[10px] text-muted-foreground">Daily rows</p>
                      </div>
                      <div className="p-2 rounded-lg bg-muted/30 border">
                        <p className="text-lg font-bold tabular-nums">
                          {runRollupMutation.data.retention.rawDeleted +
                            runRollupMutation.data.retention.hourlyDeleted +
                            runRollupMutation.data.retention.dailyDeleted}
                        </p>
                        <p className="text-[10px] text-muted-foreground">Pruned</p>
                      </div>
                    </div>
                    {[
                      ...runRollupMutation.data.hourly.errors,
                      ...runRollupMutation.data.daily.errors,
                      ...runRollupMutation.data.retention.errors,
                    ].length > 0 && (
                      <div className="mt-2 p-2 rounded-md bg-red-500/10 text-red-400 text-xs">
                        <p className="font-medium mb-1">Errors:</p>
                        {[
                          ...runRollupMutation.data.hourly.errors,
                          ...runRollupMutation.data.daily.errors,
                          ...runRollupMutation.data.retention.errors,
                        ].map((e, i) => (
                          <p key={i}>{e}</p>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="browser" className="mt-4">
          <MetricsBrowser />
        </TabsContent>

        <TabsContent value="config" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {configData && <RetentionConfig config={configData.rollupConfig} />}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Timer className="h-4 w-4 text-muted-foreground" />
                  Scheduler Status
                </CardTitle>
                <CardDescription className="text-xs">Automatic rollup schedule configuration</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    {
                      label: "Hourly Rollup",
                      interval: "Every 60 minutes",
                      window: "2-hour lookback",
                    },
                    {
                      label: "Daily Rollup",
                      interval: "Every 60 minutes",
                      window: "2-day lookback",
                    },
                    {
                      label: "Retention Prune",
                      interval: "Every 60 minutes",
                      window: "Batch delete (1000 rows/batch)",
                    },
                    {
                      label: "Startup Recovery",
                      interval: "3 minutes after boot",
                      window: "Full retention window lookback",
                    },
                  ].map((sched) => (
                    <div
                      key={sched.label}
                      className="flex items-center justify-between p-2.5 rounded-lg border bg-muted/20"
                    >
                      <div>
                        <p className="text-xs font-medium">{sched.label}</p>
                        <p className="text-[10px] text-muted-foreground">{sched.window}</p>
                      </div>
                      <Badge variant="outline" className="text-[10px] tabular-nums">
                        {sched.interval}
                      </Badge>
                    </div>
                  ))}
                </div>
                <div className="mt-3 p-2.5 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
                  <div className="flex items-start gap-2">
                    <Info className="h-3.5 w-3.5 text-cyan-400 mt-0.5 shrink-0" />
                    <p className="text-[11px] text-muted-foreground">
                      The rollup scheduler starts automatically on server boot and runs continuously. Use the manual Run
                      Rollup button above for on-demand aggregation.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
