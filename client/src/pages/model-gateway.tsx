import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Brain,
  Zap,
  ShieldAlert,
  Activity,
  Database,
  BarChart3,
  RefreshCw,
  Trash2,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  CircleDot,
  Server,
  Cpu,
  Timer,
  TrendingUp,
  TrendingDown,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";

interface CircuitBreakerEntry {
  failures: number;
  isOpen: boolean;
  resetAt: string | null;
}

interface LatencyEntry {
  timestamp: number;
  modelId: string;
  backend: string;
  latencyMs: number;
  cached: boolean;
}

interface ErrorEntry {
  timestamp: number;
  modelId: string;
  backend: string;
  error: string;
  retryable: boolean;
}

interface ModelStatEntry {
  requests: number;
  errors: number;
  avgLatencyMs: number;
  cacheHits: number;
  errorRate: number;
}

interface GatewayConfig {
  circuitBreakerThreshold: number;
  circuitBreakerResetMs: number;
  cacheTtlMs: number;
  maxCacheEntries: number;
  maxRetries: number;
  retryBaseMs: number;
  costTable: Record<string, { input: number; output: number }>;
}

interface GatewayData {
  uptime: number;
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate: number;
  cacheSize: number;
  cacheMaxSize: number;
  totalErrors: number;
  errorRate: number;
  retries: number;
  circuitBreakerTrips: number;
  circuitBreakers: Record<string, CircuitBreakerEntry>;
  latencyHistory: LatencyEntry[];
  errorHistory: ErrorEntry[];
  modelStats: Record<string, ModelStatEntry>;
  config: GatewayConfig;
}

interface PromptCatalog {
  totalPrompts: number;
  byTier: Record<string, number>;
  deprecated: number;
  totalVersions: number;
  totalInvocations: number;
}

interface AggregateUsage {
  totalCostUsd: number;
  totalInvocations: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  orgCount: number;
}

interface DashboardResponse {
  gateway: GatewayData;
  promptCatalog: PromptCatalog;
  aggregateUsage: AggregateUsage;
}

function formatUptime(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatCost(usd: number): string {
  if (usd < 0.01) return `$${usd.toFixed(6)}`;
  if (usd < 1) return `$${usd.toFixed(4)}`;
  return `$${usd.toFixed(2)}`;
}

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: typeof Brain;
  trend?: "up" | "down" | "neutral";
  variant?: "default" | "success" | "warning" | "danger";
}) {
  const variantStyles = {
    default: "border-border/50",
    success: "border-emerald-500/30",
    warning: "border-amber-500/30",
    danger: "border-red-500/30",
  };

  return (
    <Card className={`glass-card ${variantStyles[variant]}`}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">{title}</p>
            <p className="text-2xl font-bold tabular-nums">{value}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <div className="flex flex-col items-center gap-1">
            <Icon className="h-5 w-5 text-muted-foreground" />
            {trend === "up" && <TrendingUp className="h-3 w-3 text-emerald-500" />}
            {trend === "down" && <TrendingDown className="h-3 w-3 text-red-500" />}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function CircuitBreakerPanel({ breakers }: { breakers: Record<string, CircuitBreakerEntry> }) {
  const entries = Object.entries(breakers);

  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <CheckCircle2 className="h-10 w-10 mb-3 text-emerald-500/60" />
        <p className="text-sm font-medium">All Circuits Healthy</p>
        <p className="text-xs mt-1">No circuit breakers have been tripped</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {entries.map(([key, cb]) => (
        <div key={key} className="flex items-center justify-between p-3 rounded-lg border border-border/50 bg-card/50">
          <div className="flex items-center gap-3">
            <div className={`h-3 w-3 rounded-full ${cb.isOpen ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
            <div>
              <p className="text-sm font-medium">{key}</p>
              <p className="text-xs text-muted-foreground">
                {cb.failures} failure{cb.failures !== 1 ? "s" : ""}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {cb.isOpen ? (
              <Badge variant="destructive" className="text-xs">
                OPEN
              </Badge>
            ) : (
              <Badge variant="secondary" className="text-xs">
                CLOSED
              </Badge>
            )}
            {cb.resetAt && (
              <span className="text-xs text-muted-foreground">Resets {new Date(cb.resetAt).toLocaleTimeString()}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function LatencyChart({ history }: { history: LatencyEntry[] }) {
  if (history.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <Timer className="h-10 w-10 mb-3 opacity-40" />
        <p className="text-sm font-medium">No Latency Data</p>
        <p className="text-xs mt-1">Latency history will appear as requests are made</p>
      </div>
    );
  }

  const maxLatency = Math.max(...history.filter((h) => !h.cached).map((h) => h.latencyMs), 1);
  const recent = history.slice(-40);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>Recent requests (last {recent.length})</span>
        <span>Max: {maxLatency}ms</span>
      </div>
      <div className="flex items-end gap-[2px] h-32">
        {recent.map((entry, i) => {
          const height = entry.cached ? 4 : Math.max(4, (entry.latencyMs / maxLatency) * 100);
          const color = entry.cached
            ? "bg-cyan-500/60"
            : entry.latencyMs > maxLatency * 0.8
              ? "bg-red-500/80"
              : entry.latencyMs > maxLatency * 0.5
                ? "bg-amber-500/70"
                : "bg-emerald-500/70";
          return (
            <TooltipProvider key={`${entry.timestamp}-${i}`}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div
                    className={`flex-1 min-w-[3px] max-w-[12px] rounded-t ${color} transition-all hover:opacity-80`}
                    style={{ height: `${height}%` }}
                  />
                </TooltipTrigger>
                <TooltipContent side="top" className="text-xs">
                  <p className="font-medium">{entry.modelId.split(".").pop()}</p>
                  <p>{entry.cached ? "Cached" : `${entry.latencyMs}ms`}</p>
                  <p className="text-muted-foreground">{formatTimestamp(entry.timestamp)}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          );
        })}
      </div>
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <div className="h-2 w-2 rounded bg-emerald-500/70" /> Normal
        </span>
        <span className="flex items-center gap-1">
          <div className="h-2 w-2 rounded bg-amber-500/70" /> Slow
        </span>
        <span className="flex items-center gap-1">
          <div className="h-2 w-2 rounded bg-red-500/80" /> Critical
        </span>
        <span className="flex items-center gap-1">
          <div className="h-2 w-2 rounded bg-cyan-500/60" /> Cached
        </span>
      </div>
    </div>
  );
}

function ErrorLog({ errors }: { errors: ErrorEntry[] }) {
  if (errors.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <CheckCircle2 className="h-10 w-10 mb-3 text-emerald-500/60" />
        <p className="text-sm font-medium">No Errors Recorded</p>
        <p className="text-xs mt-1">Error log is clean</p>
      </div>
    );
  }

  const recent = errors.slice(-20).reverse();
  return (
    <ScrollArea className="h-64">
      <div className="space-y-2">
        {recent.map((err, i) => (
          <div
            key={`${err.timestamp}-${i}`}
            className="flex items-start gap-3 p-2 rounded border border-border/30 bg-card/30"
          >
            {err.retryable ? (
              <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
            ) : (
              <XCircle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
            )}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-xs font-medium truncate">{err.modelId}</span>
                <Badge variant={err.retryable ? "secondary" : "destructive"} className="text-[10px] px-1 py-0">
                  {err.retryable ? "RETRYABLE" : "FATAL"}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground truncate">{err.error}</p>
              <p className="text-[10px] text-muted-foreground/60 mt-0.5">{formatTimestamp(err.timestamp)}</p>
            </div>
          </div>
        ))}
      </div>
    </ScrollArea>
  );
}

function ModelStatsTable({ stats }: { stats: Record<string, ModelStatEntry> }) {
  const entries = Object.entries(stats);

  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <Cpu className="h-10 w-10 mb-3 opacity-40" />
        <p className="text-sm font-medium">No Model Activity</p>
        <p className="text-xs mt-1">Per-model statistics will appear after invocations</p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Model</TableHead>
          <TableHead className="text-right">Requests</TableHead>
          <TableHead className="text-right">Cache Hits</TableHead>
          <TableHead className="text-right">Errors</TableHead>
          <TableHead className="text-right">Error Rate</TableHead>
          <TableHead className="text-right">Avg Latency</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {entries
          .sort((a, b) => b[1].requests - a[1].requests)
          .map(([modelId, stat]) => (
            <TableRow key={modelId}>
              <TableCell className="font-medium text-sm">{modelId}</TableCell>
              <TableCell className="text-right tabular-nums">{stat.requests.toLocaleString()}</TableCell>
              <TableCell className="text-right tabular-nums">{stat.cacheHits.toLocaleString()}</TableCell>
              <TableCell className="text-right tabular-nums">{stat.errors}</TableCell>
              <TableCell className="text-right">
                <Badge
                  variant={stat.errorRate > 10 ? "destructive" : stat.errorRate > 5 ? "secondary" : "outline"}
                  className="text-xs tabular-nums"
                >
                  {stat.errorRate}%
                </Badge>
              </TableCell>
              <TableCell className="text-right tabular-nums">{stat.avgLatencyMs}ms</TableCell>
            </TableRow>
          ))}
      </TableBody>
    </Table>
  );
}

function CostTable({ costTable }: { costTable: Record<string, { input: number; output: number }> }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Model</TableHead>
          <TableHead className="text-right">Input (per token)</TableHead>
          <TableHead className="text-right">Output (per token)</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {Object.entries(costTable).map(([model, rates]) => (
          <TableRow key={model}>
            <TableCell className="font-medium text-sm">{model}</TableCell>
            <TableCell className="text-right tabular-nums text-xs">${rates.input.toFixed(8)}</TableCell>
            <TableCell className="text-right tabular-nums text-xs">${rates.output.toFixed(8)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function PromptCatalogPanel({ catalog }: { catalog: PromptCatalog }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
      <div className="p-3 rounded-lg border border-border/50 bg-card/50 text-center">
        <p className="text-2xl font-bold">{catalog.totalPrompts}</p>
        <p className="text-xs text-muted-foreground">Active Prompts</p>
      </div>
      <div className="p-3 rounded-lg border border-border/50 bg-card/50 text-center">
        <p className="text-2xl font-bold">{catalog.totalVersions}</p>
        <p className="text-xs text-muted-foreground">Total Versions</p>
      </div>
      <div className="p-3 rounded-lg border border-border/50 bg-card/50 text-center">
        <p className="text-2xl font-bold">{catalog.totalInvocations}</p>
        <p className="text-xs text-muted-foreground">Invocations</p>
      </div>
      {Object.entries(catalog.byTier).map(([tier, count]) => (
        <div key={tier} className="p-3 rounded-lg border border-border/50 bg-card/50 text-center">
          <p className="text-lg font-bold">{count}</p>
          <p className="text-xs text-muted-foreground capitalize">{tier}</p>
        </div>
      ))}
      {catalog.deprecated > 0 && (
        <div className="p-3 rounded-lg border border-amber-500/30 bg-card/50 text-center">
          <p className="text-lg font-bold text-amber-500">{catalog.deprecated}</p>
          <p className="text-xs text-muted-foreground">Deprecated</p>
        </div>
      )}
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="p-6 space-y-6" role="status" aria-label="Loading model gateway dashboard">
      <Skeleton className="h-8 w-72" />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
      <span className="sr-only">Loading model gateway dashboard...</span>
    </div>
  );
}

export default function ModelGatewayPage() {
  usePageTitle("Model Gateway Dashboard");
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("overview");

  const { data, isLoading, isError, refetch } = useQuery<DashboardResponse>({
    queryKey: ["/api/model-gateway/dashboard"],
    refetchInterval: 15000,
  });

  const clearCacheMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/model-gateway/cache/clear"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/model-gateway/dashboard"] });
      toast({ title: "Cache cleared", description: "Model response cache has been flushed." });
    },
    onError: () => toast({ title: "Failed to clear cache", variant: "destructive" }),
  });

  const resetMetricsMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/model-gateway/metrics/reset"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/model-gateway/dashboard"] });
      toast({ title: "Metrics reset", description: "Gateway metrics counters have been reset." });
    },
    onError: () => toast({ title: "Failed to reset metrics", variant: "destructive" }),
  });

  if (isLoading) return <LoadingSkeleton />;

  if (isError || !data) {
    return (
      <div className="p-6">
        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
          <AlertTriangle className="h-12 w-12 mb-4 text-red-500/60" />
          <p className="text-lg font-medium">Failed to load gateway data</p>
          <p className="text-sm mt-1 mb-4">Check your connection and try again</p>
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </div>
      </div>
    );
  }

  const { gateway, promptCatalog, aggregateUsage } = data;
  const hasOpenBreakers = Object.values(gateway.circuitBreakers).some((cb) => cb.isOpen);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-6 w-6 text-primary" />
            Model Gateway Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Circuit breaker status, cache performance, failover visibility, and cost tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" size="sm" onClick={() => refetch()} aria-label="Refresh dashboard">
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Refresh data</TooltipContent>
            </Tooltip>
          </TooltipProvider>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => clearCacheMutation.mutate()}
                  disabled={clearCacheMutation.isPending}
                  aria-label="Clear model cache"
                >
                  {clearCacheMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>Clear response cache</TooltipContent>
            </Tooltip>
          </TooltipProvider>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => resetMetricsMutation.mutate()}
                  disabled={resetMetricsMutation.isPending}
                  aria-label="Reset metrics"
                >
                  {resetMetricsMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>Reset metrics counters</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>

      {hasOpenBreakers && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-red-500/30 bg-red-500/5" role="alert">
          <ShieldAlert className="h-5 w-5 text-red-500 shrink-0" />
          <div>
            <p className="text-sm font-medium text-red-500">Circuit Breaker Alert</p>
            <p className="text-xs text-muted-foreground">
              One or more model circuit breakers are open. Requests to affected models will be rejected until the
              breaker resets.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-4 gap-4">
        <StatCard title="Uptime" value={formatUptime(gateway.uptime)} icon={Clock} subtitle="Since last restart" />
        <StatCard
          title="Total Requests"
          value={gateway.totalRequests.toLocaleString()}
          icon={Activity}
          subtitle={`${gateway.retries} retries`}
        />
        <StatCard
          title="Cache Hit Rate"
          value={`${gateway.cacheHitRate}%`}
          icon={Database}
          subtitle={`${gateway.cacheHits} hits / ${gateway.cacheMisses} misses`}
          variant={gateway.cacheHitRate > 50 ? "success" : gateway.cacheHitRate > 20 ? "default" : "warning"}
        />
        <StatCard
          title="Error Rate"
          value={`${gateway.errorRate}%`}
          icon={AlertTriangle}
          subtitle={`${gateway.totalErrors} errors total`}
          variant={gateway.errorRate > 10 ? "danger" : gateway.errorRate > 5 ? "warning" : "success"}
        />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          title="Cache Utilization"
          value={`${gateway.cacheSize}/${gateway.cacheMaxSize}`}
          icon={Database}
          subtitle={`${Math.round((gateway.cacheSize / gateway.cacheMaxSize) * 100)}% full`}
        />
        <StatCard
          title="Circuit Trips"
          value={gateway.circuitBreakerTrips}
          icon={ShieldAlert}
          variant={gateway.circuitBreakerTrips > 0 ? "warning" : "success"}
        />
        <StatCard
          title="Total Cost"
          value={formatCost(aggregateUsage.totalCostUsd)}
          icon={TrendingUp}
          subtitle={`${aggregateUsage.orgCount} org(s)`}
        />
        <StatCard
          title="Total Tokens"
          value={(aggregateUsage.totalInputTokens + aggregateUsage.totalOutputTokens).toLocaleString()}
          icon={Zap}
          subtitle={`In: ${aggregateUsage.totalInputTokens.toLocaleString()} / Out: ${aggregateUsage.totalOutputTokens.toLocaleString()}`}
        />
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview" className="text-xs">
            <BarChart3 className="h-3.5 w-3.5 mr-1" />
            Latency
          </TabsTrigger>
          <TabsTrigger value="circuits" className="text-xs">
            <CircleDot className="h-3.5 w-3.5 mr-1" />
            Circuit Breakers
          </TabsTrigger>
          <TabsTrigger value="models" className="text-xs">
            <Server className="h-3.5 w-3.5 mr-1" />
            Models
          </TabsTrigger>
          <TabsTrigger value="errors" className="text-xs">
            <AlertTriangle className="h-3.5 w-3.5 mr-1" />
            Errors
          </TabsTrigger>
          <TabsTrigger value="config" className="text-xs">
            <Info className="h-3.5 w-3.5 mr-1" />
            Config
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Timer className="h-4 w-4" />
                  Request Latency
                </CardTitle>
                <CardDescription>Response time distribution for recent model invocations</CardDescription>
              </CardHeader>
              <CardContent>
                <LatencyChart history={gateway.latencyHistory} />
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Database className="h-4 w-4" />
                  Cache Performance
                </CardTitle>
                <CardDescription>Response cache utilization and effectiveness</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Cache Fill</span>
                    <span className="tabular-nums">
                      {gateway.cacheSize}/{gateway.cacheMaxSize}
                    </span>
                  </div>
                  <Progress value={(gateway.cacheSize / gateway.cacheMaxSize) * 100} className="h-2" />
                </div>
                <Separator />
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                    <p className="text-xl font-bold text-emerald-500">{gateway.cacheHits}</p>
                    <p className="text-xs text-muted-foreground">Cache Hits</p>
                  </div>
                  <div className="text-center p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <p className="text-xl font-bold text-amber-500">{gateway.cacheMisses}</p>
                    <p className="text-xs text-muted-foreground">Cache Misses</p>
                  </div>
                </div>
                <div className="text-center">
                  <p className="text-3xl font-bold">{gateway.cacheHitRate}%</p>
                  <p className="text-xs text-muted-foreground">Hit Rate</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="circuits" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <CircleDot className="h-4 w-4" />
                  Circuit Breaker Status
                </CardTitle>
                <CardDescription>Real-time health of model endpoint circuit breakers</CardDescription>
              </CardHeader>
              <CardContent>
                <CircuitBreakerPanel breakers={gateway.circuitBreakers} />
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Failover Summary
                </CardTitle>
                <CardDescription>Circuit breaker trips and retry statistics</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-2xl font-bold">{gateway.circuitBreakerTrips}</p>
                    <p className="text-xs text-muted-foreground">Total CB Trips</p>
                  </div>
                  <div className="text-center p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-2xl font-bold">{gateway.retries}</p>
                    <p className="text-xs text-muted-foreground">Retry Attempts</p>
                  </div>
                </div>
                <Separator />
                <div className="space-y-2">
                  <p className="text-sm font-medium">Circuit Breaker Configuration</p>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <p>Failure threshold: {gateway.config.circuitBreakerThreshold} consecutive failures</p>
                    <p>Reset timeout: {gateway.config.circuitBreakerResetMs / 1000}s</p>
                    <p>Max retries per request: {gateway.config.maxRetries}</p>
                    <p>Retry base delay: {gateway.config.retryBaseMs}ms (exponential backoff)</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="models" className="mt-4">
          <div className="space-y-6">
            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="h-4 w-4" />
                  Per-Model Statistics
                </CardTitle>
                <CardDescription>Request counts, error rates, and latency by model</CardDescription>
              </CardHeader>
              <CardContent>
                <ModelStatsTable stats={gateway.modelStats} />
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Brain className="h-4 w-4" />
                  Prompt Catalog
                </CardTitle>
                <CardDescription>Registered prompt templates and usage</CardDescription>
              </CardHeader>
              <CardContent>
                <PromptCatalogPanel catalog={promptCatalog} />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="errors" className="mt-4">
          <Card className="glass-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Error Log
              </CardTitle>
              <CardDescription>Recent gateway errors with retryability classification</CardDescription>
            </CardHeader>
            <CardContent>
              <ErrorLog errors={gateway.errorHistory} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Info className="h-4 w-4" />
                  Gateway Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-sm font-medium">Cache TTL</p>
                    <p className="text-xs text-muted-foreground">{gateway.config.cacheTtlMs / 1000}s</p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-sm font-medium">Max Cache Entries</p>
                    <p className="text-xs text-muted-foreground">{gateway.config.maxCacheEntries}</p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-sm font-medium">CB Threshold</p>
                    <p className="text-xs text-muted-foreground">{gateway.config.circuitBreakerThreshold} failures</p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-sm font-medium">CB Reset</p>
                    <p className="text-xs text-muted-foreground">{gateway.config.circuitBreakerResetMs / 1000}s</p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-sm font-medium">Max Retries</p>
                    <p className="text-xs text-muted-foreground">{gateway.config.maxRetries}</p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/50 bg-card/50">
                    <p className="text-sm font-medium">Retry Base Delay</p>
                    <p className="text-xs text-muted-foreground">{gateway.config.retryBaseMs}ms</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <TrendingUp className="h-4 w-4" />
                  Cost Table
                </CardTitle>
                <CardDescription>Per-token pricing by model</CardDescription>
              </CardHeader>
              <CardContent>
                <CostTable costTable={gateway.config.costTable} />
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
