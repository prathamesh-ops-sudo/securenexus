import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Activity,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Clock,
  CheckCircle2,
  XCircle,
  BarChart3,
  Zap,
  TrendingUp,
  TrendingDown,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";

interface ModelMetrics {
  modelId: string;
  modelName: string;
  provider: string;
  status: "healthy" | "degraded" | "down";
  avgLatencyMs: number;
  p99LatencyMs: number;
  requestsPerMinute: number;
  errorRate: number;
  tokensThroughput: number;
  costPerRequest: number;
  uptime: number;
}

interface InferenceMetrics {
  totalRequests: number;
  totalTokens: number;
  avgLatencyMs: number;
  errorRate: number;
  models: ModelMetrics[];
}

interface DailyStat {
  date: string;
  totalRequests: number;
  successCount: number;
  errorCount: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  totalCostUsd: number;
}

interface TierStat {
  totalRequests: number;
  successRate: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  totalCostUsd: number;
}

interface InferenceStats {
  dailyStats: DailyStat[];
  tierStats: Record<string, TierStat>;
}

interface InferenceLogEntry {
  id: number;
  tier: string;
  model: string;
  promptId: string | null;
  promptVersion: number | null;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
  costEstimateUsd: number;
  cached: boolean;
  success: boolean;
  errorMessage: string | null;
  createdAt: string;
}

const TIER_COLORS: Record<string, string> = {
  triage: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  narrative: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  correlation: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  investigation: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

function MiniBarChart({
  data,
  dataKey,
  maxVal,
  color,
}: {
  data: DailyStat[];
  dataKey: keyof DailyStat;
  maxVal?: number;
  color: string;
}) {
  const values = data.map((d) => Number(d[dataKey]) || 0);
  const max = maxVal || Math.max(...values, 1);

  return (
    <div className="flex items-end gap-0.5 h-16">
      {data.map((d, i) => {
        const val = values[i];
        const height = Math.max((val / max) * 100, 2);
        return (
          <div key={d.date || i} className="flex-1 flex flex-col items-center gap-0.5" title={`${d.date}: ${val}`}>
            <div className={`w-full rounded-t-sm ${color}`} style={{ height: `${height}%`, minHeight: "2px" }} />
          </div>
        );
      })}
    </div>
  );
}

export default function AiModelHealthPage() {
  usePageTitle("AI Model Health & Inference Metrics");
  const [historyTier, setHistoryTier] = useState<string>("all");

  const {
    data: metrics,
    isLoading,
    isError,
    refetch,
  } = useQuery<InferenceMetrics>({
    queryKey: ["/api/ai/inference-metrics"],
    queryFn: () => apiRequest("GET", "/api/ai/inference-metrics").then((r) => r.json()),
  });

  const { data: stats, isLoading: isLoadingStats } = useQuery<InferenceStats>({
    queryKey: ["/api/ai/inference-stats"],
    queryFn: () => apiRequest("GET", "/api/ai/inference-stats?days=7").then((r) => r.json()),
  });

  const { data: history, isLoading: isLoadingHistory } = useQuery<InferenceLogEntry[]>({
    queryKey: ["/api/ai/inference-history", historyTier],
    queryFn: () => {
      const params = historyTier !== "all" ? `?tier=${historyTier}&limit=500` : "?limit=500";
      return apiRequest("GET", `/api/ai/inference-history${params}`).then((r) => r.json());
    },
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

  if (isError || !metrics) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load AI model health data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const models = Array.isArray(metrics.models) ? metrics.models : [];
  const dailyStats = stats?.dailyStats ?? [];
  const tierStats = stats?.tierStats ?? {};
  const historyEntries = Array.isArray(history) ? history : [];

  const statusIcon = (s: string) => {
    if (s === "healthy") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "degraded") return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    return <XCircle className="h-4 w-4 text-red-500" />;
  };

  // Compute 7-day aggregates
  const total7dRequests = dailyStats.reduce((s, d) => s + d.totalRequests, 0);
  const total7dErrors = dailyStats.reduce((s, d) => s + d.errorCount, 0);
  const avg7dLatency =
    dailyStats.length > 0 ? Math.round(dailyStats.reduce((s, d) => s + d.avgLatencyMs, 0) / dailyStats.length) : 0;
  const total7dCost = dailyStats.reduce((s, d) => s + d.totalCostUsd, 0);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="h-6 w-6" /> AI Model Health & Inference Metrics
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor model latency, throughput, error rates, and cost per request
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{(metrics.totalRequests || 0).toLocaleString()}</p>
              <p className="text-xs text-muted-foreground">Total Requests (in-memory)</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{(metrics.avgLatencyMs || 0).toFixed(0)}ms</p>
              <p className="text-xs text-muted-foreground">Avg Latency</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{((metrics.totalTokens || 0) / 1000).toFixed(0)}K</p>
              <p className="text-xs text-muted-foreground">Total Tokens</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{((metrics.errorRate || 0) * 100).toFixed(1)}%</p>
              <p className="text-xs text-muted-foreground">Error Rate</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="timeline">
        <TabsList>
          <TabsTrigger value="timeline">7-Day Timeline</TabsTrigger>
          <TabsTrigger value="tiers">Per-Tier Stats</TabsTrigger>
          <TabsTrigger value="models">Model Health</TabsTrigger>
          <TabsTrigger value="history">Inference History</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        {/* 7-Day Timeline Tab */}
        <TabsContent value="timeline" className="space-y-4">
          {isLoadingStats ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : dailyStats.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No inference data in the last 7 days</p>
                <p className="text-xs text-muted-foreground">
                  Data will appear here once AI inferences are persisted to the database
                </p>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="pt-4">
                    <p className="text-xs text-muted-foreground">7-Day Requests</p>
                    <p className="text-2xl font-bold tabular-nums">{total7dRequests.toLocaleString()}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4">
                    <p className="text-xs text-muted-foreground">7-Day Error Rate</p>
                    <p className="text-2xl font-bold tabular-nums">
                      {total7dRequests > 0 ? ((total7dErrors / total7dRequests) * 100).toFixed(2) : "0.00"}%
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4">
                    <p className="text-xs text-muted-foreground">Avg Latency</p>
                    <p className="text-2xl font-bold tabular-nums">{avg7dLatency}ms</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4">
                    <p className="text-xs text-muted-foreground">7-Day Cost</p>
                    <p className="text-2xl font-bold tabular-nums">${total7dCost.toFixed(4)}</p>
                  </CardContent>
                </Card>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <TrendingUp className="h-4 w-4" /> Daily Request Volume
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <MiniBarChart data={dailyStats} dataKey="totalRequests" color="bg-primary/70" />
                    <div className="flex justify-between text-[10px] text-muted-foreground mt-1">
                      {dailyStats.map((d) => (
                        <span key={d.date}>{d.date.slice(5)}</span>
                      ))}
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Clock className="h-4 w-4" /> Avg Latency (ms)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <MiniBarChart data={dailyStats} dataKey="avgLatencyMs" color="bg-blue-500/70" />
                    <div className="flex justify-between text-[10px] text-muted-foreground mt-1">
                      {dailyStats.map((d) => (
                        <span key={d.date}>{d.date.slice(5)}</span>
                      ))}
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <TrendingDown className="h-4 w-4" /> Daily Errors
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <MiniBarChart data={dailyStats} dataKey="errorCount" color="bg-red-500/70" />
                    <div className="flex justify-between text-[10px] text-muted-foreground mt-1">
                      {dailyStats.map((d) => (
                        <span key={d.date}>{d.date.slice(5)}</span>
                      ))}
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <BarChart3 className="h-4 w-4" /> P95 Latency (ms)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <MiniBarChart data={dailyStats} dataKey="p95LatencyMs" color="bg-amber-500/70" />
                    <div className="flex justify-between text-[10px] text-muted-foreground mt-1">
                      {dailyStats.map((d) => (
                        <span key={d.date}>{d.date.slice(5)}</span>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Daily Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Date</TableHead>
                        <TableHead className="text-right">Requests</TableHead>
                        <TableHead className="text-right">Errors</TableHead>
                        <TableHead className="text-right">Error %</TableHead>
                        <TableHead className="text-right">Avg (ms)</TableHead>
                        <TableHead className="text-right">P50 (ms)</TableHead>
                        <TableHead className="text-right">P95 (ms)</TableHead>
                        <TableHead className="text-right">P99 (ms)</TableHead>
                        <TableHead className="text-right">Cost</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {dailyStats
                        .slice()
                        .reverse()
                        .map((d) => (
                          <TableRow key={d.date}>
                            <TableCell className="font-mono text-xs">{d.date}</TableCell>
                            <TableCell className="text-right tabular-nums">{d.totalRequests}</TableCell>
                            <TableCell className="text-right tabular-nums">{d.errorCount}</TableCell>
                            <TableCell className="text-right tabular-nums">
                              {d.totalRequests > 0 ? ((d.errorCount / d.totalRequests) * 100).toFixed(1) : "0.0"}%
                            </TableCell>
                            <TableCell className="text-right tabular-nums">{d.avgLatencyMs}</TableCell>
                            <TableCell className="text-right tabular-nums">{d.p50LatencyMs}</TableCell>
                            <TableCell className="text-right tabular-nums">{d.p95LatencyMs}</TableCell>
                            <TableCell className="text-right tabular-nums">{d.p99LatencyMs}</TableCell>
                            <TableCell className="text-right tabular-nums">${d.totalCostUsd.toFixed(4)}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* Per-Tier Stats Tab */}
        <TabsContent value="tiers" className="space-y-4">
          {isLoadingStats ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : Object.keys(tierStats).length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Cpu className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No per-tier data available</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(tierStats).map(([tier, stat]) => (
                <Card key={tier}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base capitalize">{tier}</CardTitle>
                      <Badge variant="outline" className={TIER_COLORS[tier] ?? ""}>
                        {tier}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <p className="text-xs text-muted-foreground">Total Requests</p>
                        <p className="font-bold tabular-nums">{stat.totalRequests.toLocaleString()}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Success Rate</p>
                        <p className="font-bold tabular-nums">{(stat.successRate * 100).toFixed(1)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Avg Latency</p>
                        <p className="font-bold tabular-nums">{stat.avgLatencyMs}ms</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">P95 Latency</p>
                        <p className="font-bold tabular-nums">{stat.p95LatencyMs}ms</p>
                      </div>
                    </div>
                    <div className="mt-3">
                      <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
                        <span>Success Rate</span>
                        <span>{(stat.successRate * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={stat.successRate * 100} />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Model Health Tab */}
        <TabsContent value="models" className="space-y-3">
          {models.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Cpu className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No model data available</p>
              </CardContent>
            </Card>
          ) : (
            models.map((m) => (
              <Card key={m.modelId}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {statusIcon(m.status)}
                      <div>
                        <p className="font-medium text-sm">{m.modelName}</p>
                        <p className="text-xs text-muted-foreground">{m.provider}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          m.status === "healthy" ? "default" : m.status === "degraded" ? "secondary" : "destructive"
                        }
                      >
                        {m.status}
                      </Badge>
                      <Badge variant="outline">{m.uptime.toFixed(1)}% uptime</Badge>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-xs text-muted-foreground">Avg Latency</p>
                      <p className="font-medium">{m.avgLatencyMs.toFixed(0)}ms</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">P99 Latency</p>
                      <p className="font-medium">{m.p99LatencyMs.toFixed(0)}ms</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Req/min</p>
                      <p className="font-medium">{m.requestsPerMinute.toFixed(1)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Error Rate</p>
                      <p className="font-medium">{(m.errorRate * 100).toFixed(2)}%</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Inference History Tab */}
        <TabsContent value="history" className="space-y-4">
          <div className="flex items-center gap-3">
            <Select value={historyTier} onValueChange={setHistoryTier}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Filter tier" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tiers</SelectItem>
                <SelectItem value="triage">Triage</SelectItem>
                <SelectItem value="narrative">Narrative</SelectItem>
                <SelectItem value="correlation">Correlation</SelectItem>
                <SelectItem value="investigation">Investigation</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-xs text-muted-foreground">{historyEntries.length} entries (last 7 days)</span>
          </div>

          {isLoadingHistory ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : historyEntries.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No inference history yet</p>
                <p className="text-xs text-muted-foreground">Entries appear here once AI inferences are persisted</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <ScrollArea className="h-[500px]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Timestamp</TableHead>
                        <TableHead>Tier</TableHead>
                        <TableHead>Model</TableHead>
                        <TableHead>Prompt</TableHead>
                        <TableHead className="text-right">Latency</TableHead>
                        <TableHead className="text-right">In Tokens</TableHead>
                        <TableHead className="text-right">Out Tokens</TableHead>
                        <TableHead className="text-right">Cost</TableHead>
                        <TableHead>Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {historyEntries.map((entry) => (
                        <TableRow key={entry.id}>
                          <TableCell className="text-xs tabular-nums whitespace-nowrap">
                            {new Date(entry.createdAt).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-xs ${TIER_COLORS[entry.tier] ?? ""}`}>
                              {entry.tier}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs font-mono truncate max-w-[120px]">{entry.model}</TableCell>
                          <TableCell className="text-xs font-mono truncate max-w-[100px]">
                            {entry.promptId ? `${entry.promptId} v${entry.promptVersion}` : "\u2014"}
                          </TableCell>
                          <TableCell className="text-right tabular-nums text-xs">{entry.latencyMs}ms</TableCell>
                          <TableCell className="text-right tabular-nums text-xs">{entry.inputTokens}</TableCell>
                          <TableCell className="text-right tabular-nums text-xs">{entry.outputTokens}</TableCell>
                          <TableCell className="text-right tabular-nums text-xs">
                            ${entry.costEstimateUsd.toFixed(6)}
                          </TableCell>
                          <TableCell>
                            {entry.success ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-red-500" />
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Performance Tab */}
        <TabsContent value="performance">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Performance Overview</CardTitle>
              <CardDescription>Aggregate model performance across all providers</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {models.map((m) => (
                <div key={m.modelId} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span>{m.modelName}</span>
                    <span className="text-muted-foreground">{m.tokensThroughput.toFixed(0)} tok/s</span>
                  </div>
                  <Progress value={Math.min(m.uptime, 100)} />
                </div>
              ))}
              {models.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">No performance data</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
