import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  AlertTriangle, Shield, Target, TrendingUp, Brain, RefreshCw,
  Activity, Zap, Clock, Server, Globe, User, Hash, Mail, Link2,
  ChevronRight, ArrowUpRight, ShieldAlert, Crosshair, CheckCircle, X, BarChart3
} from "lucide-react";

function formatTimestamp(date: string | Date | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function formatType(type: string): string {
  return type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function probabilityColor(p: number): string {
  if (p > 0.7) return "text-red-500";
  if (p > 0.4) return "text-yellow-500";
  return "text-green-500";
}

function probabilityBgColor(p: number): string {
  if (p > 0.7) return "bg-red-500/10 border-red-500/30";
  if (p > 0.4) return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-green-500/10 border-green-500/30";
}

function riskScoreColor(score: number): string {
  if (score >= 75) return "bg-red-500";
  if (score >= 50) return "bg-orange-500";
  if (score >= 25) return "bg-yellow-500";
  return "bg-green-500";
}

function riskScoreBgColor(score: number): string {
  if (score >= 75) return "text-red-500";
  if (score >= 50) return "text-orange-500";
  if (score >= 25) return "text-yellow-500";
  return "text-green-500";
}

const ANOMALY_KIND_STYLES: Record<string, string> = {
  volume_spike: "bg-red-500/10 text-red-500 border-red-500/20",
  new_vector: "bg-purple-500/10 text-purple-500 border-purple-500/20",
  timing_anomaly: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  severity_escalation: "bg-red-500/10 text-red-500 border-red-500/20",
  source_deviation: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

const PRIORITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  low: "bg-green-500/10 text-green-500 border-green-500/20",
};

const ENTITY_ICONS: Record<string, typeof Globe> = {
  ip: Globe,
  host: Server,
  domain: Globe,
  user: User,
  file_hash: Hash,
  email: Mail,
  url: Link2,
};

function StatCard({ title, value, icon: Icon, loading }: {
  title: string;
  value: string | number;
  icon: typeof Globe;
  loading?: boolean;
}) {
  const testId = `stat-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className="p-1.5 rounded-md bg-muted/50">
          <Icon className="h-3.5 w-3.5 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold tabular-nums" data-testid={`value-${testId}`}>{value}</div>
        )}
      </CardContent>
    </Card>
  );
}

export default function PredictiveDefensePage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("attack-surface");
  const [subscriptionName, setSubscriptionName] = useState("");
  const [subscriptionMetricPrefix, setSubscriptionMetricPrefix] = useState("");

  const { data: forecasts, isLoading: forecastsLoading } = useQuery<any[]>({
    queryKey: ["/api/predictive/forecasts"],
  });

  const { data: anomalies, isLoading: anomaliesLoading } = useQuery<any[]>({
    queryKey: ["/api/predictive/anomalies"],
  });

  const { data: attackSurface, isLoading: surfaceLoading } = useQuery<any[]>({
    queryKey: ["/api/predictive/attack-surface"],
  });

  const { data: recommendations, isLoading: recsLoading } = useQuery<any[]>({
    queryKey: ["/api/predictive/recommendations"],
  });

  const { data: qualityTrends } = useQuery<any[]>({
    queryKey: ["/api/predictive/forecast-quality"],
  });

  const { data: anomalySubscriptions } = useQuery<any[]>({
    queryKey: ["/api/predictive/anomaly-subscriptions"],
  });

  const recomputeMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/predictive/recompute");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/forecasts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/attack-surface"] });
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/recommendations"] });
      toast({ title: "Analysis complete", description: "Predictive models have been recomputed." });
    },
    onError: (err: Error) => {
      toast({ title: "Analysis failed", description: err.message, variant: "destructive" });
    },
  });

  const updateRecMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      await apiRequest("PATCH", `/api/predictive/recommendations/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/recommendations"] });
      toast({ title: "Recommendation updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Update failed", description: err.message, variant: "destructive" });
    },
  });

  const createSubscriptionMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/predictive/anomaly-subscriptions", {
        name: subscriptionName,
        metricPrefix: subscriptionMetricPrefix,
        minimumSeverity: "medium",
        minDelta: 10,
        channel: "in_app",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/anomaly-subscriptions"] });
      setSubscriptionName("");
      setSubscriptionMetricPrefix("");
      toast({ title: "Subscription created" });
    },
  });

  const deleteSubscriptionMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/predictive/anomaly-subscriptions/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/predictive/anomaly-subscriptions"] });
    },
  });

  const isLoading = forecastsLoading || anomaliesLoading || surfaceLoading || recsLoading;

  const sortedForecasts = [...(forecasts || [])].sort((a, b) => (b.probability ?? 0) - (a.probability ?? 0));
  const sortedAnomalies = [...(anomalies || [])].sort((a, b) => (b.zScore ?? 0) - (a.zScore ?? 0));
  const sortedSurface = [...(attackSurface || [])].sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));

  const activeForecasts = sortedForecasts.filter((f) => (f.probability ?? 0) > 0.3);

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-predictive-defense-loading">
        <div>
          <Skeleton className="h-8 w-72 mb-2" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2"><Skeleton className="h-4 w-24" /></CardHeader>
              <CardContent><Skeleton className="h-7 w-16" /></CardContent>
            </Card>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6"><Skeleton className="h-32 w-full" /></CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-predictive-defense">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Predictive Defense</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            AI-Powered Threat Forecasting & Attack Surface Analysis
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Button
          onClick={() => recomputeMutation.mutate()}
          disabled={recomputeMutation.isPending}
          data-testid="button-run-analysis"
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${recomputeMutation.isPending ? "animate-spin" : ""}`} />
          {recomputeMutation.isPending ? "Running..." : "Run Analysis"}
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="stats-bar">
        <StatCard
          title="Active Anomalies"
          value={anomalies?.length ?? 0}
          icon={AlertTriangle}
        />
        <StatCard
          title="Surface Assets"
          value={attackSurface?.length ?? 0}
          icon={Target}
        />
        <StatCard
          title="Active Forecasts"
          value={activeForecasts.length}
          icon={TrendingUp}
        />
        <StatCard
          title="Recommendations"
          value={recommendations?.length ?? 0}
          icon={Shield}
        />
      </div>

      <div data-testid="section-forecasts">
        <div className="flex items-center gap-2 mb-3">
          <Brain className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Risk Forecasts</h2>
        </div>
        {sortedForecasts.length === 0 ? (
          <Card data-testid="empty-forecasts">
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <Brain className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No forecasts available</p>
              <p className="text-xs text-muted-foreground mt-1">Run an analysis to generate threat forecasts</p>
              <Button
                variant="outline"
                className="mt-4"
                onClick={() => recomputeMutation.mutate()}
                disabled={recomputeMutation.isPending}
                data-testid="button-run-analysis-empty"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Run Analysis
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {sortedForecasts.map((forecast, idx) => {
              const prob = forecast.probability ?? 0;
              const drivers = (() => {
                try {
                  if (Array.isArray(forecast.drivers)) return forecast.drivers;
                  if (typeof forecast.drivers === "string") return JSON.parse(forecast.drivers);
                  return [];
                } catch { return []; }
              })();

              return (
                <Card key={forecast.id || idx} className={`border ${probabilityBgColor(prob)}`} data-testid={`card-forecast-${forecast.id || idx}`}>
                  <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0 pb-2">
                    <div className="min-w-0 flex-1">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
                        <Crosshair className="h-4 w-4 flex-shrink-0" />
                        {formatType(forecast.forecastType || forecast.type || "Unknown")}
                      </CardTitle>
                      {forecast.predictedWindowHours && (
                        <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Within {forecast.predictedWindowHours} hours
                        </p>
                      )}
                    </div>
                    <div className="flex flex-col items-end flex-shrink-0">
                      <span className={`text-2xl font-bold tabular-nums ${probabilityColor(prob)}`} data-testid={`value-probability-${forecast.id || idx}`}>
                        {Math.round(prob * 100)}%
                      </span>
                      {forecast.confidence != null && (
                        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] mt-1" data-testid={`badge-confidence-${forecast.id || idx}`}>
                          {Math.round(forecast.confidence * 100)}% conf
                        </Badge>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {forecast.description && (
                      <p className="text-xs text-muted-foreground" data-testid={`text-forecast-desc-${forecast.id || idx}`}>
                        {forecast.description}
                      </p>
                    )}
                    {drivers.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {drivers.map((driver: string, di: number) => (
                          <Badge key={di} variant="secondary" className="text-[10px]" data-testid={`badge-driver-${forecast.id || idx}-${di}`}>
                            {driver}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      <div data-testid="section-anomalies">
        <div className="flex items-center gap-2 mb-3">
          <Activity className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Anomalies Timeline</h2>
        </div>
        {sortedAnomalies.length === 0 ? (
          <Card data-testid="empty-anomalies">
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <Activity className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No anomalies detected</p>
              <p className="text-xs text-muted-foreground mt-1">The system has not detected any behavioral anomalies</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {sortedAnomalies.map((anomaly, idx) => {
              const kindStyle = ANOMALY_KIND_STYLES[anomaly.kind] || "bg-muted text-muted-foreground border-muted";
              const topSignals = (() => {
                try {
                  if (Array.isArray(anomaly.topSignals)) return anomaly.topSignals;
                  if (typeof anomaly.topSignals === "string") return JSON.parse(anomaly.topSignals);
                  return [];
                } catch { return []; }
              })();

              return (
                <Card key={anomaly.id || idx} data-testid={`card-anomaly-${anomaly.id || idx}`}>
                  <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0 pb-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${kindStyle}`} data-testid={`badge-anomaly-kind-${anomaly.id || idx}`}>
                        {formatType(anomaly.kind || "unknown")}
                      </span>
                      {anomaly.severity && (
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${PRIORITY_STYLES[anomaly.severity] || "bg-muted text-muted-foreground border-muted"}`} data-testid={`badge-anomaly-severity-${anomaly.id || idx}`}>
                          {anomaly.severity}
                        </span>
                      )}
                    </div>
                    {anomaly.zScore != null && (
                      <span className="text-xs font-mono text-muted-foreground tabular-nums" data-testid={`value-zscore-${anomaly.id || idx}`}>
                        z={Number(anomaly.zScore).toFixed(2)}
                      </span>
                    )}
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {anomaly.metric && (
                      <p className="text-sm font-medium" data-testid={`text-anomaly-metric-${anomaly.id || idx}`}>
                        {anomaly.metric}
                      </p>
                    )}
                    <div className="flex items-center gap-4 text-xs text-muted-foreground">
                      {anomaly.baseline != null && (
                        <span data-testid={`value-baseline-${anomaly.id || idx}`}>
                          Baseline: <span className="font-mono tabular-nums">{Number(anomaly.baseline).toFixed(1)}</span>
                        </span>
                      )}
                      {anomaly.current != null && (
                        <span data-testid={`value-current-${anomaly.id || idx}`}>
                          Current: <span className="font-mono tabular-nums font-medium text-foreground">{Number(anomaly.current).toFixed(1)}</span>
                        </span>
                      )}
                    </div>
                    {topSignals.length > 0 && (
                      <ul className="space-y-0.5">
                        {topSignals.slice(0, 5).map((signal: string, si: number) => (
                          <li key={si} className="text-[11px] text-muted-foreground flex items-start gap-1.5" data-testid={`text-signal-${anomaly.id || idx}-${si}`}>
                            <ChevronRight className="h-3 w-3 mt-0.5 flex-shrink-0" />
                            {signal}
                          </li>
                        ))}
                      </ul>
                    )}
                    {(anomaly.windowStart || anomaly.windowEnd) && (
                      <p className="text-[10px] text-muted-foreground flex items-center gap-1" data-testid={`text-anomaly-window-${anomaly.id || idx}`}>
                        <Clock className="h-3 w-3" />
                        {formatTimestamp(anomaly.windowStart)} — {formatTimestamp(anomaly.windowEnd)}
                      </p>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      <Card data-testid="section-forecast-quality">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><BarChart3 className="h-4 w-4" />Forecast Quality Scoring</CardTitle>
        </CardHeader>
        <CardContent>
          {!qualityTrends?.length ? (
            <p className="text-sm text-muted-foreground">No precision/recall snapshots yet. Run analysis to generate trend points.</p>
          ) : (
            <div className="space-y-2">
              {qualityTrends.map((trend, idx) => (
                <div key={trend.module || idx} className="border rounded-md p-3">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium">{formatType(trend.module)}</div>
                    <Badge variant="outline" className="text-[10px]">n={trend.sampleSize || 0}</Badge>
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                    <div>Precision: <span className="font-semibold">{Math.round((trend.latestPrecision || 0) * 100)}%</span> ({(trend.precisionTrend || 0) >= 0 ? "+" : ""}{Math.round((trend.precisionTrend || 0) * 100)}pp)</div>
                    <div>Recall: <span className="font-semibold">{Math.round((trend.latestRecall || 0) * 100)}%</span> ({(trend.recallTrend || 0) >= 0 ? "+" : ""}{Math.round((trend.recallTrend || 0) * 100)}pp)</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card data-testid="section-anomaly-subscriptions">
        <CardHeader>
          <CardTitle className="text-base">Anomaly Subscriptions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            <Input placeholder="Subscription name" value={subscriptionName} onChange={(e) => setSubscriptionName(e.target.value)} />
            <Input placeholder="Metric prefix (optional)" value={subscriptionMetricPrefix} onChange={(e) => setSubscriptionMetricPrefix(e.target.value)} />
            <Button disabled={!subscriptionName || createSubscriptionMutation.isPending} onClick={() => createSubscriptionMutation.mutate()}>
              Subscribe
            </Button>
          </div>
          <div className="space-y-2">
            {(anomalySubscriptions || []).map((subscription) => (
              <div key={subscription.id} className="flex items-center justify-between border rounded-md p-2 text-sm">
                <div>
                  <div className="font-medium">{subscription.name}</div>
                  <div className="text-xs text-muted-foreground">{subscription.metricPrefix || "All metrics"} · {subscription.minimumSeverity}+ · Δ {subscription.minDelta}</div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => deleteSubscriptionMutation.mutate(subscription.id)}>Remove</Button>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div data-testid="section-surface-recs">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList data-testid="tabs-surface-recs">
            <TabsTrigger value="attack-surface" data-testid="tab-attack-surface">
              <Target className="h-4 w-4 mr-1.5" />
              Attack Surface
            </TabsTrigger>
            <TabsTrigger value="recommendations" data-testid="tab-recommendations">
              <Shield className="h-4 w-4 mr-1.5" />
              Recommendations
            </TabsTrigger>
          </TabsList>

          <TabsContent value="attack-surface" className="mt-3">
            {sortedSurface.length === 0 ? (
              <Card data-testid="empty-attack-surface">
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <Target className="h-10 w-10 text-muted-foreground mb-3" />
                  <p className="text-sm font-medium text-muted-foreground">No attack surface data</p>
                  <p className="text-xs text-muted-foreground mt-1">Run an analysis to map your attack surface</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-2">
                {sortedSurface.map((asset, idx) => {
                  const EntityIcon = ENTITY_ICONS[asset.entityType] || Globe;
                  const relatedSources = (() => {
                    try {
                      if (Array.isArray(asset.relatedSources)) return asset.relatedSources;
                      if (typeof asset.relatedSources === "string") return JSON.parse(asset.relatedSources);
                      return [];
                    } catch { return []; }
                  })();

                  return (
                    <Card key={asset.id || idx} data-testid={`card-asset-${asset.id || idx}`}>
                      <CardContent className="p-4">
                        <div className="flex items-start gap-3 flex-wrap">
                          <div className="p-2 rounded-md bg-muted/50 flex-shrink-0">
                            <EntityIcon className="h-4 w-4 text-muted-foreground" />
                          </div>
                          <div className="min-w-0 flex-1 space-y-2">
                            <div className="flex items-start justify-between gap-3 flex-wrap">
                              <div className="min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase" data-testid={`badge-entity-type-${asset.id || idx}`}>
                                    {asset.entityType}
                                  </Badge>
                                  <span className="text-sm font-mono font-medium truncate" data-testid={`text-entity-value-${asset.id || idx}`}>
                                    {asset.entityValue}
                                  </span>
                                </div>
                              </div>
                              <div className="flex items-center gap-2 flex-shrink-0">
                                <span className={`text-lg font-bold tabular-nums ${riskScoreBgColor(asset.riskScore ?? 0)}`} data-testid={`value-risk-score-${asset.id || idx}`}>
                                  {asset.riskScore ?? 0}
                                </span>
                              </div>
                            </div>
                            <div className="w-full bg-muted/50 rounded-full h-1.5">
                              <div
                                className={`h-1.5 rounded-full ${riskScoreColor(asset.riskScore ?? 0)}`}
                                style={{ width: `${Math.min(asset.riskScore ?? 0, 100)}%` }}
                                data-testid={`bar-risk-${asset.id || idx}`}
                              />
                            </div>
                            <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                              <span data-testid={`value-alert-count-${asset.id || idx}`}>
                                Alerts: <span className="font-medium text-foreground">{asset.alertCount ?? 0}</span>
                              </span>
                              <span data-testid={`value-critical-count-${asset.id || idx}`}>
                                Critical: <span className="font-medium text-red-500">{asset.criticalCount ?? 0}</span>
                              </span>
                              {asset.firstSeenAt && (
                                <span data-testid={`text-first-seen-${asset.id || idx}`}>
                                  First: {formatTimestamp(asset.firstSeenAt)}
                                </span>
                              )}
                              {asset.lastSeenAt && (
                                <span data-testid={`text-last-seen-${asset.id || idx}`}>
                                  Last: {formatTimestamp(asset.lastSeenAt)}
                                </span>
                              )}
                            </div>
                            {relatedSources.length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                {relatedSources.map((src: string, si: number) => (
                                  <Badge key={si} variant="secondary" className="text-[10px]" data-testid={`badge-source-${asset.id || idx}-${si}`}>
                                    {src}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </TabsContent>

          <TabsContent value="recommendations" className="mt-3">
            {!recommendations?.length ? (
              <Card data-testid="empty-recommendations">
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <Shield className="h-10 w-10 text-muted-foreground mb-3" />
                  <p className="text-sm font-medium text-muted-foreground">No recommendations available</p>
                  <p className="text-xs text-muted-foreground mt-1">Run an analysis to generate hardening recommendations</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-2">
                {recommendations.map((rec, idx) => {
                  const priorityStyle = PRIORITY_STYLES[rec.priority] || "bg-muted text-muted-foreground border-muted";
                  const relatedEntities = (() => {
                    try {
                      if (Array.isArray(rec.relatedEntities)) return rec.relatedEntities;
                      if (typeof rec.relatedEntities === "string") return JSON.parse(rec.relatedEntities);
                      return [];
                    } catch { return []; }
                  })();

                  return (
                    <Card key={rec.id || idx} data-testid={`card-rec-${rec.id || idx}`}>
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between gap-3 flex-wrap">
                          <div className="min-w-0 flex-1 space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${priorityStyle}`} data-testid={`badge-rec-priority-${rec.id || idx}`}>
                                {rec.priority}
                              </span>
                              {rec.category && (
                                <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]" data-testid={`badge-rec-category-${rec.id || idx}`}>
                                  {rec.category}
                                </Badge>
                              )}
                              {rec.status && (
                                <Badge variant="secondary" className="text-[10px]" data-testid={`badge-rec-status-${rec.id || idx}`}>
                                  {rec.status}
                                </Badge>
                              )}
                            </div>
                            <p className="text-sm font-medium" data-testid={`text-rec-title-${rec.id || idx}`}>
                              {rec.title}
                            </p>
                            {rec.rationale && (
                              <p className="text-xs text-muted-foreground" data-testid={`text-rec-rationale-${rec.id || idx}`}>
                                {rec.rationale}
                              </p>
                            )}
                            {relatedEntities.length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                {relatedEntities.map((entity: any, ei: number) => {
                                  const label = typeof entity === "string" ? entity : typeof entity === "object" && entity !== null ? Object.values(entity).join(": ") : String(entity);
                                  return (
                                  <Badge key={ei} variant="secondary" className="text-[10px]" data-testid={`badge-rec-entity-${rec.id || idx}-${ei}`}>
                                    {label}
                                  </Badge>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-1 flex-shrink-0">
                            {rec.status !== "accepted" && (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => updateRecMutation.mutate({ id: rec.id, status: "accepted" })}
                                disabled={updateRecMutation.isPending}
                                data-testid={`button-accept-rec-${rec.id || idx}`}
                              >
                                <CheckCircle className="h-3.5 w-3.5 mr-1" />
                                Accept
                              </Button>
                            )}
                            {rec.status !== "dismissed" && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => updateRecMutation.mutate({ id: rec.id, status: "dismissed" })}
                                disabled={updateRecMutation.isPending}
                                data-testid={`button-dismiss-rec-${rec.id || idx}`}
                              >
                                <X className="h-3.5 w-3.5 mr-1" />
                                Dismiss
                              </Button>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
