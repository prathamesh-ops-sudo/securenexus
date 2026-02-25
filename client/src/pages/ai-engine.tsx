import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Brain, Zap, Shield, Target, Activity, Crosshair, AlertTriangle,
  CheckCircle2, XCircle, Loader2, Sparkles, Network, Users, Server, MapPin,
  Search, ChevronsUpDown, BarChart3, Cpu, TrendingUp, TrendingDown, ThumbsUp, ThumbsDown,
  Eye, MessageSquare, RotateCcw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { Command, CommandInput, CommandList, CommandEmpty, CommandGroup, CommandItem } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SeverityBadge } from "@/components/security-badges";
import type { Alert } from "@shared/schema";

interface FeedbackMetric {
  date: string;
  avgRating: number;
  totalFeedback: number;
  negativeFeedback: number;
  positiveFeedback: number;
}

interface CorrelationGroup {
  groupName: string;
  alertIds: string[];
  confidence: number;
  reasoning: string;
  suggestedIncidentTitle: string;
  severity: string;
  mitreTactics: string[];
  mitreTechniques: string[];
  killChainPhases: string[];
  diamondModel: {
    adversary: string;
    infrastructure: string[];
    capability: string;
    victim: string[];
  };
}

interface CorrelationResult {
  correlatedGroups: CorrelationGroup[];
  uncorrelatedAlertIds: string[];
  overallAssessment: string;
  threatLandscape: string;
}

interface TriageResult {
  severity: string;
  priority: number;
  category: string;
  recommendedAction: string;
  reasoning: string;
  mitreTactic: string;
  mitreTechnique: string;
  killChainPhase: string;
  falsePositiveLikelihood: number;
  falsePositiveReasoning: string;
  relatedIocs: { type: string; value: string }[];
  nistClassification: string;
  escalationRequired: boolean;
  containmentAdvice: string;
  threatIntelSources?: string[];
}

interface AIConfig {
  backend: string;
  model: string;
  region: string;
  temperature: number;
  maxTokens: number;
}

interface AIHealth {
  status: string;
  backend: string;
  model: string;
  region: string;
  latencyMs: number;
  error?: string;
}

function ThreatMeter({ severity, priority }: { severity: string; priority: number }) {
  const severityToLevel: Record<string, number> = {
    critical: 95,
    high: 75,
    medium: 50,
    low: 25,
    informational: 10,
  };
  const level = severityToLevel[severity] ?? 50;

  const getColor = (val: number) => {
    if (val >= 80) return "bg-red-500";
    if (val >= 60) return "bg-orange-500";
    if (val >= 40) return "bg-yellow-500";
    return "bg-emerald-500";
  };

  return (
    <div className="space-y-1.5" data-testid="threat-meter">
      <div className="flex items-center justify-between gap-2 text-xs">
        <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Threat Level</span>
        <span className="font-bold tabular-nums">{level}%</span>
      </div>
      <div className="relative h-3 w-full rounded-full bg-muted overflow-hidden">
        <div
          className="absolute inset-0 rounded-full opacity-20"
          style={{
            background: "linear-gradient(to right, #22c55e, #eab308, #f97316, #ef4444)",
          }}
        />
        <div
          className={`h-full rounded-full transition-all duration-700 ${getColor(level)}`}
          style={{ width: `${level}%` }}
        />
      </div>
      <div className="flex items-center justify-between gap-2 text-[10px] text-muted-foreground">
        <span>Low</span>
        <span>Critical</span>
      </div>
    </div>
  );
}

export default function AIEnginePage() {
  const { toast } = useToast();
  const [correlationResult, setCorrelationResult] = useState<CorrelationResult | null>(null);
  const [correlationMode, setCorrelationMode] = useState<string>("all");
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [triageAlertId, setTriageAlertId] = useState<string>("");
  const [triageResult, setTriageResult] = useState<TriageResult | null>(null);
  const [alertPickerOpen, setAlertPickerOpen] = useState(false);
  const [driftDays, setDriftDays] = useState("30");
  const [feedbackRating, setFeedbackRating] = useState<number | null>(null);
  const [feedbackComment, setFeedbackComment] = useState("");
  const [feedbackOutcome, setFeedbackOutcome] = useState<"approve" | "reject" | "correct" | null>(null);
  const [showExplainability, setShowExplainability] = useState(true);

  const { data: config, isLoading: configLoading } = useQuery<AIConfig>({
    queryKey: ["/api/ai/config"],
  });

  const { data: health, isLoading: healthLoading, refetch: refetchHealth } = useQuery<AIHealth>({
    queryKey: ["/api/ai/health"],
  });

  const { data: alerts, isLoading: alertsLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: feedbackMetrics, isLoading: metricsLoading } = useQuery<FeedbackMetric[]>({
    queryKey: ["/api/ai/feedback/metrics", driftDays],
    queryFn: async () => {
      const res = await fetch(`/api/ai/feedback/metrics?days=${driftDays}`);
      if (!res.ok) return [];
      return res.json();
    },
  });

  const driftStats = (() => {
    if (!feedbackMetrics || feedbackMetrics.length === 0) {
      return { totalFeedback: 0, avgRating: 0, positiveRate: 0, negativeRate: 0 };
    }
    const totalFeedback = feedbackMetrics.reduce((s, m) => s + m.totalFeedback, 0);
    const weightedRating = totalFeedback > 0
      ? feedbackMetrics.reduce((s, m) => s + m.avgRating * m.totalFeedback, 0) / totalFeedback
      : 0;
    const totalPositive = feedbackMetrics.reduce((s, m) => s + m.positiveFeedback, 0);
    const totalNegative = feedbackMetrics.reduce((s, m) => s + m.negativeFeedback, 0);
    return {
      totalFeedback,
      avgRating: Math.round(weightedRating * 100) / 100,
      positiveRate: totalFeedback > 0 ? Math.round((totalPositive / totalFeedback) * 10000) / 100 : 0,
      negativeRate: totalFeedback > 0 ? Math.round((totalNegative / totalFeedback) * 10000) / 100 : 0,
    };
  })();

  const uncorrelatedAlerts = alerts?.filter(
    (a) => a.status === "new" || a.status === "triaged"
  );

  const pendingAlertsCount = alerts?.filter(a => a.status === "new").length ?? 0;
  const selectedAlert = alerts?.find(a => a.id === triageAlertId);

  const correlate = useMutation({
    mutationFn: async () => {
      const body = correlationMode === "select" && selectedAlertIds.length > 0
        ? { alertIds: selectedAlertIds }
        : {};
      const res = await apiRequest("POST", "/api/ai/correlate", body);
      return res.json();
    },
    onSuccess: (data) => {
      setCorrelationResult(data);
      toast({ title: "AI Correlation Complete", description: `Found ${data.correlatedGroups.length} correlated group(s)` });
    },
    onError: (error: any) => {
      toast({ title: "AI Correlation Failed", description: error.message, variant: "destructive" });
    },
  });

  const applyCorrelation = useMutation({
    mutationFn: async (group: CorrelationGroup) => {
      const res = await apiRequest("POST", "/api/ai/correlate/apply", { group });
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: "Incident Created", description: `Created incident: ${data.title}` });
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
    },
    onError: (error: any) => {
      toast({ title: "Failed to Apply", description: error.message, variant: "destructive" });
    },
  });

  const triage = useMutation({
    mutationFn: async (alertId: string) => {
      const res = await apiRequest("POST", `/api/ai/triage/${alertId}`, {});
      return res.json();
    },
    onSuccess: (data) => {
      setTriageResult(data);
      toast({ title: "AI Triage Complete", description: "Alert analysis finished" });
    },
    onError: (error: any) => {
      toast({ title: "AI Triage Failed", description: error.message, variant: "destructive" });
    },
  });

  const toggleAlertSelection = (alertId: string) => {
    setSelectedAlertIds((prev) =>
      prev.includes(alertId)
        ? prev.filter((id) => id !== alertId)
        : [...prev, alertId]
    );
  };

  const submitFeedback = useMutation({
    mutationFn: async (payload: { rating: number; outcome: string; comment: string }) => {
      const res = await apiRequest("POST", "/api/ai/feedback", {
        resourceType: "triage",
        resourceId: triageAlertId,
        rating: payload.rating,
        feedbackType: payload.outcome,
        comment: payload.comment,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Feedback submitted", description: "Your feedback helps improve AI accuracy" });
      setFeedbackRating(null);
      setFeedbackComment("");
      setFeedbackOutcome(null);
      queryClient.invalidateQueries({ queryKey: ["/api/ai/feedback/metrics"] });
    },
    onError: (error: any) => {
      toast({ title: "Feedback failed", description: error.message, variant: "destructive" });
    },
  });

  const handleRunTriage = () => {
    if (!triageAlertId) return;
    setTriageResult(null);
    setFeedbackRating(null);
    setFeedbackComment("");
    setFeedbackOutcome(null);
    triage.mutate(triageAlertId);
  };

  const shortModelName = config?.model
    ? config.model.length > 20
      ? config.model.slice(0, 18) + "..."
      : config.model
    : "—";

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <Brain className="h-6 w-6 text-primary" />
            <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">AI Correlation Engine</span></h1>
          </div>
          <div className="text-sm text-muted-foreground mt-1">
            {configLoading ? (
              <Skeleton className="h-4 w-64 inline-block" />
            ) : config ? (
              <span data-testid="text-model-info">{config.backend} / {config.model} ({config.region})</span>
            ) : (
              "AI engine configuration unavailable"
            )}
          </div>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        {health && (
          <Badge
            variant={health.status === "healthy" ? "default" : "destructive"}
            data-testid="badge-health-status"
          >
            {health.status === "healthy" ? (
              <CheckCircle2 className="h-3 w-3 mr-1" />
            ) : (
              <XCircle className="h-3 w-3 mr-1" />
            )}
            {health.status}
          </Badge>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="section-hero-stats">
        <Card className="relative overflow-visible" data-testid="stat-alerts-pending">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-primary/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Alerts Pending</div>
              <AlertTriangle className="h-3.5 w-3.5 text-primary/60" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums" data-testid="text-alerts-pending-count">
              {alertsLoading ? <Skeleton className="h-7 w-10" /> : pendingAlertsCount}
            </div>
          </CardContent>
        </Card>
        <Card className="relative overflow-visible" data-testid="stat-analyses-run">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-primary/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">AI Analyses Run</div>
              <BarChart3 className="h-3.5 w-3.5 text-primary/60" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums" data-testid="text-analyses-count">—</div>
          </CardContent>
        </Card>
        <Card className="relative overflow-visible" data-testid="stat-avg-confidence">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-primary/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Avg Confidence</div>
              <Target className="h-3.5 w-3.5 text-primary/60" />
            </div>
            <div className="text-2xl font-bold mt-1 tabular-nums" data-testid="text-avg-confidence">—</div>
          </CardContent>
        </Card>
        <Card className="relative overflow-visible" data-testid="stat-model">
          <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-primary/5 to-primary/10 pointer-events-none" />
          <CardContent className="p-4 relative">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Model</div>
              <Cpu className="h-3.5 w-3.5 text-primary/60" />
            </div>
            <div className="text-sm font-bold mt-1 truncate" data-testid="text-model-short">
              {configLoading ? <Skeleton className="h-5 w-20" /> : shortModelName}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card data-testid="card-ai-health">
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">AI Engine Health</CardTitle>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => refetchHealth()}
            disabled={healthLoading}
            data-testid="button-check-health"
          >
            {healthLoading ? <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> : <Zap className="h-3 w-3 mr-1.5" />}
            Check Health
          </Button>
        </CardHeader>
        <CardContent>
          {healthLoading ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="space-y-1">
                  <Skeleton className="h-3 w-16" />
                  <Skeleton className="h-5 w-24" />
                </div>
              ))}
            </div>
          ) : health ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Status</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <div className={`w-2 h-2 rounded-full ${health.status === "healthy" ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`} />
                    <span className="text-sm font-medium capitalize" data-testid="text-health-status">{health.status}</span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Backend</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Server className="h-3 w-3 text-muted-foreground" />
                    <span className="text-sm font-medium" data-testid="text-health-backend">{health.backend}</span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Region</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <MapPin className="h-3 w-3 text-muted-foreground" />
                    <span className="text-sm font-medium" data-testid="text-health-region">{health.region}</span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Latency</div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Zap className="h-3 w-3 text-muted-foreground" />
                    <span className="text-sm font-medium tabular-nums" data-testid="text-health-latency">{health.latencyMs}ms</span>
                  </div>
                </div>
                {health.error && (
                  <div className="col-span-full">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Error</div>
                    <p className="text-xs text-destructive mt-0.5" data-testid="text-health-error">{health.error}</p>
                  </div>
                )}
              </div>
              {health.model && (
                <div className="flex items-center gap-2 pt-2 border-t">
                  <Brain className="h-3.5 w-3.5 text-primary" />
                  <span className="text-xs text-muted-foreground">Active Model:</span>
                  <span className="text-xs font-semibold" data-testid="text-health-model">{health.model}</span>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4">Health data unavailable</p>
          )}
        </CardContent>
      </Card>

      <Card data-testid="card-correlation-runner" className="border-primary/20">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-medium">Run Alert Correlation</CardTitle>
          </div>
          <CardDescription className="text-xs">
            Analyze security alerts using AI to identify attack chains, lateral movement, and coordinated campaigns
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={correlationMode} onValueChange={setCorrelationMode}>
            <TabsList data-testid="tabs-correlation-mode">
              <TabsTrigger value="all" data-testid="tab-all-alerts">All New Alerts</TabsTrigger>
              <TabsTrigger value="select" data-testid="tab-select-alerts">Select Alerts</TabsTrigger>
            </TabsList>
            <TabsContent value="all">
              <p className="text-xs text-muted-foreground">
                Correlate all alerts with status "new" or "triaged" ({uncorrelatedAlerts?.length ?? 0} alerts available)
              </p>
            </TabsContent>
            <TabsContent value="select">
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {alertsLoading ? (
                  Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-md bg-muted/30">
                      <Skeleton className="h-4 w-4" />
                      <Skeleton className="h-4 w-48" />
                    </div>
                  ))
                ) : uncorrelatedAlerts && uncorrelatedAlerts.length > 0 ? (
                  uncorrelatedAlerts.map((alert) => (
                    <label
                      key={alert.id}
                      className="flex items-center gap-3 p-2 rounded-md hover-elevate cursor-pointer"
                      data-testid={`checkbox-alert-${alert.id}`}
                    >
                      <Checkbox
                        checked={selectedAlertIds.includes(alert.id)}
                        onCheckedChange={() => toggleAlertSelection(alert.id)}
                      />
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                        <span className="text-sm truncate">{alert.title}</span>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                    </label>
                  ))
                ) : (
                  <p className="text-xs text-muted-foreground text-center py-4">No uncorrelated alerts available</p>
                )}
              </div>
              {selectedAlertIds.length > 0 && (
                <p className="text-xs text-muted-foreground mt-2">{selectedAlertIds.length} alert(s) selected</p>
              )}
            </TabsContent>
          </Tabs>
          <Button
            onClick={() => correlate.mutate()}
            disabled={correlate.isPending || (correlationMode === "select" && selectedAlertIds.length === 0)}
            data-testid="button-run-correlation"
          >
            {correlate.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Brain className="h-4 w-4 mr-2" />
            )}
            {correlate.isPending ? "Analyzing..." : "Run Correlation"}
          </Button>

          {correlate.isPending && (
            <div className="flex items-center gap-3 py-4" data-testid="correlation-loading">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "0ms" }} />
                <div className="w-2 h-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "150ms" }} />
                <div className="w-2 h-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "300ms" }} />
              </div>
              <span className="text-sm text-muted-foreground">AI is analyzing alert patterns and correlations...</span>
            </div>
          )}
        </CardContent>
      </Card>

      {correlationResult && (
        <div className="space-y-4" data-testid="section-correlation-results">
          <Card className="border-primary/30">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-primary" />
                  Correlation Results
                </CardTitle>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setCorrelationResult(null)}
                  data-testid="button-dismiss-correlation"
                >
                  <XCircle className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Overall Assessment</div>
                <p className="text-sm" data-testid="text-overall-assessment">{correlationResult.overallAssessment}</p>
              </div>
              {correlationResult.threatLandscape && (
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Threat Landscape</div>
                  <p className="text-xs text-muted-foreground" data-testid="text-threat-landscape">{correlationResult.threatLandscape}</p>
                </div>
              )}
            </CardContent>
          </Card>

          {correlationResult.correlatedGroups.map((group, i) => (
            <Card key={i} data-testid={`card-correlation-group-${i}`}>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between gap-2 flex-wrap">
                  <div>
                    <CardTitle className="text-sm font-medium">{group.groupName}</CardTitle>
                    <CardDescription className="text-xs mt-0.5">{group.suggestedIncidentTitle}</CardDescription>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <SeverityBadge severity={group.severity} />
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-muted-foreground">Confidence</span>
                    <span className="font-medium tabular-nums" data-testid={`text-confidence-${i}`}>{Math.round(group.confidence * 100)}%</span>
                  </div>
                  <Progress value={group.confidence * 100} className="h-2" data-testid={`progress-confidence-${i}`} />
                </div>

                {group.mitreTactics.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">MITRE ATT&CK Tactics</div>
                    <div className="flex flex-wrap gap-1.5">
                      {group.mitreTactics.map((t, j) => (
                        <Badge key={j} variant="secondary" className="text-[10px]" data-testid={`badge-tactic-${i}-${j}`}>
                          <Crosshair className="h-2.5 w-2.5 mr-1" />
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {group.mitreTechniques.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Techniques</div>
                    <div className="flex flex-wrap gap-1.5">
                      {group.mitreTechniques.map((t, j) => (
                        <Badge key={j} variant="outline" className="text-[10px] font-mono" data-testid={`badge-technique-${i}-${j}`}>{t}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {group.killChainPhases.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Kill Chain Phases</div>
                    <div className="flex flex-wrap gap-1.5">
                      {group.killChainPhases.map((phase, j) => (
                        <Badge key={j} variant="secondary" className="text-[10px]" data-testid={`badge-killchain-${i}-${j}`}>
                          <Target className="h-2.5 w-2.5 mr-1" />
                          {phase}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {group.diamondModel && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Diamond Model</div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div>
                        <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Users className="h-2.5 w-2.5" /> Adversary
                        </div>
                        <p className="text-xs mt-0.5" data-testid={`text-adversary-${i}`}>{group.diamondModel.adversary || "Unknown"}</p>
                      </div>
                      <div>
                        <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Server className="h-2.5 w-2.5" /> Infrastructure
                        </div>
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {group.diamondModel.infrastructure?.map((inf, j) => (
                            <span key={j} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted" data-testid={`text-infra-${i}-${j}`}>{inf}</span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Shield className="h-2.5 w-2.5" /> Capability
                        </div>
                        <p className="text-xs mt-0.5" data-testid={`text-capability-${i}`}>{group.diamondModel.capability || "Unknown"}</p>
                      </div>
                      <div>
                        <div className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <AlertTriangle className="h-2.5 w-2.5" /> Victim
                        </div>
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {group.diamondModel.victim?.map((v, j) => (
                            <span key={j} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted" data-testid={`text-victim-${i}-${j}`}>{v}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Reasoning</div>
                  <p className="text-xs text-muted-foreground" data-testid={`text-reasoning-${i}`}>{group.reasoning}</p>
                </div>

                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Alert IDs ({group.alertIds.length})</div>
                  <div className="flex flex-wrap gap-1">
                    {group.alertIds.map((id, j) => (
                      <span key={j} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted" data-testid={`text-alert-id-${i}-${j}`}>{id}</span>
                    ))}
                  </div>
                </div>

                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => applyCorrelation.mutate(group)}
                  disabled={applyCorrelation.isPending}
                  data-testid={`button-create-incident-${i}`}
                >
                  {applyCorrelation.isPending ? (
                    <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />
                  ) : (
                    <CheckCircle2 className="h-3 w-3 mr-1.5" />
                  )}
                  Create Incident
                </Button>
              </CardContent>
            </Card>
          ))}

          {correlationResult.uncorrelatedAlertIds.length > 0 && (
            <Card data-testid="card-uncorrelated-alerts">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Uncorrelated Alerts ({correlationResult.uncorrelatedAlertIds.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {correlationResult.uncorrelatedAlertIds.map((id, j) => (
                    <span key={j} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted">{id}</span>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      <Card data-testid="card-triage">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm font-medium">AI Alert Triage</CardTitle>
          </div>
          <CardDescription className="text-xs">
            Perform deep AI analysis on a single alert for severity assessment, kill chain mapping, and actionable recommendations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <Popover open={alertPickerOpen} onOpenChange={setAlertPickerOpen}>
              <PopoverTrigger asChild>
                <Button
                  variant="outline"
                  className="w-full max-w-md justify-between"
                  data-testid="select-triage-alert"
                >
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <Search className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                    <span className={`truncate ${!selectedAlert ? "text-muted-foreground" : ""}`}>
                      {selectedAlert ? selectedAlert.title : "Search alerts..."}
                    </span>
                  </div>
                  <ChevronsUpDown className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0 ml-2" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-[400px] p-0" align="start">
                <Command>
                  <CommandInput placeholder="Search alerts by title..." data-testid="input-search-alerts" />
                  <CommandList>
                    <CommandEmpty>No alerts found.</CommandEmpty>
                    <CommandGroup>
                      {alerts?.map((alert) => (
                        <CommandItem
                          key={alert.id}
                          value={alert.title}
                          onSelect={() => {
                            setTriageAlertId(alert.id);
                            setAlertPickerOpen(false);
                          }}
                          className="cursor-pointer"
                          data-testid={`option-triage-alert-${alert.id}`}
                        >
                          <div className="flex items-center gap-2 min-w-0 flex-1">
                            <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                            <span className="truncate text-sm">{alert.title}</span>
                            <SeverityBadge severity={alert.severity} />
                          </div>
                          {triageAlertId === alert.id && (
                            <CheckCircle2 className="h-3.5 w-3.5 text-primary flex-shrink-0" />
                          )}
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
            <Button
              onClick={handleRunTriage}
              disabled={!triageAlertId || triage.isPending}
              data-testid="button-run-triage"
            >
              {triage.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Sparkles className="h-4 w-4 mr-2" />
              )}
              {triage.isPending ? "Analyzing..." : "Run Triage"}
            </Button>
          </div>

          {triage.isPending && (
            <div className="flex items-center gap-3 py-4" data-testid="triage-loading">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "0ms" }} />
                <div className="w-2 h-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "150ms" }} />
                <div className="w-2 h-2 rounded-full bg-primary animate-bounce" style={{ animationDelay: "300ms" }} />
              </div>
              <span className="text-sm text-muted-foreground">Performing deep analysis on alert...</span>
            </div>
          )}

          {triageResult && !triage.isPending && (
            <div className="space-y-4 pt-2" data-testid="section-triage-results">
              {triageResult.threatIntelSources && triageResult.threatIntelSources.length > 0 && (
                <div className="flex items-center gap-2 flex-wrap" data-testid="triage-intel-sources">
                  <Badge variant="outline" className="text-[10px] gap-1 border-green-500/50 text-green-500">
                    <Shield className="h-3 w-3" />
                    Intel-Enriched
                  </Badge>
                  {triageResult.threatIntelSources.map((source, i) => (
                    <Badge key={i} variant="secondary" className="text-[10px]">
                      {source}
                    </Badge>
                  ))}
                </div>
              )}
              <ThreatMeter severity={triageResult.severity} priority={triageResult.priority} />

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Severity</div>
                  <div className="mt-1">
                    <SeverityBadge severity={triageResult.severity} />
                  </div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Priority</div>
                  <div className="text-sm font-bold mt-1" data-testid="text-triage-priority">P{triageResult.priority}</div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Category</div>
                  <div className="text-xs mt-1" data-testid="text-triage-category">{triageResult.category}</div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Kill Chain Phase</div>
                  <div className="text-xs mt-1" data-testid="text-triage-killchain">{triageResult.killChainPhase}</div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">MITRE Tactic</div>
                  {triageResult.mitreTactic && (
                    <Badge variant="secondary" className="text-[10px]" data-testid="badge-triage-tactic">
                      <Crosshair className="h-2.5 w-2.5 mr-1" />
                      {triageResult.mitreTactic}
                    </Badge>
                  )}
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">MITRE Technique</div>
                  {triageResult.mitreTechnique && (
                    <Badge variant="outline" className="text-[10px] font-mono" data-testid="badge-triage-technique">
                      {triageResult.mitreTechnique}
                    </Badge>
                  )}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-muted-foreground">False Positive Likelihood</span>
                  <span className="font-medium tabular-nums" data-testid="text-triage-fp">{Math.round(triageResult.falsePositiveLikelihood * 100)}%</span>
                </div>
                <Progress value={triageResult.falsePositiveLikelihood * 100} className="h-2" data-testid="progress-false-positive" />
                {triageResult.falsePositiveReasoning && (
                  <p className="text-[10px] text-muted-foreground mt-1" data-testid="text-fp-reasoning">{triageResult.falsePositiveReasoning}</p>
                )}
              </div>

              <div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Reasoning</div>
                <p className="text-xs text-muted-foreground" data-testid="text-triage-reasoning">{triageResult.reasoning}</p>
              </div>

              <div className="rounded-md bg-primary/5 border border-primary/20 p-3">
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Recommended Action</div>
                <p className="text-sm font-medium" data-testid="text-triage-action">{triageResult.recommendedAction}</p>
              </div>

              {triageResult.relatedIocs && triageResult.relatedIocs.length > 0 && (
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Related IOCs</div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs" data-testid="table-iocs">
                      <thead>
                        <tr className="border-b">
                          <th className="px-2 py-1.5 text-left text-muted-foreground font-medium">Type</th>
                          <th className="px-2 py-1.5 text-left text-muted-foreground font-medium">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {triageResult.relatedIocs.map((ioc, j) => (
                          <tr key={j} className="border-b last:border-0" data-testid={`row-ioc-${j}`}>
                            <td className="px-2 py-1.5">
                              <Badge variant="outline" className="text-[10px]">{ioc.type}</Badge>
                            </td>
                            <td className="px-2 py-1.5 font-mono">{ioc.value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Escalation Required</div>
                  <div className="flex items-center gap-1.5" data-testid="text-escalation">
                    {triageResult.escalationRequired ? (
                      <>
                        <AlertTriangle className="h-3 w-3 text-orange-500" />
                        <span className="text-xs font-medium text-orange-500">Yes - Escalation Needed</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span className="text-xs font-medium text-emerald-500">No Escalation Required</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">NIST Classification</div>
                  <p className="text-xs" data-testid="text-nist">{triageResult.nistClassification}</p>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Containment Advice</div>
                  <p className="text-xs text-muted-foreground" data-testid="text-containment">{triageResult.containmentAdvice}</p>
                </div>
              </div>

              <Card className="border-primary/20 bg-primary/5" data-testid="card-explainability">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Eye className="h-4 w-4 text-primary" />
                      <CardTitle className="text-sm font-medium">AI Explainability</CardTitle>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setShowExplainability(!showExplainability)}
                      data-testid="button-toggle-explainability"
                    >
                      {showExplainability ? "Hide" : "Show"}
                    </Button>
                  </div>
                  <CardDescription className="text-xs">Signals and confidence rationale behind this AI decision</CardDescription>
                </CardHeader>
                {showExplainability && (
                  <CardContent className="space-y-4">
                    <div className="space-y-2" data-testid="explainability-signals">
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Decision Signals</div>
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-red-500" />
                            <span className="text-xs">Severity Assessment</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium">{triageResult.severity}</span>
                            <Badge variant="outline" className="text-[10px]">P{triageResult.priority}</Badge>
                          </div>
                        </div>
                        <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-orange-500" />
                            <span className="text-xs">False Positive Analysis</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium tabular-nums">{Math.round(triageResult.falsePositiveLikelihood * 100)}% likely FP</span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-blue-500" />
                            <span className="text-xs">MITRE ATT&CK Mapping</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            {triageResult.mitreTactic && <Badge variant="secondary" className="text-[10px]">{triageResult.mitreTactic}</Badge>}
                            {triageResult.mitreTechnique && <Badge variant="outline" className="text-[10px] font-mono">{triageResult.mitreTechnique}</Badge>}
                          </div>
                        </div>
                        <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-purple-500" />
                            <span className="text-xs">Kill Chain Position</span>
                          </div>
                          <span className="text-xs font-medium">{triageResult.killChainPhase}</span>
                        </div>
                        <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-emerald-500" />
                            <span className="text-xs">Threat Category</span>
                          </div>
                          <span className="text-xs font-medium">{triageResult.category}</span>
                        </div>
                        {triageResult.escalationRequired && (
                          <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                            <div className="flex items-center gap-2">
                              <div className="w-2 h-2 rounded-full bg-yellow-500" />
                              <span className="text-xs">Escalation Flag</span>
                            </div>
                            <Badge variant="destructive" className="text-[10px]">Required</Badge>
                          </div>
                        )}
                        {triageResult.relatedIocs && triageResult.relatedIocs.length > 0 && (
                          <div className="flex items-center justify-between gap-2 rounded-md bg-background p-2">
                            <div className="flex items-center gap-2">
                              <div className="w-2 h-2 rounded-full bg-cyan-500" />
                              <span className="text-xs">IOC Correlation</span>
                            </div>
                            <span className="text-xs font-medium">{triageResult.relatedIocs.length} IOC(s) linked</span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div data-testid="explainability-rationale">
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Confidence Rationale</div>
                      <p className="text-xs text-muted-foreground">{triageResult.reasoning}</p>
                      {triageResult.falsePositiveReasoning && (
                        <p className="text-xs text-muted-foreground mt-1 italic">FP reasoning: {triageResult.falsePositiveReasoning}</p>
                      )}
                    </div>
                  </CardContent>
                )}
              </Card>

              <Card className="border-amber-500/20" data-testid="card-ai-feedback">
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-2">
                    <MessageSquare className="h-4 w-4 text-amber-500" />
                    <CardTitle className="text-sm font-medium">AI Feedback</CardTitle>
                  </div>
                  <CardDescription className="text-xs">Rate this triage result to improve future accuracy</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2" data-testid="feedback-actions">
                    <Button
                      size="sm"
                      variant={feedbackOutcome === "approve" ? "default" : "outline"}
                      onClick={() => { setFeedbackOutcome("approve"); setFeedbackRating(5); }}
                      className={feedbackOutcome === "approve" ? "bg-emerald-600 hover:bg-emerald-700" : ""}
                      data-testid="button-feedback-approve"
                    >
                      <ThumbsUp className="h-3 w-3 mr-1.5" />
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant={feedbackOutcome === "reject" ? "default" : "outline"}
                      onClick={() => { setFeedbackOutcome("reject"); setFeedbackRating(1); }}
                      className={feedbackOutcome === "reject" ? "bg-red-600 hover:bg-red-700" : ""}
                      data-testid="button-feedback-reject"
                    >
                      <ThumbsDown className="h-3 w-3 mr-1.5" />
                      Reject
                    </Button>
                    <Button
                      size="sm"
                      variant={feedbackOutcome === "correct" ? "default" : "outline"}
                      onClick={() => { setFeedbackOutcome("correct"); setFeedbackRating(3); }}
                      className={feedbackOutcome === "correct" ? "bg-amber-600 hover:bg-amber-700" : ""}
                      data-testid="button-feedback-correct"
                    >
                      <RotateCcw className="h-3 w-3 mr-1.5" />
                      Correct
                    </Button>
                  </div>
                  {feedbackOutcome && (
                    <div className="space-y-2" data-testid="feedback-form">
                      <textarea
                        className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                        rows={2}
                        placeholder={feedbackOutcome === "correct" ? "Describe the correct outcome..." : "Optional comment..."}
                        value={feedbackComment}
                        onChange={(e) => setFeedbackComment(e.target.value)}
                        data-testid="input-feedback-comment"
                      />
                      <Button
                        size="sm"
                        onClick={() => {
                          if (feedbackRating !== null && feedbackOutcome) {
                            submitFeedback.mutate({ rating: feedbackRating, outcome: feedbackOutcome, comment: feedbackComment });
                          }
                        }}
                        disabled={submitFeedback.isPending || !feedbackOutcome}
                        data-testid="button-submit-feedback"
                      >
                        {submitFeedback.isPending ? <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> : <CheckCircle2 className="h-3 w-3 mr-1.5" />}
                        Submit Feedback
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </CardContent>
      </Card>

      <Card data-testid="card-model-drift">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between gap-2 flex-wrap">
            <div>
              <div className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-primary" />
                <CardTitle className="text-sm font-medium">Model Drift Dashboard</CardTitle>
              </div>
              <CardDescription className="text-xs mt-0.5">
                AI feedback quality trends over time
              </CardDescription>
            </div>
            <Select value={driftDays} onValueChange={setDriftDays}>
              <SelectTrigger className="w-[120px]" data-testid="select-drift-days">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7">7 days</SelectItem>
                <SelectItem value="14">14 days</SelectItem>
                <SelectItem value="30">30 days</SelectItem>
                <SelectItem value="60">60 days</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {metricsLoading ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="rounded-md bg-muted/40 p-3 space-y-1">
                    <Skeleton className="h-3 w-16" />
                    <Skeleton className="h-6 w-12" />
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-6 w-full" />
                ))}
              </div>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Feedback</div>
                    <BarChart3 className="h-3 w-3 text-muted-foreground" />
                  </div>
                  <div className="text-xl font-bold mt-1 tabular-nums" data-testid="text-total-feedback">
                    {driftStats.totalFeedback}
                  </div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Avg Rating</div>
                    {driftStats.avgRating >= 3.5 ? (
                      <TrendingUp className="h-3 w-3 text-emerald-500" />
                    ) : (
                      <TrendingDown className="h-3 w-3 text-red-500" />
                    )}
                  </div>
                  <div className="text-xl font-bold mt-1 tabular-nums" data-testid="text-avg-rating">
                    {driftStats.avgRating.toFixed(2)}
                  </div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Positive Rate</div>
                    <ThumbsUp className="h-3 w-3 text-emerald-500" />
                  </div>
                  <div className="text-xl font-bold mt-1 tabular-nums" data-testid="text-positive-rate">
                    {driftStats.positiveRate}%
                  </div>
                </div>
                <div className="rounded-md bg-muted/40 p-3">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Negative Rate</div>
                    <ThumbsDown className="h-3 w-3 text-red-500" />
                  </div>
                  <div className="text-xl font-bold mt-1 tabular-nums" data-testid="text-negative-rate">
                    {driftStats.negativeRate}%
                  </div>
                </div>
              </div>

              <div data-testid="chart-drift-trend">
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Rating Trend</div>
                {feedbackMetrics && feedbackMetrics.length > 0 ? (
                  <div className="space-y-1">
                    {feedbackMetrics.map((m) => {
                      const barWidth = (m.avgRating / 5) * 100;
                      const barColor =
                        m.avgRating >= 4
                          ? "bg-emerald-500"
                          : m.avgRating >= 3
                          ? "bg-yellow-500"
                          : "bg-red-500";
                      return (
                        <div key={m.date} className="flex items-center gap-2 text-xs">
                          <span className="w-20 text-muted-foreground tabular-nums flex-shrink-0 text-right">
                            {m.date.slice(5)}
                          </span>
                          <div className="flex-1 h-4 rounded bg-muted/40 overflow-hidden relative">
                            <div
                              className={`h-full rounded ${barColor} transition-all duration-300`}
                              style={{ width: `${barWidth}%` }}
                            />
                          </div>
                          <span className="w-8 tabular-nums font-medium text-right flex-shrink-0">
                            {m.avgRating.toFixed(1)}
                          </span>
                          <span className="w-8 text-muted-foreground tabular-nums text-right flex-shrink-0" title="Total feedback">
                            {m.totalFeedback}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">
                    No feedback data available for the selected period
                  </p>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
