import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { AlertTriangle, Search, Brain, Loader2, Sparkles, CheckCircle2, XCircle, Download } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useState } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { SeverityBadge, AlertStatusBadge } from "@/components/security-badges";
import type { Alert } from "@shared/schema";

interface CorrelationGroup {
  groupName: string;
  alertIds: string[];
  confidence: number;
  reasoning: string;
  suggestedIncidentTitle: string;
  severity: string;
  mitreTactics: string[];
  mitreTechniques: string[];
}

interface CorrelationResult {
  correlatedGroups: CorrelationGroup[];
  uncorrelatedAlertIds: string[];
  overallAssessment: string;
}

interface TriageResult {
  severity: string;
  priority: number;
  category: string;
  recommendedAction: string;
  reasoning: string;
  mitreTactic: string;
  mitreTechnique: string;
  falsePositiveLikelihood: number;
  relatedIocs: string[];
}

export default function AlertsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [correlationResult, setCorrelationResult] = useState<CorrelationResult | null>(null);
  const [selectedAlertForTriage, setSelectedAlertForTriage] = useState<string | null>(null);
  const [triageResult, setTriageResult] = useState<TriageResult | null>(null);
  const { toast } = useToast();

  const { data: alerts, isLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const correlate = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/ai/correlate", {});
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

  const triage = useMutation({
    mutationFn: async (alertId: string) => {
      const res = await apiRequest("POST", `/api/ai/triage/${alertId}`, {});
      return res.json();
    },
    onSuccess: (data) => {
      setTriageResult(data);
    },
    onError: (error: any) => {
      toast({ title: "AI Triage Failed", description: error.message, variant: "destructive" });
      setSelectedAlertForTriage(null);
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

  const filtered = alerts?.filter((alert) => {
    const matchesSearch = !search ||
      alert.title.toLowerCase().includes(search.toLowerCase()) ||
      alert.source.toLowerCase().includes(search.toLowerCase()) ||
      alert.description?.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const severities = ["all", "critical", "high", "medium", "low"];

  const handleTriageClick = (alertId: string) => {
    setSelectedAlertForTriage(alertId);
    setTriageResult(null);
    triage.mutate(alertId);
  };

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Alerts</span></h1>
          <p className="text-sm text-muted-foreground mt-1">All security alerts from integrated tools</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Button
          onClick={() => correlate.mutate()}
          disabled={correlate.isPending}
          data-testid="button-ai-correlate"
        >
          {correlate.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Brain className="h-4 w-4 mr-2" />
          )}
          {correlate.isPending ? "Analyzing..." : "AI Correlate Alerts"}
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-alerts"
          />
        </div>
        <Button variant="outline" size="icon" data-testid="button-export-alerts" onClick={() => window.open('/api/export/alerts', '_blank')}>
          <Download className="h-4 w-4" />
        </Button>
        <div className="flex items-center gap-1">
          {severities.map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
                severityFilter === sev
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover-elevate"
              }`}
              data-testid={`filter-${sev}`}
            >
              {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {correlationResult && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-primary" />
                AI Correlation Results
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
            <p className="text-xs text-muted-foreground mt-1" data-testid="text-correlation-assessment">{correlationResult.overallAssessment}</p>
          </CardHeader>
          <CardContent className="space-y-3">
            {correlationResult.correlatedGroups.map((group, i) => (
              <div key={i} className="p-3 rounded-md bg-muted/30 space-y-2" data-testid={`correlation-group-${i}`}>
                <div className="flex items-start justify-between gap-2 flex-wrap">
                  <div>
                    <div className="text-sm font-medium">{group.suggestedIncidentTitle}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">{group.reasoning}</div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <SeverityBadge severity={group.severity} />
                    <span className="text-xs text-primary font-medium">{Math.round(group.confidence * 100)}%</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] text-muted-foreground">{group.alertIds.length} alerts</span>
                  {group.mitreTactics.map((t, j) => (
                    <span key={j} className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px]">{t}</span>
                  ))}
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => applyCorrelation.mutate(group)}
                  disabled={applyCorrelation.isPending}
                  data-testid={`button-apply-correlation-${i}`}
                >
                  {applyCorrelation.isPending ? (
                    <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />
                  ) : (
                    <CheckCircle2 className="h-3 w-3 mr-1.5" />
                  )}
                  Create Incident
                </Button>
              </div>
            ))}
            {correlationResult.uncorrelatedAlertIds.length > 0 && (
              <p className="text-xs text-muted-foreground">{correlationResult.uncorrelatedAlertIds.length} alert(s) did not correlate to any group</p>
            )}
          </CardContent>
        </Card>
      )}

      {selectedAlertForTriage && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Brain className="h-4 w-4 text-primary" />
                AI Triage Analysis
              </CardTitle>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => { setSelectedAlertForTriage(null); setTriageResult(null); }}
                data-testid="button-dismiss-triage"
              >
                <XCircle className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {triage.isPending ? (
              <div className="flex items-center gap-2 py-4">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                <span className="text-sm text-muted-foreground">Analyzing alert...</span>
              </div>
            ) : triageResult ? (
              <div className="space-y-3" data-testid="triage-result">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">Severity</div>
                    <SeverityBadge severity={triageResult.severity} />
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">Priority</div>
                    <div className="text-sm font-bold">P{triageResult.priority}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">Category</div>
                    <div className="text-xs">{triageResult.category}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">False Positive</div>
                    <div className="text-xs">{Math.round(triageResult.falsePositiveLikelihood * 100)}%</div>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase mb-1">Recommended Action</div>
                  <div className="text-sm text-primary font-medium" data-testid="text-triage-action">{triageResult.recommendedAction}</div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase mb-1">Reasoning</div>
                  <div className="text-xs text-muted-foreground" data-testid="text-triage-reasoning">{triageResult.reasoning}</div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {triageResult.mitreTactic && <span className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px]">{triageResult.mitreTactic}</span>}
                  {triageResult.mitreTechnique && <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">{triageResult.mitreTechnique}</span>}
                </div>
                {triageResult.relatedIocs && triageResult.relatedIocs.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase mb-1">IOCs</div>
                    <div className="flex flex-wrap gap-1">
                      {triageResult.relatedIocs.map((ioc, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">{ioc}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : null}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-left">
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Alert</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden md:table-cell">Source</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Severity</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">Category</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">MITRE Tactic</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">AI</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-4 py-3"><Skeleton className="h-4 w-48" /></td>
                      <td className="px-4 py-3 hidden md:table-cell"><Skeleton className="h-4 w-24" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-20" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-28" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                    </tr>
                  ))
                ) : filtered && filtered.length > 0 ? (
                  filtered.map((alert) => (
                    <tr
                      key={alert.id}
                      className="border-b last:border-0 hover-elevate cursor-pointer"
                      onClick={() => navigate('/alerts/' + alert.id)}
                      data-testid={`row-alert-${alert.id}`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                          <div>
                            <div className="text-sm font-medium">{alert.title}</div>
                            <div className="text-xs text-muted-foreground truncate max-w-[300px]">{alert.description}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 hidden md:table-cell">
                        <span className="text-xs text-muted-foreground">{alert.source}</span>
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        <span className="text-xs text-muted-foreground">{alert.category?.replace(/_/g, " ") || "-"}</span>
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        <span className="text-xs text-muted-foreground">{alert.mitreTactic || "-"}</span>
                      </td>
                      <td className="px-4 py-3">
                        <AlertStatusBadge status={alert.status} />
                      </td>
                      <td className="px-4 py-3">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={(e) => { e.stopPropagation(); handleTriageClick(alert.id); }}
                          disabled={triage.isPending && selectedAlertForTriage === alert.id}
                          data-testid={`button-triage-${alert.id}`}
                        >
                          {triage.isPending && selectedAlertForTriage === alert.id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Brain className="h-3 w-3" />
                          )}
                        </Button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-sm text-muted-foreground">
                      No alerts found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
