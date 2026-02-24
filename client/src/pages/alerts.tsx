import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { AlertTriangle, Search, Brain, Loader2, Sparkles, CheckCircle2, XCircle, Download, ShieldOff, Eye, EyeOff, Layers, SlidersHorizontal, Plus, Trash2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useEffect, useState, useMemo } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { SeverityBadge, AlertStatusBadge } from "@/components/security-badges";
import type { Alert, SuppressionRule } from "@shared/schema";
import { ChevronLeft, ChevronRight } from "lucide-react";

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

const SCOPE_OPTIONS = ["source", "category", "severity", "title_regex", "entity", "source_ip", "dest_ip", "hostname", "domain"] as const;

export default function AlertsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [correlationResult, setCorrelationResult] = useState<CorrelationResult | null>(null);
  const [selectedAlertForTriage, setSelectedAlertForTriage] = useState<string | null>(null);
  const [triageResult, setTriageResult] = useState<TriageResult | null>(null);
  const [showSuppressionRules, setShowSuppressionRules] = useState(false);
  const [showCreateRule, setShowCreateRule] = useState(false);
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [calibratingAlertId, setCalibratingAlertId] = useState<string | null>(null);
  const [calibrateScore, setCalibrateScore] = useState(50);
  const [calibrateSource, setCalibrateSource] = useState("analyst");
  const [calibrateNotes, setCalibrateNotes] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [ruleScope, setRuleScope] = useState("");
  const [ruleScopeValue, setRuleScopeValue] = useState("");
  const [ruleSource, setRuleSource] = useState("");
  const [ruleSeverity, setRuleSeverity] = useState("");
  const [ruleCategory, setRuleCategory] = useState("");
  const [ruleExpiresAt, setRuleExpiresAt] = useState("");
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkStatus, setBulkStatus] = useState<string>("triaged");
  const [savedViews, setSavedViews] = useState<Array<{ name: string; search: string; severity: string; showSuppressed: boolean }>>([]);
  const [savedViewName, setSavedViewName] = useState("");
  const [focusedAlertId, setFocusedAlertId] = useState<string | null>(null);
  const [queueFilter, setQueueFilter] = useState<"all" | "new" | "aging" | "breached">("all");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;
  const { toast } = useToast();

  useEffect(() => {
    try {
      const raw = localStorage.getItem("alerts.savedViews.v1");
      if (raw) setSavedViews(JSON.parse(raw));
    } catch {
      setSavedViews([]);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("alerts.savedViews.v1", JSON.stringify(savedViews));
  }, [savedViews]);

  const { data: alerts, isLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: suppressionRules, isLoading: rulesLoading } = useQuery<SuppressionRule[]>({
    queryKey: ["/api/suppression-rules"],
    enabled: showSuppressionRules,
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

  const suppressAlert = useMutation({
    mutationFn: async (alertId: string) => {
      const res = await apiRequest("POST", `/api/alerts/${alertId}/suppress`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Alert Suppressed" });
    },
    onError: (error: any) => {
      toast({ title: "Failed to suppress", description: error.message, variant: "destructive" });
    },
  });

  const unsuppressAlert = useMutation({
    mutationFn: async (alertId: string) => {
      const res = await apiRequest("POST", `/api/alerts/${alertId}/unsuppress`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Alert Unsuppressed" });
    },
    onError: (error: any) => {
      toast({ title: "Failed to unsuppress", description: error.message, variant: "destructive" });
    },
  });

  const createRule = useMutation({
    mutationFn: async () => {
      const body: Record<string, any> = {
        name: ruleName,
        scope: ruleScope,
        scopeValue: ruleScopeValue,
        enabled: ruleEnabled,
      };
      if (ruleSource) body.source = ruleSource;
      if (ruleSeverity) body.severity = ruleSeverity;
      if (ruleCategory) body.category = ruleCategory;
      if (ruleExpiresAt) body.expiresAt = new Date(ruleExpiresAt).toISOString();
      const res = await apiRequest("POST", "/api/suppression-rules", body);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/suppression-rules"] });
      toast({ title: "Suppression Rule Created" });
      setShowCreateRule(false);
      setRuleName("");
      setRuleScope("");
      setRuleScopeValue("");
      setRuleSource("");
      setRuleSeverity("");
      setRuleCategory("");
      setRuleExpiresAt("");
      setRuleEnabled(true);
    },
    onError: (error: any) => {
      toast({ title: "Failed to create rule", description: error.message, variant: "destructive" });
    },
  });

  const deleteRule = useMutation({
    mutationFn: async (ruleId: string) => {
      await apiRequest("DELETE", `/api/suppression-rules/${ruleId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/suppression-rules"] });
      toast({ title: "Rule Deleted" });
    },
    onError: (error: any) => {
      toast({ title: "Failed to delete rule", description: error.message, variant: "destructive" });
    },
  });

  const updateConfidence = useMutation({
    mutationFn: async ({ alertId, confidenceScore, confidenceSource, confidenceNotes }: { alertId: string; confidenceScore: number; confidenceSource: string; confidenceNotes: string }) => {
      const res = await apiRequest("PATCH", `/api/alerts/${alertId}/confidence`, { confidenceScore: confidenceScore / 100, confidenceSource, confidenceNotes });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Confidence Updated" });
      setCalibratingAlertId(null);
    },
    onError: (error: any) => {
      toast({ title: "Failed to update confidence", description: error.message, variant: "destructive" });
    },
  });

  const scanDuplicates = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/dedup-clusters/scan", {});
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Duplicate Scan Complete", description: `Found ${data.clustersCreated ?? 0} cluster(s)` });
    },
    onError: (error: any) => {
      toast({ title: "Scan Failed", description: error.message, variant: "destructive" });
    },
  });

  const bulkUpdate = useMutation({
    mutationFn: async (payload: { status?: string; suppressed?: boolean }) => {
      const res = await apiRequest("POST", "/api/alerts/bulk-update", { alertIds: selectedIds, ...payload });
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      toast({ title: "Bulk update complete", description: `Updated ${data.updatedCount || 0} alert(s)` });
      setSelectedIds([]);
    },
    onError: (error: any) => {
      toast({ title: "Bulk update failed", description: error.message, variant: "destructive" });
    },
  });

  const filtered = alerts?.filter((alert) => {
    const matchesSearch = !search ||
      alert.title.toLowerCase().includes(search.toLowerCase()) ||
      alert.source.toLowerCase().includes(search.toLowerCase()) ||
      alert.description?.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    const matchesSuppressed = showSuppressed || !alert.suppressed;
    const ageMs = Date.now() - new Date(alert.createdAt || Date.now()).getTime();
    const queueState = alert.status !== "new"
      ? "other"
      : ageMs >= 72 * 60 * 60 * 1000
        ? "breached"
        : ageMs >= 24 * 60 * 60 * 1000
          ? "aging"
          : "new";
    const matchesQueue = queueFilter === "all" || queueState === queueFilter;
    return matchesSearch && matchesSeverity && matchesSuppressed && matchesQueue;
  });

  const severities = ["all", "critical", "high", "medium", "low"];

  useEffect(() => {
    if (!filtered || filtered.length === 0) return;
    if (!focusedAlertId || !filtered.some((a) => a.id === focusedAlertId)) {
      setFocusedAlertId(filtered[0].id);
    }
  }, [filtered, focusedAlertId]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!filtered || filtered.length === 0) return;
      const target = e.target as HTMLElement;
      if (target?.tagName === "INPUT" || target?.tagName === "TEXTAREA") return;
      const idx = filtered.findIndex((a) => a.id === focusedAlertId);
      if (e.key.toLowerCase() === "j") {
        e.preventDefault();
        setFocusedAlertId(filtered[Math.min(idx < 0 ? 0 : idx + 1, filtered.length - 1)]?.id || null);
      }
      if (e.key.toLowerCase() === "k") {
        e.preventDefault();
        setFocusedAlertId(filtered[Math.max(idx < 0 ? 0 : idx - 1, 0)]?.id || null);
      }
      if (e.key.toLowerCase() === "t" && selectedIds.length > 0) {
        e.preventDefault();
        bulkUpdate.mutate({ status: "triaged" });
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [filtered, focusedAlertId, selectedIds, bulkUpdate]);

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
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            onClick={() => setShowSuppressionRules(!showSuppressionRules)}
            data-testid="button-suppression-rules"
          >
            <ShieldOff className="h-4 w-4 mr-2" />
            Suppression Rules
          </Button>
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
        <Button
          variant="outline"
          size="icon"
          onClick={() => scanDuplicates.mutate()}
          disabled={scanDuplicates.isPending}
          data-testid="button-scan-duplicates"
        >
          {scanDuplicates.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Layers className="h-4 w-4" />}
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
        <div className="flex items-center gap-1">
          {(["all", "new", "aging", "breached"] as const).map((state) => (
            <button
              key={state}
              onClick={() => setQueueFilter(state)}
              className={`px-2.5 py-1 text-xs rounded-md transition-colors ${queueFilter === state ? "bg-primary text-primary-foreground" : "text-muted-foreground hover-elevate"}`}
            >
              {state === "all" ? "Queue: All" : state === "new" ? "Queue: New" : state === "aging" ? "Queue: Aging" : "Queue: Breached"}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={showSuppressed}
            onCheckedChange={setShowSuppressed}
            data-testid="toggle-show-suppressed"
          />
          <label className="text-xs text-muted-foreground flex items-center gap-1 cursor-pointer" onClick={() => setShowSuppressed(!showSuppressed)}>
            {showSuppressed ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
            Show Suppressed
          </label>
        </div>
        <Input placeholder="View name" value={savedViewName} onChange={(e) => setSavedViewName(e.target.value)} className="w-36" />
        <Button
          variant="outline"
          size="sm"
          disabled={!savedViewName.trim()}
          onClick={() => {
            const entry = { name: savedViewName.trim(), search, severity: severityFilter, showSuppressed };
            setSavedViews((prev) => [entry, ...prev.filter((v) => v.name !== entry.name)].slice(0, 8));
            setSavedViewName("");
          }}
        >
          Save View
        </Button>
      </div>

      {savedViews.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {savedViews.map((v) => (
            <Button key={v.name} size="sm" variant="secondary" onClick={() => {
              setSearch(v.search);
              setSeverityFilter(v.severity);
              setShowSuppressed(v.showSuppressed);
            }}>
              {v.name}
            </Button>
          ))}
        </div>
      )}

      {selectedIds.length > 0 && (
        <Card>
          <CardContent className="pt-4 flex items-center flex-wrap gap-2">
            <Badge variant="outline">{selectedIds.length} selected</Badge>
            <Select value={bulkStatus} onValueChange={setBulkStatus}>
              <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="new">New</SelectItem>
                <SelectItem value="triaged">Triaged</SelectItem>
                <SelectItem value="investigating">Investigating</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" onClick={() => bulkUpdate.mutate({ status: bulkStatus })} disabled={bulkUpdate.isPending}>Apply Status</Button>
            <Button size="sm" variant="outline" onClick={() => bulkUpdate.mutate({ suppressed: true })} disabled={bulkUpdate.isPending}>Suppress</Button>
            <Button size="sm" variant="outline" onClick={() => bulkUpdate.mutate({ suppressed: false })} disabled={bulkUpdate.isPending}>Unsuppress</Button>
            <span className="text-xs text-muted-foreground">Shortcuts: J/K focus rows, T set selected to triaged.</span>
          </CardContent>
        </Card>
      )}

      {showSuppressionRules && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <ShieldOff className="h-4 w-4 text-primary" />
                Suppression Rules
              </CardTitle>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowCreateRule(!showCreateRule)}
                  data-testid="button-create-suppression-rule"
                >
                  <Plus className="h-3 w-3 mr-1" />
                  Create Rule
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowSuppressionRules(false)}
                >
                  <XCircle className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {showCreateRule && (
              <div className="p-3 rounded-md bg-muted/30 space-y-3">
                <div className="text-xs font-medium text-muted-foreground uppercase">New Suppression Rule</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <Input
                    placeholder="Rule name"
                    value={ruleName}
                    onChange={(e) => setRuleName(e.target.value)}
                    data-testid="input-rule-name"
                  />
                  <Select value={ruleScope} onValueChange={setRuleScope}>
                    <SelectTrigger data-testid="select-rule-scope">
                      <SelectValue placeholder="Select scope" />
                    </SelectTrigger>
                    <SelectContent>
                      {SCOPE_OPTIONS.map((s) => (
                        <SelectItem key={s} value={s}>{s.replace(/_/g, " ")}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    placeholder="Scope value"
                    value={ruleScopeValue}
                    onChange={(e) => setRuleScopeValue(e.target.value)}
                    data-testid="input-rule-scope-value"
                  />
                  <Input
                    placeholder="Source (optional)"
                    value={ruleSource}
                    onChange={(e) => setRuleSource(e.target.value)}
                    data-testid="input-rule-source"
                  />
                  <Input
                    placeholder="Severity (optional)"
                    value={ruleSeverity}
                    onChange={(e) => setRuleSeverity(e.target.value)}
                    data-testid="input-rule-severity"
                  />
                  <Input
                    placeholder="Category (optional)"
                    value={ruleCategory}
                    onChange={(e) => setRuleCategory(e.target.value)}
                    data-testid="input-rule-category"
                  />
                  <Input
                    type="date"
                    placeholder="Expires at (optional)"
                    value={ruleExpiresAt}
                    onChange={(e) => setRuleExpiresAt(e.target.value)}
                    data-testid="input-rule-expires"
                  />
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={ruleEnabled}
                      onCheckedChange={setRuleEnabled}
                      data-testid="toggle-rule-enabled"
                    />
                    <span className="text-xs text-muted-foreground">Enabled</span>
                  </div>
                </div>
                <Button
                  size="sm"
                  onClick={() => createRule.mutate()}
                  disabled={createRule.isPending || !ruleName || !ruleScope || !ruleScopeValue}
                  data-testid="button-submit-rule"
                >
                  {createRule.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : null}
                  Create Rule
                </Button>
              </div>
            )}
            {rulesLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            ) : suppressionRules && suppressionRules.length > 0 ? (
              suppressionRules.map((rule) => (
                <div key={rule.id} className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/30 flex-wrap">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium flex items-center gap-2 flex-wrap">
                      {rule.name}
                      <Badge variant={rule.enabled ? "default" : "secondary"} className="text-[10px]">
                        {rule.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {rule.scope}: {rule.scopeValue}
                      {rule.source ? ` | Source: ${rule.source}` : ""}
                      {rule.matchCount ? ` | ${rule.matchCount} matches` : ""}
                    </div>
                  </div>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => deleteRule.mutate(rule.id)}
                    disabled={deleteRule.isPending}
                    data-testid={`button-delete-rule-${rule.id}`}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">No suppression rules configured</p>
            )}
          </CardContent>
        </Card>
      )}

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

      {calibratingAlertId && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <SlidersHorizontal className="h-4 w-4 text-primary" />
                Calibrate Confidence
              </CardTitle>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setCalibratingAlertId(null)}
              >
                <XCircle className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap items-end gap-3">
              <div className="space-y-1">
                <label className="text-[10px] text-muted-foreground uppercase">Score (0-100)</label>
                <Input
                  type="number"
                  min={0}
                  max={100}
                  value={calibrateScore}
                  onChange={(e) => setCalibrateScore(Number(e.target.value))}
                  className="w-24"
                  data-testid="input-confidence-score"
                />
              </div>
              <div className="space-y-1">
                <label className="text-[10px] text-muted-foreground uppercase">Source</label>
                <Select value={calibrateSource} onValueChange={setCalibrateSource}>
                  <SelectTrigger className="w-32" data-testid="select-confidence-source">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="analyst">Analyst</SelectItem>
                    <SelectItem value="ai">AI</SelectItem>
                    <SelectItem value="automated">Automated</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1 flex-1 min-w-[150px]">
                <label className="text-[10px] text-muted-foreground uppercase">Notes</label>
                <Input
                  placeholder="Confidence notes..."
                  value={calibrateNotes}
                  onChange={(e) => setCalibrateNotes(e.target.value)}
                  data-testid="input-confidence-notes"
                />
              </div>
              <Button
                size="sm"
                onClick={() => updateConfidence.mutate({ alertId: calibratingAlertId, confidenceScore: calibrateScore, confidenceSource: calibrateSource, confidenceNotes: calibrateNotes })}
                disabled={updateConfidence.isPending}
                data-testid="button-save-confidence"
              >
                {updateConfidence.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : null}
                Save
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-left">
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    <Checkbox
                      checked={filtered && filtered.length > 0 && filtered.every((a) => selectedIds.includes(a.id))}
                      onCheckedChange={(checked) => {
                        if (!filtered) return;
                        setSelectedIds(checked ? filtered.map((a) => a.id) : []);
                      }}
                    />
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Alert</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden md:table-cell">Source</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Severity</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">Category</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">MITRE Tactic</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Queue</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-4 py-3"><Skeleton className="h-4 w-4" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-48" /></td>
                      <td className="px-4 py-3 hidden md:table-cell"><Skeleton className="h-4 w-24" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-20" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-28" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                    </tr>
                  ))
                ) : filtered && filtered.length > 0 ? (
                  filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((alert) => (
                    <tr
                      key={alert.id}
                      className={`border-b last:border-0 hover-elevate cursor-pointer ${alert.suppressed ? "opacity-50" : ""} ${focusedAlertId === alert.id ? "bg-muted/40" : ""}`}
                      onClick={() => navigate('/alerts/' + alert.id)}
                      data-testid={`row-alert-${alert.id}`}
                    >
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selectedIds.includes(alert.id)}
                          onCheckedChange={(checked) => {
                            setSelectedIds((prev) => checked ? (prev.includes(alert.id) ? prev : [...prev, alert.id]) : prev.filter((id) => id !== alert.id));
                          }}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                          <div>
                            <div className={`text-sm font-medium ${alert.suppressed ? "line-through text-muted-foreground" : ""}`}>{alert.title}</div>
                            <div className="text-xs text-muted-foreground truncate max-w-[300px]">{alert.description}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 hidden md:table-cell">
                        <span className="text-xs text-muted-foreground">{alert.source}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 flex-wrap">
                          <SeverityBadge severity={alert.severity} />
                          {alert.confidenceScore != null && (
                            <Badge variant="secondary" className="text-[10px]">
                              {Math.round(alert.confidenceScore * 100)}%
                            </Badge>
                          )}
                          {alert.dedupClusterId && (
                            <Badge variant="outline" className="text-[10px]">
                              <Layers className="h-2.5 w-2.5 mr-0.5" />
                              Dup
                            </Badge>
                          )}
                        </div>
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
                        {(() => {
                          const ageMs = Date.now() - new Date(alert.createdAt || Date.now()).getTime();
                          const queueState = alert.status !== "new"
                            ? "other"
                            : ageMs >= 72 * 60 * 60 * 1000
                              ? "breached"
                              : ageMs >= 24 * 60 * 60 * 1000
                                ? "aging"
                                : "new";
                          if (queueState === "other") return <span className="text-[10px] text-muted-foreground">—</span>;
                          const style = queueState === "breached"
                            ? "bg-red-500/10 text-red-500 border-red-500/20"
                            : queueState === "aging"
                              ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
                              : "bg-blue-500/10 text-blue-500 border-blue-500/20";
                          return <span className={`inline-flex px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider ${style}`}>{queueState}</span>;
                        })()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => handleTriageClick(alert.id)}
                            disabled={triage.isPending && selectedAlertForTriage === alert.id}
                            data-testid={`button-triage-${alert.id}`}
                          >
                            {triage.isPending && selectedAlertForTriage === alert.id ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Brain className="h-3 w-3" />
                            )}
                          </Button>
                          {alert.suppressed ? (
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => unsuppressAlert.mutate(alert.id)}
                              disabled={unsuppressAlert.isPending}
                              data-testid={`button-unsuppress-${alert.id}`}
                            >
                              <Eye className="h-3 w-3" />
                            </Button>
                          ) : (
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => suppressAlert.mutate(alert.id)}
                              disabled={suppressAlert.isPending}
                              data-testid={`button-suppress-${alert.id}`}
                            >
                              <ShieldOff className="h-3 w-3" />
                            </Button>
                          )}
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => {
                              setCalibratingAlertId(alert.id);
                              setCalibrateScore(alert.confidenceScore != null ? Math.round(alert.confidenceScore * 100) : 50);
                              setCalibrateSource(alert.confidenceSource || "analyst");
                              setCalibrateNotes(alert.confidenceNotes || "");
                            }}
                            data-testid={`button-calibrate-${alert.id}`}
                          >
                            <SlidersHorizontal className="h-3 w-3" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={9} className="px-4 py-12 text-center text-sm text-muted-foreground">
                      <AlertTriangle className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50" />
                      <p>No alerts found</p>
                      <p className="text-xs mt-1">Try adjusting your filters or search criteria</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {filtered && filtered.length > PAGE_SIZE && (
            <div className="flex items-center justify-between px-4 py-3 border-t">
              <span className="text-xs text-muted-foreground">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-1">
                <Button variant="outline" size="icon" className="h-7 w-7" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft className="h-3 w-3" />
                </Button>
                <span className="text-xs px-2">{page + 1} / {Math.ceil(filtered.length / PAGE_SIZE)}</span>
                <Button variant="outline" size="icon" className="h-7 w-7" disabled={(page + 1) * PAGE_SIZE >= filtered.length} onClick={() => setPage(p => p + 1)}>
                  <ChevronRight className="h-3 w-3" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
