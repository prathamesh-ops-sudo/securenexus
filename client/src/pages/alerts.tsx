import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  AlertTriangle,
  Search,
  Brain,
  Loader2,
  Sparkles,
  CheckCircle2,
  XCircle,
  Download,
  ShieldOff,
  Eye,
  EyeOff,
  Layers,
  SlidersHorizontal,
  Plus,
  Trash2,
  ExternalLink,
  PanelRight,
  X,
  Clock,
  Tag,
  MapPin,
  UserPlus,
  ArrowUpRight,
  Activity,
  User,
  Filter,
  Save,
  BookmarkPlus,
  Keyboard,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useEffect, useState, useMemo, useCallback } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { SeverityBadge, AlertStatusBadge } from "@/components/security-badges";
import type { Alert, SuppressionRule, SavedView } from "@shared/schema";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from "@/components/ui/resizable";

function MiniTimeline({ alert }: { alert: Alert }) {
  const events: { label: string; actor?: string }[] = [];
  if (alert.createdAt) events.push({ label: "Created" });
  if (alert.assignedTo) events.push({ label: "Assigned", actor: alert.assignedTo });
  if (alert.status === "resolved" || alert.status === "false_positive") {
    events.push({ label: alert.status === "resolved" ? "Resolved" : "False Positive" });
  }
  if (events.length === 0) return null;
  const recent = events.slice(-3);
  return (
    <div className="flex items-center gap-1 mt-1">
      {recent.map((ev, i) => (
        <span key={i} className="inline-flex items-center gap-0.5">
          {i > 0 && <span className="text-muted-foreground/40 mx-0.5">→</span>}
          <span className="text-[9px] text-muted-foreground">{ev.label}</span>
          {ev.actor && <span className="text-[9px] text-primary/70">{ev.actor}</span>}
        </span>
      ))}
    </div>
  );
}

function FilterChips({
  filters,
  onRemove,
  onClearAll,
}: {
  filters: { key: string; label: string; value: string }[];
  onRemove: (key: string) => void;
  onClearAll: () => void;
}) {
  if (filters.length === 0) return null;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Active Filters:</span>
      {filters.map((f) => (
        <Badge
          key={f.key}
          variant="secondary"
          className="text-[10px] pl-2 pr-1 py-0.5 gap-1 cursor-pointer hover:bg-destructive/10 transition-colors"
        >
          <span className="text-muted-foreground">{f.label}:</span> {f.value}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onRemove(f.key);
            }}
            className="ml-0.5 rounded-full hover:bg-muted p-0.5"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </Badge>
      ))}
      <button onClick={onClearAll} className="text-[10px] text-destructive hover:underline">
        Clear all
      </button>
    </div>
  );
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

const SCOPE_OPTIONS = [
  "source",
  "category",
  "severity",
  "title_regex",
  "entity",
  "source_ip",
  "dest_ip",
  "hostname",
  "domain",
] as const;

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
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [savedViewName, setSavedViewName] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [showQueryBuilder, setShowQueryBuilder] = useState(false);
  const [showKeyboardHelp, setShowKeyboardHelp] = useState(false);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [focusedAlertId, setFocusedAlertId] = useState<string | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [queueFilter, setQueueFilter] = useState<"all" | "new" | "aging" | "breached">("all");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;
  const { toast } = useToast();

  const { data: serverSavedViews, refetch: refetchSavedViews } = useQuery<SavedView[]>({
    queryKey: ["/api/orgs/default/saved-views", "alerts"],
    queryFn: async () => {
      try {
        const res = await apiRequest("GET", "/api/orgs/default/saved-views?resourceType=alerts");
        return res.json();
      } catch {
        return [];
      }
    },
  });

  const createSavedViewMutation = useMutation({
    mutationFn: async (viewData: { name: string; filters: Record<string, unknown> }) => {
      const res = await apiRequest("POST", "/api/orgs/default/saved-views", {
        name: viewData.name,
        resourceType: "alerts",
        filters: viewData.filters,
      });
      return res.json();
    },
    onSuccess: () => {
      refetchSavedViews();
      toast({ title: "View Saved" });
      setSavedViewName("");
    },
    onError: (error: Error) => {
      toast({ title: "Failed to save view", description: error.message, variant: "destructive" });
    },
  });

  const deleteSavedViewMutation = useMutation({
    mutationFn: async (viewId: string) => {
      await apiRequest("DELETE", `/api/orgs/default/saved-views/${viewId}`);
    },
    onSuccess: () => {
      refetchSavedViews();
      toast({ title: "View Deleted" });
    },
  });

  const {
    data: alerts,
    isLoading,
    isError: alertsError,
    refetch: refetchAlerts,
  } = useQuery<Alert[]>({
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
      toast({
        title: "AI Correlation Complete",
        description: `Found ${data.correlatedGroups.length} correlated group(s)`,
      });
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
    mutationFn: async ({
      alertId,
      confidenceScore,
      confidenceSource,
      confidenceNotes,
    }: {
      alertId: string;
      confidenceScore: number;
      confidenceSource: string;
      confidenceNotes: string;
    }) => {
      const res = await apiRequest("PATCH", `/api/alerts/${alertId}/confidence`, {
        confidenceScore: confidenceScore / 100,
        confidenceSource,
        confidenceNotes,
      });
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
    mutationFn: async (payload: { status?: string; suppressed?: boolean; assignedTo?: string }) => {
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

  const getQueueState = (alert: Alert): "new" | "aging" | "breached" | "other" => {
    const ageMs = Date.now() - new Date(alert.createdAt || Date.now()).getTime();
    if (alert.status !== "new") return "other";
    if (ageMs >= 72 * 60 * 60 * 1000) return "breached";
    if (ageMs >= 24 * 60 * 60 * 1000) return "aging";
    return "new";
  };

  const _getQueueLabel = (state: "new" | "aging" | "breached" | "other") => {
    if (state === "other") return "N/A";
    return state;
  };

  const getQueueCountdown = (alert: Alert) => {
    const state = getQueueState(alert);
    if (state === "other" || state === "breached") return null;
    const ageMs = Date.now() - new Date(alert.createdAt || Date.now()).getTime();
    const targetMs = state === "new" ? 24 * 60 * 60 * 1000 : 72 * 60 * 60 * 1000;
    const remainingMs = Math.max(0, targetMs - ageMs);
    const totalMinutes = Math.floor(remainingMs / (60 * 1000));
    const hours = Math.floor(totalMinutes / 60);
    const minutes = totalMinutes % 60;
    return `${hours}h ${minutes}m remaining`;
  };

  const filtered = alerts?.filter((alert) => {
    const matchesSearch =
      !search ||
      alert.title.toLowerCase().includes(search.toLowerCase()) ||
      alert.source.toLowerCase().includes(search.toLowerCase()) ||
      alert.description?.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || alert.status === statusFilter;
    const matchesSource = sourceFilter === "all" || alert.source === sourceFilter;
    const matchesCategory = categoryFilter === "all" || alert.category === categoryFilter;
    const matchesSuppressed = showSuppressed || !alert.suppressed;
    const queueState = getQueueState(alert);
    const matchesQueue = queueFilter === "all" || queueState === queueFilter;
    const matchesDateFrom = !dateFrom || new Date(alert.createdAt || 0) >= new Date(dateFrom);
    const matchesDateTo = !dateTo || new Date(alert.createdAt || 0) <= new Date(dateTo + "T23:59:59");
    return (
      matchesSearch &&
      matchesSeverity &&
      matchesStatus &&
      matchesSource &&
      matchesCategory &&
      matchesSuppressed &&
      matchesQueue &&
      matchesDateFrom &&
      matchesDateTo
    );
  });

  const severities = ["all", "critical", "high", "medium", "low"];

  useEffect(() => {
    if (!filtered || filtered.length === 0) return;
    if (!focusedAlertId || !filtered.some((a) => a.id === focusedAlertId)) {
      setFocusedAlertId(filtered[0].id);
    }
  }, [filtered, focusedAlertId]);

  useEffect(() => {
    if (!filtered || filtered.length === 0) {
      setPage(0);
      return;
    }
    const maxPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1);
    if (page > maxPage) setPage(maxPage);
  }, [filtered, page]);

  const assignFocused = useCallback(() => {
    if (!focusedAlertId) return;
    const name = prompt("Assign to:");
    if (name && name.trim()) {
      apiRequest("PATCH", `/api/alerts/${focusedAlertId}`, { assignedTo: name.trim() })
        .then(() => {
          queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
          toast({ title: "Assigned", description: `Alert assigned to ${name.trim()}` });
        })
        .catch((err: Error) => {
          toast({ title: "Assignment failed", description: err.message, variant: "destructive" });
        });
    }
  }, [focusedAlertId, toast]);

  const escalateFocused = useCallback(() => {
    if (!focusedAlertId) return;
    apiRequest("PATCH", `/api/alerts/${focusedAlertId}`, { status: "triaged", assignedTo: "Tier 2" })
      .then(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
        toast({ title: "Escalated", description: "Alert escalated to Tier 2" });
      })
      .catch((err: Error) => {
        toast({ title: "Escalation failed", description: err.message, variant: "destructive" });
      });
  }, [focusedAlertId, toast]);

  const resolveFocused = useCallback(() => {
    if (!focusedAlertId) return;
    apiRequest("PATCH", `/api/alerts/${focusedAlertId}`, { status: "resolved" })
      .then(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
        toast({ title: "Resolved" });
      })
      .catch((err: Error) => {
        toast({ title: "Resolve failed", description: err.message, variant: "destructive" });
      });
  }, [focusedAlertId, toast]);

  const uniqueSources = useMemo(() => {
    if (!alerts) return [];
    return Array.from(new Set(alerts.map((a) => a.source).filter(Boolean))).sort();
  }, [alerts]);

  const uniqueCategories = useMemo(() => {
    if (!alerts) return [];
    return Array.from(new Set(alerts.map((a) => a.category).filter((c): c is string => !!c))).sort();
  }, [alerts]);

  const activeFilters = useMemo(() => {
    const chips: { key: string; label: string; value: string }[] = [];
    if (severityFilter !== "all") chips.push({ key: "severity", label: "Severity", value: severityFilter });
    if (statusFilter !== "all") chips.push({ key: "status", label: "Status", value: statusFilter });
    if (sourceFilter !== "all") chips.push({ key: "source", label: "Source", value: sourceFilter });
    if (categoryFilter !== "all") chips.push({ key: "category", label: "Category", value: categoryFilter });
    if (search) chips.push({ key: "search", label: "Search", value: search });
    if (queueFilter !== "all") chips.push({ key: "queue", label: "Queue", value: queueFilter });
    if (dateFrom) chips.push({ key: "dateFrom", label: "From", value: dateFrom });
    if (dateTo) chips.push({ key: "dateTo", label: "To", value: dateTo });
    if (showSuppressed) chips.push({ key: "suppressed", label: "Showing", value: "Suppressed" });
    return chips;
  }, [
    severityFilter,
    statusFilter,
    sourceFilter,
    categoryFilter,
    search,
    queueFilter,
    dateFrom,
    dateTo,
    showSuppressed,
  ]);

  const handleRemoveFilter = useCallback((key: string) => {
    if (key === "severity") setSeverityFilter("all");
    if (key === "status") setStatusFilter("all");
    if (key === "source") setSourceFilter("all");
    if (key === "category") setCategoryFilter("all");
    if (key === "search") setSearch("");
    if (key === "queue") setQueueFilter("all");
    if (key === "dateFrom") setDateFrom("");
    if (key === "dateTo") setDateTo("");
    if (key === "suppressed") setShowSuppressed(false);
  }, []);

  const handleClearAllFilters = useCallback(() => {
    setSeverityFilter("all");
    setStatusFilter("all");
    setSourceFilter("all");
    setCategoryFilter("all");
    setSearch("");
    setQueueFilter("all");
    setDateFrom("");
    setDateTo("");
    setShowSuppressed(false);
  }, []);

  const applySavedView = useCallback((view: SavedView) => {
    const f = view.filters as Record<string, string> | null;
    if (!f) return;
    if (f.severity) setSeverityFilter(f.severity);
    if (f.status) setStatusFilter(f.status);
    if (f.source) setSourceFilter(f.source);
    if (f.category) setCategoryFilter(f.category);
    if (f.search) setSearch(f.search);
    if (f.queue) setQueueFilter(f.queue as "all" | "new" | "aging" | "breached");
    if (f.dateFrom) setDateFrom(f.dateFrom);
    if (f.dateTo) setDateTo(f.dateTo);
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!filtered || filtered.length === 0) return;
      const target = e.target as HTMLElement;
      if (
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.tagName === "SELECT" ||
        target?.isContentEditable
      )
        return;
      const idx = filtered.findIndex((a) => a.id === focusedAlertId);
      if (e.key.toLowerCase() === "j") {
        e.preventDefault();
        const next = Math.min(idx < 0 ? 0 : idx + 1, filtered.length - 1);
        setFocusedAlertId(filtered[next]?.id || null);
        const newPage = Math.floor(next / PAGE_SIZE);
        if (newPage !== page) setPage(newPage);
      }
      if (e.key.toLowerCase() === "k") {
        e.preventDefault();
        const prev = Math.max(idx < 0 ? 0 : idx - 1, 0);
        setFocusedAlertId(filtered[prev]?.id || null);
        const newPage = Math.floor(prev / PAGE_SIZE);
        if (newPage !== page) setPage(newPage);
      }
      if (e.key.toLowerCase() === "t" && selectedIds.length > 0) {
        e.preventDefault();
        bulkUpdate.mutate({ status: "triaged" });
      }
      if (e.key.toLowerCase() === "a" && focusedAlertId) {
        e.preventDefault();
        assignFocused();
      }
      if (e.key.toLowerCase() === "e" && focusedAlertId) {
        e.preventDefault();
        escalateFocused();
      }
      if (e.key.toLowerCase() === "r" && focusedAlertId) {
        e.preventDefault();
        resolveFocused();
      }
      if (e.key === "Enter" && focusedAlertId) {
        e.preventDefault();
        setIsDetailOpen(true);
      }
      if (e.key === "Escape") {
        setIsDetailOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [filtered, focusedAlertId, selectedIds, bulkUpdate, page, assignFocused, escalateFocused, resolveFocused]);

  const selectedAlert = useMemo(
    () => (alerts && focusedAlertId ? (alerts.find((alert) => alert.id === focusedAlertId) ?? null) : null),
    [alerts, focusedAlertId],
  );
  const pageAlerts = useMemo(() => filtered?.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE) ?? [], [filtered, page]);

  const handleTriageClick = (alertId: string) => {
    setSelectedAlertForTriage(alertId);
    setTriageResult(null);
    triage.mutate(alertId);
  };

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" aria-label="Alerts Management">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Alerts</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1">All security alerts from integrated tools</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            onClick={() => setShowSuppressionRules(!showSuppressionRules)}
            aria-label="Toggle suppression rules panel"
            aria-expanded={showSuppressionRules}
            data-testid="button-suppression-rules"
          >
            <ShieldOff className="h-4 w-4 mr-2" aria-hidden="true" />
            Suppression Rules
          </Button>
          <Button onClick={() => correlate.mutate()} disabled={correlate.isPending} data-testid="button-ai-correlate">
            {correlate.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />
            ) : (
              <Brain className="h-4 w-4 mr-2" aria-hidden="true" />
            )}
            {correlate.isPending ? "Analyzing..." : "AI Correlate Alerts"}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-alerts"
          />
        </div>
        <Button
          variant="outline"
          size="icon"
          data-testid="button-export-alerts"
          onClick={() => window.open("/api/export/alerts", "_blank")}
        >
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
                severityFilter === sev ? "bg-primary text-primary-foreground" : "text-muted-foreground hover-elevate"
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
              {state === "all"
                ? "Queue: All"
                : state === "new"
                  ? "Queue: New"
                  : state === "aging"
                    ? "Queue: Aging"
                    : "Queue: Breached"}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={showSuppressed} onCheckedChange={setShowSuppressed} data-testid="toggle-show-suppressed" />
          <label
            className="text-xs text-muted-foreground flex items-center gap-1 cursor-pointer"
            onClick={() => setShowSuppressed(!showSuppressed)}
          >
            {showSuppressed ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
            Show Suppressed
          </label>
        </div>
        <Button variant="outline" size="sm" onClick={() => setShowQueryBuilder(!showQueryBuilder)}>
          <Filter className="h-3.5 w-3.5 mr-1.5" />
          {showQueryBuilder ? "Hide Builder" : "Query Builder"}
        </Button>
        <Button variant="outline" size="sm" onClick={() => setShowKeyboardHelp(!showKeyboardHelp)}>
          <Keyboard className="h-3.5 w-3.5 mr-1.5" />
          Keys
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setIsDetailOpen((prev) => !prev)}
          disabled={!selectedAlert}
          data-testid="button-toggle-detail-pane"
        >
          <PanelRight className="h-3.5 w-3.5 mr-1.5" />
          {isDetailOpen ? "Hide Detail" : "Show Detail"}
        </Button>
      </div>

      {showKeyboardHelp && (
        <Card className="border-primary/20 bg-muted/30">
          <CardContent className="pt-4 pb-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">J</kbd>{" "}
                <span className="text-muted-foreground">Next alert</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">K</kbd>{" "}
                <span className="text-muted-foreground">Previous alert</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">Enter</kbd>{" "}
                <span className="text-muted-foreground">Open detail</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">Esc</kbd>{" "}
                <span className="text-muted-foreground">Close detail</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">A</kbd>{" "}
                <span className="text-muted-foreground">Assign focused</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">E</kbd>{" "}
                <span className="text-muted-foreground">Escalate focused</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">R</kbd>{" "}
                <span className="text-muted-foreground">Resolve focused</span>
              </div>
              <div>
                <kbd className="px-1.5 py-0.5 bg-background rounded border text-[10px] font-mono">T</kbd>{" "}
                <span className="text-muted-foreground">Triage selected</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {showQueryBuilder && (
        <Card className="border-primary/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <SlidersHorizontal className="h-4 w-4 text-primary" />
              Query Builder
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Status</label>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="new">New</SelectItem>
                    <SelectItem value="triaged">Triaged</SelectItem>
                    <SelectItem value="investigating">Investigating</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                    <SelectItem value="false_positive">False Positive</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Source</label>
                <Select value={sourceFilter} onValueChange={setSourceFilter}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Sources</SelectItem>
                    {uniqueSources.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">
                  Category
                </label>
                <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Categories</SelectItem>
                    {uniqueCategories.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">
                  Severity
                </label>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {severities.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s === "all" ? "All Severities" : s.charAt(0).toUpperCase() + s.slice(1)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">
                  Date From
                </label>
                <Input
                  type="date"
                  value={dateFrom}
                  onChange={(e) => setDateFrom(e.target.value)}
                  className="h-8 text-xs"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Date To</label>
                <Input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} className="h-8 text-xs" />
              </div>
              <div className="col-span-2 flex items-end gap-2">
                <div className="flex-1">
                  <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">
                    Save Current Filters
                  </label>
                  <div className="flex gap-1">
                    <Input
                      placeholder="View name..."
                      value={savedViewName}
                      onChange={(e) => setSavedViewName(e.target.value)}
                      className="h-8 text-xs"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8"
                      disabled={!savedViewName.trim() || createSavedViewMutation.isPending}
                      onClick={() => {
                        createSavedViewMutation.mutate({
                          name: savedViewName.trim(),
                          filters: {
                            severity: severityFilter,
                            status: statusFilter,
                            source: sourceFilter,
                            category: categoryFilter,
                            search,
                            queue: queueFilter,
                            dateFrom,
                            dateTo,
                          },
                        });
                      }}
                    >
                      <BookmarkPlus className="h-3 w-3 mr-1" />
                      Save
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {serverSavedViews && serverSavedViews.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Saved Views:</span>
          {serverSavedViews.map((v) => (
            <div key={v.id} className="inline-flex items-center gap-0.5">
              <Button size="sm" variant="secondary" className="h-7 text-xs" onClick={() => applySavedView(v)}>
                {v.name}
              </Button>
              <button
                onClick={() => deleteSavedViewMutation.mutate(v.id)}
                className="p-0.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      <FilterChips filters={activeFilters} onRemove={handleRemoveFilter} onClearAll={handleClearAllFilters} />

      {selectedIds.length > 0 && (
        <Card>
          <CardContent className="pt-4 flex items-center flex-wrap gap-2">
            <Badge variant="outline">{selectedIds.length} selected</Badge>
            <Select value={bulkStatus} onValueChange={setBulkStatus}>
              <SelectTrigger className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="new">New</SelectItem>
                <SelectItem value="triaged">Triaged</SelectItem>
                <SelectItem value="investigating">Investigating</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" onClick={() => bulkUpdate.mutate({ status: bulkStatus })} disabled={bulkUpdate.isPending}>
              Apply Status
            </Button>
            <div className="flex items-center gap-1">
              <Input
                placeholder="Assignee"
                value={bulkAssignee}
                onChange={(e) => setBulkAssignee(e.target.value)}
                className="w-32 h-8 text-sm"
              />
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  if (bulkAssignee.trim()) bulkUpdate.mutate({ assignedTo: bulkAssignee.trim() });
                }}
                disabled={bulkUpdate.isPending || !bulkAssignee.trim()}
              >
                <UserPlus className="h-3 w-3 mr-1" />
                Assign
              </Button>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => bulkUpdate.mutate({ status: "escalated" })}
              disabled={bulkUpdate.isPending}
            >
              <ArrowUpRight className="h-3 w-3 mr-1" />
              Escalate
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => bulkUpdate.mutate({ suppressed: true })}
              disabled={bulkUpdate.isPending}
            >
              Suppress
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => bulkUpdate.mutate({ suppressed: false })}
              disabled={bulkUpdate.isPending}
            >
              Unsuppress
            </Button>
            <span className="text-xs text-muted-foreground">
              Keys: J/K nav, Enter open, Esc close, T triage, A assign, E escalate, R resolve
            </span>
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
                <Button size="sm" variant="ghost" onClick={() => setShowSuppressionRules(false)}>
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
                        <SelectItem key={s} value={s}>
                          {s.replace(/_/g, " ")}
                        </SelectItem>
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
                    <Switch checked={ruleEnabled} onCheckedChange={setRuleEnabled} data-testid="toggle-rule-enabled" />
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
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : suppressionRules && suppressionRules.length > 0 ? (
              suppressionRules.map((rule) => (
                <div
                  key={rule.id}
                  className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/30 flex-wrap"
                >
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
            <p className="text-xs text-muted-foreground mt-1" data-testid="text-correlation-assessment">
              {correlationResult.overallAssessment}
            </p>
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
                    <span key={j} className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px]">
                      {t}
                    </span>
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
              <p className="text-xs text-muted-foreground">
                {correlationResult.uncorrelatedAlertIds.length} alert(s) did not correlate to any group
              </p>
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
                onClick={() => {
                  setSelectedAlertForTriage(null);
                  setTriageResult(null);
                }}
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
                  <div className="text-sm text-primary font-medium" data-testid="text-triage-action">
                    {triageResult.recommendedAction}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase mb-1">Reasoning</div>
                  <div className="text-xs text-muted-foreground" data-testid="text-triage-reasoning">
                    {triageResult.reasoning}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {triageResult.mitreTactic && (
                    <span className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px]">
                      {triageResult.mitreTactic}
                    </span>
                  )}
                  {triageResult.mitreTechnique && (
                    <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">
                      {triageResult.mitreTechnique}
                    </span>
                  )}
                </div>
                {triageResult.relatedIocs && triageResult.relatedIocs.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase mb-1">IOCs</div>
                    <div className="flex flex-wrap gap-1">
                      {triageResult.relatedIocs.map((ioc, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">
                          {ioc}
                        </span>
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
              <Button size="sm" variant="ghost" onClick={() => setCalibratingAlertId(null)}>
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
                onClick={() =>
                  updateConfidence.mutate({
                    alertId: calibratingAlertId,
                    confidenceScore: calibrateScore,
                    confidenceSource: calibrateSource,
                    confidenceNotes: calibrateNotes,
                  })
                }
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

      <ResizablePanelGroup direction="horizontal" className="rounded-lg">
        <ResizablePanel defaultSize={isDetailOpen && selectedAlert ? 60 : 100} minSize={35}>
          <Card className="h-full transition-all duration-200">
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
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden md:table-cell">
                        Source
                      </th>
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Severity</th>
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">
                        Category
                      </th>
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">
                        MITRE Tactic
                      </th>
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Status</th>
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Queue</th>
                      <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {isLoading ? (
                      Array.from({ length: 6 }).map((_, i) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-4 py-3">
                            <Skeleton className="h-4 w-4" />
                          </td>
                          <td className="px-4 py-3">
                            <Skeleton className="h-4 w-48" />
                          </td>
                          <td className="px-4 py-3 hidden md:table-cell">
                            <Skeleton className="h-4 w-24" />
                          </td>
                          <td className="px-4 py-3">
                            <Skeleton className="h-4 w-16" />
                          </td>
                          <td className="px-4 py-3 hidden lg:table-cell">
                            <Skeleton className="h-4 w-20" />
                          </td>
                          <td className="px-4 py-3 hidden lg:table-cell">
                            <Skeleton className="h-4 w-28" />
                          </td>
                          <td className="px-4 py-3">
                            <Skeleton className="h-4 w-16" />
                          </td>
                          <td className="px-4 py-3">
                            <Skeleton className="h-4 w-16" />
                          </td>
                          <td className="px-4 py-3">
                            <Skeleton className="h-4 w-16" />
                          </td>
                        </tr>
                      ))
                    ) : alertsError ? (
                      <tr>
                        <td colSpan={9} className="px-4 py-12 text-center">
                          <div role="alert" className="flex flex-col items-center gap-3">
                            <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20">
                              <AlertTriangle className="h-6 w-6 text-destructive" />
                            </div>
                            <p className="text-sm font-medium">Failed to load alerts</p>
                            <p className="text-xs text-muted-foreground">
                              An error occurred while fetching alert data.
                            </p>
                            <Button variant="outline" size="sm" onClick={() => refetchAlerts()}>
                              <Activity className="h-3.5 w-3.5 mr-1.5" />
                              Try Again
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ) : pageAlerts.length > 0 ? (
                      pageAlerts.map((alert) => (
                        <tr
                          key={alert.id}
                          className={`border-b last:border-0 hover-elevate cursor-pointer ${alert.suppressed ? "opacity-50" : ""} ${focusedAlertId === alert.id ? "bg-primary/5 border-l-2 border-l-primary" : ""}`}
                          onClick={() => {
                            setFocusedAlertId(alert.id);
                            setIsDetailOpen(true);
                          }}
                          data-testid={`row-alert-${alert.id}`}
                        >
                          <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                            <Checkbox
                              checked={selectedIds.includes(alert.id)}
                              onCheckedChange={(checked) => {
                                setSelectedIds((prev) =>
                                  checked
                                    ? prev.includes(alert.id)
                                      ? prev
                                      : [...prev, alert.id]
                                    : prev.filter((id) => id !== alert.id),
                                );
                              }}
                            />
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <AlertTriangle
                                className="h-3 w-3 text-muted-foreground flex-shrink-0"
                                aria-hidden="true"
                              />
                              <div>
                                <div
                                  className={`text-sm font-medium ${alert.suppressed ? "line-through text-muted-foreground" : ""}`}
                                >
                                  {alert.title}
                                </div>
                                <div className="text-xs text-muted-foreground truncate max-w-[300px]">
                                  {alert.description}
                                </div>
                                <MiniTimeline alert={alert} />
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
                            <span className="text-xs text-muted-foreground">
                              {alert.category?.replace(/_/g, " ") || "-"}
                            </span>
                          </td>
                          <td className="px-4 py-3 hidden lg:table-cell">
                            <span className="text-xs text-muted-foreground">{alert.mitreTactic || "-"}</span>
                          </td>
                          <td className="px-4 py-3">
                            <AlertStatusBadge status={alert.status} />
                          </td>
                          <td className="px-4 py-3">
                            {(() => {
                              const qs = getQueueState(alert);
                              if (qs === "other") return <span className="text-[10px] text-muted-foreground">—</span>;
                              const countdown = getQueueCountdown(alert);
                              const style =
                                qs === "breached"
                                  ? "bg-red-500/10 text-red-500 border-red-500/20"
                                  : qs === "aging"
                                    ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
                                    : "bg-blue-500/10 text-blue-500 border-blue-500/20";
                              return (
                                <div className="flex flex-col gap-0.5">
                                  <span
                                    className={`inline-flex px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider ${style}`}
                                  >
                                    {qs}
                                  </span>
                                  {countdown && <span className="text-[9px] text-muted-foreground">{countdown}</span>}
                                </div>
                              );
                            })()}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                              <Button
                                size="icon"
                                variant="ghost"
                                onClick={() => handleTriageClick(alert.id)}
                                disabled={triage.isPending && selectedAlertForTriage === alert.id}
                                aria-label="AI triage this alert"
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
                                  aria-label="Unsuppress this alert"
                                  data-testid={`button-unsuppress-${alert.id}`}
                                >
                                  <Eye className="h-3 w-3" aria-hidden="true" />
                                </Button>
                              ) : (
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => suppressAlert.mutate(alert.id)}
                                  disabled={suppressAlert.isPending}
                                  aria-label="Suppress this alert"
                                  data-testid={`button-suppress-${alert.id}`}
                                >
                                  <ShieldOff className="h-3 w-3" aria-hidden="true" />
                                </Button>
                              )}
                              <Button
                                size="icon"
                                variant="ghost"
                                onClick={() => {
                                  setCalibratingAlertId(alert.id);
                                  setCalibrateScore(
                                    alert.confidenceScore != null ? Math.round(alert.confidenceScore * 100) : 50,
                                  );
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
                          <div role="status" aria-label="No alerts found">
                            <AlertTriangle
                              className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50"
                              aria-hidden="true"
                            />
                            <p className="font-medium">No alerts found</p>
                            <p className="text-xs mt-1">Try adjusting your filters or search criteria</p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {filtered && filtered.length > PAGE_SIZE && (
                <div className="flex items-center justify-between px-4 py-3 border-t">
                  <span className="text-xs text-muted-foreground">
                    Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of{" "}
                    {filtered.length}
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-7 w-7"
                      disabled={page === 0}
                      onClick={() => setPage((p) => p - 1)}
                      aria-label="Previous page"
                    >
                      <ChevronLeft className="h-3 w-3" aria-hidden="true" />
                    </Button>
                    <span className="text-xs px-2" aria-live="polite">
                      {page + 1} / {Math.ceil(filtered.length / PAGE_SIZE)}
                    </span>
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-7 w-7"
                      disabled={(page + 1) * PAGE_SIZE >= filtered.length}
                      onClick={() => setPage((p) => p + 1)}
                      aria-label="Next page"
                    >
                      <ChevronRight className="h-3 w-3" aria-hidden="true" />
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </ResizablePanel>

        {isDetailOpen && selectedAlert && (
          <>
            <ResizableHandle withHandle />
            <ResizablePanel defaultSize={40} minSize={20}>
              <Card className="flex flex-col h-full max-h-[calc(100vh-12rem)]">
                <div className="flex items-center justify-between gap-2 p-4 border-b">
                  <h3 className="text-sm font-semibold truncate">Alert Detail</h3>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => setIsDetailOpen(false)}
                    aria-label="Close detail panel"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  <div>
                    <h4 className="text-base font-semibold">{selectedAlert.title}</h4>
                    <p className="text-xs text-muted-foreground mt-1">{selectedAlert.description}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase">Severity</span>
                      <div className="mt-0.5">
                        <SeverityBadge severity={selectedAlert.severity} />
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase">Status</span>
                      <div className="mt-0.5">
                        <AlertStatusBadge status={selectedAlert.status} />
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase">Source</span>
                      <p className="text-xs mt-0.5">{selectedAlert.source}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase">Category</span>
                      <p className="text-xs mt-0.5">{selectedAlert.category?.replace(/_/g, " ") || "-"}</p>
                    </div>
                  </div>
                  {selectedAlert.assignedTo && (
                    <div className="flex items-center gap-2">
                      <User className="h-3 w-3 text-muted-foreground" />
                      <span className="text-xs">
                        Assigned to: <span className="font-medium">{selectedAlert.assignedTo}</span>
                      </span>
                    </div>
                  )}
                  {selectedAlert.mitreTactic && (
                    <div className="flex items-center gap-2">
                      <Tag className="h-3 w-3 text-muted-foreground" />
                      <span className="text-xs">{selectedAlert.mitreTactic}</span>
                      {selectedAlert.mitreTechnique && (
                        <span className="text-xs font-mono text-muted-foreground">{selectedAlert.mitreTechnique}</span>
                      )}
                    </div>
                  )}
                  {(selectedAlert.sourceIp || selectedAlert.destIp || selectedAlert.hostname) && (
                    <div className="space-y-1.5">
                      <span className="text-[10px] text-muted-foreground uppercase">Entities</span>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAlert.sourceIp && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-muted text-[10px]">
                            <MapPin className="h-2.5 w-2.5" />
                            src: {selectedAlert.sourceIp}
                          </span>
                        )}
                        {selectedAlert.destIp && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-muted text-[10px]">
                            <MapPin className="h-2.5 w-2.5" />
                            dst: {selectedAlert.destIp}
                          </span>
                        )}
                        {selectedAlert.hostname && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-muted text-[10px]">
                            {selectedAlert.hostname}
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                  {selectedAlert.confidenceScore != null && (
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase">Confidence</span>
                      <div className="flex items-center gap-2 mt-1">
                        <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary rounded-full"
                            style={{ width: `${Math.round(selectedAlert.confidenceScore * 100)}%` }}
                          />
                        </div>
                        <span className="text-xs font-medium">{Math.round(selectedAlert.confidenceScore * 100)}%</span>
                      </div>
                    </div>
                  )}
                  {(() => {
                    const qs = getQueueState(selectedAlert);
                    const countdown = getQueueCountdown(selectedAlert);
                    if (qs === "other") return null;
                    return (
                      <div className="flex items-center gap-2">
                        <Clock className="h-3 w-3 text-muted-foreground" />
                        <span className="text-xs">
                          Queue: <span className="uppercase font-medium">{qs}</span>
                        </span>
                        {countdown && <span className="text-xs text-muted-foreground">{countdown}</span>}
                      </div>
                    );
                  })()}
                  <div className="space-y-2 pt-2 border-t">
                    <div className="text-[10px] text-muted-foreground uppercase">Quick Actions</div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Button size="sm" variant="outline" onClick={assignFocused}>
                        <UserPlus className="h-3 w-3 mr-1" />
                        Assign (A)
                      </Button>
                      <Button size="sm" variant="outline" onClick={escalateFocused}>
                        <ArrowUpRight className="h-3 w-3 mr-1" />
                        Escalate (E)
                      </Button>
                      <Button size="sm" variant="outline" onClick={resolveFocused}>
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        Resolve (R)
                      </Button>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button size="sm" onClick={() => navigate("/alerts/" + selectedAlert.id)}>
                        <ExternalLink className="h-3 w-3 mr-1.5" />
                        Full Detail
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleTriageClick(selectedAlert.id)}
                        disabled={triage.isPending}
                      >
                        <Brain className="h-3 w-3 mr-1.5" />
                        AI Triage
                      </Button>
                    </div>
                  </div>
                </div>
              </Card>
            </ResizablePanel>
          </>
        )}
      </ResizablePanelGroup>
    </div>
  );
}
