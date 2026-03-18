import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  EyeOff,
  Plus,
  Search,
  Shield,
  AlertTriangle,
  RefreshCw,
  Globe,
  Clock,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  BarChart3,
  Mail,
  Key,
  User,
  Target,
  Code2,
  CreditCard,
  FileText,
  Loader2,
  Eye,
  ChevronRight,
  Activity,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { FormPageSkeleton } from "@/components/page-skeleton";

// ── Types ─────────────────────────────────────────────────────────

interface DarkWebExposure {
  id: string;
  orgId: string;
  targetId: string | null;
  exposureType: string;
  severity: string;
  status: string;
  title: string;
  description: string | null;
  sourceType: string;
  sourceName: string | null;
  sourceUrl: string | null;
  breachDate: string | null;
  discoveredAt: string;
  affectedData: string[] | null;
  affectedCount: number | null;
  matchedValue: string | null;
  confidenceScore: number | null;
  mitigationNotes: string | null;
  assignedTo: string | null;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface BreachMonitoringTarget {
  id: string;
  orgId: string;
  targetType: string;
  targetValue: string;
  label: string | null;
  isActive: boolean;
  lastCheckedAt: string | null;
  exposureCount: number;
  createdAt: string;
  updatedAt: string;
}

interface MonitoringConfig {
  id: string;
  isEnabled: boolean;
  scanFrequencyHours: number;
  autoCreateAlerts: boolean;
  alertSeverityThreshold: string;
  notifyOnNewExposure: boolean;
  hibpApiKey: string | null;
  dehashedApiKey: string | null;
  lastFullScanAt: string | null;
  totalExposuresFound: number;
  totalExposuresResolved: number;
}

interface ScanHistoryEntry {
  id: string;
  scanType: string;
  status: string;
  targetsScanned: number;
  newExposuresFound: number;
  sourcesChecked: string[] | null;
  errorMessage: string | null;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
}

interface DashboardData {
  config: MonitoringConfig | null;
  targetCounts: Array<{ targetType: string; count: number }>;
  exposureStats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    newCount: number;
    investigating: number;
    mitigated: number;
  };
  exposuresByType: Array<{ exposureType: string; count: number }>;
  recentExposures: DarkWebExposure[];
  lastScan: ScanHistoryEntry | null;
}

// ── Helpers ───────────────────────────────────────────────────────

function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-red-500/10 text-red-500 border-red-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium":
      return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    case "low":
      return "bg-blue-500/10 text-blue-500 border-blue-500/20";
    case "info":
      return "bg-slate-500/10 text-slate-500 border-slate-500/20";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function statusColor(status: string): string {
  switch (status) {
    case "new":
      return "bg-red-500/10 text-red-500";
    case "investigating":
      return "bg-yellow-500/10 text-yellow-500";
    case "confirmed":
      return "bg-orange-500/10 text-orange-500";
    case "mitigated":
      return "bg-green-500/10 text-green-500";
    case "false_positive":
      return "bg-slate-500/10 text-slate-500";
    case "ignored":
      return "bg-muted text-muted-foreground";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function exposureTypeIcon(type: string) {
  switch (type) {
    case "credential_leak":
      return Key;
    case "data_breach":
      return Shield;
    case "brand_mention":
      return Globe;
    case "executive_exposure":
      return User;
    case "source_code_leak":
      return Code2;
    case "pii_exposure":
      return FileText;
    case "credit_card_exposure":
      return CreditCard;
    case "threat_actor_mention":
      return Target;
    case "domain_mention":
      return Globe;
    case "paste_site":
      return FileText;
    default:
      return EyeOff;
  }
}

function exposureTypeLabel(type: string): string {
  return type
    .split("_")
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

function targetTypeLabel(type: string): string {
  return type
    .split("_")
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

function targetTypeIcon(type: string) {
  switch (type) {
    case "email":
    case "executive_email":
      return Mail;
    case "domain":
      return Globe;
    case "brand_keyword":
      return Target;
    case "source_code_keyword":
      return Code2;
    case "credit_card_bin":
      return CreditCard;
    case "api_key_pattern":
      return Key;
    case "ip_range":
      return Activity;
    default:
      return EyeOff;
  }
}

function formatDate(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString();
}

function formatDateTime(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleString();
}

function redactValue(val: string | null): string {
  if (!val) return "—";
  if (val.includes("@")) {
    const [user, domain] = val.split("@");
    return user.slice(0, 3) + "***@" + domain;
  }
  if (val.length > 6) {
    return val.slice(0, 4) + "***" + val.slice(-2);
  }
  return val;
}

const TARGET_TYPES = [
  { value: "email", label: "Email Address" },
  { value: "domain", label: "Domain" },
  { value: "executive_email", label: "Executive Email" },
  { value: "brand_keyword", label: "Brand Keyword" },
  { value: "source_code_keyword", label: "Source Code Keyword" },
  { value: "credit_card_bin", label: "Credit Card BIN" },
  { value: "api_key_pattern", label: "API Key Pattern" },
  { value: "ip_range", label: "IP Range" },
];

const EXPOSURE_STATUSES = [
  { value: "new", label: "New" },
  { value: "investigating", label: "Investigating" },
  { value: "confirmed", label: "Confirmed" },
  { value: "mitigated", label: "Mitigated" },
  { value: "false_positive", label: "False Positive" },
  { value: "ignored", label: "Ignored" },
];

// ── Main Component ────────────────────────────────────────────────

export default function DarkWebMonitoringPage() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [addTargetOpen, setAddTargetOpen] = useState(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [selectedExposure, setSelectedExposure] = useState<string | null>(null);
  const { toast } = useToast();
  const qc = useQueryClient();

  // ── Data Fetching ─────────────────────────────────────────────

  const { data: dashboard } = useQuery<DashboardData>({
    queryKey: ["/api/dark-web/dashboard"],
  });

  const { data: exposuresData, isLoading: exposuresLoading } = useQuery<{
    exposures: DarkWebExposure[];
    total: number;
    stats: {
      totalExposures: number;
      criticalCount: number;
      highCount: number;
      newCount: number;
      mitigatedCount: number;
    };
  }>({
    queryKey: ["/api/dark-web/exposures", search, typeFilter, severityFilter, statusFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (typeFilter !== "all") params.set("type", typeFilter);
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      return apiRequest("GET", `/api/dark-web/exposures?${params.toString()}`).then((r) => r.json());
    },
  });

  const { data: targetsData } = useQuery<{
    targets: BreachMonitoringTarget[];
    total: number;
  }>({
    queryKey: ["/api/dark-web/targets"],
  });

  const { data: scansData } = useQuery<{ scans: ScanHistoryEntry[] }>({
    queryKey: ["/api/dark-web/scans"],
  });

  const { data: exposureDetail } = useQuery<DarkWebExposure>({
    queryKey: ["/api/dark-web/exposures", selectedExposure],
    queryFn: () => apiRequest("GET", `/api/dark-web/exposures/${selectedExposure}`).then((r) => r.json()),
    enabled: !!selectedExposure,
  });

  // ── Mutations ─────────────────────────────────────────────────

  const addTargetMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/dark-web/targets", data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Monitoring target added" });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/targets"] });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/dashboard"] });
      setAddTargetOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to add target", description: err.message, variant: "destructive" });
    },
  });

  const deleteTargetMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/dark-web/targets/${id}`),
    onSuccess: () => {
      toast({ title: "Target removed" });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/targets"] });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/dashboard"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete target", description: err.message, variant: "destructive" });
    },
  });

  const updateExposureMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      apiRequest("PATCH", `/api/dark-web/exposures/${id}`, data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Exposure updated" });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/exposures"] });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/dashboard"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update", description: err.message, variant: "destructive" });
    },
  });

  const runScanMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/dark-web/scan").then((r) => r.json()),
    onSuccess: (data) => {
      toast({
        title: "Scan completed",
        description: `Scanned ${data.targetsScanned} targets, found ${data.newExposures} new exposures`,
      });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/exposures"] });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/dashboard"] });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/scans"] });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/targets"] });
    },
    onError: (err: Error) => {
      toast({ title: "Scan failed", description: err.message, variant: "destructive" });
    },
  });

  const saveConfigMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      apiRequest("POST", "/api/dark-web/config", data).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Configuration saved" });
      qc.invalidateQueries({ queryKey: ["/api/dark-web/dashboard"] });
      setConfigOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to save config", description: err.message, variant: "destructive" });
    },
  });

  const stats = dashboard?.exposureStats;
  const targets = targetsData?.targets || [];
  const exposures = exposuresData?.exposures || [];
  const scans = scansData?.scans || [];

  // ── Render ────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dark Web Monitoring</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Monitor credential exposures, data breaches, brand mentions, and threat actor activity
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setConfigOpen(true)}>
            <EyeOff className="h-4 w-4 mr-1" />
            Configure
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => runScanMutation.mutate()}
            disabled={runScanMutation.isPending}
          >
            {runScanMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-1" />
            )}
            Run Scan
          </Button>
          <Dialog open={addTargetOpen} onOpenChange={setAddTargetOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-1" />
                Add Target
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Add Monitoring Target</DialogTitle>
                <DialogDescription>Add an email, domain, or keyword to monitor on the dark web</DialogDescription>
              </DialogHeader>
              <AddTargetForm
                onSubmit={(data) => addTargetMutation.mutate(data)}
                isPending={addTargetMutation.isPending}
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <EyeOff className="h-4 w-4 text-muted-foreground" />
              <span className="text-xs text-muted-foreground">Total Exposures</span>
            </div>
            <div className="text-2xl font-semibold">{stats?.total || 0}</div>
            <div className="text-xs text-muted-foreground mt-1">
              {stats?.newCount || 0} new, {stats?.mitigated || 0} mitigated
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              <span className="text-xs text-muted-foreground">Critical & High</span>
            </div>
            <div className="text-2xl font-semibold text-red-500">{(stats?.critical || 0) + (stats?.high || 0)}</div>
            <div className="text-xs text-muted-foreground mt-1">
              {stats?.critical || 0} critical, {stats?.high || 0} high severity
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <Target className="h-4 w-4 text-blue-500" />
              <span className="text-xs text-muted-foreground">Monitoring Targets</span>
            </div>
            <div className="text-2xl font-semibold">{targets.length}</div>
            <div className="text-xs text-muted-foreground mt-1">
              {dashboard?.targetCounts?.length || 0} target types active
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <span className="text-xs text-muted-foreground">Last Scan</span>
            </div>
            <div className="text-sm font-medium">
              {dashboard?.lastScan ? formatDateTime(dashboard.lastScan.completedAt) : "Never"}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {dashboard?.lastScan ? `${dashboard.lastScan.newExposuresFound} new findings` : "No scans run yet"}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabs */}
      <Tabs defaultValue="exposures">
        <TabsList>
          <TabsTrigger value="exposures">Exposures</TabsTrigger>
          <TabsTrigger value="targets">Monitoring Targets</TabsTrigger>
          <TabsTrigger value="scan-history">Scan History</TabsTrigger>
          <TabsTrigger value="breakdown">Breakdown</TabsTrigger>
        </TabsList>

        {/* ── Exposures Tab ──────────────────────────────────────── */}
        <TabsContent value="exposures" className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search exposures..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 h-9"
              />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-[180px] h-9">
                <SelectValue placeholder="Exposure Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="credential_leak">Credential Leak</SelectItem>
                <SelectItem value="data_breach">Data Breach</SelectItem>
                <SelectItem value="brand_mention">Brand Mention</SelectItem>
                <SelectItem value="executive_exposure">Executive Exposure</SelectItem>
                <SelectItem value="source_code_leak">Source Code Leak</SelectItem>
                <SelectItem value="pii_exposure">PII Exposure</SelectItem>
                <SelectItem value="credit_card_exposure">Credit Card</SelectItem>
                <SelectItem value="threat_actor_mention">Threat Actor</SelectItem>
                <SelectItem value="paste_site">Paste Site</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[140px] h-9">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px] h-9">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                {EXPOSURE_STATUSES.map((s) => (
                  <SelectItem key={s.value} value={s.value}>
                    {s.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {exposuresLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : exposures.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <EyeOff className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
                <h3 className="text-lg font-medium mb-1">No exposures found</h3>
                <p className="text-sm text-muted-foreground">
                  {targets.length === 0
                    ? "Add monitoring targets and run a scan to discover dark web exposures."
                    : "No dark web exposures match your current filters."}
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {exposures.map((exposure) => {
                const TypeIcon = exposureTypeIcon(exposure.exposureType);
                return (
                  <Card
                    key={exposure.id}
                    className="cursor-pointer hover:bg-muted/30 transition-colors"
                    onClick={() => setSelectedExposure(exposure.id)}
                  >
                    <CardContent className="py-3 px-4">
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5">
                          <TypeIcon className="h-4 w-4 text-muted-foreground" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm font-medium truncate">{exposure.title}</span>
                            <Badge variant="outline" className={severityColor(exposure.severity)}>
                              {exposure.severity}
                            </Badge>
                            <Badge variant="outline" className={statusColor(exposure.status)}>
                              {exposure.status.replace("_", " ")}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>{exposureTypeLabel(exposure.exposureType)}</span>
                            <span>Source: {exposure.sourceName || exposure.sourceType}</span>
                            {exposure.breachDate && <span>Breach: {formatDate(exposure.breachDate)}</span>}
                            <span>Discovered: {formatDate(exposure.discoveredAt)}</span>
                            {exposure.affectedCount && <span>{exposure.affectedCount.toLocaleString()} records</span>}
                          </div>
                          {exposure.affectedData && exposure.affectedData.length > 0 && (
                            <div className="flex items-center gap-1 mt-1">
                              {exposure.affectedData.slice(0, 5).map((d) => (
                                <Badge key={d} variant="secondary" className="text-[10px] px-1.5 py-0">
                                  {d}
                                </Badge>
                              ))}
                              {exposure.affectedData.length > 5 && (
                                <span className="text-[10px] text-muted-foreground">
                                  +{exposure.affectedData.length - 5} more
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          {exposure.confidenceScore != null && (
                            <span className="text-xs text-muted-foreground">
                              {exposure.confidenceScore}% confidence
                            </span>
                          )}
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
              {(exposuresData?.total || 0) > exposures.length && (
                <p className="text-xs text-muted-foreground text-center py-2">
                  Showing {exposures.length} of {exposuresData?.total} exposures
                </p>
              )}
            </div>
          )}
        </TabsContent>

        {/* ── Targets Tab ────────────────────────────────────────── */}
        <TabsContent value="targets" className="space-y-4">
          {targets.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Target className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
                <h3 className="text-lg font-medium mb-1">No monitoring targets</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Add email addresses, domains, or keywords to monitor on the dark web.
                </p>
                <Button size="sm" onClick={() => setAddTargetOpen(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Add Target
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {targets.map((target) => {
                const TIcon = targetTypeIcon(target.targetType);
                return (
                  <Card key={target.id}>
                    <CardContent className="py-3 px-4">
                      <div className="flex items-center gap-3">
                        <TIcon className="h-4 w-4 text-muted-foreground" />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">
                              {target.label || redactValue(target.targetValue)}
                            </span>
                            <Badge variant="outline" className="text-[10px]">
                              {targetTypeLabel(target.targetType)}
                            </Badge>
                            {target.isActive ? (
                              <Badge variant="outline" className="bg-green-500/10 text-green-500 text-[10px]">
                                Active
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="bg-muted text-muted-foreground text-[10px]">
                                Disabled
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                            <span>{target.exposureCount} exposures found</span>
                            <span>Last checked: {formatDateTime(target.lastCheckedAt)}</span>
                            <span>Added: {formatDate(target.createdAt)}</span>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          onClick={() => deleteTargetMutation.mutate(target.id)}
                        >
                          <XCircle className="h-4 w-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* ── Scan History Tab ───────────────────────────────────── */}
        <TabsContent value="scan-history" className="space-y-4">
          {scans.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <RefreshCw className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
                <h3 className="text-lg font-medium mb-1">No scans yet</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Configure monitoring and run your first scan to check for dark web exposures.
                </p>
                <Button size="sm" onClick={() => runScanMutation.mutate()} disabled={runScanMutation.isPending}>
                  {runScanMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-1" />
                  )}
                  Run First Scan
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {scans.map((scan) => (
                <Card key={scan.id}>
                  <CardContent className="py-3 px-4">
                    <div className="flex items-center gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-sm font-medium capitalize">{scan.scanType} Scan</span>
                          <Badge
                            variant="outline"
                            className={
                              scan.status === "completed"
                                ? "bg-green-500/10 text-green-500"
                                : scan.status === "failed"
                                  ? "bg-red-500/10 text-red-500"
                                  : "bg-yellow-500/10 text-yellow-500"
                            }
                          >
                            {scan.status}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Started: {formatDateTime(scan.startedAt)}</span>
                          <span>{scan.targetsScanned} targets scanned</span>
                          <span>{scan.newExposuresFound} new exposures</span>
                          {scan.durationMs != null && <span>{(scan.durationMs / 1000).toFixed(1)}s duration</span>}
                          {scan.sourcesChecked && scan.sourcesChecked.length > 0 && (
                            <span>Sources: {scan.sourcesChecked.join(", ")}</span>
                          )}
                        </div>
                        {scan.errorMessage && <p className="text-xs text-red-500 mt-1">{scan.errorMessage}</p>}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Breakdown Tab ──────────────────────────────────────── */}
        <TabsContent value="breakdown" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Exposure Types Breakdown */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Exposures by Type</CardTitle>
              </CardHeader>
              <CardContent>
                {dashboard?.exposuresByType && dashboard.exposuresByType.length > 0 ? (
                  <div className="space-y-2">
                    {dashboard.exposuresByType.map((item) => {
                      const TypeIcon = exposureTypeIcon(item.exposureType);
                      const total = dashboard.exposureStats.total || 1;
                      const pct = Math.round((item.count / total) * 100);
                      return (
                        <div key={item.exposureType} className="flex items-center gap-2">
                          <TypeIcon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          <span className="text-xs min-w-[120px]">{exposureTypeLabel(item.exposureType)}</span>
                          <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                            <div className="h-full bg-primary/60 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground min-w-[40px] text-right">{item.count}</span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No data yet</p>
                )}
              </CardContent>
            </Card>

            {/* Severity Distribution */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                {stats ? (
                  <div className="space-y-3">
                    {[
                      { label: "Critical", count: stats.critical, dotColor: "bg-red-500", fillColor: "bg-red-500/60" },
                      { label: "High", count: stats.high, dotColor: "bg-orange-500", fillColor: "bg-orange-500/60" },
                      {
                        label: "Medium",
                        count: stats.medium,
                        dotColor: "bg-yellow-500",
                        fillColor: "bg-yellow-500/60",
                      },
                      { label: "Low", count: stats.low, dotColor: "bg-blue-500", fillColor: "bg-blue-500/60" },
                    ].map((item) => {
                      const total = stats.total || 1;
                      const pct = Math.round((item.count / total) * 100);
                      return (
                        <div key={item.label} className="flex items-center gap-2">
                          <div className={`h-2.5 w-2.5 rounded-full ${item.dotColor}`} />
                          <span className="text-xs min-w-[60px]">{item.label}</span>
                          <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                            <div className={`h-full rounded-full ${item.fillColor}`} style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground min-w-[30px] text-right">{item.count}</span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No data yet</p>
                )}
              </CardContent>
            </Card>

            {/* Target Coverage */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Target Coverage</CardTitle>
              </CardHeader>
              <CardContent>
                {dashboard?.targetCounts && dashboard.targetCounts.length > 0 ? (
                  <div className="space-y-2">
                    {dashboard.targetCounts.map((item) => {
                      const TIcon = targetTypeIcon(item.targetType);
                      return (
                        <div key={item.targetType} className="flex items-center gap-2">
                          <TIcon className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="text-xs flex-1">{targetTypeLabel(item.targetType)}</span>
                          <span className="text-sm font-medium">{item.count}</span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No monitoring targets configured</p>
                )}
              </CardContent>
            </Card>

            {/* Status Summary */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Exposure Status</CardTitle>
              </CardHeader>
              <CardContent>
                {stats ? (
                  <div className="space-y-2">
                    {[
                      { label: "New (unacknowledged)", count: stats.newCount, icon: AlertTriangle },
                      { label: "Investigating", count: stats.investigating, icon: Eye },
                      { label: "Mitigated", count: stats.mitigated, icon: CheckCircle2 },
                    ].map((item) => (
                      <div key={item.label} className="flex items-center gap-2">
                        <item.icon className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="text-xs flex-1">{item.label}</span>
                        <span className="text-sm font-medium">{item.count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground py-4 text-center">No data yet</p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* ── Exposure Detail Dialog ─────────────────────────────────── */}
      <Dialog open={!!selectedExposure} onOpenChange={(open) => !open && setSelectedExposure(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-base">Exposure Detail</DialogTitle>
          </DialogHeader>
          {exposureDetail && (
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium mb-1">{exposureDetail.title}</h3>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={severityColor(exposureDetail.severity)}>
                    {exposureDetail.severity}
                  </Badge>
                  <Badge variant="outline" className={statusColor(exposureDetail.status)}>
                    {exposureDetail.status.replace("_", " ")}
                  </Badge>
                  <Badge variant="outline">{exposureTypeLabel(exposureDetail.exposureType)}</Badge>
                </div>
              </div>

              {exposureDetail.description && (
                <div>
                  <Label className="text-xs text-muted-foreground">Description</Label>
                  <p className="text-sm mt-1">{exposureDetail.description}</p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <Label className="text-xs text-muted-foreground">Source</Label>
                  <p>{exposureDetail.sourceName || exposureDetail.sourceType}</p>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Matched Value</Label>
                  <p>{redactValue(exposureDetail.matchedValue)}</p>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Breach Date</Label>
                  <p>{formatDate(exposureDetail.breachDate)}</p>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Discovered</Label>
                  <p>{formatDateTime(exposureDetail.discoveredAt)}</p>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Affected Records</Label>
                  <p>{exposureDetail.affectedCount?.toLocaleString() || "Unknown"}</p>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Confidence</Label>
                  <p>{exposureDetail.confidenceScore != null ? `${exposureDetail.confidenceScore}%` : "—"}</p>
                </div>
              </div>

              {exposureDetail.affectedData && exposureDetail.affectedData.length > 0 && (
                <div>
                  <Label className="text-xs text-muted-foreground">Exposed Data Types</Label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {exposureDetail.affectedData.map((d) => (
                      <Badge key={d} variant="secondary" className="text-xs">
                        {d}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {exposureDetail.mitigationNotes && (
                <div>
                  <Label className="text-xs text-muted-foreground">Mitigation Notes</Label>
                  <p className="text-sm mt-1">{exposureDetail.mitigationNotes}</p>
                </div>
              )}

              <div className="flex items-center gap-2 pt-2 border-t">
                <Select
                  value={exposureDetail.status}
                  onValueChange={(value) => updateExposureMutation.mutate({ id: exposureDetail.id, status: value })}
                >
                  <SelectTrigger className="w-[180px] h-9">
                    <SelectValue placeholder="Change Status" />
                  </SelectTrigger>
                  <SelectContent>
                    {EXPOSURE_STATUSES.map((s) => (
                      <SelectItem key={s.value} value={s.value}>
                        {s.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select
                  value={exposureDetail.severity}
                  onValueChange={(value) => updateExposureMutation.mutate({ id: exposureDetail.id, severity: value })}
                >
                  <SelectTrigger className="w-[140px] h-9">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* ── Configuration Dialog ───────────────────────────────────── */}
      <Dialog open={configOpen} onOpenChange={setConfigOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Dark Web Monitoring Configuration</DialogTitle>
            <DialogDescription>
              Configure scanning frequency, alerting thresholds, and API integrations
            </DialogDescription>
          </DialogHeader>
          <ConfigForm
            config={dashboard?.config || null}
            onSubmit={(data) => saveConfigMutation.mutate(data)}
            isPending={saveConfigMutation.isPending}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── Add Target Form ───────────────────────────────────────────────

function AddTargetForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [targetType, setTargetType] = useState("email");
  const [targetValue, setTargetValue] = useState("");
  const [label, setLabel] = useState("");

  return (
    <div className="space-y-4">
      <div>
        <Label>Target Type</Label>
        <Select value={targetType} onValueChange={setTargetType}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TARGET_TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label>
          {targetType === "email" || targetType === "executive_email"
            ? "Email Address"
            : targetType === "domain"
              ? "Domain"
              : "Value"}
        </Label>
        <Input
          placeholder={
            targetType === "email" ? "user@example.com" : targetType === "domain" ? "example.com" : "Enter value..."
          }
          value={targetValue}
          onChange={(e) => setTargetValue(e.target.value)}
        />
      </div>
      <div>
        <Label>Label (optional)</Label>
        <Input placeholder="Friendly name for this target" value={label} onChange={(e) => setLabel(e.target.value)} />
      </div>
      <DialogFooter>
        <Button
          onClick={() => onSubmit({ targetType, targetValue, label: label || undefined })}
          disabled={isPending || !targetValue}
        >
          {isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
          Add Target
        </Button>
      </DialogFooter>
    </div>
  );
}

// ── Configuration Form ────────────────────────────────────────────

function ConfigForm({
  config,
  onSubmit,
  isPending,
}: {
  config: MonitoringConfig | null;
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [isEnabled, setIsEnabled] = useState(config?.isEnabled ?? true);
  const [scanFrequency, setScanFrequency] = useState(String(config?.scanFrequencyHours ?? 24));
  const [alertThreshold, setAlertThreshold] = useState(config?.alertSeverityThreshold ?? "medium");
  const [autoCreateAlerts, setAutoCreateAlerts] = useState(config?.autoCreateAlerts ?? true);
  const [notifyOnNew, setNotifyOnNew] = useState(config?.notifyOnNewExposure ?? true);
  const [hibpApiKey, setHibpApiKey] = useState("");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Label>Monitoring Enabled</Label>
        <Button variant={isEnabled ? "default" : "outline"} size="sm" onClick={() => setIsEnabled(!isEnabled)}>
          {isEnabled ? "Enabled" : "Disabled"}
        </Button>
      </div>
      <div>
        <Label>Scan Frequency (hours)</Label>
        <Input
          type="number"
          min="1"
          max="168"
          value={scanFrequency}
          onChange={(e) => setScanFrequency(e.target.value)}
        />
      </div>
      <div>
        <Label>Alert Severity Threshold</Label>
        <Select value={alertThreshold} onValueChange={setAlertThreshold}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="critical">Critical only</SelectItem>
            <SelectItem value="high">High and above</SelectItem>
            <SelectItem value="medium">Medium and above</SelectItem>
            <SelectItem value="low">Low and above</SelectItem>
            <SelectItem value="info">All</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="flex items-center justify-between">
        <Label>Auto-create Alerts</Label>
        <Button
          variant={autoCreateAlerts ? "default" : "outline"}
          size="sm"
          onClick={() => setAutoCreateAlerts(!autoCreateAlerts)}
        >
          {autoCreateAlerts ? "Yes" : "No"}
        </Button>
      </div>
      <div className="flex items-center justify-between">
        <Label>Notify on New Exposure</Label>
        <Button variant={notifyOnNew ? "default" : "outline"} size="sm" onClick={() => setNotifyOnNew(!notifyOnNew)}>
          {notifyOnNew ? "Yes" : "No"}
        </Button>
      </div>
      <div>
        <Label>HaveIBeenPwned API Key</Label>
        <Input
          type="password"
          placeholder={config?.hibpApiKey ? "***configured***" : "Enter HIBP API key"}
          value={hibpApiKey}
          onChange={(e) => setHibpApiKey(e.target.value)}
        />
        <p className="text-xs text-muted-foreground mt-1">
          Required for email breach lookups. Get one at haveibeenpwned.com/API/Key
        </p>
      </div>
      <DialogFooter>
        <Button
          onClick={() =>
            onSubmit({
              isEnabled,
              scanFrequencyHours: parseInt(scanFrequency) || 24,
              alertSeverityThreshold: alertThreshold,
              autoCreateAlerts,
              notifyOnNewExposure: notifyOnNew,
              ...(hibpApiKey ? { hibpApiKey } : {}),
            })
          }
          disabled={isPending}
        >
          {isPending && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}
          Save Configuration
        </Button>
      </DialogFooter>
    </div>
  );
}
