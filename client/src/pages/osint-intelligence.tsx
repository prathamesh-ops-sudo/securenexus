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
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  Search,
  Plus,
  Globe,
  Shield,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  MapPin,
  Network,
  Calendar,
  Bell,
  BellRing,
  Play,
  Trash2,
  Settings2,
  Loader2,
  Server,
  Eye,
  Zap,
  BarChart3,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";

// ── Types ─────────────────────────────────────────────────────────

interface OsintSource {
  id: string;
  orgId: string;
  name: string;
  provider: string;
  apiKeyRef: string | null;
  enabled: boolean;
  status: string;
  lastQueryAt: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastErrorMessage: string | null;
  apiQuotaTotal: number | null;
  apiQuotaUsed: number | null;
  apiQuotaResetAt: string | null;
  avgResponseTimeMs: number | null;
  totalQueries: number;
  successfulQueries: number;
  failedQueries: number;
  config: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

interface OsintQuery {
  id: string;
  orgId: string;
  sourceId: string | null;
  queryType: string;
  queryValue: string;
  status: string;
  resultCount: number;
  results: Record<string, unknown>[];
  geoData: GeoPoint[];
  domainGraph: DomainGraph;
  timeline: TimelineEntry[];
  errorMessage: string | null;
  durationMs: number | null;
  createdAt: string;
  completedAt: string | null;
}

interface GeoPoint {
  ip: string;
  lat: number;
  lng: number;
  country: string;
  city: string;
  asn: string;
}

interface DomainGraph {
  nodes: { id: string; label: string; type: string }[];
  edges: { source: string; target: string; label: string }[];
}

interface TimelineEntry {
  timestamp: string;
  event: string;
  source: string;
  value: string;
}

interface OsintAlertRule {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  enabled: boolean;
  sourceProvider: string | null;
  ruleType: string;
  conditions: Record<string, unknown>;
  actions: Record<string, unknown>;
  schedule: string;
  lastRunAt: string | null;
  lastMatchCount: number;
  totalMatches: number;
  totalRuns: number;
  createdAt: string;
  updatedAt: string;
}

interface HealthDashboard {
  totalSources: number;
  healthy: number;
  degraded: number;
  error: number;
  unknown: number;
  sources: {
    id: string;
    name: string;
    provider: string;
    enabled: boolean;
    status: string;
    lastQueryAt: string | null;
    lastSuccessAt: string | null;
    lastErrorAt: string | null;
    lastErrorMessage: string | null;
    apiQuotaTotal: number | null;
    apiQuotaUsed: number | null;
    apiQuotaResetAt: string | null;
    avgResponseTimeMs: number | null;
    successRate: number | null;
    totalQueries: number;
  }[];
}

// 5.4: Scheduled scan type
interface ScheduledScan {
  id: string;
  orgId: string;
  sourceId: string | null;
  name: string;
  queryType: string;
  queryValue: string;
  schedule: string;
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  lastRunStatus: string | null;
  lastRunResultCount: number | null;
  totalRuns: number;
  totalChangesDetected: number;
  createdAt: string;
  updatedAt: string;
}

// 5.6: Quota summary type
interface QuotaSourceSummary {
  sourceId: string;
  sourceName: string;
  provider: string;
  enabled: boolean;
  quotaTotal: number;
  quotaUsed: number;
  quotaRemaining: number;
  quotaPercent: number;
  quotaResetAt: string | null;
  isWarning: boolean;
  isCritical: boolean;
  last24h: {
    totalCalls: number;
    successCalls: number;
    failedCalls: number;
    avgResponseTimeMs: number;
  };
}

interface QuotaSummary {
  totalSources: number;
  totalWarnings: number;
  totalCritical: number;
  sources: QuotaSourceSummary[];
}

// ── Helpers ───────────────────────────────────────────────────────

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function statusColor(status: string): string {
  switch (status) {
    case "healthy":
      return "bg-emerald-500";
    case "degraded":
      return "bg-amber-500";
    case "error":
      return "bg-red-500";
    default:
      return "bg-zinc-400";
  }
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "healthy":
      return "default";
    case "degraded":
      return "secondary";
    case "error":
      return "destructive";
    default:
      return "outline";
  }
}

function providerIcon(provider: string) {
  switch (provider) {
    case "shodan":
      return <Server className="h-4 w-4" />;
    case "censys":
      return <Search className="h-4 w-4" />;
    case "virustotal":
      return <Shield className="h-4 w-4" />;
    case "greynoise":
      return <Activity className="h-4 w-4" />;
    case "urlscan":
      return <Globe className="h-4 w-4" />;
    case "pastes":
      return <Eye className="h-4 w-4" />;
    default:
      return <Globe className="h-4 w-4" />;
  }
}

const PROVIDERS = ["shodan", "censys", "virustotal", "greynoise", "urlscan", "pastes", "abuseipdb", "otx"];
const QUERY_TYPES = ["ip_lookup", "domain_lookup", "hash_lookup", "search", "passive_dns", "cert_search"];
const RULE_TYPES = [
  "new_service",
  "paste_mention",
  "new_vuln",
  "domain_change",
  "ip_reputation_drop",
  "cert_expiry",
  "exposed_credential",
  "new_port",
];
const SCHEDULES = ["realtime", "hourly", "daily", "weekly"];

// ── Main Page ─────────────────────────────────────────────────────

export default function OsintIntelligencePage() {
  usePageTitle("OSINT Intelligence");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState("visualization");
  const [showAddSourceDialog, setShowAddSourceDialog] = useState(false);
  const [showAddRuleDialog, setShowAddRuleDialog] = useState(false);
  const [showQueryDialog, setShowQueryDialog] = useState(false);
  const [showAddScheduledScanDialog, setShowAddScheduledScanDialog] = useState(false);
  const [selectedQuery, setSelectedQuery] = useState<OsintQuery | null>(null);

  // Scheduled scan form state
  const [schedScanName, setSchedScanName] = useState("");
  const [schedScanQueryType, setSchedScanQueryType] = useState("ip_lookup");
  const [schedScanQueryValue, setSchedScanQueryValue] = useState("");
  const [schedScanSchedule, setSchedScanSchedule] = useState("daily");
  const [schedScanSourceId, setSchedScanSourceId] = useState("");

  // Query form state
  const [queryType, setQueryType] = useState("ip_lookup");
  const [queryValue, setQueryValue] = useState("");
  const [querySourceId, setQuerySourceId] = useState("");

  // Source form state
  const [sourceName, setSourceName] = useState("");
  const [sourceProvider, setSourceProvider] = useState("shodan");
  const [sourceApiKey, setSourceApiKey] = useState("");

  // Rule form state
  const [ruleName, setRuleName] = useState("");
  const [ruleDescription, setRuleDescription] = useState("");
  const [ruleType, setRuleType] = useState("new_service");
  const [ruleProvider, setRuleProvider] = useState("all");
  const [ruleSchedule, setRuleSchedule] = useState("hourly");
  const [ruleIpRanges, setRuleIpRanges] = useState("");
  const [ruleDomains, setRuleDomains] = useState("");
  const [ruleKeywords, setRuleKeywords] = useState("");
  const [ruleSeverity, setRuleSeverity] = useState("high");

  // ── Data queries ────────────────────────────────────────────────

  const { data: sources } = useQuery<OsintSource[]>({
    queryKey: ["/api/osint/sources"],
  });

  const { data: queries, isLoading: queriesLoading } = useQuery<OsintQuery[]>({
    queryKey: ["/api/osint/queries"],
  });

  const { data: alertRules } = useQuery<OsintAlertRule[]>({
    queryKey: ["/api/osint/alert-rules"],
  });

  const { data: healthDashboard } = useQuery<HealthDashboard>({
    queryKey: ["/api/osint/sources/health"],
  });

  // 5.4: Scheduled scans data
  const { data: scheduledScans } = useQuery<ScheduledScan[]>({
    queryKey: ["/api/osint/scheduled-scans"],
  });

  // 5.6: Quota data
  const { data: quotaData } = useQuery<QuotaSummary>({
    queryKey: ["/api/osint/quota"],
  });

  // ── Mutations ───────────────────────────────────────────────────

  const runQueryMutation = useMutation({
    mutationFn: async (params: { queryType: string; queryValue: string; sourceId?: string }) => {
      const res = await apiRequest("POST", "/api/osint/queries", params);
      return (await res.json()) as { data: OsintQuery };
    },
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/queries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources/health"] });
      setSelectedQuery(response.data);
      setShowQueryDialog(false);
      toast({ title: "Query completed", description: `Found ${response.data.resultCount} results` });
    },
    onError: (error: Error) => {
      toast({ title: "Query failed", description: error.message, variant: "destructive" });
    },
  });

  const addSourceMutation = useMutation({
    mutationFn: async (params: { name: string; provider: string; apiKeyRef?: string }) => {
      const res = await apiRequest("POST", "/api/osint/sources", params);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources/health"] });
      setShowAddSourceDialog(false);
      setSourceName("");
      setSourceApiKey("");
      toast({ title: "Source added" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to add source", description: error.message, variant: "destructive" });
    },
  });

  const testSourceMutation = useMutation({
    mutationFn: async (sourceId: string) => {
      const res = await apiRequest("POST", `/api/osint/sources/${sourceId}/test`);
      return res.json();
    },
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources/health"] });
      const data = response.data || response;
      toast({
        title: data.success ? "Source healthy" : "Source unreachable",
        description: data.success ? `Response time: ${data.responseTimeMs}ms` : data.error || "Connection failed",
        variant: data.success ? "default" : "destructive",
      });
    },
    onError: (error: Error) => {
      toast({ title: "Test failed", description: error.message, variant: "destructive" });
    },
  });

  const deleteSourceMutation = useMutation({
    mutationFn: async (sourceId: string) => {
      await apiRequest("DELETE", `/api/osint/sources/${sourceId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources/health"] });
      toast({ title: "Source deleted" });
    },
  });

  const addRuleMutation = useMutation({
    mutationFn: async (params: Record<string, unknown>) => {
      const res = await apiRequest("POST", "/api/osint/alert-rules", params);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/alert-rules"] });
      setShowAddRuleDialog(false);
      setRuleName("");
      setRuleDescription("");
      setRuleIpRanges("");
      setRuleDomains("");
      setRuleKeywords("");
      toast({ title: "Alert rule created" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create rule", description: error.message, variant: "destructive" });
    },
  });

  const toggleRuleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/osint/alert-rules/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/alert-rules"] });
    },
  });

  const runRuleMutation = useMutation({
    mutationFn: async (ruleId: string) => {
      const res = await apiRequest("POST", `/api/osint/alert-rules/${ruleId}/run`);
      return res.json();
    },
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/alert-rules"] });
      const data = response.data || response;
      toast({ title: "Rule evaluated", description: data.message });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: async (ruleId: string) => {
      await apiRequest("DELETE", `/api/osint/alert-rules/${ruleId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/alert-rules"] });
      toast({ title: "Rule deleted" });
    },
  });

  // 5.4: Scheduled scan mutations
  const addScheduledScanMutation = useMutation({
    mutationFn: async (params: {
      name: string;
      queryType: string;
      queryValue: string;
      schedule: string;
      sourceId?: string;
    }) => {
      const res = await apiRequest("POST", "/api/osint/scheduled-scans", params);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/scheduled-scans"] });
      setShowAddScheduledScanDialog(false);
      setSchedScanName("");
      setSchedScanQueryValue("");
      toast({ title: "Scheduled scan created" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create scheduled scan", description: error.message, variant: "destructive" });
    },
  });

  const runScheduledScanMutation = useMutation({
    mutationFn: async (scanId: string) => {
      const res = await apiRequest("POST", `/api/osint/scheduled-scans/${scanId}/run`);
      return res.json();
    },
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/scheduled-scans"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/queries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/quota"] });
      const data = response.data || response;
      toast({
        title: data.success ? "Scan completed" : "Scan failed",
        description: data.success
          ? `${data.resultCount} results, ${data.newFindings} new, ${data.resolvedFindings} resolved`
          : data.error,
        variant: data.success ? "default" : "destructive",
      });
    },
    onError: (error: Error) => {
      toast({ title: "Scan failed", description: error.message, variant: "destructive" });
    },
  });

  const toggleScheduledScanMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/osint/scheduled-scans/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/scheduled-scans"] });
    },
  });

  const deleteScheduledScanMutation = useMutation({
    mutationFn: async (scanId: string) => {
      await apiRequest("DELETE", `/api/osint/scheduled-scans/${scanId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/scheduled-scans"] });
      toast({ title: "Scheduled scan deleted" });
    },
  });

  // 5.6: Quota reset mutation
  const resetQuotaMutation = useMutation({
    mutationFn: async (sourceId: string) => {
      const res = await apiRequest("POST", `/api/osint/sources/${sourceId}/quota/reset`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint/quota"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources"] });
      queryClient.invalidateQueries({ queryKey: ["/api/osint/sources/health"] });
      toast({ title: "Quota reset" });
    },
  });

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">OSINT Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Query external intelligence sources, visualize results, and set up automated alerts
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowAddSourceDialog(true)}>
            <Plus className="h-4 w-4 mr-1" /> Add Source
          </Button>
          <Button size="sm" onClick={() => setShowQueryDialog(true)}>
            <Search className="h-4 w-4 mr-1" /> New Query
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="visualization">
            <MapPin className="h-4 w-4 mr-1" /> Results & Visualization
          </TabsTrigger>
          <TabsTrigger value="alert-rules">
            <Bell className="h-4 w-4 mr-1" /> Alert Rules
          </TabsTrigger>
          <TabsTrigger value="health">
            <Activity className="h-4 w-4 mr-1" /> Source Health
          </TabsTrigger>
          <TabsTrigger value="scheduled">
            <Calendar className="h-4 w-4 mr-1" /> Scheduled Scans
          </TabsTrigger>
          <TabsTrigger value="quota">
            <BarChart3 className="h-4 w-4 mr-1" /> API Quota
          </TabsTrigger>
        </TabsList>

        {/* ── 5.1: Results & Visualization Tab ── */}
        <TabsContent value="visualization" className="space-y-4">
          {selectedQuery ? (
            <QueryVisualization query={selectedQuery} onBack={() => setSelectedQuery(null)} />
          ) : (
            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Recent Queries</CardTitle>
                  <CardDescription>Click a query to view its results and visualizations</CardDescription>
                </CardHeader>
                <CardContent>
                  {queriesLoading ? (
                    <div className="flex items-center justify-center py-8 text-muted-foreground">
                      <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading queries...
                    </div>
                  ) : !queries || queries.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p>No queries yet. Run your first OSINT query to see results here.</p>
                      <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowQueryDialog(true)}>
                        <Search className="h-4 w-4 mr-1" /> Run Query
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {queries.map((q) => (
                        <div
                          key={q.id}
                          className="flex items-center justify-between p-3 border rounded-md cursor-pointer hover:bg-muted/50 transition-colors"
                          onClick={() => setSelectedQuery(q)}
                        >
                          <div className="flex items-center gap-3">
                            <Badge variant="outline" className="font-mono text-xs">
                              {q.queryType.replace("_", " ")}
                            </Badge>
                            <span className="font-medium text-sm">{q.queryValue}</span>
                          </div>
                          <div className="flex items-center gap-3 text-sm text-muted-foreground">
                            <span>{q.resultCount} results</span>
                            {q.durationMs !== null && <span>{q.durationMs}ms</span>}
                            <span>{timeAgo(q.createdAt)}</span>
                            <Badge variant={q.status === "completed" ? "default" : "destructive"} className="text-xs">
                              {q.status}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── 5.2: Alert Rules Tab ── */}
        <TabsContent value="alert-rules" className="space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold">OSINT Alert Rules</h2>
              <p className="text-sm text-muted-foreground">
                Get alerted when OSINT sources discover exposed services, paste mentions, or domain changes
              </p>
            </div>
            <Button size="sm" onClick={() => setShowAddRuleDialog(true)}>
              <Plus className="h-4 w-4 mr-1" /> Create Rule
            </Button>
          </div>

          {!alertRules || alertRules.length === 0 ? (
            <Card>
              <CardContent className="text-center py-8 text-muted-foreground">
                <BellRing className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No alert rules configured yet.</p>
                <p className="text-xs mt-1">Create rules to automatically monitor your assets across OSINT sources.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddRuleDialog(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Create First Rule
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-3">
              {alertRules.map((rule) => (
                <Card key={rule.id}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={(checked) => toggleRuleMutation.mutate({ id: rule.id, enabled: checked })}
                        />
                        <div>
                          <div className="font-medium text-sm">{rule.name}</div>
                          {rule.description && (
                            <div className="text-xs text-muted-foreground mt-0.5">{rule.description}</div>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">
                          {rule.ruleType.replace(/_/g, " ")}
                        </Badge>
                        <Badge variant="secondary" className="text-xs">
                          {rule.schedule}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {rule.sourceProvider || "all sources"}
                        </Badge>
                        <div className="text-xs text-muted-foreground ml-2">
                          {rule.totalMatches} matches / {rule.totalRuns} runs
                        </div>
                        {rule.lastRunAt && (
                          <span className="text-xs text-muted-foreground">Last: {timeAgo(rule.lastRunAt)}</span>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={() => runRuleMutation.mutate(rule.id)}
                          disabled={runRuleMutation.isPending}
                        >
                          <Play className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive"
                          onClick={() => deleteRuleMutation.mutate(rule.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── 5.3: Source Health Dashboard Tab ── */}
        <TabsContent value="health" className="space-y-4">
          {healthDashboard && (
            <div className="grid grid-cols-5 gap-3">
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold">{healthDashboard.totalSources}</div>
                  <div className="text-xs text-muted-foreground">Total Sources</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-emerald-600">{healthDashboard.healthy}</div>
                  <div className="text-xs text-muted-foreground">Healthy</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-amber-600">{healthDashboard.degraded}</div>
                  <div className="text-xs text-muted-foreground">Degraded</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-red-600">{healthDashboard.error}</div>
                  <div className="text-xs text-muted-foreground">Error</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-zinc-400">{healthDashboard.unknown}</div>
                  <div className="text-xs text-muted-foreground">Unknown</div>
                </CardContent>
              </Card>
            </div>
          )}

          <div className="grid gap-3">
            {sources && sources.length > 0 ? (
              sources.map((source) => (
                <Card key={source.id}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`h-2.5 w-2.5 rounded-full ${statusColor(source.status)}`} />
                        <div className="flex items-center gap-2">
                          {providerIcon(source.provider)}
                          <div>
                            <div className="font-medium text-sm">{source.name}</div>
                            <div className="text-xs text-muted-foreground capitalize">{source.provider}</div>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {/* API Quota */}
                        {source.apiQuotaTotal && source.apiQuotaTotal > 0 && (
                          <div className="text-xs">
                            <span className="text-muted-foreground">Quota: </span>
                            <span className="font-medium">
                              {source.apiQuotaUsed ?? 0}/{source.apiQuotaTotal}
                            </span>
                            <div className="w-20 h-1.5 bg-muted rounded-full mt-1">
                              <div
                                className={`h-full rounded-full ${
                                  (source.apiQuotaUsed ?? 0) / source.apiQuotaTotal > 0.9
                                    ? "bg-red-500"
                                    : (source.apiQuotaUsed ?? 0) / source.apiQuotaTotal > 0.7
                                      ? "bg-amber-500"
                                      : "bg-emerald-500"
                                }`}
                                style={{
                                  width: `${Math.min(100, ((source.apiQuotaUsed ?? 0) / source.apiQuotaTotal) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        )}

                        {/* Response time */}
                        {source.avgResponseTimeMs !== null && (
                          <div className="text-xs">
                            <span className="text-muted-foreground">Avg: </span>
                            <span className="font-medium">{source.avgResponseTimeMs}ms</span>
                          </div>
                        )}

                        {/* Last success */}
                        <div className="text-xs">
                          <span className="text-muted-foreground">Last OK: </span>
                          <span>{timeAgo(source.lastSuccessAt)}</span>
                        </div>

                        {/* Total queries */}
                        <div className="text-xs">
                          <span className="text-muted-foreground">Queries: </span>
                          <span>{source.totalQueries}</span>
                        </div>

                        <Badge variant={statusBadgeVariant(source.status)} className="text-xs">
                          {source.status}
                        </Badge>

                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => testSourceMutation.mutate(source.id)}
                          disabled={testSourceMutation.isPending}
                        >
                          {testSourceMutation.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin mr-1" />
                          ) : (
                            <Zap className="h-3 w-3 mr-1" />
                          )}
                          Test
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive"
                          onClick={() => deleteSourceMutation.mutate(source.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                    {source.lastErrorMessage && (
                      <div className="mt-2 text-xs text-red-600 bg-red-50 dark:bg-red-950/20 p-2 rounded">
                        <AlertTriangle className="h-3 w-3 inline mr-1" />
                        {source.lastErrorMessage}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            ) : (
              <Card>
                <CardContent className="text-center py-8 text-muted-foreground">
                  <Settings2 className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No OSINT sources configured.</p>
                  <p className="text-xs mt-1">Add Shodan, Censys, VirusTotal, or other sources to get started.</p>
                  <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddSourceDialog(true)}>
                    <Plus className="h-4 w-4 mr-1" /> Add Source
                  </Button>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
        {/* ── 5.4: Scheduled Scans Tab ── */}
        <TabsContent value="scheduled" className="space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold">Scheduled OSINT Scans</h2>
              <p className="text-sm text-muted-foreground">
                Recurring queries that run on a schedule with automatic change detection
              </p>
            </div>
            <Button size="sm" onClick={() => setShowAddScheduledScanDialog(true)}>
              <Plus className="h-4 w-4 mr-1" /> Add Scheduled Scan
            </Button>
          </div>

          {!scheduledScans || scheduledScans.length === 0 ? (
            <Card>
              <CardContent className="text-center py-8 text-muted-foreground">
                <Calendar className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No scheduled scans configured.</p>
                <p className="text-xs mt-1">Set up recurring OSINT queries to track changes over time.</p>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-3"
                  onClick={() => setShowAddScheduledScanDialog(true)}
                >
                  <Plus className="h-4 w-4 mr-1" /> Create First Scan
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-3">
              {scheduledScans.map((scan) => (
                <Card key={scan.id}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Switch
                          checked={scan.enabled}
                          onCheckedChange={(checked) =>
                            toggleScheduledScanMutation.mutate({ id: scan.id, enabled: checked })
                          }
                        />
                        <div>
                          <div className="font-medium text-sm">{scan.name}</div>
                          <div className="text-xs text-muted-foreground mt-0.5">
                            {scan.queryType.replace(/_/g, " ")} &middot;{" "}
                            <span className="font-mono">{scan.queryValue}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary" className="text-xs">
                          <Clock className="h-3 w-3 mr-1" />
                          {scan.schedule}
                        </Badge>
                        <div className="text-xs text-muted-foreground">{scan.totalRuns} runs</div>
                        {scan.totalChangesDetected > 0 && (
                          <Badge variant="outline" className="text-xs text-amber-600">
                            {scan.totalChangesDetected} changes
                          </Badge>
                        )}
                        {scan.lastRunStatus && (
                          <Badge
                            variant={scan.lastRunStatus === "completed" ? "default" : "destructive"}
                            className="text-xs"
                          >
                            {scan.lastRunStatus === "completed" ? (
                              <CheckCircle2 className="h-3 w-3 mr-1" />
                            ) : (
                              <XCircle className="h-3 w-3 mr-1" />
                            )}
                            {scan.lastRunStatus}
                          </Badge>
                        )}
                        {scan.lastRunAt && (
                          <span className="text-xs text-muted-foreground">Last: {timeAgo(scan.lastRunAt)}</span>
                        )}
                        {scan.lastRunResultCount !== null && scan.lastRunResultCount !== undefined && (
                          <span className="text-xs text-muted-foreground">{scan.lastRunResultCount} results</span>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          title="Run now"
                          onClick={() => runScheduledScanMutation.mutate(scan.id)}
                          disabled={runScheduledScanMutation.isPending}
                        >
                          {runScheduledScanMutation.isPending ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Play className="h-3.5 w-3.5" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive"
                          onClick={() => deleteScheduledScanMutation.mutate(scan.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                    {scan.nextRunAt && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        Next run: {new Date(scan.nextRunAt).toLocaleString()}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── 5.6: API Quota Management Tab ── */}
        <TabsContent value="quota" className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold">API Quota Management</h2>
            <p className="text-sm text-muted-foreground">
              Track API usage per source, monitor quota limits, and manage rate limiting
            </p>
          </div>

          {quotaData && quotaData.totalWarnings > 0 && (
            <Card className="border-amber-500/50 bg-amber-50/50 dark:bg-amber-950/10">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-600" />
                  <span className="font-medium text-sm text-amber-700 dark:text-amber-400">
                    {quotaData.totalWarnings} source{quotaData.totalWarnings > 1 ? "s" : ""} approaching quota limits
                    {quotaData.totalCritical > 0 && (
                      <span className="text-red-600 dark:text-red-400"> ({quotaData.totalCritical} critical)</span>
                    )}
                  </span>
                </div>
              </CardContent>
            </Card>
          )}

          <div className="grid gap-3">
            {quotaData && quotaData.sources.length > 0 ? (
              quotaData.sources.map((qs) => (
                <Card
                  key={qs.sourceId}
                  className={qs.isCritical ? "border-red-500/50" : qs.isWarning ? "border-amber-500/50" : ""}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {providerIcon(qs.provider)}
                        <div>
                          <div className="font-medium text-sm">{qs.sourceName}</div>
                          <div className="text-xs text-muted-foreground capitalize">{qs.provider}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {/* Quota bar */}
                        <div className="text-xs text-right">
                          <div>
                            <span className="text-muted-foreground">Quota: </span>
                            <span className="font-medium">
                              {qs.quotaUsed}/{qs.quotaTotal > 0 ? qs.quotaTotal : "unlimited"}
                            </span>
                            {qs.quotaTotal > 0 && (
                              <span
                                className={`ml-1 font-medium ${
                                  qs.isCritical ? "text-red-600" : qs.isWarning ? "text-amber-600" : "text-emerald-600"
                                }`}
                              >
                                ({qs.quotaPercent}%)
                              </span>
                            )}
                          </div>
                          {qs.quotaTotal > 0 && (
                            <div className="w-32 h-2 bg-muted rounded-full mt-1">
                              <div
                                className={`h-full rounded-full transition-all ${
                                  qs.isCritical ? "bg-red-500" : qs.isWarning ? "bg-amber-500" : "bg-emerald-500"
                                }`}
                                style={{ width: `${Math.min(100, qs.quotaPercent)}%` }}
                              />
                            </div>
                          )}
                        </div>

                        {/* 24h stats */}
                        <div className="text-xs">
                          <span className="text-muted-foreground">24h: </span>
                          <span className="font-medium">{qs.last24h.totalCalls} calls</span>
                          {qs.last24h.failedCalls > 0 && (
                            <span className="text-red-600 ml-1">({qs.last24h.failedCalls} failed)</span>
                          )}
                        </div>

                        {/* Avg response */}
                        {qs.last24h.avgResponseTimeMs > 0 && (
                          <div className="text-xs">
                            <span className="text-muted-foreground">Avg: </span>
                            <span className="font-medium">{qs.last24h.avgResponseTimeMs}ms</span>
                          </div>
                        )}

                        {/* Status badge */}
                        {qs.isCritical ? (
                          <Badge variant="destructive" className="text-xs">
                            <AlertTriangle className="h-3 w-3 mr-1" /> Critical
                          </Badge>
                        ) : qs.isWarning ? (
                          <Badge variant="secondary" className="text-xs text-amber-600">
                            <AlertTriangle className="h-3 w-3 mr-1" /> Warning
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-xs text-emerald-600">
                            <CheckCircle2 className="h-3 w-3 mr-1" /> Healthy
                          </Badge>
                        )}

                        {/* Reset button */}
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => resetQuotaMutation.mutate(qs.sourceId)}
                          disabled={resetQuotaMutation.isPending}
                        >
                          <RefreshCw className="h-3 w-3 mr-1" /> Reset
                        </Button>
                      </div>
                    </div>
                    {qs.quotaResetAt && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        Auto-resets: {new Date(qs.quotaResetAt).toLocaleString()}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            ) : (
              <Card>
                <CardContent className="text-center py-8 text-muted-foreground">
                  <BarChart3 className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No OSINT sources configured for quota tracking.</p>
                  <p className="text-xs mt-1">Add sources and run queries to start tracking API usage.</p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* ── Add Scheduled Scan Dialog ── */}
      <Dialog open={showAddScheduledScanDialog} onOpenChange={setShowAddScheduledScanDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Scheduled Scan</DialogTitle>
            <DialogDescription>Create a recurring OSINT query with automatic change detection</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Scan Name</Label>
              <Input
                placeholder="e.g. Daily domain check"
                value={schedScanName}
                onChange={(e) => setSchedScanName(e.target.value)}
              />
            </div>
            <div>
              <Label>Query Type</Label>
              <Select value={schedScanQueryType} onValueChange={setSchedScanQueryType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {QUERY_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t.replace(/_/g, " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Query Value</Label>
              <Input
                placeholder="e.g. example.com or 8.8.8.8"
                value={schedScanQueryValue}
                onChange={(e) => setSchedScanQueryValue(e.target.value)}
              />
            </div>
            <div>
              <Label>Schedule</Label>
              <Select value={schedScanSchedule} onValueChange={setSchedScanSchedule}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hourly">Hourly</SelectItem>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {sources && sources.length > 0 && (
              <div>
                <Label>Source (optional)</Label>
                <Select value={schedScanSourceId} onValueChange={setSchedScanSourceId}>
                  <SelectTrigger>
                    <SelectValue placeholder="All sources" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All sources</SelectItem>
                    {sources.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name} ({s.provider})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddScheduledScanDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                addScheduledScanMutation.mutate({
                  name: schedScanName,
                  queryType: schedScanQueryType,
                  queryValue: schedScanQueryValue,
                  schedule: schedScanSchedule,
                  sourceId: schedScanSourceId && schedScanSourceId !== "all" ? schedScanSourceId : undefined,
                })
              }
              disabled={!schedScanName.trim() || !schedScanQueryValue.trim() || addScheduledScanMutation.isPending}
            >
              {addScheduledScanMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Calendar className="h-4 w-4 mr-1" />
              )}
              Create Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── New Query Dialog ── */}
      <Dialog open={showQueryDialog} onOpenChange={setShowQueryDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Run OSINT Query</DialogTitle>
            <DialogDescription>Search across configured OSINT sources</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Query Type</Label>
              <Select value={queryType} onValueChange={setQueryType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {QUERY_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t.replace(/_/g, " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Value</Label>
              <Input
                placeholder={
                  queryType === "ip_lookup"
                    ? "e.g. 8.8.8.8"
                    : queryType === "domain_lookup"
                      ? "e.g. example.com"
                      : queryType === "hash_lookup"
                        ? "e.g. d41d8cd98f00b204..."
                        : "Search term..."
                }
                value={queryValue}
                onChange={(e) => setQueryValue(e.target.value)}
              />
            </div>
            {sources && sources.length > 0 && (
              <div>
                <Label>Source (optional)</Label>
                <Select value={querySourceId} onValueChange={setQuerySourceId}>
                  <SelectTrigger>
                    <SelectValue placeholder="All sources" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All sources</SelectItem>
                    {sources.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name} ({s.provider})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowQueryDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                runQueryMutation.mutate({
                  queryType,
                  queryValue,
                  sourceId: querySourceId && querySourceId !== "all" ? querySourceId : undefined,
                })
              }
              disabled={!queryValue.trim() || runQueryMutation.isPending}
            >
              {runQueryMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Search className="h-4 w-4 mr-1" />
              )}
              Run Query
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add Source Dialog ── */}
      <Dialog open={showAddSourceDialog} onOpenChange={setShowAddSourceDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add OSINT Source</DialogTitle>
            <DialogDescription>Configure a new external intelligence source</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Name</Label>
              <Input
                placeholder="e.g. Production Shodan"
                value={sourceName}
                onChange={(e) => setSourceName(e.target.value)}
              />
            </div>
            <div>
              <Label>Provider</Label>
              <Select value={sourceProvider} onValueChange={setSourceProvider}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROVIDERS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {p.charAt(0).toUpperCase() + p.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>API Key (optional)</Label>
              <Input
                type="password"
                placeholder="API key or env var reference"
                value={sourceApiKey}
                onChange={(e) => setSourceApiKey(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddSourceDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                addSourceMutation.mutate({
                  name: sourceName,
                  provider: sourceProvider,
                  apiKeyRef: sourceApiKey || undefined,
                })
              }
              disabled={!sourceName.trim() || addSourceMutation.isPending}
            >
              {addSourceMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Plus className="h-4 w-4 mr-1" />
              )}
              Add Source
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add Alert Rule Dialog ── */}
      <Dialog open={showAddRuleDialog} onOpenChange={setShowAddRuleDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create OSINT Alert Rule</DialogTitle>
            <DialogDescription>Get notified when OSINT sources find something matching your criteria</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-1">
            <div>
              <Label>Rule Name</Label>
              <Input
                placeholder="e.g. Alert on new exposed services"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
              />
            </div>
            <div>
              <Label>Description</Label>
              <Textarea
                placeholder="What this rule monitors..."
                value={ruleDescription}
                onChange={(e) => setRuleDescription(e.target.value)}
                rows={2}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Rule Type</Label>
                <Select value={ruleType} onValueChange={setRuleType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RULE_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>
                        {t.replace(/_/g, " ")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Source Provider</Label>
                <Select value={ruleProvider} onValueChange={setRuleProvider}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All sources</SelectItem>
                    {PROVIDERS.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Schedule</Label>
                <Select value={ruleSchedule} onValueChange={setRuleSchedule}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCHEDULES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Alert Severity</Label>
                <Select value={ruleSeverity} onValueChange={setRuleSeverity}>
                  <SelectTrigger>
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
            </div>
            <div>
              <Label>IP Ranges (one per line)</Label>
              <Textarea
                placeholder={"192.168.1.0/24\n10.0.0.0/8"}
                value={ruleIpRanges}
                onChange={(e) => setRuleIpRanges(e.target.value)}
                rows={2}
              />
            </div>
            <div>
              <Label>Domains (one per line)</Label>
              <Textarea
                placeholder={"example.com\napi.example.com"}
                value={ruleDomains}
                onChange={(e) => setRuleDomains(e.target.value)}
                rows={2}
              />
            </div>
            <div>
              <Label>Keywords (one per line)</Label>
              <Textarea
                placeholder={"company-secret\ninternal-api\nstaging.example"}
                value={ruleKeywords}
                onChange={(e) => setRuleKeywords(e.target.value)}
                rows={2}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddRuleDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                addRuleMutation.mutate({
                  name: ruleName,
                  description: ruleDescription || undefined,
                  ruleType,
                  sourceProvider: ruleProvider !== "all" ? ruleProvider : undefined,
                  schedule: ruleSchedule,
                  conditions: {
                    ipRanges: ruleIpRanges
                      .split("\n")
                      .map((s) => s.trim())
                      .filter(Boolean),
                    domains: ruleDomains
                      .split("\n")
                      .map((s) => s.trim())
                      .filter(Boolean),
                    keywords: ruleKeywords
                      .split("\n")
                      .map((s) => s.trim())
                      .filter(Boolean),
                    severityThreshold: ruleSeverity,
                  },
                  actions: {
                    createAlert: true,
                    alertSeverity: ruleSeverity,
                  },
                })
              }
              disabled={!ruleName.trim() || addRuleMutation.isPending}
            >
              {addRuleMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Bell className="h-4 w-4 mr-1" />
              )}
              Create Rule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── 5.1: Query Result Visualization Component ─────────────────────

function QueryVisualization({ query, onBack }: { query: OsintQuery; onBack: () => void }) {
  const [vizTab, setVizTab] = useState("results");
  const geoData = (query.geoData || []) as GeoPoint[];
  const domainGraph = (query.domainGraph || { nodes: [], edges: [] }) as DomainGraph;
  const timeline = (query.timeline || []) as TimelineEntry[];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={onBack}>
          &larr; Back
        </Button>
        <div>
          <h3 className="font-semibold">
            {query.queryType.replace(/_/g, " ")} — <span className="font-mono">{query.queryValue}</span>
          </h3>
          <p className="text-xs text-muted-foreground">
            {query.resultCount} results &middot; {query.durationMs}ms &middot; {timeAgo(query.createdAt)}
          </p>
        </div>
      </div>

      <Tabs value={vizTab} onValueChange={setVizTab}>
        <TabsList>
          <TabsTrigger value="results">
            <BarChart3 className="h-4 w-4 mr-1" /> Results
          </TabsTrigger>
          {geoData.length > 0 && (
            <TabsTrigger value="geo">
              <MapPin className="h-4 w-4 mr-1" /> Geographic Map
            </TabsTrigger>
          )}
          {domainGraph.nodes && domainGraph.nodes.length > 0 && (
            <TabsTrigger value="graph">
              <Network className="h-4 w-4 mr-1" /> Relationship Graph
            </TabsTrigger>
          )}
          {timeline.length > 0 && (
            <TabsTrigger value="timeline">
              <Calendar className="h-4 w-4 mr-1" /> Timeline
            </TabsTrigger>
          )}
        </TabsList>

        {/* Raw results */}
        <TabsContent value="results">
          <Card>
            <CardContent className="p-4">
              <div className="space-y-3">
                {query.results.map((result, idx) => (
                  <div key={idx} className="border rounded-md p-3 text-sm">
                    <pre className="whitespace-pre-wrap font-mono text-xs text-muted-foreground overflow-auto max-h-48">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Geographic map visualization */}
        <TabsContent value="geo">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Geographic Distribution</CardTitle>
              <CardDescription>IP addresses plotted by geographic location</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="border rounded-lg bg-zinc-50 dark:bg-zinc-900 p-4">
                {/* Simple text-based geo visualization since we don't have a map library */}
                <div className="grid gap-2">
                  {geoData.map((point, idx) => (
                    <div key={idx} className="flex items-center justify-between p-3 bg-background border rounded-md">
                      <div className="flex items-center gap-3">
                        <MapPin className="h-4 w-4 text-blue-500" />
                        <div>
                          <span className="font-mono text-sm font-medium">{point.ip}</span>
                          <div className="text-xs text-muted-foreground">
                            {point.city}, {point.country}
                          </div>
                        </div>
                      </div>
                      <div className="text-right text-xs">
                        <div className="font-mono text-muted-foreground">{point.asn}</div>
                        <div className="text-muted-foreground">
                          {point.lat.toFixed(4)}, {point.lng.toFixed(4)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                  {Object.entries(
                    geoData.reduce(
                      (acc, p) => {
                        acc[p.country] = (acc[p.country] || 0) + 1;
                        return acc;
                      },
                      {} as Record<string, number>,
                    ),
                  ).map(([country, count]) => (
                    <div key={country} className="bg-background border rounded-md p-2">
                      <div className="text-lg font-bold">{count}</div>
                      <div className="text-xs text-muted-foreground">{country}</div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Domain relationship graph */}
        <TabsContent value="graph">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Relationship Graph</CardTitle>
              <CardDescription>Domain, IP, and service relationships</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="border rounded-lg bg-zinc-50 dark:bg-zinc-900 p-4">
                {/* Node list */}
                <div className="mb-4">
                  <h4 className="text-xs font-semibold uppercase text-muted-foreground mb-2">Nodes</h4>
                  <div className="flex flex-wrap gap-2">
                    {domainGraph.nodes.map((node) => (
                      <Badge
                        key={node.id}
                        variant={
                          node.type === "domain"
                            ? "default"
                            : node.type === "ip"
                              ? "secondary"
                              : node.type === "subdomain"
                                ? "outline"
                                : node.type === "malware" || node.type === "c2"
                                  ? "destructive"
                                  : "outline"
                        }
                        className="text-xs"
                      >
                        {node.type === "domain" && <Globe className="h-3 w-3 mr-1" />}
                        {node.type === "ip" && <Server className="h-3 w-3 mr-1" />}
                        {node.type === "subdomain" && <Network className="h-3 w-3 mr-1" />}
                        {(node.type === "malware" || node.type === "c2") && <AlertTriangle className="h-3 w-3 mr-1" />}
                        {node.label}
                      </Badge>
                    ))}
                  </div>
                </div>
                {/* Edge list */}
                <div>
                  <h4 className="text-xs font-semibold uppercase text-muted-foreground mb-2">Relationships</h4>
                  <div className="space-y-1">
                    {domainGraph.edges.map((edge, idx) => {
                      const sourceNode = domainGraph.nodes.find((n) => n.id === edge.source);
                      const targetNode = domainGraph.nodes.find((n) => n.id === edge.target);
                      return (
                        <div key={idx} className="flex items-center gap-2 text-xs p-1.5 bg-background rounded">
                          <span className="font-mono">{sourceNode?.label || edge.source}</span>
                          <span className="text-muted-foreground">&rarr;</span>
                          <Badge variant="outline" className="text-xs px-1.5 py-0">
                            {edge.label}
                          </Badge>
                          <span className="text-muted-foreground">&rarr;</span>
                          <span className="font-mono">{targetNode?.label || edge.target}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Temporal timeline */}
        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Discovery Timeline</CardTitle>
              <CardDescription>Chronological history of discoveries</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="relative border-l-2 border-muted ml-4 space-y-4">
                {timeline
                  .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
                  .map((entry, idx) => (
                    <div key={idx} className="relative pl-6">
                      <div className="absolute -left-[9px] top-1 h-4 w-4 rounded-full border-2 border-background bg-blue-500" />
                      <div className="text-xs text-muted-foreground">
                        {new Date(entry.timestamp).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </div>
                      <div className="font-medium text-sm mt-0.5">{entry.event}</div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                        <Badge variant="outline" className="text-xs px-1.5 py-0">
                          {entry.source}
                        </Badge>
                        <span className="font-mono">{entry.value}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
