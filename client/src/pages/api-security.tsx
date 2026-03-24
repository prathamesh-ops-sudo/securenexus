import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import {
  Globe,
  Shield,
  AlertTriangle,
  Search,
  Upload,
  Eye,
  EyeOff,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  RefreshCw,
  Zap,
  Lock,
  Unlock,
  Activity,
  BarChart3,
  Bug,
  FileCode,
  Network,
  Scan,
  Clock,
  ArrowUpDown,
  Gauge,
  GitCompare,
  Timer,
  Users,
  TrendingUp,
} from "lucide-react";
import { TablePageSkeleton } from "@/components/page-skeleton";

// ─── Types ──────────────────────────────────────────────────────────────────

interface ApiEndpoint {
  id: string;
  method: string;
  path: string;
  host: string;
  version: string | null;
  specSource: string | null;
  isShadow: boolean;
  isDeprecated: boolean;
  authType: string;
  riskScore: number;
  requestCount24h: number;
  errorRate24h: number;
  avgLatencyMs: number;
  lastSeenAt: string | null;
  firstSeenAt: string | null;
  sensitiveDataTypes: string[] | null;
  tags: string[] | null;
  createdAt: string;
}

interface ApiFinding {
  id: string;
  apiId: string | null;
  findingType: string;
  severity: string;
  status: string;
  title: string;
  description: string | null;
  endpoint: string | null;
  method: string | null;
  cweId: string | null;
  owaspCategory: string | null;
  remediation: string | null;
  evidence: Record<string, unknown> | null;
  createdAt: string;
}

interface ApiSummary {
  inventory: {
    totalApis: number;
    shadowCount: number;
    deprecatedCount: number;
    noAuthCount: number;
    avgRiskScore: number;
    totalRequests24h: number;
  };
  findings: {
    total: number;
    open: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    bola: number;
    bfla: number;
    credentialStuffing: number;
    sensitiveData: number;
    schemaViolation: number;
    shadow: number;
    injection: number;
    rateAbuse: number;
  };
}

interface InventoryResponse {
  apis: ApiEndpoint[];
  total: number;
  hosts: Array<{ host: string; api_count: string; shadow_count: string; no_auth_count: string; avg_risk: string }>;
}

interface FindingsResponse {
  findings: ApiFinding[];
  total: number;
  stats: {
    total: number;
    openCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}

// ─── Constants ──────────────────────────────────────────────────────────────

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  informational: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const statusColors: Record<string, string> = {
  open: "bg-red-500/20 text-red-400 border-red-500/30",
  acknowledged: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  mitigated: "bg-green-500/20 text-green-400 border-green-500/30",
  false_positive: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const methodColors: Record<string, string> = {
  GET: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  POST: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  PUT: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  PATCH: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  DELETE: "bg-red-500/20 text-red-400 border-red-500/30",
  HEAD: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  OPTIONS: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const authTypeLabels: Record<string, string> = {
  none: "No Auth",
  api_key: "API Key",
  bearer: "Bearer Token",
  oauth2: "OAuth 2.0",
  basic: "Basic Auth",
  mtls: "Mutual TLS",
  custom: "Custom",
};

const findingTypeLabels: Record<string, string> = {
  schema_violation: "Schema Violation",
  bola: "BOLA",
  bfla: "BFLA",
  credential_stuffing: "Credential Stuffing",
  scraping: "Scraping",
  sensitive_data_exposure: "Sensitive Data Exposure",
  injection: "Injection",
  rate_abuse: "Rate Abuse",
  shadow_api: "Shadow API",
  deprecated_api: "Deprecated API",
  auth_bypass: "Auth Bypass",
  mass_assignment: "Mass Assignment",
  ssrf: "SSRF",
  broken_auth: "Broken Auth",
};

// ─── Helpers ────────────────────────────────────────────────────────────────

async function apiFetch(url: string, options?: RequestInit) {
  const res = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: `API error: ${res.status}` }));
    throw new Error(body.message || `API error: ${res.status}`);
  }
  return res.json();
}

function riskColor(score: number): string {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-green-400";
}

function riskBg(score: number): string {
  if (score >= 75) return "bg-red-500/20 border-red-500/30";
  if (score >= 50) return "bg-orange-500/20 border-orange-500/30";
  if (score >= 25) return "bg-yellow-500/20 border-yellow-500/30";
  return "bg-green-500/20 border-green-500/30";
}

function formatDate(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function ApiSecurityPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [shadowFilter, setShadowFilter] = useState("all");
  const [authFilter, setAuthFilter] = useState("all");
  const [hostFilter, setHostFilter] = useState("all");
  const [findingTypeFilter, setFindingTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [importOpen, setImportOpen] = useState(false);
  const [addApiOpen, setAddApiOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<ApiFinding | null>(null);
  const [selectedApi, setSelectedApi] = useState<ApiEndpoint | null>(null);

  // Import form
  const [specJson, setSpecJson] = useState("");
  const [specHost, setSpecHost] = useState("");

  // Add API form
  const [newMethod, setNewMethod] = useState("GET");
  const [newPath, setNewPath] = useState("");
  const [newHost, setNewHost] = useState("");
  const [newAuthType, setNewAuthType] = useState("none");

  // ── Queries ─────────────────────────────────────────────────────────────

  const { data: summary, isLoading: summaryLoading } = useQuery<ApiSummary>({
    queryKey: ["/api/api-security/summary"],
    queryFn: () => apiFetch("/api/api-security/summary"),
  });

  const { data: inventoryData, isLoading: inventoryLoading } = useQuery<InventoryResponse>({
    queryKey: ["/api/api-security/inventory", searchQuery, shadowFilter, authFilter, hostFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (searchQuery) params.set("q", searchQuery);
      if (shadowFilter === "shadow") params.set("shadow", "true");
      if (shadowFilter === "deprecated") params.set("deprecated", "true");
      if (authFilter !== "all") params.set("authType", authFilter);
      if (hostFilter !== "all") params.set("host", hostFilter);
      return apiFetch(`/api/api-security/inventory?${params}`);
    },
  });

  const { data: findingsData, isLoading: findingsLoading } = useQuery<FindingsResponse>({
    queryKey: ["/api/api-security/findings", findingTypeFilter, severityFilter, statusFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams();
      if (findingTypeFilter !== "all") params.set("type", findingTypeFilter);
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (searchQuery) params.set("q", searchQuery);
      return apiFetch(`/api/api-security/findings?${params}`);
    },
  });

  // ── Mutations ───────────────────────────────────────────────────────────

  const importSpec = useMutation({
    mutationFn: (data: { spec: unknown; host: string }) =>
      apiFetch("/api/api-security/import-spec", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "OpenAPI spec imported", description: `${result.imported} new, ${result.updated} updated` });
      setImportOpen(false);
      setSpecJson("");
      setSpecHost("");
    },
    onError: (err: Error) => {
      toast({ title: "Import failed", description: err.message, variant: "destructive" });
    },
  });

  const addApi = useMutation({
    mutationFn: (data: { method: string; path: string; host: string; authType: string }) =>
      apiFetch("/api/api-security/inventory", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "API endpoint added" });
      setAddApiOpen(false);
      setNewPath("");
      setNewHost("");
    },
    onError: (err: Error) => {
      toast({ title: "Failed to add API", description: err.message, variant: "destructive" });
    },
  });

  const deleteApi = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/api-security/inventory/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "API endpoint deleted" });
      setSelectedApi(null);
    },
    onError: () => {
      toast({ title: "Failed to delete API", variant: "destructive" });
    },
  });

  const updateFinding = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch(`/api/api-security/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "Finding updated" });
    },
    onError: () => {
      toast({ title: "Failed to update finding", variant: "destructive" });
    },
  });

  const detectShadows = useMutation({
    mutationFn: () => apiFetch("/api/api-security/detect-shadows", { method: "POST" }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "Shadow detection complete", description: `${result.shadowCount} shadow APIs detected` });
    },
    onError: (err: Error) => {
      toast({ title: "Shadow detection failed", description: err.message, variant: "destructive" });
    },
  });

  const recalcRisk = useMutation({
    mutationFn: () => apiFetch("/api/api-security/recalculate-risk", { method: "POST" }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "Risk recalculated", description: `${result.updated} APIs updated` });
    },
    onError: (err: Error) => {
      toast({ title: "Risk recalc failed", description: err.message, variant: "destructive" });
    },
  });

  const dastScan = useMutation({
    mutationFn: (data: { apiId: string; scanType: string }) =>
      apiFetch("/api/api-security/dast-scan", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-security"] });
      toast({ title: "DAST scan complete", description: `${result.findingsCount} findings` });
    },
    onError: (err: Error) => {
      toast({ title: "DAST scan failed", description: err.message, variant: "destructive" });
    },
  });

  const handleImport = () => {
    if (!specHost.trim()) {
      toast({ title: "Host is required", variant: "destructive" });
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(specJson);
    } catch {
      toast({ title: "Invalid JSON", description: "OpenAPI spec must be valid JSON", variant: "destructive" });
      return;
    }
    importSpec.mutate({ spec: parsed, host: specHost.trim() });
  };

  const handleAddApi = () => {
    if (!newPath.trim() || !newHost.trim()) {
      toast({ title: "Path and host are required", variant: "destructive" });
      return;
    }
    addApi.mutate({ method: newMethod, path: newPath.trim(), host: newHost.trim(), authType: newAuthType });
  };

  // ── Render ──────────────────────────────────────────────────────────────

  const inv = summary?.inventory;
  const fnd = summary?.findings;
  const hosts = inventoryData?.hosts || [];
  const uniqueHosts = hosts.map((h) => h.host);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Globe className="h-6 w-6 text-indigo-400" />
            API Security
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            API inventory discovery, schema validation, abuse detection, sensitive data scanning, DAST testing
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
            onClick={() => detectShadows.mutate()}
            disabled={detectShadows.isPending}
          >
            <EyeOff className="h-4 w-4" />
            Detect Shadows
          </Button>
          <Button
            variant="outline"
            className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
            onClick={() => recalcRisk.mutate()}
            disabled={recalcRisk.isPending}
          >
            <RefreshCw className="h-4 w-4" />
            Recalc Risk
          </Button>
          <Button
            variant="outline"
            className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
            onClick={() => setImportOpen(true)}
          >
            <Upload className="h-4 w-4" />
            Import Spec
          </Button>
          <Button className="gap-1.5 bg-indigo-600 hover:bg-indigo-700" onClick={() => setAddApiOpen(true)}>
            <Globe className="h-4 w-4" />
            Add API
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-muted-foreground">Total APIs</div>
            <div className="text-xl font-semibold mt-0.5">{inv?.totalApis ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-purple-400">Shadow APIs</div>
            <div className="text-xl font-semibold mt-0.5 text-purple-400">{inv?.shadowCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-amber-400">No Auth</div>
            <div className="text-xl font-semibold mt-0.5 text-amber-400">{inv?.noAuthCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-zinc-400">Deprecated</div>
            <div className="text-xl font-semibold mt-0.5">{inv?.deprecatedCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-red-400">Critical</div>
            <div className="text-xl font-semibold mt-0.5 text-red-400">{fnd?.critical ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-orange-400">High</div>
            <div className="text-xl font-semibold mt-0.5 text-orange-400">{fnd?.high ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-indigo-400">Open Findings</div>
            <div className="text-xl font-semibold mt-0.5 text-indigo-400">{fnd?.open ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-muted-foreground">Requests 24h</div>
            <div className="text-xl font-semibold mt-0.5">{inv?.totalRequests24h?.toLocaleString() ?? 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="traffic">Traffic</TabsTrigger>
          <TabsTrigger value="abuse">Abuse</TabsTrigger>
          <TabsTrigger value="schema">Schema</TabsTrigger>
          <TabsTrigger value="hosts">Hosts</TabsTrigger>
        </TabsList>

        {/* ── Overview ─────────────────────────────────────────────────── */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* OWASP API Top 10 Breakdown */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  OWASP API Top 10 Findings
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {[
                  { label: "BOLA (Broken Object Level Auth)", count: fnd?.bola ?? 0, color: "bg-red-500" },
                  { label: "BFLA (Broken Function Level Auth)", count: fnd?.bfla ?? 0, color: "bg-orange-500" },
                  { label: "Credential Stuffing", count: fnd?.credentialStuffing ?? 0, color: "bg-amber-500" },
                  { label: "Sensitive Data Exposure", count: fnd?.sensitiveData ?? 0, color: "bg-purple-500" },
                  { label: "Schema Violations", count: fnd?.schemaViolation ?? 0, color: "bg-blue-500" },
                  { label: "Injection", count: fnd?.injection ?? 0, color: "bg-red-600" },
                  { label: "Rate Abuse", count: fnd?.rateAbuse ?? 0, color: "bg-yellow-500" },
                  { label: "Shadow APIs", count: fnd?.shadow ?? 0, color: "bg-violet-500" },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{item.label}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-20 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${item.color}`}
                          style={{ width: `${Math.min(100, (item.count / Math.max(fnd?.total || 1, 1)) * 100)}%` }}
                        />
                      </div>
                      <span className="w-6 text-right tabular-nums">{item.count}</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Auth Distribution */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Lock className="h-4 w-4 text-amber-400" />
                  Authentication Coverage
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <Unlock className="h-3.5 w-3.5 text-red-400" />
                    <span>No Authentication</span>
                  </div>
                  <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30">
                    {inv?.noAuthCount ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <EyeOff className="h-3.5 w-3.5 text-purple-400" />
                    <span>Shadow (Undocumented)</span>
                  </div>
                  <Badge variant="outline" className="bg-purple-500/20 text-purple-400 border-purple-500/30">
                    {inv?.shadowCount ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <Clock className="h-3.5 w-3.5 text-zinc-400" />
                    <span>Deprecated</span>
                  </div>
                  <Badge variant="outline" className="bg-zinc-500/20 text-zinc-400 border-zinc-500/30">
                    {inv?.deprecatedCount ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-3.5 w-3.5 text-green-400" />
                    <span>Authenticated</span>
                  </div>
                  <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30">
                    {(inv?.totalApis ?? 0) - (inv?.noAuthCount ?? 0)}
                  </Badge>
                </div>
                <div className="pt-2 border-t border-zinc-800">
                  <div className="text-[11px] text-muted-foreground mb-1">Average Risk Score</div>
                  <div className={`text-2xl font-semibold ${riskColor(inv?.avgRiskScore ?? 0)}`}>
                    {(inv?.avgRiskScore ?? 0).toFixed(0)}
                    <span className="text-sm text-muted-foreground">/100</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Recent Findings */}
            <Card className="bg-zinc-900/50 border-zinc-800 md:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-orange-400" />
                  Recent Findings
                </CardTitle>
              </CardHeader>
              <CardContent>
                {findingsData?.findings && findingsData.findings.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow className="border-zinc-800 hover:bg-transparent">
                        <TableHead className="text-[11px]">Type</TableHead>
                        <TableHead className="text-[11px]">Title</TableHead>
                        <TableHead className="text-[11px]">Severity</TableHead>
                        <TableHead className="text-[11px]">Status</TableHead>
                        <TableHead className="text-[11px]">OWASP</TableHead>
                        <TableHead className="text-[11px]">Detected</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findingsData.findings.slice(0, 8).map((f) => (
                        <TableRow
                          key={f.id}
                          className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                          onClick={() => setSelectedFinding(f)}
                        >
                          <TableCell>
                            <Badge variant="outline" className="text-[10px] bg-zinc-800/50">
                              {findingTypeLabels[f.findingType] || f.findingType}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-sm max-w-[300px] truncate">{f.title}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[10px] ${severityColors[f.severity] || ""}`}>
                              {f.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[10px] ${statusColors[f.status] || ""}`}>
                              {f.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-[11px] text-muted-foreground max-w-[150px] truncate">
                            {f.owaspCategory || "—"}
                          </TableCell>
                          <TableCell className="text-[11px] text-muted-foreground">{formatDate(f.createdAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="text-center py-8 text-muted-foreground text-sm">
                    No findings yet. Import an OpenAPI spec or run a DAST scan.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Inventory ────────────────────────────────────────────────── */}
        <TabsContent value="inventory" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search APIs..."
                className="pl-9 bg-zinc-900 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={shadowFilter} onValueChange={setShadowFilter}>
              <SelectTrigger className="w-[140px] bg-zinc-900 border-zinc-800">
                <SelectValue placeholder="Visibility" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All APIs</SelectItem>
                <SelectItem value="shadow">Shadow Only</SelectItem>
                <SelectItem value="deprecated">Deprecated</SelectItem>
              </SelectContent>
            </Select>
            <Select value={authFilter} onValueChange={setAuthFilter}>
              <SelectTrigger className="w-[140px] bg-zinc-900 border-zinc-800">
                <SelectValue placeholder="Auth Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Auth</SelectItem>
                <SelectItem value="none">No Auth</SelectItem>
                <SelectItem value="api_key">API Key</SelectItem>
                <SelectItem value="bearer">Bearer</SelectItem>
                <SelectItem value="oauth2">OAuth 2.0</SelectItem>
                <SelectItem value="basic">Basic</SelectItem>
                <SelectItem value="mtls">mTLS</SelectItem>
              </SelectContent>
            </Select>
            {uniqueHosts.length > 0 && (
              <Select value={hostFilter} onValueChange={setHostFilter}>
                <SelectTrigger className="w-[180px] bg-zinc-900 border-zinc-800">
                  <SelectValue placeholder="Host" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Hosts</SelectItem>
                  {uniqueHosts.map((h) => (
                    <SelectItem key={h} value={h}>
                      {h}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          {inventoryLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading inventory...</div>
          ) : inventoryData?.apis && inventoryData.apis.length > 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-[11px]">Method</TableHead>
                    <TableHead className="text-[11px]">Path</TableHead>
                    <TableHead className="text-[11px]">Host</TableHead>
                    <TableHead className="text-[11px]">Auth</TableHead>
                    <TableHead className="text-[11px]">Risk</TableHead>
                    <TableHead className="text-[11px]">Req/24h</TableHead>
                    <TableHead className="text-[11px]">Flags</TableHead>
                    <TableHead className="text-[11px]">Last Seen</TableHead>
                    <TableHead className="text-[11px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {inventoryData.apis.map((api) => (
                    <TableRow
                      key={api.id}
                      className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                      onClick={() => setSelectedApi(api)}
                    >
                      <TableCell>
                        <Badge variant="outline" className={`text-[10px] font-mono ${methodColors[api.method] || ""}`}>
                          {api.method}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm font-mono">{api.path}</TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{api.host}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${api.authType === "none" ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-green-500/20 text-green-400 border-green-500/30"}`}
                        >
                          {authTypeLabels[api.authType] || api.authType}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`text-[10px] ${riskBg(api.riskScore)}`}>
                          <span className={riskColor(api.riskScore)}>{api.riskScore}</span>
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm tabular-nums">{api.requestCount24h.toLocaleString()}</TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {api.isShadow && (
                            <Badge
                              variant="outline"
                              className="text-[9px] bg-purple-500/20 text-purple-400 border-purple-500/30"
                            >
                              Shadow
                            </Badge>
                          )}
                          {api.isDeprecated && (
                            <Badge
                              variant="outline"
                              className="text-[9px] bg-zinc-500/20 text-zinc-400 border-zinc-500/30"
                            >
                              Deprecated
                            </Badge>
                          )}
                          {api.sensitiveDataTypes && (api.sensitiveDataTypes as string[]).length > 0 && (
                            <Badge
                              variant="outline"
                              className="text-[9px] bg-orange-500/20 text-orange-400 border-orange-500/30"
                            >
                              PII
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{formatDate(api.lastSeenAt)}</TableCell>
                      <TableCell>
                        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0"
                            onClick={() => dastScan.mutate({ apiId: api.id, scanType: "quick" })}
                            title="Run DAST scan"
                          >
                            <Scan className="h-3.5 w-3.5 text-indigo-400" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0"
                            onClick={() => deleteApi.mutate(api.id)}
                            title="Delete"
                          >
                            <Trash2 className="h-3.5 w-3.5 text-red-400" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          ) : (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="py-12 text-center text-muted-foreground text-sm">
                No APIs discovered yet. Import an OpenAPI spec or register APIs manually.
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Findings ─────────────────────────────────────────────────── */}
        <TabsContent value="findings" className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                className="pl-9 bg-zinc-900 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={findingTypeFilter} onValueChange={setFindingTypeFilter}>
              <SelectTrigger className="w-[160px] bg-zinc-900 border-zinc-800">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {Object.entries(findingTypeLabels).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[130px] bg-zinc-900 border-zinc-800">
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
              <SelectTrigger className="w-[140px] bg-zinc-900 border-zinc-800">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="acknowledged">Acknowledged</SelectItem>
                <SelectItem value="mitigated">Mitigated</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Finding stats bar */}
          {findingsData?.stats && (
            <div className="flex gap-4 text-sm">
              <span>
                Total: <strong>{findingsData.stats.total}</strong>
              </span>
              <span className="text-red-400">
                Open: <strong>{findingsData.stats.openCount}</strong>
              </span>
              <span className="text-red-400">
                Critical: <strong>{findingsData.stats.criticalCount}</strong>
              </span>
              <span className="text-orange-400">
                High: <strong>{findingsData.stats.highCount}</strong>
              </span>
              <span className="text-yellow-400">
                Medium: <strong>{findingsData.stats.mediumCount}</strong>
              </span>
              <span className="text-blue-400">
                Low: <strong>{findingsData.stats.lowCount}</strong>
              </span>
            </div>
          )}

          {findingsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading findings...</div>
          ) : findingsData?.findings && findingsData.findings.length > 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-[11px]">Type</TableHead>
                    <TableHead className="text-[11px]">Title</TableHead>
                    <TableHead className="text-[11px]">Endpoint</TableHead>
                    <TableHead className="text-[11px]">Severity</TableHead>
                    <TableHead className="text-[11px]">Status</TableHead>
                    <TableHead className="text-[11px]">CWE</TableHead>
                    <TableHead className="text-[11px]">Detected</TableHead>
                    <TableHead className="text-[11px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingsData.findings.map((f) => (
                    <TableRow
                      key={f.id}
                      className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                      onClick={() => setSelectedFinding(f)}
                    >
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] bg-zinc-800/50">
                          {findingTypeLabels[f.findingType] || f.findingType}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm max-w-[250px] truncate">{f.title}</TableCell>
                      <TableCell className="text-[11px] font-mono text-muted-foreground max-w-[150px] truncate">
                        {f.endpoint || "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`text-[10px] ${severityColors[f.severity] || ""}`}>
                          {f.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`text-[10px] ${statusColors[f.status] || ""}`}>
                          {f.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{f.cweId || "—"}</TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{formatDate(f.createdAt)}</TableCell>
                      <TableCell>
                        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                          {f.status === "open" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-[10px] px-2"
                              onClick={() => updateFinding.mutate({ id: f.id, status: "acknowledged" })}
                            >
                              Ack
                            </Button>
                          )}
                          {(f.status === "open" || f.status === "acknowledged") && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-[10px] px-2"
                              onClick={() => updateFinding.mutate({ id: f.id, status: "mitigated" })}
                            >
                              Mitigate
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          ) : (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="py-12 text-center text-muted-foreground text-sm">
                No findings. Import an OpenAPI spec and run a DAST scan to detect vulnerabilities.
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── 57.1 Traffic Analysis ──────────────────────────────────────── */}
        <TabsContent value="traffic" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Gauge className="h-4 w-4 text-blue-400" />
                API Traffic Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              {inventoryData?.apis && inventoryData.apis.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-[11px]">Method</TableHead>
                      <TableHead className="text-[11px]">Endpoint</TableHead>
                      <TableHead className="text-[11px]">Host</TableHead>
                      <TableHead className="text-[11px]">
                        <div className="flex items-center gap-1">
                          <ArrowUpDown className="h-3 w-3" />
                          Requests 24h
                        </div>
                      </TableHead>
                      <TableHead className="text-[11px]">Error Rate</TableHead>
                      <TableHead className="text-[11px]">
                        <div className="flex items-center gap-1">
                          <Timer className="h-3 w-3" />
                          Avg Latency
                        </div>
                      </TableHead>
                      <TableHead className="text-[11px]">Auth</TableHead>
                      <TableHead className="text-[11px]">Schema Drift</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {inventoryData.apis
                      .slice()
                      .sort((a, b) => b.requestCount24h - a.requestCount24h)
                      .map((api) => {
                        const errPct = (api.errorRate24h * 100).toFixed(1);
                        const errCls =
                          api.errorRate24h >= 0.1
                            ? "text-red-400"
                            : api.errorRate24h >= 0.05
                              ? "text-orange-400"
                              : "text-green-400";
                        const latCls =
                          api.avgLatencyMs >= 1000
                            ? "text-red-400"
                            : api.avgLatencyMs >= 500
                              ? "text-orange-400"
                              : "text-green-400";
                        return (
                          <TableRow
                            key={api.id}
                            className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                            onClick={() => setSelectedApi(api)}
                          >
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={`font-mono text-[10px] ${methodColors[api.method] || ""}`}
                              >
                                {api.method}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-xs max-w-[200px] truncate">{api.path}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{api.host}</TableCell>
                            <TableCell className="text-xs font-semibold tabular-nums">
                              {api.requestCount24h.toLocaleString()}
                            </TableCell>
                            <TableCell className={`text-xs font-semibold tabular-nums ${errCls}`}>{errPct}%</TableCell>
                            <TableCell className={`text-xs font-semibold tabular-nums ${latCls}`}>
                              {api.avgLatencyMs.toFixed(0)}ms
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={`text-[10px] ${api.authType === "none" ? "bg-red-500/20 text-red-400" : "bg-green-500/20 text-green-400"}`}
                              >
                                {authTypeLabels[api.authType] || api.authType}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {api.isShadow ? (
                                <Badge variant="outline" className="text-[10px] bg-purple-500/20 text-purple-400">
                                  Shadow
                                </Badge>
                              ) : api.isDeprecated ? (
                                <Badge variant="outline" className="text-[10px] bg-zinc-500/20 text-zinc-400">
                                  Deprecated
                                </Badge>
                              ) : (
                                <span className="text-[10px] text-green-400">OK</span>
                              )}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No APIs discovered yet. Import an OpenAPI spec or register endpoints to see traffic analysis.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── 57.2 Abuse Detection Timeline ──────────────────────────────── */}
        <TabsContent value="abuse" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                API Abuse Detection Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              {findingsData?.findings && findingsData.findings.length > 0 ? (
                (() => {
                  const abuseTypes = [
                    "bola",
                    "bfla",
                    "credential_stuffing",
                    "rate_abuse",
                    "injection",
                    "sensitive_data",
                  ];
                  const abuseFindings = findingsData.findings.filter((f) => abuseTypes.includes(f.findingType));

                  if (abuseFindings.length === 0) {
                    return (
                      <div className="text-center py-8 text-muted-foreground text-sm">
                        No abuse events detected. Run a DAST scan to discover potential abuse patterns.
                      </div>
                    );
                  }

                  // Group by date for timeline
                  const byDate: Record<string, ApiFinding[]> = {};
                  for (const f of abuseFindings) {
                    const dateKey = f.createdAt
                      ? new Date(f.createdAt).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })
                      : "Unknown";
                    if (!byDate[dateKey]) byDate[dateKey] = [];
                    byDate[dateKey].push(f);
                  }

                  return (
                    <div className="space-y-4">
                      {/* Abuse type summary */}
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                        {[
                          {
                            type: "bola",
                            label: "Broken Object Auth",
                            icon: <Lock className="h-3.5 w-3.5" />,
                            color: "text-red-400",
                          },
                          {
                            type: "bfla",
                            label: "Broken Function Auth",
                            icon: <Unlock className="h-3.5 w-3.5" />,
                            color: "text-orange-400",
                          },
                          {
                            type: "credential_stuffing",
                            label: "Credential Stuffing",
                            icon: <Users className="h-3.5 w-3.5" />,
                            color: "text-amber-400",
                          },
                          {
                            type: "rate_abuse",
                            label: "Rate Limit Abuse",
                            icon: <TrendingUp className="h-3.5 w-3.5" />,
                            color: "text-yellow-400",
                          },
                          {
                            type: "injection",
                            label: "Injection Attacks",
                            icon: <Bug className="h-3.5 w-3.5" />,
                            color: "text-red-500",
                          },
                          {
                            type: "sensitive_data",
                            label: "Data Scraping",
                            icon: <Eye className="h-3.5 w-3.5" />,
                            color: "text-purple-400",
                          },
                        ].map((at) => {
                          const c = abuseFindings.filter((f) => f.findingType === at.type).length;
                          return (
                            <div key={at.type} className="rounded border border-zinc-800 p-2 flex items-center gap-2">
                              <span className={at.color}>{at.icon}</span>
                              <div>
                                <div className="text-xs text-muted-foreground">{at.label}</div>
                                <div className={`text-sm font-semibold ${at.color}`}>{c}</div>
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {/* Timeline */}
                      <div className="border-l-2 border-zinc-700 ml-3 space-y-3">
                        {Object.entries(byDate).map(([dateStr, events]) => (
                          <div key={dateStr} className="relative pl-6">
                            <div className="absolute left-[-5px] top-1 w-2 h-2 rounded-full bg-zinc-400" />
                            <div className="text-xs text-muted-foreground font-medium mb-1">{dateStr}</div>
                            {events.map((evt) => (
                              <div
                                key={evt.id}
                                className="rounded border border-zinc-800 p-2 mb-1 cursor-pointer hover:bg-zinc-800/50"
                                onClick={() => setSelectedFinding(evt)}
                              >
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-2">
                                    <Badge
                                      variant="outline"
                                      className={`text-[10px] ${severityColors[evt.severity] || ""}`}
                                    >
                                      {evt.severity}
                                    </Badge>
                                    <span className="text-xs">{evt.title}</span>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <Badge variant="outline" className="text-[10px] bg-zinc-800/50">
                                      {findingTypeLabels[evt.findingType] || evt.findingType}
                                    </Badge>
                                    {evt.endpoint && (
                                      <code className="text-[10px] text-muted-foreground font-mono">
                                        {evt.endpoint}
                                      </code>
                                    )}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })()
              ) : (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No abuse events detected. Run a DAST scan to discover potential abuse patterns.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── 57.3 Schema Validation Detail ──────────────────────────────── */}
        <TabsContent value="schema" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <GitCompare className="h-4 w-4 text-cyan-400" />
                Schema Validation Detail
              </CardTitle>
            </CardHeader>
            <CardContent>
              {inventoryData?.apis && inventoryData.apis.length > 0 ? (
                <div className="space-y-3">
                  <p className="text-xs text-muted-foreground">
                    Compare observed request/response schemas against documented specifications. Mismatches indicate
                    potential data leaks, breaking changes, or undocumented behavior.
                  </p>
                  <Table>
                    <TableHeader>
                      <TableRow className="border-zinc-800 hover:bg-transparent">
                        <TableHead className="text-[11px]">Endpoint</TableHead>
                        <TableHead className="text-[11px]">Spec Source</TableHead>
                        <TableHead className="text-[11px]">Shadow</TableHead>
                        <TableHead className="text-[11px]">Sensitive Data</TableHead>
                        <TableHead className="text-[11px]">Schema Status</TableHead>
                        <TableHead className="text-[11px]">Risk</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {inventoryData.apis.map((api) => {
                        const sdTypes = (api.sensitiveDataTypes || []) as string[];
                        const hasSchemaIssues = api.isShadow || sdTypes.length > 0 || api.authType === "none";
                        const schemaStatus = api.isShadow
                          ? "undocumented"
                          : sdTypes.length > 0
                            ? "data_leak_risk"
                            : api.specSource
                              ? "validated"
                              : "no_spec";
                        const statusColors: Record<string, string> = {
                          validated: "bg-green-500/20 text-green-400",
                          undocumented: "bg-purple-500/20 text-purple-400",
                          data_leak_risk: "bg-orange-500/20 text-orange-400",
                          no_spec: "bg-zinc-500/20 text-zinc-400",
                        };
                        const statusLabels: Record<string, string> = {
                          validated: "Validated",
                          undocumented: "Undocumented",
                          data_leak_risk: "Data Leak Risk",
                          no_spec: "No Spec",
                        };
                        return (
                          <TableRow
                            key={api.id}
                            className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                            onClick={() => setSelectedApi(api)}
                          >
                            <TableCell>
                              <div className="flex items-center gap-1">
                                <Badge
                                  variant="outline"
                                  className={`font-mono text-[10px] ${methodColors[api.method] || ""}`}
                                >
                                  {api.method}
                                </Badge>
                                <span className="font-mono text-xs truncate max-w-[200px]">{api.path}</span>
                              </div>
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {api.specSource || "traffic"}
                            </TableCell>
                            <TableCell>
                              {api.isShadow ? (
                                <Badge variant="outline" className="text-[10px] bg-purple-500/20 text-purple-400">
                                  Yes
                                </Badge>
                              ) : (
                                <span className="text-[10px] text-green-400">No</span>
                              )}
                            </TableCell>
                            <TableCell>
                              {sdTypes.length > 0 ? (
                                <div className="flex flex-wrap gap-0.5">
                                  {sdTypes.map((t) => (
                                    <Badge
                                      key={t}
                                      variant="outline"
                                      className="text-[9px] bg-orange-500/20 text-orange-400 border-orange-500/30"
                                    >
                                      {t}
                                    </Badge>
                                  ))}
                                </div>
                              ) : (
                                <span className="text-[10px] text-muted-foreground">None</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={`text-[10px] ${statusColors[schemaStatus] || ""}`}>
                                {statusLabels[schemaStatus] || schemaStatus}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <span className={`text-xs font-semibold ${riskColor(api.riskScore)}`}>
                                {api.riskScore}
                              </span>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>

                  {/* Schema mismatch summary */}
                  {(() => {
                    const schemaFindings =
                      findingsData?.findings?.filter((f) => f.findingType === "schema_violation") || [];
                    if (schemaFindings.length === 0) return null;
                    return (
                      <Card className="bg-zinc-800/30 border-zinc-700">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-xs flex items-center gap-2">
                            <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />
                            Schema Violation Findings ({schemaFindings.length})
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-1">
                          {schemaFindings.slice(0, 5).map((f) => (
                            <div
                              key={f.id}
                              className="flex items-center justify-between text-xs p-1.5 rounded hover:bg-zinc-800/50 cursor-pointer"
                              onClick={() => setSelectedFinding(f)}
                            >
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className={`text-[9px] ${severityColors[f.severity] || ""}`}>
                                  {f.severity}
                                </Badge>
                                <span className="truncate max-w-[300px]">{f.title}</span>
                              </div>
                              <code className="text-[10px] text-muted-foreground font-mono">{f.endpoint || ""}</code>
                            </div>
                          ))}
                        </CardContent>
                      </Card>
                    );
                  })()}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No APIs discovered yet. Import an OpenAPI spec to compare schemas.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Hosts ────────────────────────────────────────────────────── */}
        <TabsContent value="hosts" className="space-y-4">
          {hosts.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {hosts.map((h) => (
                <Card key={h.host} className="bg-zinc-900/50 border-zinc-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-mono flex items-center gap-2">
                      <Network className="h-4 w-4 text-indigo-400" />
                      {h.host}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">APIs</span>
                      <span className="font-semibold">{h.api_count}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Shadow</span>
                      <span className="text-purple-400">{h.shadow_count}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">No Auth</span>
                      <span className="text-red-400">{h.no_auth_count}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Avg Risk</span>
                      <span className={riskColor(parseFloat(h.avg_risk || "0"))}>
                        {parseFloat(h.avg_risk || "0").toFixed(0)}
                      </span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="py-12 text-center text-muted-foreground text-sm">
                No hosts discovered. Import an OpenAPI spec or register APIs to see host breakdown.
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* ── Import OpenAPI Spec Dialog ──────────────────────────────────── */}
      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-w-2xl bg-zinc-950 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Upload className="h-5 w-5 text-indigo-400" />
              Import OpenAPI Specification
            </DialogTitle>
            <DialogDescription>Paste your OpenAPI 3.x JSON spec to auto-discover all API endpoints.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Host / Base URL</Label>
              <Input
                placeholder="api.example.com"
                value={specHost}
                onChange={(e) => setSpecHost(e.target.value)}
                className="bg-zinc-900 border-zinc-800 mt-1"
              />
            </div>
            <div>
              <Label>OpenAPI Spec (JSON)</Label>
              <Textarea
                placeholder='{"openapi": "3.0.0", "info": {...}, "paths": {...}}'
                value={specJson}
                onChange={(e) => setSpecJson(e.target.value)}
                className="bg-zinc-900 border-zinc-800 mt-1 font-mono text-xs"
                rows={12}
              />
            </div>
            <Button
              className="w-full bg-indigo-600 hover:bg-indigo-700"
              onClick={handleImport}
              disabled={importSpec.isPending}
            >
              {importSpec.isPending ? "Importing..." : "Import Spec"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* ── Add API Dialog ─────────────────────────────────────────────── */}
      <Dialog open={addApiOpen} onOpenChange={setAddApiOpen}>
        <DialogContent className="bg-zinc-950 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-indigo-400" />
              Register API Endpoint
            </DialogTitle>
            <DialogDescription>Manually register an API endpoint for monitoring.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Method</Label>
                <Select value={newMethod} onValueChange={setNewMethod}>
                  <SelectTrigger className="bg-zinc-900 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Auth Type</Label>
                <Select value={newAuthType} onValueChange={setNewAuthType}>
                  <SelectTrigger className="bg-zinc-900 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(authTypeLabels).map(([k, v]) => (
                      <SelectItem key={k} value={k}>
                        {v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label>Path</Label>
              <Input
                placeholder="/api/v1/users/:id"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
                className="bg-zinc-900 border-zinc-800 mt-1 font-mono"
              />
            </div>
            <div>
              <Label>Host</Label>
              <Input
                placeholder="api.example.com"
                value={newHost}
                onChange={(e) => setNewHost(e.target.value)}
                className="bg-zinc-900 border-zinc-800 mt-1"
              />
            </div>
            <Button
              className="w-full bg-indigo-600 hover:bg-indigo-700"
              onClick={handleAddApi}
              disabled={addApi.isPending}
            >
              {addApi.isPending ? "Adding..." : "Add API Endpoint"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* ── Finding Detail Dialog ──────────────────────────────────────── */}
      <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
        <DialogContent className="max-w-2xl bg-zinc-950 border-zinc-800">
          {selectedFinding && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5 text-orange-400" />
                  {selectedFinding.title}
                </DialogTitle>
                <DialogDescription>
                  {findingTypeLabels[selectedFinding.findingType] || selectedFinding.findingType} —{" "}
                  {selectedFinding.owaspCategory || "Uncategorized"}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <Badge variant="outline" className={severityColors[selectedFinding.severity] || ""}>
                    {selectedFinding.severity}
                  </Badge>
                  <Badge variant="outline" className={statusColors[selectedFinding.status] || ""}>
                    {selectedFinding.status}
                  </Badge>
                  {selectedFinding.cweId && (
                    <Badge variant="outline" className="bg-zinc-800/50">
                      {selectedFinding.cweId}
                    </Badge>
                  )}
                </div>
                {selectedFinding.endpoint && (
                  <div>
                    <div className="text-[11px] text-muted-foreground mb-1">Endpoint</div>
                    <code className="text-sm bg-zinc-900 px-2 py-1 rounded font-mono">{selectedFinding.endpoint}</code>
                  </div>
                )}
                {selectedFinding.description && (
                  <div>
                    <div className="text-[11px] text-muted-foreground mb-1">Description</div>
                    <p className="text-sm">{selectedFinding.description}</p>
                  </div>
                )}
                {selectedFinding.remediation && (
                  <div>
                    <div className="text-[11px] text-muted-foreground mb-1">Remediation</div>
                    <p className="text-sm text-green-400/80">{selectedFinding.remediation}</p>
                  </div>
                )}
                {selectedFinding.evidence && Object.keys(selectedFinding.evidence).length > 0 && (
                  <div>
                    <div className="text-[11px] text-muted-foreground mb-1">Evidence</div>
                    <pre className="text-xs bg-zinc-900 p-2 rounded overflow-x-auto font-mono">
                      {JSON.stringify(selectedFinding.evidence, null, 2)}
                    </pre>
                  </div>
                )}
                <div className="flex gap-2 pt-2">
                  {selectedFinding.status === "open" && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="border-zinc-700"
                      onClick={() => {
                        updateFinding.mutate({ id: selectedFinding.id, status: "acknowledged" });
                        setSelectedFinding(null);
                      }}
                    >
                      Acknowledge
                    </Button>
                  )}
                  {(selectedFinding.status === "open" || selectedFinding.status === "acknowledged") && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        className="border-green-800 text-green-400"
                        onClick={() => {
                          updateFinding.mutate({ id: selectedFinding.id, status: "mitigated" });
                          setSelectedFinding(null);
                        }}
                      >
                        Mark Mitigated
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="border-zinc-700"
                        onClick={() => {
                          updateFinding.mutate({ id: selectedFinding.id, status: "false_positive" });
                          setSelectedFinding(null);
                        }}
                      >
                        False Positive
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* ── API Detail Dialog ──────────────────────────────────────────── */}
      <Dialog open={!!selectedApi} onOpenChange={() => setSelectedApi(null)}>
        <DialogContent className="max-w-lg bg-zinc-950 border-zinc-800">
          {selectedApi && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Badge variant="outline" className={`font-mono ${methodColors[selectedApi.method] || ""}`}>
                    {selectedApi.method}
                  </Badge>
                  <span className="font-mono text-sm">{selectedApi.path}</span>
                </DialogTitle>
                <DialogDescription>{selectedApi.host}</DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[11px] text-muted-foreground">Auth Type</div>
                    <Badge
                      variant="outline"
                      className={`mt-1 ${selectedApi.authType === "none" ? "bg-red-500/20 text-red-400" : "bg-green-500/20 text-green-400"}`}
                    >
                      {authTypeLabels[selectedApi.authType] || selectedApi.authType}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-[11px] text-muted-foreground">Risk Score</div>
                    <div className={`text-lg font-semibold ${riskColor(selectedApi.riskScore)}`}>
                      {selectedApi.riskScore}/100
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-muted-foreground">Requests (24h)</div>
                    <div className="text-sm font-semibold">{selectedApi.requestCount24h.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-muted-foreground">Error Rate</div>
                    <div className="text-sm font-semibold">{(selectedApi.errorRate24h * 100).toFixed(1)}%</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-muted-foreground">Avg Latency</div>
                    <div className="text-sm font-semibold">{selectedApi.avgLatencyMs.toFixed(0)}ms</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-muted-foreground">Source</div>
                    <div className="text-sm">{selectedApi.specSource || "traffic"}</div>
                  </div>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {selectedApi.isShadow && (
                    <Badge variant="outline" className="bg-purple-500/20 text-purple-400 border-purple-500/30">
                      Shadow
                    </Badge>
                  )}
                  {selectedApi.isDeprecated && (
                    <Badge variant="outline" className="bg-zinc-500/20 text-zinc-400">
                      Deprecated
                    </Badge>
                  )}
                  {selectedApi.sensitiveDataTypes &&
                    (selectedApi.sensitiveDataTypes as string[]).map((t) => (
                      <Badge
                        key={t}
                        variant="outline"
                        className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-[10px]"
                      >
                        {t}
                      </Badge>
                    ))}
                </div>
                <div className="flex gap-2 pt-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1.5 border-zinc-700"
                    onClick={() => dastScan.mutate({ apiId: selectedApi.id, scanType: "full" })}
                    disabled={dastScan.isPending}
                  >
                    <Scan className="h-3.5 w-3.5" />
                    {dastScan.isPending ? "Scanning..." : "Full DAST Scan"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1.5 border-red-800 text-red-400"
                    onClick={() => deleteApi.mutate(selectedApi.id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </Button>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
