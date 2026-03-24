import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  Database,
  Shield,
  AlertTriangle,
  Globe,
  FileText,
  Users,
  Search,
  Plus,
  ArrowRight,
  CheckCircle,
  XCircle,
  Clock,
  Fingerprint,
  Scan,
  Eye,
  Trash2,
  RefreshCw,
} from "lucide-react";

// ── API helpers ─────────────────────────────────────────────────────

async function apiFetch(url: string, options?: RequestInit) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  const csrfToken = document.cookie
    .split("; ")
    .find((c) => c.startsWith("XSRF-TOKEN="))
    ?.split("=")[1];
  if (csrfToken) headers["x-csrf-token"] = decodeURIComponent(csrfToken);

  const res = await fetch(url, { ...options, headers, credentials: "include" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as Record<string, string>).error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Types ───────────────────────────────────────────────────────────

interface Dashboard {
  totalDataAssets: number;
  classificationBreakdown: Record<string, number>;
  piiFieldCount: number;
  phiFieldCount: number;
  pciFieldCount: number;
  crossBorderFlows: number;
  openAlerts: number;
  pendingDsars: number;
  activePias: number;
  activeConsents: number;
  averageRiskScore: number;
  jurisdictionBreakdown: Record<string, number>;
  recentScans: Array<{
    id: string;
    scanType: string;
    status: string;
    findingsCount: number;
    startedAt: string;
    completedAt: string | null;
  }>;
  enums: {
    classificationLevels: string[];
    piiCategories: string[];
    assetTypes: string[];
    flowStatuses: string[];
    piaStatuses: string[];
    piaRiskLevels: string[];
    consentPurposes: string[];
    dsarTypes: string[];
    jurisdictions: string[];
  };
  // 70.1 — Data map: asset type breakdown
  assetTypeBreakdown?: Record<string, number>;
  // 70.3 — Consent purpose breakdown
  consentPurposeBreakdown?: Record<string, number>;
  // 70.5 — Automated discovery stats
  discoveryStats?: { lastScanAt: string | null; totalFindings: number; autoClassified: number };
  // 70.6 — Retention enforcement summary
  retentionSummary?: { withRetention: number; withoutRetention: number; expiredRetention: number };
}

interface DataAsset {
  id: string;
  name: string;
  description: string | null;
  assetType: string;
  hostname: string | null;
  classification: string;
  piiCategories: string[];
  recordCount: number | null;
  dataSubjectCount: number | null;
  jurisdiction: string;
  isEncrypted: boolean;
  dataOwner: string | null;
  riskScore: number;
  lastScannedAt: string | null;
  minimizationRecommendations: string[];
  createdAt: string;
}

interface DataFlow {
  id: string;
  name: string;
  description: string | null;
  sourceName: string;
  sourceJurisdiction: string;
  destinationName: string;
  destinationJurisdiction: string;
  piiCategories: string[];
  isCrossBorder: boolean;
  transferRiskLevel: string | null;
  status: string;
  purpose: string | null;
  createdAt: string;
}

interface PIA {
  id: string;
  title: string;
  description: string | null;
  projectName: string | null;
  assessorName: string | null;
  status: string;
  overallRisk: string;
  dataCollected: string[];
  crossBorderTransfers: boolean;
  dpoApproval: boolean;
  privacyRisks: Array<{
    risk: string;
    likelihood: string;
    impact: string;
    mitigation: string;
  }>;
  createdAt: string;
}

interface ConsentRecord {
  id: string;
  dataSubjectId: string;
  dataSubjectEmail: string | null;
  purpose: string;
  granted: boolean;
  source: string;
  consentVersion: string | null;
  grantedAt: string | null;
  withdrawnAt: string | null;
  createdAt: string;
}

interface CrossBorderAlert {
  id: string;
  sourceJurisdiction: string;
  destinationJurisdiction: string;
  dataCategories: string[];
  riskLevel: string;
  alertReason: string;
  legalMechanism: string | null;
  requiresAction: boolean;
  resolvedAt: string | null;
  createdAt: string;
}

// ── Utility ─────────────────────────────────────────────────────────

function riskBadge(level: string) {
  const map: Record<string, string> = {
    negligible: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    very_high: "bg-red-500/10 text-red-400 border-red-500/20",
    critical: "bg-red-500/10 text-red-400 border-red-500/20",
  };
  return (
    <Badge variant="outline" className={map[level] || "bg-slate-500/10 text-slate-400"}>
      {level.replace("_", " ")}
    </Badge>
  );
}

function classificationBadge(level: string) {
  const map: Record<string, string> = {
    public: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    internal: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    confidential: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    restricted: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    top_secret: "bg-red-500/10 text-red-400 border-red-500/20",
  };
  return (
    <Badge variant="outline" className={map[level] || "bg-slate-500/10 text-slate-400"}>
      {level.replace("_", " ")}
    </Badge>
  );
}

function statusBadge(status: string) {
  const map: Record<string, string> = {
    draft: "bg-slate-500/10 text-slate-400",
    in_review: "bg-blue-500/10 text-blue-400",
    approved: "bg-emerald-500/10 text-emerald-400",
    rejected: "bg-red-500/10 text-red-400",
    needs_revision: "bg-amber-500/10 text-amber-400",
    expired: "bg-slate-500/10 text-slate-400",
    active: "bg-emerald-500/10 text-emerald-400",
    inactive: "bg-slate-500/10 text-slate-400",
    pending: "bg-amber-500/10 text-amber-400",
    in_progress: "bg-blue-500/10 text-blue-400",
    completed: "bg-emerald-500/10 text-emerald-400",
    failed: "bg-red-500/10 text-red-400",
  };
  return (
    <Badge variant="outline" className={map[status] || "bg-slate-500/10 text-slate-400"}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function RiskMeter({ score }: { score: number }) {
  const color =
    score >= 80
      ? "bg-red-500"
      : score >= 60
        ? "bg-orange-500"
        : score >= 40
          ? "bg-amber-500"
          : score >= 20
            ? "bg-blue-500"
            : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-muted-foreground font-mono w-8">{score}</span>
    </div>
  );
}

// ── Main Page Component ─────────────────────────────────────────────

export default function PrivacyEngineeringPage() {
  const [activeTab, setActiveTab] = useState("overview");

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Fingerprint className="h-6 w-6" />
            Privacy Engineering (DSPM++)
          </h1>
          <p className="text-muted-foreground mt-1">
            Data Security Posture Management — discover, classify, and protect sensitive data
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="data-assets">Data Assets</TabsTrigger>
          <TabsTrigger value="data-flows">Data Flows</TabsTrigger>
          <TabsTrigger value="pia">PIAs</TabsTrigger>
          <TabsTrigger value="consent">Consent</TabsTrigger>
          <TabsTrigger value="cross-border">Cross-Border</TabsTrigger>
          <TabsTrigger value="dsar">DSAR</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        <TabsContent value="data-assets">
          <DataAssetsTab />
        </TabsContent>
        <TabsContent value="data-flows">
          <DataFlowsTab />
        </TabsContent>
        <TabsContent value="pia">
          <PIATab />
        </TabsContent>
        <TabsContent value="consent">
          <ConsentTab />
        </TabsContent>
        <TabsContent value="cross-border">
          <CrossBorderTab />
        </TabsContent>
        <TabsContent value="dsar">
          <DSARTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Overview Tab ────────────────────────────────────────────────────

function OverviewTab() {
  const { data: dashboard, isLoading } = useQuery<Dashboard>({
    queryKey: ["/api/privacy-engineering/dashboard"],
    queryFn: () => apiFetch("/api/privacy-engineering/dashboard"),
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      </div>
    );
  }

  const d = dashboard;

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Data Assets</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{d?.totalDataAssets ?? 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Discovered and registered</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Average Risk Score</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{d?.averageRiskScore ?? 0}/100</div>
            <RiskMeter score={d?.averageRiskScore ?? 0} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Cross-Border Flows</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{d?.crossBorderFlows ?? 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Active international transfers</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Open Alerts</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-400">{d?.openAlerts ?? 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Requiring action</p>
          </CardContent>
        </Card>
      </div>

      {/* Data Classification & Sensitive Data */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Data Classification Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            {d?.classificationBreakdown && Object.keys(d.classificationBreakdown).length > 0 ? (
              <div className="space-y-3">
                {Object.entries(d.classificationBreakdown).map(([level, cnt]) => (
                  <div key={level} className="flex items-center justify-between">
                    {classificationBadge(level)}
                    <span className="text-sm font-mono">{cnt}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No data assets discovered yet</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Sensitive Data Detected</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-blue-400" />
                  <span className="text-sm">PII Fields</span>
                </div>
                <span className="text-sm font-mono">{d?.piiFieldCount ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <span className="text-sm">PHI Fields</span>
                </div>
                <span className="text-sm font-mono">{d?.phiFieldCount ?? 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-amber-400" />
                  <span className="text-sm">PCI Fields</span>
                </div>
                <span className="text-sm font-mono">{d?.pciFieldCount ?? 0}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Activity Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Pending DSARs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{d?.pendingDsars ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>PIAs In Review</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{d?.activePias ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active Consents</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{d?.activeConsents ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Jurisdictions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {d?.jurisdictionBreakdown ? Object.keys(d.jurisdictionBreakdown).length : 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 70.1 — Data Map Visualization: Asset Type Breakdown */}
      {d?.assetTypeBreakdown && Object.keys(d.assetTypeBreakdown).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Data Map — Asset Type Breakdown</CardTitle>
            <CardDescription>Distribution of data assets by type across your infrastructure</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(d.assetTypeBreakdown).map(([type, cnt]) => (
                <div key={type} className="p-3 border border-border/50 rounded-lg text-center">
                  <p className="text-lg font-semibold">{cnt as number}</p>
                  <p className="text-xs text-muted-foreground">{type.replace(/_/g, " ")}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 70.3 — Consent Management: Purpose Breakdown */}
      {d?.consentPurposeBreakdown && Object.keys(d.consentPurposeBreakdown).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Consent Purpose Dashboard</CardTitle>
            <CardDescription>Active consent records grouped by purpose</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(d.consentPurposeBreakdown).map(([purpose, cnt]) => (
                <div
                  key={purpose}
                  className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
                >
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4 text-blue-400" />
                    <span className="text-sm">{purpose.replace(/_/g, " ")}</span>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    {cnt as number} consents
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 70.5 — Automated Data Discovery Stats */}
      {d?.discoveryStats && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Automated Discovery</CardTitle>
            <CardDescription>Data discovery scan statistics and auto-classification metrics</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold">{d.discoveryStats.totalFindings}</p>
                <p className="text-xs text-muted-foreground">Total Findings</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-green-400">{d.discoveryStats.autoClassified}</p>
                <p className="text-xs text-muted-foreground">Auto-Classified</p>
              </div>
              <div className="text-center">
                <p className="text-sm text-muted-foreground">
                  {d.discoveryStats.lastScanAt
                    ? `Last scan: ${new Date(d.discoveryStats.lastScanAt).toLocaleDateString()}`
                    : "No scans run yet"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* 70.6 — Data Retention Enforcement Summary */}
      {d?.retentionSummary && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Data Retention Enforcement</CardTitle>
            <CardDescription>Retention policy coverage and expiration tracking</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-green-400">{d.retentionSummary.withRetention}</p>
                <p className="text-xs text-muted-foreground">With Retention Policy</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-yellow-400">{d.retentionSummary.withoutRetention}</p>
                <p className="text-xs text-muted-foreground">No Retention Policy</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-red-400">{d.retentionSummary.expiredRetention}</p>
                <p className="text-xs text-muted-foreground">Expired / Overdue</p>
              </div>
            </div>
            {d.retentionSummary.withoutRetention > 0 && (
              <p className="text-xs text-amber-400 mt-3">
                <AlertTriangle className="h-3 w-3 inline mr-1" />
                {d.retentionSummary.withoutRetention} asset(s) lack a retention policy — consider adding one to ensure
                compliance.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {d?.recentScans && d.recentScans.length > 0 ? (
            <div className="space-y-2">
              {d.recentScans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between py-2 border-b border-border last:border-0"
                >
                  <div className="flex items-center gap-3">
                    <Scan className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">{scan.scanType} scan</span>
                    {statusBadge(scan.status)}
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">{scan.findingsCount} findings</span>
                    <span className="text-xs text-muted-foreground">
                      {new Date(scan.startedAt).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No scans run yet</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Data Assets Tab ─────────────────────────────────────────────────

function DataAssetsTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [classFilter, setClassFilter] = useState("all");
  const [showCreate, setShowCreate] = useState(false);
  const [showScan, setShowScan] = useState(false);
  const [scanFields, setScanFields] = useState("");
  const [scanTarget, setScanTarget] = useState("");

  const { data, isLoading } = useQuery<{ items: DataAsset[]; total: number }>({
    queryKey: ["/api/privacy-engineering/data-assets", search, classFilter],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (search) params.set("search", search);
      if (classFilter !== "all") params.set("classification", classFilter);
      return apiFetch(`/api/privacy-engineering/data-assets?${params}`);
    },
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/privacy-engineering/data-assets", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/data-assets"] });
      toast({ title: "Data asset created" });
      setShowCreate(false);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/privacy-engineering/data-assets/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/data-assets"] });
      toast({ title: "Data asset deleted" });
    },
  });

  const scanMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/privacy-engineering/scan", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (result: {
      scan: unknown;
      results: Array<{ field: string; detectedType: string; confidence: number }>;
      minimizationFindings: Array<{ field: string; recommendation: string }>;
    }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/data-assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/dashboard"] });
      toast({ title: `Scan complete — ${result.results.length} findings` });
      setShowScan(false);
    },
    onError: (err: Error) => toast({ title: "Scan failed", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search data assets..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={classFilter} onValueChange={setClassFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="public">Public</SelectItem>
            <SelectItem value="internal">Internal</SelectItem>
            <SelectItem value="confidential">Confidential</SelectItem>
            <SelectItem value="restricted">Restricted</SelectItem>
            <SelectItem value="top_secret">Top Secret</SelectItem>
          </SelectContent>
        </Select>

        <Dialog open={showScan} onOpenChange={setShowScan}>
          <DialogTrigger asChild>
            <Button variant="outline" size="sm">
              <Scan className="h-4 w-4 mr-1" />
              Scan Fields
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Run PII/PHI/PCI Scan</DialogTitle>
              <DialogDescription>
                Enter field names (one per line) to scan for sensitive data patterns
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <div>
                <Label>Target Asset ID (optional)</Label>
                <Input
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  placeholder="Asset ID to update with results"
                />
              </div>
              <div>
                <Label>Field Names</Label>
                <Textarea
                  rows={8}
                  value={scanFields}
                  onChange={(e) => setScanFields(e.target.value)}
                  placeholder={"email\nfirst_name\nlast_name\nssn\nphone_number\nip_address\ncredit_card_number"}
                />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => {
                  const fields = scanFields
                    .split("\n")
                    .map((f) => f.trim())
                    .filter(Boolean);
                  if (fields.length === 0) return;
                  scanMutation.mutate({
                    scanType: "full",
                    fields,
                    targetAssetId: scanTarget || undefined,
                    targetDescription: "Manual field scan",
                  });
                }}
                disabled={scanMutation.isPending}
              >
                {scanMutation.isPending ? "Scanning..." : "Run Scan"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              Add Asset
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Register Data Asset</DialogTitle>
            </DialogHeader>
            <CreateAssetForm onSubmit={(body) => createMutation.mutate(body)} isPending={createMutation.isPending} />
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {data?.items.map((asset) => (
            <Card key={asset.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Database className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{asset.name}</span>
                      {classificationBadge(asset.classification)}
                      <Badge variant="outline" className="text-xs">
                        {asset.assetType.replace(/_/g, " ")}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      {asset.hostname && <span>{asset.hostname}</span>}
                      <span>{asset.jurisdiction}</span>
                      {asset.dataOwner && <span>Owner: {asset.dataOwner}</span>}
                      {asset.piiCategories.length > 0 && <span>{asset.piiCategories.length} PII types</span>}
                      {asset.isEncrypted ? (
                        <span className="text-emerald-400">Encrypted</span>
                      ) : (
                        <span className="text-amber-400">Unencrypted</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-24">
                      <RiskMeter score={asset.riskScore} />
                    </div>
                    <Button variant="ghost" size="icon" onClick={() => deleteMutation.mutate(asset.id)}>
                      <Trash2 className="h-4 w-4 text-muted-foreground" />
                    </Button>
                  </div>
                </div>
                {asset.minimizationRecommendations.length > 0 && (
                  <div className="mt-2 p-2 bg-amber-500/5 border border-amber-500/10 rounded text-xs text-amber-400">
                    <strong>Minimization:</strong> {asset.minimizationRecommendations[0]}
                    {asset.minimizationRecommendations.length > 1 && (
                      <span> (+{asset.minimizationRecommendations.length - 1} more)</span>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
          {data?.items.length === 0 && (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Database className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No data assets registered yet</p>
                <p className="text-xs mt-1">Add your first data asset or run a scan to get started</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function CreateAssetForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState({
    name: "",
    assetType: "database_table",
    classification: "internal",
    jurisdiction: "US",
    hostname: "",
    dataOwner: "",
    description: "",
  });

  return (
    <div className="space-y-3">
      <div>
        <Label>Name *</Label>
        <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Asset Type</Label>
          <Select value={form.assetType} onValueChange={(v) => setForm({ ...form, assetType: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[
                "database_table",
                "database_column",
                "s3_bucket",
                "file_share",
                "api_endpoint",
                "log_stream",
                "saas_app",
                "data_warehouse",
                "cache",
                "message_queue",
                "backup",
              ].map((t) => (
                <SelectItem key={t} value={t}>
                  {t.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Classification</Label>
          <Select value={form.classification} onValueChange={(v) => setForm({ ...form, classification: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["public", "internal", "confidential", "restricted", "top_secret"].map((c) => (
                <SelectItem key={c} value={c}>
                  {c.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Jurisdiction</Label>
          <Select value={form.jurisdiction} onValueChange={(v) => setForm({ ...form, jurisdiction: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["EU", "US", "US-CA", "UK", "BR", "CA", "IN", "SG", "AU", "JP", "OTHER"].map((j) => (
                <SelectItem key={j} value={j}>
                  {j}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Hostname</Label>
          <Input value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
        </div>
      </div>
      <div>
        <Label>Data Owner</Label>
        <Input value={form.dataOwner} onChange={(e) => setForm({ ...form, dataOwner: e.target.value })} />
      </div>
      <div>
        <Label>Description</Label>
        <Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
      </div>
      <DialogFooter>
        <Button onClick={() => onSubmit(form)} disabled={!form.name || isPending}>
          {isPending ? "Creating..." : "Create Asset"}
        </Button>
      </DialogFooter>
    </div>
  );
}

// ── Data Flows Tab ──────────────────────────────────────────────────

function DataFlowsTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [crossBorderOnly, setCrossBorderOnly] = useState(false);

  const { data, isLoading } = useQuery<{ items: DataFlow[]; total: number }>({
    queryKey: ["/api/privacy-engineering/data-flows", crossBorderOnly],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (crossBorderOnly) params.set("crossBorder", "true");
      return apiFetch(`/api/privacy-engineering/data-flows?${params}`);
    },
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/privacy-engineering/data-flows", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/data-flows"] });
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/dashboard"] });
      toast({ title: "Data flow created" });
      setShowCreate(false);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/privacy-engineering/data-flows/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/data-flows"] });
      toast({ title: "Data flow deleted" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button
          variant={crossBorderOnly ? "default" : "outline"}
          size="sm"
          onClick={() => setCrossBorderOnly(!crossBorderOnly)}
        >
          <Globe className="h-4 w-4 mr-1" />
          Cross-Border Only
        </Button>

        <div className="flex-1" />

        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              Add Flow
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Map Data Flow</DialogTitle>
              <DialogDescription>Track where PII originates, travels, and who processes it</DialogDescription>
            </DialogHeader>
            <CreateFlowForm onSubmit={(body) => createMutation.mutate(body)} isPending={createMutation.isPending} />
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {data?.items.map((flow) => (
            <Card key={flow.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{flow.name}</span>
                      {statusBadge(flow.status)}
                      {flow.isCrossBorder && (
                        <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/20">
                          Cross-Border
                        </Badge>
                      )}
                      {flow.transferRiskLevel && riskBadge(flow.transferRiskLevel)}
                    </div>
                    <div className="flex items-center gap-2 mt-2 text-sm">
                      <Badge variant="secondary" className="text-xs">
                        {flow.sourceName} ({flow.sourceJurisdiction})
                      </Badge>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      <Badge variant="secondary" className="text-xs">
                        {flow.destinationName} ({flow.destinationJurisdiction})
                      </Badge>
                    </div>
                    {flow.purpose && <p className="text-xs text-muted-foreground mt-1">Purpose: {flow.purpose}</p>}
                  </div>
                  <Button variant="ghost" size="icon" onClick={() => deleteMutation.mutate(flow.id)}>
                    <Trash2 className="h-4 w-4 text-muted-foreground" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
          {data?.items.length === 0 && (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Globe className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No data flows mapped yet</p>
                <p className="text-xs mt-1">Map your first data flow to track PII movement</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function CreateFlowForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState({
    name: "",
    sourceName: "",
    sourceJurisdiction: "US",
    destinationName: "",
    destinationJurisdiction: "EU",
    purpose: "",
  });

  return (
    <div className="space-y-3">
      <div>
        <Label>Flow Name *</Label>
        <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Source System *</Label>
          <Input value={form.sourceName} onChange={(e) => setForm({ ...form, sourceName: e.target.value })} />
        </div>
        <div>
          <Label>Source Jurisdiction</Label>
          <Select value={form.sourceJurisdiction} onValueChange={(v) => setForm({ ...form, sourceJurisdiction: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["EU", "US", "US-CA", "UK", "BR", "CA", "IN", "SG", "AU", "JP", "OTHER"].map((j) => (
                <SelectItem key={j} value={j}>
                  {j}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Destination System *</Label>
          <Input value={form.destinationName} onChange={(e) => setForm({ ...form, destinationName: e.target.value })} />
        </div>
        <div>
          <Label>Destination Jurisdiction</Label>
          <Select
            value={form.destinationJurisdiction}
            onValueChange={(v) => setForm({ ...form, destinationJurisdiction: v })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["EU", "US", "US-CA", "UK", "BR", "CA", "IN", "SG", "AU", "JP", "OTHER"].map((j) => (
                <SelectItem key={j} value={j}>
                  {j}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div>
        <Label>Purpose</Label>
        <Input value={form.purpose} onChange={(e) => setForm({ ...form, purpose: e.target.value })} />
      </div>
      <DialogFooter>
        <Button
          onClick={() => onSubmit(form)}
          disabled={!form.name || !form.sourceName || !form.destinationName || isPending}
        >
          {isPending ? "Creating..." : "Create Flow"}
        </Button>
      </DialogFooter>
    </div>
  );
}

// ── PIA Tab ─────────────────────────────────────────────────────────

function PIATab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");

  const { data, isLoading } = useQuery<{ items: PIA[]; total: number }>({
    queryKey: ["/api/privacy-engineering/pias", statusFilter],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (statusFilter !== "all") params.set("status", statusFilter);
      return apiFetch(`/api/privacy-engineering/pias?${params}`);
    },
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/privacy-engineering/pias", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/pias"] });
      toast({ title: "PIA created" });
      setShowCreate(false);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      apiFetch(`/api/privacy-engineering/pias/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/pias"] });
      toast({ title: "PIA updated" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="in_review">In Review</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
            <SelectItem value="needs_revision">Needs Revision</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex-1" />
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              New PIA
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Privacy Impact Assessment</DialogTitle>
              <DialogDescription>
                Guided assessment for new products, features, or processing activities
              </DialogDescription>
            </DialogHeader>
            <CreatePIAForm onSubmit={(body) => createMutation.mutate(body)} isPending={createMutation.isPending} />
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {data?.items.map((pia) => (
            <Card key={pia.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{pia.title}</span>
                      {statusBadge(pia.status)}
                      {riskBadge(pia.overallRisk)}
                      {pia.dpoApproval && (
                        <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                          DPO Approved
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      {pia.projectName && <span>Project: {pia.projectName}</span>}
                      {pia.assessorName && <span>Assessor: {pia.assessorName}</span>}
                      {pia.dataCollected.length > 0 && <span>{pia.dataCollected.length} data types</span>}
                      {pia.crossBorderTransfers && <span className="text-purple-400">Cross-border</span>}
                      {pia.privacyRisks.length > 0 && <span>{pia.privacyRisks.length} risks identified</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {pia.status === "draft" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => updateMutation.mutate({ id: pia.id, body: { status: "in_review" } })}
                      >
                        Submit for Review
                      </Button>
                    )}
                    {pia.status === "in_review" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          updateMutation.mutate({ id: pia.id, body: { status: "approved", dpoApproval: true } })
                        }
                      >
                        <CheckCircle className="h-4 w-4 mr-1" />
                        Approve
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          {data?.items.length === 0 && (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <FileText className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No Privacy Impact Assessments yet</p>
                <p className="text-xs mt-1">Create one before launching new products or features</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function CreatePIAForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState({
    title: "",
    projectName: "",
    assessorName: "",
    assessorEmail: "",
    description: "",
    overallRisk: "medium",
    legalBasis: "",
    retentionPeriod: "",
  });

  return (
    <div className="space-y-3">
      <div>
        <Label>Title *</Label>
        <Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Project Name</Label>
          <Input value={form.projectName} onChange={(e) => setForm({ ...form, projectName: e.target.value })} />
        </div>
        <div>
          <Label>Overall Risk</Label>
          <Select value={form.overallRisk} onValueChange={(v) => setForm({ ...form, overallRisk: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["negligible", "low", "medium", "high", "very_high"].map((r) => (
                <SelectItem key={r} value={r}>
                  {r.replace("_", " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Assessor Name</Label>
          <Input value={form.assessorName} onChange={(e) => setForm({ ...form, assessorName: e.target.value })} />
        </div>
        <div>
          <Label>Assessor Email</Label>
          <Input value={form.assessorEmail} onChange={(e) => setForm({ ...form, assessorEmail: e.target.value })} />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Legal Basis</Label>
          <Input
            value={form.legalBasis}
            onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
            placeholder="e.g., Legitimate interest, Consent"
          />
        </div>
        <div>
          <Label>Retention Period</Label>
          <Input
            value={form.retentionPeriod}
            onChange={(e) => setForm({ ...form, retentionPeriod: e.target.value })}
            placeholder="e.g., 2 years"
          />
        </div>
      </div>
      <div>
        <Label>Description</Label>
        <Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
      </div>
      <DialogFooter>
        <Button onClick={() => onSubmit(form)} disabled={!form.title || isPending}>
          {isPending ? "Creating..." : "Create PIA"}
        </Button>
      </DialogFooter>
    </div>
  );
}

// ── Consent Tab ─────────────────────────────────────────────────────

function ConsentTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showCreate, setShowCreate] = useState(false);
  const [search, setSearch] = useState("");

  const { data, isLoading } = useQuery<{ items: ConsentRecord[]; total: number }>({
    queryKey: ["/api/privacy-engineering/consent-records", search],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "50" });
      if (search) params.set("search", search);
      return apiFetch(`/api/privacy-engineering/consent-records?${params}`);
    },
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/privacy-engineering/consent-records", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/consent-records"] });
      toast({ title: "Consent record created" });
      setShowCreate(false);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const withdrawMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/privacy-engineering/consent-records/${id}/withdraw`, { method: "PATCH" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/consent-records"] });
      toast({ title: "Consent withdrawn" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by subject ID or email..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              Add Consent
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Record Consent</DialogTitle>
            </DialogHeader>
            <CreateConsentForm onSubmit={(body) => createMutation.mutate(body)} isPending={createMutation.isPending} />
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {data?.items.map((record) => (
            <Card key={record.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Users className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{record.dataSubjectId}</span>
                      {record.dataSubjectEmail && (
                        <span className="text-xs text-muted-foreground">{record.dataSubjectEmail}</span>
                      )}
                      <Badge variant="outline" className="text-xs">
                        {record.purpose}
                      </Badge>
                      {record.granted ? (
                        <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Granted
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20">
                          <XCircle className="h-3 w-3 mr-1" />
                          Withdrawn
                        </Badge>
                      )}
                      <Badge variant="secondary" className="text-xs">
                        {record.source}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                      {record.grantedAt && <span>Granted: {new Date(record.grantedAt).toLocaleDateString()}</span>}
                      {record.withdrawnAt && (
                        <span>Withdrawn: {new Date(record.withdrawnAt).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                  {record.granted && (
                    <Button variant="outline" size="sm" onClick={() => withdrawMutation.mutate(record.id)}>
                      <XCircle className="h-4 w-4 mr-1" />
                      Withdraw
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
          {data?.items.length === 0 && (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Users className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No consent records yet</p>
                <p className="text-xs mt-1">Record consent manually or connect OneTrust/Cookiebot for automatic sync</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function CreateConsentForm({
  onSubmit,
  isPending,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState({
    dataSubjectId: "",
    dataSubjectEmail: "",
    purpose: "marketing",
    granted: true,
    source: "manual",
    legalBasis: "",
  });

  return (
    <div className="space-y-3">
      <div>
        <Label>Data Subject ID *</Label>
        <Input
          value={form.dataSubjectId}
          onChange={(e) => setForm({ ...form, dataSubjectId: e.target.value })}
          placeholder="Unique identifier"
        />
      </div>
      <div>
        <Label>Email</Label>
        <Input value={form.dataSubjectEmail} onChange={(e) => setForm({ ...form, dataSubjectEmail: e.target.value })} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Purpose</Label>
          <Select value={form.purpose} onValueChange={(v) => setForm({ ...form, purpose: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[
                "marketing",
                "analytics",
                "personalization",
                "third_party_sharing",
                "profiling",
                "automated_decision",
                "research",
                "service_delivery",
                "legal_obligation",
              ].map((p) => (
                <SelectItem key={p} value={p}>
                  {p.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Source</Label>
          <Select value={form.source} onValueChange={(v) => setForm({ ...form, source: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="manual">Manual</SelectItem>
              <SelectItem value="onetrust">OneTrust</SelectItem>
              <SelectItem value="cookiebot">Cookiebot</SelectItem>
              <SelectItem value="api">API</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div>
        <Label>Legal Basis</Label>
        <Input
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          placeholder="e.g., GDPR Art. 6(1)(a)"
        />
      </div>
      <DialogFooter>
        <Button onClick={() => onSubmit(form)} disabled={!form.dataSubjectId || isPending}>
          {isPending ? "Creating..." : "Record Consent"}
        </Button>
      </DialogFooter>
    </div>
  );
}

// ── Cross-Border Tab ────────────────────────────────────────────────

function CrossBorderTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showRiskAssess, setShowRiskAssess] = useState(false);
  const [riskResult, setRiskResult] = useState<{
    riskLevel: string;
    reasons: string[];
    requiredMechanisms: string[];
  } | null>(null);

  const { data: alerts, isLoading } = useQuery<CrossBorderAlert[]>({
    queryKey: ["/api/privacy-engineering/cross-border-alerts"],
    queryFn: () => apiFetch("/api/privacy-engineering/cross-border-alerts"),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes: string }) =>
      apiFetch(`/api/privacy-engineering/cross-border-alerts/${id}/resolve`, {
        method: "PATCH",
        body: JSON.stringify({ resolutionNotes: notes }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/cross-border-alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/privacy-engineering/dashboard"] });
      toast({ title: "Alert resolved" });
    },
  });

  const riskMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/privacy-engineering/cross-border-risk", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (result: { riskLevel: string; reasons: string[]; requiredMechanisms: string[] }) => {
      setRiskResult(result);
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="flex-1">
          <h3 className="font-medium">Cross-Border Transfer Alerts</h3>
          <p className="text-xs text-muted-foreground">Alerts when PII moves across jurisdictional boundaries</p>
        </div>

        <Dialog
          open={showRiskAssess}
          onOpenChange={(open) => {
            setShowRiskAssess(open);
            if (!open) setRiskResult(null);
          }}
        >
          <DialogTrigger asChild>
            <Button variant="outline" size="sm">
              <Globe className="h-4 w-4 mr-1" />
              Risk Assessment
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Cross-Border Transfer Risk Assessment</DialogTitle>
            </DialogHeader>
            <CrossBorderRiskForm
              onSubmit={(body) => riskMutation.mutate(body)}
              isPending={riskMutation.isPending}
              result={riskResult}
            />
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {alerts?.map((alert) => (
            <Card key={alert.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-400" />
                      <Badge variant="secondary" className="text-xs">
                        {alert.sourceJurisdiction}
                      </Badge>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      <Badge variant="secondary" className="text-xs">
                        {alert.destinationJurisdiction}
                      </Badge>
                      {riskBadge(alert.riskLevel)}
                      {alert.resolvedAt ? (
                        <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                          Resolved
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/20">
                          <Clock className="h-3 w-3 mr-1" />
                          Action Required
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground mt-2">{alert.alertReason}</p>
                    {alert.legalMechanism && (
                      <p className="text-xs text-blue-400 mt-1">Required: {alert.legalMechanism}</p>
                    )}
                  </div>
                  {alert.requiresAction && !alert.resolvedAt && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        resolveMutation.mutate({ id: alert.id, notes: "Reviewed and mechanisms in place" })
                      }
                    >
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Resolve
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
          {(!alerts || alerts.length === 0) && (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Globe className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No cross-border transfer alerts</p>
                <p className="text-xs mt-1">Alerts are generated when data flows cross jurisdictional boundaries</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function CrossBorderRiskForm({
  onSubmit,
  isPending,
  result,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  isPending: boolean;
  result: { riskLevel: string; reasons: string[]; requiredMechanisms: string[] } | null;
}) {
  const [form, setForm] = useState({
    sourceJurisdiction: "EU",
    destinationJurisdiction: "US",
  });

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Source Jurisdiction</Label>
          <Select value={form.sourceJurisdiction} onValueChange={(v) => setForm({ ...form, sourceJurisdiction: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["EU", "US", "US-CA", "UK", "BR", "CA", "IN", "SG", "AU", "JP", "CN", "OTHER"].map((j) => (
                <SelectItem key={j} value={j}>
                  {j}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Destination Jurisdiction</Label>
          <Select
            value={form.destinationJurisdiction}
            onValueChange={(v) => setForm({ ...form, destinationJurisdiction: v })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {["EU", "US", "US-CA", "UK", "BR", "CA", "IN", "SG", "AU", "JP", "CN", "OTHER"].map((j) => (
                <SelectItem key={j} value={j}>
                  {j}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <Button onClick={() => onSubmit(form)} disabled={isPending}>
        {isPending ? "Assessing..." : "Assess Risk"}
      </Button>

      {result && (
        <div className="mt-4 p-4 border rounded-md space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">Risk Level:</span>
            {riskBadge(result.riskLevel)}
          </div>
          {result.reasons.length > 0 && (
            <div>
              <span className="text-sm font-medium">Reasons:</span>
              <ul className="mt-1 space-y-1">
                {result.reasons.map((r, i) => (
                  <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                    <AlertTriangle className="h-3 w-3 mt-1 text-amber-400 shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {result.requiredMechanisms.length > 0 && (
            <div>
              <span className="text-sm font-medium">Required Mechanisms:</span>
              <ul className="mt-1 space-y-1">
                {result.requiredMechanisms.map((m, i) => (
                  <li key={i} className="text-sm text-blue-400 flex items-center gap-2">
                    <Shield className="h-3 w-3 shrink-0" />
                    {m}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── DSAR Tab ────────────────────────────────────────────────────────

function DSARTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: dsarData, isLoading } = useQuery<{
    items: Array<{
      id: string;
      requestorEmail: string;
      requestType: string;
      status: string;
      dueDate: string | null;
      createdAt: string;
    }>;
    total: number;
  }>({
    queryKey: ["/api/dsar-requests"],
    queryFn: () => apiFetch("/api/dsar-requests"),
  });

  const generateMutation = useMutation({
    mutationFn: (dsarId: string) =>
      apiFetch(`/api/privacy-engineering/dsar-fulfillment/${dsarId}/generate`, { method: "POST" }),
    onSuccess: (result: { tasksGenerated: number }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/dsar-requests"] });
      toast({ title: `${result.tasksGenerated} fulfillment tasks generated` });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-medium">DSAR Fulfillment Automation</h3>
        <p className="text-xs text-muted-foreground">
          Automated Data Subject Access Request fulfillment across all connected systems
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {dsarData?.items?.map((dsar) => (
            <Card key={dsar.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Eye className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{dsar.requestorEmail}</span>
                      <Badge variant="outline" className="text-xs">
                        {dsar.requestType}
                      </Badge>
                      {statusBadge(dsar.status)}
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                      <span>Created: {new Date(dsar.createdAt).toLocaleDateString()}</span>
                      {dsar.dueDate && <span>Due: {new Date(dsar.dueDate).toLocaleDateString()}</span>}
                    </div>
                  </div>
                  {dsar.status === "pending" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => generateMutation.mutate(dsar.id)}
                      disabled={generateMutation.isPending}
                    >
                      <RefreshCw className="h-4 w-4 mr-1" />
                      Generate Tasks
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
          {(!dsarData?.items || dsarData.items.length === 0) && (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Eye className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No DSAR requests</p>
                <p className="text-xs mt-1">DSARs can be submitted via the compliance module or API</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
