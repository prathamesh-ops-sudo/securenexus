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
  Package,
  Shield,
  AlertTriangle,
  Search,
  Upload,
  Bug,
  Eye,
  FileCode,
  Container,
  ShieldAlert,
  ShieldCheck,
  GitBranch,
  Trash2,
  CheckCircle,
  XCircle,
  Info,
  BarChart3,
  Network,
  Plug,
  TrendingUp,
  Clock,
  Layers,
  Scale,
  Gauge,
} from "lucide-react";
import { EmptyState } from "@/components/empty-state";
import { useLocation } from "wouter";
import { TablePageSkeleton } from "@/components/page-skeleton";

// ─── Types ──────────────────────────────────────────────────────────────────

interface SbomArtifact {
  id: string;
  name: string;
  version: string | null;
  format: string;
  source: string | null;
  componentCount: number;
  vulnerabilityCount: number;
  licenseCount: number;
  status: string;
  createdAt: string;
  processedAt: string | null;
}

interface DependencyEntry {
  id: string;
  packageName: string;
  packageVersion: string | null;
  ecosystem: string;
  isDirect: boolean;
  license: string | null;
  publisher: string | null;
  isVulnerable: boolean;
  cveCount: number;
  maintainerScore: number | null;
  typosquatCandidate: boolean;
  typosquatSimilarTo: string | null;
  typosquatDistance: number | null;
  depth: number;
}

interface SupplyChainFinding {
  id: string;
  findingType: string;
  severity: string;
  status: string;
  title: string;
  description: string | null;
  packageName: string | null;
  packageVersion: string | null;
  ecosystem: string | null;
  cveId: string | null;
  cvssScore: number | null;
  fixedVersion: string | null;
  iacResourceType: string | null;
  iacFilePath: string | null;
  iacRule: string | null;
  containerImage: string | null;
  containerLayer: string | null;
  details: Record<string, unknown> | null;
  createdAt: string;
}

interface FindingsResponse {
  findings: SupplyChainFinding[];
  stats: {
    total: number;
    openCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    vulnCount: number;
    typosquatCount: number;
    maintainerCount: number;
    licenseCount: number;
    iacCount: number;
    containerCount: number;
  };
}

interface RiskSummary {
  findings: {
    total: number;
    vulnerabilities: number;
    typosquatting: number;
    maintainerRisk: number;
    licenseRisk: number;
    iacMisconfigurations: number;
    containerVulnerabilities: number;
    provenanceFailures: number;
  };
  severity: { critical: number; high: number; medium: number; low: number };
  status: { open: number; remediated: number };
  sboms: { count: number; totalComponents: number; totalVulnerabilities: number };
  dependencies: { total: number; vulnerable: number; typosquatCandidates: number; ecosystemCount: number };
}

interface DepsResponse {
  dependencies: DependencyEntry[];
  ecosystems: Array<{ ecosystem: string; pkg_count: string; vuln_count: string }>;
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
  remediated: "bg-green-500/20 text-green-400 border-green-500/30",
  false_positive: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const findingTypeLabels: Record<string, string> = {
  vulnerable_dependency: "Vulnerable Dependency",
  typosquatting: "Typosquatting",
  maintainer_risk: "Maintainer Risk",
  outdated_dependency: "Outdated Dependency",
  license_risk: "License Risk",
  iac_misconfiguration: "IaC Misconfiguration",
  container_vulnerability: "Container Vulnerability",
  provenance_failure: "Provenance Failure",
};

const findingTypeIcons: Record<string, typeof Bug> = {
  vulnerable_dependency: Bug,
  typosquatting: Eye,
  maintainer_risk: ShieldAlert,
  license_risk: FileCode,
  iac_misconfiguration: FileCode,
  container_vulnerability: Container,
  provenance_failure: ShieldAlert,
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

// ─── Component ──────────────────────────────────────────────────────────────

export default function SupplyChainPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("overview");
  const [findingTypeFilter, setFindingTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [ecosystemFilter, setEcosystemFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [uploadOpen, setUploadOpen] = useState(false);
  const [iacScanOpen, setIacScanOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<SupplyChainFinding | null>(null);
  const [depGraphView, setDepGraphView] = useState<"table" | "tree">("table");

  // Upload form state
  const [sbomName, setSbomName] = useState("");
  const [sbomVersion, setSbomVersion] = useState("");
  const [sbomFormat, setSbomFormat] = useState("cyclonedx");
  const [sbomSource, setSbomSource] = useState("");
  const [sbomJson, setSbomJson] = useState("");

  // IaC scan form state
  const [iacContent, setIacContent] = useState("");
  const [iacFilePath, setIacFilePath] = useState("");
  const [iacEcosystem, setIacEcosystem] = useState("terraform");

  // ── Queries ─────────────────────────────────────────────────────────────

  const { data: riskSummary, isLoading: summaryLoading } = useQuery<RiskSummary>({
    queryKey: ["/api/supply-chain/risk-summary"],
    queryFn: () => apiFetch("/api/supply-chain/risk-summary"),
  });

  const { data: sbomsData } = useQuery<{ sboms: SbomArtifact[]; total: number }>({
    queryKey: ["/api/supply-chain/sboms"],
    queryFn: () => apiFetch("/api/supply-chain/sboms"),
  });

  const { data: findingsData, isLoading: findingsLoading } = useQuery<FindingsResponse>({
    queryKey: [
      "/api/supply-chain/findings",
      findingTypeFilter,
      severityFilter,
      statusFilter,
      ecosystemFilter,
      searchQuery,
    ],
    queryFn: () => {
      const params = new URLSearchParams();
      if (findingTypeFilter !== "all") params.set("type", findingTypeFilter);
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (ecosystemFilter !== "all") params.set("ecosystem", ecosystemFilter);
      if (searchQuery) params.set("q", searchQuery);
      return apiFetch(`/api/supply-chain/findings?${params}`);
    },
  });

  const { data: depsData, isLoading: depsLoading } = useQuery<DepsResponse>({
    queryKey: ["/api/supply-chain/dependencies", ecosystemFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams();
      if (ecosystemFilter !== "all") params.set("ecosystem", ecosystemFilter);
      if (searchQuery) params.set("q", searchQuery);
      return apiFetch(`/api/supply-chain/dependencies?${params}`);
    },
    enabled: tab === "dependencies",
  });

  // SBOM Dashboard data
  const { data: sbomDashboardData } = useQuery<{
    sboms: Array<SbomArtifact & { freshnessDays: number; vulnExposure: number }>;
    totals: { uniqueDeps: number; totalVulns: number; avgFreshness: number; coveragePercent: number };
  }>({
    queryKey: ["/api/supply-chain/sbom-dashboard"],
    queryFn: () => apiFetch("/api/supply-chain/sbom-dashboard"),
    enabled: tab === "sbom-dashboard",
  });

  // Typosquatting candidates from dependency graph
  const { data: typosquatData } = useQuery<{
    candidates: Array<DependencyEntry & { downloadCount?: number; authorReputation?: number }>;
    whitelisted: string[];
  }>({
    queryKey: ["/api/supply-chain/typosquatting-review"],
    queryFn: () => apiFetch("/api/supply-chain/typosquatting-review"),
    enabled: tab === "typosquatting",
  });

  // ── Mutations ───────────────────────────────────────────────────────────

  const uploadSbom = useMutation({
    mutationFn: (data: { name: string; version: string; format: string; source: string; sbomData: unknown }) =>
      apiFetch("/api/supply-chain/sbom", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/supply-chain"] });
      toast({
        title: "SBOM processed",
        description: `${result.componentCount} components, ${result.findingsCount} findings detected`,
      });
      setUploadOpen(false);
      setSbomName("");
      setSbomVersion("");
      setSbomJson("");
      setSbomSource("");
    },
    onError: (err: Error) => {
      toast({ title: "SBOM upload failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteSbom = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/supply-chain/sboms/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/supply-chain"] });
      toast({ title: "SBOM deleted" });
    },
    onError: () => {
      toast({ title: "Failed to delete SBOM", variant: "destructive" });
    },
  });

  const updateFinding = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch(`/api/supply-chain/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/supply-chain/findings"] });
      toast({ title: "Finding updated" });
    },
    onError: () => {
      toast({ title: "Failed to update finding", variant: "destructive" });
    },
  });

  const scanIac = useMutation({
    mutationFn: (data: { content: string; filePath: string; ecosystem: string }) =>
      apiFetch("/api/supply-chain/iac-scan", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["/api/supply-chain"] });
      toast({
        title: "IaC scan complete",
        description: `${result.findingsCount} misconfiguration(s) found`,
      });
      setIacScanOpen(false);
      setIacContent("");
      setIacFilePath("");
    },
    onError: (err: Error) => {
      toast({ title: "IaC scan failed", description: err.message, variant: "destructive" });
    },
  });

  // Whitelist typosquat candidate
  const whitelistPackage = useMutation({
    mutationFn: (depId: string) => apiFetch(`/api/supply-chain/dependencies/${depId}/whitelist`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/supply-chain/typosquatting-review"] });
      queryClient.invalidateQueries({ queryKey: ["/api/supply-chain/dependencies"] });
      toast({ title: "Package whitelisted" });
    },
    onError: () => toast({ title: "Failed to whitelist", variant: "destructive" }),
  });

  const handleSbomUpload = () => {
    if (!sbomName.trim()) {
      toast({ title: "Name is required", variant: "destructive" });
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(sbomJson);
    } catch {
      toast({ title: "Invalid JSON", description: "SBOM data must be valid JSON", variant: "destructive" });
      return;
    }
    uploadSbom.mutate({
      name: sbomName.trim(),
      version: sbomVersion.trim(),
      format: sbomFormat,
      source: sbomSource.trim() || "manual_upload",
      sbomData: parsed,
    });
  };

  const handleIacScan = () => {
    if (!iacContent.trim() || !iacFilePath.trim()) {
      toast({ title: "Content and file path are required", variant: "destructive" });
      return;
    }
    scanIac.mutate({ content: iacContent, filePath: iacFilePath, ecosystem: iacEcosystem });
  };

  // ── Render ──────────────────────────────────────────────────────────────

  const stats = findingsData?.stats;
  const rs = riskSummary;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <GitBranch className="h-6 w-6 text-teal-400" />
            Supply Chain Security
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            SBOM ingestion, dependency graph analysis, vulnerability mapping, typosquatting detection
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="gap-1.5 border-zinc-700 hover:bg-zinc-800"
            onClick={() => setIacScanOpen(true)}
          >
            <FileCode className="h-4 w-4" />
            IaC Scan
          </Button>
          <Button className="gap-1.5 bg-teal-600 hover:bg-teal-700" onClick={() => setUploadOpen(true)}>
            <Upload className="h-4 w-4" />
            Upload SBOM
          </Button>
        </div>
      </div>

      {/* Risk Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-muted-foreground">SBOMs</div>
            <div className="text-xl font-semibold mt-0.5">{rs?.sboms.count ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-muted-foreground">Dependencies</div>
            <div className="text-xl font-semibold mt-0.5">{rs?.dependencies.total ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-red-400">Critical</div>
            <div className="text-xl font-semibold mt-0.5 text-red-400">{rs?.severity.critical ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-orange-400">High</div>
            <div className="text-xl font-semibold mt-0.5 text-orange-400">{rs?.severity.high ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-teal-400">Vulnerabilities</div>
            <div className="text-xl font-semibold mt-0.5 text-teal-400">{rs?.findings.vulnerabilities ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-purple-400">Typosquatting</div>
            <div className="text-xl font-semibold mt-0.5 text-purple-400">{rs?.findings.typosquatting ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-amber-400">License Risk</div>
            <div className="text-xl font-semibold mt-0.5 text-amber-400">{rs?.findings.licenseRisk ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3">
            <div className="text-[11px] text-green-400">Remediated</div>
            <div className="text-xl font-semibold mt-0.5 text-green-400">{rs?.status.remediated ?? 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="overview" className="gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="findings" className="gap-1.5">
            <Bug className="h-3.5 w-3.5" />
            Findings ({stats?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="dependencies" className="gap-1.5">
            <Network className="h-3.5 w-3.5" />
            Dependency Graph
          </TabsTrigger>
          <TabsTrigger value="sboms" className="gap-1.5">
            <Package className="h-3.5 w-3.5" />
            SBOMs ({sbomsData?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="sbom-dashboard" className="gap-1.5">
            <Gauge className="h-3.5 w-3.5" />
            SBOM Dashboard
          </TabsTrigger>
          <TabsTrigger value="dep-viz" className="gap-1.5">
            <Layers className="h-3.5 w-3.5" />
            Dep Tree
          </TabsTrigger>
          <TabsTrigger value="typosquatting" className="gap-1.5">
            <Eye className="h-3.5 w-3.5" />
            Typosquatting
          </TabsTrigger>
        </TabsList>

        {/* ────────────────── OVERVIEW TAB ────────────────── */}
        <TabsContent value="overview" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Finding Type Breakdown */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Finding Types</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {[
                  {
                    label: "Vulnerable Dependencies",
                    count: rs?.findings.vulnerabilities ?? 0,
                    color: "text-red-400",
                    icon: Bug,
                  },
                  {
                    label: "Typosquatting",
                    count: rs?.findings.typosquatting ?? 0,
                    color: "text-purple-400",
                    icon: Eye,
                  },
                  {
                    label: "Maintainer Risk",
                    count: rs?.findings.maintainerRisk ?? 0,
                    color: "text-orange-400",
                    icon: ShieldAlert,
                  },
                  {
                    label: "License Risk",
                    count: rs?.findings.licenseRisk ?? 0,
                    color: "text-amber-400",
                    icon: FileCode,
                  },
                  {
                    label: "IaC Misconfigurations",
                    count: rs?.findings.iacMisconfigurations ?? 0,
                    color: "text-blue-400",
                    icon: FileCode,
                  },
                  {
                    label: "Container Vulns",
                    count: rs?.findings.containerVulnerabilities ?? 0,
                    color: "text-cyan-400",
                    icon: Container,
                  },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between py-1.5">
                    <div className="flex items-center gap-2">
                      <item.icon className={`h-4 w-4 ${item.color}`} />
                      <span className="text-sm">{item.label}</span>
                    </div>
                    <span className={`text-sm font-semibold ${item.color}`}>{item.count}</span>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Ecosystem Distribution */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Ecosystem Distribution</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {rs?.dependencies.ecosystemCount === 0 ? (
                  <p className="text-sm text-muted-foreground py-4 text-center">
                    Upload an SBOM to see ecosystem breakdown
                  </p>
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Total Dependencies</span>
                      <span className="text-sm font-semibold">{rs?.dependencies.total ?? 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Vulnerable</span>
                      <span className="text-sm font-semibold text-red-400">{rs?.dependencies.vulnerable ?? 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Typosquat Candidates</span>
                      <span className="text-sm font-semibold text-purple-400">
                        {rs?.dependencies.typosquatCandidates ?? 0}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Ecosystems</span>
                      <span className="text-sm font-semibold">{rs?.dependencies.ecosystemCount ?? 0}</span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* SBOM Summary */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">SBOM Inventory</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Total SBOMs</span>
                  <span className="text-sm font-semibold">{rs?.sboms.count ?? 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Components Tracked</span>
                  <span className="text-sm font-semibold">{rs?.sboms.totalComponents ?? 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Known Vulnerabilities</span>
                  <span className="text-sm font-semibold text-red-400">{rs?.sboms.totalVulnerabilities ?? 0}</span>
                </div>
                <div className="pt-2 border-t border-zinc-800">
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full gap-1.5 border-zinc-700"
                    onClick={() => setUploadOpen(true)}
                  >
                    <Upload className="h-3.5 w-3.5" />
                    Upload SBOM
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Findings */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Recent Findings</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Type</TableHead>
                    <TableHead className="text-muted-foreground">Title</TableHead>
                    <TableHead className="text-muted-foreground">Severity</TableHead>
                    <TableHead className="text-muted-foreground">Package</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {!findingsData?.findings?.length ? (
                    <TableRow>
                      <TableCell colSpan={5}>
                        <EmptyState
                          icon={ShieldCheck}
                          title="No supply chain findings"
                          description="Upload a CycloneDX or SPDX SBOM to scan for vulnerable dependencies, license violations, and typosquatting risks."
                          action={{
                            label: "Upload SBOM",
                            icon: Upload,
                            onClick: () => setUploadOpen(true),
                          }}
                          compact
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    findingsData.findings.slice(0, 10).map((f) => {
                      const Icon = findingTypeIcons[f.findingType] || Bug;
                      return (
                        <TableRow
                          key={f.id}
                          className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                          onClick={() => setSelectedFinding(f)}
                        >
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="text-xs">{findingTypeLabels[f.findingType] || f.findingType}</span>
                            </div>
                          </TableCell>
                          <TableCell className="max-w-[300px] truncate text-sm">{f.title}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={severityColors[f.severity] || ""}>
                              {f.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-sm">
                            {f.packageName ? `${f.packageName}@${f.packageVersion || "?"}` : f.iacFilePath || "—"}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={statusColors[f.status] || ""}>
                              {f.status.replace("_", " ")}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────────────────── FINDINGS TAB ────────────────── */}
        <TabsContent value="findings" className="mt-4 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search CVE, package, title..."
                className="pl-9 bg-zinc-900/50 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={findingTypeFilter} onValueChange={setFindingTypeFilter}>
              <SelectTrigger className="w-[170px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Finding Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="vulnerable_dependency">Vulnerabilities</SelectItem>
                <SelectItem value="typosquatting">Typosquatting</SelectItem>
                <SelectItem value="maintainer_risk">Maintainer Risk</SelectItem>
                <SelectItem value="license_risk">License Risk</SelectItem>
                <SelectItem value="iac_misconfiguration">IaC Misconfig</SelectItem>
                <SelectItem value="container_vulnerability">Container Vuln</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[130px] bg-zinc-900/50 border-zinc-800">
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
              <SelectTrigger className="w-[140px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="acknowledged">Acknowledged</SelectItem>
                <SelectItem value="remediated">Remediated</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Type</TableHead>
                    <TableHead className="text-muted-foreground">Title</TableHead>
                    <TableHead className="text-muted-foreground">Severity</TableHead>
                    <TableHead className="text-muted-foreground">Package</TableHead>
                    <TableHead className="text-muted-foreground">CVE</TableHead>
                    <TableHead className="text-muted-foreground">CVSS</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingsLoading ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                        Loading findings...
                      </TableCell>
                    </TableRow>
                  ) : !findingsData?.findings?.length ? (
                    <TableRow>
                      <TableCell colSpan={8}>
                        <EmptyState
                          icon={ShieldCheck}
                          title="No supply chain findings"
                          description="Upload a CycloneDX or SPDX SBOM to scan for CVEs, license violations, and typosquatting. You can also run an IaC scan to detect misconfigurations."
                          action={{
                            label: "Upload SBOM",
                            icon: Upload,
                            onClick: () => setUploadOpen(true),
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    findingsData.findings.map((f) => {
                      const Icon = findingTypeIcons[f.findingType] || Bug;
                      return (
                        <TableRow
                          key={f.id}
                          className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                          onClick={() => setSelectedFinding(f)}
                        >
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="text-xs whitespace-nowrap">
                                {findingTypeLabels[f.findingType] || f.findingType}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="max-w-[250px] truncate text-sm">{f.title}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={severityColors[f.severity] || ""}>
                              {f.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {f.packageName ? `${f.packageName}@${f.packageVersion || "?"}` : "—"}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-blue-400">{f.cveId || "—"}</TableCell>
                          <TableCell>
                            {f.cvssScore !== null ? (
                              <span
                                className={
                                  f.cvssScore >= 9
                                    ? "text-red-400 font-semibold"
                                    : f.cvssScore >= 7
                                      ? "text-orange-400"
                                      : "text-yellow-400"
                                }
                              >
                                {f.cvssScore.toFixed(1)}
                              </span>
                            ) : (
                              "—"
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={statusColors[f.status] || ""}>
                              {f.status.replace("_", " ")}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex gap-1 justify-end" onClick={(e) => e.stopPropagation()}>
                              {f.status === "open" && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="h-7 text-xs border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
                                  onClick={() => updateFinding.mutate({ id: f.id, status: "acknowledged" })}
                                >
                                  Ack
                                </Button>
                              )}
                              {(f.status === "open" || f.status === "acknowledged") && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="h-7 text-xs border-green-500/30 text-green-400 hover:bg-green-500/10"
                                  onClick={() => updateFinding.mutate({ id: f.id, status: "remediated" })}
                                >
                                  Fix
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────────────────── DEPENDENCY GRAPH TAB ────────────────── */}
        <TabsContent value="dependencies" className="mt-4 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search package name..."
                className="pl-9 bg-zinc-900/50 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={ecosystemFilter} onValueChange={setEcosystemFilter}>
              <SelectTrigger className="w-[140px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Ecosystem" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Ecosystems</SelectItem>
                <SelectItem value="npm">npm</SelectItem>
                <SelectItem value="pypi">PyPI</SelectItem>
                <SelectItem value="rubygems">RubyGems</SelectItem>
                <SelectItem value="nuget">NuGet</SelectItem>
                <SelectItem value="maven">Maven</SelectItem>
                <SelectItem value="cargo">Cargo</SelectItem>
                <SelectItem value="go">Go</SelectItem>
                <SelectItem value="docker">Docker</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Ecosystem Stats */}
          {depsData?.ecosystems && depsData.ecosystems.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
              {depsData.ecosystems.map((eco) => (
                <Card key={eco.ecosystem} className="bg-zinc-900/50 border-zinc-800">
                  <CardContent className="p-3">
                    <div className="text-xs text-muted-foreground capitalize">{eco.ecosystem}</div>
                    <div className="text-lg font-semibold mt-0.5">{eco.pkg_count}</div>
                    {parseInt(eco.vuln_count) > 0 && (
                      <div className="text-xs text-red-400">{eco.vuln_count} vulnerable</div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Package</TableHead>
                    <TableHead className="text-muted-foreground">Version</TableHead>
                    <TableHead className="text-muted-foreground">Ecosystem</TableHead>
                    <TableHead className="text-muted-foreground">Depth</TableHead>
                    <TableHead className="text-muted-foreground">License</TableHead>
                    <TableHead className="text-muted-foreground">Vulnerable</TableHead>
                    <TableHead className="text-muted-foreground">Maintainer Score</TableHead>
                    <TableHead className="text-muted-foreground">Typosquat</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {depsLoading ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                        Loading dependencies...
                      </TableCell>
                    </TableRow>
                  ) : !depsData?.dependencies?.length ? (
                    <TableRow>
                      <TableCell colSpan={8}>
                        <EmptyState
                          icon={Network}
                          title="No dependencies tracked"
                          description="The dependency graph is populated from uploaded SBOMs. Upload a CycloneDX or SPDX JSON file to visualize your software supply chain."
                          action={{
                            label: "Upload SBOM",
                            icon: Upload,
                            onClick: () => setUploadOpen(true),
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    depsData.dependencies.map((d) => (
                      <TableRow key={d.id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell className="font-medium">{d.packageName}</TableCell>
                        <TableCell className="font-mono text-sm">{d.packageVersion || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-zinc-800/50 border-zinc-700">
                            {d.ecosystem}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className={d.isDirect ? "text-teal-400" : "text-muted-foreground"}>
                            {d.isDirect ? "Direct" : `Depth ${d.depth}`}
                          </span>
                        </TableCell>
                        <TableCell className="text-sm">{d.license || "—"}</TableCell>
                        <TableCell>
                          {d.isVulnerable ? (
                            <div className="flex items-center gap-1">
                              <XCircle className="h-3.5 w-3.5 text-red-400" />
                              <span className="text-xs text-red-400">{d.cveCount} CVE(s)</span>
                            </div>
                          ) : (
                            <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                          )}
                        </TableCell>
                        <TableCell>
                          {d.maintainerScore !== null ? (
                            <span
                              className={
                                d.maintainerScore >= 70
                                  ? "text-green-400"
                                  : d.maintainerScore >= 40
                                    ? "text-yellow-400"
                                    : "text-red-400"
                              }
                            >
                              {d.maintainerScore}/100
                            </span>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell>
                          {d.typosquatCandidate ? (
                            <div className="flex items-center gap-1">
                              <AlertTriangle className="h-3.5 w-3.5 text-purple-400" />
                              <span className="text-xs text-purple-400">~{d.typosquatSimilarTo}</span>
                            </div>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ────────────────── SBOMS TAB ────────────────── */}
        <TabsContent value="sboms" className="mt-4 space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Name</TableHead>
                    <TableHead className="text-muted-foreground">Version</TableHead>
                    <TableHead className="text-muted-foreground">Format</TableHead>
                    <TableHead className="text-muted-foreground">Source</TableHead>
                    <TableHead className="text-muted-foreground">Components</TableHead>
                    <TableHead className="text-muted-foreground">Vulns</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                    <TableHead className="text-muted-foreground">Uploaded</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {!sbomsData?.sboms?.length ? (
                    <TableRow>
                      <TableCell colSpan={9}>
                        <EmptyState
                          icon={Package}
                          title="No SBOMs uploaded"
                          description="Upload a CycloneDX or SPDX JSON file to inventory your software components, detect vulnerable dependencies, and monitor license compliance."
                          action={{
                            label: "Upload SBOM",
                            icon: Upload,
                            onClick: () => setUploadOpen(true),
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    sbomsData.sboms.map((s) => (
                      <TableRow key={s.id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell className="font-medium">{s.name}</TableCell>
                        <TableCell className="font-mono text-sm">{s.version || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-zinc-800/50 border-zinc-700 uppercase text-xs">
                            {s.format}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">{s.source || "—"}</TableCell>
                        <TableCell className="font-semibold">{s.componentCount}</TableCell>
                        <TableCell>
                          {s.vulnerabilityCount > 0 ? (
                            <span className="text-red-400 font-semibold">{s.vulnerabilityCount}</span>
                          ) : (
                            <span className="text-green-400">0</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              s.status === "completed"
                                ? "bg-green-500/20 text-green-400 border-green-500/30"
                                : s.status === "failed"
                                  ? "bg-red-500/20 text-red-400 border-red-500/30"
                                  : "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                            }
                          >
                            {s.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(s.createdAt).toLocaleDateString()}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 w-7 p-0 text-red-400 hover:bg-red-500/10"
                            onClick={() => deleteSbom.mutate(s.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── 52.1: Dependency Tree Visualization ── */}
        <TabsContent value="dep-viz" className="mt-4 space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Layers className="h-4 w-4 text-teal-400" />
                Dependency Tree Visualization
              </CardTitle>
              <div className="flex items-center gap-3 text-[10px] mt-1">
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-green-500" /> Clean
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-red-500" /> Vulnerable
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-yellow-500" /> License Risk
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-purple-500" /> Typosquat
                </span>
              </div>
            </CardHeader>
            <CardContent className="space-y-0.5 max-h-[500px] overflow-y-auto">
              {!depsData?.dependencies?.length ? (
                <EmptyState
                  icon={Layers}
                  title="No dependencies found"
                  description="Upload an SBOM to visualize your dependency tree with vulnerability and license risk highlighting."
                  action={{ label: "Upload SBOM", icon: Upload, onClick: () => setUploadOpen(true) }}
                  compact
                />
              ) : (
                depsData.dependencies.slice(0, 120).map((d) => {
                  const isLicenseRisk =
                    d.license != null &&
                    ["GPL", "AGPL", "SSPL"].some((l) => (d.license ?? "").toUpperCase().includes(l));
                  const dotColor = d.isVulnerable
                    ? "bg-red-500"
                    : d.typosquatCandidate
                      ? "bg-purple-500"
                      : isLicenseRisk
                        ? "bg-yellow-500"
                        : "bg-green-500/60";
                  const textColor = d.isVulnerable
                    ? "text-red-400"
                    : d.typosquatCandidate
                      ? "text-purple-400"
                      : isLicenseRisk
                        ? "text-yellow-400"
                        : "";
                  return (
                    <div
                      key={d.id}
                      className="flex items-center gap-2 py-1 px-2 rounded hover:bg-zinc-800/50"
                      style={{ paddingLeft: `${(d.depth || 0) * 20 + 8}px` }}
                    >
                      <span className={`w-2 h-2 rounded-full shrink-0 ${dotColor}`} />
                      <span className={`font-mono text-xs ${textColor}`}>
                        {d.packageName}
                        <span className="text-muted-foreground">@{d.packageVersion || "?"}</span>
                      </span>
                      {d.isDirect ? (
                        <Badge
                          variant="outline"
                          className="text-[10px] h-4 bg-teal-500/10 text-teal-400 border-teal-500/30"
                        >
                          direct
                        </Badge>
                      ) : null}
                      {d.isVulnerable ? (
                        <span className="text-[10px] text-red-400 ml-auto">{d.cveCount} CVE</span>
                      ) : null}
                      {d.typosquatCandidate && d.typosquatSimilarTo ? (
                        <span className="text-[10px] text-purple-400 ml-1">~{d.typosquatSimilarTo}</span>
                      ) : null}
                      {d.license ? (
                        <span
                          className={`text-[10px] ${isLicenseRisk ? "text-yellow-400" : "text-muted-foreground"} ${!d.isVulnerable ? "ml-auto" : ""}`}
                        >
                          {d.license}
                        </span>
                      ) : null}
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── 52.2: SBOM Dashboard ── */}
        <TabsContent value="sbom-dashboard" className="mt-4 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3">
                <div className="text-[11px] text-muted-foreground">Applications with SBOM</div>
                <div className="text-xl font-semibold mt-0.5">
                  {sbomDashboardData?.sboms?.length ?? sbomsData?.total ?? 0}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3">
                <div className="text-[11px] text-muted-foreground">Unique Dependencies</div>
                <div className="text-xl font-semibold mt-0.5">
                  {sbomDashboardData?.totals?.uniqueDeps ?? riskSummary?.dependencies.total ?? 0}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3">
                <div className="text-[11px] text-red-400">Total Vulnerabilities</div>
                <div className="text-xl font-semibold mt-0.5 text-red-400">
                  {sbomDashboardData?.totals?.totalVulns ?? riskSummary?.sboms.totalVulnerabilities ?? 0}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-3">
                <div className="text-[11px] text-teal-400">Avg Freshness</div>
                <div className="text-xl font-semibold mt-0.5 text-teal-400">
                  {sbomDashboardData?.totals?.avgFreshness ?? 0}d
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Gauge className="h-4 w-4 text-teal-400" />
                SBOM Coverage by Application
              </CardTitle>
            </CardHeader>
            <CardContent>
              {!sbomsData?.sboms?.length ? (
                <EmptyState
                  icon={Package}
                  title="No SBOMs uploaded"
                  description="Upload SBOMs to see application-level coverage, freshness, and vulnerability exposure."
                  action={{ label: "Upload SBOM", icon: Upload, onClick: () => setUploadOpen(true) }}
                  compact
                />
              ) : (
                <div className="space-y-3">
                  {(sbomDashboardData?.sboms ?? sbomsData?.sboms ?? []).map(
                    (s: SbomArtifact & { freshnessDays?: number; vulnExposure?: number }) => {
                      const freshness =
                        s.freshnessDays ?? Math.floor((Date.now() - new Date(s.createdAt).getTime()) / 86400000);
                      const vulnExposure =
                        s.vulnExposure ??
                        (s.componentCount > 0 ? Math.round((s.vulnerabilityCount / s.componentCount) * 100) : 0);
                      const freshColor =
                        freshness <= 7 ? "text-green-400" : freshness <= 30 ? "text-yellow-400" : "text-red-400";
                      return (
                        <div key={s.id} className="p-3 bg-zinc-800/30 rounded-lg border border-zinc-800">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Package className="h-4 w-4 text-teal-400" />
                              <span className="font-medium text-sm">{s.name}</span>
                              {s.version ? <span className="text-xs text-muted-foreground">v{s.version}</span> : null}
                              <Badge variant="outline" className="text-[10px] uppercase">
                                {s.format}
                              </Badge>
                            </div>
                            <Badge
                              variant="outline"
                              className={
                                s.status === "completed"
                                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                                  : "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                              }
                            >
                              {s.status}
                            </Badge>
                          </div>
                          <div className="grid grid-cols-4 gap-4 text-xs">
                            <div>
                              <span className="text-muted-foreground">Components</span>
                              <p className="font-semibold mt-0.5">{s.componentCount}</p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Vulnerabilities</span>
                              <p
                                className={`font-semibold mt-0.5 ${s.vulnerabilityCount > 0 ? "text-red-400" : "text-green-400"}`}
                              >
                                {s.vulnerabilityCount}
                              </p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Freshness</span>
                              <p className={`font-semibold mt-0.5 flex items-center gap-1 ${freshColor}`}>
                                <Clock className="h-3 w-3" />
                                {freshness}d ago
                              </p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Vuln Exposure</span>
                              <div className="flex items-center gap-1 mt-0.5">
                                <div className="w-16 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${vulnExposure > 20 ? "bg-red-500" : vulnExposure > 5 ? "bg-yellow-500" : "bg-green-500"}`}
                                    style={{ width: `${Math.min(vulnExposure, 100)}%` }}
                                  />
                                </div>
                                <span className="font-semibold">{vulnExposure}%</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    },
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── 52.3: Typosquatting Alert Review ── */}
        <TabsContent value="typosquatting" className="mt-4 space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Eye className="h-4 w-4 text-purple-400" />
                Typosquatting Detection Review
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Suspicious Package</TableHead>
                    <TableHead className="text-muted-foreground">Likely Legitimate</TableHead>
                    <TableHead className="text-muted-foreground">Similarity</TableHead>
                    <TableHead className="text-muted-foreground">Ecosystem</TableHead>
                    <TableHead className="text-muted-foreground">Maintainer Score</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(() => {
                    const candidates =
                      typosquatData?.candidates ??
                      depsData?.dependencies?.filter((d: DependencyEntry) => d.typosquatCandidate) ??
                      [];
                    if (candidates.length === 0) {
                      return (
                        <TableRow>
                          <TableCell colSpan={7}>
                            <EmptyState
                              icon={ShieldCheck}
                              title="No typosquatting candidates"
                              description="No suspicious package names detected in your dependency graph."
                              compact
                            />
                          </TableCell>
                        </TableRow>
                      );
                    }
                    return candidates.map(
                      (d: DependencyEntry & { downloadCount?: number; authorReputation?: number }) => {
                        const distance = d.typosquatDistance ?? 1;
                        const similarity = Math.max(
                          0,
                          Math.round(
                            (1 - distance / Math.max((d.typosquatSimilarTo || "").length, d.packageName.length)) * 100,
                          ),
                        );
                        return (
                          <TableRow key={d.id} className="border-zinc-800 hover:bg-zinc-800/50">
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <AlertTriangle className="h-3.5 w-3.5 text-purple-400" />
                                <span className="font-mono text-sm font-medium text-purple-400">{d.packageName}</span>
                                <span className="text-xs text-muted-foreground">@{d.packageVersion || "?"}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className="font-mono text-sm text-green-400">
                                {d.typosquatSimilarTo || "\u2014"}
                              </span>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-1">
                                <div className="w-12 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${similarity >= 90 ? "bg-red-500" : similarity >= 70 ? "bg-orange-500" : "bg-yellow-500"}`}
                                    style={{ width: `${similarity}%` }}
                                  />
                                </div>
                                <span className="text-xs font-semibold">{similarity}%</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className="bg-zinc-800/50 border-zinc-700 text-xs">
                                {d.ecosystem}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {d.maintainerScore !== null && d.maintainerScore !== undefined ? (
                                <span
                                  className={
                                    d.maintainerScore >= 70
                                      ? "text-green-400"
                                      : d.maintainerScore >= 40
                                        ? "text-yellow-400"
                                        : "text-red-400"
                                  }
                                >
                                  {d.maintainerScore}/100
                                </span>
                              ) : (
                                "\u2014"
                              )}
                            </TableCell>
                            <TableCell>
                              {d.isVulnerable ? (
                                <Badge
                                  variant="outline"
                                  className="bg-red-500/20 text-red-400 border-red-500/30 text-xs"
                                >
                                  {d.cveCount} CVE
                                </Badge>
                              ) : (
                                <Badge
                                  variant="outline"
                                  className="bg-purple-500/20 text-purple-400 border-purple-500/30 text-xs"
                                >
                                  Suspect
                                </Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs border-green-500/30 text-green-400 hover:bg-green-500/10"
                                onClick={() => whitelistPackage.mutate(d.id)}
                                disabled={whitelistPackage.isPending}
                              >
                                <CheckCircle className="h-3 w-3 mr-1" /> Whitelist
                              </Button>
                            </TableCell>
                          </TableRow>
                        );
                      },
                    );
                  })()}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ────────────────── UPLOAD SBOM DIALOG ────────────────── */}
      <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
        <DialogContent className="max-w-2xl bg-zinc-950 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Upload className="h-5 w-5 text-teal-400" />
              Upload SBOM
            </DialogTitle>
            <DialogDescription>Upload a CycloneDX or SPDX JSON document to analyze dependencies</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Project Name *</Label>
                <Input
                  placeholder="e.g. my-api-service"
                  className="bg-zinc-900/50 border-zinc-800"
                  value={sbomName}
                  onChange={(e) => setSbomName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Version</Label>
                <Input
                  placeholder="e.g. 1.2.3"
                  className="bg-zinc-900/50 border-zinc-800"
                  value={sbomVersion}
                  onChange={(e) => setSbomVersion(e.target.value)}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Format *</Label>
                <Select value={sbomFormat} onValueChange={setSbomFormat}>
                  <SelectTrigger className="bg-zinc-900/50 border-zinc-800">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="cyclonedx">CycloneDX</SelectItem>
                    <SelectItem value="spdx">SPDX</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Source</Label>
                <Input
                  placeholder="e.g. CI/CD pipeline, manual"
                  className="bg-zinc-900/50 border-zinc-800"
                  value={sbomSource}
                  onChange={(e) => setSbomSource(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>SBOM JSON *</Label>
              <Textarea
                placeholder="Paste CycloneDX or SPDX JSON here..."
                className="bg-zinc-900/50 border-zinc-800 font-mono text-xs min-h-[200px]"
                value={sbomJson}
                onChange={(e) => setSbomJson(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" className="border-zinc-700" onClick={() => setUploadOpen(false)}>
                Cancel
              </Button>
              <Button
                className="bg-teal-600 hover:bg-teal-700 gap-1.5"
                onClick={handleSbomUpload}
                disabled={uploadSbom.isPending}
              >
                {uploadSbom.isPending ? "Processing..." : "Upload & Analyze"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* ────────────────── IAC SCAN DIALOG ────────────────── */}
      <Dialog open={iacScanOpen} onOpenChange={setIacScanOpen}>
        <DialogContent className="max-w-2xl bg-zinc-950 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5 text-blue-400" />
              IaC Misconfiguration Scan
            </DialogTitle>
            <DialogDescription>
              Scan Terraform, Helm charts, K8s YAML, or Dockerfiles for security misconfigurations
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Ecosystem *</Label>
                <Select value={iacEcosystem} onValueChange={setIacEcosystem}>
                  <SelectTrigger className="bg-zinc-900/50 border-zinc-800">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="terraform">Terraform</SelectItem>
                    <SelectItem value="helm">Helm</SelectItem>
                    <SelectItem value="kubernetes">Kubernetes YAML</SelectItem>
                    <SelectItem value="docker">Dockerfile</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>File Path *</Label>
                <Input
                  placeholder="e.g. main.tf, deployment.yaml"
                  className="bg-zinc-900/50 border-zinc-800"
                  value={iacFilePath}
                  onChange={(e) => setIacFilePath(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>IaC Content *</Label>
              <Textarea
                placeholder="Paste Terraform HCL, Helm values, K8s YAML, or Dockerfile here..."
                className="bg-zinc-900/50 border-zinc-800 font-mono text-xs min-h-[200px]"
                value={iacContent}
                onChange={(e) => setIacContent(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" className="border-zinc-700" onClick={() => setIacScanOpen(false)}>
                Cancel
              </Button>
              <Button
                className="bg-blue-600 hover:bg-blue-700 gap-1.5"
                onClick={handleIacScan}
                disabled={scanIac.isPending}
              >
                {scanIac.isPending ? "Scanning..." : "Scan for Misconfigurations"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* ────────────────── FINDING DETAIL DIALOG ────────────────── */}
      <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
        <DialogContent className="max-w-xl bg-zinc-950 border-zinc-800">
          {selectedFinding && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-base">
                  <Badge variant="outline" className={severityColors[selectedFinding.severity] || ""}>
                    {selectedFinding.severity}
                  </Badge>
                  {findingTypeLabels[selectedFinding.findingType] || selectedFinding.findingType}
                </DialogTitle>
                <DialogDescription className="sr-only">Finding details</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 mt-2">
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">Title</h4>
                  <p className="text-sm">{selectedFinding.title}</p>
                </div>
                {selectedFinding.description && (
                  <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-1">Description</h4>
                    <p className="text-sm text-muted-foreground">{selectedFinding.description}</p>
                  </div>
                )}
                <div className="grid grid-cols-2 gap-4">
                  {selectedFinding.packageName && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">Package</h4>
                      <p className="font-mono text-sm">
                        {selectedFinding.packageName}@{selectedFinding.packageVersion || "?"}
                      </p>
                    </div>
                  )}
                  {selectedFinding.ecosystem && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">Ecosystem</h4>
                      <p className="text-sm capitalize">{selectedFinding.ecosystem}</p>
                    </div>
                  )}
                  {selectedFinding.cveId && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">CVE</h4>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-sm text-blue-400 hover:underline"
                      >
                        {selectedFinding.cveId}
                      </a>
                    </div>
                  )}
                  {selectedFinding.cvssScore !== null && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">CVSS Score</h4>
                      <p className="text-sm font-semibold">{selectedFinding.cvssScore.toFixed(1)}</p>
                    </div>
                  )}
                  {selectedFinding.fixedVersion && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">Fixed In</h4>
                      <p className="font-mono text-sm text-green-400">{selectedFinding.fixedVersion}</p>
                    </div>
                  )}
                  {selectedFinding.iacFilePath && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">File</h4>
                      <p className="font-mono text-sm">{selectedFinding.iacFilePath}</p>
                    </div>
                  )}
                  {selectedFinding.iacRule && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">Rule ID</h4>
                      <p className="font-mono text-sm">{selectedFinding.iacRule}</p>
                    </div>
                  )}
                  {selectedFinding.containerImage && (
                    <div>
                      <h4 className="text-xs text-muted-foreground">Container Image</h4>
                      <p className="font-mono text-sm">{selectedFinding.containerImage}</p>
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-zinc-800">
                  <span className="text-xs text-muted-foreground">Status:</span>
                  <Badge variant="outline" className={statusColors[selectedFinding.status] || ""}>
                    {selectedFinding.status.replace("_", " ")}
                  </Badge>
                  <div className="flex-1" />
                  {selectedFinding.status === "open" && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs border-yellow-500/30 text-yellow-400"
                      onClick={() => {
                        updateFinding.mutate({ id: selectedFinding.id, status: "acknowledged" });
                        setSelectedFinding(null);
                      }}
                    >
                      Acknowledge
                    </Button>
                  )}
                  {(selectedFinding.status === "open" || selectedFinding.status === "acknowledged") && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs border-green-500/30 text-green-400"
                      onClick={() => {
                        updateFinding.mutate({ id: selectedFinding.id, status: "remediated" });
                        setSelectedFinding(null);
                      }}
                    >
                      Mark Remediated
                    </Button>
                  )}
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
