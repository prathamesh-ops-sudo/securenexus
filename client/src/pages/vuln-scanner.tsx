import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  Scan,
  Shield,
  AlertTriangle,
  CheckCircle,
  Search,
  Package,
  Bug,
  ShieldCheck,
  Clock,
  Filter,
  Target,
  Plus,
  Trash2,
  Calendar,
  ArrowUpDown,
  ExternalLink,
  GitCompare,
  X,
  Settings,
  Wrench,
  Globe,
} from "lucide-react";
import { TablePageSkeleton } from "@/components/page-skeleton";
import { apiRequest } from "@/lib/queryClient";
import { Skeleton } from "@/components/ui/skeleton";

interface VulnFinding {
  id: string;
  cveId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: string;
  cvssScore: number | null;
  description: string | null;
  status: string;
  sensorId: string | null;
  source: string;
  cvssVector: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
  exploitAvailable: boolean | null;
  kevDateAdded: string | null;
  matchedCpe: string | null;
  matchedVersionRange: Record<string, unknown> | null;
  matchSource: string | null;
  advisoryId: string | null;
  findingConfidence: string | null;
  findingBasis: string | null;
  acknowledgedBy: string | null;
  acknowledgedAt: string | null;
  remediatedBy: string | null;
  remediatedAt: string | null;
  createdAt: string;
}

interface VulnPackage {
  id: string;
  packageManager: string;
  packageName: string;
  installedVersion: string;
  isVulnerable: boolean;
  cveCount: number;
  sensorId: string;
  reportedAt: string;
}

interface FindingsResponse {
  findings: VulnFinding[];
  stats: {
    total: number;
    openCount: number;
    acknowledgedCount: number;
    remediatedCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}

interface PackagesResponse {
  packages: VulnPackage[];
  stats: {
    total: number;
    vulnerableCount: number;
    cleanCount: number;
    hostCount: number;
  };
}

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  none: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const statusColors: Record<string, string> = {
  open: "bg-red-500/20 text-red-400 border-red-500/30",
  acknowledged: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  remediated: "bg-green-500/20 text-green-400 border-green-500/30",
  false_positive: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const method = options?.method ?? "GET";
  const body = options?.body ? JSON.parse(String(options.body)) : undefined;
  const response = await apiRequest(method, url, body);
  return (await response.json()) as T;
}

export default function VulnScannerPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("findings");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<VulnFinding | null>(null);

  const { data: findingsData, isLoading: findingsLoading } = useQuery<FindingsResponse>({
    queryKey: ["/api/native/vuln/findings", severityFilter, statusFilter, sourceFilter, searchQuery],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (sourceFilter !== "all") params.set("source", sourceFilter);
      if (searchQuery) params.set("q", searchQuery);
      const response = await apiFetch<{ findings: VulnFinding[]; stats: FindingsResponse["stats"] }>(
        `/api/native/vuln/findings?${params}`,
      );
      response.findings.sort((left, right) => {
        const leftScore =
          (left.cvssScore ?? 0) * 10 + (left.epssScore ?? 0) * 100 + (left.exploitAvailable === true ? 100 : 0);
        const rightScore =
          (right.cvssScore ?? 0) * 10 + (right.epssScore ?? 0) * 100 + (right.exploitAvailable === true ? 100 : 0);
        return rightScore - leftScore;
      });
      return response;
    },
  });

  const { data: packagesData, isLoading: packagesLoading } = useQuery<PackagesResponse>({
    queryKey: ["/api/native/vuln/packages"],
    queryFn: () => apiFetch("/api/native/vuln/packages"),
  });

  const updateFinding = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch(`/api/native/vuln/findings/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/findings"] });
      toast({ title: "Finding updated" });
    },
    onError: () => {
      toast({ title: "Failed to update finding", variant: "destructive" });
    },
  });

  const stats = findingsData?.stats;
  const pkgStats = packagesData?.stats;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Scan className="h-6 w-6 text-teal-400" />
            Native Vulnerability Scanner
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Agent-reported package inventory matched against live OSV and NVD vulnerability evidence
          </p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Total Findings</div>
            <div className="text-2xl font-semibold mt-1">{stats?.total ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-red-400">Critical</div>
            <div className="text-2xl font-semibold mt-1 text-red-400">{stats?.criticalCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-orange-400">High</div>
            <div className="text-2xl font-semibold mt-1 text-orange-400">{stats?.highCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-yellow-400">Open</div>
            <div className="text-2xl font-semibold mt-1 text-yellow-400">{stats?.openCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-green-400">Remediated</div>
            <div className="text-2xl font-semibold mt-1 text-green-400">{stats?.remediatedCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Packages</div>
            <div className="text-2xl font-semibold mt-1">{pkgStats?.total ?? 0}</div>
            <div className="text-xs text-muted-foreground">{pkgStats?.vulnerableCount ?? 0} vulnerable</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="findings" className="gap-1.5">
            <Bug className="h-3.5 w-3.5" />
            Findings ({stats?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="packages" className="gap-1.5">
            <Package className="h-3.5 w-3.5" />
            Package Inventory ({pkgStats?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="scan-targets" className="gap-1.5">
            <Target className="h-3.5 w-3.5" />
            Scan Targets
          </TabsTrigger>
          <TabsTrigger value="scheduling" className="gap-1.5">
            <Calendar className="h-3.5 w-3.5" />
            Scheduling
          </TabsTrigger>
          <TabsTrigger value="comparison" className="gap-1.5">
            <GitCompare className="h-3.5 w-3.5" />
            Comparison
          </TabsTrigger>
        </TabsList>

        {/* FINDINGS TAB */}
        <TabsContent value="findings" className="mt-4 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search CVE ID or package name..."
                className="pl-9 bg-zinc-900/50 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[140px] bg-zinc-900/50 border-zinc-800">
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
              <SelectTrigger className="w-[150px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="acknowledged">Acknowledged</SelectItem>
                <SelectItem value="remediated">Remediated</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sourceFilter} onValueChange={setSourceFilter}>
              <SelectTrigger className="w-[160px] bg-zinc-900/50 border-zinc-800">
                <Filter className="h-3.5 w-3.5 mr-1" />
                <SelectValue placeholder="Source" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sources</SelectItem>
                <SelectItem value="native_sensor">Native Sensor</SelectItem>
                <SelectItem value="sbom">SBOM</SelectItem>
                <SelectItem value="connector">Connector</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">CVE ID</TableHead>
                    <TableHead className="text-muted-foreground">Package</TableHead>
                    <TableHead className="text-muted-foreground">Installed</TableHead>
                    <TableHead className="text-muted-foreground">Fixed</TableHead>
                    <TableHead className="text-muted-foreground">Severity</TableHead>
                    <TableHead className="text-muted-foreground">CVSS</TableHead>
                    <TableHead className="text-muted-foreground">Prioritization inputs</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingsLoading ? (
                    <>
                      {[1, 2, 3].map((row) => (
                        <TableRow key={row}>
                          <TableCell colSpan={9}>
                            <Skeleton className="h-6 w-full" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </>
                  ) : !findingsData?.findings?.length ? (
                    <TableRow>
                      <TableCell colSpan={9} className="text-center py-12">
                        <div className="flex flex-col items-center gap-2">
                          <ShieldCheck className="h-10 w-10 text-green-400/50" />
                          <p className="text-muted-foreground">
                            {pkgStats?.total === 0
                              ? "no package inventory yet — install an agent"
                              : "No vulnerability findings"}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {pkgStats?.total === 0
                              ? "Findings will appear after an authenticated agent reports installed packages."
                              : "The synchronized catalogue has no applicable findings for this inventory."}
                          </p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    findingsData.findings.map((f) => (
                      <TableRow
                        key={f.id}
                        className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                        onClick={() => setSelectedFinding(f)}
                      >
                        <TableCell className="font-mono text-sm text-blue-400">{f.cveId}</TableCell>
                        <TableCell className="font-medium">{f.packageName}</TableCell>
                        <TableCell className="font-mono text-sm">{f.installedVersion}</TableCell>
                        <TableCell className="font-mono text-sm text-green-400">{f.fixedVersion || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={severityColors[f.severity] || ""}>
                            {f.severity}
                          </Badge>
                        </TableCell>
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
                          <div className="flex flex-wrap gap-1">
                            <Badge variant="outline" className="text-[10px]">
                              CVSS {f.cvssScore === null ? "unavailable" : "available"}
                            </Badge>
                            <Badge variant="outline" className="text-[10px]">
                              EPSS {f.epssScore === null ? "unavailable" : "available"}
                            </Badge>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                f.exploitAvailable === true ? "text-red-400 border-red-500/30" : ""
                              }`}
                            >
                              KEV {f.exploitAvailable === null ? "unavailable" : f.exploitAvailable ? "yes" : "no"}
                            </Badge>
                          </div>
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
                                Acknowledge
                              </Button>
                            )}
                            {(f.status === "open" || f.status === "acknowledged") && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs border-green-500/30 text-green-400 hover:bg-green-500/10"
                                onClick={() => updateFinding.mutate({ id: f.id, status: "remediated" })}
                              >
                                Remediated
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* PACKAGES TAB */}
        <TabsContent value="packages" className="mt-4 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4 flex items-center gap-3">
                <Package className="h-8 w-8 text-blue-400" />
                <div>
                  <div className="text-xs text-muted-foreground">Total Packages</div>
                  <div className="text-xl font-semibold">{pkgStats?.total ?? 0}</div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4 flex items-center gap-3">
                <AlertTriangle className="h-8 w-8 text-red-400" />
                <div>
                  <div className="text-xs text-muted-foreground">Vulnerable</div>
                  <div className="text-xl font-semibold text-red-400">{pkgStats?.vulnerableCount ?? 0}</div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4 flex items-center gap-3">
                <ShieldCheck className="h-8 w-8 text-green-400" />
                <div>
                  <div className="text-xs text-muted-foreground">Clean</div>
                  <div className="text-xl font-semibold text-green-400">{pkgStats?.cleanCount ?? 0}</div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4 flex items-center gap-3">
                <Shield className="h-8 w-8 text-teal-400" />
                <div>
                  <div className="text-xs text-muted-foreground">Hosts Scanned</div>
                  <div className="text-xl font-semibold">{pkgStats?.hostCount ?? 0}</div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Package Name</TableHead>
                    <TableHead className="text-muted-foreground">Version</TableHead>
                    <TableHead className="text-muted-foreground">Manager</TableHead>
                    <TableHead className="text-muted-foreground">Status</TableHead>
                    <TableHead className="text-muted-foreground">CVEs</TableHead>
                    <TableHead className="text-muted-foreground">Reported</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {packagesLoading ? (
                    <>
                      {[1, 2, 3].map((row) => (
                        <TableRow key={row}>
                          <TableCell colSpan={6}>
                            <Skeleton className="h-6 w-full" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </>
                  ) : !packagesData?.packages?.length ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-12">
                        <div className="flex flex-col items-center gap-2">
                          <Package className="h-10 w-10 text-muted-foreground/50" />
                          <p className="text-muted-foreground">no package inventory yet — install an agent</p>
                          <p className="text-xs text-muted-foreground">
                            Agents will push package inventories on their inventory schedule
                          </p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    packagesData.packages.map((pkg) => (
                      <TableRow key={pkg.id} className="border-zinc-800">
                        <TableCell className="font-medium">{pkg.packageName}</TableCell>
                        <TableCell className="font-mono text-sm">{pkg.installedVersion}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-zinc-800 text-zinc-300 border-zinc-700">
                            {pkg.packageManager}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {pkg.isVulnerable ? (
                            <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30">
                              Vulnerable
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30">
                              Clean
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {pkg.cveCount > 0 ? (
                            <span className="text-red-400 font-medium">{pkg.cveCount}</span>
                          ) : (
                            <span className="text-muted-foreground">0</span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {pkg.reportedAt ? new Date(pkg.reportedAt).toLocaleDateString() : "—"}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        {/* 49.1: SCAN TARGETS TAB */}
        <TabsContent value="scan-targets" className="mt-4 space-y-4">
          <ScanTargetsPanel />
        </TabsContent>

        {/* 49.4: SCAN SCHEDULING TAB */}
        <TabsContent value="scheduling" className="mt-4 space-y-4">
          <ScanSchedulingPanel />
        </TabsContent>

        {/* 49.3: SCAN COMPARISON TAB */}
        <TabsContent value="comparison" className="mt-4 space-y-4">
          <ScanComparisonPanel />
        </TabsContent>
      </Tabs>

      {/* CVE Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bug className="h-5 w-5 text-red-400" />
              {selectedFinding?.cveId}
            </DialogTitle>
          </DialogHeader>
          {selectedFinding && (
            <div className="space-y-4">
              <div className="flex gap-2 flex-wrap">
                <Badge variant="outline" className={severityColors[selectedFinding.severity] || ""}>
                  {selectedFinding.severity}
                </Badge>
                <Badge variant="outline" className={statusColors[selectedFinding.status] || ""}>
                  {selectedFinding.status.replace("_", " ")}
                </Badge>
                {selectedFinding.cvssScore !== null && (
                  <Badge variant="outline" className="bg-zinc-800 border-zinc-700">
                    CVSS {selectedFinding.cvssScore.toFixed(1)}
                  </Badge>
                )}
                {/* 49.2: Exploit availability indicator */}
                <Badge
                  variant="outline"
                  className={
                    selectedFinding.exploitAvailable === true
                      ? "bg-red-500/20 text-red-400 border-red-500/30"
                      : "bg-zinc-800 border-zinc-700 text-zinc-400"
                  }
                >
                  {selectedFinding.exploitAvailable === null
                    ? "KEV unavailable"
                    : selectedFinding.exploitAvailable
                      ? "KEV listed"
                      : "Not in KEV"}
                </Badge>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Package</span>
                  <span className="font-medium">{selectedFinding.packageName}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Installed Version</span>
                  <span className="font-mono text-red-400">{selectedFinding.installedVersion}</span>
                </div>
                {selectedFinding.fixedVersion && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Fixed In</span>
                    <span className="font-mono text-green-400">{selectedFinding.fixedVersion}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Detected</span>
                  <span>{new Date(selectedFinding.createdAt).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Source</span>
                  <span>{selectedFinding.source || "unknown"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Advisory ID</span>
                  <span className="font-mono text-xs">{selectedFinding.advisoryId ?? "not available"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Confidence</span>
                  <span>{selectedFinding.findingConfidence ?? "not available"}</span>
                </div>
                <div className="space-y-1">
                  <span className="text-muted-foreground">Matching basis</span>
                  <p className="rounded border border-zinc-800 bg-zinc-900 p-2 text-xs">
                    {selectedFinding.findingBasis ?? "not available"}
                  </p>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">EPSS</span>
                  <span>
                    {selectedFinding.epssScore === null
                      ? "not available"
                      : `${selectedFinding.epssScore.toFixed(4)}${
                          selectedFinding.epssDate
                            ? ` (${new Date(selectedFinding.epssDate).toLocaleDateString()})`
                            : ""
                        }`}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Matched CPE</span>
                  <span className="font-mono text-xs">{selectedFinding.matchedCpe ?? "not available"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Affected range</span>
                  <span className="font-mono text-xs">
                    {selectedFinding.matchedVersionRange
                      ? JSON.stringify(selectedFinding.matchedVersionRange)
                      : "not available"}
                  </span>
                </div>
              </div>

              {selectedFinding.description && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Description</p>
                  <p className="text-sm bg-zinc-900 rounded p-3 border border-zinc-800">
                    {selectedFinding.description}
                  </p>
                </div>
              )}

              {/* 49.2: Remediation steps */}
              <div>
                <p className="text-xs text-muted-foreground mb-1">Remediation Steps</p>
                <div className="bg-zinc-900 rounded p-3 border border-zinc-800 space-y-2">
                  {selectedFinding.fixedVersion ? (
                    <>
                      <div className="flex items-start gap-2">
                        <span className="text-green-400 font-mono text-xs mt-0.5">1.</span>
                        <span className="text-sm">
                          Update <code className="bg-zinc-800 px-1 rounded">{selectedFinding.packageName}</code> from{" "}
                          <code className="text-red-400 bg-zinc-800 px-1 rounded">
                            {selectedFinding.installedVersion}
                          </code>{" "}
                          to{" "}
                          <code className="text-green-400 bg-zinc-800 px-1 rounded">
                            {selectedFinding.fixedVersion}
                          </code>
                        </span>
                      </div>
                      <div className="flex items-start gap-2">
                        <span className="text-green-400 font-mono text-xs mt-0.5">2.</span>
                        <span className="text-sm">Verify no breaking changes in the updated version</span>
                      </div>
                      <div className="flex items-start gap-2">
                        <span className="text-green-400 font-mono text-xs mt-0.5">3.</span>
                        <span className="text-sm">Run vulnerability scan after patching to confirm fix</span>
                      </div>
                    </>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      No fix version available. Monitor vendor advisories or consider migrating to an alternative
                      package.
                    </p>
                  )}
                </div>
              </div>

              {/* 49.2: Link to CVE DB */}
              <a
                href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
              >
                <ExternalLink className="h-3 w-3" />
                View on NVD (NIST)
              </a>

              <div className="flex gap-2 pt-2">
                {selectedFinding.status === "open" && (
                  <Button
                    className="flex-1"
                    variant="outline"
                    onClick={() => {
                      updateFinding.mutate({ id: selectedFinding.id, status: "acknowledged" });
                      setSelectedFinding(null);
                    }}
                  >
                    <Clock className="h-4 w-4 mr-1" />
                    Acknowledge
                  </Button>
                )}
                {selectedFinding.status !== "remediated" && (
                  <Button
                    className="flex-1 bg-green-600 hover:bg-green-700"
                    onClick={() => {
                      updateFinding.mutate({ id: selectedFinding.id, status: "remediated" });
                      setSelectedFinding(null);
                    }}
                  >
                    <CheckCircle className="h-4 w-4 mr-1" />
                    Mark Remediated
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// 49.1: Scan Target Configuration
function ScanTargetsPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAddTarget, setShowAddTarget] = useState(false);
  const [targetForm, setTargetForm] = useState({
    name: "",
    type: "ip_range",
    value: "",
    excludePatterns: "",
    maintenanceWindow: "",
  });

  const { data: targetsData } = useQuery({
    queryKey: ["/api/native/vuln/scan-targets"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native/vuln/scan-targets");
      return res.json();
    },
  });

  const addTargetMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/native/vuln/scan-targets", {
        ...targetForm,
        excludePatterns: targetForm.excludePatterns.split("\n").filter(Boolean),
      });
    },
    onSuccess: () => {
      toast({ title: "Scan target added" });
      queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/scan-targets"] });
      setShowAddTarget(false);
      setTargetForm({ name: "", type: "ip_range", value: "", excludePatterns: "", maintenanceWindow: "" });
    },
    onError: () => toast({ title: "Failed to add target", variant: "destructive" }),
  });

  const targets: Array<{
    id: string;
    name: string;
    type: string;
    value: string;
    excludePatterns: string[];
    lastScanAt: string | null;
    status: string;
  }> = targetsData?.targets || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Scan Targets</span>
          <Badge variant="outline" className="text-xs">
            {targets.length} configured
          </Badge>
        </div>
        <Button size="sm" onClick={() => setShowAddTarget(!showAddTarget)}>
          <Plus className="h-3 w-3 mr-1" /> Add Target
        </Button>
      </div>

      {showAddTarget && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Target Name</Label>
                <Input
                  placeholder="Production network"
                  className="bg-zinc-950 border-zinc-800 mt-1"
                  value={targetForm.name}
                  onChange={(e) => setTargetForm({ ...targetForm, name: e.target.value })}
                />
              </div>
              <div>
                <Label className="text-xs">Type</Label>
                <Select value={targetForm.type} onValueChange={(v) => setTargetForm({ ...targetForm, type: v })}>
                  <SelectTrigger className="bg-zinc-950 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ip_range">IP Range</SelectItem>
                    <SelectItem value="hostname">Hostname</SelectItem>
                    <SelectItem value="cidr">CIDR Block</SelectItem>
                    <SelectItem value="cloud_resource">Cloud Resource</SelectItem>
                    <SelectItem value="container">Container</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label className="text-xs">Target Value</Label>
              <Input
                placeholder={
                  targetForm.type === "ip_range"
                    ? "192.168.1.0-192.168.1.255"
                    : targetForm.type === "cidr"
                      ? "10.0.0.0/24"
                      : "host.example.com"
                }
                className="bg-zinc-950 border-zinc-800 mt-1"
                value={targetForm.value}
                onChange={(e) => setTargetForm({ ...targetForm, value: e.target.value })}
              />
            </div>
            <div>
              <Label className="text-xs">Exclusions (one per line)</Label>
              <Textarea
                placeholder="192.168.1.100&#10;dev-*.example.com"
                className="bg-zinc-950 border-zinc-800 mt-1 h-16"
                value={targetForm.excludePatterns}
                onChange={(e) => setTargetForm({ ...targetForm, excludePatterns: e.target.value })}
              />
            </div>
            <div>
              <Label className="text-xs">Maintenance Window (optional)</Label>
              <Input
                placeholder="Sat 02:00-06:00 UTC"
                className="bg-zinc-950 border-zinc-800 mt-1"
                value={targetForm.maintenanceWindow}
                onChange={(e) => setTargetForm({ ...targetForm, maintenanceWindow: e.target.value })}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setShowAddTarget(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => addTargetMutation.mutate()}
                disabled={!targetForm.name || !targetForm.value}
              >
                Save Target
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-muted-foreground">Name</TableHead>
                <TableHead className="text-muted-foreground">Type</TableHead>
                <TableHead className="text-muted-foreground">Value</TableHead>
                <TableHead className="text-muted-foreground">Exclusions</TableHead>
                <TableHead className="text-muted-foreground">Last Scan</TableHead>
                <TableHead className="text-muted-foreground">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <Target className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
                    <p className="text-sm text-muted-foreground">No scan targets configured</p>
                    <p className="text-xs text-muted-foreground">
                      Add IP ranges, hostnames, or cloud resources to scan
                    </p>
                  </TableCell>
                </TableRow>
              ) : (
                targets.map((t) => (
                  <TableRow key={t.id} className="border-zinc-800">
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {t.type.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">{t.value}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {t.excludePatterns.length > 0 ? `${t.excludePatterns.length} exclusion(s)` : "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {t.lastScanAt ? new Date(t.lastScanAt).toLocaleDateString() : "Never"}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={t.status === "active" ? "text-green-400 border-green-400/30" : "text-zinc-400"}
                      >
                        {t.status}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// 49.3: Scan Comparison (before/after)
function ScanComparisonPanel() {
  const [scanA, setScanA] = useState("");
  const [scanB, setScanB] = useState("");
  const [comparisonResult, setComparisonResult] = useState<{
    newVulns: Array<{ cveId: string; severity: string; packageName: string }>;
    fixedVulns: Array<{ cveId: string; severity: string; packageName: string }>;
    unchangedCount: number;
    remediationProgress: number;
  } | null>(null);
  const [comparing, setComparing] = useState(false);
  const { toast } = useToast();

  const runComparison = async () => {
    if (!scanA || !scanB) {
      toast({ title: "Select two scan dates to compare", variant: "destructive" });
      return;
    }
    setComparing(true);
    try {
      const res = await apiRequest("POST", "/api/native/vuln/compare-scans", { scanDateA: scanA, scanDateB: scanB });
      const data = await res.json();
      setComparisonResult(data);
    } catch {
      toast({ title: "Comparison failed", variant: "destructive" });
    } finally {
      setComparing(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <GitCompare className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">Scan Comparison</span>
      </div>
      <div className="flex items-end gap-3">
        <div>
          <Label className="text-xs">Scan A (baseline)</Label>
          <Input
            type="date"
            className="bg-zinc-900/50 border-zinc-800 mt-1 w-[180px]"
            value={scanA}
            onChange={(e) => setScanA(e.target.value)}
          />
        </div>
        <ArrowUpDown className="h-4 w-4 text-muted-foreground mb-2" />
        <div>
          <Label className="text-xs">Scan B (current)</Label>
          <Input
            type="date"
            className="bg-zinc-900/50 border-zinc-800 mt-1 w-[180px]"
            value={scanB}
            onChange={(e) => setScanB(e.target.value)}
          />
        </div>
        <Button size="sm" onClick={runComparison} disabled={comparing}>
          {comparing ? "Comparing..." : "Compare"}
        </Button>
      </div>

      {comparisonResult && (
        <div className="space-y-4">
          <div className="grid grid-cols-4 gap-3">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="text-xs text-red-400">New Vulnerabilities</div>
                <div className="text-2xl font-semibold text-red-400 mt-1">{comparisonResult.newVulns.length}</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="text-xs text-green-400">Fixed</div>
                <div className="text-2xl font-semibold text-green-400 mt-1">{comparisonResult.fixedVulns.length}</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">Unchanged</div>
                <div className="text-2xl font-semibold mt-1">{comparisonResult.unchangedCount}</div>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="text-xs text-muted-foreground">Remediation Progress</div>
                <div className="flex items-center gap-2 mt-2">
                  <Progress value={comparisonResult.remediationProgress} className="h-2 flex-1" />
                  <span className="text-sm font-medium">{comparisonResult.remediationProgress}%</span>
                </div>
              </CardContent>
            </Card>
          </div>

          {comparisonResult.newVulns.length > 0 && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-red-400">New Vulnerabilities Since Baseline</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-muted-foreground">CVE</TableHead>
                      <TableHead className="text-muted-foreground">Severity</TableHead>
                      <TableHead className="text-muted-foreground">Package</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {comparisonResult.newVulns.map((v) => (
                      <TableRow key={v.cveId} className="border-zinc-800">
                        <TableCell className="font-mono text-sm text-blue-400">{v.cveId}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={severityColors[v.severity] || ""}>
                            {v.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>{v.packageName}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {comparisonResult.fixedVulns.length > 0 && (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-green-400">Fixed Since Baseline</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-muted-foreground">CVE</TableHead>
                      <TableHead className="text-muted-foreground">Severity</TableHead>
                      <TableHead className="text-muted-foreground">Package</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {comparisonResult.fixedVulns.map((v) => (
                      <TableRow key={v.cveId} className="border-zinc-800">
                        <TableCell className="font-mono text-sm text-blue-400 line-through">{v.cveId}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={severityColors[v.severity] || ""}>
                            {v.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>{v.packageName}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// 49.4: Scan Scheduling
function ScanSchedulingPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [scheduleForm, setScheduleForm] = useState({
    name: "",
    frequency: "weekly",
    scanType: "comprehensive",
    dayOfWeek: "1",
    hour: "2",
    enabled: true,
  });

  const { data: schedulesData } = useQuery({
    queryKey: ["/api/native/vuln/scan-schedules"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/native/vuln/scan-schedules");
      return res.json();
    },
  });

  const createScheduleMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/native/vuln/scan-schedules", scheduleForm);
    },
    onSuccess: () => {
      toast({ title: "Schedule created" });
      queryClient.invalidateQueries({ queryKey: ["/api/native/vuln/scan-schedules"] });
      setShowCreate(false);
    },
    onError: () => toast({ title: "Failed to create schedule", variant: "destructive" }),
  });

  const schedules: Array<{
    id: string;
    name: string;
    frequency: string;
    scanType: string;
    nextRunAt: string;
    lastRunAt: string | null;
    enabled: boolean;
  }> = schedulesData?.schedules || [];

  const daysOfWeek = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Calendar className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Scan Schedules</span>
        </div>
        <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
          <Plus className="h-3 w-3 mr-1" /> New Schedule
        </Button>
      </div>

      {showCreate && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Schedule Name</Label>
                <Input
                  placeholder="Weekly comprehensive scan"
                  className="bg-zinc-950 border-zinc-800 mt-1"
                  value={scheduleForm.name}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                />
              </div>
              <div>
                <Label className="text-xs">Frequency</Label>
                <Select
                  value={scheduleForm.frequency}
                  onValueChange={(v) => setScheduleForm({ ...scheduleForm, frequency: v })}
                >
                  <SelectTrigger className="bg-zinc-950 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="biweekly">Bi-weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label className="text-xs">Scan Type</Label>
                <Select
                  value={scheduleForm.scanType}
                  onValueChange={(v) => setScheduleForm({ ...scheduleForm, scanType: v })}
                >
                  <SelectTrigger className="bg-zinc-950 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive</SelectItem>
                    <SelectItem value="compliance">Compliance Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Day of Week</Label>
                <Select
                  value={scheduleForm.dayOfWeek}
                  onValueChange={(v) => setScheduleForm({ ...scheduleForm, dayOfWeek: v })}
                >
                  <SelectTrigger className="bg-zinc-950 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {daysOfWeek.map((d, i) => (
                      <SelectItem key={i} value={String(i)}>
                        {d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Hour (UTC)</Label>
                <Select value={scheduleForm.hour} onValueChange={(v) => setScheduleForm({ ...scheduleForm, hour: v })}>
                  <SelectTrigger className="bg-zinc-950 border-zinc-800 mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Array.from({ length: 24 }, (_, i) => (
                      <SelectItem key={i} value={String(i)}>
                        {String(i).padStart(2, "0")}:00
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button size="sm" onClick={() => createScheduleMutation.mutate()} disabled={!scheduleForm.name}>
                Create Schedule
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Schedule Calendar View */}
      <div className="grid grid-cols-7 gap-1">
        {daysOfWeek.map((day) => (
          <div key={day} className="text-center text-[10px] text-muted-foreground py-1">
            {day.slice(0, 3)}
          </div>
        ))}
        {Array.from({ length: 28 }, (_, i) => {
          const date = new Date();
          date.setDate(date.getDate() + i - date.getDay());
          const hasSchedule = schedules.some((s) => {
            if (!s.nextRunAt) return false;
            const next = new Date(s.nextRunAt);
            return next.toDateString() === date.toDateString();
          });
          return (
            <div
              key={i}
              className={`text-center text-xs py-2 rounded ${hasSchedule ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" : "bg-zinc-900/30 text-muted-foreground border border-zinc-800/50"}`}
            >
              {date.getDate()}
            </div>
          );
        })}
      </div>

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-muted-foreground">Name</TableHead>
                <TableHead className="text-muted-foreground">Frequency</TableHead>
                <TableHead className="text-muted-foreground">Scan Type</TableHead>
                <TableHead className="text-muted-foreground">Next Run</TableHead>
                <TableHead className="text-muted-foreground">Last Run</TableHead>
                <TableHead className="text-muted-foreground">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {schedules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <Calendar className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
                    <p className="text-sm text-muted-foreground">No scan schedules configured</p>
                    <p className="text-xs text-muted-foreground">
                      Create recurring scans for continuous security monitoring
                    </p>
                  </TableCell>
                </TableRow>
              ) : (
                schedules.map((s) => (
                  <TableRow key={s.id} className="border-zinc-800">
                    <TableCell className="font-medium">{s.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {s.frequency}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{s.scanType}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {s.nextRunAt ? new Date(s.nextRunAt).toLocaleString() : "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {s.lastRunAt ? new Date(s.lastRunAt).toLocaleString() : "Never"}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={s.enabled ? "text-green-400 border-green-400/30" : "text-zinc-400"}
                      >
                        {s.enabled ? "Active" : "Paused"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
