import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
} from "lucide-react";

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
  sensorId: string;
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

async function apiFetch(url: string, options?: RequestInit) {
  const res = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
    credentials: "include",
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export default function VulnScannerPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("findings");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<VulnFinding | null>(null);

  const { data: findingsData, isLoading: findingsLoading } = useQuery<FindingsResponse>({
    queryKey: ["/api/native/vuln/findings", severityFilter, statusFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams();
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (statusFilter !== "all") params.set("status", statusFilter);
      if (searchQuery) params.set("q", searchQuery);
      return apiFetch(`/api/native/vuln/findings?${params}`);
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
            Agent-reported package inventory matched against NVD CVE data in real-time
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
                      <TableCell colSpan={8} className="text-center py-12">
                        <div className="flex flex-col items-center gap-2">
                          <ShieldCheck className="h-10 w-10 text-green-400/50" />
                          <p className="text-muted-foreground">No vulnerability findings</p>
                          <p className="text-xs text-muted-foreground">
                            Deploy sensors and push package inventories to start scanning
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
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                        Loading packages...
                      </TableCell>
                    </TableRow>
                  ) : !packagesData?.packages?.length ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-12">
                        <div className="flex flex-col items-center gap-2">
                          <Package className="h-10 w-10 text-muted-foreground/50" />
                          <p className="text-muted-foreground">No packages reported</p>
                          <p className="text-xs text-muted-foreground">
                            Agents will push package inventories during heartbeats
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
              <div className="flex gap-2">
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
              </div>

              {selectedFinding.description && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Description</p>
                  <p className="text-sm bg-zinc-900 rounded p-3 border border-zinc-800">
                    {selectedFinding.description}
                  </p>
                </div>
              )}

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
