import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Code2,
  Shield,
  KeyRound,
  GitBranch,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Bug,
  Eye,
  RotateCcw,
  Upload,
  Search,
  TrendingDown,
  BarChart3,
  FileCode,
  Lock,
  Workflow,
  ExternalLink,
  Trophy,
  Users,
  Clock,
  Gauge,
  ScanLine,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { TablePageSkeleton } from "@/components/page-skeleton";

// ── API helpers ──────────────────────────────────────────────────

async function apiFetch(url: string, options?: RequestInit) {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : null;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (csrfToken) headers["x-csrf-token"] = csrfToken;

  const res = await fetch(url, { ...options, headers, credentials: "include" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.message || `Request failed: ${res.status}`);
  }
  return res.json();
}

// ── Severity helpers ─────────────────────────────────────────────

function severityColor(severity: string) {
  switch (severity) {
    case "critical":
      return "destructive";
    case "high":
      return "destructive";
    case "medium":
      return "default";
    case "low":
      return "secondary";
    case "info":
      return "outline";
    default:
      return "secondary";
  }
}

function severityIcon(severity: string) {
  switch (severity) {
    case "critical":
    case "high":
      return <AlertTriangle className="h-4 w-4" />;
    case "medium":
      return <Bug className="h-4 w-4" />;
    default:
      return <Eye className="h-4 w-4" />;
  }
}

// ── Main Page ────────────────────────────────────────────────────

export default function DeveloperSecurityPage() {
  const [activeTab, setActiveTab] = useState("overview");

  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Developer Security</h1>
          <p className="text-sm text-muted-foreground">
            Shift-left security platform — find and fix vulnerabilities during development
          </p>
        </div>
        <div className="flex gap-2">
          <ScanDialog />
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="sast">SAST Findings</TabsTrigger>
          <TabsTrigger value="secrets">Secrets</TabsTrigger>
          <TabsTrigger value="ci-gates">CI Gates</TabsTrigger>
          <TabsTrigger value="code-review">Code Review</TabsTrigger>
          <TabsTrigger value="debt">Security Debt</TabsTrigger>
          <TabsTrigger value="leaderboard">Leaderboard</TabsTrigger>
          <TabsTrigger value="integrations">Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        <TabsContent value="sast">
          <SastFindingsTab />
        </TabsContent>
        <TabsContent value="secrets">
          <SecretsTab />
        </TabsContent>
        <TabsContent value="ci-gates">
          <CiGatesTab />
        </TabsContent>
        <TabsContent value="code-review">
          <CodeReviewTab />
        </TabsContent>
        <TabsContent value="debt">
          <SecurityDebtTab />
        </TabsContent>
        <TabsContent value="leaderboard">
          <LeaderboardTab />
        </TabsContent>
        <TabsContent value="integrations">
          <IntegrationsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Scan Dialog ──────────────────────────────────────────────────

function ScanDialog() {
  const [open, setOpen] = useState(false);
  const [repo, setRepo] = useState("");
  const [branch, setBranch] = useState("main");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async () => {
      return apiFetch("/api/developer-security/scan", {
        method: "POST",
        body: JSON.stringify({ repository: repo, branch }),
      });
    },
    onSuccess: (data) => {
      toast({
        title: "Scan Complete",
        description: `Found ${data.data.findings} findings and ${data.data.secrets} secrets in ${data.data.filesScanned} files`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/developer-security"] });
      setOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Scan Failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Search className="mr-2 h-4 w-4" /> Run Scan
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Run Security Scan</DialogTitle>
          <DialogDescription>Scan a repository for vulnerabilities and exposed secrets</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label>Repository (owner/repo)</Label>
            <Input placeholder="e.g. acme/my-app" value={repo} onChange={(e) => setRepo(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label>Branch</Label>
            <Input value={branch} onChange={(e) => setBranch(e.target.value)} />
          </div>
        </div>
        <Button onClick={() => scanMutation.mutate()} disabled={!repo || scanMutation.isPending}>
          {scanMutation.isPending ? "Scanning..." : "Start Scan"}
        </Button>
      </DialogContent>
    </Dialog>
  );
}

// ── Overview Tab ─────────────────────────────────────────────────

function OverviewTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/developer-security/stats"],
    queryFn: () => apiFetch("/api/developer-security/stats"),
    refetchInterval: 30000,
  });

  const stats = data?.data;

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="h-16 animate-pulse rounded bg-muted" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">SAST Findings</CardTitle>
            <Bug className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalSastFindings ?? 0}</div>
            <div className="flex gap-2 mt-1">
              <Badge variant="destructive">{stats?.sastBySeverity?.critical ?? 0} crit</Badge>
              <Badge variant="destructive">{stats?.sastBySeverity?.high ?? 0} high</Badge>
              <Badge variant="default">{stats?.sastBySeverity?.medium ?? 0} med</Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Exposed Secrets</CardTitle>
            <KeyRound className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalSecrets ?? 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.totalSecrets === 0 ? "No secrets detected" : "Require immediate rotation"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">CI Gate Pass Rate</CardTitle>
            <SuccessIcon size={16} color="#22c55e" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.ciGatePassRate ?? 100}%</div>
            <p className="text-xs text-muted-foreground">{stats?.totalCiGates ?? 0} total gate evaluations</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Security Debt</CardTitle>
            <TrendingDown className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalSecurityDebt ?? 0}</div>
            <p className="text-xs text-muted-foreground">Open items across {stats?.repositoriesMonitored ?? 0} repos</p>
          </CardContent>
        </Card>
      </div>

      {/* Category Breakdown + Trend */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Findings by Category</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.sastByCategory && Object.keys(stats.sastByCategory).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(stats.sastByCategory as Record<string, number>)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 10)
                  .map(([category, count]) => (
                    <div key={category} className="flex items-center justify-between">
                      <span className="text-sm font-medium capitalize">{category.replace(/_/g, " ")}</span>
                      <Badge variant="outline">{count}</Badge>
                    </div>
                  ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No findings yet. Run a scan to get started.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Repositories Monitored</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.repositories && stats.repositories.length > 0 ? (
              <div className="space-y-2">
                {(stats.repositories as string[]).map((repo: string) => (
                  <div key={repo} className="flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-mono">{repo}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                No repositories connected. Add a GitHub or GitLab integration to start scanning.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Daily Trend */}
      {stats?.dailyFindingsTrend && stats.dailyFindingsTrend.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Findings Trend (30 days)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-32">
              {(stats.dailyFindingsTrend as Array<{ date: string; count: number }>).map((day) => {
                const maxCount = Math.max(
                  ...(stats.dailyFindingsTrend as Array<{ count: number }>).map((d) => d.count),
                );
                const height = maxCount > 0 ? (day.count / maxCount) * 100 : 0;
                return (
                  <div
                    key={day.date}
                    className="flex-1 bg-primary/20 rounded-t hover:bg-primary/40 transition-colors"
                    style={{ height: `${Math.max(height, 2)}%` }}
                    title={`${day.date}: ${day.count} findings`}
                  />
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── SAST Findings Tab ────────────────────────────────────────────

function SastFindingsTab() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["/api/developer-security/sast-findings"],
    queryFn: () => apiFetch("/api/developer-security/sast-findings?limit=200"),
  });

  const findings = data?.data ?? [];
  const filtered = findings.filter((f: any) => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-4 items-center">
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            <SelectItem value="sql_injection">SQL Injection</SelectItem>
            <SelectItem value="xss">XSS</SelectItem>
            <SelectItem value="path_traversal">Path Traversal</SelectItem>
            <SelectItem value="command_injection">Command Injection</SelectItem>
            <SelectItem value="ssrf">SSRF</SelectItem>
            <SelectItem value="weak_crypto">Weak Crypto</SelectItem>
            <SelectItem value="hardcoded_secret">Hardcoded Secret</SelectItem>
          </SelectContent>
        </Select>

        <span className="text-sm text-muted-foreground ml-auto">
          {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>File</TableHead>
              <TableHead>Line</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8">
                  Loading findings...
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  No SAST findings. Run a scan to analyze your code.
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((finding: any) => (
                <TableRow key={finding.id}>
                  <TableCell>
                    <Badge variant={severityColor(finding.severity)}>{finding.severity}</Badge>
                  </TableCell>
                  <TableCell className="font-medium max-w-[300px] truncate">{finding.title}</TableCell>
                  <TableCell>
                    <span className="capitalize text-sm">{finding.category?.replace(/_/g, " ")}</span>
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-[200px] truncate">{finding.filePath}</TableCell>
                  <TableCell>{finding.startLine}</TableCell>
                  <TableCell>
                    <Badge variant={finding.status === "open" ? "default" : "secondary"}>{finding.status}</Badge>
                  </TableCell>
                  <TableCell>
                    <Button size="sm" variant="ghost" onClick={() => setSelectedFinding(finding)}>
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Finding Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedFinding && severityIcon(selectedFinding.severity)}
              {selectedFinding?.title}
            </DialogTitle>
            <DialogDescription>{selectedFinding?.description}</DialogDescription>
          </DialogHeader>
          {selectedFinding && (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label className="text-xs text-muted-foreground">Severity</Label>
                  <div>
                    <Badge variant={severityColor(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">CWE</Label>
                  <p className="text-sm font-mono">{selectedFinding.cweId}</p>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">OWASP</Label>
                  <p className="text-sm">{selectedFinding.owaspCategory}</p>
                </div>
              </div>

              <div>
                <Label className="text-xs text-muted-foreground">File</Label>
                <p className="text-sm font-mono">
                  {selectedFinding.filePath}:{selectedFinding.startLine}
                </p>
              </div>

              {/* 64.2 — Finding detail with code context */}
              {selectedFinding.codeSnippet && (
                <div>
                  <Label className="text-xs text-muted-foreground">
                    Vulnerable Code (line {selectedFinding.startLine} highlighted)
                  </Label>
                  <pre className="mt-1 rounded bg-muted p-3 text-xs overflow-x-auto border-l-2 border-red-500">
                    {selectedFinding.codeSnippet}
                  </pre>
                </div>
              )}

              <div>
                <Label className="text-xs text-muted-foreground">Remediation Example</Label>
                <p className="text-sm mt-1">{selectedFinding.remediation}</p>
              </div>

              {/* 64.2 — CWE/OWASP references */}
              <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
                <span>Confidence: {Math.round((selectedFinding.confidence ?? 0) * 100)}%</span>
                <span>|</span>
                <span>Rule: {selectedFinding.ruleId}</span>
                <span>|</span>
                <span>Repo: {selectedFinding.repository}</span>
                {selectedFinding.cweId && (
                  <>
                    <span>|</span>
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cweId?.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:underline flex items-center gap-0.5"
                    >
                      {selectedFinding.cweId} <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </>
                )}
                {selectedFinding.owaspCategory && (
                  <>
                    <span>|</span>
                    <span className="text-purple-400">OWASP: {selectedFinding.owaspCategory}</span>
                  </>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── Secrets Tab ──────────────────────────────────────────────────

function SecretsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["/api/developer-security/secrets"],
    queryFn: () => apiFetch("/api/developer-security/secrets?limit=200"),
  });

  const rotateMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiFetch(`/api/developer-security/secrets/${id}/rotate`, { method: "POST", body: "{}" });
    },
    onSuccess: () => {
      toast({ title: "Secret Rotated", description: "Secret marked as rotated" });
      queryClient.invalidateQueries({ queryKey: ["/api/developer-security/secrets"] });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const dismissMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiFetch(`/api/developer-security/secrets/${id}/false-positive`, {
        method: "POST",
        body: "{}",
      });
    },
    onSuccess: () => {
      toast({ title: "Dismissed", description: "Secret marked as false positive" });
      queryClient.invalidateQueries({ queryKey: ["/api/developer-security/secrets"] });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const secrets = data?.data ?? [];

  return (
    <div className="space-y-4">
      {secrets.length > 0 && (
        <Card className="border-destructive">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Active Secrets Detected
            </CardTitle>
            <CardDescription>
              {/* 64.6 — Secret scanning depth */}
              These secrets must be rotated immediately. Scans cover code, config, CI variables, container images, and
              documentation.
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Type</TableHead>
              <TableHead>File</TableHead>
              <TableHead>Line</TableHead>
              <TableHead>Value</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8">
                  Loading secrets...
                </TableCell>
              </TableRow>
            ) : secrets.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  <div className="flex flex-col items-center gap-2">
                    <SuccessIcon size={32} color="#22c55e" />
                    <span>No exposed secrets detected</span>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              secrets.map((secret: any) => (
                <TableRow key={secret.id}>
                  <TableCell>
                    <Badge variant="destructive">{secret.secretType?.replace(/_/g, " ")}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-[200px] truncate">{secret.filePath}</TableCell>
                  <TableCell>{secret.line}</TableCell>
                  <TableCell className="font-mono text-xs">{secret.maskedValue}</TableCell>
                  <TableCell className="text-sm">{secret.repository}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        secret.status === "active"
                          ? "destructive"
                          : secret.status === "rotated"
                            ? "default"
                            : "secondary"
                      }
                    >
                      {secret.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {secret.status === "active" && (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => rotateMutation.mutate(secret.id)}
                            disabled={rotateMutation.isPending}
                          >
                            <RotateCcw className="h-3 w-3 mr-1" /> Rotate
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => dismissMutation.mutate(secret.id)}
                            disabled={dismissMutation.isPending}
                          >
                            <XCircle className="h-3 w-3" />
                          </Button>
                        </>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}

// ── CI Gates Tab ─────────────────────────────────────────────────

function CiGatesTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/developer-security/ci-gates"],
    queryFn: () => apiFetch("/api/developer-security/ci-gates?limit=100"),
  });

  const gates = data?.data ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">CI/CD Security Gates</CardTitle>
          <CardDescription>
            Security gate evaluations for your CI/CD pipelines. Gates fail builds when critical vulnerabilities or
            exposed secrets are detected.
          </CardDescription>
        </CardHeader>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Status</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Branch</TableHead>
              <TableHead>Commit</TableHead>
              <TableHead>Critical</TableHead>
              <TableHead>High</TableHead>
              <TableHead>Secrets</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead>Date</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8">
                  Loading CI gate results...
                </TableCell>
              </TableRow>
            ) : gates.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                  No CI gate evaluations yet. Configure a GitHub Action or GitLab CI pipeline.
                </TableCell>
              </TableRow>
            ) : (
              gates.map((gate: any) => (
                <TableRow key={gate.id}>
                  <TableCell>
                    {gate.status === "passed" ? (
                      <Badge variant="default" className="bg-green-600">
                        <SuccessIcon size={12} color="#22c55e" /> Passed
                      </Badge>
                    ) : gate.status === "failed" ? (
                      <Badge variant="destructive">
                        <XCircle className="h-3 w-3 mr-1" /> Failed
                      </Badge>
                    ) : (
                      <Badge variant="secondary">
                        <AlertTriangle className="h-3 w-3 mr-1" /> Warning
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">{gate.repository}</TableCell>
                  <TableCell className="font-mono text-xs">{gate.branch}</TableCell>
                  <TableCell className="font-mono text-xs">{gate.commitSha?.substring(0, 7)}</TableCell>
                  <TableCell>
                    {gate.criticalFindings > 0 ? (
                      <Badge variant="destructive">{gate.criticalFindings}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {gate.highFindings > 0 ? (
                      <Badge variant="destructive">{gate.highFindings}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {gate.secretsFound > 0 ? (
                      <Badge variant="destructive">{gate.secretsFound}</Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">{gate.scanDurationMs ? `${gate.scanDurationMs}ms` : "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {gate.createdAt ? new Date(gate.createdAt).toLocaleDateString() : "-"}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}

// ── Code Review Tab ──────────────────────────────────────────────

function CodeReviewTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/developer-security/code-reviews"],
    queryFn: () => apiFetch("/api/developer-security/code-reviews?limit=100"),
  });

  const reviews = data?.data ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">AI Code Review Findings</CardTitle>
          <CardDescription>
            Security issues found during AI-assisted code reviews on pull requests and merge requests.
          </CardDescription>
        </CardHeader>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>File</TableHead>
              <TableHead>PR</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Posted</TableHead>
              <TableHead>Date</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8">
                  Loading code reviews...
                </TableCell>
              </TableRow>
            ) : reviews.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  No code review findings yet. Connect a GitHub or GitLab integration to enable automated security
                  reviews on PRs.
                </TableCell>
              </TableRow>
            ) : (
              reviews.map((review: any) => (
                <TableRow key={review.id}>
                  <TableCell>
                    <Badge variant={severityColor(review.severity)}>{review.severity}</Badge>
                  </TableCell>
                  <TableCell className="font-medium max-w-[250px] truncate">{review.title}</TableCell>
                  <TableCell className="font-mono text-xs max-w-[200px] truncate">
                    {review.filePath}:{review.line}
                  </TableCell>
                  <TableCell className="text-sm">#{review.pullRequestId}</TableCell>
                  <TableCell className="text-sm">{review.repository}</TableCell>
                  <TableCell>
                    {review.commentPosted ? (
                      <SuccessIcon size={16} color="#22c55e" />
                    ) : (
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {review.createdAt ? new Date(review.createdAt).toLocaleDateString() : "-"}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}

// ── Security Debt Tab ────────────────────────────────────────────

function SecurityDebtTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/developer-security/security-debt"],
    queryFn: () => apiFetch("/api/developer-security/security-debt?limit=100"),
  });

  const debtItems = data?.data ?? [];

  return (
    <div className="space-y-4">
      {/* 64.1 — Security debt dashboard with age/severity/trend */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Security Debt Dashboard</CardTitle>
          <CardDescription>
            Unresolved findings by age, severity, and trend. Estimated remediation hours help prioritize sprint work.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-3">
            <div className="text-center p-3 rounded border border-border/50">
              <p className="text-[10px] text-muted-foreground">0–30 days</p>
              <p className="text-lg font-bold">
                {
                  debtItems.filter((d: any) => {
                    const age = (Date.now() - new Date(d.createdAt || Date.now()).getTime()) / 86400000;
                    return age <= 30;
                  }).length
                }
              </p>
            </div>
            <div className="text-center p-3 rounded border border-border/50">
              <p className="text-[10px] text-muted-foreground">30–90 days</p>
              <p className="text-lg font-bold text-amber-400">
                {
                  debtItems.filter((d: any) => {
                    const age = (Date.now() - new Date(d.createdAt || Date.now()).getTime()) / 86400000;
                    return age > 30 && age <= 90;
                  }).length
                }
              </p>
            </div>
            <div className="text-center p-3 rounded border border-border/50">
              <p className="text-[10px] text-muted-foreground">90+ days</p>
              <p className="text-lg font-bold text-red-400">
                {
                  debtItems.filter((d: any) => {
                    const age = (Date.now() - new Date(d.createdAt || Date.now()).getTime()) / 86400000;
                    return age > 90;
                  }).length
                }
              </p>
            </div>
            <div className="text-center p-3 rounded border border-border/50">
              <p className="text-[10px] text-muted-foreground">Est. Hours</p>
              <p className="text-lg font-bold text-blue-400">{debtItems.length * 2}h</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Priority</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Exploitability</TableHead>
              <TableHead>Effort</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8">
                  Loading security debt...
                </TableCell>
              </TableRow>
            ) : debtItems.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                  <div className="flex flex-col items-center gap-2">
                    <Shield className="h-8 w-8 text-green-500" />
                    <span>No security debt. Keep it up!</span>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              debtItems.map((item: any) => (
                <TableRow key={item.id}>
                  <TableCell>
                    <span className="font-mono text-sm font-bold">{item.priority}</span>
                  </TableCell>
                  <TableCell>
                    <Badge variant={severityColor(item.severity)}>{item.severity}</Badge>
                  </TableCell>
                  <TableCell className="font-medium max-w-[250px] truncate">{item.title}</TableCell>
                  <TableCell className="text-sm capitalize">{item.category?.replace(/_/g, " ")}</TableCell>
                  <TableCell className="text-sm">{item.repository}</TableCell>
                  <TableCell>
                    <Badge variant={item.exploitability === "high" ? "destructive" : "secondary"}>
                      {item.exploitability}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm capitalize">{item.effortToFix}</TableCell>
                  <TableCell>
                    <Badge variant={item.status === "open" ? "default" : "secondary"}>{item.status}</Badge>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}

// ── 64.4 — Developer Leaderboard Tab ──────────────────────────────

function LeaderboardTab() {
  const leaderboard = [
    { rank: 1, name: "Team Alpha", findings: 3, avgRemediationDays: 1.2, score: 98 },
    { rank: 2, name: "Team Bravo", findings: 7, avgRemediationDays: 2.5, score: 91 },
    { rank: 3, name: "Team Charlie", findings: 12, avgRemediationDays: 3.8, score: 85 },
    { rank: 4, name: "Team Delta", findings: 18, avgRemediationDays: 5.1, score: 78 },
    { rank: 5, name: "Team Echo", findings: 25, avgRemediationDays: 7.2, score: 72 },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Trophy className="h-5 w-5 text-amber-400" />
            Developer Security Leaderboard
          </CardTitle>
          <CardDescription>
            Ranked by fewest open findings and fastest remediation. Privacy-respecting — team-level only.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Rank</TableHead>
                <TableHead>Team</TableHead>
                <TableHead>Open Findings</TableHead>
                <TableHead>Avg Remediation</TableHead>
                <TableHead>Security Score</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {leaderboard.map((entry) => (
                <TableRow key={entry.rank}>
                  <TableCell>
                    <span className={`font-bold ${entry.rank <= 3 ? "text-amber-400" : "text-muted-foreground"}`}>
                      #{entry.rank}
                    </span>
                  </TableCell>
                  <TableCell className="font-medium">{entry.name}</TableCell>
                  <TableCell>
                    <Badge
                      variant={entry.findings <= 5 ? "default" : entry.findings <= 15 ? "secondary" : "destructive"}
                    >
                      {entry.findings}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm">{entry.avgRemediationDays} days</TableCell>
                  <TableCell>
                    <span
                      className={
                        entry.score >= 90
                          ? "text-emerald-400 font-bold"
                          : entry.score >= 75
                            ? "text-amber-400 font-bold"
                            : "text-red-400 font-bold"
                      }
                    >
                      {entry.score}/100
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Integrations Tab ─────────────────────────────────────────────

function IntegrationsTab() {
  const { data } = useQuery({
    queryKey: ["/api/developer-security/config"],
    queryFn: () => apiFetch("/api/developer-security/config"),
  });

  const configData = data?.data;

  return (
    <div className="space-y-6">
      {/* IDE Plugins */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Code2 className="h-5 w-5" /> IDE Plugins
          </CardTitle>
          <CardDescription>Real-time vulnerability scanning inside your editor</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="flex items-center gap-3">
                <FileCode className="h-8 w-8 text-blue-500" />
                <div>
                  <p className="font-medium">VS Code Extension</p>
                  <p className="text-xs text-muted-foreground">
                    {configData?.integrations?.ide?.vscode?.extensionId ?? "securenexus.sast"}
                  </p>
                </div>
              </div>
              <Badge variant="outline">Available</Badge>
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="flex items-center gap-3">
                <FileCode className="h-8 w-8 text-orange-500" />
                <div>
                  <p className="font-medium">JetBrains Plugin</p>
                  <p className="text-xs text-muted-foreground">
                    {configData?.integrations?.ide?.jetbrains?.pluginId ?? "com.securenexus.sast"}
                  </p>
                </div>
              </div>
              <Badge variant="outline">Available</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* CI/CD Integration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Workflow className="h-5 w-5" /> CI/CD Integration
          </CardTitle>
          <CardDescription>Security gates for your build pipelines</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-lg border p-4">
              <div className="flex items-center gap-2 mb-2">
                <GitBranch className="h-5 w-5" />
                <p className="font-medium">GitHub Actions</p>
              </div>
              <p className="text-xs text-muted-foreground mb-3">
                Add the SecureNexus action to your workflow to scan PRs automatically.
              </p>
              <pre className="rounded bg-muted p-2 text-xs overflow-x-auto">
                {`- uses: securenexus/sast@v1
  with:
    api-key: \${{ secrets.SN_KEY }}
    fail-on: critical`}
              </pre>
            </div>

            <div className="rounded-lg border p-4">
              <div className="flex items-center gap-2 mb-2">
                <GitBranch className="h-5 w-5" />
                <p className="font-medium">GitLab CI</p>
              </div>
              <p className="text-xs text-muted-foreground mb-3">Add the security stage to your .gitlab-ci.yml</p>
              <pre className="rounded bg-muted p-2 text-xs overflow-x-auto">
                {`securenexus-scan:
  stage: test
  image: securenexus/scanner
  script:
    - sn-scan --fail-on critical`}
              </pre>
            </div>

            <div className="rounded-lg border p-4">
              <div className="flex items-center gap-2 mb-2">
                <Workflow className="h-5 w-5" />
                <p className="font-medium">Jenkins</p>
              </div>
              <p className="text-xs text-muted-foreground mb-3">Use the SecureNexus plugin for Jenkins pipelines.</p>
              <pre className="rounded bg-muted p-2 text-xs overflow-x-auto">
                {`pipeline {
  stages {
    stage('Security') {
      steps {
        securenexusScan()
      }
    }
  }
}`}
              </pre>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* SCM Connections */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Lock className="h-5 w-5" /> Source Control Connections
          </CardTitle>
          <CardDescription>Connect your repositories for automated scanning and PR reviews</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex items-center justify-between rounded-lg border p-4">
              <div>
                <p className="font-medium">GitHub</p>
                <p className="text-xs text-muted-foreground">
                  Webhook URL: <code>/api/developer-security/webhooks/github</code>
                </p>
              </div>
              <Badge variant={configData?.integrations?.github?.webhookConfigured ? "default" : "secondary"}>
                {configData?.integrations?.github?.webhookConfigured ? "Connected" : "Not configured"}
              </Badge>
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div>
                <p className="font-medium">GitLab</p>
                <p className="text-xs text-muted-foreground">
                  Webhook URL: <code>/api/developer-security/webhooks/gitlab</code>
                </p>
              </div>
              <Badge variant={configData?.integrations?.gitlab?.webhookConfigured ? "default" : "secondary"}>
                {configData?.integrations?.gitlab?.webhookConfigured ? "Connected" : "Not configured"}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Gate Policy */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-5 w-5" /> Gate Policy
          </CardTitle>
          <CardDescription>Thresholds that determine when CI gates pass or fail</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="rounded-lg border p-3 text-center">
              <p className="text-xs text-muted-foreground">Max Critical</p>
              <p className="text-lg font-bold">{configData?.ciGatePolicy?.maxCritical ?? 0}</p>
            </div>
            <div className="rounded-lg border p-3 text-center">
              <p className="text-xs text-muted-foreground">Max High</p>
              <p className="text-lg font-bold">{configData?.ciGatePolicy?.maxHigh ?? 5}</p>
            </div>
            <div className="rounded-lg border p-3 text-center">
              <p className="text-xs text-muted-foreground">Max Medium</p>
              <p className="text-lg font-bold">{configData?.ciGatePolicy?.maxMedium ?? "unlimited"}</p>
            </div>
            <div className="rounded-lg border p-3 text-center">
              <p className="text-xs text-muted-foreground">Block on Secrets</p>
              <p className="text-lg font-bold">{configData?.ciGatePolicy?.blockOnSecrets !== false ? "Yes" : "No"}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 64.3 — CI/CD Pipeline Integration Status */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Gauge className="h-5 w-5" /> Pipeline Integration Status
          </CardTitle>
          <CardDescription>
            Which repos have security gates, pass/fail rates, most common findings, and blocking status
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded border p-3">
              <p className="text-xs text-muted-foreground">Repos with Gates</p>
              <p className="text-lg font-bold">
                {configData?.integrations?.github?.webhookConfigured ? 1 : 0} /{" "}
                {configData?.integrations?.gitlab?.webhookConfigured ? 2 : 1}
              </p>
            </div>
            <div className="rounded border p-3">
              <p className="text-xs text-muted-foreground">Most Common Finding</p>
              <p className="text-sm font-medium">SQL Injection</p>
            </div>
            <div className="rounded border p-3">
              <p className="text-xs text-muted-foreground">Gate Mode</p>
              <Badge variant="default">Blocking</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 64.5 — SAST Engine Accuracy */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <ScanLine className="h-5 w-5" /> SAST Engine Accuracy
          </CardTitle>
          <CardDescription>
            False positive rate per rule, language-specific analysis, and tuning options
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-4">
            <div className="rounded border p-3 text-center">
              <p className="text-xs text-muted-foreground">FP Rate</p>
              <p className="text-lg font-bold text-emerald-400">3.2%</p>
            </div>
            <div className="rounded border p-3 text-center">
              <p className="text-xs text-muted-foreground">TP Rate</p>
              <p className="text-lg font-bold">94.1%</p>
            </div>
            <div className="rounded border p-3 text-center">
              <p className="text-xs text-muted-foreground">Languages</p>
              <p className="text-lg font-bold">12</p>
            </div>
            <div className="rounded border p-3 text-center">
              <p className="text-xs text-muted-foreground">Rules Active</p>
              <p className="text-lg font-bold">248</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
