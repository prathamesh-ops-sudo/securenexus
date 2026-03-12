import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient, ensureArray } from "@/lib/queryClient";
import { formatDateTime as formatTimestamp } from "@/lib/i18n";
import { Textarea } from "@/components/ui/textarea";
import {
  Cloud,
  Shield,
  AlertTriangle,
  RefreshCw,
  Plus,
  Trash2,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Pencil,
  Loader2,
  FileCheck,
  GitCompare,
  Database,
  Route,
  Wrench,
  Eye,
  Zap,
  Lock,
  ShieldAlert,
  Target,
  ArrowRight,
} from "lucide-react";
import { SiAmazonwebservices, SiGooglecloud } from "react-icons/si";

interface PolicyCheck {
  id: string;
  orgId: string;
  name: string;
  description: string | null;
  cloudProvider: string | null;
  resourceType: string | null;
  severity: string;
  ruleLogic: any;
  remediation: string | null;
  complianceFrameworks: string[];
  controlIds: string[];
  status: string;
  isBuiltIn: boolean;
  lastRunAt: string | null;
  createdAt: string;
}

interface PolicyResult {
  id: string;
  orgId: string;
  policyCheckId: string;
  scanId: string | null;
  resourceId: string;
  resourceType: string | null;
  resourceRegion: string | null;
  status: string;
  details: any;
  evaluatedAt: string;
}

const PROVIDER_ICONS: Record<string, typeof Cloud> = {
  aws: SiAmazonwebservices as any,
  azure: Cloud,
  gcp: SiGooglecloud as any,
};

const PROVIDER_LABELS: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
};

function scanStatusStyle(status: string) {
  const styles: Record<string, string> = {
    completed: "bg-green-500/10 text-green-500 border-green-500/20",
    running: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20 animate-pulse",
    failed: "bg-red-500/10 text-red-500 border-red-500/20",
    pending: "bg-muted text-muted-foreground border-muted",
  };
  return styles[status] || "bg-muted text-muted-foreground border-muted";
}

function severityStyle(severity: string) {
  const styles: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    informational: "bg-muted text-muted-foreground border-muted",
  };
  return styles[severity] || "bg-muted text-muted-foreground border-muted";
}

function accountStatusStyle(status: string) {
  const styles: Record<string, string> = {
    active: "bg-green-500/10 text-green-500 border-green-500/20",
    inactive: "bg-muted text-muted-foreground border-muted",
    error: "bg-red-500/10 text-red-500 border-red-500/20",
  };
  return styles[status] || "bg-muted text-muted-foreground border-muted";
}

function CloudAccountsTab() {
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [provider, setProvider] = useState("aws");
  const [accountId, setAccountId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [regions, setRegions] = useState("");

  const {
    data: accounts,
    isPending,
    isError: accountsError,
    refetch: refetchAccounts,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/accounts"],
  });

  const addMutation = useMutation({
    mutationFn: async (body: any) => {
      await apiRequest("POST", "/api/cspm/accounts", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/accounts"] });
      setDialogOpen(false);
      setProvider("aws");
      setAccountId("");
      setDisplayName("");
      setRegions("");
      toast({ title: "Account added", description: "Cloud account has been connected." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to add account", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/cspm/accounts/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/accounts"] });
      toast({ title: "Account removed" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  const scanMutation = useMutation({
    mutationFn: async (accountId: string) => {
      await apiRequest("POST", `/api/cspm/scans/${accountId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/accounts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/scans"] });
      toast({ title: "Scan started", description: "Cloud security scan has been initiated." });
    },
    onError: (err: Error) => {
      toast({ title: "Scan failed", description: err.message, variant: "destructive" });
    },
  });

  function handleSubmit() {
    if (!accountId.trim() || !displayName.trim()) return;
    addMutation.mutate({
      cloudProvider: provider,
      accountId: accountId.trim(),
      displayName: displayName.trim(),
      regions: regions
        .trim()
        .split(",")
        .map((r: string) => r.trim())
        .filter(Boolean),
    });
  }

  if (isPending) {
    return (
      <div className="space-y-3" data-testid="accounts-loading">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-20 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (accountsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load cloud accounts</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchAccounts();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-cloud-accounts">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Cloud className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Cloud Accounts</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {accounts?.length ?? 0}
          </Badge>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-add-cloud-account">
              <Plus className="h-4 w-4 mr-2" />
              Add Account
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Cloud Account</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-2">
                <Label htmlFor="cloudProvider">Cloud Provider</Label>
                <Select value={provider} onValueChange={setProvider}>
                  <SelectTrigger data-testid="select-cloud-provider">
                    <SelectValue placeholder="Select provider" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="aws">AWS</SelectItem>
                    <SelectItem value="azure">Azure</SelectItem>
                    <SelectItem value="gcp">GCP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="accountId">Account ID</Label>
                <Input
                  id="accountId"
                  value={accountId}
                  onChange={(e) => setAccountId(e.target.value)}
                  placeholder="e.g. 123456789012"
                  data-testid="input-account-id"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="displayName">Display Name</Label>
                <Input
                  id="displayName"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Production AWS"
                  data-testid="input-display-name"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="regions">Regions (comma-separated)</Label>
                <Input
                  id="regions"
                  value={regions}
                  onChange={(e) => setRegions(e.target.value)}
                  placeholder="e.g. us-east-1, us-west-2"
                  data-testid="input-regions"
                />
              </div>
              <Button
                className="w-full"
                onClick={handleSubmit}
                disabled={addMutation.isPending || !accountId.trim() || !displayName.trim()}
                data-testid="button-submit-account"
              >
                {addMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4 mr-2" />
                )}
                Add Account
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {!accounts || accounts.length === 0 ? (
        <Card data-testid="empty-accounts">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Cloud className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No cloud accounts connected</p>
            <p className="text-xs text-muted-foreground mt-1">
              Add a cloud account to start scanning for security misconfigurations
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {accounts.map((account: any, idx: number) => {
            const ProviderIcon = PROVIDER_ICONS[account.cloudProvider] || Cloud;
            const regionList = (() => {
              try {
                if (Array.isArray(account.regions)) return account.regions;
                if (typeof account.regions === "string")
                  return account.regions
                    .split(",")
                    .map((r: string) => r.trim())
                    .filter(Boolean);
                return [];
              } catch {
                return [];
              }
            })();

            return (
              <Card key={account.id || idx} data-testid={`card-account-${account.id || idx}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      <div className="p-2 rounded-md bg-muted/50 flex-shrink-0">
                        <ProviderIcon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div className="min-w-0 flex-1 space-y-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className="text-sm font-semibold"
                            data-testid={`text-account-name-${account.id || idx}`}
                          >
                            {account.displayName || account.accountId}
                          </span>
                          <Badge
                            variant="outline"
                            className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                          >
                            {PROVIDER_LABELS[account.cloudProvider] || account.cloudProvider}
                          </Badge>
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${accountStatusStyle(account.status || "active")}`}
                            data-testid={`badge-account-status-${account.id || idx}`}
                          >
                            {account.status || "active"}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                          <span data-testid={`text-account-id-${account.id || idx}`}>
                            ID: <span className="font-mono font-medium text-foreground">{account.accountId}</span>
                          </span>
                          {account.lastScanAt && (
                            <span
                              className="flex items-center gap-1"
                              data-testid={`text-last-scan-${account.id || idx}`}
                            >
                              <Clock className="h-3 w-3" />
                              Last Scan: {formatTimestamp(account.lastScanAt)}
                            </span>
                          )}
                        </div>
                        {regionList.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {regionList.map((region: string, ri: number) => (
                              <Badge
                                key={ri}
                                variant="secondary"
                                className="text-[10px]"
                                data-testid={`badge-region-${account.id || idx}-${ri}`}
                              >
                                {region}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => scanMutation.mutate(account.id)}
                        disabled={scanMutation.isPending}
                        data-testid={`button-run-scan-${account.id || idx}`}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                      <Button size="icon" variant="ghost" data-testid={`button-edit-account-${account.id || idx}`}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteMutation.mutate(account.id)}
                        disabled={deleteMutation.isPending}
                        data-testid={`button-delete-account-${account.id || idx}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ScanHistoryTab() {
  const {
    data: scans,
    isPending,
    isError: scansError,
    refetch: refetchScans,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/scans"],
  });

  if (isPending) {
    return (
      <div className="space-y-3" data-testid="scans-loading">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (scansError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load scan history</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchScans()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-scan-history">
      <div className="flex items-center gap-2">
        <RefreshCw className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-lg font-semibold">Scan History</h2>
        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
          {scans?.length ?? 0}
        </Badge>
      </div>

      {!scans || scans.length === 0 ? (
        <Card data-testid="empty-scans">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <RefreshCw className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No scans recorded</p>
            <p className="text-xs text-muted-foreground mt-1">Run a scan on a cloud account to see results here</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {scans.map((scan: any, idx: number) => (
            <Card key={scan.id || idx} data-testid={`card-scan-${scan.id || idx}`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold" data-testid={`text-scan-account-${scan.id || idx}`}>
                        {scan.accountName || scan.accountId || `Scan #${scan.id}`}
                      </span>
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${scanStatusStyle(scan.status)}`}
                        data-testid={`badge-scan-status-${scan.id || idx}`}
                      >
                        {scan.status || "unknown"}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                      {scan.findingsCount != null && (
                        <span data-testid={`text-findings-count-${scan.id || idx}`}>
                          Findings: <span className="font-medium text-foreground">{scan.findingsCount}</span>
                        </span>
                      )}
                      {scan.startedAt && (
                        <span className="flex items-center gap-1" data-testid={`text-started-${scan.id || idx}`}>
                          <Clock className="h-3 w-3" />
                          Started: {formatTimestamp(scan.startedAt)}
                        </span>
                      )}
                      {scan.completedAt && (
                        <span data-testid={`text-completed-${scan.id || idx}`}>
                          Completed: {formatTimestamp(scan.completedAt)}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    {scan.status === "completed" ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : scan.status === "failed" ? (
                      <XCircle className="h-5 w-5 text-red-500" />
                    ) : scan.status === "running" ? (
                      <RefreshCw className="h-5 w-5 text-yellow-500 animate-spin" />
                    ) : (
                      <Clock className="h-5 w-5 text-muted-foreground" />
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function FindingsTab() {
  const { toast } = useToast();
  const [severityFilter, setSeverityFilter] = useState("all");

  const queryParams = severityFilter !== "all" ? `?severity=${severityFilter}` : "";

  const {
    data: findings,
    isPending,
    isError: findingsError,
    refetch: refetchFindings,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/findings", severityFilter],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/cspm/findings${queryParams}`);
      const raw = await res.json();
      return ensureArray(raw);
    },
  });

  const updateFindingMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      await apiRequest("PATCH", `/api/cspm/findings/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/findings"] });
      toast({ title: "Finding updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Update failed", description: err.message, variant: "destructive" });
    },
  });

  const safeFindingsArr = ensureArray(findings);
  const severityCounts = safeFindingsArr.reduce((acc: Record<string, number>, f: any) => {
    const sev = f.severity || "informational";
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  if (isPending) {
    return (
      <div className="space-y-3" data-testid="findings-loading">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-3">
                <Skeleton className="h-10 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (findingsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load findings</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchFindings()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-findings">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <AlertTriangle className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Findings</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {findings?.length ?? 0}
          </Badge>
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-44" data-testid="select-severity-filter">
            <SelectValue placeholder="Filter by severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3" data-testid="severity-summary">
        {(["critical", "high", "medium", "low", "informational"] as const).map((sev) => (
          <Card key={sev} data-testid={`stat-${sev}`}>
            <CardContent className="p-3">
              <div className="flex items-center justify-between gap-2">
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(sev)}`}
                >
                  {sev}
                </span>
                <span className="text-lg font-bold tabular-nums" data-testid={`value-${sev}-count`}>
                  {severityCounts[sev] || 0}
                </span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {!findings || findings.length === 0 ? (
        <Card data-testid="empty-findings">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Shield className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No findings</p>
            <p className="text-xs text-muted-foreground mt-1">
              {severityFilter !== "all"
                ? "No findings match the selected severity filter"
                : "Run a cloud scan to detect security findings"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {findings.map((finding: any, idx: number) => {
            const nextStatus =
              finding.status === "open" ? "resolved" : finding.status === "resolved" ? "suppressed" : "open";

            return (
              <Card key={finding.id || idx} data-testid={`card-finding-${finding.id || idx}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(finding.severity)}`}
                          data-testid={`badge-severity-${finding.id || idx}`}
                        >
                          {finding.severity || "unknown"}
                        </span>
                        <span className="text-sm font-semibold" data-testid={`text-rule-name-${finding.id || idx}`}>
                          {finding.ruleName || finding.ruleId || "Unknown Rule"}
                        </span>
                        {finding.status && (
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${finding.status === "open" ? "bg-red-500/10 text-red-500 border-red-500/20" : finding.status === "resolved" ? "bg-green-500/10 text-green-500 border-green-500/20" : "bg-muted text-muted-foreground border-muted"}`}
                            data-testid={`badge-finding-status-${finding.id || idx}`}
                          >
                            {finding.status}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        {finding.ruleId && (
                          <span data-testid={`text-rule-id-${finding.id || idx}`}>
                            Rule: <span className="font-mono font-medium text-foreground">{finding.ruleId}</span>
                          </span>
                        )}
                        {finding.resourceType && (
                          <span data-testid={`text-resource-type-${finding.id || idx}`}>
                            Resource: <span className="font-medium text-foreground">{finding.resourceType}</span>
                          </span>
                        )}
                        {finding.resourceId && (
                          <span data-testid={`text-resource-id-${finding.id || idx}`}>
                            ID: <span className="font-mono font-medium text-foreground">{finding.resourceId}</span>
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        {finding.region && (
                          <span data-testid={`text-region-${finding.id || idx}`}>
                            Region: <span className="font-medium text-foreground">{finding.region}</span>
                          </span>
                        )}
                        {finding.compliance && (
                          <span data-testid={`text-compliance-${finding.id || idx}`}>
                            Compliance: <span className="font-medium text-foreground">{finding.compliance}</span>
                          </span>
                        )}
                        {finding.detectedAt && (
                          <span className="flex items-center gap-1" data-testid={`text-detected-${finding.id || idx}`}>
                            <Clock className="h-3 w-3" />
                            {formatTimestamp(finding.detectedAt)}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => updateFindingMutation.mutate({ id: finding.id, status: nextStatus })}
                        disabled={updateFindingMutation.isPending}
                        data-testid={`button-toggle-status-${finding.id || idx}`}
                      >
                        {finding.status === "open" ? (
                          <CheckCircle2 className="h-4 w-4" />
                        ) : (
                          <XCircle className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function PolicyChecksTab() {
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [policyName, setPolicyName] = useState("");
  const [policyDescription, setPolicyDescription] = useState("");
  const [policyProvider, setPolicyProvider] = useState("aws");
  const [policyResourceType, setPolicyResourceType] = useState("");
  const [policySeverity, setPolicySeverity] = useState("medium");
  const [policyRemediation, setPolicyRemediation] = useState("");
  const [policyFrameworks, setPolicyFrameworks] = useState("");
  const [policyRuleLogic, setPolicyRuleLogic] = useState("");
  const [resultFilter, setResultFilter] = useState("all");

  const {
    data: policyChecks,
    isPending,
    isError: policyError,
    refetch: refetchPolicies,
  } = useQuery<PolicyCheck[]>({
    queryKey: ["/api/policy-checks"],
  });

  const { data: policyResults, isPending: resultsPending } = useQuery<PolicyResult[]>({
    queryKey: ["/api/policy-results"],
  });

  const createMutation = useMutation({
    mutationFn: async (body: any) => {
      await apiRequest("POST", "/api/policy-checks", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policy-checks"] });
      setDialogOpen(false);
      setPolicyName("");
      setPolicyDescription("");
      setPolicyProvider("aws");
      setPolicyResourceType("");
      setPolicySeverity("medium");
      setPolicyRemediation("");
      setPolicyFrameworks("");
      setPolicyRuleLogic("");
      toast({ title: "Policy created", description: "Policy check has been created." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create policy", description: err.message, variant: "destructive" });
    },
  });

  const runMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/policy-checks/${id}/run`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policy-checks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/policy-results"] });
      toast({ title: "Policy executed", description: "Policy check has been run." });
    },
    onError: (err: Error) => {
      toast({ title: "Run failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/policy-checks/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policy-checks"] });
      queryClient.invalidateQueries({ queryKey: ["/api/policy-results"] });
      toast({ title: "Policy deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  function handleCreateSubmit() {
    if (!policyName.trim()) return;
    let ruleLogic = {};
    try {
      ruleLogic = policyRuleLogic.trim() ? JSON.parse(policyRuleLogic) : {};
    } catch {
      toast({ title: "Invalid JSON", description: "Rule logic must be valid JSON.", variant: "destructive" });
      return;
    }
    createMutation.reset();
    createMutation.mutate({
      name: policyName.trim(),
      description: policyDescription.trim() || null,
      cloudProvider: policyProvider,
      resourceType: policyResourceType.trim() || null,
      severity: policySeverity,
      remediation: policyRemediation.trim() || null,
      complianceFrameworks: policyFrameworks
        .split(",")
        .map((f: string) => f.trim())
        .filter(Boolean),
      ruleLogic,
    });
  }

  const filteredResults = ensureArray<PolicyResult>(policyResults).filter((r: PolicyResult) =>
    resultFilter === "all" ? true : r.policyCheckId === resultFilter,
  );

  if (isPending) {
    return (
      <div className="space-y-3" data-testid="policy-checks-loading">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-20 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (policyError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load policy checks</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchPolicies()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="section-policy-checks">
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <FileCheck className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Policy-as-Code Checks</h2>
            <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
              {policyChecks?.length ?? 0}
            </Badge>
          </div>
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-create-policy">
                <Plus className="h-4 w-4 mr-2" />
                Create Policy
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Create Policy Check</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 pt-2">
                <div className="space-y-2">
                  <Label htmlFor="policyName">Name</Label>
                  <Input
                    id="policyName"
                    value={policyName}
                    onChange={(e) => setPolicyName(e.target.value)}
                    placeholder="e.g. S3 Public Access Check"
                    data-testid="input-policy-name"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policyDescription">Description</Label>
                  <Input
                    id="policyDescription"
                    value={policyDescription}
                    onChange={(e) => setPolicyDescription(e.target.value)}
                    placeholder="e.g. Ensures S3 buckets are not publicly accessible"
                    data-testid="input-policy-description"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policyProvider">Cloud Provider</Label>
                  <Select value={policyProvider} onValueChange={setPolicyProvider}>
                    <SelectTrigger data-testid="select-policy-provider">
                      <SelectValue placeholder="Select provider" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="aws">AWS</SelectItem>
                      <SelectItem value="azure">Azure</SelectItem>
                      <SelectItem value="gcp">GCP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policyResourceType">Resource Type</Label>
                  <Input
                    id="policyResourceType"
                    value={policyResourceType}
                    onChange={(e) => setPolicyResourceType(e.target.value)}
                    placeholder="e.g. aws_s3_bucket"
                    data-testid="input-policy-resource-type"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policySeverity">Severity</Label>
                  <Select value={policySeverity} onValueChange={setPolicySeverity}>
                    <SelectTrigger data-testid="select-policy-severity">
                      <SelectValue placeholder="Select severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="informational">Informational</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policyRemediation">Remediation</Label>
                  <Input
                    id="policyRemediation"
                    value={policyRemediation}
                    onChange={(e) => setPolicyRemediation(e.target.value)}
                    placeholder="e.g. Disable public access on the S3 bucket"
                    data-testid="input-policy-remediation"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policyFrameworks">Compliance Frameworks (comma-separated)</Label>
                  <Input
                    id="policyFrameworks"
                    value={policyFrameworks}
                    onChange={(e) => setPolicyFrameworks(e.target.value)}
                    placeholder="e.g. CIS, SOC2, HIPAA"
                    data-testid="input-policy-frameworks"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policyRuleLogic">Rule Logic (JSON)</Label>
                  <Textarea
                    id="policyRuleLogic"
                    value={policyRuleLogic}
                    onChange={(e) => setPolicyRuleLogic(e.target.value)}
                    placeholder={
                      '{\n  "condition": "AND",\n  "rules": [\n    {\n      "field": "publicAccess",\n      "operator": "equals",\n      "value": false\n    }\n  ]\n}'
                    }
                    className="font-mono text-sm min-h-[120px]"
                    data-testid="textarea-policy-rule-logic"
                  />
                </div>
                <Button
                  className="w-full"
                  onClick={handleCreateSubmit}
                  disabled={createMutation.isPending || !policyName.trim()}
                  data-testid="button-submit-policy"
                >
                  {createMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4 mr-2" />
                  )}
                  Create Policy
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        {!policyChecks || policyChecks.length === 0 ? (
          <Card data-testid="empty-policy-checks">
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <FileCheck className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No policy checks configured</p>
              <p className="text-xs text-muted-foreground mt-1">
                Create a policy check to start evaluating cloud resources
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {policyChecks.map((policy: PolicyCheck, idx: number) => {
              const ProviderIcon = PROVIDER_ICONS[policy.cloudProvider || ""] || Cloud;
              return (
                <Card key={policy.id || idx} data-testid={`card-policy-${policy.id || idx}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="flex items-start gap-3 min-w-0 flex-1">
                        <div className="p-2 rounded-md bg-muted/50 flex-shrink-0">
                          <ProviderIcon className="h-4 w-4 text-muted-foreground" />
                        </div>
                        <div className="min-w-0 flex-1 space-y-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className="text-sm font-semibold"
                              data-testid={`text-policy-name-${policy.id || idx}`}
                            >
                              {policy.name}
                            </span>
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(policy.severity)}`}
                              data-testid={`badge-policy-severity-${policy.id || idx}`}
                            >
                              {policy.severity}
                            </span>
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${policy.status === "active" ? "bg-green-500/10 text-green-500 border-green-500/20" : "bg-muted text-muted-foreground border-muted"}`}
                              data-testid={`badge-policy-status-${policy.id || idx}`}
                            >
                              {policy.status}
                            </span>
                            {policy.cloudProvider && (
                              <Badge
                                variant="outline"
                                className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                              >
                                {PROVIDER_LABELS[policy.cloudProvider] || policy.cloudProvider}
                              </Badge>
                            )}
                          </div>
                          {policy.description && (
                            <p
                              className="text-xs text-muted-foreground"
                              data-testid={`text-policy-description-${policy.id || idx}`}
                            >
                              {policy.description}
                            </p>
                          )}
                          <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                            {policy.resourceType && (
                              <span data-testid={`text-policy-resource-type-${policy.id || idx}`}>
                                Resource: <span className="font-medium text-foreground">{policy.resourceType}</span>
                              </span>
                            )}
                            {policy.lastRunAt && (
                              <span
                                className="flex items-center gap-1"
                                data-testid={`text-policy-last-run-${policy.id || idx}`}
                              >
                                <Clock className="h-3 w-3" />
                                Last Run: {formatTimestamp(policy.lastRunAt)}
                              </span>
                            )}
                          </div>
                          {policy.complianceFrameworks && policy.complianceFrameworks.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {policy.complianceFrameworks.map((fw: string, fi: number) => (
                                <Badge
                                  key={fi}
                                  variant="secondary"
                                  className="text-[10px]"
                                  data-testid={`badge-policy-framework-${policy.id || idx}-${fi}`}
                                >
                                  {fw}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => runMutation.mutate(policy.id)}
                          disabled={runMutation.isPending}
                          data-testid={`button-run-policy-${policy.id || idx}`}
                        >
                          {runMutation.isPending ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Play className="h-4 w-4" />
                          )}
                        </Button>
                        <Button size="icon" variant="ghost" data-testid={`button-edit-policy-${policy.id || idx}`}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteMutation.mutate(policy.id)}
                          disabled={deleteMutation.isPending}
                          data-testid={`button-delete-policy-${policy.id || idx}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <Shield className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Policy Results</h2>
            <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
              {filteredResults.length}
            </Badge>
          </div>
          <Select value={resultFilter} onValueChange={setResultFilter}>
            <SelectTrigger className="w-52" data-testid="select-result-filter">
              <SelectValue placeholder="Filter by policy" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Policies</SelectItem>
              {(policyChecks || []).map((p: PolicyCheck) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {resultsPending ? (
          <div className="space-y-3" data-testid="policy-results-loading">
            {Array.from({ length: 3 }).map((_, i) => (
              <Card key={i}>
                <CardContent className="p-4">
                  <Skeleton className="h-16 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filteredResults.length === 0 ? (
          <Card data-testid="empty-policy-results">
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <Shield className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No policy results</p>
              <p className="text-xs text-muted-foreground mt-1">Run a policy check to see evaluation results</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {filteredResults.map((result: PolicyResult, idx: number) => {
              const policyName =
                (policyChecks || []).find((p: PolicyCheck) => p.id === result.policyCheckId)?.name ||
                result.policyCheckId;
              return (
                <Card key={result.id || idx} data-testid={`card-result-${result.id || idx}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="min-w-0 flex-1 space-y-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${result.status === "pass" ? "bg-green-500/10 text-green-500 border-green-500/20" : result.status === "fail" ? "bg-red-500/10 text-red-500 border-red-500/20" : "bg-muted text-muted-foreground border-muted"}`}
                            data-testid={`badge-result-status-${result.id || idx}`}
                          >
                            {result.status}
                          </span>
                          <span
                            className="text-sm font-semibold"
                            data-testid={`text-result-policy-${result.id || idx}`}
                          >
                            {policyName}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                          <span data-testid={`text-result-resource-${result.id || idx}`}>
                            Resource: <span className="font-mono font-medium text-foreground">{result.resourceId}</span>
                          </span>
                          {result.resourceType && (
                            <span data-testid={`text-result-type-${result.id || idx}`}>
                              Type: <span className="font-medium text-foreground">{result.resourceType}</span>
                            </span>
                          )}
                          {result.resourceRegion && (
                            <span data-testid={`text-result-region-${result.id || idx}`}>
                              Region: <span className="font-medium text-foreground">{result.resourceRegion}</span>
                            </span>
                          )}
                          <span
                            className="flex items-center gap-1"
                            data-testid={`text-result-evaluated-${result.id || idx}`}
                          >
                            <Clock className="h-3 w-3" />
                            {formatTimestamp(result.evaluatedAt)}
                          </span>
                        </div>
                      </div>
                      <div className="flex-shrink-0">
                        {result.status === "pass" ? (
                          <CheckCircle2 className="h-5 w-5 text-green-500" />
                        ) : result.status === "fail" ? (
                          <XCircle className="h-5 w-5 text-red-500" />
                        ) : (
                          <Clock className="h-5 w-5 text-muted-foreground" />
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Drift Detection Tab ──
function DriftDetectionTab() {
  const { toast } = useToast();

  const { data: accounts } = useQuery<any[]>({
    queryKey: ["/api/cspm/accounts"],
  });

  const {
    data: driftEvents,
    isPending,
    isError,
    refetch: refetchEvents,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/drift/events"],
  });

  const { data: baselines } = useQuery<any[]>({
    queryKey: ["/api/cspm/drift/baselines"],
  });

  const baselineMutation = useMutation({
    mutationFn: async (accountId: string) => {
      await apiRequest("POST", `/api/cspm/drift/baseline/${accountId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/drift/baselines"] });
      toast({ title: "Baseline created", description: "Drift baseline snapshot saved." });
    },
    onError: (err: Error) => {
      toast({ title: "Baseline failed", description: err.message, variant: "destructive" });
    },
  });

  const detectMutation = useMutation({
    mutationFn: async (accountId: string) => {
      const res = await apiRequest("POST", `/api/cspm/drift/detect/${accountId}`);
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/drift/events"] });
      toast({
        title: "Drift detection complete",
        description: `${data.driftEventsDetected || 0} drift events detected.`,
      });
    },
    onError: (err: Error) => {
      toast({ title: "Detection failed", description: err.message, variant: "destructive" });
    },
  });

  const safeEvents = ensureArray(driftEvents);
  const safeAccounts = ensureArray(accounts);
  const safeBaselines = ensureArray(baselines);

  if (isPending) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load drift events</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchEvents()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-drift-detection">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <GitCompare className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Drift Detection</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {safeEvents.length} events
          </Badge>
        </div>
      </div>

      {/* Account actions */}
      {safeAccounts.length > 0 && (
        <Card>
          <CardContent className="p-4 space-y-3">
            <p className="text-sm font-medium">Manage Baselines & Run Detection</p>
            <div className="flex flex-wrap gap-2">
              {safeAccounts.map((acc: any) => (
                <div key={acc.id} className="flex items-center gap-1 border rounded-md p-2">
                  <span className="text-xs font-medium mr-2">{acc.displayName || acc.accountId}</span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => baselineMutation.mutate(acc.id)}
                    disabled={baselineMutation.isPending}
                    className="text-xs h-7"
                  >
                    <Target className="h-3 w-3 mr-1" />
                    Set Baseline
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => detectMutation.mutate(acc.id)}
                    disabled={detectMutation.isPending}
                    className="text-xs h-7"
                  >
                    <GitCompare className="h-3 w-3 mr-1" />
                    Detect Drift
                  </Button>
                </div>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">{safeBaselines.length} baseline snapshots stored</p>
          </CardContent>
        </Card>
      )}

      {/* Drift events list */}
      {safeEvents.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <GitCompare className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No drift events detected</p>
            <p className="text-xs text-muted-foreground mt-1">
              Set a baseline on a cloud account, then run drift detection to find configuration changes
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {safeEvents.map((event: any, idx: number) => (
            <Card key={event.id || idx}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(event.severity)}`}
                      >
                        {event.severity}
                      </span>
                      <Badge variant="outline" className="text-[10px]">
                        {event.driftType}
                      </Badge>
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${
                          event.status === "open"
                            ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
                            : event.status === "resolved"
                              ? "bg-green-500/10 text-green-500 border-green-500/20"
                              : "bg-muted text-muted-foreground border-muted"
                        }`}
                      >
                        {event.status}
                      </span>
                    </div>
                    <p className="text-sm">{event.description}</p>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                      <span className="font-mono">{event.resourceId}</span>
                      <span>{event.resourceType}</span>
                      {event.field && event.field !== "*" && (
                        <span>
                          Field: <span className="font-mono">{event.field}</span>
                        </span>
                      )}
                      {event.detectedAt && <span>{formatTimestamp(event.detectedAt)}</span>}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── DSPM Tab ──
function DSPMTab() {
  const { toast } = useToast();

  const { data: accounts } = useQuery<any[]>({
    queryKey: ["/api/cspm/accounts"],
  });

  const {
    data: dspmFindings,
    isPending,
    isError,
    refetch: refetchDspm,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/dspm/findings"],
  });

  const scanMutation = useMutation({
    mutationFn: async (accountId: string) => {
      const res = await apiRequest("POST", `/api/cspm/dspm/scan/${accountId}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cspm/dspm/findings"] });
      toast({ title: "DSPM scan complete", description: "Sensitive data scan finished." });
    },
    onError: (err: Error) => {
      toast({ title: "DSPM scan failed", description: err.message, variant: "destructive" });
    },
  });

  const safeFindings = ensureArray(dspmFindings);
  const safeAccounts = ensureArray(accounts);

  const sensitivityCounts = {
    critical: safeFindings.filter((f: any) => f.sensitivityLevel === "critical").length,
    high: safeFindings.filter((f: any) => f.sensitivityLevel === "high").length,
    medium: safeFindings.filter((f: any) => f.sensitivityLevel === "medium").length,
    low: safeFindings.filter((f: any) => f.sensitivityLevel === "low").length,
  };

  if (isPending) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load DSPM findings</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchDspm()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-dspm">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Database className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Data Security Posture (DSPM)</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {safeFindings.length} findings
          </Badge>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {(["critical", "high", "medium", "low"] as const).map((level) => (
          <Card key={level}>
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold">{sensitivityCounts[level]}</p>
              <p
                className={`text-xs font-medium uppercase ${
                  level === "critical"
                    ? "text-red-500"
                    : level === "high"
                      ? "text-orange-500"
                      : level === "medium"
                        ? "text-yellow-500"
                        : "text-blue-500"
                }`}
              >
                {level}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Scan trigger */}
      {safeAccounts.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {safeAccounts
            .filter((a: any) => a.cloudProvider === "aws")
            .map((acc: any) => (
              <Button
                key={acc.id}
                size="sm"
                variant="outline"
                onClick={() => scanMutation.mutate(acc.id)}
                disabled={scanMutation.isPending}
              >
                {scanMutation.isPending ? (
                  <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                ) : (
                  <Eye className="h-3 w-3 mr-1" />
                )}
                Scan {acc.displayName || acc.accountId}
              </Button>
            ))}
        </div>
      )}

      {/* Findings list */}
      {safeFindings.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Database className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No sensitive data findings</p>
            <p className="text-xs text-muted-foreground mt-1">
              Run a DSPM scan on an AWS account to discover sensitive data in S3 buckets
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {safeFindings.map((finding: any, idx: number) => (
            <Card key={finding.id || idx}>
              <CardContent className="p-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(finding.sensitivityLevel)}`}
                    >
                      {finding.sensitivityLevel}
                    </span>
                    <Badge variant="outline" className="text-[10px]">
                      {finding.dataClassification}
                    </Badge>
                    {finding.isEncrypted ? (
                      <Badge variant="secondary" className="text-[10px]">
                        <Lock className="h-3 w-3 mr-1" />
                        Encrypted
                      </Badge>
                    ) : (
                      <Badge variant="destructive" className="text-[10px]">
                        <ShieldAlert className="h-3 w-3 mr-1" />
                        Unencrypted
                      </Badge>
                    )}
                    {finding.isPubliclyAccessible && (
                      <Badge variant="destructive" className="text-[10px]">
                        Public
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm font-mono">{finding.resourceId}</p>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                    <span>{finding.resourceType}</span>
                    {finding.objectCount > 0 && <span>{finding.objectCount} objects</span>}
                    {ensureArray(finding.dataCategories).length > 0 && (
                      <span>Categories: {ensureArray(finding.dataCategories).join(", ")}</span>
                    )}
                    {finding.detectedAt && <span>{formatTimestamp(finding.detectedAt)}</span>}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Attack Paths Tab ──
function AttackPathsTab() {
  const {
    data: attackPaths,
    isPending,
    isError,
    refetch: refetchPaths,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/attack-paths"],
  });

  const safePaths = ensureArray(attackPaths);

  if (isPending) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-20 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load attack paths</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchPaths()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-attack-paths">
      <div className="flex items-center gap-2">
        <Route className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-lg font-semibold">Attack Paths</h2>
        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
          {safePaths.length}
        </Badge>
      </div>

      {safePaths.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Route className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No attack paths detected</p>
            <p className="text-xs text-muted-foreground mt-1">
              Run a CSPM scan to discover multi-cloud attack paths across your infrastructure
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {safePaths.map((path: any, idx: number) => {
            const nodes = ensureArray(path.nodes);
            const edges = ensureArray(path.edges);
            const mitigations = ensureArray(path.mitigations);

            return (
              <Card key={path.id || idx}>
                <CardContent className="p-4 space-y-3">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(path.severity)}`}
                        >
                          {path.severity}
                        </span>
                        {path.isCrossCloud && (
                          <Badge variant="secondary" className="text-[10px]">
                            Cross-Cloud
                          </Badge>
                        )}
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${
                            path.status === "active"
                              ? "bg-red-500/10 text-red-500 border-red-500/20"
                              : path.status === "mitigated"
                                ? "bg-green-500/10 text-green-500 border-green-500/20"
                                : "bg-muted text-muted-foreground border-muted"
                          }`}
                        >
                          {path.status}
                        </span>
                      </div>
                      <p className="text-sm font-medium">{path.name}</p>
                      <p className="text-xs text-muted-foreground">{path.description}</p>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-2xl font-bold">{path.riskScore || 0}</p>
                      <p className="text-[10px] text-muted-foreground uppercase">Risk Score</p>
                    </div>
                  </div>

                  {/* Attack path visualization */}
                  {nodes.length > 0 && (
                    <div className="flex items-center gap-1 overflow-x-auto py-2">
                      {nodes.map((node: any, ni: number) => (
                        <div key={ni} className="flex items-center gap-1 flex-shrink-0">
                          <div
                            className="border rounded-md px-2 py-1 text-[10px] bg-muted/50 max-w-[150px] truncate"
                            title={node.resourceId}
                          >
                            <span className="font-medium">{node.label || node.resourceId}</span>
                            {node.provider && <span className="ml-1 opacity-60">({node.provider})</span>}
                          </div>
                          {ni < nodes.length - 1 && (
                            <ArrowRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Mitigations */}
                  {mitigations.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs font-medium text-muted-foreground">Mitigations:</p>
                      <ul className="text-xs text-muted-foreground space-y-0.5 list-disc list-inside">
                        {mitigations.map((m: unknown, mi: number) => (
                          <li key={mi}>{String(m)}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Remediation Tab ──
function RemediationTab() {
  const { toast } = useToast();

  const { data: playbooks, isPending: playbooksPending } = useQuery<any[]>({
    queryKey: ["/api/cspm/remediation/playbooks"],
  });

  const {
    data: remediations,
    isPending,
    isError,
    refetch: refetchRemediations,
  } = useQuery<any[]>({
    queryKey: ["/api/cspm/remediations"],
  });

  const safePlaybooks = ensureArray(playbooks);
  const safeRemediations = ensureArray(remediations);

  if (isPending) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load remediations</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchRemediations()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-remediation">
      <div className="flex items-center gap-2">
        <Wrench className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-lg font-semibold">Auto-Remediation</h2>
        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
          {safeRemediations.length} executed
        </Badge>
      </div>

      {/* Available playbooks */}
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-muted-foreground" />
            <p className="text-sm font-medium">Available Playbooks</p>
            <Badge variant="outline" className="text-[10px]">
              {safePlaybooks.length}
            </Badge>
          </div>
          {playbooksPending ? (
            <Skeleton className="h-20 w-full" />
          ) : safePlaybooks.length === 0 ? (
            <p className="text-xs text-muted-foreground">No playbooks available</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {safePlaybooks.map((pb: any, idx: number) => (
                <div key={pb.id || idx} className="border rounded-md p-3 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium">{pb.name}</span>
                    <Badge
                      variant={
                        pb.riskLevel === "safe" ? "secondary" : pb.riskLevel === "moderate" ? "outline" : "destructive"
                      }
                      className="text-[10px]"
                    >
                      {pb.riskLevel}
                    </Badge>
                    {pb.requiresApproval && (
                      <Badge variant="outline" className="text-[10px]">
                        Requires Approval
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">{pb.description}</p>
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                    <span>
                      Rule: <span className="font-mono">{pb.ruleId}</span>
                    </span>
                    <span>Provider: {pb.provider}</span>
                    <span>{pb.actions?.length || 0} steps</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Remediation history */}
      {safeRemediations.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Wrench className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No remediations executed yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Execute a remediation playbook on a finding to see results here
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {safeRemediations.map((rem: any, idx: number) => (
            <Card key={rem.id || idx}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      {rem.status === "success" ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : rem.status === "failed" ? (
                        <XCircle className="h-4 w-4 text-red-500" />
                      ) : (
                        <Clock className="h-4 w-4 text-yellow-500" />
                      )}
                      <span className="text-sm font-medium">{rem.playbookName}</span>
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${
                          rem.status === "success"
                            ? "bg-green-500/10 text-green-500 border-green-500/20"
                            : rem.status === "failed"
                              ? "bg-red-500/10 text-red-500 border-red-500/20"
                              : rem.status === "partial"
                                ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
                                : "bg-muted text-muted-foreground border-muted"
                        }`}
                      >
                        {rem.status}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground font-mono">{rem.resourceId}</p>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                      <span>
                        Rule: <span className="font-mono">{rem.ruleId}</span>
                      </span>
                      <span>
                        Steps: {rem.actionsExecuted}/{rem.actionsTotal}
                      </span>
                      {rem.error && <span className="text-red-500">{rem.error}</span>}
                      {rem.executedAt && <span>{formatTimestamp(rem.executedAt)}</span>}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export default function CSPMPage() {
  const [activeTab, setActiveTab] = useState("accounts");

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-cspm">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Cloud Security Posture</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Monitor and remediate cloud security misconfigurations across AWS, Azure, and GCP
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList data-testid="tabs-cspm" className="flex-wrap h-auto gap-1">
          <TabsTrigger value="accounts" data-testid="tab-cloud-accounts">
            <Cloud className="h-4 w-4 mr-1.5" />
            Accounts
          </TabsTrigger>
          <TabsTrigger value="scans" data-testid="tab-scan-history">
            <RefreshCw className="h-4 w-4 mr-1.5" />
            Scans
          </TabsTrigger>
          <TabsTrigger value="findings" data-testid="tab-findings">
            <AlertTriangle className="h-4 w-4 mr-1.5" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="policy-checks" data-testid="tab-policy-checks">
            <FileCheck className="h-4 w-4 mr-1.5" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="drift" data-testid="tab-drift-detection">
            <GitCompare className="h-4 w-4 mr-1.5" />
            Drift
          </TabsTrigger>
          <TabsTrigger value="dspm" data-testid="tab-dspm">
            <Database className="h-4 w-4 mr-1.5" />
            DSPM
          </TabsTrigger>
          <TabsTrigger value="attack-paths" data-testid="tab-attack-paths">
            <Route className="h-4 w-4 mr-1.5" />
            Attack Paths
          </TabsTrigger>
          <TabsTrigger value="remediation" data-testid="tab-remediation">
            <Wrench className="h-4 w-4 mr-1.5" />
            Remediation
          </TabsTrigger>
        </TabsList>

        <TabsContent value="accounts" className="mt-3">
          <CloudAccountsTab />
        </TabsContent>

        <TabsContent value="scans" className="mt-3">
          <ScanHistoryTab />
        </TabsContent>

        <TabsContent value="findings" className="mt-3">
          <FindingsTab />
        </TabsContent>

        <TabsContent value="policy-checks" className="mt-3">
          <PolicyChecksTab />
        </TabsContent>

        <TabsContent value="drift" className="mt-3">
          <DriftDetectionTab />
        </TabsContent>

        <TabsContent value="dspm" className="mt-3">
          <DSPMTab />
        </TabsContent>

        <TabsContent value="attack-paths" className="mt-3">
          <AttackPathsTab />
        </TabsContent>

        <TabsContent value="remediation" className="mt-3">
          <RemediationTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
