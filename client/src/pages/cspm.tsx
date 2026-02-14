import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Cloud, Shield, AlertTriangle, RefreshCw, Plus, Trash2, Play,
  CheckCircle2, XCircle, Clock, Pencil,
} from "lucide-react";
import { SiAmazonwebservices, SiGooglecloud } from "react-icons/si";

function formatTimestamp(date: string | Date | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
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

  const { data: accounts, isLoading } = useQuery<any[]>({
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
      regions: regions.trim().split(",").map((r: string) => r.trim()).filter(Boolean),
    });
  }

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="accounts-loading">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4"><Skeleton className="h-20 w-full" /></CardContent>
          </Card>
        ))}
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
            <p className="text-xs text-muted-foreground mt-1">Add a cloud account to start scanning for security misconfigurations</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {accounts.map((account: any, idx: number) => {
            const ProviderIcon = PROVIDER_ICONS[account.cloudProvider] || Cloud;
            const regionList = (() => {
              try {
                if (Array.isArray(account.regions)) return account.regions;
                if (typeof account.regions === "string") return account.regions.split(",").map((r: string) => r.trim()).filter(Boolean);
                return [];
              } catch { return []; }
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
                          <span className="text-sm font-semibold" data-testid={`text-account-name-${account.id || idx}`}>
                            {account.displayName || account.accountId}
                          </span>
                          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase">
                            {PROVIDER_LABELS[account.cloudProvider] || account.cloudProvider}
                          </Badge>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${accountStatusStyle(account.status || "active")}`} data-testid={`badge-account-status-${account.id || idx}`}>
                            {account.status || "active"}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                          <span data-testid={`text-account-id-${account.id || idx}`}>
                            ID: <span className="font-mono font-medium text-foreground">{account.accountId}</span>
                          </span>
                          {account.lastScanAt && (
                            <span className="flex items-center gap-1" data-testid={`text-last-scan-${account.id || idx}`}>
                              <Clock className="h-3 w-3" />
                              Last Scan: {formatTimestamp(account.lastScanAt)}
                            </span>
                          )}
                        </div>
                        {regionList.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {regionList.map((region: string, ri: number) => (
                              <Badge key={ri} variant="secondary" className="text-[10px]" data-testid={`badge-region-${account.id || idx}-${ri}`}>
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
                      <Button
                        size="icon"
                        variant="ghost"
                        data-testid={`button-edit-account-${account.id || idx}`}
                      >
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
  const { data: scans, isLoading } = useQuery<any[]>({
    queryKey: ["/api/cspm/scans"],
  });

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="scans-loading">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4"><Skeleton className="h-16 w-full" /></CardContent>
          </Card>
        ))}
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
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${scanStatusStyle(scan.status)}`} data-testid={`badge-scan-status-${scan.id || idx}`}>
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

  const { data: findings, isLoading } = useQuery<any[]>({
    queryKey: ["/api/cspm/findings", severityFilter],
    queryFn: async () => {
      const res = await fetch(`/api/cspm/findings${queryParams}`, { credentials: "include" });
      if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
      return res.json();
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

  const severityCounts = (findings || []).reduce((acc: Record<string, number>, f: any) => {
    const sev = f.severity || "informational";
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="findings-loading">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-3"><Skeleton className="h-10 w-full" /></CardContent>
            </Card>
          ))}
        </div>
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4"><Skeleton className="h-16 w-full" /></CardContent>
          </Card>
        ))}
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
                <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(sev)}`}>
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
              {severityFilter !== "all" ? "No findings match the selected severity filter" : "Run a cloud scan to detect security findings"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {findings.map((finding: any, idx: number) => {
            const nextStatus = finding.status === "open" ? "resolved" : finding.status === "resolved" ? "suppressed" : "open";

            return (
              <Card key={finding.id || idx} data-testid={`card-finding-${finding.id || idx}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(finding.severity)}`} data-testid={`badge-severity-${finding.id || idx}`}>
                          {finding.severity || "unknown"}
                        </span>
                        <span className="text-sm font-semibold" data-testid={`text-rule-name-${finding.id || idx}`}>
                          {finding.ruleName || finding.ruleId || "Unknown Rule"}
                        </span>
                        {finding.status && (
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${finding.status === "open" ? "bg-red-500/10 text-red-500 border-red-500/20" : finding.status === "resolved" ? "bg-green-500/10 text-green-500 border-green-500/20" : "bg-muted text-muted-foreground border-muted"}`} data-testid={`badge-finding-status-${finding.id || idx}`}>
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
        <TabsList data-testid="tabs-cspm">
          <TabsTrigger value="accounts" data-testid="tab-cloud-accounts">
            <Cloud className="h-4 w-4 mr-1.5" />
            Cloud Accounts
          </TabsTrigger>
          <TabsTrigger value="scans" data-testid="tab-scan-history">
            <RefreshCw className="h-4 w-4 mr-1.5" />
            Scan History
          </TabsTrigger>
          <TabsTrigger value="findings" data-testid="tab-findings">
            <AlertTriangle className="h-4 w-4 mr-1.5" />
            Findings
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
      </Tabs>
    </div>
  );
}
