import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  Database,
  Shield,
  FileText,
  Search,
  Download,
  Plus,
  RefreshCw,
  Archive,
  Clock,
  HardDrive,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Scale,
  Lock,
  Unlock,
  Trash2,
  Play,
  Layers,
  DollarSign,
  BookOpen,
  Settings,
  Wrench,
  GitBranch,
  Gauge,
  TrendingUp,
  ArrowRight,
  BarChart3,
  Eye,
  Zap,
  ChevronDown,
} from "lucide-react";
import { TablePageSkeleton } from "@/components/page-skeleton";

const apiRequest = async (url: string, options?: RequestInit) => {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta?.getAttribute("content") || "";
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": csrfToken,
      ...options?.headers,
    },
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.errors?.[0]?.message || `Request failed: ${res.status}`);
  }
  return res.json();
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatDate(date: string | Date | null): string {
  if (!date) return "-";
  return new Date(date).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const DATA_TYPES = [
  "alerts",
  "incidents",
  "audit_logs",
  "sli_metrics",
  "jobs",
  "connector_job_runs",
  "outbox_events",
  "ingestion_logs",
];

const FRAMEWORKS = [
  { value: "gdpr", label: "GDPR", desc: "90 days" },
  { value: "sox", label: "SOX", desc: "7 years" },
  { value: "hipaa", label: "HIPAA", desc: "6 years" },
  { value: "pci_dss", label: "PCI DSS", desc: "1 year" },
  { value: "iso27001", label: "ISO 27001", desc: "3 years" },
  { value: "nist", label: "NIST", desc: "3 years" },
  { value: "custom", label: "Custom", desc: "Custom" },
];

function StatusBadge({ status }: { status: string }) {
  const variants: Record<
    string,
    { variant: "default" | "secondary" | "destructive" | "outline"; icon: React.ReactNode }
  > = {
    completed: { variant: "default", icon: <CheckCircle className="h-3 w-3" /> },
    ready: { variant: "default", icon: <CheckCircle className="h-3 w-3" /> },
    running: { variant: "secondary", icon: <Loader2 className="h-3 w-3 animate-spin" /> },
    processing: { variant: "secondary", icon: <Loader2 className="h-3 w-3 animate-spin" /> },
    pending: { variant: "outline", icon: <Clock className="h-3 w-3" /> },
    requested: { variant: "outline", icon: <Clock className="h-3 w-3" /> },
    failed: { variant: "destructive", icon: <XCircle className="h-3 w-3" /> },
    expired: { variant: "destructive", icon: <AlertTriangle className="h-3 w-3" /> },
    downloaded: { variant: "default", icon: <Download className="h-3 w-3" /> },
    cancelled: { variant: "outline", icon: <XCircle className="h-3 w-3" /> },
  };
  const v = variants[status] || { variant: "outline" as const, icon: null };
  return (
    <Badge variant={v.variant} className="gap-1">
      {v.icon}
      {status}
    </Badge>
  );
}

// ─── Overview Tab ───────────────────────────────────────────────────────────

function OverviewTab() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-lake/overview"],
    queryFn: () => apiRequest("/api/data-lake/overview").then((r) => r.data || r),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const storage = data?.storage || {};
  const policies = data?.retentionPolicies || [];
  const holds = data?.legalHolds || [];
  const exports = data?.eDiscoveryExports || [];

  return (
    <div className="space-y-6">
      {/* Storage Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Cold Storage Records</CardDescription>
            <CardTitle className="text-2xl">{(storage.totalColdRecords || 0).toLocaleString()}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">{formatBytes(storage.totalColdSizeBytes || 0)} compressed</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active Policies</CardDescription>
            <CardTitle className="text-2xl">{storage.activePolicies || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">Retention policies configured</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Legal Holds</CardDescription>
            <CardTitle className="text-2xl">{holds.filter((h: any) => h.isActive).length}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-1">
              {storage.legalHoldActive ? (
                <Badge variant="destructive" className="gap-1">
                  <Lock className="h-3 w-3" /> Active Hold
                </Badge>
              ) : (
                <Badge variant="outline" className="gap-1">
                  <Unlock className="h-3 w-3" /> No Holds
                </Badge>
              )}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>eDiscovery Exports</CardDescription>
            <CardTitle className="text-2xl">{exports.length}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              {exports.filter((e: any) => e.status === "ready").length} ready for download
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Storage by Data Type */}
      {Object.keys(storage.byDataType || {}).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Storage by Data Type</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Data Type</TableHead>
                  <TableHead className="text-right">Records</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead className="text-right">Files</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(storage.byDataType || {}).map(([type, stats]: [string, any]) => (
                  <TableRow key={type}>
                    <TableCell className="font-mono text-sm">{type}</TableCell>
                    <TableCell className="text-right">{stats.records.toLocaleString()}</TableCell>
                    <TableCell className="text-right">{formatBytes(stats.sizeBytes)}</TableCell>
                    <TableCell className="text-right">{stats.files}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Recent Tiering Jobs */}
      {(storage.recentJobs || []).length > 0 && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">Recent Tiering Jobs</CardTitle>
            <Button variant="ghost" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Data Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Records</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(storage.recentJobs || []).slice(0, 10).map((job: any) => (
                  <TableRow key={job.id}>
                    <TableCell className="font-mono text-sm">{job.dataType}</TableCell>
                    <TableCell>
                      <StatusBadge status={job.status} />
                    </TableCell>
                    <TableCell className="text-right">{(job.recordCount || 0).toLocaleString()}</TableCell>
                    <TableCell className="text-right">{formatBytes(job.compressedSizeBytes || 0)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(job.createdAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Retention Policies Tab ─────────────────────────────────────────────────

function RetentionPoliciesTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    name: "",
    dataType: "alerts",
    complianceFramework: "custom",
    hotRetentionDays: 90,
    warmRetentionDays: 365,
    coldRetentionDays: 2555,
    purgeAfterDays: null as number | null,
    compressionFormat: "parquet",
  });

  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-lake/retention-policies"],
    queryFn: () => apiRequest("/api/data-lake/retention-policies").then((r) => r.data || r),
  });

  const { data: presets } = useQuery({
    queryKey: ["/api/data-lake/framework-presets"],
    queryFn: () => apiRequest("/api/data-lake/framework-presets").then((r) => r.data || r),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-lake/retention-policies", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      toast({ title: "Policy created" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/retention-policies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/overview"] });
      setShowCreate(false);
    },
    onError: (err: Error) =>
      toast({ title: "Failed to create policy", description: err.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/data-lake/retention-policies/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast({ title: "Policy deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/retention-policies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/overview"] });
    },
    onError: (err: Error) =>
      toast({ title: "Failed to delete policy", description: err.message, variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) =>
      apiRequest(`/api/data-lake/retention-policies/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ isActive }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/retention-policies"] });
    },
  });

  const policies = data?.policies || [];

  const handleFrameworkChange = (framework: string) => {
    const preset = presets?.presets?.[framework];
    setNewPolicy((prev) => ({
      ...prev,
      complianceFramework: framework,
      ...(preset
        ? {
            hotRetentionDays: preset.hotDays,
            warmRetentionDays: preset.warmDays,
            coldRetentionDays: preset.coldDays,
            purgeAfterDays: preset.purgeAfterDays,
          }
        : {}),
    }));
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Retention Policies</h3>
          <p className="text-sm text-muted-foreground">
            Configure per-data-type retention windows for GDPR, SOX, HIPAA, and custom compliance
          </p>
        </div>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-1" /> New Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Create Retention Policy</DialogTitle>
              <DialogDescription>Define data retention windows per compliance framework</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label>Policy Name</Label>
                <Input
                  value={newPolicy.name}
                  onChange={(e) => setNewPolicy((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g., GDPR Alert Retention"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Data Type</Label>
                  <Select
                    value={newPolicy.dataType}
                    onValueChange={(v) => setNewPolicy((p) => ({ ...p, dataType: v }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {DATA_TYPES.map((dt) => (
                        <SelectItem key={dt} value={dt}>
                          {dt}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Compliance Framework</Label>
                  <Select value={newPolicy.complianceFramework} onValueChange={handleFrameworkChange}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {FRAMEWORKS.map((fw) => (
                        <SelectItem key={fw.value} value={fw.value}>
                          {fw.label} ({fw.desc})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label>Hot (days)</Label>
                  <Input
                    type="number"
                    value={newPolicy.hotRetentionDays}
                    onChange={(e) => setNewPolicy((p) => ({ ...p, hotRetentionDays: parseInt(e.target.value) || 0 }))}
                  />
                </div>
                <div>
                  <Label>Warm (days)</Label>
                  <Input
                    type="number"
                    value={newPolicy.warmRetentionDays}
                    onChange={(e) => setNewPolicy((p) => ({ ...p, warmRetentionDays: parseInt(e.target.value) || 0 }))}
                  />
                </div>
                <div>
                  <Label>Cold (days)</Label>
                  <Input
                    type="number"
                    value={newPolicy.coldRetentionDays}
                    onChange={(e) => setNewPolicy((p) => ({ ...p, coldRetentionDays: parseInt(e.target.value) || 0 }))}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Purge After (days)</Label>
                  <Input
                    type="number"
                    value={newPolicy.purgeAfterDays ?? ""}
                    onChange={(e) =>
                      setNewPolicy((p) => ({
                        ...p,
                        purgeAfterDays: e.target.value ? parseInt(e.target.value) : null,
                      }))
                    }
                    placeholder="Never"
                  />
                </div>
                <div>
                  <Label>Compression</Label>
                  <Select
                    value={newPolicy.compressionFormat}
                    onValueChange={(v) => setNewPolicy((p) => ({ ...p, compressionFormat: v }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="parquet">Parquet (columnar)</SelectItem>
                      <SelectItem value="gzip_json">Gzip JSON</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate(newPolicy)}
                disabled={!newPolicy.name || createMutation.isPending}
              >
                {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                Create
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : policies.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Scale className="h-12 w-12 text-muted-foreground/30 mb-4" />
            <p className="text-muted-foreground">No retention policies configured</p>
            <p className="text-sm text-muted-foreground">Create a policy to manage data lifecycle</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {policies.map((policy: any) => (
            <Card key={policy.id}>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={policy.isActive}
                      onCheckedChange={(checked) => toggleMutation.mutate({ id: policy.id, isActive: checked })}
                    />
                    <div>
                      <div className="font-medium">{policy.name}</div>
                      <div className="text-sm text-muted-foreground flex items-center gap-2">
                        <Badge variant="outline">{policy.dataType}</Badge>
                        <Badge variant="secondary">{policy.complianceFramework?.toUpperCase()}</Badge>
                        <span>Hot: {policy.hotRetentionDays}d</span>
                        <span>Warm: {policy.warmRetentionDays}d</span>
                        <span>Cold: {policy.coldRetentionDays}d</span>
                        {policy.purgeAfterDays && <span>Purge: {policy.purgeAfterDays}d</span>}
                        <Badge variant="outline">{policy.compressionFormat}</Badge>
                      </div>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      if (confirm("Delete this retention policy?")) {
                        deleteMutation.mutate(policy.id);
                      }
                    }}
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Legal Holds Tab ────────────────────────────────────────────────────────

function LegalHoldsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newHold, setNewHold] = useState({
    name: "",
    description: "",
    holdType: "full",
    reason: "",
    caseReference: "",
  });

  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-lake/legal-holds"],
    queryFn: () => apiRequest("/api/data-lake/legal-holds").then((r) => r.data || r),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-lake/legal-holds", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      toast({ title: "Legal hold created" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/legal-holds"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/overview"] });
      setShowCreate(false);
    },
    onError: (err: Error) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, activate }: { id: string; activate: boolean }) =>
      apiRequest(`/api/data-lake/legal-holds/${id}/${activate ? "activate" : "deactivate"}`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/legal-holds"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/overview"] });
    },
    onError: (err: Error) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const holds = data?.holds || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Legal Holds</h3>
          <p className="text-sm text-muted-foreground">
            Suspend data purging for organizations under litigation or regulatory investigation
          </p>
        </div>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-1" /> New Hold
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Legal Hold</DialogTitle>
              <DialogDescription>Suspend data deletion for legal or regulatory purposes</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label>Hold Name</Label>
                <Input
                  value={newHold.name}
                  onChange={(e) => setNewHold((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g., Q1 2026 SEC Investigation"
                />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  value={newHold.description}
                  onChange={(e) => setNewHold((p) => ({ ...p, description: e.target.value }))}
                  placeholder="Details about this legal hold..."
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Hold Type</Label>
                  <Select value={newHold.holdType} onValueChange={(v) => setNewHold((p) => ({ ...p, holdType: v }))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="full">Full (all data)</SelectItem>
                      <SelectItem value="partial">Partial (specific tables)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>Case Reference</Label>
                  <Input
                    value={newHold.caseReference}
                    onChange={(e) => setNewHold((p) => ({ ...p, caseReference: e.target.value }))}
                    placeholder="CASE-2026-001"
                  />
                </div>
              </div>
              <div>
                <Label>Reason</Label>
                <Textarea
                  value={newHold.reason}
                  onChange={(e) => setNewHold((p) => ({ ...p, reason: e.target.value }))}
                  placeholder="Legal justification for the hold..."
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate(newHold)}
                disabled={!newHold.name || createMutation.isPending}
              >
                {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                Create Hold
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : holds.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Lock className="h-12 w-12 text-muted-foreground/30 mb-4" />
            <p className="text-muted-foreground">No legal holds</p>
            <p className="text-sm text-muted-foreground">Data lifecycle operates normally</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {holds.map((hold: any) => (
            <Card key={hold.id} className={hold.isActive ? "border-destructive/30" : ""}>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      {hold.isActive ? (
                        <Lock className="h-4 w-4 text-destructive" />
                      ) : (
                        <Unlock className="h-4 w-4 text-muted-foreground" />
                      )}
                      <span className="font-medium">{hold.name}</span>
                      <Badge variant={hold.isActive ? "destructive" : "outline"}>
                        {hold.isActive ? "Active" : "Inactive"}
                      </Badge>
                      <Badge variant="outline">{hold.holdType}</Badge>
                    </div>
                    {hold.description && <p className="text-sm text-muted-foreground ml-6">{hold.description}</p>}
                    <div className="text-xs text-muted-foreground ml-6 flex items-center gap-3">
                      {hold.caseReference && <span>Case: {hold.caseReference}</span>}
                      <span>Created: {formatDate(hold.createdAt)}</span>
                      {hold.activatedByName && <span>By: {hold.activatedByName}</span>}
                    </div>
                  </div>
                  <Button
                    variant={hold.isActive ? "outline" : "destructive"}
                    size="sm"
                    onClick={() => toggleMutation.mutate({ id: hold.id, activate: !hold.isActive })}
                  >
                    {hold.isActive ? "Deactivate" : "Activate"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Query Federation Tab ───────────────────────────────────────────────────

function QueryFederationTab() {
  const { toast } = useToast();
  const [queryText, setQueryText] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>(["alerts", "incidents"]);
  const [includeCold, setIncludeCold] = useState(true);
  const [results, setResults] = useState<any>(null);

  const { data: history, refetch: refetchHistory } = useQuery({
    queryKey: ["/api/data-lake/query-history"],
    queryFn: () => apiRequest("/api/data-lake/query-history").then((r) => r.data || r),
  });

  const queryMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-lake/query", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (data) => {
      setResults(data.data || data);
      refetchHistory();
    },
    onError: (err: Error) => toast({ title: "Query failed", description: err.message, variant: "destructive" }),
  });

  const toggleType = (type: string) => {
    setSelectedTypes((prev) => (prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]));
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Federated Query</CardTitle>
          <CardDescription>Search across hot (PostgreSQL) and cold (S3/Parquet) data transparently</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>Search Query</Label>
            <Input
              value={queryText}
              onChange={(e) => setQueryText(e.target.value)}
              placeholder="Search across all data tiers..."
              onKeyDown={(e) => {
                if (e.key === "Enter" && queryText && selectedTypes.length > 0) {
                  queryMutation.mutate({ queryText, dataTypes: selectedTypes, includeCold, limit: 100 });
                }
              }}
            />
          </div>
          <div>
            <Label>Data Types</Label>
            <div className="flex flex-wrap gap-2 mt-1">
              {DATA_TYPES.map((dt) => (
                <Badge
                  key={dt}
                  variant={selectedTypes.includes(dt) ? "default" : "outline"}
                  className="cursor-pointer"
                  onClick={() => toggleType(dt)}
                >
                  {dt}
                </Badge>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Switch checked={includeCold} onCheckedChange={setIncludeCold} />
              <Label>Include cold storage</Label>
            </div>
            <Button
              onClick={() => queryMutation.mutate({ queryText, dataTypes: selectedTypes, includeCold, limit: 100 })}
              disabled={!queryText || selectedTypes.length === 0 || queryMutation.isPending}
            >
              {queryMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Search className="h-4 w-4 mr-1" />
              )}
              Search
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Query Results */}
      {results && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Results</CardTitle>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <span>Hot: {results.hotCount || 0}</span>
                <span>Cold: {results.coldCount || 0}</span>
                <span>Total: {results.totalResults || 0}</span>
                <span>{formatDuration(results.executionTimeMs)}</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {(results.totalResults || 0) === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No results found</p>
            ) : (
              <div className="max-h-96 overflow-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Source</TableHead>
                      <TableHead>ID</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[...(results.hotResults || []), ...(results.coldResults || [])]
                      .slice(0, 50)
                      .map((r: any, i: number) => (
                        <TableRow key={i}>
                          <TableCell>
                            <Badge variant={r._source === "cold_storage" ? "secondary" : "default"}>
                              {r._source === "cold_storage" ? "Cold" : "Hot"}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{r.id?.substring(0, 8) || "-"}</TableCell>
                          <TableCell>{r._dataType || r.severity || r.status || "-"}</TableCell>
                          <TableCell className="text-sm">{formatDate(r.created_at || r.createdAt)}</TableCell>
                          <TableCell className="max-w-xs truncate text-sm">
                            {r.title || r.description || r.action || r.source || "-"}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </div>
            )}
            {results.errors?.length > 0 && (
              <div className="mt-2 text-sm text-destructive">
                {results.errors.map((e: string, i: number) => (
                  <p key={i}>{e}</p>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Query History */}
      {(history?.queries || []).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Query History</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Query</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Results</TableHead>
                  <TableHead className="text-right">Time</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(history?.queries || []).slice(0, 20).map((q: any) => (
                  <TableRow key={q.id}>
                    <TableCell className="max-w-xs truncate text-sm font-mono">{q.queryText}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{q.queryType}</Badge>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={q.status} />
                    </TableCell>
                    <TableCell className="text-right">{q.totalResultCount ?? "-"}</TableCell>
                    <TableCell className="text-right">{formatDuration(q.executionTimeMs)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(q.createdAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── eDiscovery Tab ─────────────────────────────────────────────────────────

function EDiscoveryTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newExport, setNewExport] = useState({
    name: "",
    description: "",
    dataTypes: ["alerts", "incidents", "audit_logs"] as string[],
    exportFormat: "json",
    includeChainOfCustody: true,
  });

  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-lake/ediscovery"],
    queryFn: () => apiRequest("/api/data-lake/ediscovery").then((r) => r.data || r),
  });

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-lake/ediscovery", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      toast({ title: "eDiscovery export requested" });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/ediscovery"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/overview"] });
      setShowCreate(false);
    },
    onError: (err: Error) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  const downloadMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/data-lake/ediscovery/${id}/download`),
    onSuccess: (data) => {
      const result = data.data || data;
      if (result.downloadUrl) {
        window.open(result.downloadUrl, "_blank");
        toast({ title: "Download started" });
        queryClient.invalidateQueries({ queryKey: ["/api/data-lake/ediscovery"] });
      }
    },
    onError: (err: Error) => toast({ title: "Download failed", description: err.message, variant: "destructive" }),
  });

  const exports = data?.exports || [];

  const toggleExportType = (type: string) => {
    setNewExport((prev) => ({
      ...prev,
      dataTypes: prev.dataTypes.includes(type) ? prev.dataTypes.filter((t) => t !== type) : [...prev.dataTypes, type],
    }));
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">eDiscovery Exports</h3>
          <p className="text-sm text-muted-foreground">
            Produce legally admissible data exports with chain-of-custody and SHA-256 checksums
          </p>
        </div>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-1" /> New Export
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create eDiscovery Export</DialogTitle>
              <DialogDescription>Export data with chain-of-custody for legal proceedings</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label>Export Name</Label>
                <Input
                  value={newExport.name}
                  onChange={(e) => setNewExport((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g., SEC Investigation Q1 2026"
                />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea
                  value={newExport.description}
                  onChange={(e) => setNewExport((p) => ({ ...p, description: e.target.value }))}
                  placeholder="Purpose and scope of this export..."
                />
              </div>
              <div>
                <Label>Data Types</Label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {DATA_TYPES.map((dt) => (
                    <Badge
                      key={dt}
                      variant={newExport.dataTypes.includes(dt) ? "default" : "outline"}
                      className="cursor-pointer"
                      onClick={() => toggleExportType(dt)}
                    >
                      {dt}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Format</Label>
                  <Select
                    value={newExport.exportFormat}
                    onValueChange={(v) => setNewExport((p) => ({ ...p, exportFormat: v }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="csv">CSV</SelectItem>
                      <SelectItem value="parquet">Parquet</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center gap-2 pt-6">
                  <Switch
                    checked={newExport.includeChainOfCustody}
                    onCheckedChange={(checked) => setNewExport((p) => ({ ...p, includeChainOfCustody: checked }))}
                  />
                  <Label>Chain of Custody</Label>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate(newExport)}
                disabled={!newExport.name || newExport.dataTypes.length === 0 || createMutation.isPending}
              >
                {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                Request Export
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : exports.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground/30 mb-4" />
            <p className="text-muted-foreground">No eDiscovery exports</p>
            <p className="text-sm text-muted-foreground">Create an export for legal or compliance needs</p>
          </CardContent>
        </Card>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Format</TableHead>
              <TableHead className="text-right">Records</TableHead>
              <TableHead className="text-right">Size</TableHead>
              <TableHead>Requested</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {exports.map((exp: any) => (
              <TableRow key={exp.id}>
                <TableCell>
                  <div className="font-medium">{exp.name}</div>
                  {exp.description && (
                    <div className="text-xs text-muted-foreground max-w-xs truncate">{exp.description}</div>
                  )}
                </TableCell>
                <TableCell>
                  <StatusBadge status={exp.status} />
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{exp.exportFormat}</Badge>
                </TableCell>
                <TableCell className="text-right">{(exp.totalRecords || 0).toLocaleString()}</TableCell>
                <TableCell className="text-right">{formatBytes(exp.exportSizeBytes || 0)}</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {formatDate(exp.createdAt)}
                  {exp.requestedByName && <div className="text-xs">{exp.requestedByName}</div>}
                </TableCell>
                <TableCell>
                  {exp.status === "ready" || exp.status === "downloaded" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => downloadMutation.mutate(exp.id)}
                      disabled={downloadMutation.isPending}
                    >
                      <Download className="h-3 w-3 mr-1" /> Download
                    </Button>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// ─── Tiering Tab ────────────────────────────────────────────────────────────

function TieringTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tieringForm, setTieringForm] = useState({
    dataType: "alerts",
    sourceTier: "hot",
    targetTier: "warm",
    olderThanDays: 90,
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-lake/tiering-jobs"],
    queryFn: () => apiRequest("/api/data-lake/tiering-jobs").then((r) => r.data || r),
  });

  const { data: inventory } = useQuery({
    queryKey: ["/api/data-lake/cold-inventory"],
    queryFn: () => apiRequest("/api/data-lake/cold-inventory").then((r) => r.data || r),
  });

  const tierMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-lake/tier", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (data) => {
      const result = data.data || data;
      toast({ title: "Tiering complete", description: `${result.recordCount || 0} records tiered` });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/tiering-jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/cold-inventory"] });
      queryClient.invalidateQueries({ queryKey: ["/api/data-lake/overview"] });
      refetch();
    },
    onError: (err: Error) => toast({ title: "Tiering failed", description: err.message, variant: "destructive" }),
  });

  const jobs = data?.jobs || [];
  const inventoryItems = inventory?.inventory || [];

  return (
    <div className="space-y-6">
      {/* Manual Tiering */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Manual Tiering</CardTitle>
          <CardDescription>Move data between storage tiers (Hot → Warm → Cold)</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-4 items-end">
            <div>
              <Label>Data Type</Label>
              <Select
                value={tieringForm.dataType}
                onValueChange={(v) => setTieringForm((p) => ({ ...p, dataType: v }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DATA_TYPES.map((dt) => (
                    <SelectItem key={dt} value={dt}>
                      {dt}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Source → Target</Label>
              <Select
                value={`${tieringForm.sourceTier}-${tieringForm.targetTier}`}
                onValueChange={(v) => {
                  const [src, tgt] = v.split("-");
                  setTieringForm((p) => ({ ...p, sourceTier: src, targetTier: tgt }));
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hot-warm">Hot → Warm</SelectItem>
                  <SelectItem value="warm-cold">Warm → Cold</SelectItem>
                  <SelectItem value="hot-cold">Hot → Cold</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Older Than (days)</Label>
              <Input
                type="number"
                value={tieringForm.olderThanDays}
                onChange={(e) => setTieringForm((p) => ({ ...p, olderThanDays: parseInt(e.target.value) || 0 }))}
              />
            </div>
            <Button onClick={() => tierMutation.mutate(tieringForm)} disabled={tierMutation.isPending}>
              {tierMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Play className="h-4 w-4 mr-1" />
              )}
              Execute
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tiering Jobs */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Tiering Jobs</CardTitle>
          <Button variant="ghost" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-4">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : jobs.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-4">No tiering jobs yet</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Data Type</TableHead>
                  <TableHead>Direction</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Records</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.slice(0, 20).map((job: any) => (
                  <TableRow key={job.id}>
                    <TableCell className="font-mono text-sm">{job.dataType}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {job.sourceTier} → {job.targetTier}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={job.status} />
                    </TableCell>
                    <TableCell className="text-right">{(job.recordCount || 0).toLocaleString()}</TableCell>
                    <TableCell className="text-right">{formatBytes(job.compressedSizeBytes || 0)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(job.createdAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Cold Storage Inventory */}
      {inventoryItems.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Cold Storage Inventory</CardTitle>
            <CardDescription>{inventoryItems.length} files in cold storage</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Data Type</TableHead>
                  <TableHead>Tier</TableHead>
                  <TableHead>Format</TableHead>
                  <TableHead className="text-right">Records</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead>Date Range</TableHead>
                  <TableHead>Purge After</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inventoryItems.slice(0, 50).map((item: any) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-mono text-sm">{item.dataType}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{item.tier}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{item.format}</Badge>
                    </TableCell>
                    <TableCell className="text-right">{item.recordCount.toLocaleString()}</TableCell>
                    <TableCell className="text-right">{formatBytes(item.compressedSizeBytes)}</TableCell>
                    <TableCell className="text-xs">
                      {formatDate(item.oldestRecord)} — {formatDate(item.newestRecord)}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {item.purgeEligibleAt ? formatDate(item.purgeEligibleAt) : "Never"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── 44.1 Storage Tier Visualization ─────────────────────────────────────────

function TierVisualizationTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-lake/tier-visualization"],
    queryFn: () => apiRequest("/api/data-lake/tier-visualization").then((r) => r.data || r),
  });

  if (isLoading)
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );

  const tiers = data?.tiers || [];
  const totalGb = data?.totalGb || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium flex items-center gap-2">
            <Layers className="h-5 w-5" /> Storage Tier Breakdown
          </h3>
          <p className="text-sm text-muted-foreground">Data distribution across storage tiers with cost analysis</p>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold">{formatBytes(totalGb * 1024 * 1024 * 1024)}</p>
          <p className="text-sm text-muted-foreground">${data?.totalMonthlyCost || 0}/mo</p>
        </div>
      </div>

      {/* Visual tier bar */}
      <div className="flex h-8 rounded-lg overflow-hidden border">
        {tiers.map((t: any) => (
          <div
            key={t.tier}
            className="transition-all"
            style={{ width: `${(t.volumeGb / totalGb) * 100}%`, backgroundColor: t.color }}
            title={`${t.label}: ${t.volumeGb} GB`}
          />
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {tiers.map((t: any) => (
          <Card key={t.tier}>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: t.color }} />
                <CardTitle className="text-base">{t.label}</CardTitle>
              </div>
              <CardDescription>{t.accessTime} access</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Volume</span>
                <span className="font-medium">{t.volumeGb} GB</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Records</span>
                <span className="font-medium">{t.recordCount.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Cost</span>
                <span className="font-medium">${(t.volumeGb * t.costPerGbMonth).toFixed(2)}/mo</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">$/GB</span>
                <span className="font-medium">${t.costPerGbMonth}</span>
              </div>
              <div className="flex flex-wrap gap-1 mt-2">
                {(t.dataTypes || []).map((dt: string) => (
                  <Badge key={dt} variant="outline" className="text-[10px]">
                    {dt}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── 44.2 Query Cost Estimation ──────────────────────────────────────────────

function QueryCostEstimationTab() {
  const [query, setQuery] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [estimation, setEstimation] = useState<any>(null);

  const estimateMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest("/api/data-lake/estimate-query", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (d) => setEstimation(d.data || d),
  });

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium flex items-center gap-2">
          <DollarSign className="h-5 w-5" /> Query Cost Estimation
        </h3>
        <p className="text-sm text-muted-foreground">Preview estimated cost before executing data lake queries</p>
      </div>

      <Card>
        <CardContent className="pt-4 space-y-4">
          <div>
            <Label>Query</Label>
            <Textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="SELECT * FROM alerts WHERE severity = 'critical' AND createdAt > '2025-01-01'"
              rows={3}
              className="font-mono text-sm"
            />
          </div>
          <div>
            <Label>Data Types (optional)</Label>
            <div className="flex flex-wrap gap-2 mt-1">
              {DATA_TYPES.map((dt) => (
                <Badge
                  key={dt}
                  variant={selectedTypes.includes(dt) ? "default" : "outline"}
                  className="cursor-pointer text-xs"
                  onClick={() =>
                    setSelectedTypes((prev) => (prev.includes(dt) ? prev.filter((t) => t !== dt) : [...prev, dt]))
                  }
                >
                  {dt}
                </Badge>
              ))}
            </div>
          </div>
          <Button
            onClick={() =>
              estimateMutation.mutate({ query, dataTypes: selectedTypes.length > 0 ? selectedTypes : undefined })
            }
            disabled={!query || estimateMutation.isPending}
          >
            {estimateMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-1" /> Estimating...
              </>
            ) : (
              <>
                <Gauge className="h-4 w-4 mr-1" /> Estimate Cost
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {estimation && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Cost Estimate</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 rounded-lg border bg-muted/10 text-center">
                <p className="text-2xl font-bold">{estimation.estimatedScanGb} GB</p>
                <p className="text-xs text-muted-foreground">Data Scanned</p>
              </div>
              <div className="p-3 rounded-lg border bg-muted/10 text-center">
                <p className="text-2xl font-bold">{formatDuration(estimation.estimatedTimeMs)}</p>
                <p className="text-xs text-muted-foreground">Est. Time</p>
              </div>
              <div className="p-3 rounded-lg border bg-muted/10 text-center">
                <p className="text-2xl font-bold text-emerald-500">${estimation.estimatedCostUsd}</p>
                <p className="text-xs text-muted-foreground">Est. Cost</p>
              </div>
              <div className="p-3 rounded-lg border bg-muted/10 text-center">
                <p className="text-2xl font-bold">{estimation.tiersQueried?.length || 0}</p>
                <p className="text-xs text-muted-foreground">Tiers Queried</p>
              </div>
            </div>
            {estimation.warning && (
              <div className="mt-4 p-3 rounded-lg border border-yellow-500/20 bg-yellow-500/5 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0" />
                <p className="text-sm text-yellow-500">{estimation.warning}</p>
              </div>
            )}
            <div className="mt-4 flex gap-2">
              {(estimation.tiersQueried || []).map((t: string) => (
                <Badge key={t} variant="outline">
                  {t}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── 44.3 Data Catalog ───────────────────────────────────────────────────────

function DataCatalogTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-lake/catalog"],
    queryFn: () => apiRequest("/api/data-lake/catalog").then((r) => r.data || r),
  });
  const [expanded, setExpanded] = useState<string | null>(null);

  if (isLoading)
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );

  const catalog = data?.catalog || [];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium flex items-center gap-2">
          <BookOpen className="h-5 w-5" /> Data Catalog
        </h3>
        <p className="text-sm text-muted-foreground">Browse tables, fields, and data freshness</p>
      </div>

      <div className="space-y-2">
        {catalog.map((tbl: any) => {
          const fresh = tbl.freshnessMs < 60000;
          return (
            <Card
              key={tbl.table}
              className="cursor-pointer hover:shadow-sm transition-shadow"
              onClick={() => setExpanded(expanded === tbl.table ? null : tbl.table)}
            >
              <CardContent className="py-3">
                <div className="flex items-center gap-4">
                  <Database className="h-5 w-5 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-medium text-sm">{tbl.table}</span>
                      <Badge variant={fresh ? "default" : "outline"} className="text-[10px]">
                        {fresh ? "Fresh" : `${Math.round(tbl.freshnessMs / 60000)}m ago`}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {tbl.rowCount.toLocaleString()} rows &middot; {tbl.sizeGb} GB &middot; {tbl.fields.length} fields
                    </p>
                  </div>
                  <ChevronDown
                    className={`h-4 w-4 text-muted-foreground transition-transform ${expanded === tbl.table ? "rotate-180" : ""}`}
                  />
                </div>
                {expanded === tbl.table && (
                  <div className="mt-3 pt-3 border-t">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Field</TableHead>
                          <TableHead className="text-xs">Type</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {tbl.fields.map((f: any) => (
                          <TableRow key={f.name}>
                            <TableCell className="font-mono text-xs py-1.5">{f.name}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className="text-[10px]">
                                {f.type}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// ─── 44.4 Legal Hold Management (enhanced) ───────────────────────────────────
// (Already exists as LegalHoldsTab — adding detail panel is covered by existing tab)

// ─── 44.5 Auto-Tiering Tab ──────────────────────────────────────────────────

function AutoTieringTab() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-lake/auto-tiering"],
    queryFn: () => apiRequest("/api/data-lake/auto-tiering").then((r) => r.data || r),
  });

  if (isLoading)
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );

  const rules = data?.rules || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium flex items-center gap-2">
            <Settings className="h-5 w-5" /> Automated Data Tiering
          </h3>
          <p className="text-sm text-muted-foreground">
            Configure automatic data movement between storage tiers based on age
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      <div className="space-y-3">
        {rules.map((rule: any) => (
          <Card key={rule.dataType}>
            <CardContent className="py-3">
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono font-medium text-sm">{rule.dataType}</span>
                    <Badge variant={rule.enabled ? "default" : "outline"} className="text-[10px]">
                      {rule.enabled ? "Active" : "Disabled"}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Badge variant="outline" className="text-[10px] bg-red-500/5">
                      Hot
                    </Badge>
                    <ArrowRight className="h-3 w-3" />
                    <span>{rule.hotToWarmDays}d</span>
                    <ArrowRight className="h-3 w-3" />
                    <Badge variant="outline" className="text-[10px] bg-yellow-500/5">
                      Warm
                    </Badge>
                    <ArrowRight className="h-3 w-3" />
                    <span>{rule.warmToColdDays}d</span>
                    <ArrowRight className="h-3 w-3" />
                    <Badge variant="outline" className="text-[10px] bg-blue-500/5">
                      Cold
                    </Badge>
                    <ArrowRight className="h-3 w-3" />
                    <span>{rule.coldToArchiveDays}d</span>
                    <ArrowRight className="h-3 w-3" />
                    <Badge variant="outline" className="text-[10px] bg-indigo-500/5">
                      Archive
                    </Badge>
                  </div>
                </div>
                <div className="text-right text-xs">
                  {rule.lastRun && <p className="text-muted-foreground">Last run: {formatDate(rule.lastRun)}</p>}
                  {rule.recordsMoved > 0 && (
                    <p className="font-medium">{rule.recordsMoved.toLocaleString()} records moved</p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── 44.6 Compaction Tab ─────────────────────────────────────────────────────

function CompactionTab() {
  const { toast } = useToast();
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["/api/data-lake/compaction-status"],
    queryFn: () => apiRequest("/api/data-lake/compaction-status").then((r) => r.data || r),
  });

  const compactMutation = useMutation({
    mutationFn: () => apiRequest("/api/data-lake/compact", { method: "POST" }),
    onSuccess: () => {
      toast({ title: "Compaction started" });
      refetch();
    },
    onError: (err: Error) => toast({ title: "Failed", description: err.message, variant: "destructive" }),
  });

  if (isLoading)
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );

  const tables = data?.tables || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium flex items-center gap-2">
            <Wrench className="h-5 w-5" /> Data Compaction & Optimization
          </h3>
          <p className="text-sm text-muted-foreground">Merge small files, rebuild indexes, update statistics</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button size="sm" onClick={() => compactMutation.mutate()} disabled={compactMutation.isPending}>
            {compactMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <Play className="h-4 w-4 mr-1" />
            )}
            Run Compaction
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{formatBytes((data?.totalSavedGb || 0) * 1024 * 1024 * 1024)}</p>
            <p className="text-xs text-muted-foreground">Space Saved</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{formatDate(data?.lastCompactionAt)}</p>
            <p className="text-xs text-muted-foreground">Last Compaction</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{formatDate(data?.nextScheduledAt)}</p>
            <p className="text-xs text-muted-foreground">Next Scheduled</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Per-Table Status</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Table</TableHead>
                <TableHead className="text-right">Small Files</TableHead>
                <TableHead className="text-right">Merged</TableHead>
                <TableHead className="text-right">Saved</TableHead>
                <TableHead>Indexes</TableHead>
                <TableHead>Stats</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tables.map((t: any) => (
                <TableRow key={t.table}>
                  <TableCell className="font-mono text-sm">{t.table}</TableCell>
                  <TableCell className="text-right">{t.smallFiles}</TableCell>
                  <TableCell className="text-right">{t.mergedFiles}</TableCell>
                  <TableCell className="text-right">{t.savedSpaceGb} GB</TableCell>
                  <TableCell>
                    {t.indexesRebuilt ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <Clock className="h-4 w-4 text-yellow-500" />
                    )}
                  </TableCell>
                  <TableCell>
                    {t.statsUpdated ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <Clock className="h-4 w-4 text-yellow-500" />
                    )}
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

// ─── 44.7 Cross-Tier Query Federation ────────────────────────────────────────

function CrossTierTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["/api/data-lake/cross-tier-stats"],
    queryFn: () => apiRequest("/api/data-lake/cross-tier-stats").then((r) => r.data || r),
  });

  if (isLoading)
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );

  const queries = data?.recentQueries || [];
  const avgByTier = data?.avgResponseByTier || {};

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium flex items-center gap-2">
          <GitBranch className="h-5 w-5" /> Cross-Tier Query Federation
        </h3>
        <p className="text-sm text-muted-foreground">See how queries span tiers and performance per tier</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Object.entries(avgByTier).map(([tier, ms]) => (
          <Card key={tier}>
            <CardContent className="pt-4 text-center">
              <p className="text-2xl font-bold">{formatDuration(ms as number)}</p>
              <p className="text-xs text-muted-foreground capitalize">{tier} Avg Response</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Cross-Tier Queries</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Query ID</TableHead>
                <TableHead>Tiers</TableHead>
                <TableHead className="text-right">Total Time</TableHead>
                <TableHead className="text-right">Records</TableHead>
                <TableHead>Time per Tier</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {queries.map((q: any) => (
                <TableRow key={q.queryId}>
                  <TableCell className="font-mono text-xs">{q.queryId}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {q.tiersQueried.map((t: string) => (
                        <Badge key={t} variant="outline" className="text-[10px]">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-right font-medium">{formatDuration(q.totalMs)}</TableCell>
                  <TableCell className="text-right">{q.recordsScanned.toLocaleString()}</TableCell>
                  <TableCell>
                    <div className="flex gap-2 text-xs">
                      {Object.entries(q.timePerTier || {}).map(([t, ms]) => (
                        <span key={t} className="text-muted-foreground">
                          {t}: {formatDuration(ms as number)}
                        </span>
                      ))}
                    </div>
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

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function DataLakePage() {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Database className="h-6 w-6" />
            Security Data Lake
          </h1>
          <p className="text-muted-foreground mt-1">
            Long-term data retention, query federation, compliance policies, and eDiscovery
          </p>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview" className="gap-1">
            <HardDrive className="h-3.5 w-3.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="retention" className="gap-1">
            <Scale className="h-3.5 w-3.5" /> Retention Policies
          </TabsTrigger>
          <TabsTrigger value="legal-holds" className="gap-1">
            <Shield className="h-3.5 w-3.5" /> Legal Holds
          </TabsTrigger>
          <TabsTrigger value="query" className="gap-1">
            <Search className="h-3.5 w-3.5" /> Query Federation
          </TabsTrigger>
          <TabsTrigger value="tiering" className="gap-1">
            <Archive className="h-3.5 w-3.5" /> Tiering
          </TabsTrigger>
          <TabsTrigger value="ediscovery" className="gap-1">
            <FileText className="h-3.5 w-3.5" /> eDiscovery
          </TabsTrigger>
          <TabsTrigger value="tier-viz" className="gap-1">
            <Layers className="h-3.5 w-3.5" /> Tier View
          </TabsTrigger>
          <TabsTrigger value="query-cost" className="gap-1">
            <DollarSign className="h-3.5 w-3.5" /> Query Cost
          </TabsTrigger>
          <TabsTrigger value="catalog" className="gap-1">
            <BookOpen className="h-3.5 w-3.5" /> Data Catalog
          </TabsTrigger>
          <TabsTrigger value="auto-tiering" className="gap-1">
            <Settings className="h-3.5 w-3.5" /> Auto-Tiering
          </TabsTrigger>
          <TabsTrigger value="compaction" className="gap-1">
            <Wrench className="h-3.5 w-3.5" /> Compaction
          </TabsTrigger>
          <TabsTrigger value="cross-tier" className="gap-1">
            <GitBranch className="h-3.5 w-3.5" /> Cross-Tier
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        <TabsContent value="retention">
          <RetentionPoliciesTab />
        </TabsContent>
        <TabsContent value="legal-holds">
          <LegalHoldsTab />
        </TabsContent>
        <TabsContent value="query">
          <QueryFederationTab />
        </TabsContent>
        <TabsContent value="tiering">
          <TieringTab />
        </TabsContent>
        <TabsContent value="ediscovery">
          <EDiscoveryTab />
        </TabsContent>
        <TabsContent value="tier-viz">
          <TierVisualizationTab />
        </TabsContent>
        <TabsContent value="query-cost">
          <QueryCostEstimationTab />
        </TabsContent>
        <TabsContent value="catalog">
          <DataCatalogTab />
        </TabsContent>
        <TabsContent value="auto-tiering">
          <AutoTieringTab />
        </TabsContent>
        <TabsContent value="compaction">
          <CompactionTab />
        </TabsContent>
        <TabsContent value="cross-tier">
          <CrossTierTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
