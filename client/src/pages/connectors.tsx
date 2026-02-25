import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Plus,
  Trash2,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Plug,
  Unplug,
  TestTube,
  Shield,
  Database,
  Cloud,
  Eye,
  Flame,
  Radar,
  ShieldCheck,
  Zap,
  CloudLightning,
  Clock,
  Settings2,
  ExternalLink,
  BookOpen,
  HeartPulse,
  BarChart3,
  Skull,
  ChevronDown,
  ChevronRight,
  KeyRound,
  RotateCcw,
  Play,
} from "lucide-react";
import type { ConnectorJobRun, ConnectorHealthCheck } from "@shared/schema";

interface ConnectorType {
  type: string;
  name: string;
  description: string;
  authType: string;
  requiredFields: { key: string; label: string; type: string; placeholder: string }[];
  optionalFields: { key: string; label: string; type: string; placeholder: string }[];
  icon: string;
  docsUrl: string;
}

interface ConnectorItem {
  id: string;
  name: string;
  type: string;
  authType: string;
  config: Record<string, any>;
  status: string;
  pollingIntervalMin: number | null;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
  lastSyncAlerts: number | null;
  lastSyncError: string | null;
  totalAlertsSynced: number | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface ConnectorMetrics {
  avgLatencyMs: number;
  errorRate: number;
  throttleCount: number;
  totalRuns: number;
  successRate: number;
}

const ICON_MAP: Record<string, any> = {
  Shield, Database, Cloud, Eye, Flame, Radar, ShieldCheck, CloudLightning, Zap,
};

function getIcon(name: string) {
  return ICON_MAP[name] || Plug;
}

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return <Badge variant="default" data-testid="badge-status-active"><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>;
    case "error":
      return <Badge variant="destructive" data-testid="badge-status-error"><XCircle className="h-3 w-3 mr-1" />Error</Badge>;
    case "syncing":
      return <Badge variant="secondary" data-testid="badge-status-syncing"><Loader2 className="h-3 w-3 mr-1 animate-spin" />Syncing</Badge>;
    case "inactive":
      return <Badge variant="outline" data-testid="badge-status-inactive"><Unplug className="h-3 w-3 mr-1" />Inactive</Badge>;
    default:
      return <Badge variant="outline" data-testid="badge-status-unknown"><AlertTriangle className="h-3 w-3 mr-1" />Unknown</Badge>;
  }
}

function jobStatusBadge(status: string) {
  switch (status) {
    case "success":
      return <Badge variant="default"><CheckCircle className="h-3 w-3 mr-1" />Success</Badge>;
    case "failed":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
    case "running":
      return <Badge variant="secondary"><Loader2 className="h-3 w-3 mr-1 animate-spin" />Running</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function healthStatusBadge(status: string) {
  switch (status) {
    case "healthy":
      return <Badge variant="default"><CheckCircle className="h-3 w-3 mr-1" />Healthy</Badge>;
    case "unhealthy":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Unhealthy</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function ConnectorObservabilityPanel({ connector }: { connector: ConnectorItem }) {
  const { data: jobs, isLoading: jobsLoading } = useQuery<ConnectorJobRun[]>({
    queryKey: ["/api/connectors", connector.id, "jobs"],
    queryFn: async () => {
      const res = await fetch(`/api/connectors/${connector.id}/jobs?limit=20`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch jobs");
      return res.json();
    },
  });

  const { data: metrics, isLoading: metricsLoading } = useQuery<ConnectorMetrics>({
    queryKey: ["/api/connectors", connector.id, "metrics"],
    queryFn: async () => {
      const res = await fetch(`/api/connectors/${connector.id}/metrics`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch metrics");
      return res.json();
    },
  });

  const { data: healthChecks, isLoading: healthLoading } = useQuery<ConnectorHealthCheck[]>({
    queryKey: ["/api/connectors", connector.id, "health"],
    queryFn: async () => {
      const res = await fetch(`/api/connectors/${connector.id}/health?limit=5`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch health");
      return res.json();
    },
  });

  const latestHealth = healthChecks?.[0];
  const credentialExpiresAt = latestHealth?.credentialExpiresAt ? new Date(latestHealth.credentialExpiresAt) : null;
  const now = new Date();
  const sevenDaysFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  const credentialExpiringSoon = credentialExpiresAt && credentialExpiresAt <= sevenDaysFromNow;

  return (
    <div className="space-y-4 p-4 bg-muted/30 rounded-md">
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3" data-testid={`card-connector-metrics-${connector.id}`}>
        {metricsLoading ? (
          <div className="col-span-5 flex justify-center py-4">
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          </div>
        ) : metrics ? (
          <>
            <Card>
              <CardContent className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Avg Latency</span>
                </div>
                <span className="text-lg font-bold" data-testid={`text-metric-avg-latency-${connector.id}`}>
                  {Math.round(metrics.avgLatencyMs)}ms
                </span>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Error Rate</span>
                </div>
                <span className="text-lg font-bold" data-testid={`text-metric-error-rate-${connector.id}`}>
                  {(metrics.errorRate * 100).toFixed(1)}%
                </span>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <RefreshCw className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Throttle Count</span>
                </div>
                <span className="text-lg font-bold" data-testid={`text-metric-throttle-count-${connector.id}`}>
                  {metrics.throttleCount}
                </span>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Success Rate</span>
                </div>
                <span className="text-lg font-bold" data-testid={`text-metric-success-rate-${connector.id}`}>
                  {(metrics.successRate * 100).toFixed(1)}%
                </span>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <BarChart3 className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Total Runs</span>
                </div>
                <span className="text-lg font-bold" data-testid={`text-metric-total-runs-${connector.id}`}>
                  {metrics.totalRuns}
                </span>
              </CardContent>
            </Card>
          </>
        ) : (
          <div className="col-span-5 text-sm text-muted-foreground text-center py-2">No metrics available</div>
        )}
      </div>

      {latestHealth && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Health Status</CardTitle>
            <HeartPulse className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {healthLoading ? (
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            ) : (
              <div className="flex items-center gap-4 flex-wrap">
                <div data-testid={`text-health-status-${connector.id}`}>
                  {healthStatusBadge(latestHealth.status)}
                </div>
                <span className="text-sm text-muted-foreground">
                  Latency: <span className="font-mono">{latestHealth.latencyMs}ms</span>
                </span>
                <span className="text-sm text-muted-foreground">
                  Credentials: <span className="font-medium">{latestHealth.credentialStatus || "unknown"}</span>
                </span>
                {credentialExpiringSoon && (
                  <Badge variant="destructive" data-testid={`badge-credential-warning-${connector.id}`}>
                    <AlertTriangle className="h-3 w-3 mr-1" />
                    Credential expires {credentialExpiresAt!.toLocaleDateString()}
                  </Badge>
                )}
                <span className="text-xs text-muted-foreground">
                  Checked: {new Date(latestHealth.checkedAt!).toLocaleString()}
                </span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Job History</CardTitle>
          <BarChart3 className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          {jobsLoading ? (
            <div className="flex justify-center py-4">
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            </div>
          ) : !jobs?.length ? (
            <p className="text-sm text-muted-foreground text-center py-4">No job runs recorded yet</p>
          ) : (
            <div className="overflow-x-auto">
              <Table data-testid={`table-job-history-${connector.id}`}>
                <TableHeader>
                  <TableRow>
                    <TableHead>Status</TableHead>
                    <TableHead>Started At</TableHead>
                    <TableHead>Latency</TableHead>
                    <TableHead>Alerts Received</TableHead>
                    <TableHead>Alerts Created</TableHead>
                    <TableHead>Error</TableHead>
                    <TableHead>Throttled</TableHead>
                    <TableHead>Dead Letter</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {jobs.map(job => (
                    <TableRow key={job.id} data-testid={`row-job-${job.id}`}>
                      <TableCell>{jobStatusBadge(job.status)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {job.startedAt ? new Date(job.startedAt).toLocaleString() : "-"}
                      </TableCell>
                      <TableCell className="text-sm font-mono">{job.latencyMs != null ? `${job.latencyMs}ms` : "-"}</TableCell>
                      <TableCell className="text-sm">{job.alertsReceived ?? 0}</TableCell>
                      <TableCell className="text-sm">{job.alertsCreated ?? 0}</TableCell>
                      <TableCell className="text-sm text-destructive max-w-xs truncate">{job.errorMessage || "-"}</TableCell>
                      <TableCell>
                        {job.throttled ? (
                          <Badge variant="secondary">Throttled</Badge>
                        ) : (
                          <span className="text-sm text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {job.isDeadLetter ? (
                          <Badge variant="destructive" data-testid="badge-dead-letter"><Skull className="h-3 w-3 mr-1" />Dead Letter</Badge>
                        ) : (
                          <span className="text-sm text-muted-foreground">-</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

interface SecretRotation {
  id: string;
  connectorId: string;
  orgId: string | null;
  secretField: string;
  lastRotatedAt: string | null;
  nextRotationDue: string | null;
  rotationIntervalDays: number;
  status: string;
  rotatedByName: string | null;
  createdAt: string;
}

function ConnectorSecretRotationPanel({ connectorId }: { connectorId: string }) {
  const [showRotate, setShowRotate] = useState(false);
  const [newSecretField, setNewSecretField] = useState("apiKey");
  const [newSecretValue, setNewSecretValue] = useState("");
  const [rotationDays, setRotationDays] = useState("90");
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const [confirmRotateId, setConfirmRotateId] = useState<string | null>(null);
  const [rotateTargetId, setRotateTargetId] = useState<string | null>(null);
  const revealTimersRef = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  const { toast } = useToast();

  const { data: rotations, isLoading } = useQuery<SecretRotation[]>({
    queryKey: [`/api/connectors/${connectorId}/secret-rotations`],
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`/api/connectors/${connectorId}/secret-rotations`, {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
        body: JSON.stringify({ secretField: newSecretField, rotationIntervalDays: parseInt(rotationDays) }),
      });
      if (!res.ok) throw new Error("Failed to create rotation schedule");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/connectors/${connectorId}/secret-rotations`] });
      toast({ title: "Rotation schedule created" });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: async (rotationId: string) => {
      const res = await fetch(`/api/connectors/${connectorId}/secret-rotations/${rotationId}/rotate`, {
        method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
        body: JSON.stringify({ newSecretValue }),
      });
      if (!res.ok) throw new Error("Failed to rotate secret");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/connectors/${connectorId}/secret-rotations`] });
      setShowRotate(false);
      setNewSecretValue("");
      setConfirmRotateId(null);
      toast({ title: "Secret rotated successfully" });
    },
  });

  const isExpiringSoon = (dueDate: string | null) => {
    if (!dueDate) return false;
    const due = new Date(dueDate);
    const now = new Date();
    const daysUntil = (due.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
    return daysUntil <= 14;
  };

  useEffect(() => {
    const timers = revealTimersRef.current;
    return () => { Object.values(timers).forEach(clearTimeout); };
  }, []);

  const toggleReveal = useCallback((id: string) => {
    if (revealTimersRef.current[id]) {
      clearTimeout(revealTimersRef.current[id]);
      delete revealTimersRef.current[id];
    }
    setRevealedSecrets(prev => {
      const next = { ...prev, [id]: !prev[id] };
      if (next[id]) {
        revealTimersRef.current[id] = setTimeout(() => {
          setRevealedSecrets(p => ({ ...p, [id]: false }));
          delete revealTimersRef.current[id];
        }, 30000);
      }
      return next;
    });
  }, []);

  const handleRotateClick = useCallback((rotationId: string) => {
    if (confirmRotateId === rotationId) {
      setRotateTargetId(rotationId);
      setShowRotate(true);
      setConfirmRotateId(null);
    } else {
      setConfirmRotateId(rotationId);
      setTimeout(() => setConfirmRotateId(null), 5000);
    }
  }, [confirmRotateId]);

  if (isLoading) return <div className="flex items-center justify-center py-4"><Loader2 className="h-4 w-4 animate-spin text-muted-foreground" /></div>;

  return (
    <div className="space-y-3 mt-3 border-t pt-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold flex items-center gap-1.5">
          <KeyRound className="h-3.5 w-3.5 text-muted-foreground" />
          Secret Rotation
        </h4>
        <div className="flex gap-1">
          <Button size="sm" variant="outline" className="h-6 px-2 text-[10px]" onClick={() => createMutation.mutate()} disabled={createMutation.isPending}>
            <Plus className="h-3 w-3 mr-1" />{createMutation.isPending ? "Adding..." : "Add Schedule"}
          </Button>
        </div>
      </div>

      {!rotations?.length ? (
        <p className="text-xs text-muted-foreground">No secret rotation schedules configured.</p>
      ) : (
        <div className="space-y-2">
          {rotations.map(r => (
            <div key={r.id} className={`flex items-center justify-between p-2 rounded border text-xs ${isExpiringSoon(r.nextRotationDue) ? "border-yellow-500/30 bg-yellow-500/5" : ""}`}>
              <div className="flex items-center gap-3">
                <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">{r.secretField}</Badge>
                <button
                  onClick={() => toggleReveal(r.id)}
                  className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
                  title={revealedSecrets[r.id] ? "Click to hide (auto-hides in 30s)" : "Click to reveal"}
                >
                  <Eye className="h-3 w-3" />
                  <span className="font-mono text-[10px]">
                    {revealedSecrets[r.id] ? r.secretField : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}
                  </span>
                </button>
                <span className="text-muted-foreground">Every {r.rotationIntervalDays}d</span>
                {r.lastRotatedAt && (
                  <span className="text-muted-foreground">Last: {new Date(r.lastRotatedAt).toLocaleDateString()}</span>
                )}
                {r.nextRotationDue && (
                  <span className={isExpiringSoon(r.nextRotationDue) ? "text-yellow-400 font-medium" : "text-muted-foreground"}>
                    Due: {new Date(r.nextRotationDue).toLocaleDateString()}
                    {isExpiringSoon(r.nextRotationDue) && " (soon)"}
                  </span>
                )}
                {r.rotatedByName && <span className="text-muted-foreground">by {r.rotatedByName}</span>}
              </div>
              <Button
                size="sm"
                variant={confirmRotateId === r.id ? "destructive" : "outline"}
                className="h-6 px-2 text-[10px]"
                onClick={() => handleRotateClick(r.id)}
              >
                <RotateCcw className="h-3 w-3 mr-1" />
                {confirmRotateId === r.id ? "Confirm Rotate?" : "Rotate"}
              </Button>
            </div>
          ))}
        </div>
      )}

      <Dialog open={showRotate} onOpenChange={setShowRotate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Rotate Secret</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div className="flex items-center gap-2 p-3 rounded-md bg-amber-500/10 border border-amber-500/20">
              <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" />
              <p className="text-xs text-amber-300">Rotating a secret will immediately update the connector configuration. Ensure the new value is valid before proceeding.</p>
            </div>
            <div>
              <Label className="text-xs">New Secret Value</Label>
              <Input type="password" value={newSecretValue} onChange={e => setNewSecretValue(e.target.value)} placeholder="Enter new secret value" />
              {newSecretValue && newSecretValue.length < 8 && (
                <p className="text-xs text-amber-400 mt-1">Secret values should be at least 8 characters</p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRotate(false)}>Cancel</Button>
            <Button onClick={() => rotateTargetId && rotateMutation.mutate(rotateTargetId)} disabled={!newSecretValue || !rotateTargetId || rotateMutation.isPending}>
              {rotateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <RotateCcw className="h-4 w-4 mr-1" />}
              Rotate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ConnectorTestResultCard({ result, connectorType }: { result: { success: boolean; latencyMs?: number; message?: string } | null; connectorType: string }) {
  if (!result) return null;

  const remediationMap: Record<string, string[]> = {
    "authentication": ["Verify your API key or credentials are correct", "Check if the key has expired or been revoked", "Ensure the key has the required permissions/scopes"],
    "timeout": ["Check if the service endpoint is reachable from your network", "Verify there are no firewall rules blocking the connection", "Try increasing the polling interval"],
    "rate_limit": ["Reduce the polling frequency", "Check your API rate limit quota", "Consider upgrading your API plan"],
    "not_found": ["Verify the API endpoint URL is correct", "Check if the service has been moved or deprecated", "Confirm the base URL matches the documentation"],
    "default": ["Check the connector configuration settings", "Verify network connectivity to the service", "Review the service's status page for outages"],
  };

  const getRemediation = (msg: string | undefined): string[] => {
    if (!msg) return remediationMap["default"];
    const lower = msg.toLowerCase();
    if (lower.includes("auth") || lower.includes("401") || lower.includes("403") || lower.includes("key")) return remediationMap["authentication"];
    if (lower.includes("timeout") || lower.includes("timed out") || lower.includes("econnrefused")) return remediationMap["timeout"];
    if (lower.includes("rate") || lower.includes("429") || lower.includes("throttl")) return remediationMap["rate_limit"];
    if (lower.includes("404") || lower.includes("not found")) return remediationMap["not_found"];
    return remediationMap["default"];
  };

  if (result.success) {
    return (
      <div className="mt-3 p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5" data-testid="test-result-card-success">
        <div className="flex items-center gap-2">
          <CheckCircle className="h-4 w-4 text-emerald-400" />
          <span className="text-sm font-medium text-emerald-400">Connection Successful</span>
          {result.latencyMs !== undefined && (
            <Badge variant="outline" className="ml-auto text-[10px] no-default-hover-elevate no-default-active-elevate">
              {result.latencyMs}ms
            </Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-1.5">The {connectorType} connector is configured correctly and responding.</p>
      </div>
    );
  }

  const steps = getRemediation(result.message);
  return (
    <div className="mt-3 p-3 rounded-lg border border-destructive/30 bg-destructive/5" data-testid="test-result-card-failure">
      <div className="flex items-center gap-2">
        <XCircle className="h-4 w-4 text-destructive" />
        <span className="text-sm font-medium text-destructive">Connection Failed</span>
      </div>
      {result.message && <p className="text-xs text-muted-foreground mt-1.5 font-mono bg-muted/30 p-2 rounded">{result.message}</p>}
      <div className="mt-2">
        <p className="text-xs font-medium mb-1">Remediation Steps:</p>
        <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
          {steps.map((step, i) => <li key={i}>{step}</li>)}
        </ol>
      </div>
    </div>
  );
}

function DeadLetterQueueView({ connectors }: { connectors: ConnectorItem[] }) {
  const { data: deadLetters, isLoading } = useQuery<ConnectorJobRun[]>({
    queryKey: ["/api/connectors/dead-letters"],
  });

  const connectorNameMap = connectors.reduce((acc, c) => {
    acc[c.id] = c.name;
    return acc;
  }, {} as Record<string, string>);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Dead Letter Queue</CardTitle>
        <CardDescription>Job runs that have exhausted all retry attempts</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : !deadLetters?.length ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Skull className="h-10 w-10 mb-3" />
            <p className="text-sm">No dead letter entries</p>
            <p className="text-xs mt-1">All job runs have been processed successfully or are still retrying</p>
          </div>
        ) : (
          <Table data-testid="table-dead-letters">
            <TableHeader>
              <TableRow>
                <TableHead>Connector</TableHead>
                <TableHead>Error</TableHead>
                <TableHead>Started At</TableHead>
                <TableHead>Attempts</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {deadLetters.map(dl => (
                <TableRow key={dl.id} data-testid={`row-dead-letter-${dl.id}`}>
                  <TableCell className="font-medium">{connectorNameMap[dl.connectorId] || dl.connectorId}</TableCell>
                  <TableCell className="text-sm text-destructive max-w-md truncate">{dl.errorMessage || "-"}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {dl.startedAt ? new Date(dl.startedAt).toLocaleString() : "-"}
                  </TableCell>
                  <TableCell className="text-sm font-mono">{dl.attempt}/{dl.maxAttempts}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export default function ConnectorsPage() {
  const { toast } = useToast();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedType, setSelectedType] = useState<string>("");
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [connectorName, setConnectorName] = useState("");
  const [pollingInterval, setPollingInterval] = useState("5");
  const [testingId, setTestingId] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; latencyMs?: number; message?: string }>>({});
  const [touchedFields, setTouchedFields] = useState<Record<string, boolean>>({});
  const [healthCheckingId, setHealthCheckingId] = useState<string | null>(null);
  const [expandedConnectorId, setExpandedConnectorId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("all-connectors");

  const { data: connectorTypes, isLoading: typesLoading } = useQuery<ConnectorType[]>({
    queryKey: ["/api/connectors/types"],
  });

  const { data: existingConnectors, isLoading: connectorsLoading } = useQuery<ConnectorItem[]>({
    queryKey: ["/api/connectors"],
  });

  const { data: deadLetters } = useQuery<ConnectorJobRun[]>({
    queryKey: ["/api/connectors/dead-letters"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/connectors", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      setShowCreateDialog(false);
      resetForm();
      toast({ title: "Connector created", description: "Ready to test and sync." });
    },
    onError: (err: any) => {
      toast({ title: "Failed to create connector", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/connectors/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      toast({ title: "Connector deleted" });
    },
    onError: (err: any) => {
      toast({ title: "Failed to delete", description: err.message, variant: "destructive" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      const res = await apiRequest("POST", `/api/connectors/${id}/test`);
      return { id, data: await res.json() };
    },
    onSuccess: ({ id, data }: { id: string; data: { success: boolean; latencyMs?: number; message?: string } }) => {
      setTestingId(null);
      setTestResults(prev => ({ ...prev, [id]: data }));
      if (data.success) {
        toast({ title: "Connection successful", description: `Latency: ${data.latencyMs}ms` });
      } else {
        toast({ title: "Connection failed", description: data.message, variant: "destructive" });
      }
    },
    onError: (err: any) => {
      setTestingId(null);
      toast({ title: "Test failed", description: err.message, variant: "destructive" });
    },
  });

  const syncMutation = useMutation({
    mutationFn: async (id: string) => {
      setSyncingId(id);
      const res = await apiRequest("POST", `/api/connectors/${id}/sync`);
      return res.json();
    },
    onSuccess: (data: any) => {
      setSyncingId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ingestion/stats"] });
      if (data.success) {
        toast({
          title: "Sync complete",
          description: `Received: ${data.alertsReceived}, Created: ${data.alertsCreated}, Deduped: ${data.alertsDeduped}`,
        });
      } else {
        toast({ title: "Sync had errors", description: data.errors?.[0] || "Unknown error", variant: "destructive" });
      }
    },
    onError: (err: any) => {
      setSyncingId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      toast({ title: "Sync failed", description: err.message, variant: "destructive" });
    },
  });

  const healthCheckMutation = useMutation({
    mutationFn: async (id: string) => {
      setHealthCheckingId(id);
      const res = await apiRequest("POST", `/api/connectors/${id}/health-check`);
      return res.json();
    },
    onSuccess: (data: any) => {
      setHealthCheckingId(null);
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      if (data.status === "healthy") {
        toast({ title: "Health check passed", description: `Latency: ${data.latencyMs}ms` });
      } else {
        toast({ title: "Health check failed", description: data.errorMessage || "Unhealthy", variant: "destructive" });
      }
    },
    onError: (err: any) => {
      setHealthCheckingId(null);
      toast({ title: "Health check failed", description: err.message, variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, newStatus }: { id: string; newStatus: string }) => {
      const res = await apiRequest("PATCH", `/api/connectors/${id}`, { status: newStatus });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
    },
  });

  function resetForm() {
    setSelectedType("");
    setFormData({});
    setConnectorName("");
    setPollingInterval("5");
    setTouchedFields({});
  }

  function handleCreate() {
    if (!selectedType || !connectorName) return;
    const meta = connectorTypes?.find(t => t.type === selectedType);
    if (!meta) return;
    const config: Record<string, string> = {};
    for (const field of [...meta.requiredFields, ...meta.optionalFields]) {
      if (formData[field.key]) config[field.key] = formData[field.key];
    }
    const missingRequired = meta.requiredFields.filter(f => !config[f.key]);
    if (missingRequired.length > 0) {
      toast({ title: "Missing required fields", description: missingRequired.map(f => f.label).join(", "), variant: "destructive" });
      return;
    }
    createMutation.mutate({
      name: connectorName,
      type: selectedType,
      authType: meta.authType,
      config,
      pollingIntervalMin: parseInt(pollingInterval) || 5,
    });
  }

  const selectedMeta = connectorTypes?.find(t => t.type === selectedType);
  const activeCount = existingConnectors?.filter(c => c.status === "active").length || 0;
  const errorCount = existingConnectors?.filter(c => c.status === "error").length || 0;
  const totalSynced = existingConnectors?.reduce((sum, c) => sum + (c.totalAlertsSynced || 0), 0) || 0;

  const deadLetterConnectorIds = new Set(
    deadLetters?.filter(dl => dl.isDeadLetter).map(dl => dl.connectorId) || []
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Connectors</span></h1>
          <p className="text-sm text-muted-foreground">Pull-based integrations that actively fetch alerts from your security tools</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Button onClick={() => setShowCreateDialog(true)} aria-label="Add new connector" data-testid="button-add-connector">
          <Plus className="h-4 w-4 mr-2" aria-hidden="true" />
          Add Connector
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Connectors</CardTitle>
            <Plug className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-connectors">{existingConnectors?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-active-count">{activeCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Errors</CardTitle>
            <XCircle className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-error-count">{errorCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Alerts Synced</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-synced">{totalSynced}</div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="all-connectors" data-testid="tab-all-connectors">
            <Plug className="h-4 w-4 mr-2" />
            All Connectors
          </TabsTrigger>
          <TabsTrigger value="dead-letters" data-testid="tab-dead-letters">
            <Skull className="h-4 w-4 mr-2" />
            Dead Letter Queue
            {deadLetters && deadLetters.length > 0 && (
              <Badge variant="destructive" className="ml-2" data-testid="badge-dead-letter-count">
                {deadLetters.length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all-connectors">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Configured Connectors</CardTitle>
              <CardDescription>Manage connections to your security tools</CardDescription>
            </CardHeader>
            <CardContent>
              {connectorsLoading ? (
                <div className="space-y-3 py-6" role="status" aria-label="Loading connectors">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <div key={i} className="flex items-center gap-4 px-4 py-3 border-b last:border-0">
                      <Skeleton className="h-4 w-4 rounded" />
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-4 w-24" />
                      <Skeleton className="h-5 w-16 rounded-full" />
                      <Skeleton className="h-4 w-28" />
                      <Skeleton className="h-4 w-12" />
                    </div>
                  ))}
                  <span className="sr-only">Loading connectors...</span>
                </div>
              ) : !existingConnectors?.length ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground" role="status" aria-label="No connectors">
                  <Unplug className="h-10 w-10 mb-3" aria-hidden="true" />
                  <p className="text-sm font-medium">No connectors configured yet</p>
                  <p className="text-xs mt-1">Add a connector to start pulling alerts from your security tools</p>
                  <Button className="mt-4" size="sm" onClick={() => setShowCreateDialog(true)} aria-label="Add your first connector">
                    <Plus className="h-4 w-4 mr-1.5" aria-hidden="true" />
                    Add First Connector
                  </Button>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8"></TableHead>
                      <TableHead>Connector</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last Sync</TableHead>
                      <TableHead>Alerts Synced</TableHead>
                      <TableHead>Interval</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {existingConnectors.map(connector => {
                      const meta = connectorTypes?.find(t => t.type === connector.type);
                      const IconComp = getIcon(meta?.icon || "");
                      const isExpanded = expandedConnectorId === connector.id;
                      const hasDeadLetters = deadLetterConnectorIds.has(connector.id);
                      return (
                        <>
                          <TableRow
                            key={connector.id}
                            data-testid={`row-connector-${connector.id}`}
                            className="cursor-pointer"
                            onClick={() => setExpandedConnectorId(isExpanded ? null : connector.id)}
                          >
                            <TableCell>
                              {isExpanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <IconComp className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-medium" data-testid={`text-connector-name-${connector.id}`}>{connector.name}</span>
                                    {hasDeadLetters && (
                                      <Badge variant="destructive" data-testid="badge-dead-letter">
                                        <Skull className="h-3 w-3 mr-1" />DLQ
                                      </Badge>
                                    )}
                                  </div>
                                  {connector.lastSyncError && connector.status === "error" && (
                                    <p className="text-xs text-destructive mt-0.5 max-w-xs truncate">{connector.lastSyncError}</p>
                                  )}
                                </div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <span className="text-sm text-muted-foreground">{meta?.name || connector.type}</span>
                                {meta?.docsUrl && (
                                  <a
                                    href={meta.docsUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-flex items-center text-primary hover:underline"
                                    data-testid={`link-table-docs-${connector.id}`}
                                    onClick={e => e.stopPropagation()}
                                  >
                                    <ExternalLink className="h-3 w-3" />
                                  </a>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>{statusBadge(connector.status)}</TableCell>
                            <TableCell>
                              {connector.lastSyncAt ? (
                                <div className="flex items-center gap-1 text-sm text-muted-foreground">
                                  <Clock className="h-3 w-3" />
                                  {new Date(connector.lastSyncAt).toLocaleString()}
                                </div>
                              ) : (
                                <span className="text-sm text-muted-foreground">Never</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <span className="text-sm font-mono" data-testid={`text-synced-${connector.id}`}>{connector.totalAlertsSynced || 0}</span>
                            </TableCell>
                            <TableCell>
                              <span className="text-sm text-muted-foreground">{connector.pollingIntervalMin || 5}m</span>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => healthCheckMutation.mutate(connector.id)}
                                  disabled={healthCheckingId === connector.id}
                                                aria-label="Health check"
                                                data-testid={`button-health-check-${connector.id}`}
                                              >
                                                {healthCheckingId === connector.id ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <HeartPulse className="h-4 w-4" aria-hidden="true" />}
                                </Button>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => testMutation.mutate(connector.id)}
                                  disabled={testingId === connector.id}
                                                aria-label="Test connection"
                                                data-testid={`button-test-${connector.id}`}
                                              >
                                                {testingId === connector.id ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <TestTube className="h-4 w-4" aria-hidden="true" />}
                                </Button>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => syncMutation.mutate(connector.id)}
                                  disabled={syncingId === connector.id}
                                                aria-label="Sync now"
                                                data-testid={`button-sync-${connector.id}`}
                                              >
                                                {syncingId === connector.id ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
                                </Button>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => {
                                    const newStatus = connector.status === "inactive" ? "active" : "inactive";
                                    toggleMutation.mutate({ id: connector.id, newStatus });
                                  }}
                                  data-testid={`button-toggle-${connector.id}`}
                                >
                                  {connector.status === "inactive" ? <Plug className="h-4 w-4" /> : <Settings2 className="h-4 w-4" />}
                                </Button>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => {
                                    if (confirm("Delete this connector? This cannot be undone.")) {
                                      deleteMutation.mutate(connector.id);
                                    }
                                  }}
                                                aria-label="Delete connector"
                                                data-testid={`button-delete-${connector.id}`}
                                              >
                                                <Trash2 className="h-4 w-4" aria-hidden="true" />
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                          {isExpanded && (
                            <TableRow key={`${connector.id}-detail`}>
                              <TableCell colSpan={8} className="p-0">
                                {testResults[connector.id] && (
                                  <div className="px-4 pt-3">
                                    <ConnectorTestResultCard result={testResults[connector.id]} connectorType={meta?.name || connector.type} />
                                  </div>
                                )}
                                <ConnectorObservabilityPanel connector={connector} />
                                <ConnectorSecretRotationPanel connectorId={connector.id} />
                              </TableCell>
                            </TableRow>
                          )}
                        </>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {!typesLoading && connectorTypes && (
            <Card className="mt-6">
              <CardHeader>
                <CardTitle className="text-lg">Available Integrations</CardTitle>
                <CardDescription>Security tools you can connect to SecureNexus</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {connectorTypes.map(ct => {
                    const IconComp = getIcon(ct.icon);
                    const isConnected = existingConnectors?.some(c => c.type === ct.type);
                    return (
                      <Card key={ct.type} className={isConnected ? "border-primary/30" : ""}>
                        <CardContent className="p-4">
                          <div className="flex items-start gap-3">
                            <div className="flex items-center justify-center w-9 h-9 rounded-md bg-muted flex-shrink-0">
                              <IconComp className="h-4 w-4" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-medium text-sm" data-testid={`text-type-name-${ct.type}`}>{ct.name}</span>
                                {isConnected && <Badge variant="secondary" className="text-[10px]">Connected</Badge>}
                              </div>
                              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{ct.description}</p>
                              {ct.docsUrl && (
                                <a
                                  href={ct.docsUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-xs text-primary mt-2 hover:underline"
                                  data-testid={`link-docs-${ct.type}`}
                                >
                                  <BookOpen className="h-3 w-3" />
                                  API Docs
                                  <ExternalLink className="h-2.5 w-2.5" />
                                </a>
                              )}
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="dead-letters">
          <DeadLetterQueueView connectors={existingConnectors || []} />
        </TabsContent>
      </Tabs>

      <Dialog open={showCreateDialog} onOpenChange={(open) => { if (!open) resetForm(); setShowCreateDialog(open); }}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Connector</DialogTitle>
            <DialogDescription>Connect a security tool to pull alerts automatically</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="connector-name">Connector Name</Label>
              <Input
                id="connector-name"
                placeholder="e.g. Production CrowdStrike"
                value={connectorName}
                onChange={e => setConnectorName(e.target.value)}
                data-testid="input-connector-name"
              />
            </div>
            <div className="space-y-2">
              <Label>Source Type</Label>
              <Select value={selectedType} onValueChange={(val) => { setSelectedType(val); setFormData({}); }}>
                <SelectTrigger data-testid="select-connector-type">
                  <SelectValue placeholder="Select a security tool..." />
                </SelectTrigger>
                <SelectContent>
                  {connectorTypes?.map(ct => (
                    <SelectItem key={ct.type} value={ct.type} data-testid={`option-type-${ct.type}`}>
                      {ct.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {selectedMeta && (
              <>
                {selectedMeta.docsUrl && (
                  <div className="flex items-center gap-2 p-3 rounded-md bg-muted">
                    <BookOpen className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-muted-foreground">
                        Refer to the official API documentation to find the required credentials and endpoint details.
                      </p>
                    </div>
                    <a
                      href={selectedMeta.docsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      data-testid="link-docs-selected"
                    >
                      <Button variant="outline" size="sm" type="button">
                        <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
                        View API Docs
                      </Button>
                    </a>
                  </div>
                )}
                {selectedMeta.requiredFields.map(field => {
                  const val = formData[field.key] || "";
                  const isTouched = touchedFields[field.key];
                  const isEmpty = !val.trim();
                  const isUrl = field.key.toLowerCase().includes("url") || field.key.toLowerCase().includes("endpoint");
                  const urlInvalid = isUrl && val.trim() && !/^https?:\/\/.+/.test(val.trim());
                  return (
                    <div key={field.key} className="space-y-2">
                      <Label htmlFor={`field-${field.key}`}>{field.label} <span className="text-destructive">*</span></Label>
                      <Input
                        id={`field-${field.key}`}
                        type={field.type === "password" ? "password" : "text"}
                        placeholder={field.placeholder}
                        value={val}
                        onChange={e => setFormData(prev => ({ ...prev, [field.key]: e.target.value }))}
                        onBlur={() => setTouchedFields(prev => ({ ...prev, [field.key]: true }))}
                        className={isTouched && isEmpty ? "border-destructive" : urlInvalid ? "border-amber-500" : ""}
                        data-testid={`input-${field.key}`}
                      />
                      {isTouched && isEmpty && <p className="text-xs text-destructive">{field.label} is required</p>}
                      {urlInvalid && <p className="text-xs text-amber-400">URL should start with http:// or https://</p>}
                    </div>
                  );
                })}
                {selectedMeta.optionalFields.map(field => {
                  const val = formData[field.key] || "";
                  const isUrl = field.key.toLowerCase().includes("url") || field.key.toLowerCase().includes("endpoint");
                  const urlInvalid = isUrl && val.trim() && !/^https?:\/\/.+/.test(val.trim());
                  return (
                    <div key={field.key} className="space-y-2">
                      <Label htmlFor={`field-${field.key}`}>{field.label}</Label>
                      <Input
                        id={`field-${field.key}`}
                        type={field.type === "password" ? "password" : "text"}
                        placeholder={field.placeholder}
                        value={val}
                        onChange={e => setFormData(prev => ({ ...prev, [field.key]: e.target.value }))}
                        className={urlInvalid ? "border-amber-500" : ""}
                        data-testid={`input-${field.key}`}
                      />
                      {urlInvalid && <p className="text-xs text-amber-400">URL should start with http:// or https://</p>}
                    </div>
                  );
                })}
                <div className="space-y-2">
                  <Label htmlFor="polling-interval">Polling Interval (minutes)</Label>
                  <Input
                    id="polling-interval"
                    type="number"
                    min="1"
                    max="1440"
                    value={pollingInterval}
                    onChange={e => setPollingInterval(e.target.value)}
                    data-testid="input-polling-interval"
                  />
                </div>
              </>
            )}
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => { resetForm(); setShowCreateDialog(false); }} data-testid="button-cancel-create">
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!selectedType || !connectorName || createMutation.isPending || (selectedMeta ? selectedMeta.requiredFields.some(f => !formData[f.key]?.trim()) : false)}
              data-testid="button-confirm-create"
            >
              {createMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Create Connector
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
