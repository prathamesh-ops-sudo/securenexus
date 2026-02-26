import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Key,
  Plus,
  Copy,
  Trash2,
  Activity,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ArrowDownToLine,
  Clock,
  Server,
  Loader2,
  Eye,
  EyeOff,
} from "lucide-react";

interface ApiKeyDisplay {
  id: string;
  name: string;
  keyPrefix: string;
  orgId: string | null;
  scopes: string[] | null;
  isActive: boolean | null;
  lastUsedAt: string | null;
  createdAt: string | null;
  revokedAt: string | null;
}

interface NewKeyResponse {
  id: string;
  name: string;
  key: string;
  keyPrefix: string;
  message: string;
}

interface IngestionLog {
  id: string;
  source: string;
  status: string;
  alertsReceived: number | null;
  alertsCreated: number | null;
  alertsDeduped: number | null;
  alertsFailed: number | null;
  errorMessage: string | null;
  requestId: string | null;
  processingTimeMs: number | null;
  receivedAt: string | null;
}

interface IngestionStats {
  totalIngested: number;
  totalCreated: number;
  totalDeduped: number;
  totalFailed: number;
  sourceBreakdown: { source: string; count: number; lastReceived: string | null }[];
}

export default function IngestionPage() {
  const { toast } = useToast();
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<NewKeyResponse | null>(null);
  const [showKey, setShowKey] = useState(false);

  const {
    data: apiKeysData,
    isLoading: keysLoading,
    isError: keysError,
    refetch: refetchKeys,
  } = useQuery<ApiKeyDisplay[]>({
    queryKey: ["/api/api-keys"],
  });

  const {
    data: ingestionLogs,
    isLoading: logsLoading,
    isError: logsError,
    refetch: refetchLogs,
  } = useQuery<IngestionLog[]>({
    queryKey: ["/api/ingestion/logs"],
  });

  const { data: ingestionStats, isLoading: statsLoading } = useQuery<IngestionStats>({
    queryKey: ["/api/ingestion/stats"],
  });

  const { data: sourcesData } = useQuery<{ supportedSources: string[]; sourceNames: Record<string, string> }>({
    queryKey: ["/api/ingestion/sources"],
  });

  const createKeyMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await apiRequest("POST", "/api/api-keys", { name });
      return res.json();
    },
    onSuccess: (data: NewKeyResponse) => {
      setCreatedKey(data);
      setNewKeyName("");
      setShowCreateDialog(false);
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API key created", description: "Copy and store the key securely." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to create key", description: error.message, variant: "destructive" });
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/api-keys/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API key revoked" });
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied to clipboard" });
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case "success":
        return (
          <Badge variant="default" data-testid={`badge-status-${status}`}>
            <CheckCircle className="h-3 w-3 mr-1" /> Success
          </Badge>
        );
      case "deduped":
        return (
          <Badge variant="secondary" data-testid={`badge-status-${status}`}>
            <Copy className="h-3 w-3 mr-1" /> Deduped
          </Badge>
        );
      case "partial":
        return (
          <Badge variant="secondary" data-testid={`badge-status-${status}`}>
            <AlertTriangle className="h-3 w-3 mr-1" /> Partial
          </Badge>
        );
      case "failed":
        return (
          <Badge variant="destructive" data-testid={`badge-status-${status}`}>
            <XCircle className="h-3 w-3 mr-1" /> Failed
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" data-testid={`badge-status-${status}`}>
            {status}
          </Badge>
        );
    }
  };

  const formatTime = (ts: string | null) => {
    if (!ts) return "Never";
    return new Date(ts).toLocaleString();
  };

  if (keysError || logsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load ingestion data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchKeys();
            refetchLogs();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Alert Ingestion</span>
          </h1>
          <p className="text-sm text-muted-foreground">
            Manage API keys and monitor alert ingestion from security tools
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Ingested</CardTitle>
            <ArrowDownToLine className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-ingested">
              {statsLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : (ingestionStats?.totalIngested ?? 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Alerts Created</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-alerts-created">
              {statsLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : (ingestionStats?.totalCreated ?? 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Deduplicated</CardTitle>
            <Copy className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-deduped">
              {statsLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : (ingestionStats?.totalDeduped ?? 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <XCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-failed">
              {statsLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : (ingestionStats?.totalFailed ?? 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      {sourcesData && ingestionStats && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Source Status</CardTitle>
            <CardDescription>Ingestion health per security tool</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {Object.entries(sourcesData.sourceNames).map(([key, name]) => {
                const sourceStats = ingestionStats.sourceBreakdown.find((s) => s.source === name);
                return (
                  <Card key={key} className="bg-muted/30">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm font-medium truncate" data-testid={`text-source-name-${key}`}>
                          {name}
                        </span>
                      </div>
                      {sourceStats ? (
                        <div className="space-y-1">
                          <div className="flex items-center gap-1 text-xs text-muted-foreground">
                            <Activity className="h-3 w-3" />
                            <span>{sourceStats.count} ingestions</span>
                          </div>
                          <div className="flex items-center gap-1 text-xs text-muted-foreground">
                            <Clock className="h-3 w-3" />
                            <span>{formatTime(sourceStats.lastReceived)}</span>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground">No data yet</p>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4 flex-wrap">
          <div>
            <CardTitle className="text-base">API Keys</CardTitle>
            <CardDescription>Create and manage API keys for alert ingestion endpoints</CardDescription>
          </div>
          <Button onClick={() => setShowCreateDialog(true)} data-testid="button-create-api-key">
            <Plus className="h-4 w-4 mr-1" /> Create Key
          </Button>
        </CardHeader>
        <CardContent>
          {keysLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : !apiKeysData || apiKeysData.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No API keys yet. Create one to start ingesting alerts.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Key Prefix</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Used</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[60px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apiKeysData.map((key) => (
                  <TableRow key={key.id} data-testid={`row-api-key-${key.id}`}>
                    <TableCell className="font-medium">{key.name}</TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{key.keyPrefix}...</code>
                    </TableCell>
                    <TableCell>
                      {key.isActive ? (
                        <Badge variant="default">Active</Badge>
                      ) : (
                        <Badge variant="destructive">Revoked</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatTime(key.lastUsedAt)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatTime(key.createdAt)}</TableCell>
                    <TableCell>
                      {key.isActive && (
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => revokeKeyMutation.mutate(key.id)}
                          disabled={revokeKeyMutation.isPending}
                          data-testid={`button-revoke-key-${key.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Ingestion Logs</CardTitle>
          <CardDescription>Latest alert ingestion activity across all sources</CardDescription>
        </CardHeader>
        <CardContent>
          {logsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : !ingestionLogs || ingestionLogs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No ingestion activity yet.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Received</TableHead>
                    <TableHead className="text-right">Created</TableHead>
                    <TableHead className="text-right">Deduped</TableHead>
                    <TableHead className="text-right">Failed</TableHead>
                    <TableHead className="text-right">Time (ms)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ingestionLogs.map((log) => (
                    <TableRow key={log.id} data-testid={`row-ingestion-log-${log.id}`}>
                      <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                        {formatTime(log.receivedAt)}
                      </TableCell>
                      <TableCell className="font-medium text-sm">{log.source}</TableCell>
                      <TableCell>{statusBadge(log.status)}</TableCell>
                      <TableCell className="text-right text-sm">{log.alertsReceived ?? 0}</TableCell>
                      <TableCell className="text-right text-sm">{log.alertsCreated ?? 0}</TableCell>
                      <TableCell className="text-right text-sm">{log.alertsDeduped ?? 0}</TableCell>
                      <TableCell className="text-right text-sm">{log.alertsFailed ?? 0}</TableCell>
                      <TableCell className="text-right text-sm text-muted-foreground">
                        {log.processingTimeMs ?? "-"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Integration Guide</CardTitle>
          <CardDescription>How to send alerts from your security tools</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <h3 className="text-sm font-semibold">Single Alert</h3>
            <pre className="bg-muted p-3 rounded-md text-xs overflow-x-auto" data-testid="text-curl-single">
              {`curl -X POST \\
  ${window.location.origin}/api/ingest/crowdstrike \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"detection_id": "det_123", "severity": 4, "detect_name": "Malware detected"}'`}
            </pre>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-semibold">Bulk Ingestion</h3>
            <pre className="bg-muted p-3 rounded-md text-xs overflow-x-auto" data-testid="text-curl-bulk">
              {`curl -X POST \\
  ${window.location.origin}/api/ingest/splunk/bulk \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '[{"sid": "event1", "severity": "high"}, {"sid": "event2", "severity": "low"}]'`}
            </pre>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-semibold">Supported Sources</h3>
            <div className="flex flex-wrap gap-2">
              {sourcesData &&
                Object.entries(sourcesData.sourceNames).map(([key, name]) => (
                  <Badge key={key} variant="outline" data-testid={`badge-source-${key}`}>
                    {name}
                  </Badge>
                ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>This key will allow external tools to push alerts into SecureNexus.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Input
              placeholder="Key name (e.g. CrowdStrike Production)"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              data-testid="input-key-name"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)} data-testid="button-cancel-create">
              Cancel
            </Button>
            <Button
              onClick={() => createKeyMutation.mutate(newKeyName)}
              disabled={!newKeyName.trim() || createKeyMutation.isPending}
              data-testid="button-confirm-create"
            >
              {createKeyMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Key className="h-4 w-4 mr-1" />
              )}
              Create Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!createdKey} onOpenChange={() => setCreatedKey(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
            <DialogDescription>Copy this key now. It will not be shown again.</DialogDescription>
          </DialogHeader>
          {createdKey && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-muted p-3 rounded-md text-xs break-all" data-testid="text-new-key">
                  {showKey ? createdKey.key : `${createdKey.keyPrefix}${"*".repeat(40)}`}
                </code>
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() => setShowKey(!showKey)}
                  data-testid="button-toggle-key-visibility"
                >
                  {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() => copyToClipboard(createdKey.key)}
                  data-testid="button-copy-key"
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">Use this key in the X-API-Key header when sending alerts.</p>
            </div>
          )}
          <DialogFooter>
            <Button
              onClick={() => {
                setCreatedKey(null);
                setShowKey(false);
              }}
              data-testid="button-done-key"
            >
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
