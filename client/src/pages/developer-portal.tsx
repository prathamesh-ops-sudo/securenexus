import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Key,
  Webhook,
  Code2,
  Package,
  Plus,
  Trash2,
  Copy,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  ShieldCheck,
  Eye,
  EyeOff,
  Send,
  ChevronRight,
  ExternalLink,
  Download,
  BookOpen,
  Terminal,
  AlertTriangle,
  RotateCcw,
  Gauge,
  GitBranch,
  BarChart3,
  Play,
  FileJson,
  Zap,
  TrendingUp,
  Lock,
} from "lucide-react";
import { SuccessIcon, EyeToggleIcon, DownloadDoneIcon } from "@/components/ui/animated-state-icons";

type PortalTab = "api-keys" | "webhooks" | "api-docs" | "sdk";

interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  orgId: string | null;
  scopes: string[] | null;
  isActive: boolean | null;
  lastUsedAt: string | null;
  createdBy: string | null;
  createdAt: string | null;
  revokedAt: string | null;
}

interface OutboundWebhook {
  id: string;
  orgId: string | null;
  url: string;
  isActive: boolean | null;
  webhookSecret: string | null;
  lastUsedAt: string | null;
  createdBy: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface WebhookLog {
  id: string;
  webhookId: string;
  event: string;
  responseStatus: number | null;
  success: boolean | null;
  createdAt: string | null;
}

interface ApiSummary {
  totalEndpoints: number;
  totalOperations: number;
  tags: { name: string; endpoints: number; methods: string[] }[];
}

function ApiKeysTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(["ingest"]);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [keyVisible, setKeyVisible] = useState(false);

  const { data: keys, isLoading } = useQuery<ApiKey[]>({
    queryKey: ["/api/api-keys"],
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      if (!newKeyName.trim()) throw new Error("Name is required");
      const res = await apiRequest("POST", "/api/api-keys", {
        name: newKeyName.trim(),
        scopes: newKeyScopes,
      });
      return await res.json();
    },
    onSuccess: (data: { key?: string }) => {
      setCreatedKey(data.key || null);
      setKeyVisible(true);
      setNewKeyName("");
      setShowCreateForm(false);
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API key created successfully" });
    },
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const revokeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/api-keys/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API key revoked" });
    },
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const copyToClipboard = useCallback(
    (text: string) => {
      navigator.clipboard.writeText(text);
      toast({ title: "Copied to clipboard" });
    },
    [toast],
  );

  const scopeOptions = [
    { id: "ingest", label: "Ingest", description: "Send data into the platform" },
    { id: "alerts:read", label: "Read Alerts", description: "Read alerts and incidents" },
    { id: "alerts:write", label: "Write Alerts", description: "Modify alert status" },
    { id: "incidents:read", label: "Read Incidents", description: "View incident details" },
  ];

  const activeKeys = keys?.filter((k) => k.isActive) || [];
  const revokedKeys = keys?.filter((k) => !k.isActive) || [];

  return (
    <div data-testid="developer-portal-page" className="space-y-6">
      {createdKey && (
        <Card data-testid="developer-portal-card-1" className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <ShieldCheck className="h-5 w-5 text-emerald-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-emerald-400">API Key Created</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Store this key securely. It will not be shown again.
                </p>
                <div className="flex items-center gap-2 mt-2">
                  <code className="text-xs font-mono bg-muted/30 px-2 py-1 rounded flex-1 truncate">
                    {keyVisible ? createdKey : "••••••••••••••••••••••••••••••••"}
                  </code>
                  <Button
                    data-testid="developer-portal-btn-ghost-0"
                    variant="ghost"
                    size="sm"
                    className="shrink-0"
                    onClick={() => setKeyVisible(!keyVisible)}
                  >
                    {keyVisible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </Button>
                  <Button
                    data-testid="developer-portal-btn-ghost-1"
                    variant="ghost"
                    size="sm"
                    className="shrink-0"
                    onClick={() => copyToClipboard(createdKey)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              <Button
                data-testid="developer-portal-btn-ghost-2"
                variant="ghost"
                size="sm"
                onClick={() => setCreatedKey(null)}
              >
                <XCircle className="h-4 w-4" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium">Active Keys ({activeKeys.length})</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Manage API keys for programmatic access</p>
        </div>
        <Button data-testid="developer-portal-btn-3" size="sm" onClick={() => setShowCreateForm(!showCreateForm)}>
          <Plus className="h-3.5 w-3.5 mr-1" />
          Create Key
        </Button>
      </div>

      {showCreateForm && (
        <Card data-testid="developer-portal-card-2" className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Create New API Key</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-xs font-medium text-muted-foreground">Name</label>
              <Input
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="e.g. Production Ingestion Key"
                className="mt-1"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground">Scopes</label>
              <div className="grid grid-cols-2 gap-2 mt-1">
                {scopeOptions.map((scope) => (
                  <button
                    key={scope.id}
                    type="button"
                    className={`p-2.5 rounded-md border text-left transition-colors ${
                      newKeyScopes.includes(scope.id)
                        ? "border-primary/50 bg-primary/5"
                        : "border-border/40 hover:bg-muted/30"
                    }`}
                    onClick={() =>
                      setNewKeyScopes((prev) =>
                        prev.includes(scope.id) ? prev.filter((s) => s !== scope.id) : [...prev, scope.id],
                      )
                    }
                  >
                    <div className="flex items-center gap-2">
                      {newKeyScopes.includes(scope.id) ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-primary" />
                      ) : (
                        <div className="h-3.5 w-3.5 rounded-full border border-muted-foreground/30" />
                      )}
                      <span className="text-xs font-medium">{scope.label}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-1 ml-5.5">{scope.description}</p>
                  </button>
                ))}
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button
                data-testid="developer-portal-btn-outline-4"
                variant="outline"
                size="sm"
                onClick={() => setShowCreateForm(false)}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => createMutation.mutate()}
                disabled={createMutation.isPending || !newKeyName.trim()}
              >
                {createMutation.isPending ? "Creating..." : "Create Key"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : activeKeys.length === 0 ? (
        <Card data-testid="developer-portal-card-3" className="glass-card border-border/40">
          <CardContent className="py-12 text-center">
            <Key className="h-10 w-10 mx-auto mb-3 text-muted-foreground/40" />
            <p className="text-sm font-medium text-muted-foreground">No active API keys</p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Create your first API key to start integrating with the platform
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {activeKeys.map((key) => (
            <Card key={key.id} className="glass-card border-border/40">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="h-8 w-8 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                      <Key className="h-4 w-4 text-primary" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{key.name}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <code className="text-xs text-muted-foreground font-mono">{key.keyPrefix}••••••••</code>
                        {key.scopes?.map((scope) => (
                          <Badge key={scope} variant="outline" className="text-[10px]">
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <p className="text-[10px] text-muted-foreground">
                        {key.lastUsedAt ? (
                          <>
                            Last used{" "}
                            <span className="font-medium">{new Date(key.lastUsedAt).toLocaleDateString()}</span>
                          </>
                        ) : (
                          "Never used"
                        )}
                      </p>
                      <p className="text-[10px] text-muted-foreground">
                        Created {key.createdAt ? new Date(key.createdAt).toLocaleDateString() : "unknown"}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                      onClick={() => {
                        if (confirm("Revoke this API key? This action cannot be undone.")) {
                          revokeMutation.mutate(key.id);
                        }
                      }}
                      disabled={revokeMutation.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {revokedKeys.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground">Revoked Keys ({revokedKeys.length})</h3>
          {revokedKeys.map((key) => (
            <Card key={key.id} className="glass-card border-border/40 opacity-60">
              <CardContent className="p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Key className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-xs font-medium line-through">{key.name}</p>
                      <code className="text-[10px] text-muted-foreground font-mono">{key.keyPrefix}••••••••</code>
                    </div>
                  </div>
                  <Badge variant="destructive" className="text-[10px]">
                    Revoked {key.revokedAt ? new Date(key.revokedAt).toLocaleDateString() : ""}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function WebhooksTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [selectedWebhookId, setSelectedWebhookId] = useState<string | null>(null);

  const { data: webhooks, isLoading } = useQuery<OutboundWebhook[]>({
    queryKey: ["/api/outbound-webhooks"],
  });

  const { data: webhookLogs, isLoading: logsLoading } = useQuery<WebhookLog[]>({
    queryKey: ["/api/outbound-webhooks", selectedWebhookId, "logs"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/outbound-webhooks/${selectedWebhookId}/logs`);
      return await res.json();
    },
    enabled: !!selectedWebhookId,
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      if (!newWebhookUrl.trim()) throw new Error("URL is required");
      const res = await apiRequest("POST", "/api/outbound-webhooks", {
        url: newWebhookUrl.trim(),
        isActive: true,
      });
      return await res.json();
    },
    onSuccess: () => {
      setNewWebhookUrl("");
      setShowCreateForm(false);
      queryClient.invalidateQueries({ queryKey: ["/api/outbound-webhooks"] });
      toast({ title: "Webhook created successfully" });
    },
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/outbound-webhooks/${id}/test`);
      return await res.json();
    },
    onSuccess: (data: { success?: boolean }) => {
      toast({
        title: data.success ? "Test delivery succeeded" : "Test delivery failed",
        variant: data.success ? "default" : "destructive",
      });
    },
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, isActive }: { id: string; isActive: boolean }) => {
      const res = await apiRequest("PATCH", `/api/outbound-webhooks/${id}`, { isActive });
      return await res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/outbound-webhooks"] });
      toast({ title: "Webhook updated" });
    },
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/outbound-webhooks/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/outbound-webhooks"] });
      if (selectedWebhookId) setSelectedWebhookId(null);
      toast({ title: "Webhook deleted" });
    },
    onError: (err) => toast({ title: String(err), variant: "destructive" }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium">Webhooks ({webhooks?.length || 0})</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Receive real-time notifications when events occur</p>
        </div>
        <Button size="sm" onClick={() => setShowCreateForm(!showCreateForm)}>
          <Plus className="h-3.5 w-3.5 mr-1" />
          Add Webhook
        </Button>
      </div>

      {showCreateForm && (
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Add Webhook Endpoint</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground">Endpoint URL</label>
              <Input
                value={newWebhookUrl}
                onChange={(e) => setNewWebhookUrl(e.target.value)}
                placeholder="https://your-server.com/webhook"
                className="mt-1 font-mono text-sm"
              />
              <p className="text-[10px] text-muted-foreground mt-1">Must be a publicly accessible HTTPS endpoint</p>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={() => setShowCreateForm(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={() => createMutation.mutate()}
                disabled={createMutation.isPending || !newWebhookUrl.trim()}
              >
                {createMutation.isPending ? "Creating..." : "Create Webhook"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16" />
          ))}
        </div>
      ) : !webhooks?.length ? (
        <Card className="glass-card border-border/40">
          <CardContent className="py-12 text-center">
            <Webhook className="h-10 w-10 mx-auto mb-3 text-muted-foreground/40" />
            <p className="text-sm font-medium text-muted-foreground">No webhooks configured</p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              Add a webhook endpoint to receive real-time event notifications
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {webhooks.map((wh) => (
            <Card
              key={wh.id}
              className={`glass-card border-border/40 transition-colors ${
                selectedWebhookId === wh.id ? "border-primary/30" : ""
              }`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div
                    className="flex items-center gap-3 min-w-0 cursor-pointer flex-1"
                    onClick={() => setSelectedWebhookId(selectedWebhookId === wh.id ? null : wh.id)}
                  >
                    <div
                      className={`h-2 w-2 rounded-full shrink-0 ${wh.isActive ? "bg-emerald-400" : "bg-muted-foreground/30"}`}
                    />
                    <div className="min-w-0">
                      <code className="text-xs font-mono truncate block">{wh.url}</code>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant={wh.isActive ? "default" : "secondary"} className="text-[10px]">
                          {wh.isActive ? "Active" : "Inactive"}
                        </Badge>
                        {wh.lastUsedAt && (
                          <span className="text-[10px] text-muted-foreground">
                            Last delivered {new Date(wh.lastUsedAt).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => testMutation.mutate(wh.id)}
                      disabled={testMutation.isPending}
                      title="Send test event"
                    >
                      <Send className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => toggleMutation.mutate({ id: wh.id, isActive: !wh.isActive })}
                      title={wh.isActive ? "Disable" : "Enable"}
                    >
                      {wh.isActive ? <XCircle className="h-3.5 w-3.5" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                      onClick={() => {
                        if (confirm("Delete this webhook?")) {
                          deleteMutation.mutate(wh.id);
                        }
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                {selectedWebhookId === wh.id && (
                  <div className="mt-4 pt-3 border-t border-border/30">
                    <h4 className="text-xs font-medium mb-2">Recent Deliveries</h4>
                    {logsLoading ? (
                      <div className="space-y-1">
                        {Array.from({ length: 3 }).map((_, i) => (
                          <Skeleton key={i} className="h-8" />
                        ))}
                      </div>
                    ) : !webhookLogs?.length ? (
                      <p className="text-xs text-muted-foreground py-3 text-center">No deliveries yet</p>
                    ) : (
                      <div className="rounded-md border border-border/30 overflow-hidden">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-border/30 bg-muted/20">
                              <th className="text-left p-2 font-medium">Event</th>
                              <th className="text-center p-2 font-medium">Status</th>
                              <th className="text-left p-2 font-medium">Time</th>
                            </tr>
                          </thead>
                          <tbody>
                            {webhookLogs.slice(0, 10).map((log) => (
                              <tr key={log.id} className="border-b border-border/10 hover:bg-muted/10">
                                <td className="p-2">
                                  <Badge variant="outline" className="text-[10px] font-mono">
                                    {log.event}
                                  </Badge>
                                </td>
                                <td className="p-2 text-center">
                                  <Badge variant={log.success ? "default" : "destructive"} className="text-[10px]">
                                    {log.responseStatus || "err"}
                                  </Badge>
                                </td>
                                <td className="p-2 text-muted-foreground">
                                  {log.createdAt ? new Date(log.createdAt).toLocaleString() : "—"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function ApiDocsTab() {
  const { data: summaryRaw, isLoading } = useQuery({
    queryKey: ["/api/developer-portal/openapi/summary"],
  });

  const summary = (summaryRaw as { data?: ApiSummary })?.data || (summaryRaw as ApiSummary);

  const [expandedTag, setExpandedTag] = useState<string | null>(null);
  const [specVisible, setSpecVisible] = useState(false);
  const { toast } = useToast();

  const { data: fullSpecRaw, isLoading: specLoading } = useQuery({
    queryKey: ["/api/developer-portal/openapi"],
    enabled: specVisible,
  });

  const copySpec = useCallback(() => {
    if (fullSpecRaw) {
      navigator.clipboard.writeText(JSON.stringify(fullSpecRaw, null, 2));
      toast({ title: "OpenAPI spec copied to clipboard" });
    }
  }, [fullSpecRaw, toast]);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!summary || (!("totalEndpoints" in summary) && !("totalOperations" in summary))) {
    return (
      <Card className="glass-card border-border/40">
        <CardContent className="py-12 text-center">
          <AlertTriangle className="h-10 w-10 mx-auto mb-3 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">Failed to load API documentation</p>
          <p className="text-xs text-muted-foreground/70 mt-1">Please try again later</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Endpoints</p>
                <p className="text-2xl font-bold mt-1">{summary.totalEndpoints}</p>
              </div>
              <Code2 className="h-8 w-8 text-cyan-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Operations</p>
                <p className="text-2xl font-bold mt-1">{summary.totalOperations}</p>
              </div>
              <RotateCcw className="h-8 w-8 text-emerald-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/40">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">API Groups</p>
                <p className="text-2xl font-bold mt-1">{summary.tags?.length || 0}</p>
              </div>
              <Shield className="h-8 w-8 text-violet-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">API Groups</CardTitle>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setSpecVisible(!specVisible)}>
                <Eye className="h-3.5 w-3.5 mr-1" />
                {specVisible ? "Hide" : "View"} Raw Spec
              </Button>
              {fullSpecRaw != null && (
                <Button variant="outline" size="sm" onClick={copySpec}>
                  <Copy className="h-3.5 w-3.5 mr-1" />
                  Copy JSON
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {summary.tags?.length ? (
            <div className="space-y-1">
              {summary.tags
                .sort((a, b) => b.endpoints - a.endpoints)
                .map((tag) => (
                  <button
                    key={tag.name}
                    className="w-full flex items-center justify-between p-2.5 rounded-md hover:bg-muted/30 transition-colors text-left"
                    onClick={() => setExpandedTag(expandedTag === tag.name ? null : tag.name)}
                  >
                    <div className="flex items-center gap-3">
                      <ChevronRight
                        className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${
                          expandedTag === tag.name ? "rotate-90" : ""
                        }`}
                      />
                      <span className="text-sm font-medium">{tag.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {tag.methods.map((m) => (
                        <Badge
                          key={m}
                          variant="outline"
                          className={`text-[10px] px-1.5 ${
                            m === "GET"
                              ? "border-emerald-500/50 text-emerald-400"
                              : m === "POST"
                                ? "border-blue-500/50 text-blue-400"
                                : m === "PUT" || m === "PATCH"
                                  ? "border-amber-500/50 text-amber-400"
                                  : "border-red-500/50 text-red-400"
                          }`}
                        >
                          {m}
                        </Badge>
                      ))}
                      <Badge variant="secondary" className="text-xs">
                        {tag.endpoints}
                      </Badge>
                    </div>
                  </button>
                ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-6">No API groups available</p>
          )}
        </CardContent>
      </Card>

      {specVisible && (
        <Card className="glass-card border-border/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">OpenAPI Specification</CardTitle>
          </CardHeader>
          <CardContent>
            {specLoading ? (
              <Skeleton className="h-64" />
            ) : (
              <pre className="text-xs bg-muted/30 p-4 rounded-lg overflow-auto max-h-96 font-mono">
                {JSON.stringify(fullSpecRaw, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function SdkTab() {
  const sdks = [
    {
      name: "Python SDK",
      lang: "python",
      install: "pip install securenexus",
      snippet: `from securenexus import Client

client = Client(api_key="snx_your_key_here")

# Ingest an alert
client.alerts.ingest(
    source="custom",
    title="Suspicious Login",
    severity="high",
    description="Multiple failed logins detected"
)

# List recent alerts
alerts = client.alerts.list(limit=10)
for alert in alerts:
    print(f"{alert.title} - {alert.severity}")`,
      docs: "https://docs.securenexus.io/sdk/python",
      icon: "🐍",
    },
    {
      name: "Node.js SDK",
      lang: "javascript",
      install: "npm install @securenexus/sdk",
      snippet: `import { SecureNexus } from '@securenexus/sdk';

const client = new SecureNexus({
  apiKey: 'snx_your_key_here'
});

// Ingest an alert
await client.alerts.ingest({
  source: 'custom',
  title: 'Suspicious Login',
  severity: 'high',
  description: 'Multiple failed logins detected'
});

// List recent alerts
const { data: alerts } = await client.alerts.list({ limit: 10 });
alerts.forEach(a => console.log(\`\${a.title} - \${a.severity}\`));`,
      docs: "https://docs.securenexus.io/sdk/nodejs",
      icon: "📦",
    },
    {
      name: "cURL",
      lang: "bash",
      install: "",
      snippet: `# Ingest an alert via API
curl -X POST https://api.securenexus.io/api/ingest/custom \\
  -H "X-Api-Key: snx_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "title": "Suspicious Login",
    "severity": "high",
    "description": "Multiple failed logins detected"
  }'

# List API keys
curl https://api.securenexus.io/api/api-keys \\
  -H "Cookie: connect.sid=your_session_cookie"`,
      docs: "https://docs.securenexus.io/api/reference",
      icon: "🔧",
    },
  ];

  const quickstartSteps = [
    {
      step: 1,
      title: "Create an API Key",
      description: "Go to the API Keys tab and create a key with the scopes you need. Copy and store it securely.",
    },
    {
      step: 2,
      title: "Install the SDK",
      description: "Install the SecureNexus SDK for your language, or use the REST API directly with cURL.",
    },
    {
      step: 3,
      title: "Send Your First Alert",
      description:
        "Use the ingest endpoint to send your first alert. The platform will normalize, correlate, and enrich it automatically.",
    },
    {
      step: 4,
      title: "Set Up Webhooks",
      description:
        "Configure webhook endpoints to receive real-time notifications when alerts or incidents are created.",
    },
  ];

  const { toast } = useToast();
  const [expandedSdk, setExpandedSdk] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <BookOpen className="h-4 w-4" />
            Quickstart Guide
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {quickstartSteps.map((step) => (
              <div
                key={step.step}
                className="p-3 rounded-lg border border-border/30 bg-muted/10 hover:bg-muted/20 transition-colors"
              >
                <div className="flex items-center gap-2 mb-2">
                  <div className="h-6 w-6 rounded-full bg-primary/10 flex items-center justify-center text-xs font-bold text-primary">
                    {step.step}
                  </div>
                  <h4 className="text-xs font-medium">{step.title}</h4>
                </div>
                <p className="text-[10px] text-muted-foreground leading-relaxed">{step.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="space-y-3">
        <h3 className="text-sm font-medium flex items-center gap-2">
          <DownloadDoneIcon size={18} color="currentColor" />
          SDKs & Integration Libraries
        </h3>

        {sdks.map((sdk) => (
          <Card key={sdk.name} className="glass-card border-border/40">
            <CardContent className="p-0">
              <button
                className="w-full flex items-center justify-between p-4 text-left hover:bg-muted/10 transition-colors"
                onClick={() => setExpandedSdk(expandedSdk === sdk.name ? null : sdk.name)}
              >
                <div className="flex items-center gap-3">
                  <span className="text-lg">{sdk.icon}</span>
                  <div>
                    <p className="text-sm font-medium">{sdk.name}</p>
                    {sdk.install && <code className="text-[10px] text-muted-foreground font-mono">{sdk.install}</code>}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs"
                    onClick={(e) => {
                      e.stopPropagation();
                      window.open(sdk.docs, "_blank");
                    }}
                  >
                    <ExternalLink className="h-3 w-3 mr-1" />
                    Docs
                  </Button>
                  <ChevronRight
                    className={`h-4 w-4 text-muted-foreground transition-transform ${
                      expandedSdk === sdk.name ? "rotate-90" : ""
                    }`}
                  />
                </div>
              </button>

              {expandedSdk === sdk.name && (
                <div className="border-t border-border/30 p-4">
                  {sdk.install && (
                    <div className="mb-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                          Install
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-5 text-[10px]"
                          onClick={() => {
                            navigator.clipboard.writeText(sdk.install);
                            toast({ title: "Install command copied" });
                          }}
                        >
                          <Copy className="h-2.5 w-2.5 mr-1" />
                          Copy
                        </Button>
                      </div>
                      <div className="bg-muted/30 rounded-md p-2.5 flex items-center gap-2">
                        <Terminal className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <code className="text-xs font-mono">{sdk.install}</code>
                      </div>
                    </div>
                  )}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                        Example
                      </span>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-5 text-[10px]"
                        onClick={() => {
                          navigator.clipboard.writeText(sdk.snippet);
                          toast({ title: "Code snippet copied" });
                        }}
                      >
                        <Copy className="h-2.5 w-2.5 mr-1" />
                        Copy
                      </Button>
                    </div>
                    <pre className="text-xs bg-muted/30 p-3 rounded-md overflow-auto max-h-64 font-mono leading-relaxed">
                      {sdk.snippet}
                    </pre>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">API Base URL</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            <code className="text-xs font-mono bg-muted/30 px-3 py-2 rounded-md flex-1">
              {window.location.origin}/api
            </code>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                navigator.clipboard.writeText(`${window.location.origin}/api`);
                toast({ title: "API base URL copied" });
              }}
            >
              <Copy className="h-3.5 w-3.5" />
            </Button>
          </div>
          <p className="text-[10px] text-muted-foreground mt-2">
            All API endpoints are relative to this base URL. Use your API key in the X-Api-Key header for
            authentication.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

const TABS: { id: PortalTab; label: string; icon: React.ElementType }[] = [
  { id: "api-keys", label: "API Keys", icon: Key },
  { id: "webhooks", label: "Webhooks", icon: Webhook },
  { id: "api-docs", label: "API Docs", icon: Code2 },
  { id: "sdk", label: "SDK & Quickstart", icon: Package },
];

/* 89.5 — API rate limiting display */
const RATE_LIMIT_TIERS: Record<string, { rpm: number; daily: number }> = {
  free: { rpm: 60, daily: 1000 },
  pro: { rpm: 300, daily: 10000 },
  business: { rpm: 1000, daily: 50000 },
  enterprise: { rpm: 5000, daily: 250000 },
};

/* 89.6 — API versioning */
const API_VERSIONS = [
  { version: "v1", status: "stable", deprecation: null },
  { version: "v2", status: "beta", deprecation: null },
];

export default function DeveloperPortalPage() {
  const [activeTab, setActiveTab] = useState<PortalTab>("api-keys");

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Developer Portal</h1>
        <p className="text-sm text-muted-foreground mt-1">API keys, webhooks, documentation, and integration guides</p>
        {/* 89.1 — consolidated portal note */}
        <p className="text-[10px] text-muted-foreground mt-0.5">
          Unified developer portal — all API management, documentation, and SDKs in one place
        </p>
      </div>

      {/* 89.6 — API versioning banner */}
      <div className="flex items-center gap-3 text-xs">
        <span className="text-muted-foreground flex items-center gap-1">
          <GitBranch className="h-3 w-3" /> API Versions:
        </span>
        {API_VERSIONS.map((v) => (
          <Badge
            key={v.version}
            variant="outline"
            className={`text-[10px] ${
              v.status === "stable"
                ? "border-green-500/30 text-green-400"
                : v.status === "beta"
                  ? "border-yellow-500/30 text-yellow-400"
                  : "border-red-500/30 text-red-400"
            }`}
          >
            {v.version} ({v.status})
          </Badge>
        ))}
      </div>

      <div className="flex gap-1 p-1 rounded-lg bg-muted/30 border border-border/40 overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all whitespace-nowrap ${
                activeTab === tab.id
                  ? "bg-background shadow-sm text-foreground"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "api-keys" && <ApiKeysTab />}
      {activeTab === "webhooks" && <WebhooksTab />}
      {activeTab === "api-docs" && <ApiDocsTab />}
      {activeTab === "sdk" && <SdkTab />}

      {/* 89.5 — API rate limiting info */}
      <Card className="glass-card border-border/40">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Gauge className="h-4 w-4 text-muted-foreground" />
            API Rate Limits by Plan
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(RATE_LIMIT_TIERS).map(([tier, limits]) => (
              <div key={tier} className="border rounded-md p-3 space-y-1">
                <p className="text-xs font-medium capitalize">{tier}</p>
                <p className="text-[10px] text-muted-foreground">{limits.rpm.toLocaleString()} req/min</p>
                <p className="text-[10px] text-muted-foreground">{limits.daily.toLocaleString()} req/day</p>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground mt-2">
            Rate limits are enforced per API key. Upgrade your plan for higher limits.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
