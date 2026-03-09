import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  Webhook,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Send,
  RefreshCw,
  Loader2,
  Search,
  Lock,
  Unlock,
  Activity,
  BarChart3,
  Eye,
  Play,
  Globe,
  Hash,
  FileText,
  ShieldAlert,
  Zap,
  ArrowRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface OutboundWebhook {
  id: number;
  orgId: string;
  name: string;
  url: string;
  secret: string | null;
  events: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

interface WebhookLog {
  id: number;
  webhookId: number;
  event: string;
  payload: Record<string, unknown>;
  responseStatus: number;
  responseBody: string;
  success: boolean;
  createdAt: string;
}

interface TestResult {
  success: boolean;
  statusCode: number;
  responseBody: string;
}

function LoadingSkeleton() {
  return (
    <div className="p-6 space-y-6" role="status" aria-label="Loading webhook security center">
      <Skeleton className="h-8 w-72" />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-96" />
      <span className="sr-only">Loading webhook security center...</span>
    </div>
  );
}

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="p-6">
      <Card className="glass-card border-red-500/30">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-400 mb-4" />
          <p className="text-lg font-semibold mb-2">Failed to Load Webhook Security Center</p>
          <p className="text-sm text-muted-foreground mb-4">Could not retrieve webhook data from the server.</p>
          <Button onClick={onRetry} variant="outline" size="sm">
            Retry
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function SecurityBadge({ webhook }: { webhook: OutboundWebhook }) {
  const hasSecret = !!webhook.secret;
  const isHttps = webhook.url.startsWith("https://");

  return (
    <div className="flex items-center gap-1.5">
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div
              className={`h-5 w-5 rounded-full flex items-center justify-center ${hasSecret ? "bg-emerald-500/15" : "bg-amber-500/15"}`}
            >
              {hasSecret ? (
                <Lock className="h-3 w-3 text-emerald-400" />
              ) : (
                <Unlock className="h-3 w-3 text-amber-400" />
              )}
            </div>
          </TooltipTrigger>
          <TooltipContent side="top" className="text-xs">
            {hasSecret ? "HMAC signing enabled" : "No HMAC secret configured"}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div
              className={`h-5 w-5 rounded-full flex items-center justify-center ${isHttps ? "bg-emerald-500/15" : "bg-red-500/15"}`}
            >
              {isHttps ? (
                <Shield className="h-3 w-3 text-emerald-400" />
              ) : (
                <ShieldAlert className="h-3 w-3 text-red-400" />
              )}
            </div>
          </TooltipTrigger>
          <TooltipContent side="top" className="text-xs">
            {isHttps ? "TLS encrypted (HTTPS)" : "Unencrypted (HTTP) — insecure"}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
  );
}

function WebhookDetailPanel({
  webhook,
  logs,
  isLoadingLogs,
  onTest,
  isTesting,
}: {
  webhook: OutboundWebhook;
  logs: WebhookLog[];
  isLoadingLogs: boolean;
  onTest: () => void;
  isTesting: boolean;
}) {
  const successCount = logs.filter((l) => l.success).length;
  const failureCount = logs.filter((l) => !l.success).length;
  const successRate = logs.length > 0 ? Math.round((successCount / logs.length) * 100) : 0;
  const lastDelivery = logs.length > 0 ? logs[0] : null;

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold">{webhook.name}</h3>
            <SecurityBadge webhook={webhook} />
          </div>
          <p className="text-xs text-muted-foreground font-mono mt-1 break-all">{webhook.url}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge variant={webhook.enabled ? "default" : "secondary"} className="text-xs">
            {webhook.enabled ? "Active" : "Disabled"}
          </Badge>
          <Button variant="outline" size="sm" onClick={onTest} disabled={isTesting} className="gap-1.5">
            {isTesting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            Test
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground">Deliveries</p>
          <p className="text-lg font-bold tabular-nums">{logs.length}</p>
        </div>
        <div className="p-3 rounded-lg border border-emerald-500/20 bg-card/50">
          <p className="text-xs text-muted-foreground">Successes</p>
          <p className="text-lg font-bold tabular-nums text-emerald-400">{successCount}</p>
        </div>
        <div className="p-3 rounded-lg border border-red-500/20 bg-card/50">
          <p className="text-xs text-muted-foreground">Failures</p>
          <p className="text-lg font-bold tabular-nums text-red-400">{failureCount}</p>
        </div>
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground">Success Rate</p>
          <p
            className={`text-lg font-bold tabular-nums ${successRate >= 90 ? "text-emerald-400" : successRate >= 70 ? "text-amber-400" : "text-red-400"}`}
          >
            {successRate}%
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground mb-2">Security Status</p>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5" />
                HMAC Signing
              </span>
              {webhook.secret ? (
                <Badge variant="outline" className="text-xs bg-emerald-500/15 text-emerald-400 border-emerald-500/30">
                  Enabled
                </Badge>
              ) : (
                <Badge variant="outline" className="text-xs bg-amber-500/15 text-amber-400 border-amber-500/30">
                  Not Set
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5" />
                TLS Encryption
              </span>
              {webhook.url.startsWith("https://") ? (
                <Badge variant="outline" className="text-xs bg-emerald-500/15 text-emerald-400 border-emerald-500/30">
                  HTTPS
                </Badge>
              ) : (
                <Badge variant="outline" className="text-xs bg-red-500/15 text-red-400 border-red-500/30">
                  HTTP Only
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5" />
                SSRF Protection
              </span>
              <Badge variant="outline" className="text-xs bg-emerald-500/15 text-emerald-400 border-emerald-500/30">
                Active
              </Badge>
            </div>
          </div>
        </div>
        <div className="p-3 rounded-lg border border-border/50 bg-card/50">
          <p className="text-xs text-muted-foreground mb-2">Configuration</p>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Events</span>
              <span className="font-medium">{webhook.events.length > 0 ? webhook.events.length : "All"}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Created</span>
              <span className="text-xs">{new Date(webhook.createdAt).toLocaleDateString()}</span>
            </div>
            {lastDelivery && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Last Delivery</span>
                <span className="text-xs">{new Date(lastDelivery.createdAt).toLocaleString()}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {webhook.events.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {webhook.events.map((evt) => (
            <Badge key={evt} variant="secondary" className="text-xs">
              {evt}
            </Badge>
          ))}
        </div>
      )}

      <Separator />

      <div>
        <h4 className="text-sm font-medium mb-3">Delivery Log</h4>
        {isLoadingLogs ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
            <Send className="h-8 w-8 mb-2 opacity-40" />
            <p className="text-sm">No delivery logs yet</p>
            <p className="text-xs mt-1">Logs will appear after webhook deliveries are attempted</p>
          </div>
        ) : (
          <ScrollArea className="h-64">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">Status</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>HTTP Status</TableHead>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Response</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs
                  .slice()
                  .reverse()
                  .map((log) => (
                    <TableRow key={log.id}>
                      <TableCell>
                        {log.success ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                      </TableCell>
                      <TableCell className="text-xs font-medium">{log.event}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`text-xs tabular-nums ${
                            log.responseStatus >= 200 && log.responseStatus < 300
                              ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                              : log.responseStatus >= 400
                                ? "bg-red-500/15 text-red-400 border-red-500/30"
                                : "bg-amber-500/15 text-amber-400 border-amber-500/30"
                          }`}
                        >
                          {log.responseStatus || "N/A"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs tabular-nums text-muted-foreground">
                        {new Date(log.createdAt).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground truncate max-w-[150px]">
                        {log.responseBody ? log.responseBody.slice(0, 80) : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </ScrollArea>
        )}
      </div>
    </div>
  );
}

export default function WebhookSecurityCenterPage() {
  usePageTitle("Webhook Security Center");
  const { toast } = useToast();
  const [selectedWebhookId, setSelectedWebhookId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const {
    data: webhooks,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<OutboundWebhook[]>({
    queryKey: ["/api/v1/webhooks"],
    queryFn: async () => {
      const headers: Record<string, string> = {};
      try {
        const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
        if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
      } catch {
        /* privacy mode */
      }
      const res = await fetch("/api/v1/webhooks", { credentials: "include", headers });
      if (!res.ok) throw new Error("Failed to fetch webhooks");
      const envelope = await res.json();
      return envelope.data ?? [];
    },
  });

  const selectedWebhook = (webhooks ?? []).find((w) => w.id === selectedWebhookId) ?? null;

  const { data: webhookLogs, isLoading: isLoadingLogs } = useQuery<WebhookLog[]>({
    queryKey: ["/api/v1/webhooks", selectedWebhookId, "logs"],
    queryFn: async () => {
      const headers: Record<string, string> = {};
      try {
        const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
        if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
      } catch {
        /* privacy mode */
      }
      const res = await fetch(`/api/v1/webhooks/${selectedWebhookId}/logs?limit=50`, {
        credentials: "include",
        headers,
      });
      if (!res.ok) return [];
      const envelope = await res.json();
      return envelope.data ?? [];
    },
    enabled: !!selectedWebhookId,
  });

  const testMutation = useMutation({
    mutationFn: async (webhookId: number) => {
      const res = await apiRequest("POST", `/api/outbound-webhooks/${webhookId}/test`);
      return res.json() as Promise<TestResult>;
    },
    onSuccess: (data) => {
      toast({
        title: data.success ? "Test delivery succeeded" : "Test delivery failed",
        description: `HTTP ${data.statusCode}`,
        variant: data.success ? "default" : "destructive",
      });
      if (selectedWebhookId) {
        queryClient.invalidateQueries({ queryKey: ["/api/v1/webhooks", selectedWebhookId, "logs"] });
      }
    },
    onError: () => {
      toast({
        title: "Test delivery failed",
        description: "Could not reach the webhook endpoint",
        variant: "destructive",
      });
    },
  });

  if (isLoading) return <LoadingSkeleton />;
  if (isError) return <ErrorState onRetry={refetch} />;

  const allWebhooks = webhooks ?? [];
  const filteredWebhooks = allWebhooks.filter(
    (w) =>
      !searchQuery ||
      w.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      w.url.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const activeCount = allWebhooks.filter((w) => w.enabled).length;
  const signedCount = allWebhooks.filter((w) => !!w.secret).length;
  const httpsCount = allWebhooks.filter((w) => w.url.startsWith("https://")).length;
  const unsecuredCount = allWebhooks.filter((w) => !w.secret || !w.url.startsWith("https://")).length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Webhook Security Center</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Replay defense, signing status, delivery retries, and forensic logs
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} className="gap-1.5">
          {isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Total Webhooks</p>
                <p className="text-2xl font-bold tabular-nums">{allWebhooks.length}</p>
                <p className="text-xs text-muted-foreground">{activeCount} active</p>
              </div>
              <Webhook className="h-5 w-5 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-emerald-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">HMAC Signed</p>
                <p className="text-2xl font-bold tabular-nums text-emerald-400">{signedCount}</p>
                <p className="text-xs text-muted-foreground">of {allWebhooks.length} total</p>
              </div>
              <Lock className="h-5 w-5 text-emerald-400/60" />
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-emerald-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">HTTPS</p>
                <p className="text-2xl font-bold tabular-nums text-emerald-400">{httpsCount}</p>
                <p className="text-xs text-muted-foreground">of {allWebhooks.length} total</p>
              </div>
              <Shield className="h-5 w-5 text-emerald-400/60" />
            </div>
          </CardContent>
        </Card>
        <Card className={`glass-card ${unsecuredCount > 0 ? "border-amber-500/30" : "border-emerald-500/20"}`}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Security Gaps</p>
                <p
                  className={`text-2xl font-bold tabular-nums ${unsecuredCount > 0 ? "text-amber-400" : "text-emerald-400"}`}
                >
                  {unsecuredCount}
                </p>
                <p className="text-xs text-muted-foreground">{unsecuredCount > 0 ? "need attention" : "all secured"}</p>
              </div>
              <ShieldAlert className={`h-5 w-5 ${unsecuredCount > 0 ? "text-amber-400/60" : "text-emerald-400/60"}`} />
            </div>
          </CardContent>
        </Card>
      </div>

      {unsecuredCount > 0 && (
        <Card className="glass-card border-amber-500/30">
          <CardContent className="p-3">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium text-amber-400">Security Recommendations</p>
                <ul className="text-xs text-muted-foreground mt-1 space-y-1">
                  {allWebhooks.filter((w) => !w.secret).length > 0 && (
                    <li className="flex items-center gap-1.5">
                      <ArrowRight className="h-3 w-3 shrink-0" />
                      {allWebhooks.filter((w) => !w.secret).length} webhook(s) missing HMAC signing — configure secrets
                      for replay defense
                    </li>
                  )}
                  {allWebhooks.filter((w) => !w.url.startsWith("https://")).length > 0 && (
                    <li className="flex items-center gap-1.5">
                      <ArrowRight className="h-3 w-3 shrink-0" />
                      {allWebhooks.filter((w) => !w.url.startsWith("https://")).length} webhook(s) using HTTP — upgrade
                      to HTTPS for transport encryption
                    </li>
                  )}
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card className="glass-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Webhooks ({filteredWebhooks.length})</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="p-2 pb-0">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by name or URL..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9 h-8 text-xs"
                  />
                </div>
              </div>
              {filteredWebhooks.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Webhook className="h-8 w-8 mb-2 opacity-40" />
                  <p className="text-sm">
                    {allWebhooks.length === 0 ? "No webhooks configured" : "No webhooks match your search"}
                  </p>
                </div>
              ) : (
                <ScrollArea className="h-[520px]">
                  <div className="space-y-1 p-2">
                    {filteredWebhooks.map((w) => (
                      <button
                        key={w.id}
                        onClick={() => setSelectedWebhookId(w.id)}
                        className={`w-full text-left p-3 rounded-lg transition-colors ${
                          selectedWebhookId === w.id
                            ? "bg-cyan-500/10 border border-cyan-500/30"
                            : "hover:bg-card/80 border border-transparent"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium truncate">{w.name}</span>
                          <div className="flex items-center gap-1.5 shrink-0 ml-2">
                            <SecurityBadge webhook={w} />
                            <div className={`h-2 w-2 rounded-full ${w.enabled ? "bg-emerald-500" : "bg-gray-500"}`} />
                          </div>
                        </div>
                        <p className="text-[10px] text-muted-foreground font-mono truncate">{w.url}</p>
                        <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground/70">
                          <span className="flex items-center gap-1">
                            <Hash className="h-3 w-3" />
                            {w.events.length > 0 ? `${w.events.length} events` : "All events"}
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(w.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                      </button>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-2">
          <Card className="glass-card">
            <CardContent className="p-4">
              {selectedWebhook ? (
                <WebhookDetailPanel
                  webhook={selectedWebhook}
                  logs={webhookLogs ?? []}
                  isLoadingLogs={isLoadingLogs}
                  onTest={() => testMutation.mutate(selectedWebhook.id)}
                  isTesting={testMutation.isPending}
                />
              ) : (
                <div className="flex flex-col items-center justify-center py-24 text-muted-foreground">
                  <Eye className="h-12 w-12 mb-3 opacity-30" />
                  <p className="text-sm font-medium">Select a webhook to inspect</p>
                  <p className="text-xs mt-1">View security status, delivery logs, and run test deliveries</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
