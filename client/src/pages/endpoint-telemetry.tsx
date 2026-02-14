import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Monitor, Cpu, HardDrive, Shield, Activity, Wifi, AlertTriangle,
  RefreshCw, Database, Plus, Eye, ChevronRight
} from "lucide-react";
import type { EndpointAsset, EndpointTelemetry } from "@shared/schema";

function formatTimestamp(date: string | Date | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function statusDot(status: string | null | undefined) {
  const s = status ?? "offline";
  if (s === "online") return "bg-green-500";
  if (s === "degraded") return "bg-yellow-500";
  return "bg-red-500";
}

function riskBadgeColor(score: number) {
  if (score > 60) return "bg-red-500/10 text-red-500 border-red-500/20";
  if (score > 30) return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
  return "bg-green-500/10 text-green-500 border-green-500/20";
}

function riskBarColor(score: number) {
  if (score > 60) return "bg-red-500";
  if (score > 30) return "bg-yellow-500";
  return "bg-green-500";
}

function StatCard({ title, value, icon: Icon, loading }: {
  title: string;
  value: string | number;
  icon: typeof Monitor;
  loading?: boolean;
}) {
  const testId = `stat-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className="p-1.5 rounded-md bg-muted/50">
          <Icon className="h-3.5 w-3.5 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold tabular-nums" data-testid={`value-${testId}`}>{value}</div>
        )}
      </CardContent>
    </Card>
  );
}

function parseTelemetryMetric(telemetry: EndpointTelemetry[], metricType: string) {
  const entry = telemetry.find(t => t.metricType === metricType);
  if (!entry) return null;
  try {
    if (typeof entry.metricValue === "string") return JSON.parse(entry.metricValue);
    return entry.metricValue;
  } catch {
    return null;
  }
}

function AssetDetailView({ assetId, assets }: { assetId: string; assets: EndpointAsset[] }) {
  const asset = assets.find(a => a.id === assetId);

  const { data: telemetry, isLoading: telemetryLoading } = useQuery<EndpointTelemetry[]>({
    queryKey: ["/api/endpoints", assetId, "telemetry"],
    enabled: !!assetId,
  });

  if (!asset) {
    return (
      <Card data-testid="empty-asset-detail">
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <Monitor className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium text-muted-foreground">Asset not found</p>
        </CardContent>
      </Card>
    );
  }

  const riskScore = asset.riskScore ?? 0;
  const cpu = parseTelemetryMetric(telemetry || [], "cpu");
  const memory = parseTelemetryMetric(telemetry || [], "memory");
  const disk = parseTelemetryMetric(telemetry || [], "disk");
  const processes = parseTelemetryMetric(telemetry || [], "processes");
  const av = parseTelemetryMetric(telemetry || [], "antivirus");
  const patches = parseTelemetryMetric(telemetry || [], "patches");
  const network = parseTelemetryMetric(telemetry || [], "network");
  const suspiciousProcs = parseTelemetryMetric(telemetry || [], "suspicious_processes");

  return (
    <div className="space-y-4" data-testid="section-asset-detail">
      <Card data-testid={`card-asset-info-${assetId}`}>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2 flex-wrap">
            <Monitor className="h-4 w-4" />
            {asset.hostname}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
            <div>
              <span className="text-xs text-muted-foreground">OS</span>
              <p className="font-medium" data-testid="text-asset-os">{asset.os} {asset.osVersion || ""}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Agent Version</span>
              <p className="font-medium" data-testid="text-asset-agent">{asset.agentVersion || "N/A"}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">IP Address</span>
              <p className="font-mono text-sm" data-testid="text-asset-ip">{asset.ipAddress || "N/A"}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">MAC Address</span>
              <p className="font-mono text-sm" data-testid="text-asset-mac">{asset.macAddress || "N/A"}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Status</span>
              <div className="flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${statusDot(asset.agentStatus)}`} />
                <span className="font-medium capitalize">{asset.agentStatus || "offline"}</span>
              </div>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Last Seen</span>
              <p className="text-sm">{formatTimestamp(asset.lastSeenAt)}</p>
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="text-xs text-muted-foreground">Risk Score</span>
              <span className={`text-lg font-bold tabular-nums ${riskScore > 60 ? "text-red-500" : riskScore > 30 ? "text-yellow-500" : "text-green-500"}`} data-testid="value-asset-risk">
                {riskScore}
              </span>
            </div>
            <div className="w-full bg-muted/50 rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all ${riskBarColor(riskScore)}`}
                style={{ width: `${Math.min(riskScore, 100)}%` }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {telemetryLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4"><Skeleton className="h-24 w-full" /></CardContent>
            </Card>
          ))}
        </div>
      ) : !telemetry || telemetry.length === 0 ? (
        <Card data-testid="empty-telemetry">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Activity className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No telemetry data available</p>
            <p className="text-xs text-muted-foreground mt-1">Generate telemetry from the Endpoint Inventory tab</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3" data-testid="telemetry-grid">
          {cpu && (
            <Card data-testid="card-telemetry-cpu">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">CPU Usage</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><Cpu className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="text-2xl font-bold tabular-nums">{cpu.usage ?? cpu.percent ?? 0}%</div>
                <Progress value={cpu.usage ?? cpu.percent ?? 0} className="h-2" />
                {cpu.cores && <p className="text-xs text-muted-foreground">{cpu.cores} cores</p>}
              </CardContent>
            </Card>
          )}

          {memory && (
            <Card data-testid="card-telemetry-memory">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Memory Usage</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><Activity className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="text-2xl font-bold tabular-nums">{memory.usage ?? memory.percent ?? 0}%</div>
                <Progress value={memory.usage ?? memory.percent ?? 0} className="h-2" />
                {memory.totalGb && <p className="text-xs text-muted-foreground">{memory.totalGb} GB total</p>}
              </CardContent>
            </Card>
          )}

          {disk && (
            <Card data-testid="card-telemetry-disk">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Disk Usage</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><HardDrive className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="text-2xl font-bold tabular-nums">{disk.usage ?? disk.percent ?? 0}%</div>
                <Progress value={disk.usage ?? disk.percent ?? 0} className="h-2" />
                {disk.totalGb && <p className="text-xs text-muted-foreground">{disk.totalGb} GB total</p>}
              </CardContent>
            </Card>
          )}

          {processes && (
            <Card data-testid="card-telemetry-processes">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Process Count</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><Monitor className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold tabular-nums">{processes.total ?? 0}</div>
                {(processes.suspicious != null && processes.suspicious > 0) && (
                  <p className="text-xs text-red-500 font-medium mt-1">{processes.suspicious} suspicious</p>
                )}
              </CardContent>
            </Card>
          )}

          {av && (
            <Card data-testid="card-telemetry-antivirus">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">AV Status</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><Shield className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent className="space-y-1">
                {av.engine && <p className="text-sm font-medium">{av.engine}</p>}
                {av.lastScan && <p className="text-xs text-muted-foreground">Last scan: {formatTimestamp(av.lastScan)}</p>}
                {av.definitionsStatus && (
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${av.definitionsStatus === "current" ? "bg-green-500/10 text-green-500 border-green-500/20" : "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"}`}>
                    Definitions: {av.definitionsStatus}
                  </span>
                )}
              </CardContent>
            </Card>
          )}

          {patches && (
            <Card data-testid="card-telemetry-patches">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Patch Level</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><Database className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent className="space-y-1">
                <div className="flex items-center gap-4 text-sm">
                  <span>Installed: <span className="font-medium">{patches.installed ?? 0}</span></span>
                  <span>Pending: <span className="font-medium">{patches.pending ?? 0}</span></span>
                </div>
                {(patches.criticalPending != null && patches.criticalPending > 0) && (
                  <p className="text-xs text-red-500 font-medium">{patches.criticalPending} critical pending</p>
                )}
              </CardContent>
            </Card>
          )}

          {network && (
            <Card data-testid="card-telemetry-network">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Network Connections</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><Wifi className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4 text-sm">
                  <span>Active: <span className="font-bold">{network.active ?? 0}</span></span>
                  {(network.suspicious != null && network.suspicious > 0) && (
                    <span className="text-red-500 font-medium">{network.suspicious} suspicious</span>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {suspiciousProcs && (
            <Card data-testid="card-telemetry-suspicious">
              <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Suspicious Processes</CardTitle>
                <div className="p-1.5 rounded-md bg-muted/50"><AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" /></div>
              </CardHeader>
              <CardContent>
                {Array.isArray(suspiciousProcs) && suspiciousProcs.length > 0 ? (
                  <ul className="space-y-1">
                    {suspiciousProcs.map((proc: any, i: number) => (
                      <li key={i} className="text-xs flex items-start gap-1.5" data-testid={`text-suspicious-proc-${i}`}>
                        <ChevronRight className="h-3 w-3 mt-0.5 flex-shrink-0 text-red-500" />
                        <span>
                          <span className="font-medium text-red-500">{proc.name || "unknown"}</span>
                          {proc.pid && <span className="text-muted-foreground"> (PID: {proc.pid})</span>}
                          {proc.user && <span className="text-muted-foreground"> - {proc.user}</span>}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    {Array.isArray(suspiciousProcs) ? "No suspicious processes" : (suspiciousProcs.list && Array.isArray(suspiciousProcs.list) ? (
                      suspiciousProcs.list.length === 0 ? "No suspicious processes" : ""
                    ) : "No data")}
                  </p>
                )}
                {suspiciousProcs && !Array.isArray(suspiciousProcs) && suspiciousProcs.list && Array.isArray(suspiciousProcs.list) && suspiciousProcs.list.length > 0 && (
                  <ul className="space-y-1">
                    {suspiciousProcs.list.map((proc: any, i: number) => (
                      <li key={i} className="text-xs flex items-start gap-1.5" data-testid={`text-suspicious-proc-${i}`}>
                        <ChevronRight className="h-3 w-3 mt-0.5 flex-shrink-0 text-red-500" />
                        <span>
                          <span className="font-medium text-red-500">{proc.name || "unknown"}</span>
                          {proc.pid && <span className="text-muted-foreground"> (PID: {proc.pid})</span>}
                          {proc.user && <span className="text-muted-foreground"> - {proc.user}</span>}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

export default function EndpointTelemetryPage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("inventory");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const { data: endpoints, isLoading } = useQuery<EndpointAsset[]>({
    queryKey: ["/api/endpoints"],
  });

  const seedMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/endpoints/seed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] });
      toast({ title: "Endpoints seeded", description: "Demo endpoint data has been created." });
    },
    onError: (err: Error) => {
      toast({ title: "Seeding failed", description: err.message, variant: "destructive" });
    },
  });

  const genTelemetryMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/endpoints/${id}/telemetry`);
    },
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints", id, "telemetry"] });
      toast({ title: "Telemetry generated", description: "Endpoint telemetry data has been collected." });
    },
    onError: (err: Error) => {
      toast({ title: "Telemetry generation failed", description: err.message, variant: "destructive" });
    },
  });

  const calcRiskMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/endpoints/${id}/risk`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] });
      toast({ title: "Risk calculated", description: "Endpoint risk score has been updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Risk calculation failed", description: err.message, variant: "destructive" });
    },
  });

  const totalEndpoints = endpoints?.length ?? 0;
  const onlineCount = endpoints?.filter(e => e.agentStatus === "online").length ?? 0;
  const offlineDegradedCount = endpoints?.filter(e => e.agentStatus === "offline" || e.agentStatus === "degraded").length ?? 0;
  const highRiskCount = endpoints?.filter(e => (e.riskScore ?? 0) > 60).length ?? 0;

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-endpoint-telemetry-loading">
        <div>
          <Skeleton className="h-8 w-72 mb-2" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2"><Skeleton className="h-4 w-24" /></CardHeader>
              <CardContent><Skeleton className="h-7 w-16" /></CardContent>
            </Card>
          ))}
        </div>
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4"><Skeleton className="h-16 w-full" /></CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-endpoint-telemetry">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Endpoint Telemetry</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Monitor endpoint health, telemetry metrics, and risk posture
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            onClick={() => seedMutation.mutate()}
            disabled={seedMutation.isPending}
            data-testid="button-seed-endpoints"
          >
            <Plus className={`h-4 w-4 mr-2 ${seedMutation.isPending ? "animate-spin" : ""}`} />
            {seedMutation.isPending ? "Seeding..." : "Seed Endpoints"}
          </Button>
          <Button
            variant="outline"
            onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] })}
            data-testid="button-refresh-all"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh All
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList data-testid="tabs-endpoint">
          <TabsTrigger value="inventory" data-testid="tab-inventory">
            <Monitor className="h-4 w-4 mr-1.5" />
            Endpoint Inventory
          </TabsTrigger>
          <TabsTrigger value="detail" data-testid="tab-detail">
            <Eye className="h-4 w-4 mr-1.5" />
            Asset Detail
          </TabsTrigger>
        </TabsList>

        <TabsContent value="inventory" className="mt-4 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="stats-bar">
            <StatCard title="Total Endpoints" value={totalEndpoints} icon={Monitor} />
            <StatCard title="Online" value={onlineCount} icon={Activity} />
            <StatCard title="Offline / Degraded" value={offlineDegradedCount} icon={AlertTriangle} />
            <StatCard title="High Risk" value={highRiskCount} icon={Shield} />
          </div>

          {!endpoints || endpoints.length === 0 ? (
            <Card data-testid="empty-endpoints">
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Monitor className="h-10 w-10 text-muted-foreground mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No endpoints discovered</p>
                <p className="text-xs text-muted-foreground mt-1">Seed demo endpoint data to get started</p>
                <Button
                  className="mt-4"
                  onClick={() => seedMutation.mutate()}
                  disabled={seedMutation.isPending}
                  data-testid="button-seed-endpoints-empty"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Seed Endpoints
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2" data-testid="endpoint-list">
              {endpoints.map((asset) => {
                const risk = asset.riskScore ?? 0;
                const tags: string[] = (() => {
                  try {
                    if (Array.isArray(asset.tags)) return asset.tags;
                    if (typeof asset.tags === "string") return JSON.parse(asset.tags);
                    return [];
                  } catch { return []; }
                })();

                return (
                  <Card key={asset.id} data-testid={`card-endpoint-${asset.id}`}>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3 flex-wrap">
                        <div className="flex items-center gap-2 flex-shrink-0 pt-1">
                          <span className={`h-2.5 w-2.5 rounded-full ${statusDot(asset.agentStatus)}`} data-testid={`status-dot-${asset.id}`} />
                        </div>
                        <div className="min-w-0 flex-1 space-y-2">
                          <div className="flex items-start justify-between gap-3 flex-wrap">
                            <div className="min-w-0 space-y-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-semibold" data-testid={`text-hostname-${asset.id}`}>
                                  {asset.hostname}
                                </span>
                                <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase">
                                  {asset.os}
                                </Badge>
                              </div>
                              <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                                {asset.osVersion && (
                                  <span data-testid={`text-os-version-${asset.id}`}>
                                    v{asset.osVersion}
                                  </span>
                                )}
                                {asset.agentVersion && (
                                  <span data-testid={`text-agent-version-${asset.id}`}>
                                    Agent: {asset.agentVersion}
                                  </span>
                                )}
                                {asset.ipAddress && (
                                  <span className="font-mono" data-testid={`text-ip-${asset.id}`}>
                                    {asset.ipAddress}
                                  </span>
                                )}
                                <span data-testid={`text-last-seen-${asset.id}`}>
                                  {formatTimestamp(asset.lastSeenAt)}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border tabular-nums ${riskBadgeColor(risk)}`} data-testid={`badge-risk-${asset.id}`}>
                                Risk: {risk}
                              </span>
                            </div>
                          </div>
                          {tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {tags.map((tag, ti) => (
                                <Badge key={ti} variant="secondary" className="text-[10px]" data-testid={`badge-tag-${asset.id}-${ti}`}>
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                          <div className="flex items-center gap-1 flex-wrap">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                setSelectedAssetId(asset.id);
                                setActiveTab("detail");
                              }}
                              data-testid={`button-view-detail-${asset.id}`}
                            >
                              <Eye className="h-3.5 w-3.5 mr-1.5" />
                              View Detail
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => genTelemetryMutation.mutate(asset.id)}
                              disabled={genTelemetryMutation.isPending}
                              data-testid={`button-gen-telemetry-${asset.id}`}
                            >
                              <Activity className="h-3.5 w-3.5 mr-1.5" />
                              Generate Telemetry
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => calcRiskMutation.mutate(asset.id)}
                              disabled={calcRiskMutation.isPending}
                              data-testid={`button-calc-risk-${asset.id}`}
                            >
                              <Shield className="h-3.5 w-3.5 mr-1.5" />
                              Calculate Risk
                            </Button>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="detail" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Select Asset</CardTitle>
            </CardHeader>
            <CardContent>
              <Select
                value={selectedAssetId ?? ""}
                onValueChange={(val) => setSelectedAssetId(val)}
              >
                <SelectTrigger className="w-full max-w-sm" data-testid="select-asset">
                  <SelectValue placeholder="Choose an endpoint..." />
                </SelectTrigger>
                <SelectContent>
                  {endpoints?.map((asset) => (
                    <SelectItem key={asset.id} value={asset.id} data-testid={`option-asset-${asset.id}`}>
                      {asset.hostname} ({asset.ipAddress || asset.os})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </CardContent>
          </Card>

          {selectedAssetId && endpoints ? (
            <AssetDetailView assetId={selectedAssetId} assets={endpoints} />
          ) : (
            <Card data-testid="empty-asset-selection">
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Monitor className="h-10 w-10 text-muted-foreground mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No asset selected</p>
                <p className="text-xs text-muted-foreground mt-1">Select an endpoint from the dropdown above or click "View Detail" from the inventory</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
