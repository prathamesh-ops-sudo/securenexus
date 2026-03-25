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
import { formatDateTime as formatTimestamp } from "@/lib/i18n";
import {
  Monitor,
  Cpu,
  HardDrive,
  Shield,
  Activity,
  Wifi,
  AlertTriangle,
  RefreshCw,
  Database,
  Plus,
  Eye,
  ChevronRight,
  Users,
  Package,
  Globe,
  Lock,
  CheckCircle,
  XCircle,
  Radio,
  Layers,
  Bug,
  Network,
  Server,
} from "lucide-react";
import type { EndpointAsset, EndpointTelemetry } from "@shared/schema";

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

function StatCard({
  title,
  value,
  icon: Icon,
  loading,
  subtitle,
  color,
}: {
  title: string;
  value: string | number;
  icon: typeof Monitor;
  loading?: boolean;
  subtitle?: string;
  color?: string;
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
          <div>
            <div className={`text-2xl font-bold tabular-nums ${color || ""}`} data-testid={`value-${testId}`}>
              {value}
            </div>
            {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function parseTelemetryMetric(telemetry: EndpointTelemetry[], metricType: string) {
  const entry = telemetry.find((t) => t.metricType === metricType);
  if (!entry) return null;
  try {
    if (typeof entry.metricValue === "string") return JSON.parse(entry.metricValue);
    return entry.metricValue;
  } catch {
    return null;
  }
}

// ─── 26.2 Endpoint Dashboard Tab ─────────────────────────────────────────────

function EndpointDashboardTab() {
  const { data: dashboard, isLoading } = useQuery<any>({
    queryKey: ["/api/endpoints/dashboard"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (!dashboard) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <Monitor className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium text-muted-foreground">No endpoint data available</p>
          <p className="text-xs text-muted-foreground mt-1">Seed endpoints from the Inventory tab to see dashboard</p>
        </CardContent>
      </Card>
    );
  }

  const osEntries = Object.entries(dashboard.osDistribution || {}) as [string, number][];

  return (
    <div className="space-y-4" data-testid="section-endpoint-dashboard">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard title="Total Endpoints" value={dashboard.total ?? 0} icon={Monitor} />
        <StatCard title="Online" value={dashboard.online ?? 0} icon={Activity} color="text-green-500" />
        <StatCard
          title="Offline"
          value={dashboard.offline ?? 0}
          icon={AlertTriangle}
          color={dashboard.offline > 0 ? "text-red-500" : ""}
        />
        <StatCard
          title="Degraded"
          value={dashboard.degraded ?? 0}
          icon={Wifi}
          color={dashboard.degraded > 0 ? "text-yellow-500" : ""}
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          title="Outdated Agents"
          value={dashboard.outdatedAgents ?? 0}
          icon={RefreshCw}
          subtitle="Need upgrade"
          color={dashboard.outdatedAgents > 0 ? "text-yellow-500" : ""}
        />
        <StatCard
          title="Critical Vulns"
          value={dashboard.criticalVulnEndpoints ?? 0}
          icon={Bug}
          subtitle="Endpoints affected"
          color={dashboard.criticalVulnEndpoints > 0 ? "text-red-500" : ""}
        />
        <StatCard
          title="Compliance Failures"
          value={dashboard.complianceFailures ?? 0}
          icon={Shield}
          subtitle="Failing checks"
          color={dashboard.complianceFailures > 0 ? "text-red-500" : ""}
        />
        <StatCard
          title="Avg Risk Score"
          value={dashboard.avgRiskScore ?? 0}
          icon={Activity}
          subtitle="Across all endpoints"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* OS Distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Layers className="h-4 w-4" />
              OS Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {osEntries.length === 0 ? (
              <p className="text-xs text-muted-foreground">No data</p>
            ) : (
              osEntries.map(([os, ct]) => (
                <div key={os} className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{os}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 bg-muted/50 rounded-full h-2">
                      <div
                        className="h-2 rounded-full bg-blue-500"
                        style={{ width: `${dashboard.total > 0 ? (ct / dashboard.total) * 100 : 0}%` }}
                      />
                    </div>
                    <span className="text-xs tabular-nums text-muted-foreground w-8 text-right">{ct}</span>
                  </div>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* Risk Distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Risk Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              { label: "Critical", value: dashboard.riskDistribution?.critical ?? 0, color: "bg-red-500" },
              { label: "High", value: dashboard.riskDistribution?.high ?? 0, color: "bg-orange-500" },
              { label: "Medium", value: dashboard.riskDistribution?.medium ?? 0, color: "bg-yellow-500" },
              { label: "Low", value: dashboard.riskDistribution?.low ?? 0, color: "bg-green-500" },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium">{item.label}</span>
                <div className="flex items-center gap-2">
                  <div className="w-32 bg-muted/50 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${item.color}`}
                      style={{ width: `${dashboard.total > 0 ? (item.value / dashboard.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="text-xs tabular-nums text-muted-foreground w-8 text-right">{item.value}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Check-in Status */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Radio className="h-4 w-4" />
              Check-in Status
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm">Recent check-ins (24h)</span>
              <span className="text-sm font-bold tabular-nums text-green-500">{dashboard.recentCheckIns ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm">Stale endpoints (7d+)</span>
              <span
                className={`text-sm font-bold tabular-nums ${(dashboard.staleEndpoints ?? 0) > 0 ? "text-red-500" : ""}`}
              >
                {dashboard.staleEndpoints ?? 0}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── 26.3 Endpoint Group Management Tab ──────────────────────────────────────

function EndpointGroupsTab() {
  const { data: groups, isLoading } = useQuery<any>({
    queryKey: ["/api/endpoints/groups"],
  });

  if (isLoading) {
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

  const autoGroups = groups?.autoGroups || [];
  const customGroups = groups?.customGroups || [];

  return (
    <div className="space-y-4" data-testid="section-endpoint-groups">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Endpoint Groups</h2>
        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
          {autoGroups.length + customGroups.length} groups
        </Badge>
      </div>

      {autoGroups.length === 0 && customGroups.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Users className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No endpoint groups yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Groups are auto-generated based on OS type when endpoints exist
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {autoGroups.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2 uppercase tracking-wider">
                Auto-Generated Groups
              </h3>
              <div className="space-y-2">
                {autoGroups.map((group: any) => (
                  <Card key={group.id} data-testid={`card-group-${group.id}`}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between gap-3 flex-wrap">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Layers className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm font-semibold">{group.name}</span>
                            <Badge
                              variant="outline"
                              className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                            >
                              {group.groupBy}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>{group.endpointCount} endpoints</span>
                            <span>{group.onlineCount} online</span>
                            <span>Avg Risk: {group.avgRiskScore}</span>
                          </div>
                        </div>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border tabular-nums ${riskBadgeColor(group.avgRiskScore)}`}
                        >
                          Risk: {group.avgRiskScore}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {customGroups.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2 uppercase tracking-wider">Custom Groups</h3>
              <div className="space-y-2">
                {customGroups.map((group: any) => (
                  <Card key={group.id}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between gap-3 flex-wrap">
                        <div className="space-y-1">
                          <span className="text-sm font-semibold">{group.name}</span>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>{group.endpointCount} endpoints</span>
                            <span>Created: {formatTimestamp(group.createdAt)}</span>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── 26.7 Sensor Coverage Tab ────────────────────────────────────────────────

function SensorCoverageTab() {
  const { data: coverage, isLoading } = useQuery<any>({
    queryKey: ["/api/endpoints/sensor-coverage"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (!coverage) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <Radio className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-sm font-medium text-muted-foreground">No sensor data available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4" data-testid="section-sensor-coverage">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard title="Total Endpoints" value={coverage.totalEndpoints ?? 0} icon={Monitor} />
        <StatCard
          title="Sensors Deployed"
          value={coverage.sensorsDeployed ?? 0}
          icon={Radio}
          subtitle={`${coverage.coveragePercent ?? 0}% coverage`}
          color="text-green-500"
        />
        <StatCard
          title="Up to Date"
          value={coverage.sensorsCurrent ?? 0}
          icon={CheckCircle}
          subtitle={`${coverage.currentPercent ?? 0}% current`}
          color="text-green-500"
        />
        <StatCard
          title="No Coverage"
          value={coverage.noCoverage ?? 0}
          icon={XCircle}
          subtitle="Missing sensors"
          color={coverage.noCoverage > 0 ? "text-red-500" : ""}
        />
      </div>

      {/* Coverage progress bar */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Sensor Deployment Coverage</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Deployed</span>
            <span className="font-bold tabular-nums">{coverage.coveragePercent ?? 0}%</span>
          </div>
          <Progress value={coverage.coveragePercent ?? 0} className="h-3" />
        </CardContent>
      </Card>

      {/* Uncovered endpoints */}
      {(coverage.uncoveredEndpoints || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              Endpoints Without Sensors
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(coverage.uncoveredEndpoints || []).map((ep: any) => (
                <div
                  key={ep.assetId}
                  className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                >
                  <div className="flex items-center gap-2">
                    <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="font-medium">{ep.hostname}</span>
                    <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
                      {ep.os}
                    </Badge>
                  </div>
                  <Badge variant="destructive" className="text-[10px]">
                    No Sensor
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Outdated sensors */}
      {(coverage.outdatedEndpoints || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <RefreshCw className="h-4 w-4 text-yellow-500" />
              Outdated Sensors
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(coverage.outdatedEndpoints || []).map((ep: any) => (
                <div
                  key={ep.assetId}
                  className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                >
                  <div className="flex items-center gap-2">
                    <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="font-medium">{ep.hostname}</span>
                    <span className="text-xs text-muted-foreground">v{ep.sensorVersion}</span>
                  </div>
                  <Badge
                    variant="outline"
                    className="no-default-hover-elevate no-default-active-elevate text-[10px] text-yellow-500 border-yellow-500/20"
                  >
                    Needs Upgrade
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── 26.1 Enhanced Asset Detail View ─────────────────────────────────────────

function AssetDetailView({ assetId, assets }: { assetId: string; assets: EndpointAsset[] }) {
  const asset = assets.find((a) => a.id === assetId);
  const [detailTab, setDetailTab] = useState("overview");

  const { data: detail, isLoading: detailLoading } = useQuery<any>({
    queryKey: ["/api/endpoints", assetId, "detail"],
    enabled: !!assetId,
  });

  const { data: telemetry, isLoading: telemetryLoading } = useQuery<EndpointTelemetry[]>({
    queryKey: ["/api/endpoints", assetId, "telemetry"],
    enabled: !!assetId,
  });

  const { data: vulns } = useQuery<any>({
    queryKey: ["/api/endpoints", assetId, "vulnerabilities"],
    enabled: !!assetId,
  });

  const { data: softwareInv } = useQuery<any>({
    queryKey: ["/api/endpoints", assetId, "software-inventory"],
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

  return (
    <div className="space-y-4" data-testid="section-asset-detail">
      {/* Asset Header Card */}
      <Card data-testid={`card-asset-info-${assetId}`}>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2 flex-wrap">
            <Monitor className="h-4 w-4" />
            {asset.hostname}
            <span className={`h-2.5 w-2.5 rounded-full ${statusDot(asset.agentStatus)}`} />
            <span className="text-xs text-muted-foreground capitalize">{asset.agentStatus || "offline"}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
            <div>
              <span className="text-xs text-muted-foreground">OS</span>
              <p className="font-medium">
                {asset.os} {asset.osVersion || ""}
              </p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Agent Version</span>
              <p className="font-medium">{asset.agentVersion || "N/A"}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">IP Address</span>
              <p className="font-mono text-sm">{asset.ipAddress || "N/A"}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">MAC Address</span>
              <p className="font-mono text-sm">{asset.macAddress || "N/A"}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Last Seen</span>
              <p className="text-sm">{formatTimestamp(asset.lastSeenAt)}</p>
            </div>
            <div>
              <span className="text-xs text-muted-foreground">Risk Score</span>
              <span
                className={`text-lg font-bold tabular-nums ${riskScore > 60 ? "text-red-500" : riskScore > 30 ? "text-yellow-500" : "text-green-500"}`}
              >
                {riskScore}
              </span>
            </div>
          </div>
          <div className="w-full bg-muted/50 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all ${riskBarColor(riskScore)}`}
              style={{ width: `${Math.min(riskScore, 100)}%` }}
            />
          </div>
        </CardContent>
      </Card>

      {/* Detail Sub-tabs */}
      <Tabs value={detailTab} onValueChange={setDetailTab}>
        <TabsList>
          <TabsTrigger value="overview">
            <Activity className="h-3.5 w-3.5 mr-1" />
            Telemetry
          </TabsTrigger>
          <TabsTrigger value="software">
            <Package className="h-3.5 w-3.5 mr-1" />
            Software
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="h-3.5 w-3.5 mr-1" />
            Security
          </TabsTrigger>
          <TabsTrigger value="network">
            <Network className="h-3.5 w-3.5 mr-1" />
            Network
          </TabsTrigger>
          <TabsTrigger value="vulns">
            <Bug className="h-3.5 w-3.5 mr-1" />
            Vulnerabilities
          </TabsTrigger>
        </TabsList>

        {/* Telemetry Overview */}
        <TabsContent value="overview" className="mt-4">
          {telemetryLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <Card key={i}>
                  <CardContent className="p-4">
                    <Skeleton className="h-24 w-full" />
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : !telemetry || telemetry.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Activity className="h-10 w-10 text-muted-foreground mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No telemetry data available</p>
                <p className="text-xs text-muted-foreground mt-1">Generate telemetry from the Endpoint Inventory tab</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {cpu && (
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      CPU Usage
                    </CardTitle>
                    <div className="p-1.5 rounded-md bg-muted/50">
                      <Cpu className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="text-2xl font-bold tabular-nums">{cpu.usage ?? cpu.percent ?? 0}%</div>
                    <Progress value={cpu.usage ?? cpu.percent ?? 0} className="h-2" />
                    {cpu.cores && <p className="text-xs text-muted-foreground">{cpu.cores} cores</p>}
                  </CardContent>
                </Card>
              )}
              {memory && (
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Memory Usage
                    </CardTitle>
                    <div className="p-1.5 rounded-md bg-muted/50">
                      <Activity className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="text-2xl font-bold tabular-nums">{memory.usage ?? memory.percent ?? 0}%</div>
                    <Progress value={memory.usage ?? memory.percent ?? 0} className="h-2" />
                    {memory.totalGb && <p className="text-xs text-muted-foreground">{memory.totalGb} GB total</p>}
                  </CardContent>
                </Card>
              )}
              {disk && (
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Disk Usage
                    </CardTitle>
                    <div className="p-1.5 rounded-md bg-muted/50">
                      <HardDrive className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="text-2xl font-bold tabular-nums">{disk.usage ?? disk.percent ?? 0}%</div>
                    <Progress value={disk.usage ?? disk.percent ?? 0} className="h-2" />
                    {disk.totalGb && <p className="text-xs text-muted-foreground">{disk.totalGb} GB total</p>}
                  </CardContent>
                </Card>
              )}
              {processes && (
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Processes
                    </CardTitle>
                    <div className="p-1.5 rounded-md bg-muted/50">
                      <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold tabular-nums">{processes.total ?? 0}</div>
                    {processes.suspicious != null && processes.suspicious > 0 && (
                      <p className="text-xs text-red-500 font-medium mt-1">{processes.suspicious} suspicious</p>
                    )}
                  </CardContent>
                </Card>
              )}
              {av && (
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Antivirus
                    </CardTitle>
                    <div className="p-1.5 rounded-md bg-muted/50">
                      <Shield className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-2">
                      {av.enabled !== false ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-500" />
                      )}
                      <span className="text-sm font-medium">{av.enabled !== false ? "Active" : "Disabled"}</span>
                    </div>
                    {av.lastUpdate && <p className="text-xs text-muted-foreground mt-1">Updated: {av.lastUpdate}</p>}
                    {av.product && <p className="text-xs text-muted-foreground">{av.product}</p>}
                  </CardContent>
                </Card>
              )}
              {patches && (
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Patches
                    </CardTitle>
                    <div className="p-1.5 rounded-md bg-muted/50">
                      <Database className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold tabular-nums">
                      {patches.installed ?? 0}/{patches.total ?? 0}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {(patches.pending ?? 0) > 0 ? (
                        <span className="text-yellow-500 font-medium">{patches.pending} pending</span>
                      ) : (
                        "All patches applied"
                      )}
                    </p>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* 26.5 Software Inventory */}
        <TabsContent value="software" className="mt-4">
          {!softwareInv ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Package className="h-10 w-10 text-muted-foreground mb-3" />
                <p className="text-sm font-medium text-muted-foreground">Software inventory loading...</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <StatCard title="Total Software" value={softwareInv.totalSoftware ?? 0} icon={Package} />
                <StatCard
                  title="Total CVEs"
                  value={softwareInv.totalCves ?? 0}
                  icon={Bug}
                  color={softwareInv.totalCves > 0 ? "text-yellow-500" : ""}
                />
                <StatCard
                  title="High Risk"
                  value={softwareInv.highRiskSoftware ?? 0}
                  icon={AlertTriangle}
                  color={softwareInv.highRiskSoftware > 0 ? "text-red-500" : ""}
                />
              </div>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Installed Software</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(softwareInv.inventory || []).map((sw: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <Package className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                          <div className="min-w-0">
                            <span className="font-medium">{sw.name}</span>
                            <span className="text-xs text-muted-foreground ml-2">v{sw.version}</span>
                            <p className="text-xs text-muted-foreground">{sw.vendor}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {sw.cveCount > 0 && (
                            <Badge
                              variant="outline"
                              className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${sw.riskLevel === "high" ? "text-red-500 border-red-500/20" : "text-yellow-500 border-yellow-500/20"}`}
                            >
                              {sw.cveCount} CVE{sw.cveCount > 1 ? "s" : ""}
                            </Badge>
                          )}
                          <Badge
                            variant="outline"
                            className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${sw.riskLevel === "high" ? "text-red-500" : sw.riskLevel === "medium" ? "text-yellow-500" : "text-green-500"}`}
                          >
                            {sw.riskLevel}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Security Agent + Compliance (26.1) */}
        <TabsContent value="security" className="mt-4">
          {detailLoading || !detail ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Card key={i}>
                  <CardContent className="p-4">
                    <Skeleton className="h-20 w-full" />
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="space-y-4">
              {/* Security Agent Status */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    Security Agent Status
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
                    <div className="flex items-center gap-2">
                      {detail.securityAgentStatus?.agentInstalled ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span>Agent {detail.securityAgentStatus?.agentInstalled ? "Installed" : "Not Installed"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {detail.securityAgentStatus?.antivirusEnabled ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span>Antivirus {detail.securityAgentStatus?.antivirusEnabled ? "Active" : "Disabled"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {detail.securityAgentStatus?.firewallEnabled ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span>Firewall {detail.securityAgentStatus?.firewallEnabled ? "Active" : "Disabled"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {detail.securityAgentStatus?.encryptionEnabled ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span>Disk Encryption</span>
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Patch Level</span>
                      <p className="font-medium">{detail.securityAgentStatus?.patchLevel || "Unknown"}</p>
                    </div>
                    {detail.securityAgentStatus?.agentVersion && (
                      <div>
                        <span className="text-xs text-muted-foreground">Agent Version</span>
                        <p className="font-medium">{detail.securityAgentStatus.agentVersion}</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Compliance State */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Lock className="h-4 w-4" />
                    Compliance Checks
                    <Badge
                      variant={detail.complianceState?.overallCompliant ? "outline" : "destructive"}
                      className="text-[10px] ml-auto"
                    >
                      {detail.complianceState?.passingChecks || 0}/{detail.complianceState?.totalChecks || 0} passing
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(detail.complianceState?.checks || []).map((check: any, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                      >
                        <div className="flex items-center gap-2">
                          {check.status === "pass" ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : check.status === "fail" ? (
                            <XCircle className="h-4 w-4 text-red-500" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-yellow-500" />
                          )}
                          <span className="font-medium">{check.control}</span>
                        </div>
                        <Badge
                          variant="outline"
                          className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${check.severity === "critical" ? "text-red-500" : check.severity === "high" ? "text-orange-500" : "text-yellow-500"}`}
                        >
                          {check.severity}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* User Sessions */}
              {(detail.userSessions || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Users className="h-4 w-4" />
                      Active User Sessions
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {(detail.userSessions || []).map((session: any, idx: number) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                        >
                          <div className="flex items-center gap-2">
                            <Users className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="font-medium">{session.user}</span>
                            <Badge
                              variant="outline"
                              className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                            >
                              {session.sessionType}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">{formatTimestamp(session.loginTime)}</span>
                            {session.active && <span className="h-2 w-2 rounded-full bg-green-500" />}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* Network (26.1 - open ports, connections) */}
        <TabsContent value="network" className="mt-4">
          {detailLoading || !detail ? (
            <Card>
              <CardContent className="p-4">
                <Skeleton className="h-32 w-full" />
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {/* Open Ports */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Globe className="h-4 w-4" />
                    Open Ports
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {(detail.openPorts || []).length === 0 ? (
                    <p className="text-xs text-muted-foreground">No open ports detected</p>
                  ) : (
                    <div className="space-y-1">
                      {(detail.openPorts || []).map((port: any, idx: number) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                        >
                          <div className="flex items-center gap-3">
                            <span className="font-mono font-bold tabular-nums">{port.port}</span>
                            <Badge
                              variant="outline"
                              className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                            >
                              {port.protocol}
                            </Badge>
                            <span className="text-muted-foreground">{port.service}</span>
                          </div>
                          <Badge
                            variant="outline"
                            className="no-default-hover-elevate no-default-active-elevate text-[10px] text-green-500"
                          >
                            {port.state}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Network Connections */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Network className="h-4 w-4" />
                    Active Connections
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {(detail.networkConnections || []).length === 0 ? (
                    <p className="text-xs text-muted-foreground">No active connections</p>
                  ) : (
                    <div className="space-y-1">
                      {(detail.networkConnections || []).map((conn: any, idx: number) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="font-mono text-xs">{conn.localAddr}</span>
                            <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                            <span className="font-mono text-xs">{conn.remoteAddr}</span>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <span className="text-xs text-muted-foreground">{conn.process}</span>
                            <Badge
                              variant="outline"
                              className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${conn.state === "ESTABLISHED" ? "text-green-500" : "text-yellow-500"}`}
                            >
                              {conn.state}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Running Processes */}
              {(detail.runningProcesses || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Server className="h-4 w-4" />
                      Running Processes
                      <Badge
                        variant="outline"
                        className="no-default-hover-elevate no-default-active-elevate text-[10px] ml-auto"
                      >
                        {(detail.runningProcesses || []).length}
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1 max-h-64 overflow-y-auto">
                      {(detail.runningProcesses || []).map((proc: any, idx: number) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between gap-2 text-sm p-1.5 rounded bg-muted/30"
                        >
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-xs text-muted-foreground tabular-nums w-12">
                              {proc.pid}
                            </span>
                            <span className="font-medium text-xs">{proc.name}</span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground">
                            <span className="tabular-nums">CPU: {proc.cpu}%</span>
                            <span className="tabular-nums">MEM: {proc.memory}MB</span>
                            <span>{proc.user}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* 26.6 Vulnerabilities */}
        <TabsContent value="vulns" className="mt-4">
          {!vulns ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Bug className="h-10 w-10 text-muted-foreground mb-3" />
                <p className="text-sm font-medium text-muted-foreground">Vulnerability data loading...</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatCard title="Total Vulns" value={vulns.totalVulnerabilities ?? 0} icon={Bug} />
                <StatCard
                  title="Open"
                  value={vulns.openVulnerabilities ?? 0}
                  icon={AlertTriangle}
                  color={vulns.openVulnerabilities > 0 ? "text-red-500" : ""}
                />
                <StatCard
                  title="Critical"
                  value={vulns.criticalVulnerabilities ?? 0}
                  icon={Shield}
                  color={vulns.criticalVulnerabilities > 0 ? "text-red-500" : ""}
                />
                <StatCard title="CSPM Correlations" value={vulns.cspmCorrelations ?? 0} icon={Globe} />
              </div>

              {/* Vulnerability list */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Prioritized Vulnerabilities</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(vulns.vulnerabilities || []).map((v: any) => (
                      <div key={v.id} className="p-3 rounded border bg-muted/20 space-y-2">
                        <div className="flex items-start justify-between gap-2 flex-wrap">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-xs font-bold">{v.cveId}</span>
                              <Badge
                                variant={v.severity === "critical" ? "destructive" : "outline"}
                                className="text-[10px]"
                              >
                                {v.severity}
                              </Badge>
                              <Badge
                                variant="outline"
                                className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${v.status === "open" ? "text-red-500" : v.status === "patched" ? "text-green-500" : "text-yellow-500"}`}
                              >
                                {v.status}
                              </Badge>
                            </div>
                            <p className="text-sm">{v.title}</p>
                            <div className="flex items-center gap-3 text-xs text-muted-foreground">
                              <span>CVSS: {v.cvssScore}</span>
                              <span>EPSS: {(v.epssScore * 100).toFixed(0)}%</span>
                              <span>Software: {v.software}</span>
                            </div>
                          </div>
                          <div className="text-right flex-shrink-0">
                            <span className="text-xs text-muted-foreground">Priority</span>
                            <div
                              className={`text-lg font-bold tabular-nums ${v.priorityScore > 50 ? "text-red-500" : v.priorityScore > 25 ? "text-yellow-500" : "text-green-500"}`}
                            >
                              {v.priorityScore}
                            </div>
                          </div>
                        </div>
                        {v.patchAvailable && v.status === "open" && (
                          <div className="flex items-center gap-1 text-xs text-green-600">
                            <CheckCircle className="h-3 w-3" />
                            <span>Patch available</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Patching priority */}
              {(vulns.patchingPriority || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <ChevronRight className="h-4 w-4" />
                      Patching Priority Queue
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {(vulns.patchingPriority || []).map((p: any, idx: number) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between gap-2 text-sm p-2 rounded bg-muted/30"
                        >
                          <div>
                            <span className="font-mono text-xs font-bold">{p.cveId}</span>
                            <span className="text-muted-foreground ml-2">{p.title}</span>
                          </div>
                          <div className="text-xs text-muted-foreground">{p.reason}</div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Main Page Component ─────────────────────────────────────────────────────

export default function EndpointTelemetryPage() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("dashboard");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const {
    data: endpoints,
    isLoading,
    isError: endpointsError,
    refetch: refetchEndpoints,
  } = useQuery<EndpointAsset[]>({
    queryKey: ["/api/endpoints"],
  });

  const seedMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/endpoints/seed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints/dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints/groups"] });
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints/sensor-coverage"] });
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
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints", id, "detail"] });
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
      queryClient.invalidateQueries({ queryKey: ["/api/endpoints/dashboard"] });
      toast({ title: "Risk calculated", description: "Endpoint risk score has been updated." });
    },
    onError: (err: Error) => {
      toast({ title: "Risk calculation failed", description: err.message, variant: "destructive" });
    },
  });

  const totalEndpoints = endpoints?.length ?? 0;
  const onlineCount = endpoints?.filter((e) => e.agentStatus === "online").length ?? 0;
  const offlineDegradedCount =
    endpoints?.filter((e) => e.agentStatus === "offline" || e.agentStatus === "degraded").length ?? 0;
  const highRiskCount = endpoints?.filter((e) => (e.riskScore ?? 0) > 60).length ?? 0;

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
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (endpointsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load endpoint inventory</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchEndpoints()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-endpoint-telemetry">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            Endpoint Telemetry
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Monitor endpoint health, telemetry metrics, and risk posture
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            onClick={() => {
              seedMutation.reset();
              seedMutation.mutate();
            }}
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
          <TabsTrigger value="dashboard" data-testid="tab-dashboard">
            <Activity className="h-4 w-4 mr-1.5" />
            Dashboard
          </TabsTrigger>
          <TabsTrigger value="inventory" data-testid="tab-inventory">
            <Monitor className="h-4 w-4 mr-1.5" />
            Inventory
          </TabsTrigger>
          <TabsTrigger value="detail" data-testid="tab-detail">
            <Eye className="h-4 w-4 mr-1.5" />
            Asset Detail
          </TabsTrigger>
          <TabsTrigger value="groups" data-testid="tab-groups">
            <Users className="h-4 w-4 mr-1.5" />
            Groups
          </TabsTrigger>
          <TabsTrigger value="sensors" data-testid="tab-sensors">
            <Radio className="h-4 w-4 mr-1.5" />
            Sensor Coverage
          </TabsTrigger>
        </TabsList>

        {/* 26.2 Dashboard */}
        <TabsContent value="dashboard" className="mt-4">
          <EndpointDashboardTab />
        </TabsContent>

        {/* Inventory */}
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
                  onClick={() => {
                    seedMutation.reset();
                    seedMutation.mutate();
                  }}
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
                  } catch {
                    return [];
                  }
                })();

                return (
                  <Card key={asset.id} data-testid={`card-endpoint-${asset.id}`}>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3 flex-wrap">
                        <div className="flex items-center gap-2 flex-shrink-0 pt-1">
                          <span
                            className={`h-2.5 w-2.5 rounded-full ${statusDot(asset.agentStatus)}`}
                            data-testid={`status-dot-${asset.id}`}
                          />
                        </div>
                        <div className="min-w-0 flex-1 space-y-2">
                          <div className="flex items-start justify-between gap-3 flex-wrap">
                            <div className="min-w-0 space-y-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-semibold" data-testid={`text-hostname-${asset.id}`}>
                                  {asset.hostname}
                                </span>
                                <Badge
                                  variant="outline"
                                  className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                                >
                                  {asset.os}
                                </Badge>
                              </div>
                              <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                                {asset.osVersion && (
                                  <span data-testid={`text-os-version-${asset.id}`}>v{asset.osVersion}</span>
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
                              <span
                                className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border tabular-nums ${riskBadgeColor(risk)}`}
                                data-testid={`badge-risk-${asset.id}`}
                              >
                                Risk: {risk}
                              </span>
                            </div>
                          </div>
                          {tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {tags.map((tag, ti) => (
                                <Badge
                                  key={ti}
                                  variant="secondary"
                                  className="text-[10px]"
                                  data-testid={`badge-tag-${asset.id}-${ti}`}
                                >
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
                              onClick={() => {
                                genTelemetryMutation.reset();
                                genTelemetryMutation.mutate(asset.id);
                              }}
                              disabled={genTelemetryMutation.isPending}
                              data-testid={`button-gen-telemetry-${asset.id}`}
                            >
                              <Activity className="h-3.5 w-3.5 mr-1.5" />
                              Generate Telemetry
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                calcRiskMutation.reset();
                                calcRiskMutation.mutate(asset.id);
                              }}
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

        {/* 26.1 Enhanced Detail */}
        <TabsContent value="detail" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Select Asset</CardTitle>
            </CardHeader>
            <CardContent>
              <Select value={selectedAssetId ?? ""} onValueChange={(val) => setSelectedAssetId(val)}>
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
                <p className="text-xs text-muted-foreground mt-1">
                  Select an endpoint from the dropdown above or click &quot;View Detail&quot; from the inventory
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* 26.3 Groups */}
        <TabsContent value="groups" className="mt-4">
          <EndpointGroupsTab />
        </TabsContent>

        {/* 26.7 Sensor Coverage */}
        <TabsContent value="sensors" className="mt-4">
          <SensorCoverageTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
