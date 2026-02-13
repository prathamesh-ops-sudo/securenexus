import { useQuery } from "@tanstack/react-query";
import { useState, useEffect, useCallback } from "react";
import {
  Shield, AlertTriangle, FileWarning, CheckCircle2, Zap, ArrowUpRight,
  Clock, Target, Plug, Activity, TrendingUp, Crosshair, RefreshCw
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import { SeverityBadge } from "@/components/security-badges";
import { LiveActivityFeed } from "@/components/live-activity-feed";
import type { Alert, Incident } from "@shared/schema";
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip as RechartsTooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  informational: "#6b7280",
};

const SOURCE_COLORS = [
  "#ef4444", "#f97316", "#ec4899", "#14b8a6", "#f59e0b",
  "#e11d48", "#10b981", "#f43f5e", "#d946ef", "#84cc16",
];

function StatCard({ title, value, icon: Icon, subtitle, loading, accent, href }: {
  title: string;
  value: number | string;
  icon: any;
  subtitle?: string;
  loading?: boolean;
  accent?: string;
  href?: string;
}) {
  const testId = `stat-${title.toLowerCase().replace(/\s/g, "-")}`;
  const card = (
    <Card className={href ? "gradient-card cursor-pointer" : "glass-subtle gradient-stat-card"} data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className={`p-1.5 rounded-md ${accent ? 'gradient-icon-bg' : 'bg-muted/50'}`}>
          <Icon className={`h-3.5 w-3.5 ${accent || "text-muted-foreground"}`} />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold tabular-nums" data-testid={`value-${title.toLowerCase().replace(/\s/g, "-")}`}>{value}</div>
        )}
        {subtitle && <p className="text-[11px] text-muted-foreground mt-1">{subtitle}</p>}
      </CardContent>
    </Card>
  );

  if (href) {
    return (
      <Link href={href} data-testid={`link-${testId}`}>
        {card}
      </Link>
    );
  }

  return card;
}

function ChartSkeleton() {
  return (
    <div className="space-y-3 p-4">
      <Skeleton className="h-4 w-32" />
      <Skeleton className="h-[180px] w-full" />
    </div>
  );
}

type AnalyticsData = {
  severityDistribution: { name: string; value: number }[];
  sourceDistribution: { name: string; value: number }[];
  categoryDistribution: { name: string; value: number }[];
  statusDistribution: { name: string; value: number }[];
  alertTrend: { date: string; count: number }[];
  mttrHours: number | null;
  topMitreTactics: { name: string; value: number }[];
  connectorHealth: { name: string; type: string; status: string; lastSyncAt: string | null; lastSyncAlerts: number; lastSyncError: string | null }[];
  ingestionRate: { date: string; created: number; deduped: number; failed: number }[];
};

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-popover border border-border rounded-md px-3 py-2 text-xs shadow-lg">
      {label && <p className="text-muted-foreground mb-1">{label}</p>}
      {payload.map((entry: any, i: number) => (
        <p key={i} style={{ color: entry.color }} className="font-medium">
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
}

function PieTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-popover border border-border rounded-md px-3 py-2 text-xs shadow-lg">
      <p className="font-medium" style={{ color: payload[0].payload.fill }}>
        {payload[0].name}: {payload[0].value}
      </p>
    </div>
  );
}

function SeverityChart({ data }: { data: { name: string; value: number }[] }) {
  const ordered = ["critical", "high", "medium", "low", "informational"];
  const sorted = ordered
    .map(s => data.find(d => d.name === s))
    .filter(Boolean) as { name: string; value: number }[];
  const total = sorted.reduce((s, d) => s + d.value, 0);

  return (
    <Card className="gradient-card" data-testid="chart-severity">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4">
          <div className="w-[140px] h-[140px] flex-shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={sorted}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={65}
                  dataKey="value"
                  stroke="none"
                >
                  {sorted.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#6b7280"} />
                  ))}
                </Pie>
                <RechartsTooltip content={<PieTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex-1 space-y-1.5">
            {sorted.map((entry) => (
              <div key={entry.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[entry.name] || "#6b7280" }}
                  />
                  <span className="capitalize text-muted-foreground">{entry.name}</span>
                </div>
                <span className="font-medium tabular-nums">
                  {entry.value} <span className="text-muted-foreground">({total > 0 ? Math.round((entry.value / total) * 100) : 0}%)</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function SourceChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card className="gradient-card" data-testid="chart-source">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Alerts by Source</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 0, right: 12, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="hsl(var(--border))" />
              <XAxis type="number" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fontSize: 10 }}
                width={100}
                stroke="hsl(var(--muted-foreground))"
              />
              <RechartsTooltip content={<CustomTooltip />} />
              <Bar dataKey="value" name="Alerts" radius={[0, 4, 4, 0]}>
                {data.map((_, i) => (
                  <Cell key={i} fill={SOURCE_COLORS[i % SOURCE_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

function TrendChart({ data }: { data: { date: string; count: number }[] }) {
  const formatted = data.map(d => ({
    ...d,
    label: new Date(d.date + "T00:00:00").toLocaleDateString("en-US", { month: "short", day: "numeric" }),
  }));

  return (
    <Card className="gradient-card" data-testid="chart-trend">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Alert Trend (7 Days)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formatted} margin={{ left: 0, right: 12, top: 4, bottom: 4 }}>
              <defs>
                <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis dataKey="label" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
              <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
              <RechartsTooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="count"
                name="Alerts"
                stroke="#ef4444"
                strokeWidth={2}
                fill="url(#trendGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

function MitreTacticsWidget({ data }: { data: { name: string; value: number }[] }) {
  const maxVal = Math.max(...data.map(d => d.value), 1);
  return (
    <Card className="gradient-card" data-testid="widget-mitre">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">Top MITRE ATT&CK Tactics</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-4">No MITRE data available</p>
        ) : (
          <div className="space-y-2.5">
            {data.map((item) => (
              <div key={item.name} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground truncate max-w-[70%]">{item.name}</span>
                  <span className="font-medium tabular-nums">{item.value}</span>
                </div>
                <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all bg-gradient-to-r from-red-500 to-red-600"
                    style={{ width: `${(item.value / maxVal) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CategoryWidget({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card className="gradient-card" data-testid="widget-categories">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">Threat Categories</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-4">No category data</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {data.map((item) => (
              <Badge key={item.name} variant="secondary" className="text-[10px]" data-testid={`badge-category-${item.name}`}>
                {item.name.replace(/_/g, " ")} ({item.value})
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ConnectorHealthWidget({ data }: { data: AnalyticsData["connectorHealth"] }) {
  const statusColors: Record<string, string> = {
    active: "bg-emerald-500",
    inactive: "bg-gray-400",
    error: "bg-red-500",
    syncing: "bg-red-500",
  };

  return (
    <Card className="gradient-card" data-testid="widget-connectors">
      <CardHeader className="flex flex-row items-center justify-between gap-1 pb-2">
        <div className="flex items-center gap-2">
          <Plug className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">Connector Health</CardTitle>
        </div>
        <Link href="/connectors" className="text-xs text-primary hover:underline" data-testid="link-manage-connectors">Manage</Link>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-4">No connectors configured</p>
        ) : (
          <div className="space-y-2">
            {data.slice(0, 6).map((c) => (
              <div key={c.name} className="flex items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2 min-w-0">
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColors[c.status] || "bg-gray-400"}`} />
                  <span className="truncate">{c.name}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 text-muted-foreground">
                  <span className="capitalize">{c.status}</span>
                  {c.lastSyncAlerts > 0 && <span className="tabular-nums">{c.lastSyncAlerts} synced</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function IngestionRateChart({ data }: { data: AnalyticsData["ingestionRate"] }) {
  const formatted = data.map(d => ({
    ...d,
    label: new Date(d.date + "T00:00:00").toLocaleDateString("en-US", { month: "short", day: "numeric" }),
  }));

  return (
    <Card className="gradient-card" data-testid="chart-ingestion">
      <CardHeader className="flex flex-row items-center justify-between gap-1 pb-2">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">Ingestion Rate (7 Days)</CardTitle>
        </div>
        <Link href="/ingestion" className="text-xs text-primary hover:underline" data-testid="link-ingestion-details">Details</Link>
      </CardHeader>
      <CardContent>
        {formatted.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-4">No ingestion data</p>
        ) : (
          <div className="h-[140px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={formatted} margin={{ left: 0, right: 4, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="label" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
                <RechartsTooltip content={<CustomTooltip />} />
                <Bar dataKey="created" name="Created" fill="#10b981" stackId="a" radius={[0, 0, 0, 0]} />
                <Bar dataKey="deduped" name="Deduped" fill="#f59e0b" stackId="a" radius={[0, 0, 0, 0]} />
                <Bar dataKey="failed" name="Failed" fill="#ef4444" stackId="a" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [secondsAgo, setSecondsAgo] = useState(0);

  const { data: stats, isLoading: statsLoading, dataUpdatedAt: statsUpdatedAt, refetch: refetchStats } = useQuery<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }>({
    queryKey: ["/api/dashboard/stats"],
    refetchInterval: 30000,
  });

  const { data: analytics, isLoading: analyticsLoading, dataUpdatedAt: analyticsUpdatedAt, refetch: refetchAnalytics } = useQuery<AnalyticsData>({
    queryKey: ["/api/dashboard/analytics"],
    refetchInterval: 30000,
  });

  const { data: recentAlerts, isLoading: alertsLoading, refetch: refetchAlerts } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: recentIncidents, isLoading: incidentsLoading, refetch: refetchIncidents } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  useEffect(() => {
    const latest = Math.max(statsUpdatedAt || 0, analyticsUpdatedAt || 0);
    if (latest > 0) {
      setLastUpdated(new Date(latest));
    }
  }, [statsUpdatedAt, analyticsUpdatedAt]);

  useEffect(() => {
    const interval = setInterval(() => {
      setSecondsAgo(Math.floor((Date.now() - lastUpdated.getTime()) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [lastUpdated]);

  const handleRefresh = useCallback(() => {
    refetchStats();
    refetchAnalytics();
    refetchAlerts();
    refetchIncidents();
  }, [refetchStats, refetchAnalytics, refetchAlerts, refetchIncidents]);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between gap-4 flex-wrap animate-fade-in">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Security Operations Center</span></h1>
          <p className="text-sm text-muted-foreground mt-1">Real-time threat monitoring and operational intelligence</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground" data-testid="text-last-updated">
              Last updated: {secondsAgo < 60 ? `${secondsAgo}s ago` : `${Math.floor(secondsAgo / 60)}m ago`}
            </span>
            <Button size="icon" variant="ghost" onClick={handleRefresh} data-testid="button-refresh">
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
          {analytics?.mttrHours !== null && analytics?.mttrHours !== undefined && (
            <Card className="gradient-card px-4 py-2" data-testid="stat-mttr">
              <div className="flex items-center gap-3">
                <div className="p-1.5 rounded-md bg-primary/10">
                  <Clock className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">MTTR</p>
                  <p className="text-lg font-bold tabular-nums">{analytics.mttrHours}h</p>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="animate-fade-in delay-100">
          <StatCard title="Total Alerts" value={stats?.totalAlerts ?? 0} icon={AlertTriangle} subtitle="All sources" loading={statsLoading} href="/alerts" />
        </div>
        <div className="animate-fade-in delay-150">
          <StatCard title="Open Incidents" value={stats?.openIncidents ?? 0} icon={FileWarning} subtitle="Requires attention" loading={statsLoading} accent="text-orange-500" href="/incidents?status=open" />
        </div>
        <div className="animate-fade-in delay-200">
          <StatCard title="Critical Alerts" value={stats?.criticalAlerts ?? 0} icon={Shield} subtitle="Immediate action" loading={statsLoading} accent="text-red-500" href="/alerts?severity=critical" />
        </div>
        <div className="animate-fade-in delay-300">
          <StatCard title="New Today" value={stats?.newAlertsToday ?? 0} icon={Zap} subtitle="Ingested today" loading={statsLoading} accent="text-red-500" href="/alerts" />
        </div>
        <div className="animate-fade-in delay-400">
          <StatCard title="Escalated" value={stats?.escalatedIncidents ?? 0} icon={ArrowUpRight} subtitle="Escalated incidents" loading={statsLoading} accent="text-amber-500" href="/incidents" />
        </div>
        <div className="animate-fade-in delay-500">
          <StatCard title="Resolved" value={stats?.resolvedIncidents ?? 0} icon={CheckCircle2} subtitle="Resolved incidents" loading={statsLoading} accent="text-emerald-500" href="/incidents?status=resolved" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-fade-in delay-300">
        {analyticsLoading ? (
          <>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
          </>
        ) : analytics ? (
          <>
            <SeverityChart data={analytics.severityDistribution} />
            <SourceChart data={analytics.sourceDistribution} />
            <TrendChart data={analytics.alertTrend} />
          </>
        ) : null}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in delay-500">
        {analyticsLoading ? (
          <>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
          </>
        ) : analytics ? (
          <>
            <MitreTacticsWidget data={analytics.topMitreTactics} />
            <CategoryWidget data={analytics.categoryDistribution} />
            <ConnectorHealthWidget data={analytics.connectorHealth} />
            <IngestionRateChart data={analytics.ingestionRate} />
          </>
        ) : null}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-fade-in delay-600">
        <Card className="gradient-card">
          <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
            <CardTitle className="text-sm font-medium">Active Incidents</CardTitle>
            <Link href="/incidents" className="text-xs text-primary hover:underline" data-testid="link-view-all-incidents">View all</Link>
          </CardHeader>
          <CardContent className="space-y-2">
            {incidentsLoading ? (
              Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/30">
                  <Skeleton className="h-10 w-10 rounded-md flex-shrink-0" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              ))
            ) : recentIncidents && recentIncidents.length > 0 ? (
              recentIncidents.slice(0, 5).map((incident) => (
                <Link
                  key={incident.id}
                  href={`/incidents/${incident.id}`}
                  className="flex items-start gap-3 p-3 rounded-md hover-elevate cursor-pointer"
                  data-testid={`card-incident-${incident.id}`}
                >
                  <div className="flex items-center justify-center w-10 h-10 rounded-md bg-muted/50 flex-shrink-0">
                    <FileWarning className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium truncate">{incident.title}</span>
                      <SeverityBadge severity={incident.severity} />
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        {incident.alertCount} alerts
                      </span>
                      {incident.confidence && (
                        <span className="flex items-center gap-1">
                          <TrendingUp className="h-3 w-3" />
                          {Math.round(incident.confidence * 100)}%
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {incident.status}
                      </span>
                    </div>
                  </div>
                </Link>
              ))
            ) : (
              <div className="text-center py-6 text-sm text-muted-foreground">
                No active incidents
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="gradient-card">
          <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
            <CardTitle className="text-sm font-medium">Recent Alerts</CardTitle>
            <Link href="/alerts" className="text-xs text-primary hover:underline" data-testid="link-view-all-alerts">View all</Link>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {alertsLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-2 rounded-md">
                  <Skeleton className="h-8 w-8 rounded-md flex-shrink-0" />
                  <div className="flex-1 space-y-1">
                    <Skeleton className="h-3 w-3/4" />
                    <Skeleton className="h-2 w-1/2" />
                  </div>
                </div>
              ))
            ) : recentAlerts && recentAlerts.length > 0 ? (
              recentAlerts.slice(0, 8).map((alert) => (
                <div
                  key={alert.id}
                  className="flex items-center gap-3 p-2 rounded-md hover-elevate"
                  data-testid={`card-alert-${alert.id}`}
                >
                  <div className="flex items-center justify-center w-8 h-8 rounded-md bg-muted/50 flex-shrink-0">
                    <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{alert.title}</div>
                    <div className="text-[11px] text-muted-foreground truncate">{alert.source}</div>
                  </div>
                  <SeverityBadge severity={alert.severity} />
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-sm text-muted-foreground">
                No alerts yet
              </div>
            )}
          </CardContent>
        </Card>

        <LiveActivityFeed />
      </div>
    </div>
  );
}
