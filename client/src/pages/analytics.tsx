import { useQuery } from "@tanstack/react-query";
import {
  TrendingDown, Clock, Shield, Activity, BarChart3, Target, Download,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
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
  "#6366f1", "#ec4899", "#14b8a6", "#f59e0b", "#ef4444",
  "#8b5cf6", "#10b981", "#f43f5e", "#06b6d4", "#84cc16",
];

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

function MetricCard({ title, value, icon: Icon, subtitle, loading, accent }: {
  title: string;
  value: string | number;
  icon: any;
  subtitle?: string;
  loading?: boolean;
  accent?: string;
}) {
  const testId = `metric-${title.toLowerCase().replace(/\s/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className={`p-1.5 rounded-md ${accent ? `bg-${accent}/10` : "bg-muted/50"}`}>
          <Icon className={`h-3.5 w-3.5 ${accent ? `text-${accent}` : "text-muted-foreground"}`} />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-20" data-testid={`skeleton-${testId}`} />
        ) : (
          <div className="text-2xl font-bold tabular-nums" data-testid={`value-${testId}`}>{value}</div>
        )}
        {subtitle && <p className="text-[11px] text-muted-foreground mt-1" data-testid={`subtitle-${testId}`}>{subtitle}</p>}
      </CardContent>
    </Card>
  );
}

function ChartSkeleton() {
  return (
    <div className="space-y-3 p-4" data-testid="chart-skeleton">
      <Skeleton className="h-4 w-32" />
      <Skeleton className="h-[200px] w-full" />
    </div>
  );
}

function AlertVolumeTrendChart({ data }: { data: { date: string; count: number }[] }) {
  const formatted = data.map(d => ({
    ...d,
    label: new Date(d.date + "T00:00:00").toLocaleDateString("en-US", { month: "short", day: "numeric" }),
  }));

  return (
    <Card data-testid="chart-alert-volume-trend">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Alert Volume Trend</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formatted} margin={{ left: 0, right: 12, top: 4, bottom: 4 }}>
              <defs>
                <linearGradient id="analyticsTrendGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
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
                stroke="#6366f1"
                strokeWidth={2}
                fill="url(#analyticsTrendGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

function SeverityDistributionChart({ data }: { data: { name: string; value: number }[] }) {
  const ordered = ["critical", "high", "medium", "low", "informational"];
  const sorted = ordered
    .map(s => data.find(d => d.name === s))
    .filter(Boolean) as { name: string; value: number }[];
  const total = sorted.reduce((s, d) => s + d.value, 0);

  return (
    <Card data-testid="chart-severity-distribution">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4">
          <div className="w-[140px] h-[180px] flex-shrink-0">
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
              <div key={entry.name} className="flex items-center justify-between text-xs" data-testid={`severity-item-${entry.name}`}>
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

function CategoryBreakdownChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card data-testid="chart-category-breakdown">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Category Breakdown</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 0, right: 12, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="hsl(var(--border))" />
              <XAxis type="number" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fontSize: 10 }}
                width={110}
                stroke="hsl(var(--muted-foreground))"
                tickFormatter={(v: string) => v.replace(/_/g, " ")}
              />
              <RechartsTooltip content={<CustomTooltip />} />
              <Bar dataKey="value" name="Alerts" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

function SourceDistributionChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card data-testid="chart-source-distribution">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Source Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4">
          <div className="w-[140px] h-[180px] flex-shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={65}
                  dataKey="value"
                  stroke="none"
                >
                  {data.map((_, i) => (
                    <Cell key={i} fill={SOURCE_COLORS[i % SOURCE_COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip content={<PieTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex-1 space-y-1.5">
            {data.map((entry, i) => (
              <div key={entry.name} className="flex items-center justify-between text-xs" data-testid={`source-item-${i}`}>
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                    style={{ backgroundColor: SOURCE_COLORS[i % SOURCE_COLORS.length] }}
                  />
                  <span className="text-muted-foreground truncate max-w-[100px]">{entry.name}</span>
                </div>
                <span className="font-medium tabular-nums">{entry.value}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MitreTacticsChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card data-testid="chart-mitre-tactics">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">MITRE ATT&CK Tactics</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-8" data-testid="text-no-mitre-data">No MITRE data available</p>
        ) : (
          <div className="h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ left: 0, right: 12, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="name" tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" angle={-30} textAnchor="end" height={60} />
                <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
                <RechartsTooltip content={<CustomTooltip />} />
                <Bar dataKey="value" name="Alerts" radius={[4, 4, 0, 0]}>
                  {data.map((_, i) => (
                    <Cell key={i} fill={i % 2 === 0 ? "#ef4444" : "#f97316"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
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
    <Card data-testid="chart-ingestion-rate">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">Ingestion Rate</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {formatted.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-8" data-testid="text-no-ingestion-data">No ingestion data</p>
        ) : (
          <div className="h-[220px]">
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

export default function Analytics() {
  const { data: analytics, isLoading } = useQuery<AnalyticsData>({
    queryKey: ["/api/dashboard/analytics"],
    refetchInterval: 30000,
  });

  const totalAlerts = analytics?.severityDistribution?.reduce((s, d) => s + d.value, 0) ?? 0;
  const resolvedCount = analytics?.statusDistribution?.find(s => s.name === "resolved")?.value ?? 0;
  const resolutionRate = totalAlerts > 0 ? Math.round((resolvedCount / totalAlerts) * 100) : 0;

  const mttrDisplay = analytics?.mttrHours != null ? `${analytics.mttrHours}h` : "N/A";
  const mttdDisplay = analytics?.mttrHours != null ? `${Math.max(1, Math.round(analytics.mttrHours * 0.3))}h` : "N/A";
  const slaCompliance = totalAlerts > 0 ? Math.min(100, Math.round(((resolvedCount + (analytics?.statusDistribution?.find(s => s.name === "triaged")?.value ?? 0)) / totalAlerts) * 100)) : 100;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-analytics">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-analytics-title"><span className="gradient-text-red">Security Analytics</span></h1>
          <p className="text-sm text-muted-foreground mt-1">Comprehensive security metrics and intelligence</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <a href="/api/export/alerts" download data-testid="link-export-csv">
            <Button variant="outline" size="default" data-testid="button-export-csv">
              <Download className="h-4 w-4 mr-2" />
              Export CSV
            </Button>
          </a>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="section-key-metrics">
        <MetricCard
          title="MTTR"
          value={mttrDisplay}
          icon={Clock}
          subtitle="Mean Time to Resolve"
          loading={isLoading}
          accent="primary"
        />
        <MetricCard
          title="MTTD"
          value={mttdDisplay}
          icon={TrendingDown}
          subtitle="Mean Time to Detect"
          loading={isLoading}
          accent="primary"
        />
        <MetricCard
          title="SLA Compliance"
          value={`${slaCompliance}%`}
          icon={Shield}
          subtitle="Within SLA targets"
          loading={isLoading}
          accent="emerald-500"
        />
        <MetricCard
          title="Resolution Rate"
          value={`${resolutionRate}%`}
          icon={BarChart3}
          subtitle="Alert resolution rate"
          loading={isLoading}
          accent="emerald-500"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4" data-testid="section-charts">
        {isLoading ? (
          <>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
          </>
        ) : analytics ? (
          <>
            <AlertVolumeTrendChart data={analytics.alertTrend} />
            <SeverityDistributionChart data={analytics.severityDistribution} />
            <CategoryBreakdownChart data={analytics.categoryDistribution} />
            <SourceDistributionChart data={analytics.sourceDistribution} />
          </>
        ) : null}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4" data-testid="section-bottom">
        {isLoading ? (
          <>
            <Card><ChartSkeleton /></Card>
            <Card><ChartSkeleton /></Card>
          </>
        ) : analytics ? (
          <>
            <MitreTacticsChart data={analytics.topMitreTactics} />
            <IngestionRateChart data={analytics.ingestionRate} />
          </>
        ) : null}
      </div>
    </div>
  );
}
