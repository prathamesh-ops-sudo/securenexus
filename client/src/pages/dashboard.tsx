import { useQuery, useMutation } from "@tanstack/react-query";
import { useState, useEffect, useCallback, useMemo } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Shield,
  AlertTriangle,
  FileWarning,
  CheckCircle2,
  Zap,
  ArrowUpRight,
  Target,
  Plug,
  Activity,
  TrendingUp,
  Crosshair,
  RefreshCw,
  Bell,
  Eye,
  EyeOff,
  Timer,
  Gauge,
  Pin,
  LayoutDashboard,
  RotateCcw,
  ArrowDown,
  ArrowUp,
  Minus,
  ExternalLink,
  XCircle,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { GuidedWorkflowBanner } from "@/components/guided-workflow";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area,
} from "recharts";
import { formatChartDateLabel, formatTime } from "@/lib/i18n";

type WidgetId = "severity" | "sources" | "trend" | "mitre" | "categories" | "connectors" | "ingestion" | "whatChanged";

type WidgetConfig = {
  id: WidgetId;
  label: string;
  visible: boolean;
  pinned: boolean;
  order: number;
};

type LayoutPreset = {
  name: string;
  key: string;
  widgets: WidgetId[];
};

const DEFAULT_WIDGETS: WidgetConfig[] = [
  { id: "severity", label: "Severity Distribution", visible: true, pinned: false, order: 0 },
  { id: "sources", label: "Alerts by Source", visible: true, pinned: false, order: 1 },
  { id: "trend", label: "Alert Trend", visible: true, pinned: false, order: 2 },
  { id: "mitre", label: "MITRE Tactics", visible: true, pinned: false, order: 3 },
  { id: "categories", label: "Threat Categories", visible: true, pinned: false, order: 4 },
  { id: "connectors", label: "Connector Health", visible: true, pinned: false, order: 5 },
  { id: "ingestion", label: "Ingestion Rate", visible: true, pinned: false, order: 6 },
  { id: "whatChanged", label: "What Changed (24h)", visible: true, pinned: false, order: 7 },
];

const LAYOUT_PRESETS: LayoutPreset[] = [
  { name: "SOC Analyst", key: "soc", widgets: ["severity", "trend", "mitre", "sources", "whatChanged", "connectors"] },
  {
    name: "Enterprise",
    key: "enterprise",
    widgets: ["severity", "sources", "trend", "categories", "connectors", "ingestion", "whatChanged", "mitre"],
  },
  { name: "Cloud-first", key: "cloud", widgets: ["connectors", "ingestion", "trend", "severity", "whatChanged"] },
];

function loadWidgetConfig(): WidgetConfig[] {
  try {
    const raw = localStorage.getItem("dashboard.widgets.v1");
    if (raw) return JSON.parse(raw);
  } catch (_parseErr) {
    console.warn("Failed to parse dashboard widget config from localStorage", _parseErr);
  }
  return DEFAULT_WIDGETS;
}

function saveWidgetConfig(config: WidgetConfig[]) {
  localStorage.setItem("dashboard.widgets.v1", JSON.stringify(config));
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  informational: "#6b7280",
};

const SOURCE_COLORS = [
  "#0891b2",
  "#2563eb",
  "#059669",
  "#7c3aed",
  "#d97706",
  "#be123c",
  "#0d9488",
  "#e11d48",
  "#c026d3",
  "#65a30d",
];

const TACTIC_COLORS = ["#ea580c", "#2563eb", "#ca8a04", "#7c3aed", "#059669", "#dc2626", "#0891b2", "#db2777"];

function StatCardSkeleton() {
  return (
    <Card data-testid="dashboard-card-1">
      <CardContent className="p-4" role="status" aria-label="Loading statistic">
        <div className="flex items-center justify-between mb-3">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="h-5 w-5 rounded" />
        </div>
        <Skeleton className="h-9 w-16 mb-1" />
        <Skeleton className="h-3 w-16" />
        <span className="sr-only">Loading...</span>
      </CardContent>
    </Card>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  subtitle,
  subtitleColor,
  loading,
  href,
  iconColor,
  badge,
}: {
  title: string;
  value: number | string;
  icon: React.ElementType;
  subtitle?: string;
  subtitleColor?: string;
  loading?: boolean;
  href?: string;
  iconColor?: string;
  badge?: boolean;
}) {
  const content = (
    <Card
      data-testid="dashboard-card-2"
      className={`group relative overflow-hidden border-border/50 hover:border-border/80 transition-[border-color,box-shadow] duration-200 hover:shadow-lg hover:shadow-black/5 ${href ? "cursor-pointer hover:-translate-y-px" : ""}`}
    >
      <CardContent className="p-4 relative">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-medium text-muted-foreground tracking-wide">{title}</span>
          <div className="relative">
            <div
              className={`flex items-center justify-center w-8 h-8 rounded-lg ${iconColor === "text-red-500" ? "bg-red-500/8" : iconColor === "text-amber-500" ? "bg-amber-500/8" : iconColor === "text-orange-500" ? "bg-orange-500/8" : iconColor === "text-cyan-500" ? "bg-cyan-500/8" : iconColor === "text-indigo-500" ? "bg-indigo-500/8" : iconColor === "text-emerald-500" ? "bg-emerald-500/8" : "bg-muted/15"} group-hover:scale-105 transition-transform duration-200`}
            >
              <Icon className={`h-5 w-5 ${iconColor || "text-muted-foreground"}`} aria-hidden="true" />
            </div>
            {badge && (
              <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2 items-center justify-center rounded-full bg-red-500 ring-2 ring-card animate-pulse" />
            )}
          </div>
        </div>
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-8 w-24" />
            <Skeleton className="h-3 w-32" />
          </div>
        ) : (
          <div className="text-2xl font-semibold tabular-nums tracking-tight font-mono">{value}</div>
        )}
        {subtitle && (
          <p className={`text-[11px] mt-1.5 font-medium ${subtitleColor || "text-muted-foreground/60"}`}>{subtitle}</p>
        )}
      </CardContent>
    </Card>
  );

  if (href) {
    return <Link href={href}>{content}</Link>;
  }
  return content;
}

function ChartSkeleton() {
  return (
    <div data-testid="dashboard-page" className="space-y-3 p-4" role="status" aria-label="Loading chart">
      <Skeleton className="h-4 w-32" />
      <Skeleton className="h-[180px] w-full" />
      <span className="sr-only">Loading chart...</span>
    </div>
  );
}

function clampNumber(value: number, minValue: number, maxValue: number) {
  return Math.min(maxValue, Math.max(minValue, value));
}

function SecurityScorePill({ score }: { score: number }) {
  const color =
    score >= 90 ? "text-emerald-400" : score >= 70 ? "text-cyan-400" : score >= 50 ? "text-amber-400" : "text-red-400";
  const stroke = score >= 90 ? "#34d399" : score >= 70 ? "#22d3ee" : score >= 50 ? "#fbbf24" : "#ef4444";
  const radius = 14;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-border bg-muted/30">
      <div className="relative h-10 w-10">
        <svg className="h-10 w-10 -rotate-90" viewBox="0 0 40 40" aria-hidden="true">
          <circle cx="20" cy="20" r={radius} stroke="rgba(148,163,184,0.18)" strokeWidth="5" fill="none" />
          <circle
            cx="20"
            cy="20"
            r={radius}
            stroke={stroke}
            strokeWidth="5"
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 650ms ease-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-[11px] font-bold tabular-nums ${color}`}>{score}</span>
        </div>
      </div>
      <div className="leading-tight">
        <div className="text-[10px] font-medium text-muted-foreground tracking-wider">Security score</div>
        <div className={`text-[11px] font-semibold ${color}`}>
          {score >= 90 ? "Excellent" : score >= 70 ? "Good" : score >= 50 ? "At risk" : "Critical"}
        </div>
      </div>
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
  connectorHealth: {
    name: string;
    type: string;
    status: string;
    lastSyncAt: string | null;
    lastSyncAlerts: number;
    lastSyncError: string | null;
  }[];
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
  const sorted = ordered.map((s) => data.find((d) => d.name === s)).filter(Boolean) as {
    name: string;
    value: number;
  }[];
  const total = sorted.reduce((s, d) => s + d.value, 0);

  return (
    <Card data-testid="dashboard-card-3" className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <CardTitle className="text-sm font-semibold tracking-tight">Severity Distribution</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {sorted.length === 0 ? (
          <div
            className="flex items-center justify-center h-[200px] text-sm text-muted-foreground"
            role="status"
            aria-label="No severity data"
          >
            <div className="text-center">
              <AlertTriangle className="h-6 w-6 mx-auto mb-2 opacity-50" aria-hidden="true" />
              <span>No severity data available</span>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-6">
            <div className="w-[150px] h-[150px] flex-shrink-0 relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sorted} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" stroke="none">
                    {sorted.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#6b7280"} />
                    ))}
                  </Pie>
                  <RechartsTooltip content={<PieTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-2xl font-bold tabular-nums">{total}</span>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Total</span>
              </div>
            </div>
            <div className="flex-1 space-y-2">
              {sorted.map((entry) => (
                <div key={entry.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                      style={{ backgroundColor: SEVERITY_COLORS[entry.name] || "#6b7280" }}
                    />
                    <span className="capitalize">{entry.name}</span>
                  </div>
                  <span className="font-semibold tabular-nums">
                    {entry.value}{" "}
                    <span className="text-muted-foreground font-normal">
                      ({total > 0 ? Math.round((entry.value / total) * 100) : 0}%)
                    </span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SourceChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <CardTitle className="text-sm font-semibold tracking-tight">Alerts by Source</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <div
            className="flex items-center justify-center h-[200px] text-sm text-muted-foreground"
            role="status"
            aria-label="No source data"
          >
            <div className="text-center">
              <Activity className="h-6 w-6 mx-auto mb-2 opacity-50" aria-hidden="true" />
              <span>No source data available</span>
            </div>
          </div>
        ) : (
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} layout="vertical" margin={{ left: 0, right: 12, top: 4, bottom: 4 }}>
                <defs>
                  {SOURCE_COLORS.map((color, i) => (
                    <linearGradient key={i} id={`barGrad${i}`} x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor={color} stopOpacity={0.85} />
                      <stop offset="100%" stopColor={color} stopOpacity={1} />
                    </linearGradient>
                  ))}
                </defs>
                <XAxis
                  type="number"
                  tick={{ fontSize: 10 }}
                  stroke="hsl(var(--muted-foreground))"
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fontSize: 11 }}
                  width={100}
                  stroke="hsl(var(--muted-foreground))"
                  axisLine={false}
                  tickLine={false}
                />
                <RechartsTooltip content={<CustomTooltip />} />
                <Bar dataKey="value" name="Alerts" radius={[0, 4, 4, 0]} barSize={16}>
                  {data.map((_, i) => (
                    <Cell key={i} fill={`url(#barGrad${i % SOURCE_COLORS.length})`} />
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

function TrendChart({ data }: { data: { date: string; count: number }[] }) {
  const formatted = data.map((d) => ({
    ...d,
    label: formatChartDateLabel(d.date),
  }));

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <CardTitle className="text-sm font-semibold tracking-tight">Alert Trend (7 Days)</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {formatted.length === 0 ? (
          <div
            className="flex items-center justify-center h-[200px] text-sm text-muted-foreground"
            role="status"
            aria-label="No trend data"
          >
            <div className="text-center">
              <TrendingUp className="h-6 w-6 mx-auto mb-2 opacity-50" aria-hidden="true" />
              <span>No trend data available</span>
            </div>
          </div>
        ) : (
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={formatted} margin={{ left: -10, right: 12, top: 4, bottom: 4 }}>
                <defs>
                  <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.45} />
                    <stop offset="50%" stopColor="#818cf8" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#818cf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 10 }}
                  stroke="hsl(var(--muted-foreground))"
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 10 }}
                  stroke="hsl(var(--muted-foreground))"
                  allowDecimals={false}
                  axisLine={false}
                  tickLine={false}
                />
                <RechartsTooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="count"
                  name="Alerts"
                  stroke="#818cf8"
                  strokeWidth={2.5}
                  fill="url(#trendGradient)"
                  dot={{ r: 3, fill: "#a78bfa", strokeWidth: 2, stroke: "#818cf8" }}
                  activeDot={{ r: 6, fill: "#a78bfa", strokeWidth: 2, stroke: "#fff" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MitreTacticsWidget({ data }: { data: { name: string; value: number }[] }) {
  const maxVal = Math.max(...data.map((d) => d.value), 1);
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-semibold tracking-tight">Top MITRE Tactics</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <div
            className="flex items-center justify-center h-[160px] text-sm text-muted-foreground"
            role="status"
            aria-label="No MITRE data"
          >
            <div className="text-center">
              <Crosshair className="h-6 w-6 mx-auto mb-2 opacity-50" aria-hidden="true" />
              <span>No MITRE data available</span>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {data.slice(0, 5).map((item, idx) => (
              <div key={item.name} className="flex items-center gap-3">
                <span className="text-xs min-w-0 flex-1 truncate">{item.name}</span>
                <div className="w-24 h-2 bg-muted rounded-full overflow-hidden flex-shrink-0">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${(item.value / maxVal) * 100}%`,
                      backgroundColor: TACTIC_COLORS[idx % TACTIC_COLORS.length],
                    }}
                  />
                </div>
                <Badge variant="secondary" className="text-[10px] tabular-nums h-5 min-w-[24px] justify-center px-1.5">
                  {item.value}
                </Badge>
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
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-semibold tracking-tight">Threat Categories</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-[160px] text-sm text-muted-foreground">
            No category data available
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {data.map((item) => (
              <Badge
                key={item.name}
                variant="outline"
                className="text-[11px] px-2.5 py-1 border-border/60 bg-muted/30 hover:bg-muted/50 transition-colors"
              >
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
  const statusConfig: Record<string, { color: string; dotColor: string }> = {
    active: { color: "text-emerald-400", dotColor: "bg-emerald-500" },
    inactive: { color: "text-gray-400", dotColor: "bg-gray-400" },
    error: { color: "text-red-400", dotColor: "bg-red-500" },
    degraded: { color: "text-amber-400", dotColor: "bg-amber-500" },
    syncing: { color: "text-blue-400", dotColor: "bg-blue-500" },
  };

  function formatSyncTime(lastSyncAt: string | null): string {
    if (!lastSyncAt) return "-";
    const diff = Date.now() - new Date(lastSyncAt).getTime();
    const seconds = Math.floor(diff / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h`;
  }

  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between gap-1 pb-2">
        <div className="flex items-center gap-2">
          <Plug className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-semibold tracking-tight">Connector Health</CardTitle>
        </div>
        <Link href="/connectors" className="text-xs text-primary hover:underline font-medium">
          Manage
        </Link>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-[160px] text-sm text-muted-foreground">
            No connectors configured
          </div>
        ) : (
          <div className="space-y-3">
            {data.slice(0, 5).map((c) => {
              const cfg = statusConfig[c.status] || statusConfig.inactive;
              return (
                <div key={c.name} className="flex items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dotColor}`} />
                    <span className="truncate font-medium">{c.name}</span>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className={`capitalize font-medium ${cfg.color}`}>{c.status}</span>
                    <span className="text-muted-foreground tabular-nums">{formatSyncTime(c.lastSyncAt)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function IngestionRateChart({ data }: { data: AnalyticsData["ingestionRate"] }) {
  const formatted = data.map((d) => ({
    ...d,
    total: d.created + d.deduped + d.failed,
    label: formatChartDateLabel(d.date),
  }));

  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between gap-1 pb-2">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-semibold tracking-tight">Ingestion Rate</CardTitle>
        </div>
        <Link href="/ingestion" className="text-xs text-primary hover:underline font-medium">
          Details
        </Link>
      </CardHeader>
      <CardContent>
        {formatted.length === 0 ? (
          <div className="flex items-center justify-center h-[160px] text-sm text-muted-foreground">
            No ingestion data available
          </div>
        ) : (
          <div className="h-[160px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={formatted} margin={{ left: -10, right: 4, top: 4, bottom: 4 }}>
                <defs>
                  <linearGradient id="ingestionGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#a855f7" stopOpacity={0.4} />
                    <stop offset="50%" stopColor="#818cf8" stopOpacity={0.15} />
                    <stop offset="100%" stopColor="#818cf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 9 }}
                  stroke="hsl(var(--muted-foreground))"
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 9 }}
                  stroke="hsl(var(--muted-foreground))"
                  allowDecimals={false}
                  axisLine={false}
                  tickLine={false}
                />
                <RechartsTooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="total"
                  name="Events"
                  stroke="#a855f7"
                  strokeWidth={2.5}
                  fill="url(#ingestionGradient)"
                  dot={{ r: 2, fill: "#c084fc", strokeWidth: 0 }}
                  activeDot={{ r: 5, fill: "#c084fc", strokeWidth: 2, stroke: "#fff" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AnomalyBanners({
  stats,
}: {
  stats:
    | {
        totalAlerts: number;
        openIncidents: number;
        criticalAlerts: number;
        resolvedIncidents: number;
        newAlertsToday: number;
        escalatedIncidents: number;
      }
    | undefined;
}) {
  const banners: { message: string; severity: "critical" | "warning" | "info"; href: string }[] = [];
  if ((stats?.criticalAlerts ?? 0) >= 5) {
    banners.push({
      message: `${stats?.criticalAlerts} critical alerts detected — immediate triage recommended`,
      severity: "critical",
      href: "/alerts?severity=critical",
    });
  }
  if ((stats?.escalatedIncidents ?? 0) >= 3) {
    banners.push({
      message: `${stats?.escalatedIncidents} incidents escalated to Tier 2 — review queue`,
      severity: "warning",
      href: "/incidents",
    });
  }
  if ((stats?.newAlertsToday ?? 0) > 50) {
    banners.push({
      message: `Unusual spike: ${stats?.newAlertsToday} new alerts today (above normal baseline)`,
      severity: "warning",
      href: "/alerts",
    });
  }
  if ((stats?.openIncidents ?? 0) >= 10) {
    banners.push({
      message: `${stats?.openIncidents} open incidents — consider prioritizing resolution`,
      severity: "info",
      href: "/incidents?status=open",
    });
  }
  if (banners.length === 0) return null;
  const severityStyles = {
    critical: "bg-red-500/10 border-red-500/30 text-red-400",
    warning: "bg-amber-500/10 border-amber-500/30 text-amber-400",
    info: "bg-blue-500/10 border-blue-500/30 text-blue-400",
  };
  return (
    <div className="space-y-2">
      {banners.map((b, i) => (
        <Link key={i} href={b.href}>
          <div
            className={`flex items-center gap-3 px-4 py-2.5 rounded-lg border cursor-pointer hover:opacity-90 transition-opacity ${severityStyles[b.severity]}`}
          >
            <AlertTriangle className="h-4 w-4 flex-shrink-0" />
            <span className="text-xs font-medium flex-1">{b.message}</span>
            <ExternalLink className="h-3.5 w-3.5 flex-shrink-0 opacity-60" />
          </div>
        </Link>
      ))}
    </div>
  );
}

function WhatChangedWidget({
  stats,
}: {
  stats:
    | {
        totalAlerts: number;
        openIncidents: number;
        criticalAlerts: number;
        resolvedIncidents: number;
        newAlertsToday: number;
        escalatedIncidents: number;
      }
    | undefined;
}) {
  const metrics = useMemo(() => {
    if (!stats) return [];
    return [
      { label: "New Alerts Today", value: stats.newAlertsToday, baseline: 20, href: "/alerts" },
      { label: "Critical Alerts", value: stats.criticalAlerts, baseline: 2, href: "/alerts?severity=critical" },
      { label: "Open Incidents", value: stats.openIncidents, baseline: 5, href: "/incidents?status=open" },
      { label: "Resolved (24h)", value: stats.resolvedIncidents, baseline: 3, href: "/incidents?status=resolved" },
      { label: "Escalated", value: stats.escalatedIncidents, baseline: 1, href: "/incidents" },
    ];
  }, [stats]);

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-semibold tracking-tight">What Changed (Last 24h)</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {!stats ? (
          <div className="flex items-center justify-center h-[160px] text-sm text-muted-foreground">
            No data available
          </div>
        ) : (
          <div className="space-y-3">
            {metrics.map((m) => {
              const delta = m.value - m.baseline;
              const pct = m.baseline > 0 ? Math.round((delta / m.baseline) * 100) : 0;
              const isUp = delta > 0;
              const isDown = delta < 0;
              return (
                <Link key={m.label} href={m.href}>
                  <div className="flex items-center justify-between py-1.5 hover:bg-muted/30 rounded px-2 -mx-2 transition-colors cursor-pointer">
                    <span className="text-xs">{m.label}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold tabular-nums">{m.value}</span>
                      <div
                        className={`flex items-center gap-0.5 text-[10px] font-medium ${isUp ? "text-red-400" : isDown ? "text-emerald-400" : "text-muted-foreground"}`}
                      >
                        {isUp ? (
                          <ArrowUp className="h-3 w-3" />
                        ) : isDown ? (
                          <ArrowDown className="h-3 w-3" />
                        ) : (
                          <Minus className="h-3 w-3" />
                        )}
                        <span>{Math.abs(pct)}%</span>
                      </div>
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function WidgetCustomizer({
  widgets,
  onToggle,
  onPin,
  onApplyPreset,
  onReset,
}: {
  widgets: WidgetConfig[];
  onToggle: (id: WidgetId) => void;
  onPin: (id: WidgetId) => void;
  onApplyPreset: (preset: LayoutPreset) => void;
  onReset: () => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Presets:</span>
        {LAYOUT_PRESETS.map((p) => (
          <Button
            data-testid="dashboard-btn-outline-0"
            key={p.key}
            size="sm"
            variant="outline"
            className="text-[10px] h-6 px-2"
            onClick={() => onApplyPreset(p)}
          >
            <LayoutDashboard className="h-3 w-3 mr-1" />
            {p.name}
          </Button>
        ))}
        <Button
          data-testid="dashboard-btn-ghost-1"
          size="sm"
          variant="ghost"
          className="text-[10px] h-6 px-2"
          onClick={onReset}
        >
          <RotateCcw className="h-3 w-3 mr-1" />
          Reset
        </Button>
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Widgets:</span>
        {widgets
          .sort((a, b) => a.order - b.order)
          .map((w) => (
            <div key={w.id} className="flex items-center gap-1">
              <Button
                data-testid="dashboard-btn-2"
                size="sm"
                variant={w.visible ? "secondary" : "outline"}
                className={`text-[10px] h-6 px-2 ${!w.visible ? "opacity-50" : ""}`}
                onClick={() => onToggle(w.id)}
              >
                {w.visible ? <Eye className="h-3 w-3 mr-1" /> : <EyeOff className="h-3 w-3 mr-1" />}
                {w.label}
              </Button>
              <Button
                data-testid="dashboard-btn-ghost-3"
                size="sm"
                variant="ghost"
                className={`h-6 w-6 p-0 ${w.pinned ? "text-amber-400" : "text-muted-foreground/40"}`}
                onClick={() => onPin(w.id)}
                title={w.pinned ? "Unpin" : "Pin to top"}
              >
                <Pin className="h-3 w-3" />
              </Button>
            </div>
          ))}
      </div>
    </div>
  );
}

interface CircuitAlert {
  id: string;
  title: string;
  description: string;
  severity: string;
  created_at: string;
}

function DeceptionHitsWidget() {
  const { data: hitsData } = useQuery<{
    hits: Array<{
      id: string;
      sourceIp: string;
      sourceType: string;
      sourceName: string;
      severity: string;
      hitAt: string;
    }>;
  }>({
    queryKey: ["/api/deception/hits"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/deception/hits");
      return res.json();
    },
    refetchInterval: 60000,
  });

  // Filter to last 24h client-side
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const allHits = hitsData?.hits ?? [];
  const recentHits = allHits.filter((h) => new Date(h.hitAt).getTime() >= cutoff);
  const total = recentHits.length;
  const recent = recentHits.slice(0, 5);

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Target className="h-4 w-4 text-red-400" />
          Deception Hits (24h)
          {total > 0 && (
            <Badge variant="destructive" className="ml-auto text-[10px] px-1.5 py-0">
              {total}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        {recent.length === 0 ? (
          <p className="text-xs text-muted-foreground py-4 text-center">No deception hits in the last 24 hours</p>
        ) : (
          <div className="space-y-2">
            {recent.map((hit) => (
              <div key={hit.id} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${hit.severity === "critical" ? "bg-red-500" : hit.severity === "high" ? "bg-orange-500" : "bg-yellow-500"}`}
                  />
                  <span className="text-muted-foreground">{hit.sourceIp}</span>
                </div>
                <span className="text-muted-foreground">{hit.sourceType}</span>
              </div>
            ))}
            {total > 5 && (
              <Link href="/deception" className="text-xs text-blue-400 hover:underline block text-center pt-1">
                View all {total} hits
              </Link>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AICircuitBreakerBanner() {
  const { data: circuitAlerts } = useQuery<CircuitAlert[]>({
    queryKey: ["/api/ai/circuit-alerts"],
    refetchInterval: 60000,
  });

  const dismiss = useMutation({
    mutationFn: async (alertId: string) => {
      await apiRequest("PATCH", `/api/ai/circuit-alerts/${alertId}/dismiss`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ai/circuit-alerts"] });
    },
  });

  if (!circuitAlerts || circuitAlerts.length === 0) return null;

  const newest = circuitAlerts[0];
  const minutesAgo = Math.max(1, Math.round((Date.now() - new Date(newest.created_at).getTime()) / 60000));

  return (
    <div
      className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 flex items-center justify-between gap-3"
      data-testid="circuit-breaker-banner"
    >
      <div className="flex items-center gap-2 min-w-0">
        <XCircle className="h-4 w-4 text-red-500 shrink-0" aria-hidden="true" />
        <p className="text-xs text-red-700 dark:text-red-300 truncate">
          AI inference failures detected {minutesAgo} min ago ({circuitAlerts.length} alert
          {circuitAlerts.length > 1 ? "s" : ""}).{" "}
          <Link href="/ai-engine" className="underline font-medium">
            Check status
          </Link>
        </p>
      </div>
      <Button
        size="sm"
        variant="ghost"
        className="h-6 w-6 p-0 shrink-0"
        onClick={() => dismiss.mutate(circuitAlerts[0].id)}
        aria-label="Dismiss banner"
      >
        <X className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

export default function Dashboard() {
  usePageTitle("Security Dashboard — SecureNexus Agentic SOC", true);
  const { user } = useAuth();
  const [timeRange, setTimeRange] = useState<"24h" | "live">("24h");
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showCustomizer, setShowCustomizer] = useState(false);
  const [widgetConfig, setWidgetConfig] = useState<WidgetConfig[]>(loadWidgetConfig);

  const greeting = useMemo(() => {
    const hour = new Date().getHours();
    if (hour < 12) return "Good morning";
    if (hour < 18) return "Good afternoon";
    return "Good evening";
  }, []);

  const {
    data: stats,
    isLoading: statsLoading,
    isError: statsError,
    dataUpdatedAt: statsUpdatedAt,
    refetch: refetchStats,
  } = useQuery<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }>({
    queryKey: ["/api/dashboard/stats"],
    refetchInterval: timeRange === "live" ? 5000 : 30000,
  });

  const {
    data: analytics,
    isLoading: analyticsLoading,
    isError: analyticsError,
    dataUpdatedAt: analyticsUpdatedAt,
    refetch: refetchAnalytics,
  } = useQuery<AnalyticsData>({
    queryKey: ["/api/dashboard/analytics"],
    refetchInterval: timeRange === "live" ? 5000 : 30000,
  });

  const { data: opMetrics, refetch: refetchOpMetrics } = useQuery<{
    mttrHours: number | null;
    mttdMinutes: number | null;
    alertsProcessed24h: number;
    alertsResolved24h: number;
    resolutionRate: number | null;
    mttrTrend: { date: string; avgValue: number; sampleCount: number }[];
  }>({
    queryKey: ["/api/dashboard/operational-metrics"],
    refetchInterval: timeRange === "live" ? 10000 : 60000,
  });

  useEffect(() => {
    const latest = Math.max(statsUpdatedAt || 0, analyticsUpdatedAt || 0);
    if (latest > 0) {
      setLastUpdated(new Date(latest));
    }
  }, [statsUpdatedAt, analyticsUpdatedAt]);

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true);
    await Promise.all([refetchStats(), refetchAnalytics(), refetchOpMetrics()]);
    setLastUpdated(new Date());
    setTimeout(() => setIsRefreshing(false), 600);
  }, [refetchStats, refetchAnalytics, refetchOpMetrics]);

  const toggleWidget = useCallback((id: WidgetId) => {
    setWidgetConfig((prev) => {
      const updated = prev.map((w) => (w.id === id ? { ...w, visible: !w.visible } : w));
      saveWidgetConfig(updated);
      return updated;
    });
  }, []);

  const pinWidget = useCallback((id: WidgetId) => {
    setWidgetConfig((prev) => {
      const updated = prev.map((w) => (w.id === id ? { ...w, pinned: !w.pinned } : w));
      saveWidgetConfig(updated);
      return updated;
    });
  }, []);

  const applyPreset = useCallback((preset: LayoutPreset) => {
    setWidgetConfig((prev) => {
      const updated = prev.map((w) => ({
        ...w,
        visible: preset.widgets.includes(w.id),
        order: preset.widgets.indexOf(w.id) >= 0 ? preset.widgets.indexOf(w.id) : w.order + 100,
      }));
      saveWidgetConfig(updated);
      return updated;
    });
  }, []);

  const resetWidgets = useCallback(() => {
    setWidgetConfig(DEFAULT_WIDGETS);
    saveWidgetConfig(DEFAULT_WIDGETS);
  }, []);

  const isWidgetVisible = useCallback(
    (id: WidgetId) => {
      return widgetConfig.find((w) => w.id === id)?.visible ?? true;
    },
    [widgetConfig],
  );

  // Contextual widget awareness: auto-hide widgets that have no data
  const widgetHasData = useCallback(
    (id: WidgetId): boolean => {
      if (!analytics) return true; // still loading, assume visible
      switch (id) {
        case "severity":
          return (analytics.severityDistribution ?? []).some((d) => d.value > 0);
        case "sources":
          return (analytics.sourceDistribution ?? []).length > 0;
        case "trend":
          return (analytics.alertTrend ?? []).some((d) => d.count > 0);
        case "mitre":
          return (analytics.topMitreTactics ?? []).length > 0;
        case "categories":
          return (analytics.categoryDistribution ?? []).length > 0;
        case "connectors":
          return (analytics.connectorHealth ?? []).length > 0;
        case "ingestion":
          return (analytics.ingestionRate ?? []).some((d) => d.created > 0 || d.deduped > 0);
        case "whatChanged":
          return true; // always relevant
        default:
          return true;
      }
    },
    [analytics],
  );

  const visibleChartWidgets = useMemo(() => {
    const chartIds: WidgetId[] = ["severity", "sources", "trend"];
    return chartIds.filter((id) => isWidgetVisible(id) && widgetHasData(id));
  }, [isWidgetVisible, widgetHasData]);

  const visibleBottomWidgets = useMemo(() => {
    const bottomIds: WidgetId[] = ["mitre", "categories", "connectors", "ingestion", "whatChanged"];
    return bottomIds.filter((id) => isWidgetVisible(id) && widgetHasData(id));
  }, [isWidgetVisible, widgetHasData]);

  const securityScore = useMemo(() => {
    if (!stats) return null;

    const criticalPenalty = Math.min(stats.criticalAlerts, 6) * 5;
    const incidentPenalty = Math.min(stats.openIncidents, 5) * 3;
    const recovery = Math.min(stats.resolvedIncidents, 5) * 2;

    return clampNumber(100 - criticalPenalty - incidentPenalty + recovery, 0, 100);
  }, [stats]);

  const showSecurityScore = securityScore !== null && !statsLoading && !statsError;

  return (
    <div className="flex flex-col min-h-[calc(100vh-2rem)]" aria-label="Security Operations Dashboard">
      <div className="flex-1 p-4 md:p-6 space-y-5 max-w-[1440px] mx-auto w-full">
        <AnomalyBanners stats={stats} />
        <AICircuitBreakerBanner />
        <DeceptionHitsWidget />
        <GuidedWorkflowBanner />

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-lg md:text-xl font-semibold tracking-tight font-display">
              {greeting}
              {user?.firstName ? `, ${user.firstName}` : ""}
            </h1>
            <p className="text-xs text-muted-foreground/60 mt-0.5">
              Your brief for {timeRange === "live" ? "right now" : "the last 24 hours"} · Updated{" "}
              {formatTime(lastUpdated)}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {showSecurityScore && <SecurityScorePill score={securityScore} />}
            <div className="flex items-center rounded-lg border border-border bg-muted/30 p-0.5">
              <Button
                data-testid="dashboard-btn-4"
                size="sm"
                variant={timeRange === "24h" ? "secondary" : "ghost"}
                className={`h-7 px-3 text-xs font-medium rounded-md transition-all duration-200 ${timeRange === "24h" ? "shadow-sm" : "hover:bg-muted/50"}`}
                onClick={() => {
                  setTimeRange("24h");
                  handleRefresh();
                }}
              >
                Last 24h
              </Button>
              <Button
                size="sm"
                variant={timeRange === "live" ? "secondary" : "ghost"}
                className={`h-7 px-3 text-xs font-medium rounded-md transition-all duration-200 ${timeRange === "live" ? "shadow-sm" : "hover:bg-muted/50"}`}
                onClick={() => {
                  setTimeRange("live");
                  handleRefresh();
                }}
              >
                <span className={`${timeRange === "live" ? "flex items-center gap-1.5" : ""}`}>
                  {timeRange === "live" && (
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                    </span>
                  )}
                  Live
                </span>
              </Button>
            </div>
            <Button
              size="icon"
              variant="ghost"
              className="h-8 w-8 hover:bg-muted/60 active:scale-95 transition-all duration-150"
              onClick={handleRefresh}
              aria-label="Refresh dashboard data"
              title="Refresh data"
            >
              <RefreshCw
                className={`h-4 w-4 transition-transform duration-500 ${isRefreshing ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
            </Button>
            <Button
              size="icon"
              variant={showCustomizer ? "secondary" : "ghost"}
              className="h-8 w-8 hover:bg-muted/60 active:scale-95 transition-all duration-150"
              onClick={() => setShowCustomizer(!showCustomizer)}
              aria-label="Customize dashboard widgets"
              aria-expanded={showCustomizer}
              title="Customize dashboard"
            >
              <LayoutDashboard className="h-4 w-4" aria-hidden="true" />
            </Button>
            <div className="relative">
              <Button
                size="icon"
                variant="ghost"
                className="h-8 w-8 hover:bg-muted/60 active:scale-95 transition-all duration-150"
                onClick={() => setShowNotifications(!showNotifications)}
                aria-label="Toggle notifications panel"
                aria-expanded={showNotifications}
                title="Notifications"
              >
                <Bell className="h-4 w-4" aria-hidden="true" />
                {(stats?.criticalAlerts ?? 0) > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-red-500 text-[8px] font-bold text-white animate-subtle-ping">
                    {stats?.criticalAlerts}
                  </span>
                )}
              </Button>
              {showNotifications && (
                <div className="absolute right-0 top-10 w-72 bg-popover border border-border rounded-lg shadow-xl z-50 overflow-hidden">
                  <div className="px-3 py-2 border-b border-border bg-muted/30">
                    <span className="text-xs font-semibold">Notifications</span>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    {(stats?.criticalAlerts ?? 0) > 0 ? (
                      <Link href="/alerts?severity=critical" onClick={() => setShowNotifications(false)}>
                        <div className="px-3 py-2.5 hover:bg-muted/50 transition-colors cursor-pointer border-b border-border/50">
                          <div className="flex items-center gap-2">
                            <span className="flex h-2 w-2 rounded-full bg-red-500" />
                            <span className="text-xs font-medium">
                              {stats?.criticalAlerts} critical alert{(stats?.criticalAlerts ?? 0) > 1 ? "s" : ""} need
                              attention
                            </span>
                          </div>
                          <p className="text-[10px] text-muted-foreground mt-1 ml-4">Click to view critical alerts</p>
                        </div>
                      </Link>
                    ) : null}
                    {(stats?.openIncidents ?? 0) > 0 ? (
                      <Link href="/incidents?status=open" onClick={() => setShowNotifications(false)}>
                        <div className="px-3 py-2.5 hover:bg-muted/50 transition-colors cursor-pointer border-b border-border/50">
                          <div className="flex items-center gap-2">
                            <span className="flex h-2 w-2 rounded-full bg-orange-500" />
                            <span className="text-xs font-medium">
                              {stats?.openIncidents} open incident{(stats?.openIncidents ?? 0) > 1 ? "s" : ""}
                            </span>
                          </div>
                          <p className="text-[10px] text-muted-foreground mt-1 ml-4">Click to investigate</p>
                        </div>
                      </Link>
                    ) : null}
                    {(stats?.escalatedIncidents ?? 0) > 0 ? (
                      <Link href="/incidents" onClick={() => setShowNotifications(false)}>
                        <div className="px-3 py-2.5 hover:bg-muted/50 transition-colors cursor-pointer">
                          <div className="flex items-center gap-2">
                            <span className="flex h-2 w-2 rounded-full bg-amber-500" />
                            <span className="text-xs font-medium">
                              {stats?.escalatedIncidents} escalated for Tier 2
                            </span>
                          </div>
                          <p className="text-[10px] text-muted-foreground mt-1 ml-4">Click to review</p>
                        </div>
                      </Link>
                    ) : null}
                    {!stats?.criticalAlerts && !stats?.openIncidents && !stats?.escalatedIncidents && (
                      <div className="px-3 py-6 text-center">
                        <CheckCircle2 className="h-5 w-5 mx-auto text-emerald-500 mb-1.5" />
                        <p className="text-xs text-muted-foreground">All clear — no new notifications</p>
                      </div>
                    )}
                  </div>
                  <div className="px-3 py-2 border-t border-border bg-muted/20 text-center">
                    <span className="text-[10px] text-muted-foreground">Updated {formatTime(lastUpdated)}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {showCustomizer && (
          <Card>
            <CardContent className="p-4">
              <WidgetCustomizer
                widgets={widgetConfig}
                onToggle={toggleWidget}
                onPin={pinWidget}
                onApplyPreset={applyPreset}
                onReset={resetWidgets}
              />
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* Stat cards row - tighter grouping */}
          {statsLoading ? (
            Array.from({ length: 6 }).map((_, i) => <StatCardSkeleton key={i} />)
          ) : statsError ? (
            <Card className="col-span-full">
              <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
                <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
                  <AlertTriangle className="h-6 w-6 text-destructive" />
                </div>
                <p className="text-sm font-medium">Failed to load dashboard stats</p>
                <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchStats()}>
                  Try Again
                </Button>
              </div>
            </Card>
          ) : (
            <>
              <StatCard
                title="Total Alerts"
                value={stats?.totalAlerts ?? 0}
                icon={AlertTriangle}
                subtitle="All sources"
                iconColor="text-amber-500"
                href="/alerts"
              />
              <StatCard
                title="Critical"
                value={stats?.criticalAlerts ?? 0}
                icon={Shield}
                subtitle={stats?.criticalAlerts ? "Action Required" : "All clear"}
                subtitleColor={stats?.criticalAlerts ? "text-orange-400" : "text-emerald-400"}
                iconColor="text-red-500"
                badge={(stats?.criticalAlerts ?? 0) > 0}
                href="/alerts?severity=critical"
              />
              <StatCard
                title="Open Incidents"
                value={stats?.openIncidents ?? 0}
                icon={FileWarning}
                subtitle={stats?.openIncidents ? "Investigating" : "None open"}
                subtitleColor={stats?.openIncidents ? "text-orange-400" : "text-emerald-400"}
                iconColor="text-orange-500"
                badge={(stats?.openIncidents ?? 0) > 0}
                href="/incidents?status=open"
              />
              <StatCard
                title="New Today"
                value={stats?.newAlertsToday ?? 0}
                icon={Zap}
                subtitle="+0 from avg"
                subtitleColor="text-cyan-400"
                iconColor="text-cyan-500"
                href="/alerts"
              />
              <StatCard
                title="Escalated"
                value={stats?.escalatedIncidents ?? 0}
                icon={ArrowUpRight}
                subtitle={stats?.escalatedIncidents ? "Tier 2 review" : "None pending"}
                subtitleColor={stats?.escalatedIncidents ? "text-amber-400" : "text-muted-foreground"}
                iconColor="text-indigo-500"
                href="/incidents"
              />
              <StatCard
                title="Resolved"
                value={stats?.resolvedIncidents ?? 0}
                icon={CheckCircle2}
                subtitle="Last 24h"
                iconColor="text-emerald-500"
                href="/incidents?status=resolved"
              />
            </>
          )}
        </div>

        {/* Operational Metrics Row: MTTD, MTTR, Resolution Rate */}
        {opMetrics && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard
              title="MTTD"
              value={opMetrics.mttdMinutes != null ? `${opMetrics.mttdMinutes}m` : "—"}
              icon={Timer}
              subtitle="Mean Time to Detect (30d)"
              iconColor="text-cyan-500"
            />
            <StatCard
              title="MTTR"
              value={opMetrics.mttrHours != null ? `${opMetrics.mttrHours}h` : "—"}
              icon={Target}
              subtitle="Mean Time to Resolve (30d)"
              iconColor="text-orange-500"
            />
            <StatCard
              title="Resolution Rate"
              value={opMetrics.resolutionRate != null ? `${opMetrics.resolutionRate}%` : "—"}
              icon={Gauge}
              subtitle={`${opMetrics.alertsResolved24h}/${opMetrics.alertsProcessed24h} alerts (24h)`}
              subtitleColor={
                opMetrics.resolutionRate != null && opMetrics.resolutionRate >= 80
                  ? "text-emerald-400"
                  : opMetrics.resolutionRate != null && opMetrics.resolutionRate >= 50
                    ? "text-amber-400"
                    : "text-red-400"
              }
              iconColor="text-indigo-500"
            />
            <StatCard
              title="Throughput"
              value={opMetrics.alertsProcessed24h}
              icon={Activity}
              subtitle="Alerts processed (24h)"
              iconColor="text-emerald-500"
              href="/alerts"
            />
          </div>
        )}

        {visibleChartWidgets.length > 0 && (
          <div
            className={`grid grid-cols-1 ${visibleChartWidgets.length === 2 ? "lg:grid-cols-2" : visibleChartWidgets.length >= 3 ? "lg:grid-cols-3" : ""} gap-4`}
          >
            {analyticsLoading ? (
              visibleChartWidgets.map((_, i) => (
                <Card key={i}>
                  <ChartSkeleton />
                </Card>
              ))
            ) : analyticsError ? (
              <Card className="col-span-full">
                <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
                  <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
                    <AlertTriangle className="h-6 w-6 text-destructive" />
                  </div>
                  <p className="text-sm font-medium">Failed to load chart data</p>
                  <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching analytics.</p>
                  <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchAnalytics()}>
                    Try Again
                  </Button>
                </div>
              </Card>
            ) : analytics ? (
              <>
                {isWidgetVisible("severity") && <SeverityChart data={analytics.severityDistribution} />}
                {isWidgetVisible("sources") && <SourceChart data={analytics.sourceDistribution} />}
                {isWidgetVisible("trend") && <TrendChart data={analytics.alertTrend} />}
              </>
            ) : (
              <Card className="col-span-3">
                <div
                  className="flex flex-col items-center justify-center h-[240px] text-sm text-muted-foreground"
                  role="status"
                  aria-label="No analytics data"
                >
                  <Activity className="h-8 w-8 mb-3 opacity-50" aria-hidden="true" />
                  <p>No analytics data available</p>
                  <p className="text-xs mt-1">Connect a data source to start seeing analytics</p>
                </div>
              </Card>
            )}
          </div>
        )}

        {visibleBottomWidgets.length > 0 && (
          <div
            className={`grid grid-cols-1 md:grid-cols-2 ${visibleBottomWidgets.length >= 4 ? "lg:grid-cols-4" : visibleBottomWidgets.length === 3 ? "lg:grid-cols-3" : visibleBottomWidgets.length === 2 ? "lg:grid-cols-2" : ""} gap-4`}
          >
            {analyticsLoading ? (
              visibleBottomWidgets.map((_, i) => (
                <Card key={i}>
                  <ChartSkeleton />
                </Card>
              ))
            ) : analytics ? (
              <>
                {isWidgetVisible("mitre") && <MitreTacticsWidget data={analytics.topMitreTactics} />}
                {isWidgetVisible("categories") && <CategoryWidget data={analytics.categoryDistribution} />}
                {isWidgetVisible("connectors") && <ConnectorHealthWidget data={analytics.connectorHealth} />}
                {isWidgetVisible("ingestion") && <IngestionRateChart data={analytics.ingestionRate} />}
                {isWidgetVisible("whatChanged") && <WhatChangedWidget stats={stats} />}
              </>
            ) : null}
          </div>
        )}
      </div>

      <footer className="border-t border-border/20 py-2.5 px-6 text-center">
        <span className="text-[10px] text-muted-foreground/40">
          SecureNexus SOC Platform v3.0.0 &copy; {new Date().getFullYear()}
        </span>
      </footer>
    </div>
  );
}
