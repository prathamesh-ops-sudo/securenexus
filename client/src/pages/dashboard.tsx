import { useQuery } from "@tanstack/react-query";
import { Shield, AlertTriangle, FileWarning, CheckCircle2, TrendingDown, Clock, Zap, ArrowUpRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import type { Alert, Incident } from "@shared/schema";

function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-green-500/10 text-green-500 border-green-500/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${variants[severity] || variants.medium}`}>
      {severity}
    </span>
  );
}

function StatCard({ title, value, icon: Icon, subtitle, loading }: {
  title: string;
  value: number | string;
  icon: any;
  subtitle?: string;
  loading?: boolean;
}) {
  return (
    <Card data-testid={`stat-${title.toLowerCase().replace(/\s/g, "-")}`}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold" data-testid={`value-${title.toLowerCase().replace(/\s/g, "-")}`}>{value}</div>
        )}
        {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery<{
    totalAlerts: number;
    openIncidents: number;
    criticalAlerts: number;
    resolvedIncidents: number;
    newAlertsToday: number;
    escalatedIncidents: number;
  }>({
    queryKey: ["/api/dashboard/stats"],
  });

  const { data: recentAlerts, isLoading: alertsLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: recentIncidents, isLoading: incidentsLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">Security Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">Real-time overview of your security posture</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard
          title="Total Alerts"
          value={stats?.totalAlerts ?? 0}
          icon={AlertTriangle}
          subtitle="All sources"
          loading={statsLoading}
        />
        <StatCard
          title="Open Incidents"
          value={stats?.openIncidents ?? 0}
          icon={FileWarning}
          subtitle="Requires attention"
          loading={statsLoading}
        />
        <StatCard
          title="Critical Alerts"
          value={stats?.criticalAlerts ?? 0}
          icon={Shield}
          subtitle="Immediate action needed"
          loading={statsLoading}
        />
        <StatCard
          title="New Today"
          value={stats?.newAlertsToday ?? 0}
          icon={Zap}
          subtitle="Alerts ingested today"
          loading={statsLoading}
        />
        <StatCard
          title="Escalated"
          value={stats?.escalatedIncidents ?? 0}
          icon={ArrowUpRight}
          subtitle="Incidents escalated"
          loading={statsLoading}
        />
        <StatCard
          title="Resolved"
          value={stats?.resolvedIncidents ?? 0}
          icon={CheckCircle2}
          subtitle="Incidents resolved"
          loading={statsLoading}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
            <CardTitle className="text-base font-semibold">Active Incidents</CardTitle>
            <Link href="/incidents" className="text-xs text-primary hover:underline" data-testid="link-view-all-incidents">View all</Link>
          </CardHeader>
          <CardContent className="space-y-3">
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
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        {incident.alertCount} alerts
                      </span>
                      {incident.confidence && (
                        <span className="flex items-center gap-1">
                          <TrendingDown className="h-3 w-3" />
                          {Math.round(incident.confidence * 100)}% confidence
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
              <div className="text-center py-8 text-sm text-muted-foreground">
                No active incidents
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
            <CardTitle className="text-base font-semibold">Recent Alerts</CardTitle>
            <Link href="/alerts" className="text-xs text-primary hover:underline" data-testid="link-view-all-alerts">View all</Link>
          </CardHeader>
          <CardContent className="space-y-2">
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
                    <AlertTriangle className="h-3 w-3 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{alert.title}</div>
                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap">
                      <span>{alert.source}</span>
                      <SeverityBadge severity={alert.severity} />
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-sm text-muted-foreground">
                No alerts
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
