import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  LayoutDashboard,
  AlertTriangle,
  RefreshCw,
  Shield,
  Eye,
  Activity,
  Users,
  BarChart3,
  Bell,
  CheckCircle2,
  Clock,
  TrendingUp,
} from "lucide-react";
import { NotificationIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface RoleDashboardData {
  role: string;
  widgets: { id: string; title: string; type: string; value: number | string; trend?: number; status?: string }[];
  recentActivity: { id: string; action: string; timestamp: string; user: string }[];
  kpis: { label: string; value: number; target: number; unit: string }[];
}

export default function RoleDashboardPage() {
  usePageTitle("Role-Specific Dashboard");

  const {
    data: dashboard,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<RoleDashboardData>({
    queryKey: ["/api/dashboard/role"],
    queryFn: () => apiRequest("GET", "/api/dashboard/role").then((r) => r.json()),
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (isError || !dashboard) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load dashboard data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const widgets = Array.isArray(dashboard.widgets) ? dashboard.widgets : [];
  const activity = Array.isArray(dashboard.recentActivity) ? dashboard.recentActivity : [];
  const kpis = Array.isArray(dashboard.kpis) ? dashboard.kpis : [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <LayoutDashboard className="h-6 w-6" /> Role-Specific Dashboard
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Personalized view for <span className="capitalize font-medium">{dashboard.role || "analyst"}</span> role
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {widgets.slice(0, 4).map((w) => (
          <Card key={w.id}>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-2xl font-bold">
                    {typeof w.value === "number" ? w.value.toLocaleString() : w.value}
                  </p>
                  <p className="text-xs text-muted-foreground">{w.title}</p>
                </div>
                {w.trend !== undefined && (
                  <Badge variant={w.trend > 0 ? "default" : w.trend < 0 ? "destructive" : "secondary"}>
                    <TrendingUp className="mr-1 h-3 w-3" />
                    {w.trend > 0 ? "+" : ""}
                    {w.trend}%
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="kpis">
        <TabsList>
          <TabsTrigger value="kpis">KPIs</TabsTrigger>
          <TabsTrigger value="activity">Recent Activity</TabsTrigger>
          <TabsTrigger value="widgets">All Widgets</TabsTrigger>
        </TabsList>

        <TabsContent value="kpis" className="space-y-3">
          {kpis.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No KPI data available</p>
              </CardContent>
            </Card>
          ) : (
            kpis.map((k, i) => {
              const pct = k.target > 0 ? Math.round((k.value / k.target) * 100) : 0;
              return (
                <Card key={i}>
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">{k.label}</span>
                      <span className="text-sm">
                        {k.value} / {k.target} {k.unit}
                      </span>
                    </div>
                    <Progress value={Math.min(pct, 100)} />
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>

        <TabsContent value="activity" className="space-y-2">
          {activity.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Activity className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No recent activity</p>
              </CardContent>
            </Card>
          ) : (
            activity.map((a) => (
              <Card key={a.id}>
                <CardContent className="py-3 flex items-center gap-3">
                  <Bell className="h-4 w-4 text-primary" />
                  <div className="flex-1">
                    <p className="text-sm">{a.action}</p>
                    <p className="text-xs text-muted-foreground">
                      {a.user} &middot; {new Date(a.timestamp).toLocaleString()}
                    </p>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="widgets" className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {widgets.map((w) => (
              <Card key={w.id}>
                <CardContent className="pt-4">
                  <p className="text-xs text-muted-foreground mb-1">{w.title}</p>
                  <p className="text-xl font-bold">
                    {typeof w.value === "number" ? w.value.toLocaleString() : w.value}
                  </p>
                  {w.status && (
                    <Badge
                      variant={w.status === "good" ? "default" : w.status === "warning" ? "secondary" : "destructive"}
                      className="mt-1"
                    >
                      {w.status}
                    </Badge>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
