import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  BarChart3,
  AlertTriangle,
  RefreshCw,
  TrendingUp,
  Users,
  Zap,
  Database,
  Clock,
  DollarSign,
  Activity,
  Filter,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface UsageMetric {
  category: string;
  current: number;
  limit: number;
  unit: string;
  trend: number;
}

interface MeteringData {
  plan: string;
  billingPeriodStart: string;
  billingPeriodEnd: string;
  totalCost: number;
  metrics: UsageMetric[];
  dailyUsage: { date: string; requests: number; tokens: number; storage: number }[];
  topConsumers: { user: string; requests: number; cost: number }[];
}

export default function UsageMeteringAnalyticsPage() {
  usePageTitle("Usage & Metering Analytics");
  const [period, setPeriod] = useState("current");

  const {
    data: metering,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<MeteringData>({
    queryKey: ["/api/usage-metering/analytics", period],
    queryFn: () => apiRequest("GET", `/api/usage-metering/analytics?period=${period}`).then((r) => r.json()),
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

  if (isError || !metering) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load usage data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const metrics = Array.isArray(metering.metrics) ? metering.metrics : [];
  const dailyUsage = Array.isArray(metering.dailyUsage) ? metering.dailyUsage : [];
  const topConsumers = Array.isArray(metering.topConsumers) ? metering.topConsumers : [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BarChart3 className="h-6 w-6" /> Usage & Metering Analytics
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor resource consumption, plan usage, and cost analytics
          </p>
        </div>
        <div className="flex gap-2">
          <Select value={period} onValueChange={setPeriod}>
            <SelectTrigger className="w-40">
              <Filter className="mr-2 h-4 w-4" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="current">Current Period</SelectItem>
              <SelectItem value="previous">Previous Period</SelectItem>
              <SelectItem value="90d">Last 90 Days</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <DollarSign className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">${(metering.totalCost || 0).toFixed(2)}</p>
              <p className="text-xs text-muted-foreground">Total Cost</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold capitalize">{metering.plan || "free"}</p>
              <p className="text-xs text-muted-foreground">Current Plan</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-sm font-bold">
                {metering.billingPeriodStart ? new Date(metering.billingPeriodStart).toLocaleDateString() : "N/A"}{" "}
                &mdash; {metering.billingPeriodEnd ? new Date(metering.billingPeriodEnd).toLocaleDateString() : "N/A"}
              </p>
              <p className="text-xs text-muted-foreground">Billing Period</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Activity className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{metrics.length}</p>
              <p className="text-xs text-muted-foreground">Tracked Metrics</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="usage">
        <TabsList>
          <TabsTrigger value="usage">Usage Quotas</TabsTrigger>
          <TabsTrigger value="daily">Daily Trends</TabsTrigger>
          <TabsTrigger value="consumers">Top Consumers</TabsTrigger>
        </TabsList>

        <TabsContent value="usage" className="space-y-3">
          {metrics.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <BarChart3 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No usage metrics available</p>
              </CardContent>
            </Card>
          ) : (
            metrics.map((m) => {
              const pct = m.limit > 0 ? Math.round((m.current / m.limit) * 100) : 0;
              return (
                <Card key={m.category}>
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Database className="h-4 w-4 text-primary" />
                        <span className="font-medium text-sm capitalize">{m.category.replace(/_/g, " ")}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm">
                          {m.current.toLocaleString()} / {m.limit.toLocaleString()} {m.unit}
                        </span>
                        {m.trend !== 0 && (
                          <Badge variant={m.trend > 0 ? "secondary" : "default"}>
                            <TrendingUp className="mr-1 h-3 w-3" />
                            {m.trend > 0 ? "+" : ""}
                            {m.trend}%
                          </Badge>
                        )}
                        <Badge variant={pct >= 90 ? "destructive" : pct >= 70 ? "secondary" : "outline"}>{pct}%</Badge>
                      </div>
                    </div>
                    <Progress value={Math.min(pct, 100)} />
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>

        <TabsContent value="daily" className="space-y-3">
          {dailyUsage.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <TrendingUp className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No daily usage data</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Daily Usage</CardTitle>
                <CardDescription>Last {dailyUsage.length} days of usage data</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {dailyUsage.slice(-14).map((d) => (
                    <div key={d.date} className="flex items-center justify-between text-sm border-b pb-1">
                      <span className="text-muted-foreground">{new Date(d.date).toLocaleDateString()}</span>
                      <div className="flex gap-4">
                        <span>
                          <Zap className="inline h-3 w-3 mr-1" />
                          {d.requests.toLocaleString()} req
                        </span>
                        <span>
                          <Activity className="inline h-3 w-3 mr-1" />
                          {(d.tokens / 1000).toFixed(0)}K tok
                        </span>
                        <span>
                          <Database className="inline h-3 w-3 mr-1" />
                          {(d.storage / 1e6).toFixed(1)} MB
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="consumers" className="space-y-3">
          {topConsumers.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Users className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No consumer data available</p>
              </CardContent>
            </Card>
          ) : (
            topConsumers.map((c, i) => (
              <Card key={c.user}>
                <CardContent className="py-3 flex items-center gap-3">
                  <Badge variant="outline" className="w-8 h-8 flex items-center justify-center rounded-full">
                    {i + 1}
                  </Badge>
                  <div className="flex-1">
                    <p className="font-medium text-sm">{c.user}</p>
                    <p className="text-xs text-muted-foreground">{c.requests.toLocaleString()} requests</p>
                  </div>
                  <p className="font-bold">${c.cost.toFixed(2)}</p>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
