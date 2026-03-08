import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Activity,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Clock,
  CheckCircle2,
  XCircle,
  BarChart3,
  Zap,
  TrendingUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface ModelMetrics {
  modelId: string;
  modelName: string;
  provider: string;
  status: "healthy" | "degraded" | "down";
  avgLatencyMs: number;
  p99LatencyMs: number;
  requestsPerMinute: number;
  errorRate: number;
  tokensThroughput: number;
  costPerRequest: number;
  uptime: number;
}

interface InferenceMetrics {
  totalRequests: number;
  totalTokens: number;
  avgLatencyMs: number;
  errorRate: number;
  models: ModelMetrics[];
}

export default function AiModelHealthPage() {
  usePageTitle("AI Model Health & Inference Metrics");

  const {
    data: metrics,
    isLoading,
    isError,
    refetch,
  } = useQuery<InferenceMetrics>({
    queryKey: ["/api/ai/inference-metrics"],
    queryFn: () => apiRequest("GET", "/api/ai/inference-metrics").then((r) => r.json()),
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

  if (isError || !metrics) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load AI model health data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const models = Array.isArray(metrics.models) ? metrics.models : [];

  const statusIcon = (s: string) => {
    if (s === "healthy") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "degraded") return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    return <XCircle className="h-4 w-4 text-red-500" />;
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="h-6 w-6" /> AI Model Health & Inference Metrics
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor model latency, throughput, error rates, and cost per request
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{(metrics.totalRequests || 0).toLocaleString()}</p>
              <p className="text-xs text-muted-foreground">Total Requests</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{(metrics.avgLatencyMs || 0).toFixed(0)}ms</p>
              <p className="text-xs text-muted-foreground">Avg Latency</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{((metrics.totalTokens || 0) / 1000).toFixed(0)}K</p>
              <p className="text-xs text-muted-foreground">Total Tokens</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{((metrics.errorRate || 0) * 100).toFixed(1)}%</p>
              <p className="text-xs text-muted-foreground">Error Rate</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="models">
        <TabsList>
          <TabsTrigger value="models">Model Health</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="models" className="space-y-3">
          {models.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-2">
                <Cpu className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No model data available</p>
              </CardContent>
            </Card>
          ) : (
            models.map((m) => (
              <Card key={m.modelId}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {statusIcon(m.status)}
                      <div>
                        <p className="font-medium text-sm">{m.modelName}</p>
                        <p className="text-xs text-muted-foreground">{m.provider}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          m.status === "healthy" ? "default" : m.status === "degraded" ? "secondary" : "destructive"
                        }
                      >
                        {m.status}
                      </Badge>
                      <Badge variant="outline">{m.uptime.toFixed(1)}% uptime</Badge>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-xs text-muted-foreground">Avg Latency</p>
                      <p className="font-medium">{m.avgLatencyMs.toFixed(0)}ms</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">P99 Latency</p>
                      <p className="font-medium">{m.p99LatencyMs.toFixed(0)}ms</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Req/min</p>
                      <p className="font-medium">{m.requestsPerMinute.toFixed(1)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Error Rate</p>
                      <p className="font-medium">{(m.errorRate * 100).toFixed(2)}%</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="performance">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Performance Overview</CardTitle>
              <CardDescription>Aggregate model performance across all providers</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {models.map((m) => (
                <div key={m.modelId} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span>{m.modelName}</span>
                    <span className="text-muted-foreground">{m.tokensThroughput.toFixed(0)} tok/s</span>
                  </div>
                  <Progress value={Math.min(m.uptime, 100)} />
                </div>
              ))}
              {models.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">No performance data</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
