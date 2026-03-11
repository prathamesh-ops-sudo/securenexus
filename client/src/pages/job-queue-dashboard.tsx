import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  ListTodo,
  AlertTriangle,
  RefreshCw,
  Play,
  Pause,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  BarChart3,
  Trash2,
  RotateCcw,
  Construction,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface Job {
  id: string;
  type: string;
  status: "pending" | "running" | "completed" | "failed" | "dead";
  priority: number;
  attempts: number;
  maxAttempts: number;
  payload: Record<string, unknown>;
  error?: string;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
}

interface QueueStats {
  pending: number;
  running: number;
  completed: number;
  failed: number;
  dead: number;
  throughputPerMinute: number;
  avgDurationMs: number;
  jobs: Job[];
}

export default function JobQueueDashboardPage() {
  usePageTitle("Job Queue Dashboard");
  const { toast } = useToast();

  const {
    data: stats,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<QueueStats>({
    queryKey: ["/api/jobs/stats"],
    queryFn: () => apiRequest("GET", "/api/jobs/stats").then((r) => r.json()),
  });

  const isNotImplemented = isError && error?.message?.startsWith("501:");

  const retryMutation = useMutation({
    mutationFn: (jobId: string) => apiRequest("POST", `/api/jobs/${jobId}/retry`),
    onSuccess: () => {
      toast({ title: "Job retry queued" });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });
    },
    onError: () => toast({ title: "Retry failed", variant: "destructive" }),
  });

  const purgeDeadMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/jobs/purge-dead"),
    onSuccess: () => {
      toast({ title: "Dead jobs purged" });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });
    },
    onError: () => toast({ title: "Purge failed", variant: "destructive" }),
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-5 gap-4">
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      </div>
    );
  }

  if (isNotImplemented) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ListTodo className="h-6 w-6" /> Job Queue Dashboard
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor background job processing, throughput, and failures
          </p>
        </div>
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 gap-4">
            <Construction className="h-10 w-10 text-muted-foreground" />
            <div className="text-center">
              <p className="text-lg font-semibold">Coming Soon</p>
              <p className="text-sm text-muted-foreground mt-1 max-w-md">
                The job queue dashboard is under development. This will provide real-time monitoring of background jobs,
                retry management, and throughput analytics.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isError || !stats) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load job queue data</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const jobs = Array.isArray(stats.jobs) ? stats.jobs : [];

  const statusIcon = (s: string) => {
    if (s === "running") return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
    if (s === "completed") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    if (s === "dead") return <XCircle className="h-4 w-4 text-muted-foreground" />;
    return <Clock className="h-4 w-4 text-yellow-500" />;
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ListTodo className="h-6 w-6" /> Job Queue Dashboard
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor background job processing, throughput, and failures
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          {stats.dead > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => purgeDeadMutation.mutate()}
              disabled={purgeDeadMutation.isPending}
            >
              {purgeDeadMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="mr-2 h-4 w-4" />
              )}
              Purge Dead ({stats.dead})
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{stats.pending}</p>
              <p className="text-xs text-muted-foreground">Pending</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Loader2 className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{stats.running}</p>
              <p className="text-xs text-muted-foreground">Running</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{stats.completed}</p>
              <p className="text-xs text-muted-foreground">Completed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{stats.failed}</p>
              <p className="text-xs text-muted-foreground">Failed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{stats.throughputPerMinute.toFixed(1)}</p>
              <p className="text-xs text-muted-foreground">Jobs/min</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="all">
        <TabsList>
          <TabsTrigger value="all">All Jobs</TabsTrigger>
          <TabsTrigger value="failed">Failed ({stats.failed})</TabsTrigger>
          <TabsTrigger value="running">Running ({stats.running})</TabsTrigger>
        </TabsList>

        {["all", "failed", "running"].map((tab) => (
          <TabsContent key={tab} value={tab} className="space-y-2">
            {(() => {
              const filtered = tab === "all" ? jobs : jobs.filter((j) => j.status === tab);
              if (filtered.length === 0)
                return (
                  <Card>
                    <CardContent className="flex flex-col items-center py-12 gap-2">
                      <ListTodo className="h-8 w-8 text-muted-foreground" />
                      <p className="text-muted-foreground">No jobs in this category</p>
                    </CardContent>
                  </Card>
                );
              return filtered.map((j) => (
                <Card key={j.id}>
                  <CardContent className="py-3 flex items-center gap-3">
                    {statusIcon(j.status)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm">{j.type}</span>
                        <span className="font-mono text-xs text-muted-foreground">{j.id.slice(0, 8)}</span>
                      </div>
                      {j.error && <p className="text-xs text-red-500 truncate">{j.error}</p>}
                      <p className="text-xs text-muted-foreground">
                        Attempt {j.attempts}/{j.maxAttempts} &middot; {new Date(j.createdAt).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">P{j.priority}</Badge>
                      <Badge
                        variant={
                          j.status === "completed" ? "default" : j.status === "failed" ? "destructive" : "secondary"
                        }
                      >
                        {j.status}
                      </Badge>
                      {(j.status === "failed" || j.status === "dead") && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => retryMutation.mutate(j.id)}
                          disabled={retryMutation.isPending}
                        >
                          <RotateCcw className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ));
            })()}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
