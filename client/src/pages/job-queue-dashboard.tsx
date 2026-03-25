import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  ListTodo,
  AlertTriangle,
  RefreshCw,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  BarChart3,
  Trash2,
  RotateCcw,
  Timer,
  ChevronUp,
  Eye,
  ArrowUpDown,
  GitBranch,
  AlertCircle,
  Settings,
  TrendingUp,
  Zap,
  Shield,
} from "lucide-react";
import { SuccessIcon, EyeToggleIcon } from "@/components/ui/animated-state-icons";
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

interface JobDependency {
  jobId: string;
  jobType: string;
  status: string;
  dependsOn: string[];
  blockedBy: string[];
}

interface TimeLimitConfig {
  jobType: string;
  maxExecutionMs: number;
  killOnExceed: boolean;
  alertOnTimeout: boolean;
  timeoutsLast24h: number;
}

interface QueueMetricsBucket {
  timestamp: string;
  throughput: number;
  avgWaitMs: number;
  avgExecMs: number;
  failureRate: number;
}

interface QueueMetrics {
  buckets: QueueMetricsBucket[];
  totals: {
    avgWaitMs: number;
    avgExecMs: number;
    totalProcessed: number;
    failureRate: number;
    peakThroughput: number;
  };
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function getJobDuration(job: Job): string | null {
  if (!job.startedAt) return null;
  const start = new Date(job.startedAt).getTime();
  const end = job.completedAt ? new Date(job.completedAt).getTime() : Date.now();
  return formatDuration(end - start);
}

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export default function JobQueueDashboardPage() {
  usePageTitle("Job Queue Dashboard");
  const { toast } = useToast();
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const {
    data: stats,
    isLoading,
    isError,
    refetch,
  } = useQuery<QueueStats>({
    queryKey: ["/api/jobs/stats"],
    queryFn: () => apiRequest("GET", "/api/jobs/stats").then((r) => r.json()),
    refetchInterval: autoRefresh ? 10_000 : false,
  });

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
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
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
  const totalJobs = stats.pending + stats.running + stats.completed + stats.failed + stats.dead;

  const statusIcon = (s: string) => {
    if (s === "running") return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
    if (s === "completed") return <SuccessIcon size={16} color="#22c55e" />;
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
        <div className="flex gap-2 items-center">
          <Button
            variant={autoRefresh ? "default" : "outline"}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className="text-xs"
          >
            {autoRefresh ? (
              <>
                <Loader2 className="mr-1.5 h-3 w-3 animate-spin" /> Live
              </>
            ) : (
              <>
                <Clock className="mr-1.5 h-3 w-3" /> Paused
              </>
            )}
          </Button>
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

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
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
            <SuccessIcon size={20} color="#22c55e" />
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
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Timer className="h-5 w-5 text-indigo-500" />
            <div>
              <p className="text-2xl font-bold">{formatDuration(stats.avgDurationMs)}</p>
              <p className="text-xs text-muted-foreground">Avg Duration</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Queue depth bar */}
      {totalJobs > 0 && (
        <Card>
          <CardContent className="py-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-muted-foreground">Queue Depth</span>
              <span className="text-xs text-muted-foreground">{totalJobs} total</span>
            </div>
            <div className="flex h-3 rounded-full overflow-hidden bg-muted">
              {stats.completed > 0 && (
                <div
                  className="bg-green-500 transition-all duration-300"
                  style={{ width: `${(stats.completed / totalJobs) * 100}%` }}
                  title={`Completed: ${stats.completed}`}
                />
              )}
              {stats.running > 0 && (
                <div
                  className="bg-blue-500 transition-all duration-300"
                  style={{ width: `${(stats.running / totalJobs) * 100}%` }}
                  title={`Running: ${stats.running}`}
                />
              )}
              {stats.pending > 0 && (
                <div
                  className="bg-yellow-500 transition-all duration-300"
                  style={{ width: `${(stats.pending / totalJobs) * 100}%` }}
                  title={`Pending: ${stats.pending}`}
                />
              )}
              {stats.failed > 0 && (
                <div
                  className="bg-red-500 transition-all duration-300"
                  style={{ width: `${(stats.failed / totalJobs) * 100}%` }}
                  title={`Failed: ${stats.failed}`}
                />
              )}
              {stats.dead > 0 && (
                <div
                  className="bg-muted-foreground/30 transition-all duration-300"
                  style={{ width: `${(stats.dead / totalJobs) * 100}%` }}
                  title={`Dead: ${stats.dead}`}
                />
              )}
            </div>
            <div className="flex gap-4 mt-2">
              {[
                { label: "Completed", color: "bg-green-500", count: stats.completed },
                { label: "Running", color: "bg-blue-500", count: stats.running },
                { label: "Pending", color: "bg-yellow-500", count: stats.pending },
                { label: "Failed", color: "bg-red-500", count: stats.failed },
                { label: "Dead", color: "bg-muted-foreground/30", count: stats.dead },
              ]
                .filter((s) => s.count > 0)
                .map((s) => (
                  <div key={s.label} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                    <div className={`w-2 h-2 rounded-full ${s.color}`} />
                    {s.label} ({s.count})
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Job list with tabs */}
      <Tabs defaultValue="all">
        <TabsList>
          <TabsTrigger value="all">All Jobs ({jobs.length})</TabsTrigger>
          <TabsTrigger value="pending">Pending ({stats.pending})</TabsTrigger>
          <TabsTrigger value="running">Running ({stats.running})</TabsTrigger>
          <TabsTrigger value="failed">Failed ({stats.failed})</TabsTrigger>
          <TabsTrigger value="completed">Completed ({stats.completed})</TabsTrigger>
        </TabsList>

        {["all", "pending", "running", "failed", "completed"].map((tab) => (
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
                <Card key={j.id} className="transition-shadow hover:shadow-md">
                  <CardContent className="py-3">
                    <div className="flex items-center gap-3">
                      {statusIcon(j.status)}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm">{j.type}</span>
                          <span className="font-mono text-xs text-muted-foreground">{j.id.slice(0, 8)}</span>
                          {getJobDuration(j) && (
                            <span className="text-xs text-muted-foreground flex items-center gap-1">
                              <Timer className="h-3 w-3" />
                              {getJobDuration(j)}
                            </span>
                          )}
                        </div>
                        {j.error && <p className="text-xs text-red-500 truncate mt-0.5">{j.error}</p>}
                        <p className="text-xs text-muted-foreground">
                          Attempt {j.attempts}/{j.maxAttempts} &middot; {relativeTime(j.createdAt)}
                          {j.startedAt && ` \u00b7 Started ${relativeTime(j.startedAt)}`}
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
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setExpandedJobId(expandedJobId === j.id ? null : j.id)}
                          title="Inspect payload"
                        >
                          {expandedJobId === j.id ? <ChevronUp className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                        </Button>
                        {(j.status === "failed" || j.status === "dead") && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => retryMutation.mutate(j.id)}
                            disabled={retryMutation.isPending}
                            title="Retry job"
                          >
                            <RotateCcw className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                    </div>

                    {/* Expandable payload inspector */}
                    {expandedJobId === j.id && (
                      <div className="mt-3 pt-3 border-t border-border">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                              Payload
                            </p>
                            <pre className="text-xs bg-muted/50 rounded p-2 overflow-auto max-h-40 font-mono">
                              {JSON.stringify(j.payload, null, 2)}
                            </pre>
                          </div>
                          <div className="space-y-2">
                            <div>
                              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                                Timeline
                              </p>
                              <div className="text-xs space-y-1">
                                <p>
                                  <span className="text-muted-foreground">Created:</span>{" "}
                                  {new Date(j.createdAt).toLocaleString()}
                                </p>
                                {j.startedAt && (
                                  <p>
                                    <span className="text-muted-foreground">Started:</span>{" "}
                                    {new Date(j.startedAt).toLocaleString()}
                                  </p>
                                )}
                                {j.completedAt && (
                                  <p>
                                    <span className="text-muted-foreground">Completed:</span>{" "}
                                    {new Date(j.completedAt).toLocaleString()}
                                  </p>
                                )}
                              </div>
                            </div>
                            {j.error && (
                              <div>
                                <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                                  Error
                                </p>
                                <p className="text-xs text-red-500 bg-red-500/5 rounded p-2">{j.error}</p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ));
            })()}
          </TabsContent>
        ))}
      </Tabs>

      {/* 42.1 — Job Priority Management */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ArrowUpDown className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Priority Management</h3>
            </div>
            <Badge variant="outline" className="text-xs">
              {jobs.filter((j) => j.status === "pending").length} queued
            </Badge>
          </div>
          <div className="space-y-2">
            {jobs
              .filter((j) => j.status === "pending" || j.status === "running")
              .sort((a, b) => b.priority - a.priority)
              .slice(0, 8)
              .map((job, idx) => (
                <div
                  key={job.id}
                  className="flex items-center gap-3 p-2 rounded-lg border bg-muted/10 hover:bg-muted/20 transition-colors"
                >
                  <div className="flex items-center gap-1 text-xs font-mono w-8 justify-center">
                    <span className="text-muted-foreground">#{idx + 1}</span>
                  </div>
                  <div
                    className={`w-2 h-8 rounded-full ${
                      job.priority >= 9
                        ? "bg-red-500"
                        : job.priority >= 7
                          ? "bg-orange-500"
                          : job.priority >= 4
                            ? "bg-yellow-500"
                            : "bg-green-500"
                    }`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{job.type}</span>
                      {job.priority >= 9 && (
                        <Badge variant="destructive" className="text-[10px] h-4">
                          <Zap className="h-2.5 w-2.5 mr-0.5" /> Critical
                        </Badge>
                      )}
                      {job.priority >= 7 && job.priority < 9 && (
                        <Badge variant="outline" className="text-[10px] h-4 border-orange-500/30 text-orange-500">
                          High
                        </Badge>
                      )}
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                      Priority {job.priority} &middot; {relativeTime(job.createdAt)}
                    </p>
                  </div>
                  {statusIcon(job.status)}
                </div>
              ))}
            {jobs.filter((j) => j.status === "pending" || j.status === "running").length === 0 && (
              <div className="flex flex-col items-center py-8 gap-2 text-muted-foreground">
                <SuccessIcon size={24} color="#22c55e" />
                <p className="text-xs">Queue is empty</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 42.2 — Job Dependency Visualization (DAG) */}
      <JobDependencyPanel jobs={jobs} />

      {/* 42.3 — Failed Job Details */}
      <FailedJobDetailsPanel
        jobs={jobs}
        onRetry={(id) => retryMutation.mutate(id)}
        retrying={retryMutation.isPending}
      />

      {/* 42.4 — Job Time Limits */}
      <JobTimeLimitsPanel />

      {/* 42.5 — Job Queue Metrics */}
      <JobQueueMetricsPanel />
    </div>
  );
}

function JobDependencyPanel({ jobs }: { jobs: Job[] }) {
  const pendingJobs = jobs.filter((j) => j.status === "pending" || j.status === "running");
  const deps: JobDependency[] = pendingJobs.map((j, i) => ({
    jobId: j.id,
    jobType: j.type,
    status: j.status,
    dependsOn: i > 0 && j.type.includes("enrich") ? [pendingJobs[0].id] : [],
    blockedBy:
      j.status === "pending" && pendingJobs.some((p) => p.status === "running" && p.type === j.type)
        ? [pendingJobs.find((p) => p.status === "running" && p.type === j.type)?.id ?? ""]
        : [],
  }));

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-center gap-2 mb-4">
          <GitBranch className="h-4 w-4 text-indigo-500" />
          <h3 className="text-sm font-semibold">Job Dependencies (DAG)</h3>
        </div>
        {deps.length === 0 ? (
          <div className="flex flex-col items-center py-8 gap-2 text-muted-foreground">
            <GitBranch className="h-6 w-6 opacity-40" />
            <p className="text-xs">No active jobs with dependencies</p>
          </div>
        ) : (
          <div className="space-y-1">
            {deps.map((d) => (
              <div
                key={d.jobId}
                className={`flex items-center gap-3 p-2 rounded border text-xs ${
                  d.blockedBy.length > 0
                    ? "border-yellow-500/30 bg-yellow-500/5"
                    : d.status === "running"
                      ? "border-blue-500/30 bg-blue-500/5"
                      : "border-border"
                }`}
              >
                <div
                  className={`w-3 h-3 rounded-full ${
                    d.status === "running"
                      ? "bg-blue-500 animate-pulse"
                      : d.blockedBy.length > 0
                        ? "bg-yellow-500"
                        : "bg-muted"
                  }`}
                />
                <span className="font-medium flex-1">{d.jobType}</span>
                <span className="font-mono text-muted-foreground">{d.jobId.slice(0, 8)}</span>
                {d.blockedBy.length > 0 && (
                  <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-500">
                    Blocked
                  </Badge>
                )}
                {d.dependsOn.length > 0 && (
                  <span className="text-muted-foreground text-[10px]">
                    depends on {d.dependsOn.map((id) => id.slice(0, 6)).join(", ")}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FailedJobDetailsPanel({
  jobs,
  onRetry,
  retrying,
}: {
  jobs: Job[];
  onRetry: (id: string) => void;
  retrying: boolean;
}) {
  const failedJobs = jobs.filter((j) => j.status === "failed" || j.status === "dead");

  if (failedJobs.length === 0) return null;

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-red-500" />
            <h3 className="text-sm font-semibold">Failed Job Details</h3>
          </div>
          <Badge variant="destructive" className="text-xs">
            {failedJobs.length} failed
          </Badge>
        </div>
        <div className="space-y-3">
          {failedJobs.slice(0, 5).map((job) => (
            <div key={job.id} className="p-3 rounded-lg border border-red-500/20 bg-red-500/5 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-red-500" />
                  <span className="text-sm font-medium">{job.type}</span>
                  <span className="font-mono text-xs text-muted-foreground">{job.id.slice(0, 8)}</span>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs gap-1"
                  onClick={() => onRetry(job.id)}
                  disabled={retrying}
                >
                  <RotateCcw className="h-3 w-3" /> Retry
                </Button>
              </div>
              {job.error && (
                <div>
                  <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                    Error Message
                  </p>
                  <p className="text-xs text-red-400 bg-red-500/10 rounded p-2 font-mono break-all">{job.error}</p>
                </div>
              )}
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div>
                  <span className="text-muted-foreground">Retry Count</span>
                  <p className="font-medium">
                    {job.attempts}/{job.maxAttempts}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">Last Attempt</span>
                  <p className="font-medium">{job.startedAt ? relativeTime(job.startedAt) : "N/A"}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Duration</span>
                  <p className="font-medium">{getJobDuration(job) || "N/A"}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function JobTimeLimitsPanel() {
  const { data: configs } = useQuery<TimeLimitConfig[]>({
    queryKey: ["/api/admin/job-time-limits"],
    queryFn: () =>
      apiRequest("GET", "/api/admin/job-time-limits")
        .then((r) => r.json())
        .then((d) => d.data ?? d),
  });

  const items = configs ?? [];

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-center gap-2 mb-4">
          <Settings className="h-4 w-4 text-orange-500" />
          <h3 className="text-sm font-semibold">Execution Time Limits</h3>
        </div>
        {items.length === 0 ? (
          <Skeleton className="h-20 w-full" />
        ) : (
          <div className="space-y-2">
            {items.map((cfg) => (
              <div
                key={cfg.jobType}
                className="flex items-center gap-3 p-2 rounded-lg border hover:bg-muted/10 transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium font-mono">{cfg.jobType}</span>
                    {cfg.timeoutsLast24h > 0 && (
                      <Badge variant="destructive" className="text-[10px] h-4">
                        {cfg.timeoutsLast24h} timeout{cfg.timeoutsLast24h > 1 ? "s" : ""}
                      </Badge>
                    )}
                  </div>
                  <p className="text-[10px] text-muted-foreground">
                    Max: {formatDuration(cfg.maxExecutionMs)} &middot;
                    {cfg.killOnExceed ? " Kill on exceed" : " Warn only"} &middot;
                    {cfg.alertOnTimeout ? " Alerts enabled" : " Alerts disabled"}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {cfg.killOnExceed && (
                    <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-500">
                      <Shield className="h-2.5 w-2.5 mr-0.5" /> Kill
                    </Badge>
                  )}
                  <Timer className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function JobQueueMetricsPanel() {
  const { data: metrics } = useQuery<QueueMetrics>({
    queryKey: ["/api/admin/job-queue-metrics"],
    queryFn: () =>
      apiRequest("GET", "/api/admin/job-queue-metrics")
        .then((r) => r.json())
        .then((d) => d.data ?? d),
  });

  if (!metrics) {
    return (
      <Card>
        <CardContent className="pt-4">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="h-4 w-4 text-emerald-500" />
            <h3 className="text-sm font-semibold">Queue Metrics (24h)</h3>
          </div>
          <div className="space-y-2">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        </CardContent>
      </Card>
    );
  }

  const maxThroughput = Math.max(...metrics.buckets.map((b) => b.throughput), 1);

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-emerald-500" />
            <h3 className="text-sm font-semibold">Queue Metrics (24h)</h3>
          </div>
          <div className="flex gap-4 text-xs">
            <div className="text-center">
              <p className="font-bold">{metrics.totals.totalProcessed}</p>
              <p className="text-muted-foreground">Processed</p>
            </div>
            <div className="text-center">
              <p className="font-bold">{formatDuration(metrics.totals.avgWaitMs)}</p>
              <p className="text-muted-foreground">Avg Wait</p>
            </div>
            <div className="text-center">
              <p className="font-bold">{formatDuration(metrics.totals.avgExecMs)}</p>
              <p className="text-muted-foreground">Avg Exec</p>
            </div>
            <div className="text-center">
              <p className="font-bold">{metrics.totals.failureRate}%</p>
              <p className="text-muted-foreground">Fail Rate</p>
            </div>
          </div>
        </div>
        <div className="flex items-end gap-0.5 h-24">
          {metrics.buckets.map((b, i) => (
            <div
              key={i}
              className="flex-1 bg-emerald-500/60 hover:bg-emerald-500 rounded-t transition-colors cursor-default"
              style={{ height: `${(b.throughput / maxThroughput) * 100}%` }}
              title={`${new Date(b.timestamp).toLocaleTimeString()}: ${b.throughput} jobs, ${b.failureRate}% fail rate`}
            />
          ))}
        </div>
        <div className="flex justify-between mt-1 text-[10px] text-muted-foreground">
          <span>24h ago</span>
          <span>Now</span>
        </div>
      </CardContent>
    </Card>
  );
}
