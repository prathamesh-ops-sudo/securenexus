import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Textarea } from "@/components/ui/textarea";
import {
  Server,
  Target,
  BookOpen,
  Archive,
  Play,
  Trash2,
  Plus,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Loader2,
  Gauge,
  Database,
} from "lucide-react";

function formatTimestamp(date: string | Date | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function jobStatusStyle(status: string) {
  const styles: Record<string, string> = {
    completed: "bg-green-500/10 text-green-500 border-green-500/20",
    running: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20 animate-pulse",
    failed: "bg-red-500/10 text-red-500 border-red-500/20",
    pending: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    cancelled: "bg-muted text-muted-foreground border-muted",
  };
  return styles[status] || "bg-muted text-muted-foreground border-muted";
}

function sloStatusStyle(breached: boolean | null) {
  if (breached === null || breached === undefined) return "bg-muted text-muted-foreground border-muted";
  return breached
    ? "bg-red-500/10 text-red-500 border-red-500/20"
    : "bg-green-500/10 text-green-500 border-green-500/20";
}

function drCategoryStyle(category: string) {
  const styles: Record<string, string> = {
    backup: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    restore: "bg-green-500/10 text-green-500 border-green-500/20",
    failover: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    data_recovery: "bg-purple-500/10 text-purple-500 border-purple-500/20",
    incident_response: "bg-red-500/10 text-red-500 border-red-500/20",
  };
  return styles[category] || "bg-muted text-muted-foreground border-muted";
}

function testResultStyle(result: string) {
  const styles: Record<string, string> = {
    pass: "bg-green-500/10 text-green-500 border-green-500/20",
    fail: "bg-red-500/10 text-red-500 border-red-500/20",
    partial: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  };
  return styles[result] || "bg-muted text-muted-foreground border-muted";
}

function severityStyle(severity: string) {
  const styles: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    informational: "bg-muted text-muted-foreground border-muted",
  };
  return styles[severity] || "bg-muted text-muted-foreground border-muted";
}

const JOB_TYPES = [
  "connector_sync",
  "threat_enrichment",
  "report_generation",
  "cache_refresh",
  "archive_alerts",
  "daily_stats_rollup",
  "sli_collection",
];

function WorkerQueueTab() {
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [jobType, setJobType] = useState(JOB_TYPES[0]);
  const [payload, setPayload] = useState("");
  const [priority, setPriority] = useState("0");

  const {
    data: workerStatus,
    isLoading: workerLoading,
    isError: workerError,
    refetch: refetchWorker,
  } = useQuery<any>({
    queryKey: ["/api/ops/worker/status"],
  });

  const {
    data: jobStats,
    isLoading: statsLoading,
    isError: statsError,
    refetch: _refetchStats,
  } = useQuery<any>({
    queryKey: ["/api/ops/jobs/stats"],
  });

  const {
    data: jobs,
    isLoading: jobsLoading,
    isError: jobsError,
    refetch: _refetchJobs,
  } = useQuery<any[]>({
    queryKey: ["/api/ops/jobs"],
  });

  const enqueueMutation = useMutation({
    mutationFn: async (body: any) => {
      await apiRequest("POST", "/api/ops/jobs", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ops/jobs/stats"] });
      setDialogOpen(false);
      setJobType(JOB_TYPES[0]);
      setPayload("");
      setPriority("0");
      toast({ title: "Job enqueued", description: "New job has been added to the queue." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to enqueue job", description: err.message, variant: "destructive" });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/ops/jobs/${id}/cancel`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ops/jobs/stats"] });
      toast({ title: "Job cancelled" });
    },
    onError: (err: Error) => {
      toast({ title: "Cancel failed", description: err.message, variant: "destructive" });
    },
  });

  function handleEnqueue() {
    let parsedPayload = {};
    if (payload.trim()) {
      try {
        parsedPayload = JSON.parse(payload);
      } catch {
        parsedPayload = { raw: payload };
      }
    }
    enqueueMutation.mutate({
      type: jobType,
      payload: parsedPayload,
      priority: parseInt(priority, 10) || 0,
    });
  }

  const isLoading = workerLoading || statsLoading || jobsLoading;

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="worker-queue-loading">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-3">
                <Skeleton className="h-12 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
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

  if (workerError || statsError || jobsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load worker queue data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchWorker()}>
          Try Again
        </Button>
      </div>
    );
  }

  const statItems = [
    { label: "Pending", value: jobStats?.pending ?? 0, icon: Clock, color: "text-blue-500" },
    { label: "Running", value: jobStats?.running ?? 0, icon: Loader2, color: "text-yellow-500" },
    { label: "Completed", value: jobStats?.completed ?? 0, icon: CheckCircle2, color: "text-green-500" },
    { label: "Failed", value: jobStats?.failed ?? 0, icon: XCircle, color: "text-red-500" },
  ];

  return (
    <div className="space-y-4">
      <Card data-testid="card-worker-status">
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-muted/50">
                <Server className="h-4 w-4 text-muted-foreground" />
              </div>
              <div>
                <div className="text-sm font-semibold">Worker Status</div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                  <span className="flex items-center gap-1">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${workerStatus?.running ? "bg-green-500" : "bg-red-500"}`}
                    />
                    {workerStatus?.running ? "Running" : "Stopped"}
                  </span>
                  <span>Active Jobs: {workerStatus?.activeJobs ?? 0}</span>
                  <span>Poll Interval: {workerStatus?.pollIntervalMs ?? 0}ms</span>
                </div>
              </div>
            </div>
            <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
              <DialogTrigger asChild>
                <Button data-testid="button-enqueue-job">
                  <Plus className="h-4 w-4 mr-2" />
                  Enqueue Job
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Enqueue New Job</DialogTitle>
                </DialogHeader>
                <div className="space-y-4 pt-2">
                  <div className="space-y-2">
                    <Label>Job Type</Label>
                    <Select value={jobType} onValueChange={setJobType}>
                      <SelectTrigger data-testid="select-job-type">
                        <SelectValue placeholder="Select job type" />
                      </SelectTrigger>
                      <SelectContent>
                        {JOB_TYPES.map((t) => (
                          <SelectItem key={t} value={t}>
                            {t}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Payload (JSON)</Label>
                    <Textarea
                      value={payload}
                      onChange={(e) => setPayload(e.target.value)}
                      placeholder='{"key": "value"}'
                      data-testid="input-job-payload"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Priority</Label>
                    <Input
                      type="number"
                      value={priority}
                      onChange={(e) => setPriority(e.target.value)}
                      placeholder="0"
                      data-testid="input-job-priority"
                    />
                  </div>
                  <Button
                    className="w-full"
                    onClick={handleEnqueue}
                    disabled={enqueueMutation.isPending}
                    data-testid="button-submit-job"
                  >
                    {enqueueMutation.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Plus className="h-4 w-4 mr-2" />
                    )}
                    Enqueue Job
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="card-job-stats">
        {statItems.map((stat) => (
          <Card key={stat.label}>
            <CardContent className="p-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                  <span className="text-xs text-muted-foreground">{stat.label}</span>
                </div>
                <span
                  className="text-lg font-bold tabular-nums"
                  data-testid={`value-${stat.label.toLowerCase()}-count`}
                >
                  {stat.value}
                </span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {!jobs || jobs.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Database className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No jobs in queue</p>
            <p className="text-xs text-muted-foreground mt-1">Enqueue a job to get started</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {jobs.map((job: any, idx: number) => (
            <Card key={job.id || idx} data-testid={`card-job-${job.id || idx}`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold">{job.type}</span>
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${jobStatusStyle(job.status)}`}
                      >
                        {job.status}
                      </span>
                      {job.priority != null && job.priority !== 0 && (
                        <Badge
                          variant="outline"
                          className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                        >
                          Priority: {job.priority}
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Created: {formatTimestamp(job.createdAt)}
                      </span>
                      {job.startedAt && <span>Started: {formatTimestamp(job.startedAt)}</span>}
                      {job.completedAt && <span>Completed: {formatTimestamp(job.completedAt)}</span>}
                    </div>
                    {job.errorMessage && (
                      <div className="text-xs text-red-500 bg-red-500/5 rounded p-2">{job.errorMessage}</div>
                    )}
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {(job.status === "pending" || job.status === "running") && (
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => cancelMutation.mutate(job.id)}
                        disabled={cancelMutation.isPending}
                        data-testid={`button-cancel-job-${job.id}`}
                      >
                        <XCircle className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function SLODashboardTab() {
  const { toast } = useToast();
  const [createOpen, setCreateOpen] = useState(false);
  const [service, setService] = useState("");
  const [metric, setMetric] = useState("");
  const [targetValue, setTargetValue] = useState("");
  const [operator, setOperator] = useState(">=");
  const [windowMinutes, setWindowMinutes] = useState("60");
  const [description, setDescription] = useState("");

  const {
    data: sloRaw,
    isLoading,
    isError: _sloError,
    refetch: _refetchSlo,
  } = useQuery<any>({
    queryKey: ["/api/ops/slo"],
  });

  const sloData = (() => {
    if (!sloRaw) return [];
    const targets = sloRaw.targets || [];
    const evals = sloRaw.evaluations || [];
    return targets.map((t: any) => {
      const ev = evals.find((e: any) => e.sloId === t.id);
      return {
        ...t,
        targetValue: t.target,
        actual: ev?.actual ?? null,
        breached: ev?.breached ?? null,
      };
    });
  })();

  const seedMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/ops/slo-targets/seed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/slo"] });
      toast({ title: "SLOs seeded", description: "Default SLO targets have been created." });
    },
    onError: (err: Error) => {
      toast({ title: "Seed failed", description: err.message, variant: "destructive" });
    },
  });

  const createMutation = useMutation({
    mutationFn: async (body: any) => {
      await apiRequest("POST", "/api/ops/slo-targets", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/slo"] });
      setCreateOpen(false);
      setService("");
      setMetric("");
      setTargetValue("");
      setOperator(">=");
      setWindowMinutes("60");
      setDescription("");
      toast({ title: "SLO target created" });
    },
    onError: (err: Error) => {
      toast({ title: "Create failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/ops/slo-targets/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/slo"] });
      toast({ title: "SLO target deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  function handleCreate() {
    if (!service.trim() || !metric.trim() || !targetValue.trim()) return;
    createMutation.mutate({
      service: service.trim(),
      metric: metric.trim(),
      target: parseFloat(targetValue),
      operator,
      windowMinutes: parseInt(windowMinutes, 10) || 60,
      description: description.trim() || null,
    });
  }

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="slo-loading">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-20 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Gauge className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">SLO Targets</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {sloData?.length ?? 0}
          </Badge>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            onClick={() => seedMutation.mutate()}
            disabled={seedMutation.isPending}
            data-testid="button-seed-slos"
          >
            {seedMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Database className="h-4 w-4 mr-2" />
            )}
            Seed Default SLOs
          </Button>
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-create-slo">
                <Plus className="h-4 w-4 mr-2" />
                Create SLO
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create SLO Target</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 pt-2">
                <div className="space-y-2">
                  <Label>Service</Label>
                  <Input
                    value={service}
                    onChange={(e) => setService(e.target.value)}
                    placeholder="e.g. api"
                    data-testid="input-slo-service"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Metric</Label>
                  <Input
                    value={metric}
                    onChange={(e) => setMetric(e.target.value)}
                    placeholder="e.g. availability"
                    data-testid="input-slo-metric"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <Label>Target Value</Label>
                    <Input
                      type="number"
                      step="0.01"
                      value={targetValue}
                      onChange={(e) => setTargetValue(e.target.value)}
                      placeholder="99.9"
                      data-testid="input-slo-target"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Operator</Label>
                    <Select value={operator} onValueChange={setOperator}>
                      <SelectTrigger data-testid="select-slo-operator">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value=">=">{">="} (at least)</SelectItem>
                        <SelectItem value="<=">{"<="} (at most)</SelectItem>
                        <SelectItem value=">">{">"} (greater than)</SelectItem>
                        <SelectItem value="<">{"<"} (less than)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Window (minutes)</Label>
                  <Input
                    type="number"
                    value={windowMinutes}
                    onChange={(e) => setWindowMinutes(e.target.value)}
                    placeholder="60"
                    data-testid="input-slo-window"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Description</Label>
                  <Textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Describe this SLO target..."
                    data-testid="input-slo-description"
                  />
                </div>
                <Button
                  className="w-full"
                  onClick={handleCreate}
                  disabled={createMutation.isPending || !service.trim() || !metric.trim() || !targetValue.trim()}
                  data-testid="button-submit-slo"
                >
                  {createMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4 mr-2" />
                  )}
                  Create SLO Target
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {!sloData || sloData.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Target className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No SLO targets configured</p>
            <p className="text-xs text-muted-foreground mt-1">Seed default SLOs or create a custom target</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {sloData.map((slo: any) => {
            const breached = slo.actual != null ? slo.breached : null;
            return (
              <Card key={slo.id} data-testid={`card-slo-${slo.id}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold">{slo.service}</span>
                        <Badge
                          variant="outline"
                          className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                        >
                          {slo.metric}
                        </Badge>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${sloStatusStyle(breached)}`}
                        >
                          {breached === null ? "No Data" : breached ? "Breached" : "Met"}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        <span>
                          Target:{" "}
                          <span className="font-medium text-foreground">
                            {slo.operator} {slo.targetValue}
                          </span>
                        </span>
                        {slo.actual != null && (
                          <span>
                            Actual:{" "}
                            <span className={`font-medium ${breached ? "text-red-500" : "text-green-500"}`}>
                              {typeof slo.actual === "number" ? slo.actual.toFixed(2) : slo.actual}
                            </span>
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {slo.windowMinutes}m window
                        </span>
                      </div>
                      {slo.description && <p className="text-xs text-muted-foreground">{slo.description}</p>}
                    </div>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => deleteMutation.mutate(slo.id)}
                      disabled={deleteMutation.isPending}
                      data-testid={`button-delete-slo-${slo.id}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function DRRunbooksTab() {
  const { toast } = useToast();
  const [createOpen, setCreateOpen] = useState(false);
  const [testOpen, setTestOpen] = useState<string | null>(null);
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  const [title, setTitle] = useState("");
  const [rbDescription, setRbDescription] = useState("");
  const [category, setCategory] = useState("backup");
  const [steps, setSteps] = useState("");
  const [rtoMinutes, setRtoMinutes] = useState("");
  const [rpoMinutes, setRpoMinutes] = useState("");
  const [owner, setOwner] = useState("");

  const [testResult, setTestResult] = useState("pass");
  const [testNotes, setTestNotes] = useState("");

  const {
    data: runbooks,
    isLoading,
    isError: _runbooksError,
    refetch: _refetchRunbooks,
  } = useQuery<any[]>({
    queryKey: ["/api/ops/dr-runbooks"],
  });

  const seedMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/ops/dr-runbooks/seed");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/dr-runbooks"] });
      toast({ title: "Runbooks seeded", description: "Default DR runbooks have been created." });
    },
    onError: (err: Error) => {
      toast({ title: "Seed failed", description: err.message, variant: "destructive" });
    },
  });

  const createMutation = useMutation({
    mutationFn: async (body: any) => {
      await apiRequest("POST", "/api/ops/dr-runbooks", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/dr-runbooks"] });
      setCreateOpen(false);
      setTitle("");
      setRbDescription("");
      setCategory("backup");
      setSteps("");
      setRtoMinutes("");
      setRpoMinutes("");
      setOwner("");
      toast({ title: "Runbook created" });
    },
    onError: (err: Error) => {
      toast({ title: "Create failed", description: err.message, variant: "destructive" });
    },
  });

  const testMutation = useMutation({
    mutationFn: async ({ id, result, notes }: { id: string; result: string; notes: string }) => {
      await apiRequest("POST", `/api/ops/dr-runbooks/${id}/test`, { result, notes });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/dr-runbooks"] });
      setTestOpen(null);
      setTestResult("pass");
      setTestNotes("");
      toast({ title: "Test drill recorded" });
    },
    onError: (err: Error) => {
      toast({ title: "Test failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/ops/dr-runbooks/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ops/dr-runbooks"] });
      toast({ title: "Runbook deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  function handleCreate() {
    if (!title.trim()) return;
    let parsedSteps: any[] = [];
    if (steps.trim()) {
      try {
        parsedSteps = JSON.parse(steps);
      } catch {
        parsedSteps = steps
          .split("\n")
          .filter(Boolean)
          .map((s, i) => ({ step: i + 1, action: s.trim() }));
      }
    }
    createMutation.mutate({
      title: title.trim(),
      description: rbDescription.trim() || null,
      category,
      steps: parsedSteps,
      rtoMinutes: parseInt(rtoMinutes, 10) || null,
      rpoMinutes: parseInt(rpoMinutes, 10) || null,
      owner: owner.trim() || null,
    });
  }

  function toggleSteps(id: string) {
    setExpandedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="runbooks-loading">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-24 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <BookOpen className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">DR Runbooks</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {runbooks?.length ?? 0}
          </Badge>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            onClick={() => seedMutation.mutate()}
            disabled={seedMutation.isPending}
            data-testid="button-seed-runbooks"
          >
            {seedMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Database className="h-4 w-4 mr-2" />
            )}
            Seed Default Runbooks
          </Button>
          <Dialog open={createOpen} onOpenChange={setCreateOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-create-runbook">
                <Plus className="h-4 w-4 mr-2" />
                Create Runbook
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create DR Runbook</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 pt-2 max-h-[60vh] overflow-y-auto">
                <div className="space-y-2">
                  <Label>Title</Label>
                  <Input
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="Runbook title"
                    data-testid="input-runbook-title"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Description</Label>
                  <Textarea
                    value={rbDescription}
                    onChange={(e) => setRbDescription(e.target.value)}
                    placeholder="Describe the runbook..."
                    data-testid="input-runbook-description"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Category</Label>
                  <Select value={category} onValueChange={setCategory}>
                    <SelectTrigger data-testid="select-runbook-category">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="backup">Backup</SelectItem>
                      <SelectItem value="restore">Restore</SelectItem>
                      <SelectItem value="failover">Failover</SelectItem>
                      <SelectItem value="data_recovery">Data Recovery</SelectItem>
                      <SelectItem value="incident_response">Incident Response</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Steps (JSON array or one per line)</Label>
                  <Textarea
                    value={steps}
                    onChange={(e) => setSteps(e.target.value)}
                    placeholder='[{"step": 1, "action": "..."}]'
                    data-testid="input-runbook-steps"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <Label>RTO (minutes)</Label>
                    <Input
                      type="number"
                      value={rtoMinutes}
                      onChange={(e) => setRtoMinutes(e.target.value)}
                      placeholder="30"
                      data-testid="input-runbook-rto"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>RPO (minutes)</Label>
                    <Input
                      type="number"
                      value={rpoMinutes}
                      onChange={(e) => setRpoMinutes(e.target.value)}
                      placeholder="15"
                      data-testid="input-runbook-rpo"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Owner</Label>
                  <Input
                    value={owner}
                    onChange={(e) => setOwner(e.target.value)}
                    placeholder="Team or person"
                    data-testid="input-runbook-owner"
                  />
                </div>
                <Button
                  className="w-full"
                  onClick={handleCreate}
                  disabled={createMutation.isPending || !title.trim()}
                  data-testid="button-submit-runbook"
                >
                  {createMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="h-4 w-4 mr-2" />
                  )}
                  Create Runbook
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {!runbooks || runbooks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <BookOpen className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No DR runbooks</p>
            <p className="text-xs text-muted-foreground mt-1">Seed defaults or create a custom runbook</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {runbooks.map((rb: any) => {
            const stepsArr = (() => {
              try {
                if (Array.isArray(rb.steps)) return rb.steps;
                if (typeof rb.steps === "string") return JSON.parse(rb.steps);
                return [];
              } catch {
                return [];
              }
            })();
            const isExpanded = expandedSteps.has(rb.id);

            return (
              <Card key={rb.id} data-testid={`card-runbook-${rb.id}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold">{rb.title}</span>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${drCategoryStyle(rb.category)}`}
                        >
                          {rb.category?.replace(/_/g, " ")}
                        </span>
                        {rb.lastTestResult && (
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${testResultStyle(rb.lastTestResult)}`}
                          >
                            {rb.lastTestResult}
                          </span>
                        )}
                      </div>
                      {rb.description && <p className="text-xs text-muted-foreground">{rb.description}</p>}
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        {rb.rtoMinutes != null && (
                          <span>
                            RTO: <span className="font-medium text-foreground">{rb.rtoMinutes}m</span>
                          </span>
                        )}
                        {rb.rpoMinutes != null && (
                          <span>
                            RPO: <span className="font-medium text-foreground">{rb.rpoMinutes}m</span>
                          </span>
                        )}
                        {rb.owner && (
                          <span>
                            Owner: <span className="font-medium text-foreground">{rb.owner}</span>
                          </span>
                        )}
                        {rb.lastTestedAt && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            Last tested: {formatTimestamp(rb.lastTestedAt)}
                          </span>
                        )}
                      </div>
                      {stepsArr.length > 0 && (
                        <div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleSteps(rb.id)}
                            data-testid={`button-toggle-steps-${rb.id}`}
                          >
                            {isExpanded ? "Hide Steps" : `Show Steps (${stepsArr.length})`}
                          </Button>
                          {isExpanded && (
                            <div className="mt-2 space-y-1 pl-2 border-l-2 border-border">
                              {stepsArr.map((step: any, si: number) => (
                                <div key={si} className="text-xs text-muted-foreground">
                                  <span className="font-medium text-foreground">{step.step || si + 1}.</span>{" "}
                                  {step.action || step.description || JSON.stringify(step)}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <Dialog
                        open={testOpen === rb.id}
                        onOpenChange={(open) => {
                          setTestOpen(open ? rb.id : null);
                          if (!open) {
                            setTestResult("pass");
                            setTestNotes("");
                          }
                        }}
                      >
                        <DialogTrigger asChild>
                          <Button size="icon" variant="ghost" data-testid={`button-test-runbook-${rb.id}`}>
                            <Play className="h-4 w-4" />
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Record Test Drill</DialogTitle>
                          </DialogHeader>
                          <div className="space-y-4 pt-2">
                            <p className="text-sm text-muted-foreground">
                              Recording test for: <span className="font-medium text-foreground">{rb.title}</span>
                            </p>
                            <div className="space-y-2">
                              <Label>Result</Label>
                              <Select value={testResult} onValueChange={setTestResult}>
                                <SelectTrigger data-testid="select-test-result">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="pass">Pass</SelectItem>
                                  <SelectItem value="fail">Fail</SelectItem>
                                  <SelectItem value="partial">Partial</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                            <div className="space-y-2">
                              <Label>Notes</Label>
                              <Textarea
                                value={testNotes}
                                onChange={(e) => setTestNotes(e.target.value)}
                                placeholder="Test observations..."
                                data-testid="input-test-notes"
                              />
                            </div>
                            <Button
                              className="w-full"
                              onClick={() => testMutation.mutate({ id: rb.id, result: testResult, notes: testNotes })}
                              disabled={testMutation.isPending}
                              data-testid="button-submit-test"
                            >
                              {testMutation.isPending ? (
                                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                              ) : (
                                <CheckCircle2 className="h-4 w-4 mr-2" />
                              )}
                              Record Result
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteMutation.mutate(rb.id)}
                        disabled={deleteMutation.isPending}
                        data-testid={`button-delete-runbook-${rb.id}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function AlertArchiveTab() {
  const { toast } = useToast();
  const [offset, setOffset] = useState(0);
  const limit = 20;

  const {
    data: archiveData,
    isLoading,
    isError: _archiveError,
    refetch: _refetchArchive,
  } = useQuery<any>({
    queryKey: ["/api/alerts/archive", offset, limit],
    queryFn: async () => {
      const res = await fetch(`/api/alerts/archive?offset=${offset}&limit=${limit}`, { credentials: "include" });
      if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
      return res.json();
    },
  });

  const restoreMutation = useMutation({
    mutationFn: async (alertId: string) => {
      await apiRequest("POST", "/api/alerts/archive/restore", { alertIds: [alertId] });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts/archive"] });
      toast({ title: "Alert restored", description: "Alert has been moved back to active." });
    },
    onError: (err: Error) => {
      toast({ title: "Restore failed", description: err.message, variant: "destructive" });
    },
  });

  const alerts = archiveData?.alerts || archiveData?.items || (Array.isArray(archiveData) ? archiveData : []);
  const totalCount = archiveData?.total ?? archiveData?.totalCount ?? alerts.length;

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="archive-loading">
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

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Archive className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Alert Archive</h2>
          <Badge
            variant="outline"
            className="no-default-hover-elevate no-default-active-elevate text-[10px]"
            data-testid="text-archive-count"
          >
            {totalCount}
          </Badge>
        </div>
      </div>

      {alerts.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Archive className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No archived alerts</p>
            <p className="text-xs text-muted-foreground mt-1">Archived alerts will appear here</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="space-y-2">
            {alerts.map((alert: any, idx: number) => (
              <Card key={alert.id || idx} data-testid={`card-archive-${alert.id || idx}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold">
                          {alert.title || alert.name || `Alert #${alert.id}`}
                        </span>
                        {alert.severity && (
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${severityStyle(alert.severity)}`}
                          >
                            {alert.severity}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        {alert.source && (
                          <span>
                            Source: <span className="font-medium text-foreground">{alert.source}</span>
                          </span>
                        )}
                        {alert.archivedAt && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            Archived: {formatTimestamp(alert.archivedAt)}
                          </span>
                        )}
                        {alert.archiveReason && (
                          <span>
                            Reason: <span className="font-medium text-foreground">{alert.archiveReason}</span>
                          </span>
                        )}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => restoreMutation.mutate(alert.id)}
                      disabled={restoreMutation.isPending}
                      data-testid={`button-restore-alert-${alert.id}`}
                    >
                      {restoreMutation.isPending ? (
                        <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3 w-3 mr-1" />
                      )}
                      Restore
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <span className="text-xs text-muted-foreground">
              Showing {offset + 1}-{Math.min(offset + limit, totalCount)} of {totalCount}
            </span>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}
                data-testid="button-archive-prev"
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={offset + limit >= totalCount}
                onClick={() => setOffset(offset + limit)}
                data-testid="button-archive-next"
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default function OperationsPage() {
  const { data: workerStatus } = useQuery<any>({
    queryKey: ["/api/ops/worker/status"],
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold" data-testid="text-page-title">
            Operations Center
          </h1>
          <p className="text-sm text-muted-foreground">Worker queue, SLOs, disaster recovery, and data management</p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`inline-block w-2.5 h-2.5 rounded-full ${workerStatus?.running ? "bg-green-500" : "bg-red-500"}`}
          />
          <span className="text-xs text-muted-foreground">
            {workerStatus?.running ? "System Healthy" : "System Degraded"}
          </span>
        </div>
      </div>
      <Tabs defaultValue="worker-queue">
        <TabsList>
          <TabsTrigger value="worker-queue" data-testid="tab-worker-queue">
            Worker Queue
          </TabsTrigger>
          <TabsTrigger value="slo-dashboard" data-testid="tab-slo-dashboard">
            SLO Dashboard
          </TabsTrigger>
          <TabsTrigger value="dr-runbooks" data-testid="tab-dr-runbooks">
            DR Runbooks
          </TabsTrigger>
          <TabsTrigger value="alert-archive" data-testid="tab-alert-archive">
            Alert Archive
          </TabsTrigger>
        </TabsList>
        <TabsContent value="worker-queue">
          <WorkerQueueTab />
        </TabsContent>
        <TabsContent value="slo-dashboard">
          <SLODashboardTab />
        </TabsContent>
        <TabsContent value="dr-runbooks">
          <DRRunbooksTab />
        </TabsContent>
        <TabsContent value="alert-archive">
          <AlertArchiveTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
