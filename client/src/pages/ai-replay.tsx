import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Clock, FileSearch, Loader2, Play, RefreshCw, XCircle, CheckCircle2 } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

type ReplayRun = {
  id: string;
  fromAt: string;
  toAt: string;
  source: string | null;
  severity: string | null;
  reason: string;
  status: string;
  cursor: number;
  totalCount: number;
  processedCount: number;
  succeededCount: number;
  failedCount: number;
  concurrency: number;
  error: string | null;
  createdAt: string | null;
  completedAt: string | null;
};

async function envelope<T>(url: string): Promise<T> {
  const response = await apiRequest("GET", url);
  return (await response.json()) as T;
}

function statusIcon(status: string) {
  if (status === "running") return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
  if (status === "completed") return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (status === "failed") return <XCircle className="h-4 w-4 text-destructive" />;
  return <Clock className="h-4 w-4 text-muted-foreground" />;
}

export default function AiReplayPage() {
  usePageTitle("AI Historical Replay");
  const { toast } = useToast();
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");
  const [reason, setReason] = useState("");
  const [concurrency, setConcurrency] = useState("1");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const runsQuery = useQuery<ReplayRun[]>({
    queryKey: ["/api/ai/replays"],
    queryFn: () => envelope<ReplayRun[]>("/api/ai/replays"),
    refetchInterval: (query) =>
      query.state.data?.some((run) => run.status === "pending" || run.status === "running") ? 3000 : false,
  });
  const selectedRunQuery = useQuery<ReplayRun>({
    queryKey: ["/api/ai/replays", selectedId],
    queryFn: () => envelope<ReplayRun>(`/api/ai/replays/${selectedId}`),
    enabled: Boolean(selectedId),
    refetchInterval: (query) =>
      query.state.data?.status === "pending" || query.state.data?.status === "running" ? 2000 : false,
  });
  const startMutation = useMutation({
    mutationFn: async () => {
      if (!from || !to || !reason.trim()) throw new Error("From, to, and a nonempty reason are required.");
      if (new Date(to) <= new Date(from)) throw new Error("The end of the replay window must be after its start.");
      const response = await apiRequest("POST", "/api/ai/replays", {
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
        ...(source.trim() ? { source: source.trim() } : {}),
        ...(severity ? { severity } : {}),
        reason: reason.trim(),
        concurrency: Number(concurrency),
      });
      const run = (await response.json()) as ReplayRun;
      if (!run.id) throw new Error("Replay could not be started.");
      return run;
    },
    onSuccess: (run) => {
      setSelectedId(run.id);
      setValidationError(null);
      queryClient.invalidateQueries({ queryKey: ["/api/ai/replays"] });
      toast({ title: "Historical replay started" });
    },
    onError: (error: Error) => setValidationError(error.message),
  });
  const runs = runsQuery.data ?? [];
  const selectedRun = selectedRunQuery.data ?? runs.find((run) => run.id === selectedId) ?? null;
  const progress = useMemo(
    () => (selectedRun && selectedRun.totalCount > 0 ? (selectedRun.processedCount / selectedRun.totalCount) * 100 : 0),
    [selectedRun],
  );

  if (runsQuery.isLoading) {
    return (
      <div className="space-y-4 p-6">
        <Skeleton className="h-10 w-80" />
        <Skeleton className="h-72 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }
  if (runsQuery.isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p>Replay runs could not be loaded.</p>
            <Button variant="outline" onClick={() => runsQuery.refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <FileSearch className="h-6 w-6" />
          Historical replay
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Re-run analysis against existing alerts without changing alerts, incidents, or response state.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Start a replay</CardTitle>
          <CardDescription>Use an explicit UTC time window and record why this replay is being run.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2 text-sm">
            <Label htmlFor="replay-from">From</Label>
            <Input
              id="replay-from"
              type="datetime-local"
              value={from}
              onChange={(event) => setFrom(event.target.value)}
            />
          </label>
          <label className="space-y-2 text-sm">
            <Label htmlFor="replay-to">To</Label>
            <Input id="replay-to" type="datetime-local" value={to} onChange={(event) => setTo(event.target.value)} />
          </label>
          <label className="space-y-2 text-sm">
            <Label htmlFor="replay-source">Source (optional)</Label>
            <Input
              id="replay-source"
              value={source}
              onChange={(event) => setSource(event.target.value)}
              placeholder="Connector source"
            />
          </label>
          <label className="space-y-2 text-sm">
            <Label>Severity (optional)</Label>
            <Select value={severity || "all"} onValueChange={(value) => setSeverity(value === "all" ? "" : value)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All severities</SelectItem>
                {["critical", "high", "medium", "low", "informational"].map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </label>
          <label className="space-y-2 text-sm">
            <Label htmlFor="replay-concurrency">Concurrency (1–10)</Label>
            <Input
              id="replay-concurrency"
              type="number"
              min="1"
              max="10"
              value={concurrency}
              onChange={(event) => setConcurrency(event.target.value)}
            />
          </label>
          <label className="space-y-2 text-sm md:col-span-2">
            <Label htmlFor="replay-reason">Reason</Label>
            <Textarea
              id="replay-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Explain the purpose of this historical analysis"
            />
          </label>
          {validationError && <p className="text-sm text-destructive md:col-span-2">{validationError}</p>}
          <div className="md:col-span-2">
            <Button onClick={() => startMutation.mutate()} disabled={startMutation.isPending}>
              <Play className="mr-2 h-4 w-4" />
              {startMutation.isPending ? "Starting…" : "Start replay"}
            </Button>
          </div>
        </CardContent>
      </Card>
      {selectedRun && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {statusIcon(selectedRun.status)} Run progress <Badge variant="outline">{selectedRun.status}</Badge>
            </CardTitle>
            <CardDescription>
              {selectedRun.fromAt} → {selectedRun.toAt} · {selectedRun.reason}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {selectedRun.totalCount === 0 && selectedRun.status === "completed" ? (
              <p className="text-sm text-muted-foreground">
                No alerts matched this replay window and filters. No decisions were produced.
              </p>
            ) : (
              <>
                <Progress value={progress} />
                <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                  <div>
                    <p className="text-muted-foreground">Processed</p>
                    <p className="text-xl font-semibold">
                      {selectedRun.processedCount} / {selectedRun.totalCount}
                    </p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Succeeded</p>
                    <p className="text-xl font-semibold text-emerald-600">{selectedRun.succeededCount}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Failed</p>
                    <p className="text-xl font-semibold text-destructive">{selectedRun.failedCount}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Concurrency</p>
                    <p className="text-xl font-semibold">{selectedRun.concurrency}</p>
                  </div>
                </div>
              </>
            )}
            {selectedRun.error && (
              <div className="rounded border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                Replay stopped with an error: {selectedRun.error}
              </div>
            )}
            <a
              className="inline-flex items-center text-sm underline"
              href={`/autonomous-soc?replayRunId=${encodeURIComponent(selectedRun.id)}`}
            >
              View decisions produced by this run
            </a>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Replay runs</CardTitle>
        </CardHeader>
        <CardContent>
          {runs.length === 0 ? (
            <p className="py-6 text-sm text-muted-foreground">No replay runs have been started.</p>
          ) : (
            <div className="space-y-2">
              {runs.map((run) => (
                <button
                  key={run.id}
                  className={`w-full rounded border p-3 text-left hover:bg-muted/40 ${selectedId === run.id ? "border-primary" : ""}`}
                  onClick={() => setSelectedId(run.id)}
                >
                  <div className="flex items-center gap-2 text-sm">
                    {statusIcon(run.status)}
                    <span className="font-medium">{run.id}</span>
                    <Badge className="ml-auto" variant="outline">
                      {run.status}
                    </Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {run.processedCount}/{run.totalCount} processed ·{" "}
                    {new Date(run.createdAt ?? Date.now()).toLocaleString()}
                  </p>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
