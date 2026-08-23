import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, EyeOff, FileText, RefreshCw } from "lucide-react";
import { useLocation, useSearch } from "wouter";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

type ReplayRun = { id: string; status: string; createdAt: string | null };
type Report = {
  generatedAt: string;
  runId: string;
  window: { from: string; to: string };
  partialCoverage: boolean;
  alertsInWindow: { total: number; bySource: Array<{ source: string; count: number }> };
  replayCoverage: { replayed: number; inWindow: number; rate: number | null; rateReason: string | null };
  dispositionMix: { counts: Record<string, number>; abstentionCount: number; decisionIds: string[] };
  autoCloseCandidates: { count: number; threshold: number; decisionIds: string[] };
  humanAgreement: {
    agreed: number;
    definitive: number;
    coverage: { adjudicated: number; replayed: number };
    rate: number | null;
    rateReason: string | null;
  };
  mttrBaseline: {
    averageMinutes: number | null;
    sampleSize: number;
    unresolvedExcluded: number;
    unavailableReason: string | null;
  };
  whatWeCouldNotSee: {
    replayedDecisions: number;
    retrievalUnavailable: number;
    retrievalNotAttempted: number;
    zeroEvidenceRows: number;
    decisionIds: string[];
  };
  attackCoverage: { tactics: string[]; techniques: string[]; absentStatement: string };
  runCost: {
    inputTokens: number | null;
    outputTokens: number | null;
    costUsd: number | null;
    unmeasuredInvocations: number;
  };
};

async function getEnvelope<T>(method: string, url: string): Promise<T> {
  const response = await apiRequest(method, url);
  return (await response.json()) as T;
}

export default function SocRealityReportPage() {
  const [, setLocation] = useLocation();
  const search = useSearch();
  const initialRunId = new URLSearchParams(search).get("runId") ?? "";
  const [runId, setRunId] = useState(initialRunId);
  const runsQuery = useQuery<ReplayRun[]>({
    queryKey: ["/api/ai/replays"],
    queryFn: () => getEnvelope("GET", "/api/ai/replays"),
  });
  const reportQuery = useQuery<Report>({
    queryKey: ["/api/ai/replays", runId, "report"],
    queryFn: () => getEnvelope("GET", `/api/ai/replays/${encodeURIComponent(runId)}/report`),
    enabled: Boolean(runId),
  });
  const report = reportQuery.data;
  const activeRun = runsQuery.data?.find((run) => run.id === runId);

  if (runsQuery.isLoading)
    return (
      <div className="space-y-4 p-6">
        <Skeleton className="h-10 w-80" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <FileText className="h-6 w-6" />
          SOC Reality Report
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Evidence from one replay run only. No extrapolation, business-value estimates, or incident-prevention claims.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Select a replay run</CardTitle>
          <CardDescription>Reports are tenant-scoped and generated only for completed or failed runs.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Select
            value={runId}
            onValueChange={(value) => {
              setRunId(value);
              setLocation(`/soc-reality-report?runId=${encodeURIComponent(value)}`);
            }}
          >
            <SelectTrigger className="w-full md:w-[420px]">
              <SelectValue placeholder="Choose a replay run" />
            </SelectTrigger>
            <SelectContent>
              {(runsQuery.data ?? []).map((run) => (
                <SelectItem key={run.id} value={run.id}>
                  {run.id} · {run.status}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {activeRun && <Badge variant="outline">{activeRun.status}</Badge>}
        </CardContent>
      </Card>
      {reportQuery.isLoading && <Skeleton className="h-96 w-full" />}
      {reportQuery.isError && (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p>{(reportQuery.error as Error).message}</p>
            <Button variant="outline" onClick={() => reportQuery.refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Retry
            </Button>
          </CardContent>
        </Card>
      )}
      {report && (
        <>
          <Card className={report.partialCoverage ? "border-amber-500/50 bg-amber-500/5" : "border-emerald-500/30"}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {report.partialCoverage ? (
                  <AlertTriangle className="h-5 w-5 text-amber-500" />
                ) : (
                  <FileText className="h-5 w-5" />
                )}{" "}
                {report.partialCoverage ? "Partial replay coverage" : "Replay coverage"}
              </CardTitle>
              <CardDescription>
                {report.window.from} → {report.window.to} · replayed {report.replayCoverage.replayed} of{" "}
                {report.replayCoverage.inWindow} alerts in the window
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm">
                {report.replayCoverage.rate == null
                  ? report.replayCoverage.rateReason
                  : `${(report.replayCoverage.rate * 100).toFixed(1)}% (${report.replayCoverage.replayed}/${report.replayCoverage.inWindow})`}
              </p>
            </CardContent>
          </Card>
          <Card className="border-amber-500/60 bg-amber-500/5">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <EyeOff className="h-5 w-5 text-amber-500" />
                What we could not see
              </CardTitle>
              <CardDescription>Unavailable, not-attempted, and empty evidence are reported separately.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 text-sm md:grid-cols-4">
              <div>
                <p className="text-muted-foreground">Replay decisions</p>
                <p className="text-xl font-semibold">{report.whatWeCouldNotSee.replayedDecisions}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Retrieval unavailable</p>
                <p className="text-xl font-semibold">{report.whatWeCouldNotSee.retrievalUnavailable}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Retrieval not attempted</p>
                <p className="text-xl font-semibold">{report.whatWeCouldNotSee.retrievalNotAttempted}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Zero evidence rows</p>
                <p className="text-xl font-semibold">{report.whatWeCouldNotSee.zeroEvidenceRows}</p>
              </div>
            </CardContent>
          </Card>
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Alerts in window</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold">{report.alertsInWindow.total}</p>
                <div className="mt-3 space-y-1 text-sm">
                  {report.alertsInWindow.bySource.map((item) => (
                    <p key={item.source}>
                      {item.source}: {item.count}
                    </p>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>AI disposition mix</CardTitle>
                <CardDescription>
                  Abstentions: {report.dispositionMix.abstentionCount} (failed, unmappable, or below acting threshold)
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-1 text-sm">
                  {Object.entries(report.dispositionMix.counts).map(([key, count]) => (
                    <p key={key}>
                      {key}: {count}
                    </p>
                  ))}
                </div>
                <a
                  className="mt-3 inline-block text-sm underline"
                  href={`/autonomous-soc?replayRunId=${encodeURIComponent(report.runId)}`}
                >
                  View replay decisions
                </a>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Would have been auto-closed under this policy</CardTitle>
                <CardDescription>
                  Benign decisions at or above {Math.round(report.autoCloseCandidates.threshold * 100)}% confidence with
                  no safety veto.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold">{report.autoCloseCandidates.count}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Human agreement</CardTitle>
                <CardDescription>
                  Batch B adjudications only; judgements may postdate the decision window.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold">
                  {report.humanAgreement.rate == null
                    ? "Withheld"
                    : `${(report.humanAgreement.rate * 100).toFixed(1)}%`}
                </p>
                <p className="text-sm text-muted-foreground">
                  {report.humanAgreement.agreed}/{report.humanAgreement.definitive} definitive adjudications · coverage{" "}
                  {report.humanAgreement.coverage.adjudicated}/{report.humanAgreement.coverage.replayed}
                  {report.humanAgreement.rateReason ? ` · ${report.humanAgreement.rateReason}` : ""}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>MTTR baseline</CardTitle>
              </CardHeader>
              <CardContent>
                {report.mttrBaseline.averageMinutes == null ? (
                  <p className="text-sm text-muted-foreground">{report.mttrBaseline.unavailableReason}</p>
                ) : (
                  <p className="text-2xl font-semibold">{report.mttrBaseline.averageMinutes.toFixed(1)} minutes</p>
                )}
                <p className="text-sm text-muted-foreground">
                  Sample size: {report.mttrBaseline.sampleSize}; unresolved excluded:{" "}
                  {report.mttrBaseline.unresolvedExcluded}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Run cost</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 text-sm">
                <p>Input tokens: {report.runCost.inputTokens ?? "unmeasured"}</p>
                <p>Output tokens: {report.runCost.outputTokens ?? "unmeasured"}</p>
                <p>Cost: {report.runCost.costUsd == null ? "unmeasured" : `$${report.runCost.costUsd.toFixed(6)}`}</p>
                <p>Invocations with unmeasured fields: {report.runCost.unmeasuredInvocations}</p>
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>ATT&amp;CK coverage</CardTitle>
              <CardDescription>{report.attackCoverage.absentStatement}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 text-sm md:grid-cols-2">
              <div>
                <p className="font-medium">Tactics present</p>
                <p className="mt-1 text-muted-foreground">
                  {report.attackCoverage.tactics.length
                    ? report.attackCoverage.tactics.join(", ")
                    : "No alerts mapped to a tactic in this window."}
                </p>
              </div>
              <div>
                <p className="font-medium">Techniques present</p>
                <p className="mt-1 text-muted-foreground">
                  {report.attackCoverage.techniques.length
                    ? report.attackCoverage.techniques.join(", ")
                    : "No alerts mapped to a technique in this window."}
                </p>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
