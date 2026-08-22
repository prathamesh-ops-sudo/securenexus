import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Shield,
  AlertTriangle,
  RefreshCw,
  Play,
  Calendar,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Activity,
  Timer,
  BarChart3,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";

interface DrDrill {
  id: string;
  name: string;
  type: "failover" | "backup_restore" | "canary" | "chaos";
  status: "pending" | "scheduled" | "running" | "passed" | "failed" | "cancelled";
  scheduledAt: string;
  startedAt?: string;
  completedAt?: string;
  rpoSeconds?: number;
  rtoSeconds?: number;
  rpoTargetSeconds?: number;
  rtoTargetSeconds?: number;
  findings: string[];
}

export default function DrDrillSchedulerPage() {
  usePageTitle("DR Drill Scheduler & Canary Analysis");
  const { toast } = useToast();

  const {
    data: drills,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<DrDrill[]>({
    queryKey: ["/api/dr-drills"],
    queryFn: () => apiRequest("GET", "/api/dr-drills").then((r) => r.json()),
  });

  const runDrillMutation = useMutation({
    mutationFn: (type: string) =>
      apiRequest("POST", "/api/dr-drills", { type, name: `${type} drill - ${new Date().toISOString().slice(0, 10)}` }),
    onSuccess: () => {
      toast({ title: "DR drill requested" });
      queryClient.invalidateQueries({ queryKey: ["/api/dr-drills"] });
    },
    onError: () => toast({ title: "Failed to start drill", variant: "destructive" }),
  });

  const list = Array.isArray(drills) ? drills : [];

  const statusIcon = (s: string) => {
    if (s === "running") return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
    if (s === "passed") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    if (s === "scheduled") return <Calendar className="h-4 w-4 text-yellow-500" />;
    return <Clock className="h-4 w-4 text-muted-foreground" />;
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load DR drills</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" /> DR Drill Scheduler & Canary Analysis
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Request disaster recovery drills and monitor measured RPO/RTO results
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Button size="sm" onClick={() => runDrillMutation.mutate("failover")} disabled={runDrillMutation.isPending}>
            {runDrillMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-2 h-4 w-4" />
            )}
            Request Drill
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total Drills</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((d) => d.status === "passed").length}</p>
              <p className="text-xs text-muted-foreground">Passed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((d) => d.status === "failed").length}</p>
              <p className="text-xs text-muted-foreground">Failed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Calendar className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">
                {list.filter((d) => d.status === "pending" || d.status === "scheduled").length}
              </p>
              <p className="text-xs text-muted-foreground">Requested</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <Shield className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">No DR drill requests or measured results</p>
            <Button size="sm" onClick={() => runDrillMutation.mutate("failover")}>
              <Play className="mr-2 h-4 w-4" /> Request First Drill
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {list.map((d) => (
            <Card key={d.id}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {statusIcon(d.status)}
                    <div>
                      <p className="font-medium text-sm">{d.name}</p>
                      <p className="text-xs text-muted-foreground capitalize">
                        {d.type.replace(/_/g, " ")} &middot; {new Date(d.scheduledAt).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={d.status === "passed" ? "default" : d.status === "failed" ? "destructive" : "secondary"}
                    >
                      {d.status === "pending" ? "Requested — not executed" : d.status}
                    </Badge>
                    <Badge variant="outline" className="capitalize">
                      {d.type.replace(/_/g, " ")}
                    </Badge>
                  </div>
                </div>
                {(d.rpoSeconds !== undefined || d.rtoSeconds !== undefined) && (
                  <div className="grid grid-cols-2 gap-4">
                    {d.rpoSeconds !== undefined && d.rpoTargetSeconds !== undefined && (
                      <div>
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="text-muted-foreground">RPO</span>
                          <span>
                            {d.rpoSeconds}s / {d.rpoTargetSeconds}s target
                          </span>
                        </div>
                        <Progress value={Math.min((d.rpoSeconds / d.rpoTargetSeconds) * 100, 100)} />
                      </div>
                    )}
                    {d.rtoSeconds !== undefined && d.rtoTargetSeconds !== undefined && (
                      <div>
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="text-muted-foreground">RTO</span>
                          <span>
                            {d.rtoSeconds}s / {d.rtoTargetSeconds}s target
                          </span>
                        </div>
                        <Progress value={Math.min((d.rtoSeconds / d.rtoTargetSeconds) * 100, 100)} />
                      </div>
                    )}
                  </div>
                )}
                {d.findings && d.findings.length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs font-medium text-muted-foreground mb-1">Findings</p>
                    <ul className="space-y-1">
                      {d.findings.map((f, i) => (
                        <li key={i} className="text-xs flex items-start gap-1">
                          <AlertTriangle className="h-3 w-3 mt-0.5 text-yellow-500 shrink-0" />
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
