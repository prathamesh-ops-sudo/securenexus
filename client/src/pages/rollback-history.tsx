import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  RotateCcw,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  Eye,
  Loader2,
  ChevronDown,
  ChevronUp,
  Undo2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

interface RollbackEntry {
  id: string;
  orgId: string | null;
  originalActionId: string | null;
  actionType: string;
  target: string;
  rollbackAction: Record<string, unknown>;
  status: string;
  executedBy: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  createdAt: string | null;
  executedAt: string | null;
}

export default function RollbackHistoryPage() {
  usePageTitle("Response Action Rollback History");
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const {
    data: entries,
    isPending,
    isError,
    refetch,
  } = useQuery<RollbackEntry[]>({
    queryKey: ["/api/autonomous/rollbacks"],
    queryFn: () => apiRequest("GET", "/api/autonomous/rollbacks").then((r) => r.json()),
  });

  const executeMutation = useMutation({
    mutationFn: (rollbackId: string) => apiRequest("POST", `/api/autonomous/rollbacks/${rollbackId}/execute`),
    onSuccess: () => {
      toast({ title: "Rollback executed successfully" });
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/rollbacks"] });
    },
    onError: () => toast({ title: "Rollback execution failed", variant: "destructive" }),
  });

  const list = Array.isArray(entries) ? entries : [];

  const statusIcon = (s: string) => {
    if (s === "executed") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    if (s === "completed") return <Undo2 className="h-4 w-4 text-blue-500" />;
    return <Clock className="h-4 w-4 text-yellow-500" />;
  };

  if (isPending) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-20" />
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
            <p className="text-muted-foreground">Failed to load rollback history</p>
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
            <RotateCcw className="h-6 w-6" /> Response Action Rollback History
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Track and revert automated response actions with full audit trail
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total Rollbacks</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">
                {list.filter((e) => e.status === "executed" || e.status === "completed").length}
              </p>
              <p className="text-xs text-muted-foreground">Executed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((e) => e.status === "pending").length}</p>
              <p className="text-xs text-muted-foreground">Pending</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((e) => e.status === "failed").length}</p>
              <p className="text-xs text-muted-foreground">Failed</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <RotateCcw className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">No rollback entries recorded</p>
            <p className="text-xs text-muted-foreground">
              Rollback entries appear when automated response actions are created
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {list.map((e) => (
            <Card
              key={e.id}
              className="transition-all hover:shadow-sm cursor-pointer"
              onClick={() => setExpandedId(expandedId === e.id ? null : e.id)}
            >
              <CardContent className="py-3">
                <div className="flex items-center gap-3">
                  {statusIcon(e.status)}
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm">
                      {e.actionType} on {e.target}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {e.originalActionId ? `Action: ${e.originalActionId.slice(0, 8)}...` : "Manual"} &middot;{" "}
                      {e.executedBy || "system"} &middot; {e.createdAt ? new Date(e.createdAt).toLocaleString() : ""}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        e.status === "executed" || e.status === "completed"
                          ? "default"
                          : e.status === "failed"
                            ? "destructive"
                            : "outline"
                      }
                    >
                      {e.status}
                    </Badge>
                    {e.status === "pending" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          executeMutation.mutate(e.id);
                        }}
                        disabled={executeMutation.isPending}
                      >
                        {executeMutation.isPending ? (
                          <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                        ) : (
                          <Undo2 className="mr-1 h-3 w-3" />
                        )}
                        Execute Rollback
                      </Button>
                    )}
                    {expandedId === e.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>
                {expandedId === e.id && (
                  <div className="mt-3 border-t pt-3 space-y-2">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-xs text-muted-foreground">Target</p>
                        <p className="font-mono text-xs">{e.target}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Action Type</p>
                        <p>{e.actionType}</p>
                      </div>
                    </div>
                    {e.executedAt && (
                      <div className="text-sm">
                        <p className="text-xs text-muted-foreground">Executed At</p>
                        <p>{new Date(e.executedAt).toLocaleString()}</p>
                      </div>
                    )}
                    {e.error && (
                      <div>
                        <p className="text-xs font-medium text-destructive mb-1">Error</p>
                        <p className="text-sm text-destructive">{e.error}</p>
                      </div>
                    )}
                    {e.rollbackAction && Object.keys(e.rollbackAction).length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Rollback Action</p>
                        <pre className="text-xs bg-muted p-2 rounded overflow-auto max-h-32">
                          {JSON.stringify(e.rollbackAction, null, 2)}
                        </pre>
                      </div>
                    )}
                    {e.result && Object.keys(e.result).length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Result</p>
                        <pre className="text-xs bg-muted p-2 rounded overflow-auto max-h-32">
                          {JSON.stringify(e.result, null, 2)}
                        </pre>
                      </div>
                    )}
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
