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
  actionType: string;
  targetId: string;
  targetType: string;
  description: string;
  status: "completed" | "failed" | "pending" | "reverted";
  performedBy: string;
  performedAt: string;
  revertedAt?: string;
  revertedBy?: string;
  details: Record<string, unknown>;
}

export default function RollbackHistoryPage() {
  usePageTitle("Response Action Rollback History");
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const {
    data: entries,
    isLoading,
    isError,
    refetch,
  } = useQuery<RollbackEntry[]>({
    queryKey: ["/api/response-actions/history"],
    queryFn: () => apiRequest("GET", "/api/response-actions/history").then((r) => r.json()),
  });

  const rollbackMutation = useMutation({
    mutationFn: (actionId: string) => apiRequest("POST", `/api/response-actions/${actionId}/rollback`),
    onSuccess: () => {
      toast({ title: "Action rolled back successfully" });
      queryClient.invalidateQueries({ queryKey: ["/api/response-actions/history"] });
    },
    onError: () => toast({ title: "Rollback failed", variant: "destructive" }),
  });

  const list = Array.isArray(entries) ? entries : [];

  const statusIcon = (s: string) => {
    if (s === "completed") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    if (s === "reverted") return <Undo2 className="h-4 w-4 text-blue-500" />;
    return <Clock className="h-4 w-4 text-yellow-500" />;
  };

  if (isLoading) {
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
              <p className="text-xs text-muted-foreground">Total Actions</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((e) => e.status === "completed").length}</p>
              <p className="text-xs text-muted-foreground">Completed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Undo2 className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((e) => e.status === "reverted").length}</p>
              <p className="text-xs text-muted-foreground">Reverted</p>
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
            <p className="text-muted-foreground">No response actions recorded</p>
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
                    <p className="font-medium text-sm">{e.description}</p>
                    <p className="text-xs text-muted-foreground">
                      {e.actionType} on {e.targetType} &middot; by {e.performedBy} &middot;{" "}
                      {new Date(e.performedAt).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        e.status === "completed"
                          ? "default"
                          : e.status === "reverted"
                            ? "secondary"
                            : e.status === "failed"
                              ? "destructive"
                              : "outline"
                      }
                    >
                      {e.status}
                    </Badge>
                    {e.status === "completed" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          rollbackMutation.mutate(e.id);
                        }}
                        disabled={rollbackMutation.isPending}
                      >
                        {rollbackMutation.isPending ? (
                          <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                        ) : (
                          <Undo2 className="mr-1 h-3 w-3" />
                        )}
                        Rollback
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
                        <p className="font-mono text-xs">{e.targetId}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Action Type</p>
                        <p>{e.actionType}</p>
                      </div>
                    </div>
                    {e.revertedAt && (
                      <div className="text-sm">
                        <p className="text-xs text-muted-foreground">Reverted</p>
                        <p>
                          {new Date(e.revertedAt).toLocaleString()} by {e.revertedBy}
                        </p>
                      </div>
                    )}
                    {Object.keys(e.details || {}).length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Details</p>
                        <pre className="text-xs bg-muted p-2 rounded overflow-auto max-h-32">
                          {JSON.stringify(e.details, null, 2)}
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
