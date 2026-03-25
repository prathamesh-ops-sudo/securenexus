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
  ArrowRight,
  FileText,
  Activity,
  Settings2,
  Plus,
  Trash2,
  BarChart3,
  Timer,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

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
  const [detailId, setDetailId] = useState<string | null>(null);
  const [impactId, setImpactId] = useState<string | null>(null);
  const [auditId, setAuditId] = useState<string | null>(null);
  const [showTriggerForm, setShowTriggerForm] = useState(false);
  const [newTrigger, setNewTrigger] = useState({
    name: "",
    description: "",
    actionType: "isolate_host",
    metric: "service_alerts",
    threshold: 5,
    windowMinutes: 10,
    comparison: "gt" as "gt" | "lt" | "gte" | "lte" | "eq",
  });

  const {
    data: entries,
    isPending,
    isError,
    refetch,
  } = useQuery<{ rollbacks: RollbackEntry[]; count: number }>({
    queryKey: ["/api/autonomous/rollbacks"],
    queryFn: () => apiRequest("GET", "/api/autonomous/rollbacks").then((r) => r.json()),
  });

  const executeMutation = useMutation({
    mutationFn: (rollbackId: string) => apiRequest("POST", `/api/autonomous/rollbacks/${rollbackId}/execute`),
    onSuccess: () => {
      toast({ title: "Rollback executed successfully" });
      queryClient.invalidateQueries({
        queryKey: ["/api/autonomous/rollbacks"],
      });
    },
    onError: () => toast({ title: "Rollback execution failed", variant: "destructive" }),
  });

  // 22.1: Rollback detail query
  const { data: detailData } = useQuery({
    queryKey: ["/api/autonomous/rollbacks", detailId, "detail"],
    queryFn: () => apiRequest("GET", `/api/autonomous/rollbacks/${detailId}/detail`).then((r) => r.json()),
    enabled: !!detailId,
  });

  // 22.2: Rollback impact query
  const { data: impactData } = useQuery({
    queryKey: ["/api/autonomous/rollbacks", impactId, "impact"],
    queryFn: () => apiRequest("GET", `/api/autonomous/rollbacks/${impactId}/impact`).then((r) => r.json()),
    enabled: !!impactId,
  });

  // 22.3: Auto-rollback triggers
  const { data: triggersData, refetch: refetchTriggers } = useQuery({
    queryKey: ["/api/autonomous/rollback-triggers"],
    queryFn: () => apiRequest("GET", "/api/autonomous/rollback-triggers").then((r) => r.json()),
  });

  const createTriggerMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => apiRequest("POST", "/api/autonomous/rollback-triggers", data),
    onSuccess: () => {
      toast({ title: "Auto-rollback trigger created" });
      refetchTriggers();
      setShowTriggerForm(false);
      setNewTrigger({
        name: "",
        description: "",
        actionType: "isolate_host",
        metric: "service_alerts",
        threshold: 5,
        windowMinutes: 10,
        comparison: "gt",
      });
    },
    onError: () => toast({ title: "Failed to create trigger", variant: "destructive" }),
  });

  const toggleTriggerMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiRequest("PATCH", `/api/autonomous/rollback-triggers/${id}`, {
        enabled,
      }),
    onSuccess: () => {
      toast({ title: "Trigger updated" });
      refetchTriggers();
    },
  });

  const deleteTriggerMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/autonomous/rollback-triggers/${id}`),
    onSuccess: () => {
      toast({ title: "Trigger deleted" });
      refetchTriggers();
    },
  });

  // 22.4: Audit trail query
  const { data: auditData } = useQuery({
    queryKey: ["/api/autonomous/rollbacks", auditId, "audit-trail"],
    queryFn: () => apiRequest("GET", `/api/autonomous/rollbacks/${auditId}/audit-trail`).then((r) => r.json()),
    enabled: !!auditId,
  });

  const list = Array.isArray(entries) ? entries : (entries as any)?.rollbacks || [];
  const triggers = (triggersData as any)?.triggers || [];

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
                {list.filter((e: RollbackEntry) => e.status === "executed" || e.status === "completed").length}
              </p>
              <p className="text-xs text-muted-foreground">Executed</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((e: RollbackEntry) => e.status === "pending").length}</p>
              <p className="text-xs text-muted-foreground">Pending</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((e: RollbackEntry) => e.status === "failed").length}</p>
              <p className="text-xs text-muted-foreground">Failed</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="history" className="space-y-4">
        <TabsList>
          <TabsTrigger value="history" className="gap-1.5">
            <RotateCcw className="h-3.5 w-3.5" />
            History
          </TabsTrigger>
          <TabsTrigger value="triggers" className="gap-1.5">
            <Settings2 className="h-3.5 w-3.5" />
            Auto-Rollback Triggers
          </TabsTrigger>
        </TabsList>

        {/* HISTORY TAB */}
        <TabsContent value="history" className="space-y-2">
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
              {list.map((e: RollbackEntry) => (
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
                          {e.executedBy || "system"} &middot;{" "}
                          {e.createdAt ? new Date(e.createdAt).toLocaleString() : ""}
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
                            Execute
                          </Button>
                        )}
                        {expandedId === e.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </div>
                    {expandedId === e.id && (
                      <div className="mt-3 border-t pt-3 space-y-3">
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
                        {/* 22.1, 22.2, 22.4 action buttons */}
                        <div className="flex gap-2 pt-2 border-t">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setDetailId(e.id);
                            }}
                          >
                            <Eye className="mr-1 h-3 w-3" />
                            Detail View
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setImpactId(e.id);
                            }}
                          >
                            <BarChart3 className="mr-1 h-3 w-3" />
                            Impact Analysis
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setAuditId(e.id);
                            }}
                          >
                            <FileText className="mr-1 h-3 w-3" />
                            Audit Trail
                          </Button>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* 22.3: AUTO-ROLLBACK TRIGGERS TAB */}
        <TabsContent value="triggers" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Configure conditions that automatically trigger rollbacks when response actions cause more damage than the
              threat.
            </p>
            <Button size="sm" onClick={() => setShowTriggerForm(!showTriggerForm)}>
              <Plus className="mr-1 h-3.5 w-3.5" />
              Add Trigger
            </Button>
          </div>

          {showTriggerForm && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">New Auto-Rollback Trigger</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs text-muted-foreground">Name</label>
                    <Input
                      value={newTrigger.name}
                      onChange={(e) => setNewTrigger({ ...newTrigger, name: e.target.value })}
                      placeholder="e.g. Isolation Service Alert Limit"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Action Type</label>
                    <Select
                      value={newTrigger.actionType}
                      onValueChange={(v) => setNewTrigger({ ...newTrigger, actionType: v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="isolate_host">Isolate Host</SelectItem>
                        <SelectItem value="block_ip">Block IP</SelectItem>
                        <SelectItem value="block_domain">Block Domain</SelectItem>
                        <SelectItem value="disable_user">Disable User</SelectItem>
                        <SelectItem value="quarantine_file">Quarantine File</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">Description</label>
                  <Input
                    value={newTrigger.description}
                    onChange={(e) =>
                      setNewTrigger({
                        ...newTrigger,
                        description: e.target.value,
                      })
                    }
                    placeholder="e.g. Auto-rollback if isolation causes too many service alerts"
                  />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="text-xs text-muted-foreground">Metric</label>
                    <Select
                      value={newTrigger.metric}
                      onValueChange={(v) => setNewTrigger({ ...newTrigger, metric: v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="service_alerts">Service Alerts</SelectItem>
                        <SelectItem value="failed_connections">Failed Connections</SelectItem>
                        <SelectItem value="user_complaints">User Complaints</SelectItem>
                        <SelectItem value="error_rate">Error Rate %</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Threshold</label>
                    <Input
                      type="number"
                      value={newTrigger.threshold}
                      onChange={(e) =>
                        setNewTrigger({
                          ...newTrigger,
                          threshold: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Window (minutes)</label>
                    <Input
                      type="number"
                      value={newTrigger.windowMinutes}
                      onChange={(e) =>
                        setNewTrigger({
                          ...newTrigger,
                          windowMinutes: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={() =>
                      createTriggerMutation.mutate({
                        name: newTrigger.name,
                        description: newTrigger.description,
                        actionType: newTrigger.actionType,
                        condition: {
                          metric: newTrigger.metric,
                          threshold: newTrigger.threshold,
                          windowMinutes: newTrigger.windowMinutes,
                          comparison: newTrigger.comparison,
                        },
                      })
                    }
                    disabled={!newTrigger.name || createTriggerMutation.isPending}
                  >
                    {createTriggerMutation.isPending && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
                    Create Trigger
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setShowTriggerForm(false)}>
                    Cancel
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {triggers.length === 0 && !showTriggerForm ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-3">
                <Settings2 className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">No auto-rollback triggers configured</p>
                <p className="text-xs text-muted-foreground">
                  Create triggers to automatically rollback actions that cause more damage than the threat
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {triggers.map((t: any) => (
                <Card key={t.id}>
                  <CardContent className="py-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 rounded-full ${t.enabled ? "bg-green-500" : "bg-gray-400"}`} />
                        <div>
                          <p className="font-medium text-sm">{t.name}</p>
                          <p className="text-xs text-muted-foreground">
                            If <span className="font-mono">{t.condition?.metric}</span> &gt; {t.condition?.threshold}{" "}
                            within {t.condition?.windowMinutes}min after{" "}
                            <Badge variant="outline" className="text-xs">
                              {t.actionType}
                            </Badge>
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            toggleTriggerMutation.mutate({
                              id: t.id,
                              enabled: !t.enabled,
                            })
                          }
                        >
                          {t.enabled ? "Disable" : "Enable"}
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => deleteTriggerMutation.mutate(t.id)}>
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* 22.1: ROLLBACK DETAIL DIALOG */}
      <Dialog open={!!detailId} onOpenChange={() => setDetailId(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5" />
              Rollback Detail View
            </DialogTitle>
          </DialogHeader>
          {detailData ? (
            <div className="space-y-4">
              {/* Original Action */}
              {(detailData as any).originalAction && (
                <div>
                  <h3 className="text-sm font-semibold mb-2">Original Action</h3>
                  <Card>
                    <CardContent className="py-3">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <span className="text-muted-foreground">Type: </span>
                          <Badge variant="outline">{(detailData as any).originalAction.actionType}</Badge>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Target: </span>
                          <span className="font-mono text-xs">{(detailData as any).originalAction.targetValue}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Status: </span>
                          {(detailData as any).originalAction.status}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Created: </span>
                          {(detailData as any).originalAction.createdAt
                            ? new Date((detailData as any).originalAction.createdAt).toLocaleString()
                            : "N/A"}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* Who initiated & why */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="text-sm font-semibold mb-1">Initiated By</h3>
                  <p className="text-sm">{(detailData as any).initiatedBy}</p>
                </div>
                <div>
                  <h3 className="text-sm font-semibold mb-1">Reason</h3>
                  <p className="text-sm">{(detailData as any).reason}</p>
                </div>
              </div>

              {/* Before / After State Comparison */}
              <div>
                <h3 className="text-sm font-semibold mb-2">Before / After State</h3>
                <div className="grid grid-cols-2 gap-3">
                  <Card className="border-red-500/20">
                    <CardHeader className="py-2 px-3">
                      <CardTitle className="text-xs text-red-400">Before Rollback</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2 px-3">
                      {Object.entries((detailData as any).beforeState || {}).map(([key, val]) => (
                        <div key={key} className="text-xs mb-1">
                          <span className="text-muted-foreground">{key}: </span>
                          <span className="font-mono">{String(val)}</span>
                        </div>
                      ))}
                      {Object.keys((detailData as any).beforeState || {}).length === 0 && (
                        <p className="text-xs text-muted-foreground">No state data</p>
                      )}
                    </CardContent>
                  </Card>
                  <Card className="border-green-500/20">
                    <CardHeader className="py-2 px-3">
                      <CardTitle className="text-xs text-green-400">After Rollback</CardTitle>
                    </CardHeader>
                    <CardContent className="py-2 px-3">
                      {Object.entries((detailData as any).afterState || {}).map(([key, val]) => (
                        <div key={key} className="text-xs mb-1">
                          <span className="text-muted-foreground">{key}: </span>
                          <span className="font-mono">{String(val)}</span>
                        </div>
                      ))}
                      {Object.keys((detailData as any).afterState || {}).length === 0 && (
                        <p className="text-xs text-muted-foreground">No state data</p>
                      )}
                    </CardContent>
                  </Card>
                </div>
              </div>

              {/* Verification Status */}
              <div>
                <h3 className="text-sm font-semibold mb-2">Verification Status</h3>
                <Badge
                  variant={
                    (detailData as any).verificationStatus === "verified"
                      ? "default"
                      : (detailData as any).verificationStatus === "failed"
                        ? "destructive"
                        : "outline"
                  }
                  className="mb-2"
                >
                  {(detailData as any).verificationStatus}
                </Badge>
                {((detailData as any).verificationChecks || []).map((c: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs mb-1">
                    {c.status === "pass" ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                    ) : c.status === "fail" ? (
                      <XCircle className="h-3.5 w-3.5 text-red-500" />
                    ) : (
                      <Clock className="h-3.5 w-3.5 text-yellow-500" />
                    )}
                    <span className="font-mono">{c.check}</span>
                    <span className="text-muted-foreground">{c.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 22.2: IMPACT ANALYSIS DIALOG */}
      <Dialog open={!!impactId} onOpenChange={() => setImpactId(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Rollback Impact Analysis
            </DialogTitle>
          </DialogHeader>
          {impactData ? (
            <div className="space-y-4">
              <Card className="bg-muted/50">
                <CardContent className="py-3">
                  <p className="text-sm">{(impactData as any).impact?.description}</p>
                </CardContent>
              </Card>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <Card>
                  <CardContent className="pt-3 text-center">
                    <Timer className="h-5 w-5 mx-auto mb-1 text-primary" />
                    <p className="text-lg font-bold">{(impactData as any).impact?.durationFormatted}</p>
                    <p className="text-xs text-muted-foreground">Duration</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-3 text-center">
                    <Activity className="h-5 w-5 mx-auto mb-1 text-orange-400" />
                    <p className="text-lg font-bold">{(impactData as any).impact?.businessImpact || "N/A"}</p>
                    <p className="text-xs text-muted-foreground">Business Impact</p>
                  </CardContent>
                </Card>
                {(impactData as any).impact?.affectedSessions !== undefined && (
                  <Card>
                    <CardContent className="pt-3 text-center">
                      <p className="text-lg font-bold">{(impactData as any).impact.affectedSessions}</p>
                      <p className="text-xs text-muted-foreground">Affected Sessions</p>
                    </CardContent>
                  </Card>
                )}
                {(impactData as any).impact?.serviceAlertsGenerated !== undefined && (
                  <Card>
                    <CardContent className="pt-3 text-center">
                      <p className="text-lg font-bold">{(impactData as any).impact.serviceAlertsGenerated}</p>
                      <p className="text-xs text-muted-foreground">Service Alerts</p>
                    </CardContent>
                  </Card>
                )}
                {(impactData as any).impact?.droppedConnections !== undefined && (
                  <Card>
                    <CardContent className="pt-3 text-center">
                      <p className="text-lg font-bold">{(impactData as any).impact.droppedConnections}</p>
                      <p className="text-xs text-muted-foreground">Dropped Connections</p>
                    </CardContent>
                  </Card>
                )}
                {(impactData as any).impact?.terminatedSessions !== undefined && (
                  <Card>
                    <CardContent className="pt-3 text-center">
                      <p className="text-lg font-bold">{(impactData as any).impact.terminatedSessions}</p>
                      <p className="text-xs text-muted-foreground">Terminated Sessions</p>
                    </CardContent>
                  </Card>
                )}
              </div>

              {/* Impact timeline */}
              <div>
                <h3 className="text-sm font-semibold mb-2">Impact Timeline</h3>
                <div className="space-y-2">
                  {((impactData as any).timeline || []).map((evt: any, i: number) => (
                    <div key={i} className="flex items-start gap-3">
                      <div className="flex flex-col items-center">
                        <div className="w-2 h-2 rounded-full bg-primary mt-1.5" />
                        {i < ((impactData as any).timeline || []).length - 1 && <div className="w-px h-8 bg-border" />}
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">{evt.event}</p>
                        <p className="text-xs text-muted-foreground">{evt.detail}</p>
                        {evt.timestamp && (
                          <p className="text-xs text-muted-foreground">{new Date(evt.timestamp).toLocaleString()}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* 22.4: AUDIT TRAIL DIALOG */}
      <Dialog open={!!auditId} onOpenChange={() => setAuditId(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Rollback Audit Trail
            </DialogTitle>
          </DialogHeader>
          {auditData ? (
            <div className="space-y-4">
              {/* Summary */}
              <Card className="bg-muted/50">
                <CardContent className="py-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <span className="text-muted-foreground">Requested By: </span>
                      {(auditData as any).summary?.requestedBy}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Reason: </span>
                      {(auditData as any).summary?.reason}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Action: </span>
                      {(auditData as any).summary?.originalActionType} on {(auditData as any).summary?.originalTarget}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Final Status: </span>
                      <Badge variant="outline">{(auditData as any).summary?.finalStatus}</Badge>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mt-2 italic">
                    {(auditData as any).summary?.complianceNote}
                  </p>
                </CardContent>
              </Card>

              {/* Audit entries */}
              <div className="space-y-1">
                {((auditData as any).auditTrail || []).map((entry: any, i: number) => (
                  <div key={i} className="flex items-start gap-3 p-2 rounded hover:bg-muted/50">
                    <div className="flex flex-col items-center mt-1">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          entry.category === "action"
                            ? "bg-blue-500"
                            : entry.category === "rollback"
                              ? "bg-orange-500"
                              : entry.category === "verification"
                                ? "bg-green-500"
                                : "bg-red-500"
                        }`}
                      />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium">{entry.action.replace(/_/g, " ")}</p>
                        <Badge variant="outline" className="text-xs">
                          {entry.category}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">{entry.detail}</p>
                      <p className="text-xs text-muted-foreground">
                        {entry.actor} &middot; {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "N/A"}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
