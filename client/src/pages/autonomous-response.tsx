import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { formatDateTime as formatTimestamp } from "@/lib/i18n";
import {
  Bot,
  Shield,
  RotateCcw,
  Play,
  Pause,
  Check,
  Clock,
  Zap,
  Eye,
  Loader2,
  Trash2,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

function formatType(type: string): string {
  return type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function policyStatusBadge(status: string) {
  const styles: Record<string, string> = {
    active: "bg-green-500/10 text-green-500 border-green-500/20",
    inactive: "bg-muted text-muted-foreground border-muted",
    testing: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  };
  return styles[status] || "bg-muted text-muted-foreground border-muted";
}

function runStatusBadge(status: string) {
  const styles: Record<string, string> = {
    queued: "bg-muted text-muted-foreground border-muted",
    running: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    completed: "bg-green-500/10 text-green-500 border-green-500/20",
    failed: "bg-red-500/10 text-red-500 border-red-500/20",
  };
  return styles[status] || "bg-muted text-muted-foreground border-muted";
}

function rollbackStatusBadge(status: string) {
  const styles: Record<string, string> = {
    pending: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    completed: "bg-green-500/10 text-green-500 border-green-500/20",
    failed: "bg-red-500/10 text-red-500 border-red-500/20",
  };
  return styles[status] || "bg-muted text-muted-foreground border-muted";
}

function stepIcon(stepType: string) {
  const icons: Record<string, typeof Bot> = {
    analyze: Eye,
    enrich: Zap,
    correlate: Shield,
    respond: Play,
    validate: Check,
  };
  const Icon = icons[stepType] || Bot;
  return <Icon className="h-4 w-4 flex-shrink-0" />;
}

function PoliciesTab() {
  const { toast } = useToast();
  const [globalCooldown, setGlobalCooldown] = useState("30");
  const [globalRatePerHour, setGlobalRatePerHour] = useState("10");

  const {
    data: policies,
    isLoading,
    isError: _policiesError,
    refetch: _refetchPolicies,
  } = useQuery<any[]>({
    queryKey: ["/api/autonomous/policies"],
  });

  const seedMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/autonomous/policies/seed-defaults");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/policies"] });
      toast({ title: "Policies seeded", description: "Default policies have been created." });
    },
    onError: (err: Error) => {
      toast({ title: "Seeding failed", description: err.message, variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const newStatus = status === "active" ? "inactive" : "active";
      await apiRequest("PATCH", `/api/autonomous/policies/${id}`, { status: newStatus });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/policies"] });
      toast({ title: "Policy updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Update failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/autonomous/policies/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/policies"] });
      toast({ title: "Policy deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Delete failed", description: err.message, variant: "destructive" });
    },
  });

  const applyGlobalControls = useMutation({
    mutationFn: async () => {
      const list = Array.isArray(policies) ? policies : [];
      const targets = list.filter((p) => p.status === "active");
      await Promise.all(
        targets.map((policy) =>
          apiRequest("PATCH", `/api/autonomous/policies/${policy.id}`, {
            cooldownMinutes: Number(globalCooldown) || 0,
            maxActionsPerHour: Number(globalRatePerHour) || 0,
          }),
        ),
      );
      return targets.length;
    },
    onSuccess: (count) => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/policies"] });
      toast({ title: "Global controls applied", description: `Updated ${count} active policy(ies)` });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to apply controls", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="policies-loading">
        {Array.from({ length: 3 }).map((_, i) => (
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
    <div className="space-y-4" data-testid="section-policies">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-muted-foreground" />
          <h2 className="text-lg font-semibold">Response Policies</h2>
          <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
            {policies?.length ?? 0}
          </Badge>
        </div>
        <Button
          onClick={() => seedMutation.mutate()}
          disabled={seedMutation.isPending}
          data-testid="button-seed-policies"
        >
          {seedMutation.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Zap className="h-4 w-4 mr-2" />
          )}
          Seed Default Policies
        </Button>
      </div>

      <Card data-testid="card-global-safety-controls">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Unified Cooldown / Rate Controls</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-2">
          <div className="space-y-1">
            <div className="text-[10px] uppercase text-muted-foreground">Cooldown (min)</div>
            <Input value={globalCooldown} onChange={(e) => setGlobalCooldown(e.target.value)} className="w-28" />
          </div>
          <div className="space-y-1">
            <div className="text-[10px] uppercase text-muted-foreground">Rate (/hour)</div>
            <Input value={globalRatePerHour} onChange={(e) => setGlobalRatePerHour(e.target.value)} className="w-28" />
          </div>
          <Button onClick={() => applyGlobalControls.mutate()} disabled={applyGlobalControls.isPending}>
            {applyGlobalControls.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
            Apply to Active Policies
          </Button>
        </CardContent>
      </Card>

      {!policies || policies.length === 0 ? (
        <Card data-testid="empty-policies">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Shield className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No policies configured</p>
            <p className="text-xs text-muted-foreground mt-1">
              Seed default policies to get started with autonomous response
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {policies.map((policy: any, idx: number) => {
            const _conditions = (() => {
              try {
                if (typeof policy.conditions === "string") return JSON.parse(policy.conditions);
                return policy.conditions || {};
              } catch {
                return {};
              }
            })();
            const actions = (() => {
              try {
                if (Array.isArray(policy.actions)) return policy.actions;
                if (typeof policy.actions === "string") return JSON.parse(policy.actions);
                return [];
              } catch {
                return [];
              }
            })();

            return (
              <Card key={policy.id || idx} data-testid={`card-policy-${policy.id || idx}`}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold" data-testid={`text-policy-name-${policy.id || idx}`}>
                          {policy.name || "Unnamed Policy"}
                        </span>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${policyStatusBadge(policy.status)}`}
                          data-testid={`badge-policy-status-${policy.id || idx}`}
                        >
                          {policy.status || "unknown"}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        {policy.triggerType && (
                          <span data-testid={`text-trigger-type-${policy.id || idx}`}>
                            Trigger:{" "}
                            <span className="font-medium text-foreground">{formatType(policy.triggerType)}</span>
                          </span>
                        )}
                        {policy.confidenceThreshold != null && (
                          <span data-testid={`text-confidence-${policy.id || idx}`}>
                            Confidence:{" "}
                            <span className="font-medium text-foreground">
                              {Math.round(policy.confidenceThreshold * 100)}%
                            </span>
                          </span>
                        )}
                        {policy.severityFilter && (
                          <span data-testid={`text-severity-${policy.id || idx}`}>
                            Severity: <span className="font-medium text-foreground">{policy.severityFilter}</span>
                          </span>
                        )}
                      </div>
                      {(policy.cooldownMinutes || policy.maxActionsPerHour || policy.rateLimitPerHour) && (
                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                          {policy.cooldownMinutes && (
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Cooldown: {policy.cooldownMinutes}m
                            </span>
                          )}
                          {(policy.maxActionsPerHour || policy.rateLimitPerHour) && (
                            <span className="flex items-center gap-1">
                              <Zap className="h-3 w-3" />
                              Rate: {policy.maxActionsPerHour || policy.rateLimitPerHour}/hr
                            </span>
                          )}
                        </div>
                      )}
                      {actions.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {actions.map((action: string, ai: number) => (
                            <Badge
                              key={ai}
                              variant="secondary"
                              className="text-[10px]"
                              data-testid={`badge-action-${policy.id || idx}-${ai}`}
                            >
                              {typeof action === "string" ? action : JSON.stringify(action)}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => toggleMutation.mutate({ id: policy.id, status: policy.status })}
                        disabled={toggleMutation.isPending}
                        data-testid={`button-toggle-policy-${policy.id || idx}`}
                      >
                        {policy.status === "active" ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteMutation.mutate(policy.id)}
                        disabled={deleteMutation.isPending}
                        data-testid={`button-delete-policy-${policy.id || idx}`}
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

function ActionTimelineTab() {
  const {
    data: actions,
    isLoading,
    isError: _actionsError,
    refetch: _refetchActions,
  } = useQuery<any[]>({
    queryKey: ["/api/response-actions"],
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <Skeleton className="h-20 w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3" data-testid="section-action-timeline">
      <div className="flex items-center gap-2">
        <Clock className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-lg font-semibold">Action Audit Timeline</h2>
        <Badge variant="outline" className="text-[10px]">
          {actions?.length ?? 0}
        </Badge>
      </div>
      {!actions || actions.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No response actions recorded yet.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {actions.slice(0, 50).map((action, idx) => (
            <Card key={action.id || idx}>
              <CardContent className="p-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider ${runStatusBadge(action.status || "queued")}`}
                    >
                      {action.status || "queued"}
                    </span>
                    <span className="text-sm font-medium">{formatType(action.actionType || "unknown")}</span>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {formatTimestamp(action.executedAt || action.createdAt)}
                  </span>
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  Target:{" "}
                  <span className="text-foreground font-medium">{action.targetValue || action.target || "n/a"}</span>
                  {action.incidentId ? (
                    <span>
                      {" "}
                      · Incident: <span className="text-foreground font-medium">{action.incidentId}</span>
                    </span>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function InvestigationsTab() {
  const { toast } = useToast();
  const [selectedIncident, setSelectedIncident] = useState<string>("");
  const [expandedRun, setExpandedRun] = useState<string | null>(null);

  const { data: investigations, isLoading } = useQuery<any[]>({
    queryKey: ["/api/autonomous/investigations"],
  });

  const { data: incidents } = useQuery<any[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: expandedRunData } = useQuery<any>({
    queryKey: ["/api/autonomous/investigations", expandedRun],
    enabled: !!expandedRun,
  });

  const runMutation = useMutation({
    mutationFn: async (incidentId: string) => {
      await apiRequest("POST", "/api/autonomous/investigations", { incidentId: Number(incidentId) });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/investigations"] });
      setSelectedIncident("");
      toast({ title: "Investigation started", description: "AI investigation has been queued." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to start investigation", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="investigations-loading">
        {Array.from({ length: 3 }).map((_, i) => (
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
    <div className="space-y-4" data-testid="section-investigations">
      <div className="flex items-center gap-2 mb-1">
        <Eye className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-lg font-semibold">AI Investigations</h2>
        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
          {investigations?.length ?? 0}
        </Badge>
      </div>

      <Card data-testid="card-run-investigation">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Run New Investigation</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={selectedIncident} onValueChange={setSelectedIncident}>
              <SelectTrigger className="w-64" data-testid="select-incident">
                <SelectValue placeholder="Select an incident..." />
              </SelectTrigger>
              <SelectContent>
                {incidents?.map((incident: any) => (
                  <SelectItem
                    key={incident.id}
                    value={String(incident.id)}
                    data-testid={`option-incident-${incident.id}`}
                  >
                    #{incident.id} - {incident.title || incident.name || `Incident ${incident.id}`}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              onClick={() => selectedIncident && runMutation.mutate(selectedIncident)}
              disabled={!selectedIncident || runMutation.isPending}
              data-testid="button-run-investigation"
            >
              {runMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Play className="h-4 w-4 mr-2" />
              )}
              Run Investigation
            </Button>
          </div>
        </CardContent>
      </Card>

      {!investigations || investigations.length === 0 ? (
        <Card data-testid="empty-investigations">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Eye className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No investigations yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Select an incident above to start an AI-powered investigation
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {investigations.map((run: any, idx: number) => {
            const isExpanded = expandedRun === String(run.id);
            const steps = (() => {
              if (isExpanded && expandedRunData?.steps) return expandedRunData.steps;
              if (run.steps) {
                try {
                  if (Array.isArray(run.steps)) return run.steps;
                  if (typeof run.steps === "string") return JSON.parse(run.steps);
                } catch (_parseErr) {
                  console.warn("Failed to parse investigation steps", _parseErr);
                }
              }
              return [];
            })();

            return (
              <Card key={run.id || idx} data-testid={`card-investigation-${run.id || idx}`}>
                <CardContent className="p-4">
                  <div
                    className="flex items-start justify-between gap-3 cursor-pointer flex-wrap"
                    onClick={() => setExpandedRun(isExpanded ? null : String(run.id))}
                    data-testid={`button-expand-investigation-${run.id || idx}`}
                  >
                    <div className="min-w-0 flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Bot className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        <span className="text-sm font-semibold" data-testid={`text-investigation-id-${run.id || idx}`}>
                          Investigation #{run.id}
                        </span>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${runStatusBadge(run.status)}`}
                          data-testid={`badge-investigation-status-${run.id || idx}`}
                        >
                          {run.status || "unknown"}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        {run.incidentId && (
                          <span data-testid={`text-incident-link-${run.id || idx}`}>
                            Incident: <span className="font-medium text-foreground">#{run.incidentId}</span>
                          </span>
                        )}
                        {run.triggeredBy && (
                          <span data-testid={`text-triggered-by-${run.id || idx}`}>
                            By: <span className="font-medium text-foreground">{run.triggeredBy}</span>
                          </span>
                        )}
                        {run.confidenceScore != null && (
                          <span data-testid={`text-confidence-score-${run.id || idx}`}>
                            Confidence:{" "}
                            <span className="font-medium text-foreground">
                              {Math.round(run.confidenceScore * 100)}%
                            </span>
                          </span>
                        )}
                        {run.durationMs != null && (
                          <span className="flex items-center gap-1" data-testid={`text-duration-${run.id || idx}`}>
                            <Clock className="h-3 w-3" />
                            {(run.durationMs / 1000).toFixed(1)}s
                          </span>
                        )}
                        {run.createdAt && (
                          <span data-testid={`text-created-${run.id || idx}`}>{formatTimestamp(run.createdAt)}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex-shrink-0">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                  </div>

                  {isExpanded && steps.length > 0 && (
                    <div
                      className="mt-4 ml-6 border-l border-border pl-4 space-y-3"
                      data-testid={`timeline-${run.id || idx}`}
                    >
                      {steps.map((step: any, si: number) => (
                        <div key={si} className="flex items-start gap-3" data-testid={`step-${run.id || idx}-${si}`}>
                          <div className="p-1.5 rounded-md bg-muted/50 flex-shrink-0 mt-0.5">
                            {stepIcon(step.type || step.stepType || "")}
                          </div>
                          <div className="min-w-0 flex-1 space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span
                                className="text-sm font-medium"
                                data-testid={`text-step-title-${run.id || idx}-${si}`}
                              >
                                {step.title || formatType(step.type || step.stepType || "Step")}
                              </span>
                              <span
                                className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${runStatusBadge(step.status || "completed")}`}
                                data-testid={`badge-step-status-${run.id || idx}-${si}`}
                              >
                                {step.status || "completed"}
                              </span>
                              {step.durationMs != null && (
                                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                  <Clock className="h-2.5 w-2.5" />
                                  {(step.durationMs / 1000).toFixed(1)}s
                                </span>
                              )}
                            </div>
                            {step.result && (
                              <p
                                className="text-xs text-muted-foreground"
                                data-testid={`text-step-result-${run.id || idx}-${si}`}
                              >
                                {typeof step.result === "string" ? step.result : JSON.stringify(step.result)}
                              </p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {isExpanded && steps.length === 0 && (
                    <div
                      className="mt-4 ml-6 text-xs text-muted-foreground"
                      data-testid={`empty-steps-${run.id || idx}`}
                    >
                      No steps recorded for this investigation.
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RollbacksTab() {
  const { toast } = useToast();
  const [newActionType, setNewActionType] = useState("");
  const [newTarget, setNewTarget] = useState("");

  const { data: rollbacks, isLoading } = useQuery<any[]>({
    queryKey: ["/api/autonomous/rollbacks"],
  });

  const executeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/autonomous/rollbacks/${id}/execute`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/rollbacks"] });
      toast({ title: "Rollback executed", description: "The rollback action has been completed." });
    },
    onError: (err: Error) => {
      toast({ title: "Rollback failed", description: err.message, variant: "destructive" });
    },
  });

  const createMutation = useMutation({
    mutationFn: async ({ actionType, target }: { actionType: string; target: string }) => {
      await apiRequest("POST", "/api/autonomous/rollbacks", { actionType, target });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/autonomous/rollbacks"] });
      setNewActionType("");
      setNewTarget("");
      toast({ title: "Rollback created", description: "New rollback record has been created." });
    },
    onError: (err: Error) => {
      toast({ title: "Creation failed", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-3" data-testid="rollbacks-loading">
        {Array.from({ length: 3 }).map((_, i) => (
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
    <div className="space-y-4" data-testid="section-rollbacks">
      <div className="flex items-center gap-2 mb-1">
        <RotateCcw className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-lg font-semibold">Action Rollbacks</h2>
        <Badge variant="outline" className="no-default-hover-elevate no-default-active-elevate text-[10px]">
          {rollbacks?.length ?? 0}
        </Badge>
      </div>

      <Card data-testid="card-create-rollback">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Create New Rollback</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={newActionType} onValueChange={setNewActionType}>
              <SelectTrigger className="w-48" data-testid="select-action-type">
                <SelectValue placeholder="Action type..." />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="block_ip">Block IP</SelectItem>
                <SelectItem value="disable_user">Disable User</SelectItem>
                <SelectItem value="quarantine_file">Quarantine File</SelectItem>
                <SelectItem value="revoke_token">Revoke Token</SelectItem>
                <SelectItem value="isolate_host">Isolate Host</SelectItem>
              </SelectContent>
            </Select>
            <Input
              placeholder="Target (e.g., IP, username)..."
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              className="w-64"
              data-testid="input-rollback-target"
            />
            <Button
              onClick={() =>
                newActionType && newTarget && createMutation.mutate({ actionType: newActionType, target: newTarget })
              }
              disabled={!newActionType || !newTarget || createMutation.isPending}
              data-testid="button-create-rollback"
            >
              {createMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <RotateCcw className="h-4 w-4 mr-2" />
              )}
              Create Rollback
            </Button>
          </div>
        </CardContent>
      </Card>

      {!rollbacks || rollbacks.length === 0 ? (
        <Card data-testid="empty-rollbacks">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <RotateCcw className="h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No rollback records</p>
            <p className="text-xs text-muted-foreground mt-1">
              Rollback records will appear here when autonomous actions are taken
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {rollbacks.map((rollback: any, idx: number) => (
            <Card key={rollback.id || idx} data-testid={`card-rollback-${rollback.id || idx}`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <RotateCcw className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      <span
                        className="text-sm font-semibold"
                        data-testid={`text-rollback-action-${rollback.id || idx}`}
                      >
                        {formatType(rollback.actionType || "Unknown Action")}
                      </span>
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${rollbackStatusBadge(rollback.status)}`}
                        data-testid={`badge-rollback-status-${rollback.id || idx}`}
                      >
                        {rollback.status || "unknown"}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                      {rollback.target && (
                        <span data-testid={`text-rollback-target-${rollback.id || idx}`}>
                          Target: <span className="font-mono font-medium text-foreground">{rollback.target}</span>
                        </span>
                      )}
                      {rollback.createdAt && (
                        <span
                          className="flex items-center gap-1"
                          data-testid={`text-rollback-created-${rollback.id || idx}`}
                        >
                          <Clock className="h-3 w-3" />
                          {formatTimestamp(rollback.createdAt)}
                        </span>
                      )}
                      {rollback.executedAt && (
                        <span data-testid={`text-rollback-executed-${rollback.id || idx}`}>
                          Executed: {formatTimestamp(rollback.executedAt)}
                        </span>
                      )}
                    </div>
                  </div>
                  {rollback.status === "pending" && (
                    <Button
                      variant="outline"
                      onClick={() => executeMutation.mutate(String(rollback.id))}
                      disabled={executeMutation.isPending}
                      data-testid={`button-execute-rollback-${rollback.id || idx}`}
                    >
                      {executeMutation.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4 mr-2" />
                      )}
                      Execute
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AutonomousResponsePage() {
  const [activeTab, setActiveTab] = useState("policies");

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-autonomous-response">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Autonomous Response</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Agentic SOC &mdash; AI-Driven Investigation, Policy Enforcement & Rollback
          </p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2">
          <Bot className="h-5 w-5 text-muted-foreground" />
          <Badge
            variant="outline"
            className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase tracking-wider"
          >
            Phase 9
          </Badge>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} data-testid="tabs-autonomous">
        <TabsList data-testid="tabslist-autonomous">
          <TabsTrigger value="policies" data-testid="tab-policies">
            <Shield className="h-4 w-4 mr-1.5" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="investigations" data-testid="tab-investigations">
            <Eye className="h-4 w-4 mr-1.5" />
            Investigations
          </TabsTrigger>
          <TabsTrigger value="rollbacks" data-testid="tab-rollbacks">
            <RotateCcw className="h-4 w-4 mr-1.5" />
            Rollbacks
          </TabsTrigger>
          <TabsTrigger value="timeline" data-testid="tab-action-timeline">
            <Clock className="h-4 w-4 mr-1.5" />
            Action Timeline
          </TabsTrigger>
        </TabsList>

        <TabsContent value="policies" className="mt-4">
          <PoliciesTab />
        </TabsContent>

        <TabsContent value="investigations" className="mt-4">
          <InvestigationsTab />
        </TabsContent>

        <TabsContent value="rollbacks" className="mt-4">
          <RollbacksTab />
        </TabsContent>

        <TabsContent value="timeline" className="mt-4">
          <ActionTimelineTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
