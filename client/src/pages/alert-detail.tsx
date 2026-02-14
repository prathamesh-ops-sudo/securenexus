import { useQuery, useMutation } from "@tanstack/react-query";
import { useParams } from "wouter";
import { ArrowLeft, Brain, Loader2, ChevronDown, ChevronRight, Network, Shield, Tag, Save, Plus, Globe, Server, Hash, Clock, FileText, Sparkles, ThumbsUp, ThumbsDown, User, Mail, Link2, Terminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Link } from "wouter";
import { useState } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { SeverityBadge, AlertStatusBadge, formatTimestamp } from "@/components/security-badges";
import type { Alert, Tag as TagType } from "@shared/schema";

const ALERT_STATUSES = ["new", "triaged", "correlated", "investigating", "resolved", "dismissed", "false_positive"] as const;

interface TriageResult {
  severity: string;
  priority: number;
  category: string;
  recommendedAction: string;
  reasoning: string;
  mitreTactic: string;
  mitreTechnique: string;
  falsePositiveLikelihood: number;
  relatedIocs: (string | { type: string; value: string })[];
  threatIntelSources?: string[];
}

export default function AlertDetailPage() {
  const params = useParams<{ id: string }>();
  const [rawDataOpen, setRawDataOpen] = useState(false);
  const [normalizedDataOpen, setNormalizedDataOpen] = useState(false);
  const [triageResult, setTriageResult] = useState<TriageResult | null>(null);
  const [analystNotes, setAnalystNotes] = useState<string | null>(null);
  const [assigneeValue, setAssigneeValue] = useState<string | null>(null);
  const [showTagSelect, setShowTagSelect] = useState(false);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);
  const { toast } = useToast();

  const { data: alert, isLoading } = useQuery<Alert>({
    queryKey: ["/api/alerts", params.id],
    enabled: !!params.id,
  });

  const { data: alertTags } = useQuery<TagType[]>({
    queryKey: ["/api/alerts", params.id, "tags"],
    enabled: !!params.id,
  });

  const { data: allTags } = useQuery<TagType[]>({
    queryKey: ["/api/tags"],
    enabled: showTagSelect,
  });

  const { data: alertEntities } = useQuery<{ id: string; type: string; value: string; displayName: string; riskScore: number; alertCount: number; role: string }[]>({
    queryKey: ["/api/alerts", params.id, "entities"],
    enabled: !!params.id,
  });

  const updateAlert = useMutation({
    mutationFn: async (data: Partial<Alert>) => {
      await apiRequest("PATCH", `/api/alerts/${params.id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts", params.id] });
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      toast({ title: "Alert Updated", description: "Changes saved successfully" });
    },
    onError: (error: any) => {
      toast({ title: "Update Failed", description: error.message, variant: "destructive" });
    },
  });

  const triage = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/ai/triage/${params.id}`, {});
      return res.json();
    },
    onSuccess: (data: TriageResult) => {
      setTriageResult(data);
      toast({ title: "AI Triage Complete", description: "Analysis results are ready" });
    },
    onError: (error: any) => {
      toast({ title: "AI Triage Failed", description: error.message, variant: "destructive" });
    },
  });

  const submitFeedback = useMutation({
    mutationFn: async (rating: number) => {
      await apiRequest("POST", "/api/ai/feedback", { resourceType: "triage", resourceId: alert?.id, rating });
    },
    onSuccess: () => {
      setFeedbackSubmitted(true);
      toast({ title: "Feedback Submitted", description: "Thank you for your feedback" });
    },
    onError: (error: any) => {
      toast({ title: "Feedback Failed", description: error.message, variant: "destructive" });
    },
  });

  const addTag = useMutation({
    mutationFn: async (tagId: string) => {
      await apiRequest("POST", `/api/alerts/${params.id}/tags`, { tagId });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts", params.id, "tags"] });
      setShowTagSelect(false);
      toast({ title: "Tag Added" });
    },
    onError: (error: any) => {
      toast({ title: "Failed to add tag", description: error.message, variant: "destructive" });
    },
  });

  const currentNotes = analystNotes ?? alert?.analystNotes ?? "";
  const currentAssignee = assigneeValue ?? alert?.assignedTo ?? "";

  function handleNoteSave() {
    updateAlert.mutate({ analystNotes: currentNotes } as Partial<Alert>);
    setAnalystNotes(null);
  }

  function handleAssigneeSubmit() {
    const trimmed = currentAssignee.trim();
    if (trimmed !== (alert?.assignedTo || "")) {
      updateAlert.mutate({ assignedTo: trimmed || null } as Partial<Alert>);
    }
    setAssigneeValue(null);
  }

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-6xl mx-auto">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="p-4 md:p-6 text-center py-20">
        <p className="text-muted-foreground">Alert not found</p>
        <Link href="/alerts">
          <Button variant="outline" className="mt-4" data-testid="button-back-alerts">Back to Alerts</Button>
        </Link>
      </div>
    );
  }

  const hasNetworkData = alert.sourceIp || alert.destIp || alert.sourcePort || alert.destPort || alert.protocol || alert.hostname || alert.domain || alert.url || alert.fileHash;
  const hasCorrelation = alert.correlationScore != null || alert.correlationReason;
  const existingTagIds = new Set(alertTags?.map(t => t.id) || []);
  const availableTags = allTags?.filter(t => !existingTagIds.has(t.id)) || [];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-6xl mx-auto">
      <div className="space-y-3">
        <div className="flex items-start gap-3">
          <Link href="/alerts">
            <Button size="icon" variant="ghost" data-testid="button-back">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold tracking-tight" data-testid="text-alert-title">{alert.title}</h1>
              <SeverityBadge severity={alert.severity} />
              <AlertStatusBadge status={alert.status} />
            </div>
            {alert.description && (
              <p className="text-sm text-muted-foreground mt-1" data-testid="text-alert-description">{alert.description}</p>
            )}
            <div className="gradient-accent-line w-24 mt-2" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <Card className="gradient-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Alert Overview
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-xs text-muted-foreground">Source</span>
                  <div className="font-medium" data-testid="text-alert-source">{alert.source}</div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Category</span>
                  <div className="font-medium capitalize" data-testid="text-alert-category">{alert.category?.replace(/_/g, " ") || "Other"}</div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Severity</span>
                  <div><SeverityBadge severity={alert.severity} /></div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Status</span>
                  <div><AlertStatusBadge status={alert.status} /></div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Detected At</span>
                  <div className="text-xs" data-testid="text-detected-at">{formatTimestamp(alert.detectedAt)}</div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Ingested At</span>
                  <div className="text-xs" data-testid="text-ingested-at">{formatTimestamp(alert.ingestedAt)}</div>
                </div>
                {alert.sourceEventId && (
                  <div className="col-span-2">
                    <span className="text-xs text-muted-foreground">Source Event ID</span>
                    <div className="text-xs font-mono" data-testid="text-source-event-id">{alert.sourceEventId}</div>
                  </div>
                )}
                {alert.mitreTactic && (
                  <div>
                    <span className="text-xs text-muted-foreground">MITRE ATT&CK Tactic</span>
                    <div className="mt-1"><span className="px-2 py-1 rounded-md bg-primary/10 text-primary text-xs" data-testid="text-mitre-tactic">{alert.mitreTactic}</span></div>
                  </div>
                )}
                {alert.mitreTechnique && (
                  <div>
                    <span className="text-xs text-muted-foreground">MITRE ATT&CK Technique</span>
                    <div className="mt-1"><span className="px-2 py-1 rounded-md bg-muted text-xs font-mono" data-testid="text-mitre-technique">{alert.mitreTechnique}</span></div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {hasNetworkData && (
            <Card className="gradient-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Network className="h-4 w-4" />
                  Network Details
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  {alert.sourceIp && (
                    <div>
                      <span className="text-xs text-muted-foreground">Source IP</span>
                      <div className="font-mono text-xs" data-testid="text-source-ip">{alert.sourceIp}</div>
                    </div>
                  )}
                  {alert.destIp && (
                    <div>
                      <span className="text-xs text-muted-foreground">Dest IP</span>
                      <div className="font-mono text-xs" data-testid="text-dest-ip">{alert.destIp}</div>
                    </div>
                  )}
                  {alert.sourcePort != null && (
                    <div>
                      <span className="text-xs text-muted-foreground">Source Port</span>
                      <div className="font-mono text-xs" data-testid="text-source-port">{alert.sourcePort}</div>
                    </div>
                  )}
                  {alert.destPort != null && (
                    <div>
                      <span className="text-xs text-muted-foreground">Dest Port</span>
                      <div className="font-mono text-xs" data-testid="text-dest-port">{alert.destPort}</div>
                    </div>
                  )}
                  {alert.protocol && (
                    <div>
                      <span className="text-xs text-muted-foreground">Protocol</span>
                      <div className="text-xs" data-testid="text-protocol">{alert.protocol}</div>
                    </div>
                  )}
                  {alert.hostname && (
                    <div>
                      <span className="text-xs text-muted-foreground">Hostname</span>
                      <div className="font-mono text-xs" data-testid="text-hostname">{alert.hostname}</div>
                    </div>
                  )}
                  {alert.domain && (
                    <div>
                      <span className="text-xs text-muted-foreground">Domain</span>
                      <div className="font-mono text-xs" data-testid="text-domain">{alert.domain}</div>
                    </div>
                  )}
                  {alert.url && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">URL</span>
                      <div className="font-mono text-xs break-all" data-testid="text-url">{alert.url}</div>
                    </div>
                  )}
                  {alert.fileHash && (
                    <div className="col-span-2">
                      <span className="text-xs text-muted-foreground">File Hash</span>
                      <div className="font-mono text-xs break-all" data-testid="text-file-hash">{alert.fileHash}</div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {hasCorrelation && (
            <Card className="border-primary/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-primary" />
                  AI Correlation Info
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {alert.correlationScore != null && (
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-xs text-muted-foreground">Correlation Score</span>
                      <span className="text-xs font-medium" data-testid="text-correlation-score">{Math.round(alert.correlationScore * 100)}%</span>
                    </div>
                    <Progress value={alert.correlationScore * 100} className="h-2" data-testid="progress-correlation" />
                  </div>
                )}
                {alert.correlationReason && (
                  <div>
                    <span className="text-xs text-muted-foreground">Correlation Reason</span>
                    <p className="text-sm text-muted-foreground mt-1" data-testid="text-correlation-reason">{alert.correlationReason}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {triageResult && (
            <Card className="border-primary/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
                  <Brain className="h-4 w-4 text-primary" />
                  AI Triage Results
                  {triageResult.threatIntelSources && triageResult.threatIntelSources.length > 0 && (
                    <Badge variant="outline" className="text-[10px] gap-1 border-green-500/50 text-green-500" data-testid="badge-threat-intel-enriched">
                      <Shield className="h-3 w-3" />
                      Intel-Enriched ({triageResult.threatIntelSources.length} sources)
                    </Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3" data-testid="triage-result">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">Severity</div>
                    <SeverityBadge severity={triageResult.severity} />
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">Priority</div>
                    <div className="text-sm font-bold" data-testid="text-triage-priority">P{triageResult.priority}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">Category</div>
                    <div className="text-xs" data-testid="text-triage-category">{triageResult.category}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase">False Positive</div>
                    <div className="text-xs" data-testid="text-triage-fp">{Math.round(triageResult.falsePositiveLikelihood * 100)}%</div>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase mb-1">Recommended Action</div>
                  <div className="text-sm text-primary font-medium" data-testid="text-triage-action">{triageResult.recommendedAction}</div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase mb-1">Reasoning</div>
                  <div className="text-xs text-muted-foreground" data-testid="text-triage-reasoning">{triageResult.reasoning}</div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {triageResult.mitreTactic && <span className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px]" data-testid="text-triage-mitre-tactic">{triageResult.mitreTactic}</span>}
                  {triageResult.mitreTechnique && <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono" data-testid="text-triage-mitre-technique">{triageResult.mitreTechnique}</span>}
                </div>
                {triageResult.relatedIocs && triageResult.relatedIocs.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase mb-1">IOCs</div>
                    <div className="flex flex-wrap gap-1">
                      {triageResult.relatedIocs.map((ioc, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono" data-testid={`triage-ioc-${i}`}>{typeof ioc === "string" ? ioc : `${ioc.value} (${ioc.type})`}</span>
                      ))}
                    </div>
                  </div>
                )}
                {triageResult.threatIntelSources && triageResult.threatIntelSources.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase mb-1">Threat Intel Sources Used</div>
                    <div className="flex flex-wrap gap-1" data-testid="triage-intel-sources">
                      {triageResult.threatIntelSources.map((source, i) => (
                        <Badge key={i} variant="secondary" className="text-[10px] gap-1" data-testid={`badge-intel-source-${i}`}>
                          <Shield className="h-3 w-3" />
                          {source}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              {!feedbackSubmitted && (
                <div className="flex items-center gap-2 pt-2 border-t">
                  <span className="text-xs text-muted-foreground">Was this AI analysis helpful?</span>
                  <Button size="icon" variant="ghost" data-testid="button-feedback-up" disabled={feedbackSubmitted || submitFeedback.isPending} onClick={() => submitFeedback.mutate(5)}>
                    <ThumbsUp className="h-3 w-3" />
                  </Button>
                  <Button size="icon" variant="ghost" data-testid="button-feedback-down" disabled={feedbackSubmitted || submitFeedback.isPending} onClick={() => submitFeedback.mutate(1)}>
                    <ThumbsDown className="h-3 w-3" />
                  </Button>
                </div>
              )}
              {feedbackSubmitted && (
                <div className="flex items-center gap-2 pt-2 border-t">
                  <span className="text-xs text-muted-foreground">Thank you for your feedback!</span>
                </div>
              )}
              </CardContent>
            </Card>
          )}

          <Collapsible open={rawDataOpen} onOpenChange={setRawDataOpen}>
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between gap-2">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    Raw Data
                  </CardTitle>
                  <CollapsibleTrigger asChild>
                    <Button size="sm" variant="ghost" data-testid="button-toggle-raw-data">
                      {rawDataOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </Button>
                  </CollapsibleTrigger>
                </div>
              </CardHeader>
              <CollapsibleContent>
                <CardContent>
                  <pre className="text-xs font-mono bg-muted/30 p-3 rounded-md overflow-auto max-h-96" data-testid="text-raw-data">
                    {alert.rawData ? JSON.stringify(alert.rawData, null, 2) : "No raw data available"}
                  </pre>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>

          <Collapsible open={normalizedDataOpen} onOpenChange={setNormalizedDataOpen}>
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between gap-2">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    Normalized Data
                  </CardTitle>
                  <CollapsibleTrigger asChild>
                    <Button size="sm" variant="ghost" data-testid="button-toggle-normalized-data">
                      {normalizedDataOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </Button>
                  </CollapsibleTrigger>
                </div>
              </CardHeader>
              <CollapsibleContent>
                <CardContent>
                  <pre className="text-xs font-mono bg-muted/30 p-3 rounded-md overflow-auto max-h-96" data-testid="text-normalized-data">
                    {alert.normalizedData ? JSON.stringify(alert.normalizedData, null, 2) : "No normalized data available"}
                  </pre>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        </div>

        <div className="space-y-4">
          <Card className="gradient-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Actions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <span className="text-xs text-muted-foreground">Status</span>
                <Select
                  value={alert.status}
                  onValueChange={(value) => updateAlert.mutate({ status: value } as Partial<Alert>)}
                >
                  <SelectTrigger className="mt-1" data-testid="select-status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ALERT_STATUSES.map((s) => (
                      <SelectItem key={s} value={s}>
                        <span className="capitalize">{s.replace(/_/g, " ")}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <Button
                className="w-full"
                onClick={() => triage.mutate()}
                disabled={triage.isPending}
                data-testid="button-triage"
              >
                {triage.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Brain className="h-4 w-4 mr-2" />
                )}
                {triage.isPending ? "Analyzing..." : "Triage with AI"}
              </Button>

              <div>
                <span className="text-xs text-muted-foreground">Assign To</span>
                <Input
                  className="mt-1"
                  placeholder="Unassigned"
                  value={assigneeValue ?? alert.assignedTo ?? ""}
                  onChange={(e) => setAssigneeValue(e.target.value)}
                  onBlur={handleAssigneeSubmit}
                  onKeyDown={(e) => { if (e.key === "Enter") handleAssigneeSubmit(); }}
                  data-testid="input-assignee"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Tag className="h-4 w-4" />
                Tags
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {alertTags && alertTags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {alertTags.map((tag) => (
                    <Badge
                      key={tag.id}
                      variant="secondary"
                      className="text-[10px]"
                      style={{ borderColor: (tag.color || "#6366f1") + "40", backgroundColor: (tag.color || "#6366f1") + "15", color: tag.color || "#6366f1" }}
                      data-testid={`tag-${tag.id}`}
                    >
                      {tag.name}
                    </Badge>
                  ))}
                </div>
              )}
              {showTagSelect ? (
                <Select onValueChange={(tagId) => addTag.mutate(tagId)}>
                  <SelectTrigger data-testid="select-add-tag">
                    <SelectValue placeholder="Select a tag..." />
                  </SelectTrigger>
                  <SelectContent>
                    {availableTags.map((tag) => (
                      <SelectItem key={tag.id} value={tag.id}>{tag.name}</SelectItem>
                    ))}
                    {availableTags.length === 0 && (
                      <div className="px-3 py-2 text-xs text-muted-foreground">No tags available</div>
                    )}
                  </SelectContent>
                </Select>
              ) : (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowTagSelect(true)}
                  data-testid="button-add-tag"
                >
                  <Plus className="h-3 w-3 mr-1" />
                  Add Tag
                </Button>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Analyst Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Textarea
                placeholder="Add analyst notes..."
                value={analystNotes ?? alert.analystNotes ?? ""}
                onChange={(e) => setAnalystNotes(e.target.value)}
                className="min-h-[100px]"
                data-testid="input-analyst-notes"
              />
              <Button
                size="sm"
                onClick={handleNoteSave}
                disabled={updateAlert.isPending}
                data-testid="button-save-notes"
              >
                <Save className="h-3 w-3 mr-1" />
                Save Notes
              </Button>
            </CardContent>
          </Card>

          {alertEntities && alertEntities.length > 0 && (
            <Card data-testid="alert-entities-panel">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Network className="h-4 w-4 text-purple-400" />
                  Linked Entities ({alertEntities.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1.5">
                  {alertEntities.map((entity) => (
                    <Link key={entity.id} href="/entity-graph">
                      <div className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20 hover-elevate cursor-pointer" data-testid={`alert-entity-${entity.id}`}>
                        {entity.type === "user" && <User className="h-3.5 w-3.5 text-blue-400 shrink-0" />}
                        {entity.type === "host" && <Server className="h-3.5 w-3.5 text-emerald-400 shrink-0" />}
                        {entity.type === "ip" && <Globe className="h-3.5 w-3.5 text-purple-400 shrink-0" />}
                        {entity.type === "domain" && <Globe className="h-3.5 w-3.5 text-cyan-400 shrink-0" />}
                        {entity.type === "file_hash" && <Hash className="h-3.5 w-3.5 text-orange-400 shrink-0" />}
                        {entity.type === "email" && <Mail className="h-3.5 w-3.5 text-pink-400 shrink-0" />}
                        {entity.type === "url" && <Link2 className="h-3.5 w-3.5 text-yellow-400 shrink-0" />}
                        {entity.type === "process" && <Terminal className="h-3.5 w-3.5 text-red-400 shrink-0" />}
                        <span className="font-mono truncate flex-1">{entity.displayName || entity.value}</span>
                        <Badge variant="outline" className="text-[9px] shrink-0">{entity.type}</Badge>
                        <Badge variant="outline" className="text-[9px] shrink-0">{entity.role}</Badge>
                        <span className={`text-[10px] font-semibold shrink-0 ${
                          (entity.riskScore || 0) >= 0.8 ? "text-red-400" :
                          (entity.riskScore || 0) >= 0.6 ? "text-orange-400" :
                          (entity.riskScore || 0) >= 0.4 ? "text-yellow-400" : "text-emerald-400"
                        }`}>{((entity.riskScore || 0) * 100).toFixed(0)}%</span>
                      </div>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {alert.incidentId && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Related Incident
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Link href={`/incidents/${alert.incidentId}`}>
                  <Button variant="outline" className="w-full" data-testid="button-view-incident">
                    <Globe className="h-4 w-4 mr-2" />
                    View Incident
                  </Button>
                </Link>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
