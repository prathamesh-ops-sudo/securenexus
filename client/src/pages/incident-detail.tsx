import { useQuery, useMutation } from "@tanstack/react-query";
import { useParams } from "wouter";
import { ArrowLeft, Shield, AlertTriangle, Clock, TrendingDown, CheckCircle2, MessageSquare, Tag, Send, ArrowUpRight, User, Brain, Loader2, Sparkles, Activity, ThumbsUp, ThumbsDown, Network, Server, Globe, Hash, Mail, Link2, Terminal, FileText, BarChart3, Target, Users, Crosshair, CheckCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Link } from "wouter";
import { useState } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { SeverityBadge, IncidentStatusBadge, PriorityBadge, formatTimestamp, formatRelativeTime } from "@/components/security-badges";
import type { Incident, Alert, IncidentComment, Tag as TagType, AuditLog } from "@shared/schema";

const INCIDENT_STATUSES = ["open", "investigating", "contained", "eradicated", "recovered", "resolved", "closed"] as const;

function formatActionDescription(action: string, details: any): string {
  if (!details) return action.replace(/_/g, " ");
  switch (action) {
    case "incident_status_change":
      return `Status changed from ${details.from || "unknown"} to ${details.to || "unknown"}`;
    case "incident_priority_change":
      return `Priority changed from P${details.from || "?"} to P${details.to || "?"}`;
    case "incident_assignment_change":
      return `Assigned to ${details.to || "unassigned"}${details.from ? ` (was ${details.from})` : ""}`;
    case "incident_escalated":
      return details.escalated ? "Incident escalated" : "Incident de-escalated";
    case "incident_created":
      return "Incident created";
    case "comment_added":
      return "Comment added";
    default:
      return action.replace(/_/g, " ");
  }
}

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const [commentBody, setCommentBody] = useState("");
  const [narrativeResult, setNarrativeResult] = useState<NarrativeResult | null>(null);
  const [assigneeValue, setAssigneeValue] = useState<string | null>(null);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);
  const [showReasoningTrace, setShowReasoningTrace] = useState(false);
  const [showConfidenceBreakdown, setShowConfidenceBreakdown] = useState(false);
  const { toast } = useToast();

  function renderNarrativeWithCitations(text: string, alertList?: Alert[]) {
    const parts = text.split(/(\[Alert [^\]]+\])/g);
    return parts.map((part, i) => {
      const match = part.match(/^\[Alert ([^\]]+)\]$/);
      if (match) {
        const alertId = match[1];
        const linkedAlert = alertList?.find(a => a.id === alertId || a.id.startsWith(alertId));
        return (
          <Link key={i} href={linkedAlert ? `/alerts/${linkedAlert.id}` : "#"}>
            <span
              className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-primary/15 text-primary text-[11px] font-mono cursor-pointer hover-elevate"
              data-testid={`citation-${alertId.substring(0, 8)}`}
            >
              <AlertTriangle className="h-2.5 w-2.5" />
              Alert {alertId.substring(0, 8)}
            </span>
          </Link>
        );
      }
      return <span key={i}>{part}</span>;
    });
  }

  const { data: incident, isLoading } = useQuery<Incident>({
    queryKey: ["/api/incidents", params.id],
    enabled: !!params.id,
  });

  const { data: relatedAlerts } = useQuery<Alert[]>({
    queryKey: ["/api/incidents", params.id, "alerts"],
    enabled: !!params.id,
  });

  const { data: comments } = useQuery<IncidentComment[]>({
    queryKey: ["/api/incidents", params.id, "comments"],
    enabled: !!params.id,
  });

  const { data: incidentTags } = useQuery<TagType[]>({
    queryKey: ["/api/incidents", params.id, "tags"],
    enabled: !!params.id,
  });

  const { data: activityLogs } = useQuery<AuditLog[]>({
    queryKey: ["/api/incidents", params.id, "activity"],
    enabled: !!params.id,
  });

  const { data: incidentEntities } = useQuery<{ id: string; type: string; value: string; displayName: string; riskScore: number; alertCount: number; role: string; alertId: string }[]>({
    queryKey: ["/api/incidents", params.id, "entities"],
    enabled: !!params.id,
  });

  const updateIncident = useMutation({
    mutationFn: async (data: Partial<Incident>) => {
      await apiRequest("PATCH", `/api/incidents/${params.id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "activity"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      toast({ title: "Incident Updated", description: "Changes saved successfully" });
    },
    onError: (error: any) => {
      toast({ title: "Update Failed", description: error.message, variant: "destructive" });
    },
  });

  const addComment = useMutation({
    mutationFn: async (body: string) => {
      await apiRequest("POST", `/api/incidents/${params.id}/comments`, { body, userName: "Analyst" });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "comments"] });
      setCommentBody("");
    },
  });

  const submitFeedback = useMutation({
    mutationFn: async (rating: number) => {
      await apiRequest("POST", "/api/ai/feedback", { resourceType: "narrative", resourceId: incident?.id, rating });
    },
    onSuccess: () => {
      setFeedbackSubmitted(true);
      toast({ title: "Feedback Submitted", description: "Thank you for your feedback" });
    },
    onError: (error: any) => {
      toast({ title: "Feedback Failed", description: error.message, variant: "destructive" });
    },
  });

  const generateNarrative = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/ai/narrative/${params.id}`, {});
      return res.json();
    },
    onSuccess: (data: NarrativeResult) => {
      setNarrativeResult(data);
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id] });
      toast({ title: "AI Narrative Generated", description: "Attack narrative and recommendations are ready for review" });
    },
    onError: (error: any) => {
      toast({ title: "AI Narrative Failed", description: error.message, variant: "destructive" });
    },
  });

  const currentAssignee = assigneeValue ?? incident?.assignedTo ?? "";

  function handleAssigneeSubmit() {
    const trimmed = currentAssignee.trim();
    if (trimmed !== (incident?.assignedTo || "")) {
      updateIncident.mutate({ assignedTo: trimmed || null } as Partial<Incident>);
    }
    setAssigneeValue(null);
  }

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-4 md:p-6 text-center py-20">
        <p className="text-muted-foreground">Incident not found</p>
        <Link href="/incidents">
          <Button variant="outline" className="mt-4" data-testid="button-back-incidents">Back to Incidents</Button>
        </Link>
      </div>
    );
  }

  const mitigationSteps = incident.mitigationSteps
    ? (typeof incident.mitigationSteps === "string"
      ? JSON.parse(incident.mitigationSteps)
      : incident.mitigationSteps) as string[]
    : [];

  const affectedAssets = incident.affectedAssets
    ? (typeof incident.affectedAssets === "string"
      ? JSON.parse(incident.affectedAssets)
      : incident.affectedAssets) as string[]
    : [];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
      <div className="space-y-3">
        <div className="flex items-start gap-3">
          <Link href="/incidents">
            <Button size="icon" variant="ghost" data-testid="button-back">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold tracking-tight" data-testid="text-incident-title">{incident.title}</h1>
              <SeverityBadge severity={incident.severity} />
              <IncidentStatusBadge status={incident.status} />
              {incident.escalated && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border bg-red-500/10 text-red-500 border-red-500/20">
                  <ArrowUpRight className="h-3 w-3" />
                  Escalated
                </span>
              )}
            </div>
            <p className="text-sm text-muted-foreground mt-1">{incident.summary}</p>
            <div className="gradient-accent-line w-24 mt-2" />
            {incidentTags && incidentTags.length > 0 && (
              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                {incidentTags.map((tag) => (
                  <Badge key={tag.id} variant="secondary" className="text-[10px]" style={{ borderColor: (tag.color || "#6366f1") + "40", backgroundColor: (tag.color || "#6366f1") + "15", color: tag.color || "#6366f1" }} data-testid={`tag-${tag.id}`}>
                    {tag.name}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <Button
            onClick={() => generateNarrative.mutate()}
            disabled={generateNarrative.isPending}
            data-testid="button-generate-narrative"
          >
            {generateNarrative.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Brain className="h-4 w-4 mr-2" />
            )}
            {generateNarrative.isPending ? "Generating..." : "AI Narrative"}
          </Button>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Status:</span>
            <Select
              value={incident.status}
              onValueChange={(value) => updateIncident.mutate({ status: value })}
            >
              <SelectTrigger className="w-[140px]" data-testid="select-status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {INCIDENT_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    <span className="capitalize">{s}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Priority:</span>
            <Select
              value={String(incident.priority ?? 3)}
              onValueChange={(value) => updateIncident.mutate({ priority: parseInt(value) })}
            >
              <SelectTrigger className="w-[80px]" data-testid="select-priority">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[1, 2, 3, 4, 5].map((p) => (
                  <SelectItem key={p} value={String(p)}>P{p}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Assignee:</span>
            <Input
              className="w-[160px]"
              placeholder="Unassigned"
              value={assigneeValue ?? incident.assignedTo ?? ""}
              onChange={(e) => setAssigneeValue(e.target.value)}
              onBlur={handleAssigneeSubmit}
              onKeyDown={(e) => { if (e.key === "Enter") handleAssigneeSubmit(); }}
              data-testid="input-assignee"
            />
          </div>

          <Button
            variant={incident.escalated ? "destructive" : "outline"}
            onClick={() => updateIncident.mutate({ escalated: !incident.escalated })}
            disabled={updateIncident.isPending}
            data-testid="button-escalate"
          >
            <ArrowUpRight className="h-4 w-4 mr-1" />
            {incident.escalated ? "De-escalate" : "Escalate"}
          </Button>
        </div>
      </div>

      {narrativeResult && (
        <Card className="border-primary/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
              <Sparkles className="h-4 w-4 text-primary" />
              AI-Generated Analysis (Risk Score: {narrativeResult.riskScore}/100)
              {narrativeResult.threatIntelSources && narrativeResult.threatIntelSources.length > 0 && (
                <Badge variant="outline" className="text-[10px] gap-1 border-green-500/50 text-green-500" data-testid="badge-narrative-intel-enriched">
                  <Shield className="h-3 w-3" />
                  Intel-Enriched ({narrativeResult.threatIntelSources.length} sources)
                </Badge>
              )}
            </CardTitle>
            <p className="text-xs text-primary/80 font-medium mt-1" data-testid="text-ai-gen-summary">{narrativeResult.summary}</p>
          </CardHeader>
          <CardContent className="space-y-4">
            {narrativeResult.attackTimeline.length > 0 && (
              <div>
                <div className="text-xs font-medium mb-2">Attack Timeline</div>
                <div className="space-y-1.5 border-l-2 border-primary/30 pl-3">
                  {narrativeResult.attackTimeline.map((event, i) => (
                    <div key={i} className="text-xs" data-testid={`timeline-event-${i}`}>
                      <span className="text-primary font-mono">{event.timestamp}</span>
                      {event.mitreTechnique && (
                        <span className="ml-1 px-1 py-0.5 rounded bg-muted text-[9px] font-mono">{event.mitreTechnique}</span>
                      )}
                      <span className="text-muted-foreground ml-2">{event.description}</span>
                      {event.alertId && (
                        <Link href={`/alerts/${event.alertId}`}>
                          <span className="ml-1 inline-flex items-center gap-0.5 px-1 py-0.5 rounded bg-primary/15 text-primary text-[9px] font-mono cursor-pointer hover-elevate">
                            <AlertTriangle className="h-2 w-2" />
                            {event.alertId.substring(0, 8)}
                          </span>
                        </Link>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div>
              <div className="text-xs font-medium mb-1">Attacker Profile</div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><span className="text-muted-foreground">Sophistication:</span> <span className="capitalize">{narrativeResult.attackerProfile.sophistication}</span></div>
                <div><span className="text-muted-foreground">Motivation:</span> <span className="capitalize">{narrativeResult.attackerProfile.likelyMotivation}</span></div>
                <div className="col-span-2"><span className="text-muted-foreground">Origin:</span> {narrativeResult.attackerProfile.estimatedOrigin}</div>
              </div>
              {narrativeResult.attackerProfile.ttps.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {narrativeResult.attackerProfile.ttps.map((ttp, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px]">{ttp}</span>
                  ))}
                </div>
              )}
            </div>
            {narrativeResult.iocs.length > 0 && (
              <div>
                <div className="text-xs font-medium mb-1">Indicators of Compromise</div>
                <div className="flex flex-wrap gap-1">
                  {narrativeResult.iocs.map((ioc, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono" data-testid={`ioc-${i}`}>{typeof ioc === "string" ? ioc : `${(ioc as any).value} (${(ioc as any).type})`}</span>
                  ))}
                </div>
              </div>
            )}
            {narrativeResult.killChainAnalysis && narrativeResult.killChainAnalysis.length > 0 && (
              <div>
                <div className="text-xs font-medium mb-2">Kill Chain Analysis</div>
                <div className="space-y-2">
                  {narrativeResult.killChainAnalysis.map((phase, i) => (
                    <div key={i} className="p-2 rounded-md bg-muted/30 text-xs" data-testid={`killchain-phase-${i}`}>
                      <div className="font-medium text-primary">{phase.phase}</div>
                      <div className="text-muted-foreground mt-0.5">{phase.description}</div>
                      {phase.evidence.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {phase.evidence.map((ev, j) => (
                            <span key={j} className="px-1 py-0.5 rounded bg-muted text-[9px] font-mono">{ev}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {narrativeResult.nistPhase && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">NIST IR Phase:</span>
                <Badge variant="outline" className="text-[10px]">{narrativeResult.nistPhase}</Badge>
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

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <AlertTriangle className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">{incident.alertCount}</div>
            <div className="text-[10px] text-muted-foreground">Correlated Alerts</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <TrendingDown className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">{incident.confidence ? `${Math.round(incident.confidence * 100)}%` : "N/A"}</div>
            <div className="text-[10px] text-muted-foreground">Confidence</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <Clock className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold capitalize">{incident.status}</div>
            <div className="text-[10px] text-muted-foreground">Status</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <Shield className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">{incident.mitreTactics?.length || 0}</div>
            <div className="text-[10px] text-muted-foreground">MITRE Tactics</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <Tag className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
            <div className="text-lg font-bold">P{incident.priority ?? 3}</div>
            <div className="text-[10px] text-muted-foreground">Priority</div>
          </CardContent>
        </Card>
      </div>

      {incident.aiNarrative && (
        <Card className="gradient-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              AI-Generated Narrative
              {(incident as any).referencedAlertIds?.length > 0 && (
                <Badge variant="secondary" className="text-[9px]">{(incident as any).referencedAlertIds.length} citations</Badge>
              )}
            </CardTitle>
            {incident.aiSummary && (
              <p className="text-xs text-primary/80 font-medium mt-1" data-testid="text-ai-summary">{incident.aiSummary}</p>
            )}
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm leading-relaxed text-muted-foreground" data-testid="text-ai-narrative">
              {renderNarrativeWithCitations(incident.aiNarrative, relatedAlerts || undefined)}
            </div>
            {(incident as any).reasoningTrace && (
              <div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowReasoningTrace(!showReasoningTrace)}
                  data-testid="button-toggle-reasoning-trace"
                  className="text-xs"
                >
                  <FileText className="h-3 w-3 mr-1" />
                  {showReasoningTrace ? "Hide" : "Show"} Reasoning Trace
                </Button>
                {showReasoningTrace && (
                  <div className="mt-2 p-3 rounded-md bg-muted/50 border text-[11px] font-mono whitespace-pre-wrap text-muted-foreground" data-testid="reasoning-trace-content">
                    {(incident as any).reasoningTrace}
                  </div>
                )}
              </div>
            )}
            {incident.confidence != null && (
              <div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowConfidenceBreakdown(!showConfidenceBreakdown)}
                  data-testid="button-toggle-confidence"
                  className="text-xs"
                >
                  <BarChart3 className="h-3 w-3 mr-1" />
                  {showConfidenceBreakdown ? "Hide" : "Show"} Confidence Breakdown
                </Button>
                {showConfidenceBreakdown && (
                  <div className="mt-2 p-3 rounded-md bg-muted/50 border space-y-2" data-testid="confidence-breakdown">
                    <div className="text-[11px] font-medium">Correlation Confidence: {Math.round(incident.confidence * 100)}%</div>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { label: "Shared Entities", weight: 0.25 },
                        { label: "Temporal Proximity", weight: 0.15 },
                        { label: "MITRE Alignment", weight: 0.20 },
                        { label: "Severity Pattern", weight: 0.10 },
                        { label: "Source Correlation", weight: 0.05 },
                        { label: "Category Match", weight: 0.15 },
                        { label: "Kill Chain Progression", weight: 0.10 },
                      ].map((factor) => (
                        <div key={factor.label} className="flex items-center gap-2">
                          <span className="text-[10px] text-muted-foreground w-32 shrink-0">{factor.label}</span>
                          <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-primary rounded-full" 
                              style={{ width: `${factor.weight * 100 * (incident.confidence || 0) / 0.25}%` }}
                            />
                          </div>
                          <span className="text-[10px] text-muted-foreground w-8 text-right">{Math.round(factor.weight * 100)}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {incident.mitreTactics && incident.mitreTactics.length > 0 && (
          <Card className="gradient-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">MITRE ATT&CK Mapping</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1.5">Tactics</div>
                <div className="flex flex-wrap gap-1.5">
                  {incident.mitreTactics.map((tactic, i) => (
                    <span key={i} className="px-2 py-1 rounded-md bg-primary/10 text-primary text-xs">{tactic}</span>
                  ))}
                </div>
              </div>
              {incident.mitreTechniques && incident.mitreTechniques.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1.5">Techniques</div>
                  <div className="flex flex-wrap gap-1.5">
                    {incident.mitreTechniques.map((technique, i) => (
                      <span key={i} className="px-2 py-1 rounded-md bg-muted text-xs font-mono">{technique}</span>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {mitigationSteps.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-green-500" />
                Mitigation Steps
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-2">
                {mitigationSteps.map((step: string, i: number) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-muted text-[10px] font-medium flex-shrink-0 mt-0.5">{i + 1}</span>
                    <span className="text-muted-foreground">{step}</span>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        )}
      </div>

      {affectedAssets.length > 0 && (
        <Card className="gradient-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Affected Assets</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {affectedAssets.map((asset: string, i: number) => (
                <span key={i} className="px-2 py-1 rounded-md bg-muted text-xs font-mono" data-testid={`asset-${i}`}>{asset}</span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {incidentEntities && incidentEntities.length > 0 && (
        <Card data-testid="incident-entities-panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Network className="h-4 w-4 text-purple-400" />
              Linked Entities ({Math.min(incidentEntities.length, 20)})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5">
              {incidentEntities.slice(0, 20).map((entity) => (
                <Link key={entity.id} href="/entity-graph">
                  <div className="flex items-center gap-2 text-xs p-2 rounded-md bg-muted/20 hover-elevate cursor-pointer" data-testid={`incident-entity-${entity.id}`}>
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
            {incidentEntities.length > 20 && (
              <div className="text-[10px] text-muted-foreground mt-2 text-center">
                Showing 20 of {incidentEntities.length} entities
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {relatedAlerts && relatedAlerts.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Related Alerts ({relatedAlerts.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {relatedAlerts.map((alert) => (
                <div key={alert.id} className="flex items-center gap-3 p-2 rounded-md hover-elevate" data-testid={`related-alert-${alert.id}`}>
                  <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium">{alert.title}</div>
                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap">
                      <span>{alert.source}</span>
                      <SeverityBadge severity={alert.severity} />
                      {alert.sourceIp && <span>IP: {alert.sourceIp}</span>}
                      {alert.correlationScore && (
                        <span className="text-primary">{Math.round(alert.correlationScore * 100)}% correlation</span>
                      )}
                      {alert.detectedAt && <span>{formatTimestamp(alert.detectedAt)}</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <MessageSquare className="h-4 w-4" />
            Analyst Comments ({comments?.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {comments && comments.length > 0 ? (
            <div className="space-y-3">
              {comments.map((comment) => (
                <div key={comment.id} className="flex items-start gap-3 p-3 rounded-md bg-muted/30" data-testid={`comment-${comment.id}`}>
                  <div className="flex items-center justify-center w-7 h-7 rounded-full bg-muted flex-shrink-0">
                    <User className="h-3 w-3 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-medium">{comment.userName || "Unknown"}</span>
                      <span className="text-[10px] text-muted-foreground">{formatTimestamp(comment.createdAt)}</span>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">{comment.body}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No comments yet</p>
          )}

          <div className="flex items-start gap-2">
            <Textarea
              placeholder="Add a comment..."
              value={commentBody}
              onChange={(e) => setCommentBody(e.target.value)}
              className="flex-1 min-h-[60px]"
              data-testid="input-comment"
            />
            <Button
              size="icon"
              onClick={() => commentBody.trim() && addComment.mutate(commentBody.trim())}
              disabled={!commentBody.trim() || addComment.isPending}
              data-testid="button-add-comment"
            >
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Activity Timeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          {activityLogs && activityLogs.length > 0 ? (
            <div className="relative space-y-0">
              {activityLogs.map((log, index) => (
                <div
                  key={log.id}
                  className="flex items-start gap-3 relative pb-4"
                  data-testid={`timeline-entry-${index}`}
                >
                  <div className="flex flex-col items-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-primary flex-shrink-0 mt-1.5" />
                    {index < activityLogs.length - 1 && (
                      <div className="w-px flex-1 bg-border mt-1" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0 pb-1">
                    <div className="text-sm">
                      {formatActionDescription(log.action, log.details)}
                    </div>
                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap mt-0.5">
                      {log.userName && <span>{log.userName}</span>}
                      <span>{formatRelativeTime(log.createdAt)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No activity recorded yet</p>
          )}
        </CardContent>
      </Card>

      <Card className="gradient-card" data-testid="executive-attack-summary">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FileText className="h-4 w-4 text-red-500" />
            <span className="gradient-text-red">Executive Attack Summary</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div data-testid="kill-chain-progress">
            <div className="text-xs font-medium mb-2 flex items-center gap-1.5">
              <Target className="h-3.5 w-3.5 text-muted-foreground" />
              Kill Chain Progress
            </div>
            <div className="flex items-center gap-1 overflow-x-auto pb-1">
              {(() => {
                const killChainStages = [
                  { name: "Reconnaissance", tactics: ["reconnaissance", "resource_development"] },
                  { name: "Weaponization", tactics: ["credential_access", "discovery"] },
                  { name: "Delivery", tactics: ["initial_access"] },
                  { name: "Exploitation", tactics: ["execution"] },
                  { name: "Installation", tactics: ["persistence", "privilege_escalation", "defense_evasion"] },
                  { name: "Command & Control", tactics: ["command_and_control"] },
                  { name: "Actions on Objectives", tactics: ["collection", "exfiltration", "impact", "lateral_movement"] },
                ];
                const incidentTactics = (incident.mitreTactics || []).map((t: string) => t.toLowerCase().replace(/\s+/g, "_"));
                return killChainStages.map((stage, idx) => {
                  const isActive = stage.tactics.some((t) => incidentTactics.includes(t));
                  return (
                    <div
                      key={stage.name}
                      className={`flex items-center gap-1 px-2 py-1.5 rounded-md text-[10px] font-medium flex-shrink-0 border ${
                        isActive
                          ? "bg-red-500/15 border-red-500/30 text-red-500"
                          : "bg-muted/30 border-border text-muted-foreground"
                      }`}
                      data-testid={`killchain-stage-${stage.name.toLowerCase().replace(/\s+/g, "-")}`}
                    >
                      {isActive && <CheckCircle className="h-3 w-3" />}
                      {stage.name}
                    </div>
                  );
                });
              })()}
            </div>
          </div>

          <div data-testid="diamond-model">
            <div className="text-xs font-medium mb-2 flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5 text-muted-foreground" />
              Diamond Model
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="p-3 rounded-md bg-muted/30 border border-border" data-testid="diamond-adversary">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1 flex items-center gap-1">
                  <Users className="h-3 w-3" />
                  Adversary
                </div>
                <div className="text-xs">
                  {incident.attackerProfile ? (
                    <>
                      <span className="font-medium">{(incident.attackerProfile as any)?.type || (incident.attackerProfile as any)?.sophistication || "Unknown"}</span>
                      {(incident.attackerProfile as any)?.origin && (
                        <span className="text-muted-foreground ml-1">({(incident.attackerProfile as any).origin})</span>
                      )}
                      {(incident.attackerProfile as any)?.estimatedOrigin && (
                        <span className="text-muted-foreground ml-1">({(incident.attackerProfile as any).estimatedOrigin})</span>
                      )}
                    </>
                  ) : (
                    <span className="text-muted-foreground">Not identified</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-md bg-muted/30 border border-border" data-testid="diamond-infrastructure">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1 flex items-center gap-1">
                  <Server className="h-3 w-3" />
                  Infrastructure
                </div>
                <div className="text-xs">
                  {incident.iocs && (incident.iocs as any[]).length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {(incident.iocs as any[]).slice(0, 3).map((ioc: any, i: number) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">
                          {typeof ioc === "string" ? ioc : ioc.value || ioc}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">No IOCs identified</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-md bg-muted/30 border border-border" data-testid="diamond-capability">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1 flex items-center gap-1">
                  <Shield className="h-3 w-3" />
                  Capability
                </div>
                <div className="text-xs">
                  {incident.mitreTechniques && incident.mitreTechniques.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {incident.mitreTechniques.slice(0, 4).map((tech: string, i: number) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px] font-mono">
                          {tech}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">No techniques mapped</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-md bg-muted/30 border border-border" data-testid="diamond-victim">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1 flex items-center gap-1">
                  <Target className="h-3 w-3" />
                  Victim
                </div>
                <div className="text-xs">
                  {affectedAssets.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {affectedAssets.slice(0, 3).map((asset: string, i: number) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">
                          {asset}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">No assets identified</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div data-testid="impact-assessment">
            <div className="text-xs font-medium mb-2 flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
              Impact Assessment
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-muted-foreground">Severity:</span>
                <SeverityBadge severity={incident.severity} />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-muted-foreground">Confidence:</span>
                <span className="text-xs font-semibold" data-testid="text-exec-confidence">
                  {incident.confidence ? `${Math.round(incident.confidence * 100)}%` : "N/A"}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-muted-foreground">Alerts:</span>
                <span className="text-xs font-semibold" data-testid="text-exec-alert-count">{incident.alertCount}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-muted-foreground">Time Span:</span>
                <span className="text-xs font-semibold" data-testid="text-exec-timespan">
                  {(() => {
                    if (!incident.createdAt) return "N/A";
                    const start = new Date(incident.createdAt);
                    const end = incident.updatedAt ? new Date(incident.updatedAt) : new Date();
                    const diffMs = end.getTime() - start.getTime();
                    const diffHours = Math.floor(diffMs / 3600000);
                    const diffDays = Math.floor(diffMs / 86400000);
                    if (diffDays > 0) return `${diffDays}d ${diffHours % 24}h`;
                    return `${diffHours}h`;
                  })()}
                </span>
              </div>
            </div>
          </div>

          {Array.isArray(incident.iocs) && incident.iocs.length > 0 ? (
            <div data-testid="key-iocs">
              <div className="text-xs font-medium mb-2 flex items-center gap-1.5">
                <Crosshair className="h-3.5 w-3.5 text-muted-foreground" />
                Key IOCs
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(incident.iocs as any[]).slice(0, 5).map((ioc: any, i: number) => (
                  <span
                    key={i}
                    className="px-2 py-1 rounded-md bg-muted text-[10px] font-mono"
                    data-testid={`exec-ioc-${i}`}
                  >
                    {typeof ioc === "string" ? ioc : String((ioc as any).value || ioc)}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {incident.aiSummary && (
            <div data-testid="exec-ai-summary">
              <div className="text-xs font-medium mb-2 flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-muted-foreground" />
                AI Summary
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed" data-testid="text-exec-ai-summary">
                {incident.aiSummary}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {incident.leadAnalyst && (
        <div className="text-xs text-muted-foreground flex items-center gap-2 flex-wrap">
          <User className="h-3 w-3" />
          Lead Analyst: {incident.leadAnalyst}
          {incident.createdAt && <span className="ml-2">Created: {formatTimestamp(incident.createdAt)}</span>}
          {incident.updatedAt && <span className="ml-2">Updated: {formatTimestamp(incident.updatedAt)}</span>}
        </div>
      )}
    </div>
  );
}

interface NarrativeResult {
  narrative: string;
  summary: string;
  attackTimeline: { timestamp: string; description: string; alertId?: string; mitreTechnique?: string }[];
  attackerProfile: { ttps: string[]; sophistication: string; likelyMotivation: string; estimatedOrigin: string; diamondModel?: { adversary: string; infrastructure: string[]; capability: string; victim: string[] } };
  killChainAnalysis?: { phase: string; description: string; evidence: string[] }[];
  mitigationSteps: string[];
  iocs: (string | { type: string; value: string; context?: string })[];
  riskScore: number;
  nistPhase?: string;
  citedAlertIds?: string[];
  threatIntelSources?: string[];
}
