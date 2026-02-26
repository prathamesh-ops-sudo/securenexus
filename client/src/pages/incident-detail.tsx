import { useQuery, useMutation } from "@tanstack/react-query";
import { useParams } from "wouter";
import { ArrowLeft, Shield, AlertTriangle, Clock, TrendingDown, CheckCircle2, MessageSquare, Tag, Send, ArrowUpRight, User, Brain, Loader2, Sparkles, Activity, ThumbsUp, ThumbsDown, Network, Server, Globe, Hash, Mail, Link2, Terminal, FileText, BarChart3, Target, Users, Crosshair, CheckCircle, Plus, Trash2, ClipboardList, BookOpen, Lightbulb, Download, Calendar, ListChecks, PlayCircle, Eye, ClipboardCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Link } from "wouter";
import { useState, useMemo, useEffect } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { SeverityBadge, IncidentStatusBadge, PriorityBadge, formatTimestamp, formatRelativeTime } from "@/components/security-badges";
import type { Incident, Alert, IncidentComment, Tag as TagType, AuditLog, PostIncidentReview } from "@shared/schema";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";

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
  const [incidentFeedbackGiven, setIncidentFeedbackGiven] = useState<"up" | "down" | null>(null);
  const [correctionReason, setCorrectionReason] = useState("");
  const [correctionComment, setCorrectionComment] = useState("");
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

  const { data: rootCauseSummary } = useQuery<{ incidentId: string; summary: string; contributingSignals: { category: string; count: number }[]; impactedAssets: string[] }>({
    queryKey: ["/api/incidents", params.id, "root-cause-summary"],
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

  const submitIncidentFeedback = useMutation({
    mutationFn: async ({ rating, reason, comment }: { rating: number; reason?: string; comment?: string }) => {
      await apiRequest("POST", "/api/ai/feedback", {
        resourceType: "incident",
        resourceId: incident?.id,
        rating,
        correctionReason: reason,
        correctionComment: comment,
      });
    },
    onSuccess: () => {
      toast({ title: "Feedback Submitted", description: "Thank you for your feedback on this incident correlation" });
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

  const [activeTab, setActiveTab] = useState("overview");

  const [showAddEvidenceDialog, setShowAddEvidenceDialog] = useState(false);
  const [evidenceTitle, setEvidenceTitle] = useState("");
  const [evidenceType, setEvidenceType] = useState("note");
  const [evidenceDescription, setEvidenceDescription] = useState("");
  const [evidenceUrl, setEvidenceUrl] = useState("");

  const { data: evidenceItems, isLoading: evidenceLoading } = useQuery<any[]>({
    queryKey: ["/api/incidents", params.id, "evidence"],
    enabled: !!params.id,
  });

  const createEvidence = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", `/api/incidents/${params.id}/evidence`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "evidence"] });
      setShowAddEvidenceDialog(false);
      setEvidenceTitle(""); setEvidenceType("note"); setEvidenceDescription(""); setEvidenceUrl("");
      toast({ title: "Evidence Added" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteEvidence = useMutation({
    mutationFn: async (id: string) => { await apiRequest("DELETE", `/api/incidents/${params.id}/evidence/${id}`); },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "evidence"] });
      toast({ title: "Evidence Removed" });
    },
  });

  const [showAddHypothesisDialog, setShowAddHypothesisDialog] = useState(false);
  const [hypothesisTitle, setHypothesisTitle] = useState("");
  const [hypothesisDescription, setHypothesisDescription] = useState("");

  const { data: hypotheses, isLoading: hypothesesLoading } = useQuery<any[]>({
    queryKey: ["/api/incidents", params.id, "hypotheses"],
    enabled: !!params.id,
  });

  const createHypothesis = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", `/api/incidents/${params.id}/hypotheses`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "hypotheses"] });
      setShowAddHypothesisDialog(false);
      setHypothesisTitle(""); setHypothesisDescription("");
      toast({ title: "Hypothesis Created" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const updateHypothesis = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiRequest("PATCH", `/api/incidents/${params.id}/hypotheses/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "hypotheses"] });
      toast({ title: "Hypothesis Updated" });
    },
  });

  const deleteHypothesis = useMutation({
    mutationFn: async (id: string) => { await apiRequest("DELETE", `/api/incidents/${params.id}/hypotheses/${id}`); },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "hypotheses"] });
      toast({ title: "Hypothesis Removed" });
    },
  });

  const [showAddTaskDialog, setShowAddTaskDialog] = useState(false);
  const [taskTitle, setTaskTitle] = useState("");
  const [taskDescription, setTaskDescription] = useState("");
  const [taskAssignee, setTaskAssignee] = useState("");
  const [taskPriority, setTaskPriority] = useState("3");

  const { data: tasks, isLoading: tasksLoading } = useQuery<any[]>({
    queryKey: ["/api/incidents", params.id, "tasks"],
    enabled: !!params.id,
  });

  const createTask = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", `/api/incidents/${params.id}/tasks`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "tasks"] });
      setShowAddTaskDialog(false);
      setTaskTitle(""); setTaskDescription(""); setTaskAssignee(""); setTaskPriority("3");
      toast({ title: "Task Created" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const updateTask = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiRequest("PATCH", `/api/incidents/${params.id}/tasks/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "tasks"] });
      toast({ title: "Task Updated" });
    },
  });

  const deleteTask = useMutation({
    mutationFn: async (id: string) => { await apiRequest("DELETE", `/api/incidents/${params.id}/tasks/${id}`); },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "tasks"] });
      toast({ title: "Task Removed" });
    },
  });

  const { data: runbookTemplates } = useQuery<any[]>({
    queryKey: ["/api/runbook-templates"],
  });

  const seedRunbooks = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/runbook-templates/seed", {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/runbook-templates"] });
      toast({ title: "Runbooks Seeded", description: "Built-in runbook templates loaded" });
    },
  });

  const exportEvidence = useMutation({
    mutationFn: async () => {
      const res = await fetch(`/api/incidents/${params.id}/evidence-export`, { credentials: "include" });
      if (!res.ok) throw new Error("Export failed");
      const body = await res.json();
      const data = body.data ?? body;
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident-${params.id}-export.json`;
      a.click();
      URL.revokeObjectURL(url);
    },
    onSuccess: () => toast({ title: "Evidence Exported" }),
    onError: (e: Error) => toast({ title: "Export Failed", description: e.message, variant: "destructive" }),
  });

  const taskStats = useMemo(() => {
    if (!tasks) return { total: 0, done: 0, inProgress: 0, open: 0 };
    return {
      total: tasks.length,
      done: tasks.filter((t: any) => t.status === "done").length,
      inProgress: tasks.filter((t: any) => t.status === "in_progress").length,
      open: tasks.filter((t: any) => t.status === "open").length,
    };
  }, [tasks]);

  const [expandedRunbook, setExpandedRunbook] = useState<string | null>(null);

  const acknowledgeIncident = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", `/api/incidents/${params.id}/acknowledge`, {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id] });
      toast({ title: "Incident Acknowledged" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const applySla = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", `/api/incidents/${params.id}/apply-sla`, {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id] });
      toast({ title: "SLA Policy Applied" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const [slaTimerNow, setSlaTimerNow] = useState(() => new Date());
  useEffect(() => {
    const interval = setInterval(() => setSlaTimerNow(new Date()), 60000);
    return () => clearInterval(interval);
  }, []);

  function formatSlaTimer(dueAt: string | Date | null | undefined, completedAt: string | Date | null | undefined, completedLabel: string) {
    if (completedAt) return completedLabel;
    if (!dueAt) return "Not set";
    const due = new Date(dueAt);
    const diffMs = due.getTime() - slaTimerNow.getTime();
    const absDiffMs = Math.abs(diffMs);
    const hours = Math.floor(absDiffMs / 3600000);
    const minutes = Math.floor((absDiffMs % 3600000) / 60000);
    if (diffMs < 0) return `OVERDUE by ${hours}h ${minutes}m`;
    return `${hours}h ${minutes}m remaining`;
  }

  function isSlaOverdue(dueAt: string | Date | null | undefined, completedAt: string | Date | null | undefined) {
    if (completedAt || !dueAt) return false;
    return new Date(dueAt).getTime() < slaTimerNow.getTime();
  }

  const { data: pirData, isLoading: pirLoading } = useQuery<PostIncidentReview[]>({
    queryKey: ["/api/incidents", params.id, "pir"],
    enabled: !!params.id,
  });

  const existingPir = pirData && pirData.length > 0 ? pirData[0] : null;

  const [pirStatus, setPirStatus] = useState("draft");
  const [pirSummary, setPirSummary] = useState("");
  const [pirTimeline, setPirTimeline] = useState("");
  const [pirRootCause, setPirRootCause] = useState("");
  const [pirLessons, setPirLessons] = useState("");
  const [pirWell, setPirWell] = useState("");
  const [pirWrong, setPirWrong] = useState("");
  const [pirActionItems, setPirActionItems] = useState<string[]>([]);
  const [pirNewActionItem, setPirNewActionItem] = useState("");
  const [pirAttendees, setPirAttendees] = useState<string[]>([]);
  const [pirNewAttendee, setPirNewAttendee] = useState("");
  const [pirDate, setPirDate] = useState("");
  const [pirFormLoaded, setPirFormLoaded] = useState(false);

  useEffect(() => {
    if (existingPir && !pirFormLoaded) {
      setPirStatus(existingPir.status || "draft");
      setPirSummary(existingPir.summary || "");
      setPirTimeline(existingPir.timeline || "");
      setPirRootCause(existingPir.rootCause || "");
      setPirLessons(existingPir.lessonsLearned || "");
      setPirWell(existingPir.whatWentWell || "");
      setPirWrong(existingPir.whatWentWrong || "");
      setPirActionItems(Array.isArray(existingPir.actionItems) ? (existingPir.actionItems as string[]) : []);
      setPirAttendees(Array.isArray(existingPir.attendees) ? existingPir.attendees : []);
      setPirDate(existingPir.reviewDate ? new Date(existingPir.reviewDate).toISOString().split("T")[0] : "");
      setPirFormLoaded(true);
    }
  }, [existingPir, pirFormLoaded]);

  const createPir = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", `/api/incidents/${params.id}/pir`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "pir"] });
      setPirFormLoaded(false);
      toast({ title: "Post-Incident Review Created" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const updatePir = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiRequest("PATCH", `/api/pir/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "pir"] });
      toast({ title: "Post-Incident Review Updated" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deletePir = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/pir/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", params.id, "pir"] });
      setPirFormLoaded(false);
      setPirStatus("draft"); setPirSummary(""); setPirTimeline(""); setPirRootCause("");
      setPirLessons(""); setPirWell(""); setPirWrong(""); setPirActionItems([]);
      setPirAttendees([]); setPirDate("");
      toast({ title: "Post-Incident Review Deleted" });
    },
    onError: (e: Error) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function handleSavePir() {
    const data = {
      status: pirStatus,
      summary: pirSummary || undefined,
      timeline: pirTimeline || undefined,
      rootCause: pirRootCause || undefined,
      lessonsLearned: pirLessons || undefined,
      whatWentWell: pirWell || undefined,
      whatWentWrong: pirWrong || undefined,
      actionItems: pirActionItems.length > 0 ? pirActionItems : undefined,
      attendees: pirAttendees.length > 0 ? pirAttendees : undefined,
      reviewDate: pirDate ? new Date(pirDate).toISOString() : undefined,
    };
    if (existingPir) {
      updatePir.mutate({ id: existingPir.id, data });
    } else {
      createPir.mutate({ ...data, incidentId: params.id });
    }
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
              onValueChange={(value) => updateIncident.mutate({ priority: parseInt(value, 10) })}
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

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <TabsList data-testid="tabs-investigation">
            <TabsTrigger value="overview" data-testid="tab-overview">Overview</TabsTrigger>
            <TabsTrigger value="evidence" data-testid="tab-evidence">Evidence</TabsTrigger>
            <TabsTrigger value="hypotheses" data-testid="tab-hypotheses">Hypotheses</TabsTrigger>
            <TabsTrigger value="tasks" data-testid="tab-tasks">Tasks</TabsTrigger>
            <TabsTrigger value="runbooks" data-testid="tab-runbooks">Runbooks</TabsTrigger>
            <TabsTrigger value="pir" data-testid="tab-pir">PIR</TabsTrigger>
          </TabsList>
          <Button variant="outline" size="sm" onClick={() => exportEvidence.mutate()} disabled={exportEvidence.isPending} data-testid="button-export-evidence">
            <Download className="h-3.5 w-3.5 mr-1.5" />
            Export Package
          </Button>
        </div>

        <TabsContent value="overview" className="space-y-6 mt-4">
          <Card data-testid="card-sla-timers">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-muted-foreground" />
                  SLA Tracking
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {!incident.ackAt && incident.ackDueAt && (
                    <Button size="sm" onClick={() => acknowledgeIncident.mutate()} disabled={acknowledgeIncident.isPending} data-testid="button-acknowledge">
                      <CheckCircle className="h-3.5 w-3.5 mr-1.5" />
                      Acknowledge
                    </Button>
                  )}
                  {!incident.ackDueAt && !incident.containDueAt && !incident.resolveDueAt && (
                    <Button size="sm" variant="outline" onClick={() => applySla.mutate()} disabled={applySla.isPending} data-testid="button-apply-sla">
                      <Clock className="h-3.5 w-3.5 mr-1.5" />
                      Apply SLA Policy
                    </Button>
                  )}
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex items-center gap-3">
                  <Clock className="h-5 w-5 text-muted-foreground shrink-0" />
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Acknowledge</div>
                    <div className={`text-sm font-medium ${isSlaOverdue(incident.ackDueAt, incident.ackAt) ? "text-red-500" : incident.ackAt ? "text-green-500" : ""}`} data-testid="text-ack-timer">
                      {formatSlaTimer(incident.ackDueAt, incident.ackAt, "Acknowledged")}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Clock className="h-5 w-5 text-muted-foreground shrink-0" />
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Containment</div>
                    <div className={`text-sm font-medium ${isSlaOverdue(incident.containDueAt, incident.containedAt) ? "text-red-500" : incident.containedAt ? "text-green-500" : ""}`} data-testid="text-contain-timer">
                      {formatSlaTimer(incident.containDueAt, incident.containedAt, "Contained")}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Clock className="h-5 w-5 text-muted-foreground shrink-0" />
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Resolution</div>
                    <div className={`text-sm font-medium ${isSlaOverdue(incident.resolveDueAt, incident.resolvedAt) ? "text-red-500" : incident.resolvedAt ? "text-green-500" : ""}`} data-testid="text-resolve-timer">
                      {formatSlaTimer(incident.resolveDueAt, incident.resolvedAt, "Resolved")}
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {(incident.reasoningTrace || incident.confidence != null) && (
            <Card data-testid="card-incident-correlation-evidence">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Lightbulb className="h-4 w-4 text-yellow-500" />
                  Correlation Evidence
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {incident.confidence != null && (
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">Confidence Score:</span>
                    <span
                      className={`text-sm font-semibold ${
                        incident.confidence > 0.7
                          ? "text-green-500"
                          : incident.confidence >= 0.4
                          ? "text-yellow-500"
                          : "text-red-500"
                      }`}
                      data-testid="text-incident-confidence"
                    >
                      {Math.round(incident.confidence * 100)}%
                    </span>
                    <div className="flex-1 max-w-[200px] h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          incident.confidence > 0.7
                            ? "bg-green-500"
                            : incident.confidence >= 0.4
                            ? "bg-yellow-500"
                            : "bg-red-500"
                        }`}
                        style={{ width: `${Math.round(incident.confidence * 100)}%` }}
                      />
                    </div>
                  </div>
                )}

                {incident.reasoningTrace && (
                  <div>
                    <div className="text-xs font-medium mb-1.5">Reasoning Trace</div>
                    <div className="text-xs text-muted-foreground leading-relaxed space-y-1">
                      {String(incident.reasoningTrace).split("\n").map((line, i) => (
                        <p key={i}>{line}</p>
                      ))}
                    </div>
                  </div>
                )}

                {incident.referencedAlertIds && Array.isArray(incident.referencedAlertIds) && incident.referencedAlertIds.length > 0 && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Referenced Alerts:</span>
                    <Badge variant="secondary" className="text-xs">
                      {incident.referencedAlertIds.length} correlated alert{incident.referencedAlertIds.length !== 1 ? "s" : ""}
                    </Badge>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

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

          {rootCauseSummary && (
            <Card className="gradient-card border-amber-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Target className="h-4 w-4 text-amber-500" />
                  Root-Cause Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm leading-relaxed text-muted-foreground" data-testid="text-root-cause-summary">{rootCauseSummary.summary}</p>
                {rootCauseSummary.contributingSignals.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-muted-foreground mb-1.5">Contributing Signal Categories</div>
                    <div className="flex flex-wrap gap-1.5">
                      {rootCauseSummary.contributingSignals.map((signal) => (
                        <Badge key={signal.category} variant="secondary" className="text-[10px]">
                          {signal.category.replace(/_/g, " ")} ({signal.count})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {rootCauseSummary.impactedAssets.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-muted-foreground mb-1.5">Impacted Assets</div>
                    <div className="flex flex-wrap gap-1.5">
                      {rootCauseSummary.impactedAssets.map((asset) => (
                        <span key={asset} className="px-2 py-1 rounded-md bg-amber-500/10 text-amber-500 text-xs font-mono">{asset}</span>
                      ))}
                    </div>
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

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <ThumbsUp className="h-4 w-4 text-muted-foreground" />
                Incident Correlation Feedback
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">Was this correlation accurate?</span>
                <Button
                  size="icon"
                  variant={incidentFeedbackGiven === "up" ? "default" : "outline"}
                  onClick={() => {
                    setIncidentFeedbackGiven("up");
                    submitIncidentFeedback.mutate({ rating: 1 });
                  }}
                  disabled={submitIncidentFeedback.isPending}
                  data-testid="button-incident-feedback-up"
                >
                  <ThumbsUp className="h-4 w-4" />
                </Button>
                <Button
                  size="icon"
                  variant={incidentFeedbackGiven === "down" ? "default" : "outline"}
                  onClick={() => {
                    setIncidentFeedbackGiven("down");
                  }}
                  disabled={submitIncidentFeedback.isPending}
                  data-testid="button-incident-feedback-down"
                >
                  <ThumbsDown className="h-4 w-4" />
                </Button>
              </div>

              {incidentFeedbackGiven === "down" && (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <span className="text-xs text-muted-foreground">Correction Reason</span>
                    <Select value={correctionReason} onValueChange={setCorrectionReason}>
                      <SelectTrigger data-testid="select-incident-correction-reason">
                        <SelectValue placeholder="Select a reason..." />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="false_positive">False Positive</SelectItem>
                        <SelectItem value="wrong_severity">Wrong Severity</SelectItem>
                        <SelectItem value="wrong_grouping">Wrong Grouping</SelectItem>
                        <SelectItem value="missing_alerts">Missing Alerts</SelectItem>
                        <SelectItem value="over_correlated">Over Correlated</SelectItem>
                        <SelectItem value="other">Other</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <span className="text-xs text-muted-foreground">Additional Comments</span>
                    <Input
                      value={correctionComment}
                      onChange={(e) => setCorrectionComment(e.target.value)}
                      placeholder="Describe the issue..."
                      data-testid="input-incident-correction-comment"
                    />
                  </div>
                  <Button
                    size="sm"
                    onClick={() => {
                      submitIncidentFeedback.mutate({
                        rating: -1,
                        reason: correctionReason || undefined,
                        comment: correctionComment || undefined,
                      });
                    }}
                    disabled={submitIncidentFeedback.isPending || !correctionReason}
                    data-testid="button-incident-submit-correction"
                  >
                    {submitIncidentFeedback.isPending ? "Submitting..." : "Submit Correction"}
                  </Button>
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
        </TabsContent>

        <TabsContent value="evidence" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold" data-testid="text-evidence-header">Evidence Timeline</h2>
            </div>
            <Button size="sm" onClick={() => setShowAddEvidenceDialog(true)} data-testid="button-add-evidence">
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Add Evidence
            </Button>
          </div>

          {evidenceLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : evidenceItems && evidenceItems.length > 0 ? (
            <div className="relative space-y-0">
              {[...evidenceItems].sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).map((item: any, index: number) => (
                <div
                  key={item.id}
                  className="flex items-start gap-3 relative pb-4"
                  data-testid={`evidence-item-${item.id}`}
                >
                  <div className="flex flex-col items-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-primary flex-shrink-0 mt-1.5" />
                    {index < evidenceItems.length - 1 && (
                      <div className="w-px flex-1 bg-border mt-1" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="outline" className="text-[9px] no-default-hover-elevate no-default-active-elevate" data-testid={`evidence-type-${item.id}`}>
                        {item.type}
                      </Badge>
                      <span className="text-sm font-medium" data-testid={`evidence-title-${item.id}`}>{item.title}</span>
                    </div>
                    {item.description && (
                      <p className="text-xs text-muted-foreground mt-1" data-testid={`evidence-desc-${item.id}`}>{item.description}</p>
                    )}
                    {item.url && (
                      <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary mt-1 inline-flex items-center gap-1" data-testid={`evidence-url-${item.id}`}>
                        <Link2 className="h-3 w-3" />
                        {item.url}
                      </a>
                    )}
                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap mt-1">
                      {item.createdByName && <span>{item.createdByName}</span>}
                      <span>{formatTimestamp(item.createdAt)}</span>
                    </div>
                  </div>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => deleteEvidence.mutate(item.id)}
                    data-testid={`button-delete-evidence-${item.id}`}
                  >
                    <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <ClipboardList className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground" data-testid="text-evidence-empty">No evidence items yet</p>
                <p className="text-xs text-muted-foreground mt-1">Add notes, files, logs, or screenshots to build the evidence timeline</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="hypotheses" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <Lightbulb className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold" data-testid="text-hypotheses-header">Investigation Hypotheses</h2>
            </div>
            <Button size="sm" onClick={() => setShowAddHypothesisDialog(true)} data-testid="button-add-hypothesis">
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Add Hypothesis
            </Button>
          </div>

          {hypothesesLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : hypotheses && hypotheses.length > 0 ? (
            <div className="space-y-3">
              {hypotheses.map((hypothesis: any) => (
                <Card key={hypothesis.id} data-testid={`hypothesis-card-${hypothesis.id}`}>
                  <CardContent className="p-4 space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium" data-testid={`hypothesis-title-${hypothesis.id}`}>{hypothesis.title}</span>
                          <Badge
                            variant={hypothesis.status === "open" ? "outline" : hypothesis.status === "validated" ? "default" : hypothesis.status === "invalidated" ? "destructive" : "default"}
                            className={`text-[9px] no-default-hover-elevate no-default-active-elevate ${hypothesis.status === "validated" ? "bg-green-500/15 text-green-500 border-green-500/30" : ""}`}
                            data-testid={`hypothesis-status-${hypothesis.id}`}
                          >
                            {hypothesis.status}
                          </Badge>
                        </div>
                        {hypothesis.description && (
                          <p className="text-xs text-muted-foreground mt-1" data-testid={`hypothesis-desc-${hypothesis.id}`}>{hypothesis.description}</p>
                        )}
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteHypothesis.mutate(hypothesis.id)}
                        data-testid={`button-delete-hypothesis-${hypothesis.id}`}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                      </Button>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-muted-foreground">Confidence:</span>
                      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden max-w-[200px]">
                        <div className="h-full bg-primary rounded-full" style={{ width: `${hypothesis.confidence || 0}%` }} />
                      </div>
                      <span className="text-[10px] font-medium" data-testid={`hypothesis-confidence-${hypothesis.id}`}>{hypothesis.confidence || 0}%</span>
                    </div>

                    {hypothesis.mitreTactics && hypothesis.mitreTactics.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {hypothesis.mitreTactics.map((tactic: string, i: number) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[9px]">{tactic}</span>
                        ))}
                      </div>
                    )}

                    <div className="flex items-center gap-2 flex-wrap">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => updateHypothesis.mutate({ id: hypothesis.id, data: { status: "investigating" } })}
                        disabled={hypothesis.status === "investigating"}
                        data-testid={`button-investigating-${hypothesis.id}`}
                      >
                        <Eye className="h-3 w-3 mr-1" />
                        Investigating
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => updateHypothesis.mutate({ id: hypothesis.id, data: { status: "validated", confidence: 100 } })}
                        disabled={hypothesis.status === "validated"}
                        data-testid={`button-validate-${hypothesis.id}`}
                      >
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Validate
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => updateHypothesis.mutate({ id: hypothesis.id, data: { status: "invalidated", confidence: 0 } })}
                        disabled={hypothesis.status === "invalidated"}
                        data-testid={`button-invalidate-${hypothesis.id}`}
                      >
                        <Trash2 className="h-3 w-3 mr-1" />
                        Invalidate
                      </Button>
                    </div>

                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap">
                      {hypothesis.createdByName && <span>{hypothesis.createdByName}</span>}
                      <span>{formatTimestamp(hypothesis.createdAt)}</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <Lightbulb className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground" data-testid="text-hypotheses-empty">No hypotheses yet</p>
                <p className="text-xs text-muted-foreground mt-1">Create hypotheses to track your investigation theories</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="tasks" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold" data-testid="text-tasks-header">Investigation Tasks</h2>
              {taskStats.total > 0 && (
                <Badge variant="outline" className="text-[9px] no-default-hover-elevate no-default-active-elevate" data-testid="badge-task-progress">
                  {taskStats.done}/{taskStats.total} done
                </Badge>
              )}
            </div>
            <Button size="sm" onClick={() => setShowAddTaskDialog(true)} data-testid="button-add-task">
              <Plus className="h-3.5 w-3.5 mr-1.5" />
              Add Task
            </Button>
          </div>

          {tasksLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-20 w-full" />
            </div>
          ) : tasks && tasks.length > 0 ? (
            <div className="space-y-3">
              {tasks.map((task: any) => (
                <Card key={task.id} data-testid={`task-card-${task.id}`}>
                  <CardContent className="p-4 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium" data-testid={`task-title-${task.id}`}>{task.title}</span>
                          <PriorityBadge priority={task.priority} />
                        </div>
                        {task.description && (
                          <p className="text-xs text-muted-foreground mt-1" data-testid={`task-desc-${task.id}`}>{task.description}</p>
                        )}
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteTask.mutate(task.id)}
                        data-testid={`button-delete-task-${task.id}`}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                      </Button>
                    </div>

                    <div className="flex items-center gap-3 flex-wrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-muted-foreground">Status:</span>
                        <Select
                          value={task.status}
                          onValueChange={(value) => updateTask.mutate({ id: task.id, data: { status: value } })}
                        >
                          <SelectTrigger className="w-[130px]" data-testid={`select-task-status-${task.id}`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="open">Open</SelectItem>
                            <SelectItem value="in_progress">In Progress</SelectItem>
                            <SelectItem value="blocked">Blocked</SelectItem>
                            <SelectItem value="done">Done</SelectItem>
                            <SelectItem value="cancelled">Cancelled</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      {task.assignedToName && (
                        <div className="flex items-center gap-1">
                          <User className="h-3 w-3 text-muted-foreground" />
                          <span className="text-xs text-muted-foreground" data-testid={`task-assignee-${task.id}`}>{task.assignedToName}</span>
                        </div>
                      )}

                      {task.dueDate && (
                        <div className="flex items-center gap-1">
                          <Calendar className="h-3 w-3 text-muted-foreground" />
                          <span className="text-xs text-muted-foreground" data-testid={`task-due-${task.id}`}>{formatTimestamp(task.dueDate)}</span>
                        </div>
                      )}
                    </div>

                    <div className="text-[10px] text-muted-foreground flex items-center gap-2 flex-wrap">
                      {task.createdByName && <span>{task.createdByName}</span>}
                      <span>{formatTimestamp(task.createdAt)}</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <ListChecks className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground" data-testid="text-tasks-empty">No tasks yet</p>
                <p className="text-xs text-muted-foreground mt-1">Create tasks to assign investigation work to team members</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="runbooks" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold" data-testid="text-runbooks-header">Runbook Templates</h2>
            </div>
            <Button size="sm" variant="outline" onClick={() => seedRunbooks.mutate()} disabled={seedRunbooks.isPending} data-testid="button-seed-runbooks">
              <PlayCircle className="h-3.5 w-3.5 mr-1.5" />
              {seedRunbooks.isPending ? "Loading..." : "Load Built-in Runbooks"}
            </Button>
          </div>

          {runbookTemplates && runbookTemplates.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {runbookTemplates.map((runbook: any) => (
                <Card key={runbook.id} data-testid={`runbook-card-${runbook.id}`}>
                  <CardContent className="p-4 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium" data-testid={`runbook-title-${runbook.id}`}>{runbook.title}</span>
                          {runbook.isBuiltIn && (
                            <Badge variant="secondary" className="text-[9px] no-default-hover-elevate no-default-active-elevate" data-testid={`runbook-builtin-${runbook.id}`}>
                              Built-in
                            </Badge>
                          )}
                        </div>
                        {runbook.description && (
                          <p className="text-xs text-muted-foreground mt-1" data-testid={`runbook-desc-${runbook.id}`}>{runbook.description}</p>
                        )}
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => setExpandedRunbook(expandedRunbook === runbook.id ? null : runbook.id)}
                        data-testid={`button-expand-runbook-${runbook.id}`}
                      >
                        <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                      </Button>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      {runbook.incidentType && (
                        <Badge variant="outline" className="text-[9px] no-default-hover-elevate no-default-active-elevate" data-testid={`runbook-type-${runbook.id}`}>
                          {runbook.incidentType}
                        </Badge>
                      )}
                      {runbook.severity && (
                        <SeverityBadge severity={runbook.severity} />
                      )}
                      {runbook.estimatedDuration && (
                        <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {runbook.estimatedDuration}
                        </span>
                      )}
                    </div>

                    {expandedRunbook === runbook.id && runbook.steps && runbook.steps.length > 0 && (
                      <div className="mt-3 space-y-2 border-t pt-3">
                        <div className="text-xs font-medium">Steps</div>
                        {[...runbook.steps].sort((a: any, b: any) => (a.stepOrder || 0) - (b.stepOrder || 0)).map((step: any, i: number) => (
                          <div key={i} className="flex items-start gap-2 text-xs p-2 rounded-md bg-muted/30" data-testid={`runbook-step-${runbook.id}-${i}`}>
                            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-muted text-[10px] font-medium flex-shrink-0 mt-0.5">{step.stepOrder || i + 1}</span>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-medium">{step.title}</span>
                                {step.actionType && (
                                  <Badge variant="outline" className="text-[8px] no-default-hover-elevate no-default-active-elevate">{step.actionType}</Badge>
                                )}
                                {step.required && (
                                  <span className="text-[9px] text-red-500 font-medium">Required</span>
                                )}
                              </div>
                              {step.instructions && (
                                <p className="text-muted-foreground mt-0.5">{step.instructions}</p>
                              )}
                              {step.estimatedMinutes && (
                                <span className="text-[10px] text-muted-foreground mt-0.5 inline-flex items-center gap-1">
                                  <Clock className="h-2.5 w-2.5" />
                                  ~{step.estimatedMinutes} min
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <BookOpen className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground" data-testid="text-runbooks-empty">No runbook templates available</p>
                <p className="text-xs text-muted-foreground mt-1">Load built-in runbook templates to get started</p>
                <Button size="sm" variant="outline" className="mt-3" onClick={() => seedRunbooks.mutate()} disabled={seedRunbooks.isPending} data-testid="button-seed-runbooks-empty">
                  <PlayCircle className="h-3.5 w-3.5 mr-1.5" />
                  Load Built-in Runbooks
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="pir" className="space-y-4 mt-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold">Post-Incident Review</h2>
            </div>
          </div>

          {pirLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : !existingPir && !pirFormLoaded ? (
            <Card>
              <CardContent className="p-8 text-center">
                <ClipboardCheck className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">No post-incident review yet</p>
                <p className="text-xs text-muted-foreground mt-1">Start a review to document lessons learned and action items</p>
                <Button
                  size="sm"
                  className="mt-3"
                  onClick={() => {
                    setPirFormLoaded(true);
                    setPirStatus("draft");
                  }}
                  data-testid="button-start-pir"
                >
                  <Plus className="h-3.5 w-3.5 mr-1.5" />
                  Start Post-Incident Review
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              <Card>
                <CardContent className="p-4 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select value={pirStatus} onValueChange={setPirStatus}>
                        <SelectTrigger data-testid="select-pir-status">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="draft">Draft</SelectItem>
                          <SelectItem value="in_review">In Review</SelectItem>
                          <SelectItem value="finalized">Finalized</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Review Date</Label>
                      <Input
                        type="date"
                        value={pirDate}
                        onChange={(e) => setPirDate(e.target.value)}
                        data-testid="input-pir-date"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Summary</Label>
                    <Textarea
                      value={pirSummary}
                      onChange={(e) => setPirSummary(e.target.value)}
                      placeholder="Provide a summary of the incident and its resolution..."
                      data-testid="textarea-pir-summary"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Timeline</Label>
                    <Textarea
                      value={pirTimeline}
                      onChange={(e) => setPirTimeline(e.target.value)}
                      placeholder="Document the timeline of events..."
                      data-testid="textarea-pir-timeline"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Root Cause</Label>
                    <Textarea
                      value={pirRootCause}
                      onChange={(e) => setPirRootCause(e.target.value)}
                      placeholder="Describe the root cause of the incident..."
                      data-testid="textarea-pir-root-cause"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Lessons Learned</Label>
                    <Textarea
                      value={pirLessons}
                      onChange={(e) => setPirLessons(e.target.value)}
                      placeholder="What lessons were learned from this incident?"
                      data-testid="textarea-pir-lessons"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>What Went Well</Label>
                    <Textarea
                      value={pirWell}
                      onChange={(e) => setPirWell(e.target.value)}
                      placeholder="What aspects of the response went well?"
                      data-testid="textarea-pir-well"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>What Went Wrong</Label>
                    <Textarea
                      value={pirWrong}
                      onChange={(e) => setPirWrong(e.target.value)}
                      placeholder="What could have been handled better?"
                      data-testid="textarea-pir-wrong"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Action Items</Label>
                    {pirActionItems.length > 0 && (
                      <div className="space-y-1.5">
                        {pirActionItems.map((item, i) => (
                          <div key={i} className="flex items-center gap-2 text-sm">
                            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-muted text-[10px] font-medium shrink-0">{i + 1}</span>
                            <span className="flex-1 text-muted-foreground">{item}</span>
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => setPirActionItems(pirActionItems.filter((_, idx) => idx !== i))}
                            >
                              <Trash2 className="h-3 w-3 text-muted-foreground" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <Input
                        value={pirNewActionItem}
                        onChange={(e) => setPirNewActionItem(e.target.value)}
                        placeholder="Add an action item..."
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && pirNewActionItem.trim()) {
                            setPirActionItems([...pirActionItems, pirNewActionItem.trim()]);
                            setPirNewActionItem("");
                          }
                        }}
                        data-testid="input-pir-action-item"
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          if (pirNewActionItem.trim()) {
                            setPirActionItems([...pirActionItems, pirNewActionItem.trim()]);
                            setPirNewActionItem("");
                          }
                        }}
                        data-testid="button-add-action-item"
                      >
                        <Plus className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Attendees</Label>
                    {pirAttendees.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {pirAttendees.map((attendee, i) => (
                          <Badge key={i} variant="secondary" className="text-xs gap-1">
                            {attendee}
                            <button
                              className="ml-1 text-muted-foreground"
                              onClick={() => setPirAttendees(pirAttendees.filter((_, idx) => idx !== i))}
                            >
                              <Trash2 className="h-2.5 w-2.5" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <Input
                        value={pirNewAttendee}
                        onChange={(e) => setPirNewAttendee(e.target.value)}
                        placeholder="Add attendee name..."
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && pirNewAttendee.trim()) {
                            setPirAttendees([...pirAttendees, pirNewAttendee.trim()]);
                            setPirNewAttendee("");
                          }
                        }}
                        data-testid="input-pir-attendee"
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          if (pirNewAttendee.trim()) {
                            setPirAttendees([...pirAttendees, pirNewAttendee.trim()]);
                            setPirNewAttendee("");
                          }
                        }}
                        data-testid="button-add-attendee"
                      >
                        <Plus className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <div className="flex items-center gap-2 flex-wrap">
                <Button
                  onClick={handleSavePir}
                  disabled={createPir.isPending || updatePir.isPending}
                  data-testid="button-save-pir"
                >
                  {(createPir.isPending || updatePir.isPending) ? "Saving..." : existingPir ? "Update Review" : "Save Review"}
                </Button>
                {existingPir && (
                  <Button
                    variant="destructive"
                    onClick={() => deletePir.mutate(existingPir.id)}
                    disabled={deletePir.isPending}
                    data-testid="button-delete-pir"
                  >
                    <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                    {deletePir.isPending ? "Deleting..." : "Delete Review"}
                  </Button>
                )}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>

      <Dialog open={showAddEvidenceDialog} onOpenChange={setShowAddEvidenceDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Evidence</DialogTitle>
            <DialogDescription>Attach evidence to this incident investigation</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="evidence-title">Title</Label>
              <Input
                id="evidence-title"
                value={evidenceTitle}
                onChange={(e) => setEvidenceTitle(e.target.value)}
                placeholder="Evidence title"
                data-testid="input-evidence-title"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="evidence-type">Type</Label>
              <Select value={evidenceType} onValueChange={setEvidenceType}>
                <SelectTrigger data-testid="select-evidence-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="note">Note</SelectItem>
                  <SelectItem value="file">File</SelectItem>
                  <SelectItem value="log">Log</SelectItem>
                  <SelectItem value="screenshot">Screenshot</SelectItem>
                  <SelectItem value="artifact">Artifact</SelectItem>
                  <SelectItem value="network_capture">Network Capture</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="evidence-description">Description</Label>
              <Textarea
                id="evidence-description"
                value={evidenceDescription}
                onChange={(e) => setEvidenceDescription(e.target.value)}
                placeholder="Describe the evidence..."
                data-testid="input-evidence-description"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="evidence-url">URL (optional)</Label>
              <Input
                id="evidence-url"
                value={evidenceUrl}
                onChange={(e) => setEvidenceUrl(e.target.value)}
                placeholder="https://..."
                data-testid="input-evidence-url"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddEvidenceDialog(false)} data-testid="button-cancel-evidence">Cancel</Button>
            <Button
              onClick={() => createEvidence.mutate({ title: evidenceTitle, type: evidenceType, description: evidenceDescription, url: evidenceUrl || undefined })}
              disabled={!evidenceTitle.trim() || createEvidence.isPending}
              data-testid="button-submit-evidence"
            >
              {createEvidence.isPending ? "Adding..." : "Add Evidence"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showAddHypothesisDialog} onOpenChange={setShowAddHypothesisDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Hypothesis</DialogTitle>
            <DialogDescription>Create a new investigation hypothesis</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="hypothesis-title">Title</Label>
              <Input
                id="hypothesis-title"
                value={hypothesisTitle}
                onChange={(e) => setHypothesisTitle(e.target.value)}
                placeholder="Hypothesis title"
                data-testid="input-hypothesis-title"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="hypothesis-description">Description</Label>
              <Textarea
                id="hypothesis-description"
                value={hypothesisDescription}
                onChange={(e) => setHypothesisDescription(e.target.value)}
                placeholder="Describe your hypothesis..."
                data-testid="input-hypothesis-description"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddHypothesisDialog(false)} data-testid="button-cancel-hypothesis">Cancel</Button>
            <Button
              onClick={() => createHypothesis.mutate({ title: hypothesisTitle, description: hypothesisDescription, status: "open", confidence: 0 })}
              disabled={!hypothesisTitle.trim() || createHypothesis.isPending}
              data-testid="button-submit-hypothesis"
            >
              {createHypothesis.isPending ? "Creating..." : "Create Hypothesis"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showAddTaskDialog} onOpenChange={setShowAddTaskDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Task</DialogTitle>
            <DialogDescription>Create a new investigation task</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="task-title">Title</Label>
              <Input
                id="task-title"
                value={taskTitle}
                onChange={(e) => setTaskTitle(e.target.value)}
                placeholder="Task title"
                data-testid="input-task-title"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="task-description">Description</Label>
              <Textarea
                id="task-description"
                value={taskDescription}
                onChange={(e) => setTaskDescription(e.target.value)}
                placeholder="Describe the task..."
                data-testid="input-task-description"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="task-assignee">Assignee</Label>
              <Input
                id="task-assignee"
                value={taskAssignee}
                onChange={(e) => setTaskAssignee(e.target.value)}
                placeholder="Assigned to"
                data-testid="input-task-assignee"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="task-priority">Priority</Label>
              <Select value={taskPriority} onValueChange={setTaskPriority}>
                <SelectTrigger data-testid="select-task-priority">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">P1 - Critical</SelectItem>
                  <SelectItem value="2">P2 - High</SelectItem>
                  <SelectItem value="3">P3 - Medium</SelectItem>
                  <SelectItem value="4">P4 - Low</SelectItem>
                  <SelectItem value="5">P5 - Informational</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddTaskDialog(false)} data-testid="button-cancel-task">Cancel</Button>
            <Button
              onClick={() => createTask.mutate({ title: taskTitle, description: taskDescription, assignedTo: taskAssignee || undefined, assignedToName: taskAssignee || undefined, priority: parseInt(taskPriority, 10) })}
              disabled={!taskTitle.trim() || createTask.isPending}
              data-testid="button-submit-task"
            >
              {createTask.isPending ? "Creating..." : "Create Task"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
