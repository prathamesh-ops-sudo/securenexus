import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Clock,
  Plus,
  Search,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Target,
  MessageSquare,
  Lightbulb,
  FileText,
  ArrowUpRight,
  Send,
  Eye,
  Loader2,
  GitBranch,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function InvestigationTimelinePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newTimeline, setNewTimeline] = useState({ investigationId: "", title: "" });
  const [newEvent, setNewEvent] = useState({ title: "", type: "action", severity: "info", description: "" });

  const { data: timelines, isLoading } = useQuery({
    queryKey: ["/api/investigation-timelines"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/investigation-timelines");
      return r.json();
    },
  });

  const { data: detail } = useQuery({
    queryKey: ["/api/investigation-timelines", selectedId],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/investigation-timelines/${selectedId}`);
      return r.json();
    },
    enabled: !!selectedId,
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof newTimeline) => {
      const r = await apiRequest("POST", "/api/investigation-timelines", data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Timeline Created" });
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines"] });
      setShowCreate(false);
      setNewTimeline({ investigationId: "", title: "" });
    },
    onError: () => toast({ title: "Failed to create timeline", variant: "destructive" }),
  });

  const addEventMutation = useMutation({
    mutationFn: async (data: typeof newEvent) => {
      const r = await apiRequest("POST", `/api/investigation-timelines/${selectedId}/events`, data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Event Added" });
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines", selectedId] });
      setNewEvent({ title: "", type: "action", severity: "info", description: "" });
    },
    onError: () => toast({ title: "Failed to add event", variant: "destructive" }),
  });

  const updateStatusMutation = useMutation({
    mutationFn: async (status: string) => {
      const r = await apiRequest("PATCH", `/api/investigation-timelines/${selectedId}`, { status });
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines"] });
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines", selectedId] });
    },
  });

  const timelineList = Array.isArray(timelines) ? timelines : (timelines as any)?.data || [];
  const timelineDetail = detail as any;

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <GitBranch className="h-6 w-6 text-blue-400" />
            Investigation Timeline
          </h1>
          <p className="text-sm text-muted-foreground mt-1">Chronological event tracking for security investigations</p>
        </div>
        <Button onClick={() => setShowCreate(true)} className="bg-blue-600 hover:bg-blue-700">
          <Plus className="h-4 w-4 mr-2" />
          New Timeline
        </Button>
      </div>

      {showCreate && (
        <Card className="border-blue-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg">Create Investigation Timeline</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Investigation ID (e.g., INV-2024-001)"
              value={newTimeline.investigationId}
              onChange={(e) => setNewTimeline({ ...newTimeline, investigationId: e.target.value })}
            />
            <Input
              placeholder="Investigation title"
              value={newTimeline.title}
              onChange={(e) => setNewTimeline({ ...newTimeline, title: e.target.value })}
            />
            <div className="flex gap-2">
              <Button
                onClick={() => createMutation.mutate(newTimeline)}
                disabled={!newTimeline.investigationId || !newTimeline.title || createMutation.isPending}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {createMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Create Timeline
              </Button>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Investigations</h2>
          {timelineList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-8 text-center">
                <Clock className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No investigation timelines yet</p>
              </CardContent>
            </Card>
          )}
          {timelineList.map((tl: any) => (
            <Card
              key={tl.investigationId}
              onClick={() => setSelectedId(tl.investigationId)}
              className={`cursor-pointer transition-all hover:border-blue-500/30 ${selectedId === tl.investigationId ? "border-blue-400 bg-blue-500/5" : "border-border bg-card/50"}`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{tl.title}</span>
                  <InvStatusBadge status={tl.status} />
                </div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span>{tl.investigationId}</span>
                  <span>{tl.eventCount || 0} events</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Lead: {tl.leadAnalyst} | Started: {new Date(tl.startTime).toLocaleDateString()}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="lg:col-span-2">
          {!selectedId && (
            <Card className="border-dashed border-border bg-card/30 h-full">
              <CardContent className="py-20 text-center">
                <GitBranch className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">Select an investigation to view its timeline</p>
              </CardContent>
            </Card>
          )}

          {selectedId && timelineDetail && (
            <div className="space-y-4">
              <Card className="border-blue-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{timelineDetail.title}</CardTitle>
                    <div className="flex gap-2">
                      {timelineDetail.status === "open" && (
                        <Button size="sm" onClick={() => updateStatusMutation.mutate("in_progress")}>
                          Start Investigation
                        </Button>
                      )}
                      {timelineDetail.status !== "closed" && (
                        <Button size="sm" variant="outline" onClick={() => updateStatusMutation.mutate("closed")}>
                          Close
                        </Button>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>ID: {timelineDetail.investigationId}</span>
                    <span>Lead: {timelineDetail.leadAnalyst}</span>
                    <InvStatusBadge status={timelineDetail.status} />
                  </div>
                </CardHeader>
              </Card>

              <Card className="border-blue-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Event Timeline</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="relative">
                    <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />
                    <div className="space-y-4">
                      {(timelineDetail.events || []).map((event: any) => (
                        <div key={event.id} className="relative pl-10">
                          <div className="absolute left-2 w-5 h-5 rounded-full border-2 border-background bg-card flex items-center justify-center">
                            <EventIcon type={event.type} />
                          </div>
                          <div className="p-3 rounded-lg bg-background/50 border border-border">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-medium">{event.title}</span>
                              <Badge variant="outline" className="text-xs">
                                {event.type}
                              </Badge>
                              <SeverityDot severity={event.severity} />
                            </div>
                            {event.description && <p className="text-xs text-muted-foreground">{event.description}</p>}
                            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                              <span>{event.actor}</span>
                              <span>{new Date(event.timestamp).toLocaleString()}</span>
                              <span>{event.source}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {timelineDetail.status !== "closed" && (
                    <div className="mt-4 pt-4 border-t border-border space-y-3">
                      <h3 className="text-sm font-semibold">Add Event</h3>
                      <Input
                        placeholder="Event title"
                        value={newEvent.title}
                        onChange={(e) => setNewEvent({ ...newEvent, title: e.target.value })}
                      />
                      <Input
                        placeholder="Description (optional)"
                        value={newEvent.description}
                        onChange={(e) => setNewEvent({ ...newEvent, description: e.target.value })}
                      />
                      <div className="flex gap-2">
                        <select
                          value={newEvent.type}
                          onChange={(e) => setNewEvent({ ...newEvent, type: e.target.value })}
                          className="px-3 py-2 text-sm bg-background border border-border rounded"
                        >
                          <option value="action">Action</option>
                          <option value="alert">Alert</option>
                          <option value="evidence">Evidence</option>
                          <option value="hypothesis">Hypothesis</option>
                          <option value="decision">Decision</option>
                          <option value="escalation">Escalation</option>
                          <option value="communication">Communication</option>
                          <option value="artifact">Artifact</option>
                        </select>
                        <select
                          value={newEvent.severity}
                          onChange={(e) => setNewEvent({ ...newEvent, severity: e.target.value })}
                          className="px-3 py-2 text-sm bg-background border border-border rounded"
                        >
                          <option value="info">Info</option>
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                          <option value="critical">Critical</option>
                        </select>
                        <Button
                          onClick={() => addEventMutation.mutate(newEvent)}
                          disabled={!newEvent.title || addEventMutation.isPending}
                          className="bg-blue-600 hover:bg-blue-700"
                        >
                          {addEventMutation.isPending ? (
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          ) : (
                            <Plus className="h-4 w-4 mr-2" />
                          )}
                          Add
                        </Button>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function InvStatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    open: "bg-blue-500/20 text-blue-400",
    in_progress: "bg-yellow-500/20 text-yellow-400",
    closed: "bg-gray-500/20 text-gray-400",
  };
  return <Badge className={`text-xs ${styles[status] || styles.open}`}>{status?.replace("_", " ")}</Badge>;
}

function EventIcon({ type }: { type: string }) {
  const size = "h-3 w-3";
  switch (type) {
    case "alert":
      return <AlertTriangle className={`${size} text-red-400`} />;
    case "action":
      return <CheckCircle2 className={`${size} text-green-400`} />;
    case "evidence":
      return <FileText className={`${size} text-blue-400`} />;
    case "hypothesis":
      return <Lightbulb className={`${size} text-yellow-400`} />;
    case "decision":
      return <Shield className={`${size} text-purple-400`} />;
    case "escalation":
      return <ArrowUpRight className={`${size} text-orange-400`} />;
    case "communication":
      return <MessageSquare className={`${size} text-cyan-400`} />;
    default:
      return <Target className={`${size} text-muted-foreground`} />;
  }
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-400",
    high: "bg-orange-400",
    medium: "bg-yellow-400",
    low: "bg-green-400",
    info: "bg-blue-400",
  };
  return <span className={`w-2 h-2 rounded-full ${colors[severity] || colors.info}`} />;
}
