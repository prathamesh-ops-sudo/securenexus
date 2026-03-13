import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Radio,
  Users,
  MessageSquare,
  Plus,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Target,
  Send,
  UserPlus,
  XCircle,
  Loader2,
  ChevronRight,
  Siren,
  ArrowRightLeft,
  FileText,
  Play,
  Lightbulb,
  Search,
  Gavel,
  Video,
  LogOut,
  Hash,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

type DetailTab = "timeline" | "canvas" | "handoff" | "replay" | "postmortem";

export default function WarRoomPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedRoom, setSelectedRoom] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newRoom, setNewRoom] = useState({ name: "", incidentId: "", severity: "high" });
  const [message, setMessage] = useState("");
  const [activeTab, setActiveTab] = useState<DetailTab>("timeline");
  const [messageType, setMessageType] = useState("message");

  // ── Handoff form state ──
  const [showHandoff, setShowHandoff] = useState(false);
  const [handoffForm, setHandoffForm] = useState({
    toUserId: "",
    toUserName: "",
    summary: "",
    keyFindings: "",
    nextSteps: "",
  });

  // ── Action item form state ──
  const [showNewAction, setShowNewAction] = useState(false);
  const [actionForm, setActionForm] = useState({ title: "", assignee: "", priority: "medium" });

  const { data: rooms, isLoading } = useQuery({
    queryKey: ["/api/war-rooms"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/war-rooms");
      return r.json();
    },
  });

  const { data: roomDetail } = useQuery({
    queryKey: ["/api/war-rooms", selectedRoom],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/war-rooms/${selectedRoom}`);
      return r.json();
    },
    enabled: !!selectedRoom,
    refetchInterval: selectedRoom ? 10000 : false, // Auto-refresh every 10s for live updates
  });

  const { data: replayData } = useQuery({
    queryKey: ["/api/war-rooms", selectedRoom, "replay"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/war-rooms/${selectedRoom}/replay`);
      return r.json();
    },
    enabled: !!selectedRoom && activeTab === "replay",
  });

  const { data: handoffsData } = useQuery({
    queryKey: ["/api/war-rooms", selectedRoom, "handoffs"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/war-rooms/${selectedRoom}/handoffs`);
      return r.json();
    },
    enabled: !!selectedRoom && activeTab === "handoff",
  });

  const { data: hypothesesData } = useQuery({
    queryKey: ["/api/war-rooms", selectedRoom, "canvas", "hypotheses"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/war-rooms/${selectedRoom}/canvas/hypotheses`);
      return r.json();
    },
    enabled: !!selectedRoom && activeTab === "canvas",
  });

  const { data: evidenceData } = useQuery({
    queryKey: ["/api/war-rooms", selectedRoom, "canvas", "evidence"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/war-rooms/${selectedRoom}/canvas/evidence`);
      return r.json();
    },
    enabled: !!selectedRoom && activeTab === "canvas",
  });

  const { data: decisionsData } = useQuery({
    queryKey: ["/api/war-rooms", selectedRoom, "canvas", "decisions"],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/war-rooms/${selectedRoom}/canvas/decisions`);
      return r.json();
    },
    enabled: !!selectedRoom && activeTab === "canvas",
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof newRoom) => {
      const r = await apiRequest("POST", "/api/war-rooms", data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "War Room Created" });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms"] });
      setShowCreate(false);
      setNewRoom({ name: "", incidentId: "", severity: "high" });
    },
    onError: () => toast({ title: "Failed to create war room", variant: "destructive" }),
  });

  const postTimelineMutation = useMutation({
    mutationFn: async ({ content, type }: { content: string; type: string }) => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/timeline`, { type, content });
      return r.json();
    },
    onSuccess: () => {
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
      if (activeTab === "canvas") {
        queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom, "canvas"] });
      }
    },
  });

  const joinMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/join`);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Joined War Room" });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
    },
  });

  const leaveMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/leave`);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Left War Room" });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
    },
  });

  const closeMutation = useMutation({
    mutationFn: async (resolution: string) => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/close`, { resolution });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "War Room Closed" });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms"] });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
    },
  });

  const handoffMutation = useMutation({
    mutationFn: async (data: typeof handoffForm) => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/handoff`, {
        toUserId: data.toUserId,
        toUserName: data.toUserName,
        summary: data.summary,
        keyFindings: data.keyFindings ? data.keyFindings.split("\n").filter((s) => s.trim()) : [],
        nextSteps: data.nextSteps ? data.nextSteps.split("\n").filter((s) => s.trim()) : [],
      });
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Command Handoff Completed" });
      setShowHandoff(false);
      setHandoffForm({ toUserId: "", toUserName: "", summary: "", keyFindings: "", nextSteps: "" });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom, "handoffs"] });
    },
    onError: () => toast({ title: "Handoff failed", variant: "destructive" }),
  });

  const postMortemMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/post-mortem`);
      return r.json();
    },
    onError: () => toast({ title: "Failed to generate post-mortem", variant: "destructive" }),
  });

  const createActionMutation = useMutation({
    mutationFn: async (data: typeof actionForm) => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/actions`, data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Action Item Created" });
      setShowNewAction(false);
      setActionForm({ title: "", assignee: "", priority: "medium" });
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
    },
    onError: () => toast({ title: "Failed to create action", variant: "destructive" }),
  });

  const updateActionMutation = useMutation({
    mutationFn: async ({ actionId, status }: { actionId: string; status: string }) => {
      const r = await apiRequest("PATCH", `/api/war-rooms/${selectedRoom}/actions/${actionId}`, { status });
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
    },
  });

  const roomList = Array.isArray(rooms) ? rooms : ((rooms as Record<string, unknown>)?.data as unknown[]) || [];
  const detail = roomDetail as Record<string, unknown> | null;
  const detailData = detail?.data ? (detail.data as Record<string, unknown>) : detail;

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      </div>
    );
  }

  const tabs: { id: DetailTab; label: string; icon: React.ReactNode }[] = [
    { id: "timeline", label: "Timeline", icon: <MessageSquare className="h-4 w-4" /> },
    { id: "canvas", label: "Investigation Canvas", icon: <Search className="h-4 w-4" /> },
    { id: "handoff", label: "Handoff", icon: <ArrowRightLeft className="h-4 w-4" /> },
    { id: "replay", label: "Replay", icon: <Play className="h-4 w-4" /> },
    { id: "postmortem", label: "Post-Mortem", icon: <FileText className="h-4 w-4" /> },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Radio className="h-6 w-6 text-red-400" />
            Incident War Room
          </h1>
          <p className="text-sm text-muted-foreground mt-1">Persistent collaborative incident response coordination</p>
        </div>
        <Button onClick={() => setShowCreate(true)} className="bg-red-600 hover:bg-red-700">
          <Plus className="h-4 w-4 mr-2" />
          Open War Room
        </Button>
      </div>

      {showCreate && (
        <Card className="border-red-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-lg">Open New War Room</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="War room name (e.g., Ransomware Response Team)"
              value={newRoom.name}
              onChange={(e) => setNewRoom({ ...newRoom, name: e.target.value })}
            />
            <Input
              placeholder="Incident ID"
              value={newRoom.incidentId}
              onChange={(e) => setNewRoom({ ...newRoom, incidentId: e.target.value })}
            />
            <select
              value={newRoom.severity}
              onChange={(e) => setNewRoom({ ...newRoom, severity: e.target.value })}
              className="w-full px-3 py-2 text-sm bg-background border border-border rounded"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <div className="flex gap-2">
              <Button
                onClick={() => createMutation.mutate(newRoom)}
                disabled={!newRoom.name || !newRoom.incidentId || createMutation.isPending}
                className="bg-red-600 hover:bg-red-700"
              >
                {createMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Open War Room
              </Button>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── War Room List (left column) ── */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">War Rooms</h2>
          {roomList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-8 text-center">
                <Siren className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No active war rooms</p>
              </CardContent>
            </Card>
          )}
          {roomList.map((room: Record<string, unknown>) => (
            <Card
              key={room.id as string}
              onClick={() => {
                setSelectedRoom(room.id as string);
                setActiveTab("timeline");
              }}
              className={`cursor-pointer transition-all hover:border-red-500/30 ${selectedRoom === room.id ? "border-red-400 bg-red-500/5" : "border-border bg-card/50"}`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{room.name as string}</span>
                  <SeverityBadge severity={room.severity as string} />
                </div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Target className="h-3 w-3" />
                    {room.incidentId as string}
                  </span>
                  <span className="flex items-center gap-1">
                    <Users className="h-3 w-3" />
                    {(room.participantCount as number) || ((room.participants as unknown[]) || []).length}
                  </span>
                  <StatusBadge status={room.status as string} />
                </div>
                {room.slackChannelName ? (
                  <div className="flex items-center gap-1 text-xs text-muted-foreground mt-1">
                    <Hash className="h-3 w-3" />
                    {String(room.slackChannelName)}
                  </div>
                ) : null}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* ── Detail Panel (right 2 columns) ── */}
        <div className="lg:col-span-2">
          {!selectedRoom && (
            <Card className="border-dashed border-border bg-card/30 h-full">
              <CardContent className="py-20 text-center">
                <Radio className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">Select a war room to view timeline and actions</p>
              </CardContent>
            </Card>
          )}

          {selectedRoom && detailData && (
            <div className="space-y-4">
              {/* Header Card */}
              <Card className="border-red-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{detailData.name as string}</CardTitle>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => joinMutation.mutate()}>
                        <UserPlus className="h-4 w-4 mr-1" />
                        Join
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => leaveMutation.mutate()}>
                        <LogOut className="h-4 w-4 mr-1" />
                        Leave
                      </Button>
                      {(detailData.status as string) !== "closed" && (
                        <>
                          <Button size="sm" variant="outline" onClick={() => setShowHandoff(true)}>
                            <ArrowRightLeft className="h-4 w-4 mr-1" />
                            Handoff
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => closeMutation.mutate("Resolved")}>
                            <XCircle className="h-4 w-4 mr-1" />
                            Close
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>Commander: {(detailData.commanderName as string) || (detailData.commander as string)}</span>
                    <span>{((detailData.participants as unknown[]) || []).length} participants</span>
                    <SeverityBadge severity={detailData.severity as string} />
                    <StatusBadge status={detailData.status as string} />
                    {detailData.slackChannelName ? (
                      <span className="flex items-center gap-1">
                        <Hash className="h-3 w-3" />
                        {String(detailData.slackChannelName)}
                      </span>
                    ) : null}
                  </div>
                </CardHeader>
              </Card>

              {/* Handoff modal */}
              {showHandoff && (
                <Card className="border-orange-500/20 bg-card/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <ArrowRightLeft className="h-4 w-4" />
                      Command Handoff
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <Input
                        placeholder="Incoming commander user ID"
                        value={handoffForm.toUserId}
                        onChange={(e) => setHandoffForm({ ...handoffForm, toUserId: e.target.value })}
                      />
                      <Input
                        placeholder="Incoming commander name"
                        value={handoffForm.toUserName}
                        onChange={(e) => setHandoffForm({ ...handoffForm, toUserName: e.target.value })}
                      />
                    </div>
                    <textarea
                      placeholder="Handoff summary — current situation, what's been done, what's outstanding..."
                      value={handoffForm.summary}
                      onChange={(e) => setHandoffForm({ ...handoffForm, summary: e.target.value })}
                      className="w-full px-3 py-2 text-sm bg-background border border-border rounded min-h-[80px]"
                    />
                    <textarea
                      placeholder="Key findings (one per line)"
                      value={handoffForm.keyFindings}
                      onChange={(e) => setHandoffForm({ ...handoffForm, keyFindings: e.target.value })}
                      className="w-full px-3 py-2 text-sm bg-background border border-border rounded min-h-[60px]"
                    />
                    <textarea
                      placeholder="Next steps (one per line)"
                      value={handoffForm.nextSteps}
                      onChange={(e) => setHandoffForm({ ...handoffForm, nextSteps: e.target.value })}
                      className="w-full px-3 py-2 text-sm bg-background border border-border rounded min-h-[60px]"
                    />
                    <div className="flex gap-2">
                      <Button
                        onClick={() => handoffMutation.mutate(handoffForm)}
                        disabled={
                          !handoffForm.toUserId ||
                          !handoffForm.toUserName ||
                          !handoffForm.summary ||
                          handoffMutation.isPending
                        }
                      >
                        {handoffMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                        Complete Handoff
                      </Button>
                      <Button variant="outline" onClick={() => setShowHandoff(false)}>
                        Cancel
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Tab navigation */}
              <div className="flex gap-1 border-b border-border pb-0">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-t transition-colors ${
                      activeTab === tab.id
                        ? "bg-card text-foreground border border-b-0 border-border"
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {tab.icon}
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* ── Timeline Tab ── */}
              {activeTab === "timeline" && (
                <>
                  <Card className="border-cyan-500/20 bg-card/50">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Timeline</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {(((detailData.timeline as unknown[]) || []) as Record<string, unknown>[]).map((entry) => (
                          <div key={entry.id as string} className="flex gap-3 p-2 rounded bg-background/50">
                            <TimelineIcon type={entry.type as string} />
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium">{entry.actor as string}</span>
                                <Badge variant="outline" className="text-xs">
                                  {entry.type as string}
                                </Badge>
                                <span className="text-xs text-muted-foreground">
                                  {new Date((entry.createdAt || entry.timestamp) as string).toLocaleTimeString()}
                                </span>
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">{entry.content as string}</p>
                            </div>
                          </div>
                        ))}
                      </div>

                      {(detailData.status as string) !== "closed" && (
                        <div className="mt-3 pt-3 border-t border-border space-y-2">
                          <div className="flex gap-2">
                            <select
                              value={messageType}
                              onChange={(e) => setMessageType(e.target.value)}
                              className="px-2 py-1 text-xs bg-background border border-border rounded"
                            >
                              <option value="message">Message</option>
                              <option value="evidence">Evidence</option>
                              <option value="hypothesis">Hypothesis</option>
                              <option value="decision">Decision</option>
                              <option value="action">Action</option>
                            </select>
                            <Input
                              placeholder="Post update to timeline..."
                              value={message}
                              onChange={(e) => setMessage(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" && message.trim())
                                  postTimelineMutation.mutate({
                                    content: message,
                                    type: messageType,
                                  });
                              }}
                              className="flex-1"
                            />
                            <Button
                              onClick={() => {
                                if (message.trim())
                                  postTimelineMutation.mutate({
                                    content: message,
                                    type: messageType,
                                  });
                              }}
                              disabled={!message.trim() || postTimelineMutation.isPending}
                              size="sm"
                            >
                              <Send className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Action Items */}
                  <Card className="border-cyan-500/20 bg-card/50">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm">Action Items</CardTitle>
                        {(detailData.status as string) !== "closed" && (
                          <Button size="sm" variant="outline" onClick={() => setShowNewAction(!showNewAction)}>
                            <Plus className="h-3 w-3 mr-1" />
                            Add
                          </Button>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent>
                      {showNewAction && (
                        <div className="space-y-2 mb-4 p-3 rounded border border-border bg-background/50">
                          <Input
                            placeholder="Action item title"
                            value={actionForm.title}
                            onChange={(e) => setActionForm({ ...actionForm, title: e.target.value })}
                          />
                          <div className="flex gap-2">
                            <Input
                              placeholder="Assignee"
                              value={actionForm.assignee}
                              onChange={(e) => setActionForm({ ...actionForm, assignee: e.target.value })}
                              className="flex-1"
                            />
                            <select
                              value={actionForm.priority}
                              onChange={(e) => setActionForm({ ...actionForm, priority: e.target.value })}
                              className="px-2 py-1 text-xs bg-background border border-border rounded"
                            >
                              <option value="critical">Critical</option>
                              <option value="high">High</option>
                              <option value="medium">Medium</option>
                              <option value="low">Low</option>
                            </select>
                            <Button
                              size="sm"
                              onClick={() => createActionMutation.mutate(actionForm)}
                              disabled={!actionForm.title || createActionMutation.isPending}
                            >
                              Create
                            </Button>
                          </div>
                        </div>
                      )}

                      <div className="space-y-2">
                        {((detailData.actions as unknown[]) || []).length === 0 && (
                          <p className="text-xs text-muted-foreground text-center py-4">No action items yet</p>
                        )}
                        {(((detailData.actions as unknown[]) || []) as Record<string, unknown>[]).map((action) => (
                          <div
                            key={action.id as string}
                            className="flex items-center justify-between p-2 rounded bg-background/50"
                          >
                            <div className="flex items-center gap-2">
                              <CheckCircle2
                                className={`h-4 w-4 ${(action.status as string) === "completed" ? "text-green-400" : "text-muted-foreground"}`}
                              />
                              <span className="text-sm">{action.title as string}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-muted-foreground">{action.assignee as string}</span>
                              <SeverityBadge severity={action.priority as string} />
                              {(detailData.status as string) !== "closed" ? (
                                <select
                                  value={action.status as string}
                                  onChange={(e) =>
                                    updateActionMutation.mutate({
                                      actionId: action.id as string,
                                      status: e.target.value,
                                    })
                                  }
                                  className="px-1 py-0.5 text-xs bg-background border border-border rounded"
                                >
                                  <option value="pending">Pending</option>
                                  <option value="in_progress">In Progress</option>
                                  <option value="completed">Completed</option>
                                  <option value="blocked">Blocked</option>
                                </select>
                              ) : (
                                <Badge variant="outline" className="text-xs">
                                  {action.status as string}
                                </Badge>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  {/* Participants */}
                  <Card className="border-cyan-500/20 bg-card/50">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Users className="h-4 w-4" />
                        Participants
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {(((detailData.participants as unknown[]) || []) as Record<string, unknown>[]).map((p) => (
                          <Badge
                            key={p.userId as string}
                            variant="outline"
                            className={`text-xs ${(p.role as string) === "commander" ? "border-red-500/30 text-red-400" : ""}`}
                          >
                            {p.displayName as string} ({p.role as string})
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </>
              )}

              {/* ── Investigation Canvas Tab ── */}
              {activeTab === "canvas" && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <CanvasColumn
                    title="Hypotheses"
                    icon={<Lightbulb className="h-4 w-4 text-yellow-400" />}
                    items={hypothesesData}
                    color="yellow"
                  />
                  <CanvasColumn
                    title="Evidence"
                    icon={<Target className="h-4 w-4 text-green-400" />}
                    items={evidenceData}
                    color="green"
                  />
                  <CanvasColumn
                    title="Decisions"
                    icon={<Gavel className="h-4 w-4 text-orange-400" />}
                    items={decisionsData}
                    color="orange"
                  />
                </div>
              )}

              {/* ── Handoff Tab ── */}
              {activeTab === "handoff" && (
                <Card className="border-orange-500/20 bg-card/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <ArrowRightLeft className="h-4 w-4" />
                      Command Handoff History
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <HandoffList data={handoffsData} />
                  </CardContent>
                </Card>
              )}

              {/* ── Replay Tab ── */}
              {activeTab === "replay" && <ReplayView data={replayData} />}

              {/* ── Post-Mortem Tab ── */}
              {activeTab === "postmortem" && <PostMortemView detail={detailData} mutation={postMortemMutation} />}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function CanvasColumn({
  title,
  icon,
  items,
  color,
}: {
  title: string;
  icon: React.ReactNode;
  items: unknown;
  color: string;
}) {
  const list = Array.isArray(items) ? items : ((items as Record<string, unknown>)?.data as unknown[]) || [];

  return (
    <Card className={`border-${color}-500/20 bg-card/50`}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          {icon}
          {title} ({list.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2 max-h-80 overflow-y-auto">
          {list.length === 0 && (
            <p className="text-xs text-muted-foreground text-center py-4">
              No {title.toLowerCase()} posted yet. Use the timeline to add them.
            </p>
          )}
          {list.map((item: Record<string, unknown>) => (
            <div key={item.id as string} className="p-2 rounded bg-background/50 border border-border">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium">{item.actor as string}</span>
                <span className="text-xs text-muted-foreground">
                  {new Date((item.createdAt || item.timestamp) as string).toLocaleString()}
                </span>
              </div>
              <p className="text-sm">{item.content as string}</p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function HandoffList({ data }: { data: unknown }) {
  const list = Array.isArray(data) ? data : ((data as Record<string, unknown>)?.data as unknown[]) || [];

  if (list.length === 0) {
    return (
      <p className="text-xs text-muted-foreground text-center py-8">
        No command handoffs recorded yet. Use the Handoff button in the header to initiate one.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {list.map((h: Record<string, unknown>) => (
        <div key={h.id as string} className="p-3 rounded border border-border bg-background/50">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">
                {h.fromUserName as string} &rarr; {h.toUserName as string}
              </span>
              <Badge
                variant="outline"
                className={`text-xs ${(h.status as string) === "acknowledged" ? "border-green-500/30 text-green-400" : "border-yellow-500/30 text-yellow-400"}`}
              >
                {h.status as string}
              </Badge>
            </div>
            <span className="text-xs text-muted-foreground">{new Date(h.createdAt as string).toLocaleString()}</span>
          </div>
          <p className="text-sm text-muted-foreground">{h.summary as string}</p>
          {Array.isArray(h.keyFindings) && (h.keyFindings as string[]).length > 0 && (
            <div className="mt-2">
              <span className="text-xs font-medium">Key Findings:</span>
              <ul className="text-xs text-muted-foreground ml-4 list-disc">
                {(h.keyFindings as string[]).map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>
          )}
          {Array.isArray(h.nextSteps) && (h.nextSteps as string[]).length > 0 && (
            <div className="mt-2">
              <span className="text-xs font-medium">Next Steps:</span>
              <ul className="text-xs text-muted-foreground ml-4 list-disc">
                {(h.nextSteps as string[]).map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ReplayView({ data }: { data: unknown }) {
  const replay = (data as Record<string, unknown>)?.data
    ? ((data as Record<string, unknown>).data as Record<string, unknown>)
    : (data as Record<string, unknown>);

  if (!replay || !replay.events) {
    return (
      <Card className="border-cyan-500/20 bg-card/50">
        <CardContent className="py-12 text-center">
          <Play className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">Loading replay data...</p>
        </CardContent>
      </Card>
    );
  }

  const events = replay.events as Record<string, unknown>[];
  const stats = replay.stats as Record<string, number>;
  const warRoom = replay.warRoom as Record<string, unknown>;

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Events", value: stats?.totalEvents || 0 },
          { label: "Messages", value: stats?.messageCount || 0 },
          { label: "Actions", value: stats?.actionCount || 0 },
          { label: "Handoffs", value: stats?.handoffCount || 0 },
          {
            label: "Duration",
            value: warRoom?.durationMinutes ? `${warRoom.durationMinutes}m` : "Ongoing",
          },
        ].map((s) => (
          <Card key={s.label} className="border-border bg-card/50">
            <CardContent className="p-3 text-center">
              <p className="text-lg font-bold">{s.value}</p>
              <p className="text-xs text-muted-foreground">{s.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Event timeline */}
      <Card className="border-cyan-500/20 bg-card/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Play className="h-4 w-4" />
            Incident Timeline Replay ({events.length} events)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-[500px] overflow-y-auto">
            {events.map((event, i) => (
              <div key={i} className="flex gap-3 p-2 rounded bg-background/50">
                <div className="flex flex-col items-center">
                  <TimelineIcon type={event.type as string} />
                  {i < events.length - 1 && <div className="w-px h-full bg-border mt-1" />}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{event.actor as string}</span>
                    <Badge variant="outline" className="text-xs">
                      {event.category as string}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {new Date(event.timestamp as string).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground mt-0.5">{event.content as string}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function PostMortemView({ detail, mutation }: { detail: Record<string, unknown>; mutation: any }) {
  const [pir, setPir] = useState<Record<string, unknown> | null>(null);

  const handleGenerate = async () => {
    try {
      const result = await mutation.mutateAsync();
      const pirData = (result as Record<string, unknown>)?.data || result;
      setPir(pirData as Record<string, unknown>);
    } catch {
      // error handled by mutation
    }
  };

  if ((detail.status as string) !== "closed") {
    return (
      <Card className="border-border bg-card/50">
        <CardContent className="py-12 text-center">
          <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">
            Post-mortem reports can only be generated after the war room is closed.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (!pir) {
    return (
      <Card className="border-border bg-card/50">
        <CardContent className="py-12 text-center">
          <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground mb-4">
            Generate a Post-Incident Review (PIR) document from war room data.
          </p>
          <Button onClick={handleGenerate} disabled={mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Generate Post-Mortem
          </Button>
        </CardContent>
      </Card>
    );
  }

  const summary = pir.incidentSummary as Record<string, unknown>;
  const timelineInfo = pir.timeline as Record<string, unknown>;
  const actionItems = pir.actionItems as Record<string, unknown>;

  return (
    <div className="space-y-4">
      <Card className="border-green-500/20 bg-card/50">
        <CardHeader>
          <CardTitle className="text-lg">{pir.title as string}</CardTitle>
          <p className="text-xs text-muted-foreground">
            Generated: {new Date(pir.generatedAt as string).toLocaleString()}
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Incident Summary */}
          <div>
            <h3 className="text-sm font-semibold mb-2">Incident Summary</h3>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-muted-foreground">Severity:</span>{" "}
                <SeverityBadge severity={summary?.severity as string} />
              </div>
              <div>
                <span className="text-muted-foreground">Commander:</span> {summary?.commander as string}
              </div>
              <div>
                <span className="text-muted-foreground">Duration:</span>{" "}
                {summary?.durationMinutes ? `${summary.durationMinutes} minutes` : "N/A"}
              </div>
              <div>
                <span className="text-muted-foreground">Resolution:</span> {summary?.resolution as string}
              </div>
            </div>
          </div>

          {/* Timeline Stats */}
          <div>
            <h3 className="text-sm font-semibold mb-2">Timeline</h3>
            <p className="text-sm text-muted-foreground">
              {timelineInfo?.totalEntries as number} entries from{" "}
              {timelineInfo?.firstEntry ? new Date(timelineInfo.firstEntry as string).toLocaleString() : "N/A"} to{" "}
              {timelineInfo?.lastEntry ? new Date(timelineInfo.lastEntry as string).toLocaleString() : "N/A"}
            </p>
          </div>

          {/* Decisions */}
          {Array.isArray(pir.decisions) && (pir.decisions as unknown[]).length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2">Key Decisions ({(pir.decisions as unknown[]).length})</h3>
              <div className="space-y-1">
                {(pir.decisions as Record<string, unknown>[]).map((d, i) => (
                  <div key={i} className="text-sm p-2 bg-background/50 rounded">
                    <span className="text-muted-foreground text-xs">
                      {new Date(d.timestamp as string).toLocaleString()} — {d.actor as string}
                    </span>
                    <p>{d.content as string}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action Items Summary */}
          <div>
            <h3 className="text-sm font-semibold mb-2">Action Items</h3>
            <div className="flex gap-4 text-sm">
              <span>
                Total: <strong>{actionItems?.total as number}</strong>
              </span>
              <span className="text-green-400">Completed: {actionItems?.completed as number}</span>
              <span className="text-yellow-400">Pending: {actionItems?.pending as number}</span>
              <span className="text-red-400">Blocked: {actionItems?.blocked as number}</span>
            </div>
          </div>

          {/* Participants */}
          {Array.isArray(pir.participants) && (
            <div>
              <h3 className="text-sm font-semibold mb-2">Participants</h3>
              <div className="flex flex-wrap gap-2">
                {(pir.participants as Record<string, unknown>[]).map((p, i) => (
                  <Badge key={i} variant="outline" className="text-xs">
                    {p.displayName as string} ({p.role as string})
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Handoffs */}
          {Array.isArray(pir.handoffs) && (pir.handoffs as unknown[]).length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2">Command Handoffs</h3>
              {(pir.handoffs as Record<string, unknown>[]).map((h, i) => (
                <div key={i} className="text-sm p-2 bg-background/50 rounded mb-1">
                  {h.from as string} &rarr; {h.to as string}: {h.summary as string}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return <Badge className={`text-xs ${colors[severity] || colors.medium}`}>{severity}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  if (status === "active")
    return <Badge className="text-xs bg-green-500/20 text-green-400 border-green-500/30">Active</Badge>;
  if (status === "closed")
    return <Badge className="text-xs bg-gray-500/20 text-gray-400 border-gray-500/30">Closed</Badge>;
  return <Badge className="text-xs bg-yellow-500/20 text-yellow-400 border-yellow-500/30">{status}</Badge>;
}

function TimelineIcon({ type }: { type: string }) {
  switch (type) {
    case "message":
      return <MessageSquare className="h-4 w-4 text-cyan-400 mt-1" />;
    case "action":
    case "action_created":
    case "action_completed":
      return <ChevronRight className="h-4 w-4 text-blue-400 mt-1" />;
    case "status_change":
      return <Shield className="h-4 w-4 text-yellow-400 mt-1" />;
    case "evidence":
      return <Target className="h-4 w-4 text-green-400 mt-1" />;
    case "decision":
      return <AlertTriangle className="h-4 w-4 text-orange-400 mt-1" />;
    case "hypothesis":
      return <Lightbulb className="h-4 w-4 text-yellow-400 mt-1" />;
    case "handoff":
      return <ArrowRightLeft className="h-4 w-4 text-purple-400 mt-1" />;
    default:
      return <Clock className="h-4 w-4 text-muted-foreground mt-1" />;
  }
}
