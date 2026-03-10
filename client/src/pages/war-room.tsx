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
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function WarRoomPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedRoom, setSelectedRoom] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newRoom, setNewRoom] = useState({ name: "", incidentId: "", severity: "high" });
  const [message, setMessage] = useState("");

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
    mutationFn: async (content: string) => {
      const r = await apiRequest("POST", `/api/war-rooms/${selectedRoom}/timeline`, { type: "message", content });
      return r.json();
    },
    onSuccess: () => {
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["/api/war-rooms", selectedRoom] });
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

  const roomList = Array.isArray(rooms) ? rooms : (rooms as any)?.data || [];
  const detail = roomDetail as any;

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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Radio className="h-6 w-6 text-red-400" />
            Incident War Room
          </h1>
          <p className="text-sm text-muted-foreground mt-1">Real-time collaborative incident response coordination</p>
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
          {roomList.map((room: any) => (
            <Card
              key={room.id}
              onClick={() => setSelectedRoom(room.id)}
              className={`cursor-pointer transition-all hover:border-red-500/30 ${selectedRoom === room.id ? "border-red-400 bg-red-500/5" : "border-border bg-card/50"}`}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{room.name}</span>
                  <SeverityBadge severity={room.severity} />
                </div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Target className="h-3 w-3" />
                    {room.incidentId}
                  </span>
                  <span className="flex items-center gap-1">
                    <Users className="h-3 w-3" />
                    {room.participants?.length || 0}
                  </span>
                  <StatusBadge status={room.status} />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="lg:col-span-2">
          {!selectedRoom && (
            <Card className="border-dashed border-border bg-card/30 h-full">
              <CardContent className="py-20 text-center">
                <Radio className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">Select a war room to view timeline and actions</p>
              </CardContent>
            </Card>
          )}

          {selectedRoom && detail && (
            <div className="space-y-4">
              <Card className="border-red-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{detail.name}</CardTitle>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => joinMutation.mutate()}>
                        <UserPlus className="h-4 w-4 mr-1" />
                        Join
                      </Button>
                      {detail.status !== "closed" && (
                        <Button size="sm" variant="destructive" onClick={() => closeMutation.mutate("Resolved")}>
                          <XCircle className="h-4 w-4 mr-1" />
                          Close
                        </Button>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>Commander: {detail.commander}</span>
                    <span>{detail.participants?.length || 0} participants</span>
                    <SeverityBadge severity={detail.severity} />
                  </div>
                </CardHeader>
              </Card>

              <Card className="border-cyan-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Timeline</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {(detail.timeline || []).map((entry: any) => (
                      <div key={entry.id} className="flex gap-3 p-2 rounded bg-background/50">
                        <TimelineIcon type={entry.type} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{entry.actor}</span>
                            <Badge variant="outline" className="text-xs">
                              {entry.type}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {new Date(entry.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">{entry.content}</p>
                        </div>
                      </div>
                    ))}
                  </div>

                  {detail.status !== "closed" && (
                    <div className="flex gap-2 mt-3 pt-3 border-t border-border">
                      <Input
                        placeholder="Post update to timeline..."
                        value={message}
                        onChange={(e) => setMessage(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && message.trim()) postTimelineMutation.mutate(message);
                        }}
                      />
                      <Button
                        onClick={() => {
                          if (message.trim()) postTimelineMutation.mutate(message);
                        }}
                        disabled={!message.trim() || postTimelineMutation.isPending}
                        size="sm"
                      >
                        <Send className="h-4 w-4" />
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>

              {detail.actions?.length > 0 && (
                <Card className="border-cyan-500/20 bg-card/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Action Items</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {detail.actions.map((action: any) => (
                        <div key={action.id} className="flex items-center justify-between p-2 rounded bg-background/50">
                          <div className="flex items-center gap-2">
                            <CheckCircle2
                              className={`h-4 w-4 ${action.status === "completed" ? "text-green-400" : "text-muted-foreground"}`}
                            />
                            <span className="text-sm">{action.title}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">{action.assignee}</span>
                            <Badge variant="outline" className="text-xs">
                              {action.status}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </div>
      </div>
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
      return <ChevronRight className="h-4 w-4 text-blue-400 mt-1" />;
    case "status_change":
      return <Shield className="h-4 w-4 text-yellow-400 mt-1" />;
    case "evidence":
      return <Target className="h-4 w-4 text-green-400 mt-1" />;
    case "decision":
      return <AlertTriangle className="h-4 w-4 text-orange-400 mt-1" />;
    default:
      return <Clock className="h-4 w-4 text-muted-foreground mt-1" />;
  }
}
