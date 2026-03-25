import { useState, useRef, useCallback, useMemo } from "react";
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
  ZoomIn,
  ZoomOut,
  Layers,
  Download,
  Tag,
  Trash2,
  Minus,
  ChevronDown,
  ChevronRight,
  Play,
  Bookmark,
  ArrowRight,
  RefreshCw,
  Copy,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { EmptyState } from "@/components/empty-state";

// ─── Types ──────────────────────────────────────────────────────────────────

interface TimelineEvent {
  id: string;
  investigationId: string;
  timestamp: string;
  type: string;
  title: string;
  description: string;
  actor: string;
  severity: string;
  source: string;
  linkedEntities: string[];
  metadata: Record<string, unknown>;
}

interface Annotation {
  id: string;
  text: string;
  markerType: string;
  timestamp: string;
  color: string;
  author: string;
  createdAt: string;
}

interface TimelineSummary {
  investigationId: string;
  title: string;
  status: string;
  eventCount: number;
  startTime: string;
  endTime: string | null;
  leadAnalyst: string;
}

interface TimelineDetail {
  investigationId: string;
  title: string;
  status: string;
  events: TimelineEvent[];
  annotations?: Annotation[];
  startTime: string;
  endTime: string | null;
  leadAnalyst: string;
  summary: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

const EVENT_TYPE_COLORS: Record<string, string> = {
  alert: "bg-red-500",
  action: "bg-emerald-500",
  evidence: "bg-blue-500",
  hypothesis: "bg-yellow-500",
  decision: "bg-purple-500",
  escalation: "bg-orange-500",
  communication: "bg-cyan-500",
  artifact: "bg-pink-500",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-500/30",
  high: "text-orange-400 border-orange-500/30",
  medium: "text-yellow-400 border-yellow-500/30",
  low: "text-emerald-400 border-emerald-500/30",
  info: "text-blue-400 border-blue-500/30",
};

function formatTS(ts: string | null): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatFullTS(ts: string | null): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function durationBetween(a: string, b: string): string {
  const ms = Math.abs(new Date(b).getTime() - new Date(a).getTime());
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  if (ms < 86400000) return `${(ms / 3600000).toFixed(1)}h`;
  return `${(ms / 86400000).toFixed(1)}d`;
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

function InvStatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    open: "bg-blue-500/20 text-blue-400",
    in_progress: "bg-yellow-500/20 text-yellow-400",
    closed: "bg-gray-500/20 text-gray-400",
  };
  return <Badge className={`text-xs ${styles[status] || styles.open}`}>{status?.replace("_", " ")}</Badge>;
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

// ─── 17.1 Visual Timeline with Zoom and Pan ─────────────────────────────────

function VisualTimelineView({
  events,
  annotations,
  onEventClick,
  onAnnotationClick,
}: {
  events: TimelineEvent[];
  annotations: Annotation[];
  onEventClick: (e: TimelineEvent) => void;
  onAnnotationClick: (a: Annotation) => void;
}) {
  const [zoomLevel, setZoomLevel] = useState(2); // 0=minutes, 1=hours, 2=days
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const containerRef = useRef<HTMLDivElement>(null);
  const zoomLabels = ["Minutes", "Hours", "Days"];

  const filteredEvents = useMemo(() => {
    if (typeFilter === "all") return events;
    return events.filter((e) => e.type === typeFilter);
  }, [events, typeFilter]);

  // Group events by actor (swimlanes)
  const swimlanes = useMemo(() => {
    const lanes = new Map<string, TimelineEvent[]>();
    for (const e of filteredEvents) {
      const actor = e.actor || "system";
      if (!lanes.has(actor)) lanes.set(actor, []);
      lanes.get(actor)!.push(e);
    }
    return lanes;
  }, [filteredEvents]);

  // Cluster events that are very close together
  const timeRange = useMemo(() => {
    if (filteredEvents.length === 0) return { start: Date.now(), end: Date.now(), duration: 0 };
    const times = filteredEvents.map((e) => new Date(e.timestamp).getTime());
    const start = Math.min(...times);
    const end = Math.max(...times);
    return { start, end, duration: end - start || 1 };
  }, [filteredEvents]);

  const getPosition = useCallback(
    (ts: string) => {
      const t = new Date(ts).getTime();
      return ((t - timeRange.start) / timeRange.duration) * 100;
    },
    [timeRange],
  );

  const eventTypes = useMemo(() => {
    const types = new Set(events.map((e) => e.type));
    return ["all", ...Array.from(types)];
  }, [events]);

  if (events.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="py-12 text-center">
          <Clock className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">No events on this timeline yet</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs"
            onClick={() => setZoomLevel(Math.max(0, zoomLevel - 1))}
            disabled={zoomLevel === 0}
          >
            <ZoomIn className="h-3 w-3 mr-1" /> Zoom In
          </Button>
          <span className="text-xs text-muted-foreground">{zoomLabels[zoomLevel]}</span>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs"
            onClick={() => setZoomLevel(Math.min(2, zoomLevel + 1))}
            disabled={zoomLevel === 2}
          >
            <ZoomOut className="h-3 w-3 mr-1" /> Zoom Out
          </Button>
        </div>
        <div className="flex items-center gap-2">
          <Label className="text-xs">Filter:</Label>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="h-7 w-32 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {eventTypes.map((t) => (
                <SelectItem key={t} value={t} className="text-xs">
                  {t === "all" ? "All Types" : t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Horizontal time axis */}
      <Card className="overflow-hidden">
        <CardContent className="p-4">
          <div className="relative" ref={containerRef}>
            {/* Time axis */}
            <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-2 px-1">
              <span>{formatFullTS(new Date(timeRange.start).toISOString())}</span>
              <span>{formatFullTS(new Date((timeRange.start + timeRange.end) / 2).toISOString())}</span>
              <span>{formatFullTS(new Date(timeRange.end).toISOString())}</span>
            </div>
            <div className="h-px bg-border mb-3" />

            {/* Annotations layer */}
            {annotations.length > 0 && (
              <div className="relative h-6 mb-2">
                {annotations.map((a) => {
                  const pos = getPosition(a.timestamp);
                  if (pos < 0 || pos > 100) return null;
                  return (
                    <TooltipProvider key={a.id}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            className="absolute top-0 -translate-x-1/2 cursor-pointer"
                            style={{ left: `${Math.max(1, Math.min(99, pos))}%` }}
                            onClick={() => onAnnotationClick(a)}
                          >
                            <div
                              className="w-0 h-0 border-l-[5px] border-r-[5px] border-t-[8px] border-l-transparent border-r-transparent"
                              style={{ borderTopColor: a.color }}
                            />
                            <div
                              className="text-[8px] font-medium whitespace-nowrap mt-0.5 max-w-[80px] truncate"
                              style={{ color: a.color }}
                            >
                              {a.text}
                            </div>
                          </button>
                        </TooltipTrigger>
                        <TooltipContent className="text-xs">
                          <p className="font-medium">{a.text}</p>
                          <p className="text-muted-foreground">
                            {a.author} · {formatTS(a.timestamp)}
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  );
                })}
              </div>
            )}

            {/* Swimlanes */}
            {Array.from(swimlanes.entries()).map(([actor, laneEvents]) => (
              <div key={actor} className="mb-3">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-[10px] font-medium text-muted-foreground w-20 truncate">{actor}</span>
                  <div className="flex-1 h-px bg-border/50" />
                </div>
                <div className="relative h-8 ml-20">
                  <div className="absolute inset-y-0 left-0 right-0 bg-muted/20 rounded" />
                  {laneEvents.map((evt) => {
                    const pos = getPosition(evt.timestamp);
                    return (
                      <TooltipProvider key={evt.id}>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button
                              className="absolute top-1 -translate-x-1/2 w-5 h-5 rounded-full border-2 border-background flex items-center justify-center cursor-pointer hover:scale-125 transition-transform"
                              style={{ left: `${Math.max(2, Math.min(98, pos))}%` }}
                              onClick={() => onEventClick(evt)}
                            >
                              <div className={`w-3 h-3 rounded-full ${EVENT_TYPE_COLORS[evt.type] || "bg-gray-500"}`} />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent className="text-xs max-w-xs">
                            <p className="font-medium">{evt.title}</p>
                            <p className="text-muted-foreground">
                              {evt.type} · {evt.severity} · {formatTS(evt.timestamp)}
                            </p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    );
                  })}
                </div>
              </div>
            ))}

            {/* Legend */}
            <div className="flex items-center gap-3 flex-wrap mt-3 pt-3 border-t border-border">
              {Object.entries(EVENT_TYPE_COLORS).map(([type, color]) => (
                <div key={type} className="flex items-center gap-1">
                  <div className={`w-2.5 h-2.5 rounded-full ${color}`} />
                  <span className="text-[10px] text-muted-foreground">{type}</span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── 17.2 Event Detail Expansion ────────────────────────────────────────────

function EventDetailDialog({
  event,
  open,
  onClose,
}: {
  event: TimelineEvent | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!event) return null;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm">
            <EventIcon type={event.type} />
            {event.title}
          </DialogTitle>
          <DialogDescription className="text-xs">Full event details</DialogDescription>
        </DialogHeader>
        <ScrollArea className="max-h-[60vh]">
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <p className="text-muted-foreground mb-0.5">Event Type</p>
                <Badge variant="outline" className="text-xs">
                  {event.type}
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground mb-0.5">Severity</p>
                <Badge variant="outline" className={`text-xs ${SEVERITY_COLORS[event.severity] || ""}`}>
                  <SeverityDot severity={event.severity} />
                  <span className="ml-1">{event.severity}</span>
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground mb-0.5">Actor</p>
                <p>{event.actor}</p>
              </div>
              <div>
                <p className="text-muted-foreground mb-0.5">Source</p>
                <p>{event.source}</p>
              </div>
              <div className="col-span-2">
                <p className="text-muted-foreground mb-0.5">Timestamp</p>
                <p>{formatFullTS(event.timestamp)}</p>
              </div>
            </div>
            <Separator />
            <div className="text-xs">
              <p className="text-muted-foreground mb-1">Description</p>
              <p>{event.description || "No description provided."}</p>
            </div>
            {event.linkedEntities && event.linkedEntities.length > 0 && (
              <>
                <Separator />
                <div className="text-xs">
                  <p className="text-muted-foreground mb-1">Linked Entities</p>
                  <div className="flex flex-wrap gap-1">
                    {event.linkedEntities.map((e, i) => (
                      <Badge key={i} variant="secondary" className="text-[10px]">
                        {e}
                      </Badge>
                    ))}
                  </div>
                </div>
              </>
            )}
            {event.metadata && Object.keys(event.metadata).length > 0 && (
              <>
                <Separator />
                <div className="text-xs">
                  <p className="text-muted-foreground mb-1">Raw Data / Metadata</p>
                  <pre className="text-[10px] font-mono bg-muted/30 rounded-md p-3 overflow-x-auto whitespace-pre-wrap break-all">
                    {JSON.stringify(event.metadata, null, 2)}
                  </pre>
                </div>
              </>
            )}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

// ─── 17.3 Timeline Annotations ──────────────────────────────────────────────

function AnnotationsPanel({ investigationId, annotations }: { investigationId: string; annotations: Annotation[] }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [text, setText] = useState("");
  const [markerType, setMarkerType] = useState("note");
  const [color, setColor] = useState("#3b82f6");

  const addMutation = useMutation({
    mutationFn: async (data: { text: string; markerType: string; color: string }) => {
      const r = await apiRequest("POST", `/api/investigation-timelines/${investigationId}/annotations`, data);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Annotation added" });
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines", investigationId] });
      setText("");
      setShowAdd(false);
    },
    onError: () => toast({ title: "Failed to add annotation", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (annotationId: string) => {
      const r = await apiRequest(
        "DELETE",
        `/api/investigation-timelines/${investigationId}/annotations/${annotationId}`,
      );
      return r.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines", investigationId] });
    },
  });

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Bookmark className="h-4 w-4 text-blue-400" />
            Annotations ({annotations.length})
          </CardTitle>
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setShowAdd(!showAdd)}>
            <Plus className="h-3 w-3 mr-1" /> Add
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {showAdd && (
          <div className="space-y-2 p-3 bg-muted/30 rounded-lg">
            <Input
              placeholder="Annotation text..."
              value={text}
              onChange={(e) => setText(e.target.value)}
              className="h-8 text-xs"
            />
            <div className="flex items-center gap-2">
              <Select value={markerType} onValueChange={setMarkerType}>
                <SelectTrigger className="h-7 w-36 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {["milestone", "note", "warning", "start", "end", "containment"].map((t) => (
                    <SelectItem key={t} value={t} className="text-xs">
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <input
                type="color"
                value={color}
                onChange={(e) => setColor(e.target.value)}
                className="w-7 h-7 rounded border cursor-pointer"
              />
              <Button
                size="sm"
                className="h-7 text-xs ml-auto"
                onClick={() => addMutation.mutate({ text, markerType, color })}
                disabled={!text || addMutation.isPending}
              >
                {addMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Save"}
              </Button>
            </div>
          </div>
        )}
        {annotations.length === 0 ? (
          <p className="text-xs text-muted-foreground py-2">No annotations. Add markers to highlight key moments.</p>
        ) : (
          <div className="space-y-1.5">
            {annotations.map((a) => (
              <div key={a.id} className="flex items-center gap-2 p-2 bg-muted/20 rounded text-xs">
                <div className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: a.color }} />
                <div className="flex-1 min-w-0">
                  <span className="font-medium">{a.text}</span>
                  <span className="text-muted-foreground ml-2">
                    {a.author} · {formatTS(a.timestamp)}
                  </span>
                </div>
                <Badge variant="outline" className="text-[10px] shrink-0">
                  {a.markerType}
                </Badge>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-5 w-5 p-0 text-muted-foreground hover:text-destructive"
                  onClick={() => deleteMutation.mutate(a.id)}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── 17.4 Multi-Incident Timeline Overlay ───────────────────────────────────

function OverlayPanel({ timelines }: { timelines: TimelineSummary[] }) {
  const { toast } = useToast();
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [overlayData, setOverlayData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const toggleId = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const fetchOverlay = async () => {
    if (selectedIds.length < 2) {
      toast({ title: "Select at least 2 timelines", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      const r = await apiRequest("POST", "/api/investigation-timelines/overlay", { investigationIds: selectedIds });
      const data = await r.json();
      setOverlayData(data);
    } catch {
      toast({ title: "Failed to build overlay", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const overlayColors = ["#3b82f6", "#ef4444", "#22c55e", "#f59e0b", "#8b5cf6", "#ec4899"];

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Layers className="h-4 w-4 text-purple-400" />
          Multi-Incident Overlay
        </CardTitle>
        <CardDescription className="text-xs">Compare timelines side-by-side to identify patterns</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1">
          {timelines.map((tl) => (
            <label
              key={tl.investigationId}
              className="flex items-center gap-2 p-2 bg-muted/20 rounded cursor-pointer hover:bg-muted/30 text-xs"
            >
              <input
                type="checkbox"
                checked={selectedIds.includes(tl.investigationId)}
                onChange={() => toggleId(tl.investigationId)}
                className="rounded"
              />
              <span className="font-medium">{tl.title}</span>
              <span className="text-muted-foreground">({tl.eventCount} events)</span>
              <InvStatusBadge status={tl.status} />
            </label>
          ))}
        </div>

        <Button
          size="sm"
          className="w-full h-7 text-xs"
          onClick={fetchOverlay}
          disabled={selectedIds.length < 2 || loading}
        >
          {loading ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Layers className="h-3 w-3 mr-1" />}
          Compare {selectedIds.length} Timelines
        </Button>

        {overlayData && (
          <div className="space-y-3 pt-2">
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>{overlayData.totalEvents} total events</span>
              {overlayData.timeRange?.start && (
                <span>
                  Range: {formatTS(overlayData.timeRange.start)} → {formatTS(overlayData.timeRange.end)}
                </span>
              )}
            </div>

            {overlayData.timelines?.map((tl: any, idx: number) => (
              <div key={tl.investigationId} className="space-y-1">
                <div className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: overlayColors[idx % overlayColors.length] }}
                  />
                  <span className="text-xs font-medium">{tl.title}</span>
                  <span className="text-[10px] text-muted-foreground">({tl.events.length} events)</span>
                </div>
                <div className="ml-5 space-y-0.5">
                  {tl.events.slice(0, 5).map((e: any) => (
                    <div key={e.id} className="flex items-center gap-2 text-[10px] text-muted-foreground">
                      <SeverityDot severity={e.severity} />
                      <span>{formatTS(e.timestamp)}</span>
                      <span className="truncate">{e.title}</span>
                    </div>
                  ))}
                  {tl.events.length > 5 && (
                    <p className="text-[10px] text-muted-foreground">+{tl.events.length - 5} more events</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── 17.5 Auto-Populate Panel ───────────────────────────────────────────────

function AutoPopulatePanel({ investigationId, status }: { investigationId: string; status: string }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const autoPopulateMutation = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", `/api/investigation-timelines/${investigationId}/auto-populate`);
      return r.json();
    },
    onSuccess: (data: any) => {
      toast({ title: `${data.eventsAdded} events auto-imported from data sources` });
      queryClient.invalidateQueries({ queryKey: ["/api/investigation-timelines", investigationId] });
    },
    onError: () => toast({ title: "Failed to auto-populate", variant: "destructive" }),
  });

  return (
    <Button
      size="sm"
      variant="outline"
      className="h-7 text-xs"
      onClick={() => autoPopulateMutation.mutate()}
      disabled={autoPopulateMutation.isPending || status === "closed"}
    >
      {autoPopulateMutation.isPending ? (
        <Loader2 className="h-3 w-3 animate-spin mr-1" />
      ) : (
        <RefreshCw className="h-3 w-3 mr-1" />
      )}
      Auto-Populate
    </Button>
  );
}

// ─── 17.6 Timeline Export ───────────────────────────────────────────────────

function ExportPanel({ investigationId }: { investigationId: string }) {
  const { toast } = useToast();
  const [exporting, setExporting] = useState(false);

  const doExport = async (format: string) => {
    setExporting(true);
    try {
      const r = await apiRequest("GET", `/api/investigation-timelines/${investigationId}/export?format=${format}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const ext = format === "stix" ? "stix.json" : format;
      a.href = url;
      a.download = `timeline-${investigationId}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: `Exported as ${format.toUpperCase()}` });
    } catch {
      toast({ title: "Export failed", variant: "destructive" });
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="flex items-center gap-1">
      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => doExport("json")} disabled={exporting}>
        <Download className="h-3 w-3 mr-1" /> JSON
      </Button>
      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => doExport("csv")} disabled={exporting}>
        <Download className="h-3 w-3 mr-1" /> CSV
      </Button>
      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => doExport("stix")} disabled={exporting}>
        <Download className="h-3 w-3 mr-1" /> STIX
      </Button>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function InvestigationTimelinePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newTimeline, setNewTimeline] = useState({ investigationId: "", title: "" });
  const [newEvent, setNewEvent] = useState({ title: "", type: "action", severity: "info", description: "" });
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const [viewMode, setViewMode] = useState<"visual" | "list">("visual");

  const { data: timelines, isLoading } = useQuery<TimelineSummary[]>({
    queryKey: ["/api/investigation-timelines"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/investigation-timelines");
      const data = await r.json();
      return Array.isArray(data) ? data : (data as any)?.data || [];
    },
  });

  const { data: detail } = useQuery<TimelineDetail>({
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

  const timelineList = Array.isArray(timelines) ? timelines : [];
  const timelineDetail = detail as TimelineDetail | undefined;
  const events = timelineDetail?.events || [];
  const annotations = (timelineDetail as any)?.annotations || [];

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
          <p className="text-sm text-muted-foreground mt-1">
            Chronological event tracking with visual timeline, annotations, and multi-incident overlay
          </p>
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

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left sidebar: timeline list + overlay */}
        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Investigations</h2>
          {timelineList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-8 text-center">
                <Clock className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No investigation timelines yet</p>
              </CardContent>
            </Card>
          )}
          {timelineList.map((tl) => (
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

          {/* 17.4 Multi-Incident Overlay */}
          {timelineList.length >= 2 && <OverlayPanel timelines={timelineList} />}
        </div>

        {/* Main content area */}
        <div className="lg:col-span-3">
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
              {/* Header card with actions */}
              <Card className="border-blue-500/20 bg-card/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <CardTitle className="text-lg">{timelineDetail.title}</CardTitle>
                    <div className="flex items-center gap-2 flex-wrap">
                      {/* 17.5 Auto-populate */}
                      <AutoPopulatePanel investigationId={selectedId} status={timelineDetail.status} />
                      {/* View mode toggle */}
                      <div className="flex items-center gap-1 border rounded px-1">
                        <Button
                          size="sm"
                          variant={viewMode === "visual" ? "secondary" : "ghost"}
                          className="h-6 text-[10px] px-2"
                          onClick={() => setViewMode("visual")}
                        >
                          Visual
                        </Button>
                        <Button
                          size="sm"
                          variant={viewMode === "list" ? "secondary" : "ghost"}
                          className="h-6 text-[10px] px-2"
                          onClick={() => setViewMode("list")}
                        >
                          List
                        </Button>
                      </div>
                      {timelineDetail.status === "open" && (
                        <Button size="sm" onClick={() => updateStatusMutation.mutate("in_progress")}>
                          Start
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
                    <span>{events.length} events</span>
                    {events.length >= 2 && (
                      <span>Duration: {durationBetween(events[0].timestamp, events[events.length - 1].timestamp)}</span>
                    )}
                  </div>
                  {/* 17.6 Export buttons */}
                  <div className="mt-2">
                    <ExportPanel investigationId={selectedId} />
                  </div>
                </CardHeader>
              </Card>

              {/* 17.1 Visual Timeline */}
              {viewMode === "visual" ? (
                <VisualTimelineView
                  events={events}
                  annotations={annotations}
                  onEventClick={(e) => setSelectedEvent(e)}
                  onAnnotationClick={() => {}}
                />
              ) : (
                /* List view (original) */
                <Card className="border-blue-500/20 bg-card/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Event Timeline</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="relative">
                      <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />
                      <div className="space-y-4">
                        {events.map((event) => (
                          <div
                            key={event.id}
                            className="relative pl-10 cursor-pointer"
                            onClick={() => setSelectedEvent(event)}
                          >
                            <div className="absolute left-2 w-5 h-5 rounded-full border-2 border-background bg-card flex items-center justify-center">
                              <EventIcon type={event.type} />
                            </div>
                            <div className="p-3 rounded-lg bg-background/50 border border-border hover:border-blue-500/30 transition-colors">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-sm font-medium">{event.title}</span>
                                <Badge variant="outline" className="text-xs">
                                  {event.type}
                                </Badge>
                                <SeverityDot severity={event.severity} />
                              </div>
                              {event.description && (
                                <p className="text-xs text-muted-foreground">{event.description}</p>
                              )}
                              <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                                <span>{event.actor}</span>
                                <span>{formatFullTS(event.timestamp)}</span>
                                <span>{event.source}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* 17.3 Annotations */}
              <AnnotationsPanel investigationId={selectedId} annotations={annotations} />

              {/* Add Event form */}
              {timelineDetail.status !== "closed" && (
                <Card className="border-blue-500/20 bg-card/50">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Add Event</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
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
                      <Select value={newEvent.type} onValueChange={(v) => setNewEvent({ ...newEvent, type: v })}>
                        <SelectTrigger className="h-9 w-40 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {[
                            "action",
                            "alert",
                            "evidence",
                            "hypothesis",
                            "decision",
                            "escalation",
                            "communication",
                            "artifact",
                          ].map((t) => (
                            <SelectItem key={t} value={t} className="text-xs">
                              {t}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Select
                        value={newEvent.severity}
                        onValueChange={(v) => setNewEvent({ ...newEvent, severity: v })}
                      >
                        <SelectTrigger className="h-9 w-32 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {["info", "low", "medium", "high", "critical"].map((s) => (
                            <SelectItem key={s} value={s} className="text-xs">
                              {s}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
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
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 17.2 Event Detail Dialog */}
      <EventDetailDialog event={selectedEvent} open={!!selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
}
