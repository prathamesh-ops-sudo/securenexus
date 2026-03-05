import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Send,
  RefreshCw,
  Play,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Clock,
  XCircle,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
  Filter,
  Search,
  Eye,
  X,
  Activity,
  Hash,
  Layers,
  ArrowUpDown,
  Info,
  CheckSquare,
  Square,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";

interface OutboxEvent {
  id: string;
  orgId: string | null;
  eventType: string;
  aggregateType: string;
  aggregateId: string;
  payload: Record<string, unknown>;
  status: string;
  fingerprint: string;
  dispatchedAt: string | null;
  attempts: number;
  maxAttempts: number;
  lastError: string | null;
  nextRetryAt: string | null;
  createdAt: string;
}

interface ProcessorStatus {
  running: boolean;
  processedCount: number;
  failedCount: number;
  pollIntervalMs: number;
}

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof CheckCircle2; bgClass: string }> = {
  pending: {
    label: "Pending",
    color: "text-yellow-500",
    icon: Clock,
    bgClass: "bg-yellow-500/10 border-yellow-500/20",
  },
  dispatched: {
    label: "Dispatched",
    color: "text-emerald-500",
    icon: CheckCircle2,
    bgClass: "bg-emerald-500/10 border-emerald-500/20",
  },
  failed: {
    label: "Failed",
    color: "text-red-500",
    icon: XCircle,
    bgClass: "bg-red-500/10 border-red-500/20",
  },
  replayed: {
    label: "Replayed",
    color: "text-blue-500",
    icon: RotateCcw,
    bgClass: "bg-blue-500/10 border-blue-500/20",
  },
};

const EVENT_TYPE_LABELS: Record<string, string> = {
  "alert.created": "Alert Created",
  "alert.updated": "Alert Updated",
  "alert.correlated": "Alert Correlated",
  "alert.closed": "Alert Closed",
  "incident.created": "Incident Created",
  "incident.updated": "Incident Updated",
  "incident.closed": "Incident Closed",
  "incident.escalated": "Incident Escalated",
  "connector.synced": "Connector Synced",
  "connector.failed": "Connector Failed",
  "response_action.executed": "Response Executed",
  "response_action.failed": "Response Failed",
  "scan.completed": "Scan Completed",
  "policy.violation": "Policy Violation",
  "enrichment.completed": "Enrichment Done",
  "report.generated": "Report Generated",
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "\u2014";
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "\u2014";
  }
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "\u2014";
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const secs = Math.floor(diff / 1000);
    if (secs < 60) return `${secs}s ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return "\u2014";
  }
}

function StatusBadge({ status }: { status: string }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const Icon = config.icon;
  return (
    <Badge variant="outline" className={`text-[10px] gap-1 ${config.bgClass} ${config.color} border`}>
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  );
}

function EventTypeBadge({ eventType }: { eventType: string }) {
  const isAlert = eventType.startsWith("alert.");
  const isIncident = eventType.startsWith("incident.");
  const isConnector = eventType.startsWith("connector.");
  const isResponse = eventType.startsWith("response_action.");

  let colorClass = "bg-muted/50 text-muted-foreground";
  if (isAlert) colorClass = "bg-orange-500/10 text-orange-400 border-orange-500/20";
  else if (isIncident) colorClass = "bg-red-500/10 text-red-400 border-red-500/20";
  else if (isConnector) colorClass = "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
  else if (isResponse) colorClass = "bg-violet-500/10 text-violet-400 border-violet-500/20";

  return (
    <Badge variant="outline" className={`text-[10px] font-mono ${colorClass}`}>
      {eventType}
    </Badge>
  );
}

function ProcessorStatusCard({ status }: { status: ProcessorStatus }) {
  return (
    <Card>
      <CardContent className="pt-4 pb-3 px-4">
        <div className="flex items-center gap-2 mb-2">
          <Activity className="h-4 w-4 text-cyan-400" />
          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            Processor Status
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            {status.running && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            )}
            <span
              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${status.running ? "bg-emerald-500" : "bg-red-500"}`}
            />
          </span>
          <span className="text-sm font-semibold">{status.running ? "Running" : "Stopped"}</span>
        </div>
        <p className="text-[10px] text-muted-foreground mt-1">Poll interval: {status.pollIntervalMs / 1000}s</p>
      </CardContent>
    </Card>
  );
}

function StatsCards({ total, processorStatus }: { total: number; processorStatus: ProcessorStatus | undefined }) {
  const processed = processorStatus?.processedCount ?? 0;
  const failed = processorStatus?.failedCount ?? 0;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Total Events</span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{total.toLocaleString()}</p>
          <p className="text-[10px] text-muted-foreground mt-1">In current view</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Processed</span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{processed.toLocaleString()}</p>
          <p className="text-[10px] text-muted-foreground mt-1">Since last restart</p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4 pb-3 px-4">
          <div className="flex items-center gap-2 mb-2">
            <XCircle className="h-4 w-4 text-red-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Failed</span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{failed.toLocaleString()}</p>
          <p className="text-[10px] text-muted-foreground mt-1">Permanently failed</p>
        </CardContent>
      </Card>
      {processorStatus ? (
        <ProcessorStatusCard status={processorStatus} />
      ) : (
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Processor</span>
            </div>
            <Skeleton className="h-6 w-20 mt-1" />
            <Skeleton className="h-3 w-28 mt-2" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function EventDetailDialog({
  event,
  open,
  onClose,
  onReplay,
  replaying,
}: {
  event: OutboxEvent | null;
  open: boolean;
  onClose: () => void;
  onReplay: (id: string) => void;
  replaying: boolean;
}) {
  if (!event) return null;

  const canReplay = event.status === "failed" || event.status === "dispatched";

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm">
            <Send className="h-4 w-4 text-cyan-400" />
            Event Details
          </DialogTitle>
          <DialogDescription className="text-xs">
            {EVENT_TYPE_LABELS[event.eventType] || event.eventType} &mdash; {event.id.slice(0, 8)}
          </DialogDescription>
        </DialogHeader>
        <ScrollArea className="flex-1 pr-4">
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Status</span>
                <div>
                  <StatusBadge status={event.status} />
                </div>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                  Event Type
                </span>
                <div>
                  <EventTypeBadge eventType={event.eventType} />
                </div>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                  Aggregate
                </span>
                <p className="text-xs font-mono">
                  {event.aggregateType}/{event.aggregateId.slice(0, 12)}
                </p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Created</span>
                <p className="text-xs">{formatDate(event.createdAt)}</p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                  Dispatched
                </span>
                <p className="text-xs">{formatDate(event.dispatchedAt)}</p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Attempts</span>
                <p className="text-xs tabular-nums">
                  {event.attempts} / {event.maxAttempts}
                </p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                  Fingerprint
                </span>
                <p className="text-xs font-mono truncate">{event.fingerprint}</p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                  Next Retry
                </span>
                <p className="text-xs">{formatDate(event.nextRetryAt)}</p>
              </div>
            </div>

            {event.lastError && (
              <div className="space-y-1">
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                  Last Error
                </span>
                <div className="p-2.5 rounded-lg border border-red-500/20 bg-red-500/5">
                  <p className="text-xs text-red-400 font-mono break-all">{event.lastError}</p>
                </div>
              </div>
            )}

            <div className="space-y-1">
              <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Payload</span>
              <div className="p-2.5 rounded-lg border bg-muted/20">
                <pre className="text-[11px] font-mono whitespace-pre-wrap break-all leading-relaxed">
                  {JSON.stringify(event.payload, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </ScrollArea>
        <div className="flex items-center justify-end gap-2 pt-3 border-t">
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
          {canReplay && (
            <Button size="sm" onClick={() => onReplay(event.id)} disabled={replaying} className="gap-1.5">
              {replaying ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              Replay Event
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function EventsTable({
  events,
  isLoading,
  selectedIds,
  onToggleSelect,
  onToggleSelectAll,
  onViewDetail,
  onReplay,
  replaying,
}: {
  events: OutboxEvent[];
  isLoading: boolean;
  selectedIds: Set<string>;
  onToggleSelect: (id: string) => void;
  onToggleSelectAll: () => void;
  onViewDetail: (event: OutboxEvent) => void;
  onReplay: (id: string) => void;
  replaying: boolean;
}) {
  if (isLoading) {
    return (
      <div className="space-y-2 p-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={`skeleton-${i}`} className="flex items-center gap-3">
            <Skeleton className="h-4 w-4" />
            <Skeleton className="h-8 flex-1" />
          </div>
        ))}
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
        <Send className="h-10 w-10 mb-3 opacity-30" />
        <p className="text-sm font-medium">No outbox events found</p>
        <p className="text-xs mt-1">Events will appear here as they are published by the system</p>
      </div>
    );
  }

  const allSelected = events.length > 0 && events.every((e) => selectedIds.has(e.id));
  const someSelected = events.some((e) => selectedIds.has(e.id)) && !allSelected;

  return (
    <ScrollArea className="h-[500px]">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-background z-10">
          <tr className="border-b">
            <th className="text-left py-2 px-2 w-8">
              <button
                onClick={onToggleSelectAll}
                className="flex items-center justify-center hover:text-foreground text-muted-foreground transition-colors"
                aria-label={allSelected ? "Deselect all events" : "Select all events"}
              >
                {allSelected ? (
                  <CheckSquare className="h-4 w-4 text-cyan-400" />
                ) : someSelected ? (
                  <CheckSquare className="h-4 w-4 text-cyan-400/50" />
                ) : (
                  <Square className="h-4 w-4" />
                )}
              </button>
            </th>
            <th className="text-left py-2 px-2 font-medium text-muted-foreground">
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                Time
              </div>
            </th>
            <th className="text-left py-2 px-2 font-medium text-muted-foreground">Event Type</th>
            <th className="text-left py-2 px-2 font-medium text-muted-foreground">Status</th>
            <th className="text-left py-2 px-2 font-medium text-muted-foreground">
              <div className="flex items-center gap-1">
                <Hash className="h-3 w-3" />
                Aggregate
              </div>
            </th>
            <th className="text-center py-2 px-2 font-medium text-muted-foreground">
              <div className="flex items-center justify-center gap-1">
                <ArrowUpDown className="h-3 w-3" />
                Attempts
              </div>
            </th>
            <th className="text-right py-2 px-2 font-medium text-muted-foreground">Actions</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, i) => {
            const isSelected = selectedIds.has(event.id);
            const canReplay = event.status === "failed" || event.status === "dispatched";
            return (
              <tr
                key={event.id}
                className={`border-b border-border/30 transition-colors ${
                  isSelected ? "bg-cyan-500/5" : i % 2 === 0 ? "" : "bg-muted/10"
                } hover:bg-muted/20`}
              >
                <td className="py-2 px-2">
                  <button
                    onClick={() => onToggleSelect(event.id)}
                    className="flex items-center justify-center hover:text-foreground text-muted-foreground transition-colors"
                    aria-label={isSelected ? `Deselect event ${event.id}` : `Select event ${event.id}`}
                  >
                    {isSelected ? <CheckSquare className="h-4 w-4 text-cyan-400" /> : <Square className="h-4 w-4" />}
                  </button>
                </td>
                <td className="py-2 px-2">
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="text-muted-foreground cursor-default">{relativeTime(event.createdAt)}</span>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="text-xs">
                        {formatDate(event.createdAt)}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </td>
                <td className="py-2 px-2">
                  <EventTypeBadge eventType={event.eventType} />
                </td>
                <td className="py-2 px-2">
                  <StatusBadge status={event.status} />
                </td>
                <td className="py-2 px-2">
                  <span className="font-mono text-muted-foreground">
                    {event.aggregateType}/{event.aggregateId.slice(0, 8)}
                  </span>
                </td>
                <td className="py-2 px-2 text-center">
                  <span className="tabular-nums">
                    {event.attempts}/{event.maxAttempts}
                  </span>
                </td>
                <td className="py-2 px-2">
                  <div className="flex items-center justify-end gap-1">
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => onViewDetail(event)}
                            aria-label={`View details for event ${event.id}`}
                          >
                            <Eye className="h-3.5 w-3.5" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="text-xs">
                          View details
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                    {canReplay && (
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-cyan-400 hover:text-cyan-300"
                              onClick={() => onReplay(event.id)}
                              disabled={replaying}
                              aria-label={`Replay event ${event.id}`}
                            >
                              {replaying ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              ) : (
                                <Play className="h-3.5 w-3.5" />
                              )}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent side="top" className="text-xs">
                            Replay event
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </ScrollArea>
  );
}

export default function OutboxMonitoringPage() {
  usePageTitle("Outbox Event Monitor");

  const { toast } = useToast();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(0);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailEvent, setDetailEvent] = useState<OutboxEvent | null>(null);
  const [activeTab, setActiveTab] = useState("events");
  const pageSize = 50;

  const eventsQueryKey = ["/api/v1/outbox/events", statusFilter, page];
  const {
    data: eventsData,
    isLoading: eventsLoading,
    isError: eventsError,
    refetch: refetchEvents,
  } = useQuery<{ items: OutboxEvent[]; total: number }>({
    queryKey: eventsQueryKey,
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter !== "all") params.set("status", statusFilter);
      params.set("limit", String(pageSize));
      params.set("offset", String(page * pageSize));
      const res = await apiRequest("GET", `/api/v1/outbox/events?${params.toString()}`);
      const envelope = await res.json();
      return { items: envelope.data ?? [], total: envelope.meta?.total ?? 0 };
    },
  });

  const { data: processorStatus, refetch: refetchStatus } = useQuery<ProcessorStatus>({
    queryKey: ["/api/v1/outbox/status"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/v1/outbox/status");
      const envelope = await res.json();
      return envelope.data;
    },
  });

  const events = eventsData?.items ?? [];
  const total = eventsData?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const filteredEvents = searchQuery
    ? events.filter(
        (e) =>
          e.eventType.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.aggregateType.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.aggregateId.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.id.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : events;

  const replayMutation = useMutation({
    mutationFn: async (eventId: string) => {
      const res = await apiRequest("POST", `/api/v1/outbox/replay/${eventId}`);
      return await res.json();
    },
    onSuccess: (_data, eventId) => {
      toast({ title: "Event replayed", description: `Event ${eventId.slice(0, 8)} queued for replay` });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/outbox/events"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/outbox/status"] });
      if (detailEvent?.id === eventId) {
        setDetailEvent(null);
      }
    },
    onError: (err: Error) => {
      toast({ title: "Replay failed", description: err.message, variant: "destructive" });
    },
  });

  const batchReplayMutation = useMutation({
    mutationFn: async (eventIds: string[]) => {
      const res = await apiRequest("POST", "/api/v1/outbox/replay-batch", { eventIds });
      return await res.json();
    },
    onSuccess: (envelope: { data: { id: string; replayed: boolean }[] }) => {
      const results = envelope.data ?? [];
      const replayedCount = results.filter((r) => r.replayed).length;
      toast({
        title: "Batch replay complete",
        description: `${replayedCount} of ${results.length} events replayed`,
      });
      setSelectedIds(new Set());
      queryClient.invalidateQueries({ queryKey: ["/api/v1/outbox/events"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/outbox/status"] });
    },
    onError: (err: Error) => {
      toast({ title: "Batch replay failed", description: err.message, variant: "destructive" });
    },
  });

  const handleToggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const handleToggleSelectAll = useCallback(() => {
    setSelectedIds((prev) => {
      const allCurrentSelected = filteredEvents.every((e) => prev.has(e.id));
      if (allCurrentSelected) {
        return new Set();
      }
      return new Set(filteredEvents.map((e) => e.id));
    });
  }, [filteredEvents]);

  const handleReplay = useCallback(
    (id: string) => {
      replayMutation.mutate(id);
    },
    [replayMutation],
  );

  const handleBatchReplay = useCallback(() => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    batchReplayMutation.mutate(ids);
  }, [selectedIds, batchReplayMutation]);

  const handleRefresh = useCallback(() => {
    refetchEvents();
    refetchStatus();
  }, [refetchEvents, refetchStatus]);

  const selectedReplayableCount = Array.from(selectedIds).filter((id) => {
    const event = events.find((e) => e.id === id);
    return event && (event.status === "failed" || event.status === "dispatched");
  }).length;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <Send className="h-5 w-5 text-cyan-400" />
            Outbox Event Monitor
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Track event delivery, manage retries, and replay failed events
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefresh} className="gap-1.5 shrink-0">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      <StatsCards total={total} processorStatus={processorStatus} />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <TabsList>
            <TabsTrigger value="events" className="gap-1.5 text-xs">
              <Send className="h-3.5 w-3.5" />
              Event Log
            </TabsTrigger>
            <TabsTrigger value="retry-queue" className="gap-1.5 text-xs">
              <RotateCcw className="h-3.5 w-3.5" />
              Retry Queue
            </TabsTrigger>
          </TabsList>

          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">
                {selectedIds.size} selected
              </Badge>
              {selectedReplayableCount > 0 && (
                <Button
                  size="sm"
                  onClick={handleBatchReplay}
                  disabled={batchReplayMutation.isPending}
                  className="gap-1.5 text-xs h-7"
                >
                  {batchReplayMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Play className="h-3.5 w-3.5" />
                  )}
                  Replay {selectedReplayableCount}
                </Button>
              )}
              <Button variant="ghost" size="sm" onClick={() => setSelectedIds(new Set())} className="gap-1 text-xs h-7">
                <X className="h-3.5 w-3.5" />
                Clear
              </Button>
            </div>
          )}
        </div>

        <TabsContent value="events" className="mt-4 space-y-3">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-2">
                  <CardTitle className="text-sm">Event Log</CardTitle>
                  <Badge variant="outline" className="text-[10px] tabular-nums">
                    {total.toLocaleString()} total
                  </Badge>
                </div>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                      placeholder="Search events..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="h-8 w-[200px] pl-8 text-xs"
                      aria-label="Search outbox events"
                    />
                    {searchQuery && (
                      <button
                        onClick={() => setSearchQuery("")}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                        aria-label="Clear search"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                    <Select
                      value={statusFilter}
                      onValueChange={(v) => {
                        setStatusFilter(v);
                        setPage(0);
                      }}
                    >
                      <SelectTrigger className="h-8 w-[140px] text-xs">
                        <SelectValue placeholder="All statuses" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all" className="text-xs">
                          All Statuses
                        </SelectItem>
                        <SelectItem value="pending" className="text-xs">
                          Pending
                        </SelectItem>
                        <SelectItem value="dispatched" className="text-xs">
                          Dispatched
                        </SelectItem>
                        <SelectItem value="failed" className="text-xs">
                          Failed
                        </SelectItem>
                        <SelectItem value="replayed" className="text-xs">
                          Replayed
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {eventsError ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <AlertTriangle className="h-8 w-8 mb-2 text-red-400 opacity-60" />
                  <p className="text-sm font-medium">Failed to load events</p>
                  <p className="text-xs mt-1">Check your connection and try again</p>
                  <Button variant="outline" size="sm" onClick={() => refetchEvents()} className="mt-3 gap-1.5">
                    <RefreshCw className="h-3.5 w-3.5" />
                    Retry
                  </Button>
                </div>
              ) : (
                <EventsTable
                  events={filteredEvents}
                  isLoading={eventsLoading}
                  selectedIds={selectedIds}
                  onToggleSelect={handleToggleSelect}
                  onToggleSelectAll={handleToggleSelectAll}
                  onViewDetail={setDetailEvent}
                  onReplay={handleReplay}
                  replaying={replayMutation.isPending}
                />
              )}
            </CardContent>
            {total > pageSize && (
              <div className="flex items-center justify-between px-4 py-3 border-t">
                <p className="text-xs text-muted-foreground">
                  Showing {page * pageSize + 1}&ndash;{Math.min((page + 1) * pageSize, total)} of{" "}
                  {total.toLocaleString()}
                </p>
                <div className="flex items-center gap-1">
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    disabled={page === 0}
                    aria-label="Previous page"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <span className="text-xs tabular-nums px-2">
                    {page + 1} / {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1}
                    aria-label="Next page"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="retry-queue" className="mt-4 space-y-3">
          <RetryQueueView
            events={events}
            eventsLoading={eventsLoading}
            statusFilter={statusFilter}
            onChangeFilter={setStatusFilter}
            onReplay={handleReplay}
            replaying={replayMutation.isPending}
            onViewDetail={setDetailEvent}
          />
        </TabsContent>
      </Tabs>

      <EventDetailDialog
        event={detailEvent}
        open={!!detailEvent}
        onClose={() => setDetailEvent(null)}
        onReplay={handleReplay}
        replaying={replayMutation.isPending}
      />
    </div>
  );
}

function RetryQueueView({
  events,
  eventsLoading,
  statusFilter,
  onChangeFilter,
  onReplay,
  replaying,
  onViewDetail,
}: {
  events: OutboxEvent[];
  eventsLoading: boolean;
  statusFilter: string;
  onChangeFilter: (v: string) => void;
  onReplay: (id: string) => void;
  replaying: boolean;
  onViewDetail: (event: OutboxEvent) => void;
}) {
  const failedEvents = events.filter((e) => e.status === "failed");
  const pendingRetryEvents = events.filter((e) => e.status === "pending" && (e.attempts ?? 0) > 0);
  const retryEvents = [...failedEvents, ...pendingRetryEvents].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );

  if (eventsLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={`retry-skeleton-${i}`}>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <Skeleton className="h-8 w-8 rounded-full" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-48" />
                  <Skeleton className="h-3 w-32" />
                </div>
                <Skeleton className="h-8 w-20" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm flex items-center gap-2">
                <RotateCcw className="h-4 w-4 text-muted-foreground" />
                Retry Queue
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                Events that failed or are pending retry after previous failures
              </CardDescription>
            </div>
            <Badge variant="outline" className="text-xs tabular-nums">
              {retryEvents.length} events
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          {statusFilter !== "all" && statusFilter !== "failed" && (
            <div className="flex items-center gap-2 mb-4 p-2.5 rounded-lg border bg-muted/20">
              <Info className="h-4 w-4 text-muted-foreground shrink-0" />
              <p className="text-xs text-muted-foreground">
                Showing retry queue for current filter. Switch to &ldquo;All Statuses&rdquo; or &ldquo;Failed&rdquo; to
                see the full retry queue.
              </p>
              <Button
                variant="outline"
                size="sm"
                className="ml-auto text-xs h-7 shrink-0"
                onClick={() => onChangeFilter("all")}
              >
                Show All
              </Button>
            </div>
          )}

          {retryEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <CheckCircle2 className="h-10 w-10 mb-3 opacity-30 text-emerald-400" />
              <p className="text-sm font-medium">Retry queue is empty</p>
              <p className="text-xs mt-1">No events are currently pending retry or in a failed state</p>
            </div>
          ) : (
            <ScrollArea className="h-[500px]">
              <div className="space-y-2">
                {retryEvents.map((event) => (
                  <div
                    key={event.id}
                    className="flex items-center gap-3 p-3 rounded-lg border bg-muted/10 hover:bg-muted/20 transition-colors"
                  >
                    <div
                      className={`flex items-center justify-center h-9 w-9 rounded-full shrink-0 ${
                        event.status === "failed" ? "bg-red-500/10" : "bg-yellow-500/10"
                      }`}
                    >
                      {event.status === "failed" ? (
                        <XCircle className="h-4.5 w-4.5 text-red-400" />
                      ) : (
                        <Clock className="h-4.5 w-4.5 text-yellow-400" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center gap-2">
                        <EventTypeBadge eventType={event.eventType} />
                        <StatusBadge status={event.status} />
                      </div>
                      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                        <span>
                          Attempts: {event.attempts}/{event.maxAttempts}
                        </span>
                        <span>{relativeTime(event.createdAt)}</span>
                        {event.nextRetryAt && <span>Next retry: {relativeTime(event.nextRetryAt)}</span>}
                      </div>
                      {event.lastError && (
                        <p className="text-[10px] text-red-400 font-mono truncate">{event.lastError}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8"
                              onClick={() => onViewDetail(event)}
                              aria-label={`View details for event ${event.id}`}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent side="top" className="text-xs">
                            View details
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                      {(event.status === "failed" || event.status === "dispatched") && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => onReplay(event.id)}
                          disabled={replaying}
                          className="gap-1.5 text-xs h-8"
                          aria-label={`Replay event ${event.id}`}
                        >
                          {replaying ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Play className="h-3.5 w-3.5" />
                          )}
                          Replay
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
