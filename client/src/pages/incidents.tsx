import { useQuery, useMutation } from "@tanstack/react-query";
import { FileWarning, Search, Download, Settings, ArrowUpRight, UserPlus, Bookmark, Trash2, X, PanelRight, ExternalLink, CheckCircle2, User, Clock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { useState, useMemo, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { SeverityBadge, IncidentStatusBadge, PriorityBadge, formatRelativeTime } from "@/components/security-badges";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Incident, IncidentSlaPolicy } from "@shared/schema";

function IncidentMiniTimeline({ incident }: { incident: Incident }) {
  const events: { label: string; actor?: string }[] = [];
  if (incident.createdAt) events.push({ label: "Created" });
  if (incident.assignedTo) events.push({ label: "Assigned", actor: incident.assignedTo });
  if (incident.ackAt) events.push({ label: "Acknowledged" });
  if (incident.containedAt) events.push({ label: "Contained" });
  if (incident.status === "resolved" || incident.status === "closed") events.push({ label: incident.status === "resolved" ? "Resolved" : "Closed" });
  if (events.length <= 1) return null;
  const recent = events.slice(-3);
  return (
    <div className="flex items-center gap-1 mt-1">
      {recent.map((ev, i) => (
        <span key={i} className="inline-flex items-center gap-0.5">
          {i > 0 && <span className="text-muted-foreground/40 mx-0.5">&rarr;</span>}
          <span className="text-[9px] text-muted-foreground">{ev.label}</span>
          {ev.actor && <span className="text-[9px] text-primary/70">{ev.actor}</span>}
        </span>
      ))}
    </div>
  );
}

function IncidentFilterChips({ filters, onRemove, onClearAll }: {
  filters: { key: string; label: string; value: string }[];
  onRemove: (key: string) => void;
  onClearAll: () => void;
}) {
  if (filters.length === 0) return null;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Active Filters:</span>
      {filters.map((f) => (
        <Badge key={f.key} variant="secondary" className="text-[10px] pl-2 pr-1 py-0.5 gap-1 cursor-pointer hover:bg-destructive/10 transition-colors">
          <span className="text-muted-foreground">{f.label}:</span> {f.value}
          <button onClick={(e) => { e.stopPropagation(); onRemove(f.key); }} className="ml-0.5 rounded-full hover:bg-muted p-0.5">
            <X className="h-2.5 w-2.5" />
          </button>
        </Badge>
      ))}
      <button onClick={onClearAll} className="text-[10px] text-destructive hover:underline">Clear all</button>
    </div>
  );
}

const STATUSES = ["all", "open", "investigating", "contained", "eradicated", "recovered", "resolved", "closed"] as const;

const STATUS_LABELS: Record<string, string> = {
  all: "All",
  open: "Open",
  investigating: "Investigating",
  contained: "Contained",
  eradicated: "Eradicated",
  recovered: "Recovered",
  resolved: "Resolved",
  closed: "Closed",
};

type QueueTab = "all" | "unassigned" | "escalated" | "aging";

interface QueuesResponse {
  unassigned: Incident[];
  escalated: Incident[];
  aging: Incident[];
}

interface SavedView {
  name: string;
  search: string;
  status: string;
  queue: QueueTab;
}

function getSlaStatus(incident: Incident): { label: string; variant: "destructive" | "default" } | null {
  const now = new Date();

  if (incident.slaBreached) {
    return { label: "SLA Breached", variant: "destructive" };
  }

  if (incident.ackDueAt && !incident.ackAt && now > new Date(incident.ackDueAt)) {
    return { label: "ACK Overdue", variant: "destructive" };
  }

  if (incident.containDueAt && !incident.containedAt && now > new Date(incident.containDueAt)) {
    return { label: "Contain Overdue", variant: "destructive" };
  }

  if (incident.resolveDueAt && !incident.resolvedAt && now > new Date(incident.resolveDueAt)) {
    return { label: "Resolve Overdue", variant: "destructive" };
  }

  if (incident.ackDueAt || incident.containDueAt || incident.resolveDueAt) {
    return { label: "On Track", variant: "default" };
  }

  return null;
}

function SlaPolicyDialog() {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("");
  const [ackMinutes, setAckMinutes] = useState("");
  const [containMinutes, setContainMinutes] = useState("");
  const [resolveMinutes, setResolveMinutes] = useState("");
  const [enabled, setEnabled] = useState(true);

  const { data: policies, isLoading } = useQuery<IncidentSlaPolicy[]>({
    queryKey: ["/api/sla-policies"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await apiRequest("POST", "/api/sla-policies", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sla-policies"] });
      toast({ title: "SLA policy created" });
      setName("");
      setSeverity("");
      setAckMinutes("");
      setContainMinutes("");
      setResolveMinutes("");
      setEnabled(true);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create policy", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/sla-policies/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sla-policies"] });
      toast({ title: "SLA policy deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete policy", description: err.message, variant: "destructive" });
    },
  });

  const handleSubmit = () => {
    if (!name || !severity || !ackMinutes || !containMinutes || !resolveMinutes) return;
    createMutation.mutate({
      name,
      severity,
      ackMinutes: parseInt(ackMinutes, 10),
      containMinutes: parseInt(containMinutes, 10),
      resolveMinutes: parseInt(resolveMinutes, 10),
      enabled,
    });
  };

  return (
    <DialogContent className="max-w-lg max-h-[80vh] overflow-y-auto">
      <DialogHeader>
        <DialogTitle>SLA Policy Settings</DialogTitle>
      </DialogHeader>

      <div className="space-y-4">
        <div className="space-y-3">
          <h3 className="text-sm font-medium">Existing Policies</h3>
          {isLoading ? (
            <Skeleton className="h-16 w-full" />
          ) : policies && policies.length > 0 ? (
            <div className="space-y-2">
              {policies.map((policy) => (
                <div key={policy.id} className="flex items-center justify-between gap-3 p-3 rounded-md border">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium truncate">{policy.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {policy.severity} — ACK: {policy.ackMinutes}m, Contain: {policy.containMinutes}m, Resolve: {policy.resolveMinutes}m
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge variant={policy.enabled ? "default" : "secondary"} className="text-[10px] no-default-active-elevate">
                      {policy.enabled ? "Active" : "Disabled"}
                    </Badge>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => deleteMutation.mutate(policy.id)}
                      disabled={deleteMutation.isPending}
                      data-testid={`button-delete-sla-policy-${policy.id}`}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No SLA policies configured yet.</p>
          )}
        </div>

        <div className="border-t pt-4 space-y-3">
          <h3 className="text-sm font-medium" data-testid="button-create-sla-policy">Create Policy</h3>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Name</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Policy name"
                data-testid="input-sla-name"
              />
            </div>
            <div>
              <Label className="text-xs">Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger data-testid="select-sla-severity">
                  <SelectValue placeholder="Select severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label className="text-xs">ACK (min)</Label>
                <Input
                  type="number"
                  value={ackMinutes}
                  onChange={(e) => setAckMinutes(e.target.value)}
                  placeholder="15"
                  data-testid="input-sla-ack"
                />
              </div>
              <div>
                <Label className="text-xs">Contain (min)</Label>
                <Input
                  type="number"
                  value={containMinutes}
                  onChange={(e) => setContainMinutes(e.target.value)}
                  placeholder="60"
                  data-testid="input-sla-contain"
                />
              </div>
              <div>
                <Label className="text-xs">Resolve (min)</Label>
                <Input
                  type="number"
                  value={resolveMinutes}
                  onChange={(e) => setResolveMinutes(e.target.value)}
                  placeholder="240"
                  data-testid="input-sla-resolve"
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={enabled} onCheckedChange={setEnabled} data-testid="switch-sla-enabled" />
              <Label className="text-xs">Enabled</Label>
            </div>
            <Button
              onClick={handleSubmit}
              disabled={createMutation.isPending || !name || !severity || !ackMinutes || !containMinutes || !resolveMinutes}
              className="w-full"
              data-testid="button-submit-sla-policy"
            >
              {createMutation.isPending ? "Creating..." : "Create Policy"}
            </Button>
          </div>
        </div>
      </div>
    </DialogContent>
  );
}

export default function IncidentsPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [queueTab, setQueueTab] = useState<QueueTab>("all");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkStatus, setBulkStatus] = useState<string>("investigating");
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [savedViewName, setSavedViewName] = useState("");
  const [focusedIncidentId, setFocusedIncidentId] = useState<string | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("incidents.savedViews.v1");
      if (raw) setSavedViews(JSON.parse(raw));
    } catch {
      setSavedViews([]);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("incidents.savedViews.v1", JSON.stringify(savedViews));
  }, [savedViews]);

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: queues, isLoading: queuesLoading } = useQuery<QueuesResponse>({
    queryKey: ["/api/incidents/queues"],
    enabled: queueTab !== "all",
  });

  const bulkUpdate = useMutation({
    mutationFn: async (payload: { status?: string; assignedTo?: string; escalated?: boolean; priority?: number }) => {
      const res = await apiRequest("POST", "/api/incidents/bulk-update", { incidentIds: selectedIds, ...payload });
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents/queues"] });
      toast({ title: "Bulk update complete", description: `Updated ${data.updatedCount || 0} incident(s)` });
      setSelectedIds([]);
    },
    onError: (error: Error) => {
      toast({ title: "Bulk update failed", description: error.message, variant: "destructive" });
    },
  });

  const activeIncidents = useMemo(() => {
    if (queueTab === "all") return incidents || [];
    if (!queues) return [];
    return queues[queueTab] || [];
  }, [queueTab, incidents, queues]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = { all: activeIncidents.length };
    STATUSES.forEach((s) => {
      if (s !== "all") counts[s] = 0;
    });
    activeIncidents.forEach((inc) => {
      if (counts[inc.status] !== undefined) {
        counts[inc.status]++;
      }
    });
    return counts;
  }, [activeIncidents]);

  const filtered = useMemo(() => {
    return activeIncidents
      .filter((inc) => {
        const matchesStatus = statusFilter === "all" || inc.status === statusFilter;
        const matchesSearch =
          !search ||
          inc.title.toLowerCase().includes(search.toLowerCase()) ||
          inc.summary?.toLowerCase().includes(search.toLowerCase());
        return matchesStatus && matchesSearch;
      })
      .sort((a, b) => {
        const aDate = a.updatedAt ? new Date(a.updatedAt).getTime() : 0;
        const bDate = b.updatedAt ? new Date(b.updatedAt).getTime() : 0;
        return bDate - aDate;
      });
  }, [activeIncidents, search, statusFilter]);

  const currentLoading = queueTab === "all" ? isLoading : queuesLoading;
  const allPageIds = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((i) => i.id);
  const allSelected = allPageIds.length > 0 && allPageIds.every((id) => selectedIds.includes(id));

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds((prev) => prev.filter((id) => !allPageIds.includes(id)));
    } else {
      setSelectedIds((prev) => Array.from(new Set([...prev, ...allPageIds])));
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]);
  };

  const selectedIncident = useMemo(() => {
    if (!focusedIncidentId || !filtered) return null;
    return filtered.find((i) => i.id === focusedIncidentId) || null;
  }, [focusedIncidentId, filtered]);

  const assignFocused = useCallback(() => {
    if (!focusedIncidentId) return;
    const name = prompt("Assign to:");
    if (name && name.trim()) {
      apiRequest("PATCH", `/api/incidents/${focusedIncidentId}`, { assignedTo: name.trim() }).then(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
        toast({ title: "Assigned", description: `Incident assigned to ${name.trim()}` });
      });
    }
  }, [focusedIncidentId, toast]);

  const escalateFocused = useCallback(() => {
    if (!focusedIncidentId) return;
    apiRequest("PATCH", `/api/incidents/${focusedIncidentId}`, { status: "escalated" }).then(() => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: "Escalated" });
    });
  }, [focusedIncidentId, toast]);

  const resolveFocused = useCallback(() => {
    if (!focusedIncidentId) return;
    apiRequest("PATCH", `/api/incidents/${focusedIncidentId}`, { status: "resolved" }).then(() => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: "Resolved" });
    });
  }, [focusedIncidentId, toast]);

  const activeFilters = useMemo(() => {
    const chips: { key: string; label: string; value: string }[] = [];
    if (statusFilter !== "all") chips.push({ key: "status", label: "Status", value: STATUS_LABELS[statusFilter] || statusFilter });
    if (search) chips.push({ key: "search", label: "Search", value: search });
    if (queueTab !== "all") chips.push({ key: "queue", label: "Queue", value: queueTab });
    return chips;
  }, [statusFilter, search, queueTab]);

  const handleRemoveFilter = useCallback((key: string) => {
    if (key === "status") setStatusFilter("all");
    if (key === "search") setSearch("");
    if (key === "queue") setQueueTab("all");
  }, []);

  const handleClearAllFilters = useCallback(() => {
    setStatusFilter("all");
    setSearch("");
    setQueueTab("all");
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!filtered || filtered.length === 0) return;
      const target = e.target as HTMLElement;
      if (target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.tagName === "SELECT" || target?.isContentEditable) return;
      const idx = filtered.findIndex((i) => i.id === focusedIncidentId);
      if (e.key.toLowerCase() === "j") {
        e.preventDefault();
        const next = Math.min(idx < 0 ? 0 : idx + 1, filtered.length - 1);
        setFocusedIncidentId(filtered[next]?.id || null);
        const newPage = Math.floor(next / PAGE_SIZE);
        if (newPage !== page) setPage(newPage);
      }
      if (e.key.toLowerCase() === "k") {
        e.preventDefault();
        const prev = Math.max(idx < 0 ? 0 : idx - 1, 0);
        setFocusedIncidentId(filtered[prev]?.id || null);
        const newPage = Math.floor(prev / PAGE_SIZE);
        if (newPage !== page) setPage(newPage);
      }
      if (e.key.toLowerCase() === "a" && focusedIncidentId) {
        e.preventDefault();
        assignFocused();
      }
      if (e.key.toLowerCase() === "e" && focusedIncidentId) {
        e.preventDefault();
        escalateFocused();
      }
      if (e.key.toLowerCase() === "r" && focusedIncidentId) {
        e.preventDefault();
        resolveFocused();
      }
      if (e.key === "Enter" && focusedIncidentId) {
        e.preventDefault();
        setIsDetailOpen(true);
      }
      if (e.key === "Escape") {
        setIsDetailOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [filtered, focusedIncidentId, page, assignFocused, escalateFocused, resolveFocused]);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Incidents</span></h1>
          <p className="text-sm text-muted-foreground mt-1">AI-correlated security incidents</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="outline" size="icon" data-testid="button-sla-settings">
              <Settings className="h-4 w-4" />
            </Button>
          </DialogTrigger>
          <SlaPolicyDialog />
        </Dialog>
      </div>

      <Tabs value={queueTab} onValueChange={(v) => { setQueueTab(v as QueueTab); setStatusFilter("all"); setSelectedIds([]); }}>
        <TabsList>
          <TabsTrigger value="all" data-testid="tab-queue-all">All Incidents</TabsTrigger>
          <TabsTrigger value="unassigned" data-testid="tab-queue-unassigned">Unassigned</TabsTrigger>
          <TabsTrigger value="escalated" data-testid="tab-queue-escalated">Escalated</TabsTrigger>
          <TabsTrigger value="aging" data-testid="tab-queue-aging">Aging (&gt;7 days)</TabsTrigger>
        </TabsList>
      </Tabs>

      <div className="flex items-center gap-1 flex-wrap">
        {STATUSES.map((status) => (
          <button
            key={status}
            onClick={() => setStatusFilter(status)}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              statusFilter === status
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover-elevate"
            }`}
            data-testid={`filter-${status}`}
          >
            {STATUS_LABELS[status]} ({statusCounts[status] || 0})
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search incidents..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-incidents"
          />
        </div>
        <Button variant="outline" size="icon" data-testid="button-export-incidents" onClick={() => window.open('/api/export/incidents', '_blank')}>
          <Download className="h-4 w-4" />
        </Button>
        <Input placeholder="View name" value={savedViewName} onChange={(e) => setSavedViewName(e.target.value)} className="w-36" />
        <Button
          variant="outline"
          size="sm"
          disabled={!savedViewName.trim()}
          onClick={() => {
            const entry: SavedView = { name: savedViewName.trim(), search, status: statusFilter, queue: queueTab };
            setSavedViews((prev) => [entry, ...prev.filter((v) => v.name !== entry.name)].slice(0, 8));
            setSavedViewName("");
            toast({ title: "View saved" });
          }}
          data-testid="button-save-view"
        >
          <Bookmark className="h-3.5 w-3.5 mr-1.5" />
          Save View
        </Button>
      </div>

      {savedViews.length > 0 && (
        <div className="flex flex-wrap gap-2" data-testid="section-saved-views">
          {savedViews.map((v) => (
            <div key={v.name} className="flex items-center gap-1">
              <Button size="sm" variant="secondary" onClick={() => {
                setSearch(v.search);
                setStatusFilter(v.status);
                setQueueTab(v.queue);
              }} data-testid={`saved-view-${v.name}`}>
                {v.name}
              </Button>
              <Button size="icon" variant="ghost" className="h-6 w-6" onClick={() => setSavedViews((prev) => prev.filter((x) => x.name !== v.name))}>
                <Trash2 className="h-3 w-3" />
              </Button>
            </div>
          ))}
        </div>
      )}

      <IncidentFilterChips filters={activeFilters} onRemove={handleRemoveFilter} onClearAll={handleClearAllFilters} />

      <div className="flex items-center gap-2 text-[10px] text-muted-foreground border border-border/50 rounded-md px-3 py-1.5 bg-muted/20">
        <span className="font-medium">Shortcuts:</span>
        <kbd className="px-1 py-0.5 bg-muted rounded text-[9px]">J/K</kbd> navigate
        <kbd className="px-1 py-0.5 bg-muted rounded text-[9px]">Enter</kbd> open
        <kbd className="px-1 py-0.5 bg-muted rounded text-[9px]">A</kbd> assign
        <kbd className="px-1 py-0.5 bg-muted rounded text-[9px]">E</kbd> escalate
        <kbd className="px-1 py-0.5 bg-muted rounded text-[9px]">R</kbd> resolve
        <kbd className="px-1 py-0.5 bg-muted rounded text-[9px]">Esc</kbd> close
      </div>

      {selectedIds.length > 0 && (
        <Card data-testid="section-bulk-actions">
          <CardContent className="pt-4 flex items-center flex-wrap gap-2">
            <Badge variant="outline">{selectedIds.length} selected</Badge>
            <Select value={bulkStatus} onValueChange={setBulkStatus}>
              <SelectTrigger className="w-44" data-testid="select-bulk-status"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="investigating">Investigating</SelectItem>
                <SelectItem value="contained">Contained</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="closed">Closed</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" onClick={() => bulkUpdate.mutate({ status: bulkStatus })} disabled={bulkUpdate.isPending} data-testid="button-bulk-status">
              Apply Status
            </Button>
            <div className="flex items-center gap-1">
              <Input placeholder="Assignee" value={bulkAssignee} onChange={(e) => setBulkAssignee(e.target.value)} className="w-32 h-8 text-sm" data-testid="input-bulk-assignee" />
              <Button size="sm" variant="outline" onClick={() => { if (bulkAssignee.trim()) bulkUpdate.mutate({ assignedTo: bulkAssignee.trim() }); }} disabled={bulkUpdate.isPending || !bulkAssignee.trim()} data-testid="button-bulk-assign">
                <UserPlus className="h-3 w-3 mr-1" />
                Assign
              </Button>
            </div>
            <Button size="sm" variant="outline" onClick={() => bulkUpdate.mutate({ escalated: true })} disabled={bulkUpdate.isPending} data-testid="button-bulk-escalate">
              <ArrowUpRight className="h-3 w-3 mr-1" />
              Escalate
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelectedIds([])} data-testid="button-clear-selection">
              Clear
            </Button>
          </CardContent>
        </Card>
      )}

      <div className={`flex gap-4 ${isDetailOpen && selectedIncident ? "" : ""}`}>
      <Card className={`${isDetailOpen && selectedIncident ? "flex-1 min-w-0" : "w-full"} transition-all duration-200`}>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-left">
                  <th className="px-4 py-3 w-10">
                    <Checkbox
                      checked={allSelected}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all incidents on this page"
                      data-testid="checkbox-select-all"
                    />
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Incident</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Severity</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Priority</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">SLA</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden md:table-cell">Assignee</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">Alert Count</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">Updated</th>
                </tr>
              </thead>
              <tbody>
                {currentLoading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-4 py-3"><Skeleton className="h-4 w-4" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-48" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-12" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3 hidden md:table-cell"><Skeleton className="h-4 w-20" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-12" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-16" /></td>
                    </tr>
                  ))
                ) : filtered.length > 0 ? (
                  filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((incident) => {
                    const slaStatus = getSlaStatus(incident);
                    const isSelected = selectedIds.includes(incident.id);
                    const isFocused = focusedIncidentId === incident.id;
                    return (
                      <tr
                        key={incident.id}
                        className={`border-b last:border-0 hover-elevate cursor-pointer ${isSelected ? "bg-primary/5" : ""} ${isFocused ? "ring-1 ring-primary/40 bg-primary/5" : ""}`}
                        data-testid={`row-incident-${incident.id}`}
                        onClick={() => { setFocusedIncidentId(incident.id); setIsDetailOpen(true); }}
                      >
                        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={() => toggleSelect(incident.id)}
                            aria-label={`Select incident ${incident.title}`}
                            data-testid={`checkbox-incident-${incident.id}`}
                          />
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <FileWarning className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                            <div>
                              <div className="text-sm font-medium">{incident.title}</div>
                              <div className="text-xs text-muted-foreground truncate max-w-[300px]">{incident.summary}</div>
                              <IncidentMiniTimeline incident={incident} />
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={incident.severity} />
                        </td>
                        <td className="px-4 py-3">
                          <IncidentStatusBadge status={incident.status} />
                        </td>
                        <td className="px-4 py-3">
                          <PriorityBadge priority={incident.priority ?? 3} />
                        </td>
                        <td className="px-4 py-3" data-testid={`badge-sla-${incident.id}`}>
                          {slaStatus ? (
                            <Badge
                              variant={slaStatus.variant}
                              className="text-[10px] no-default-active-elevate"
                            >
                              {slaStatus.label}
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 hidden md:table-cell">
                          <span className="text-xs text-muted-foreground">{incident.assignedTo || "-"}</span>
                        </td>
                        <td className="px-4 py-3 hidden lg:table-cell">
                          <span className="text-xs text-muted-foreground">{incident.alertCount ?? 0}</span>
                        </td>
                        <td className="px-4 py-3 hidden lg:table-cell">
                          <span className="text-xs text-muted-foreground">{formatRelativeTime(incident.updatedAt)}</span>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={9} className="px-4 py-12 text-center text-sm text-muted-foreground">
                      <FileWarning className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50" />
                      <p>No incidents found</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {filtered.length > PAGE_SIZE && (
            <div className="flex items-center justify-between px-4 py-3 border-t">
              <span className="text-xs text-muted-foreground">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-1">
                <Button variant="outline" size="icon" className="h-7 w-7" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft className="h-3 w-3" />
                </Button>
                <span className="text-xs px-2">{page + 1} / {Math.ceil(filtered.length / PAGE_SIZE)}</span>
                <Button variant="outline" size="icon" className="h-7 w-7" disabled={(page + 1) * PAGE_SIZE >= filtered.length} onClick={() => setPage(p => p + 1)}>
                  <ChevronRight className="h-3 w-3" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {isDetailOpen && selectedIncident && (
        <Card className="w-full max-w-md flex-shrink-0 hidden lg:flex flex-col max-h-[calc(100vh-12rem)] sticky top-24">
          <div className="flex items-center justify-between px-4 py-3 border-b">
            <div className="flex items-center gap-2">
              <PanelRight className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-semibold truncate">{selectedIncident.title}</span>
            </div>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setIsDetailOpen(false)}>
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Severity</span>
                <div className="mt-1"><SeverityBadge severity={selectedIncident.severity} /></div>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Status</span>
                <div className="mt-1"><IncidentStatusBadge status={selectedIncident.status} /></div>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Priority</span>
                <div className="mt-1"><PriorityBadge priority={selectedIncident.priority ?? 3} /></div>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Assigned To</span>
                <div className="mt-1 flex items-center gap-1">
                  <User className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs">{selectedIncident.assignedTo || "Unassigned"}</span>
                </div>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Alert Count</span>
                <div className="mt-1 text-xs">{selectedIncident.alertCount ?? 0}</div>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Updated</span>
                <div className="mt-1 flex items-center gap-1">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs">{formatRelativeTime(selectedIncident.updatedAt)}</span>
                </div>
              </div>
            </div>
            {selectedIncident.summary && (
              <div>
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Summary</span>
                <p className="text-xs mt-1 text-muted-foreground leading-relaxed">{selectedIncident.summary}</p>
              </div>
            )}
            <IncidentMiniTimeline incident={selectedIncident} />
            <div className="space-y-2">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Quick Actions</span>
              <div className="grid grid-cols-3 gap-2">
                <Button size="sm" variant="outline" className="text-xs h-8" onClick={assignFocused}>
                  <UserPlus className="h-3 w-3 mr-1" />
                  Assign <kbd className="ml-1 text-[9px] opacity-50">A</kbd>
                </Button>
                <Button size="sm" variant="outline" className="text-xs h-8" onClick={escalateFocused}>
                  <ArrowUpRight className="h-3 w-3 mr-1" />
                  Escalate <kbd className="ml-1 text-[9px] opacity-50">E</kbd>
                </Button>
                <Button size="sm" variant="outline" className="text-xs h-8" onClick={resolveFocused}>
                  <CheckCircle2 className="h-3 w-3 mr-1" />
                  Resolve <kbd className="ml-1 text-[9px] opacity-50">R</kbd>
                </Button>
              </div>
            </div>
          </div>
          <div className="px-4 py-3 border-t">
            <Button size="sm" className="w-full text-xs" onClick={() => navigate(`/incidents/${selectedIncident.id}`)}>
              <ExternalLink className="h-3 w-3 mr-1.5" />
              View Full Details
            </Button>
          </div>
        </Card>
      )}
      </div>
    </div>
  );
}
