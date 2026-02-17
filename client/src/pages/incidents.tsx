import { useQuery, useMutation } from "@tanstack/react-query";
import { FileWarning, Search, Download, Settings } from "lucide-react";
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
import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import { SeverityBadge, IncidentStatusBadge, PriorityBadge, formatRelativeTime } from "@/components/security-badges";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Incident, IncidentSlaPolicy } from "@shared/schema";

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
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [queueTab, setQueueTab] = useState<QueueTab>("all");

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: queues, isLoading: queuesLoading } = useQuery<QueuesResponse>({
    queryKey: ["/api/incidents/queues"],
    enabled: queueTab !== "all",
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

      <Tabs value={queueTab} onValueChange={(v) => { setQueueTab(v as QueueTab); setStatusFilter("all"); }}>
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

      <div className="flex items-center gap-3">
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
      </div>

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-left">
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
                  filtered.map((incident) => {
                    const slaStatus = getSlaStatus(incident);
                    return (
                      <tr
                        key={incident.id}
                        className="border-b last:border-0 hover-elevate cursor-pointer"
                        onClick={() => navigate(`/incidents/${incident.id}`)}
                        data-testid={`row-incident-${incident.id}`}
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <FileWarning className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                            <div>
                              <div className="text-sm font-medium">{incident.title}</div>
                              <div className="text-xs text-muted-foreground truncate max-w-[300px]">{incident.summary}</div>
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
                    <td colSpan={8} className="px-4 py-12 text-center text-sm text-muted-foreground">
                      <FileWarning className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50" />
                      <p>No incidents found</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
