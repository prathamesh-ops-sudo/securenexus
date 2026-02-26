import { useQuery } from "@tanstack/react-query";
import { Activity, User, Shield, AlertTriangle, FileWarning, Search, X } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useState, useMemo } from "react";
import type { AuditLog } from "@shared/schema";

const ACTION_ICONS: Record<string, any> = {
  "incident.escalate": FileWarning,
  "incident.contain": Shield,
  "alert.triage": AlertTriangle,
  "alert.correlate": Shield,
  "alert.dismiss": AlertTriangle,
  incident_status_change: Shield,
  incident_priority_change: AlertTriangle,
  alert_status_change: AlertTriangle,
  ai_correlation_applied: Shield,
  ai_narrative_generated: FileWarning,
  ai_triage: AlertTriangle,
  comment_added: User,
  tag_added: Activity,
  tag_removed: Activity,
  incident_escalated: FileWarning,
  incident_assignment_change: User,
};

const ACTION_LABELS: Record<string, string> = {
  "incident.escalate": "Escalated incident",
  "incident.contain": "Contained incident",
  "alert.triage": "Triaged alert",
  "alert.correlate": "Correlated alerts",
  "alert.dismiss": "Dismissed alert",
  incident_status_change: "Status changed",
  incident_priority_change: "Priority changed",
  alert_status_change: "Alert status changed",
  ai_correlation_applied: "AI correlation applied",
  ai_narrative_generated: "AI narrative generated",
  ai_triage: "AI triage",
  comment_added: "Comment added",
  tag_added: "Tag added",
  tag_removed: "Tag removed",
  incident_escalated: "Incident escalated",
  incident_assignment_change: "Assignment changed",
};

const ACTION_CATEGORIES = {
  all: "All",
  "status-changes": "Status Changes",
  "ai-actions": "AI Actions",
  comments: "Comments",
  tags: "Tags",
  escalations: "Escalations",
} as const;

const ACTION_TO_CATEGORY: Record<string, string> = {
  incident_status_change: "status-changes",
  incident_priority_change: "status-changes",
  alert_status_change: "status-changes",
  ai_correlation_applied: "ai-actions",
  ai_narrative_generated: "ai-actions",
  ai_triage: "ai-actions",
  comment_added: "comments",
  tag_added: "tags",
  tag_removed: "tags",
  incident_escalated: "escalations",
  incident_assignment_change: "escalations",
};

export default function AuditLogPage() {
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  const {
    data: logs,
    isLoading,
    isError: logsError,
    refetch: refetchLogs,
  } = useQuery<AuditLog[]>({
    queryKey: ["/api/audit-logs"],
  });

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: logs?.length || 0 };
    Object.keys(ACTION_CATEGORIES).forEach((cat) => {
      if (cat !== "all") counts[cat] = 0;
    });
    logs?.forEach((log) => {
      const category = ACTION_TO_CATEGORY[log.action] || "all";
      if (category !== "all" && counts[category] !== undefined) {
        counts[category]++;
      }
    });
    return counts;
  }, [logs]);

  const filtered = useMemo(() => {
    if (!logs) return [];
    return logs
      .filter((log) => {
        const matchesCategory = categoryFilter === "all" || ACTION_TO_CATEGORY[log.action] === categoryFilter;
        const matchesSearch =
          !search ||
          (log.userName && log.userName.toLowerCase().includes(search.toLowerCase())) ||
          (log.resourceId && log.resourceId.toLowerCase().includes(search.toLowerCase())) ||
          log.action.toLowerCase().includes(search.toLowerCase());
        return matchesCategory && matchesSearch;
      })
      .sort((a, b) => {
        const aDate = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const bDate = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return bDate - aDate;
      });
  }, [logs, search, categoryFilter]);

  const handleClearFilters = () => {
    setSearch("");
    setCategoryFilter("all");
  };

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Audit Log</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1">All platform activities and changes</p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <div className="flex items-center gap-1 flex-wrap">
        {(Object.keys(ACTION_CATEGORIES) as Array<keyof typeof ACTION_CATEGORIES>).map((category) => (
          <button
            key={category}
            onClick={() => setCategoryFilter(category)}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              categoryFilter === category ? "bg-primary text-primary-foreground" : "text-muted-foreground hover-elevate"
            }`}
            data-testid={`filter-${category}`}
          >
            {ACTION_CATEGORIES[category]} ({categoryCounts[category] || 0})
          </button>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by user, resource ID, or action..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-audit-logs"
          />
        </div>
        {(search || categoryFilter !== "all") && (
          <Button
            variant="outline"
            size="default"
            onClick={handleClearFilters}
            data-testid="button-clear-filters"
            className="flex items-center gap-2"
          >
            <X className="h-4 w-4" />
            Clear
          </Button>
        )}
      </div>

      <div className="text-sm text-muted-foreground" data-testid="text-result-count">
        Showing {filtered.length} of {logs?.length || 0} entries
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-0">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-4 border-b last:border-0">
                  <Skeleton className="h-8 w-8 rounded-full flex-shrink-0" />
                  <div className="flex-1 space-y-1">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              ))}
            </div>
          ) : logsError ? (
            <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
              <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
                <AlertTriangle className="h-6 w-6 text-destructive" />
              </div>
              <p className="text-sm font-medium">Failed to load audit logs</p>
              <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
              <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchLogs()}>
                Try Again
              </Button>
            </div>
          ) : filtered && filtered.length > 0 ? (
            <div className="space-y-0">
              {filtered.map((log) => {
                const Icon = ACTION_ICONS[log.action] || Activity;
                const label = ACTION_LABELS[log.action] || log.action;
                const details = log.details
                  ? ((typeof log.details === "string" ? JSON.parse(log.details) : log.details) as Record<string, any>)
                  : null;

                return (
                  <div
                    key={log.id}
                    className="flex items-start gap-3 p-4 border-b last:border-0"
                    data-testid={`log-${log.id}`}
                  >
                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-muted flex-shrink-0 mt-0.5">
                      <Icon className="h-3 w-3 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{label}</span>
                        {log.resourceType && (
                          <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono">
                            {log.resourceType}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5 flex-wrap">
                        {log.userName && (
                          <span className="flex items-center gap-1">
                            <User className="h-3 w-3" />
                            {log.userName}
                          </span>
                        )}
                        {log.createdAt && <span>{new Date(log.createdAt).toLocaleString()}</span>}
                      </div>
                      {details && (
                        <div className="mt-1.5 text-xs text-muted-foreground/80">
                          {details.reason && <span>{details.reason}</span>}
                          {details.action && <span>{details.action}</span>}
                          {details.newStatus && <span>Status changed to: {details.newStatus}</span>}
                          {details.alertsCorrelated && (
                            <span>
                              {details.alertsCorrelated} alerts correlated via {details.method}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-16 text-sm text-muted-foreground">
              <Activity className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50" />
              <p>No audit log entries match your filters</p>
              <p className="text-xs mt-1">Try adjusting your search criteria</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
