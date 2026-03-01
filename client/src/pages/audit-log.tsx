import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  User,
  Shield,
  AlertTriangle,
  FileWarning,
  Search,
  X,
  Download,
  Calendar,
  ChevronLeft,
  ChevronRight,
  Globe,
  FileJson,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useState, useMemo, useCallback } from "react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { AuditLog } from "@shared/schema";
import { formatDateTime } from "@/lib/i18n";

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

const ITEMS_PER_PAGE = 50;

function formatDateForInput(date: Date): string {
  return date.toISOString().split("T")[0];
}

export default function AuditLogPage() {
  const { toast } = useToast();
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [page, setPage] = useState(1);
  const [exporting, setExporting] = useState(false);

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
          log.action.toLowerCase().includes(search.toLowerCase()) ||
          (log.ipAddress && log.ipAddress.toLowerCase().includes(search.toLowerCase()));

        let matchesDateRange = true;
        if (dateFrom && log.createdAt) {
          matchesDateRange = new Date(log.createdAt) >= new Date(dateFrom);
        }
        if (dateTo && log.createdAt && matchesDateRange) {
          const toDate = new Date(dateTo);
          toDate.setHours(23, 59, 59, 999);
          matchesDateRange = new Date(log.createdAt) <= toDate;
        }

        return matchesCategory && matchesSearch && matchesDateRange;
      })
      .sort((a, b) => {
        const aDate = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const bDate = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return bDate - aDate;
      });
  }, [logs, search, categoryFilter, dateFrom, dateTo]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / ITEMS_PER_PAGE));
  const paginatedLogs = useMemo(() => {
    const start = (page - 1) * ITEMS_PER_PAGE;
    return filtered.slice(start, start + ITEMS_PER_PAGE);
  }, [filtered, page]);

  const handleClearFilters = () => {
    setSearch("");
    setCategoryFilter("all");
    setDateFrom("");
    setDateTo("");
    setPage(1);
  };

  const hasActiveFilters = search || categoryFilter !== "all" || dateFrom || dateTo;

  const handleExportCSV = useCallback(async () => {
    setExporting(true);
    try {
      const params = new URLSearchParams();
      if (dateFrom) params.set("startDate", dateFrom);
      if (dateTo) params.set("endDate", dateTo);
      const url = `/api/compliance/audit/export/csv${params.toString() ? `?${params}` : ""}`;
      const res = await apiRequest("GET", url);
      const text = await res.text();
      const blob = new Blob([text], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `audit-log-${formatDateForInput(new Date())}.csv`;
      link.click();
      URL.revokeObjectURL(link.href);
      toast({ title: "Export complete", description: "Audit log CSV downloaded." });
    } catch (err: unknown) {
      toast({
        title: "Export failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    } finally {
      setExporting(false);
    }
  }, [dateFrom, dateTo, toast]);

  const handleExportJSON = useCallback(async () => {
    setExporting(true);
    try {
      const params = new URLSearchParams();
      if (dateFrom) params.set("startDate", dateFrom);
      if (dateTo) params.set("endDate", dateTo);
      const url = `/api/compliance/audit/export${params.toString() ? `?${params}` : ""}`;
      const res = await apiRequest("GET", url);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `audit-log-${formatDateForInput(new Date())}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
      toast({ title: "Export complete", description: "Audit log JSON downloaded." });
    } catch (err: unknown) {
      toast({
        title: "Export failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    } finally {
      setExporting(false);
    }
  }, [dateFrom, dateTo, toast]);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            <span className="gradient-text-red">Audit Log</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1">All platform activities and changes</p>
          <div className="gradient-accent-line w-24 mt-2" />
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportCSV}
            disabled={exporting || !logs?.length}
            data-testid="button-export-csv"
            className="gap-1.5"
          >
            <Download className="h-3.5 w-3.5" />
            CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportJSON}
            disabled={exporting || !logs?.length}
            data-testid="button-export-json"
            className="gap-1.5"
          >
            <FileJson className="h-3.5 w-3.5" />
            JSON
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-1 flex-wrap">
        {(Object.keys(ACTION_CATEGORIES) as Array<keyof typeof ACTION_CATEGORIES>).map((category) => (
          <button
            key={category}
            onClick={() => {
              setCategoryFilter(category);
              setPage(1);
            }}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              categoryFilter === category ? "bg-primary text-primary-foreground" : "text-muted-foreground hover-elevate"
            }`}
            data-testid={`filter-${category}`}
          >
            {ACTION_CATEGORIES[category]} ({categoryCounts[category] || 0})
          </button>
        ))}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by user, resource, action, or IP..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="pl-9"
            data-testid="input-search-audit-logs"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Calendar className="h-4 w-4 text-muted-foreground" />
          <Input
            type="date"
            value={dateFrom}
            onChange={(e) => {
              setDateFrom(e.target.value);
              setPage(1);
            }}
            className="w-[140px] text-xs"
            aria-label="Date from"
            data-testid="input-date-from"
          />
          <span className="text-xs text-muted-foreground">to</span>
          <Input
            type="date"
            value={dateTo}
            onChange={(e) => {
              setDateTo(e.target.value);
              setPage(1);
            }}
            className="w-[140px] text-xs"
            aria-label="Date to"
            data-testid="input-date-to"
          />
        </div>
        {hasActiveFilters && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleClearFilters}
            data-testid="button-clear-filters"
            className="gap-1.5"
          >
            <X className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}
      </div>

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span data-testid="text-result-count">
          Showing {paginatedLogs.length} of {filtered.length} entries
          {filtered.length !== (logs?.length || 0) && ` (${logs?.length || 0} total)`}
        </span>
        {totalPages > 1 && (
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              aria-label="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="text-xs">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              aria-label="Next page"
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        )}
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
          ) : paginatedLogs.length > 0 ? (
            <div className="space-y-0">
              {paginatedLogs.map((log) => {
                const Icon = ACTION_ICONS[log.action] || Activity;
                const label = ACTION_LABELS[log.action] || log.action;
                const details = log.details
                  ? ((typeof log.details === "string" ? JSON.parse(log.details) : log.details) as Record<
                      string,
                      unknown
                    >)
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
                        {log.resourceId && (
                          <span className="px-1.5 py-0.5 rounded bg-muted/50 text-[10px] font-mono text-muted-foreground">
                            {log.resourceId}
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
                        {log.ipAddress && (
                          <span className="flex items-center gap-1">
                            <Globe className="h-3 w-3" />
                            {log.ipAddress}
                          </span>
                        )}
                        {log.createdAt && <span>{formatDateTime(log.createdAt)}</span>}
                      </div>
                      {details && (
                        <div className="mt-1.5 text-xs text-muted-foreground/80">
                          {typeof details.reason === "string" && <span>{details.reason}</span>}
                          {typeof details.action === "string" && <span>{details.action}</span>}
                          {typeof details.newStatus === "string" && <span>Status changed to: {details.newStatus}</span>}
                          {typeof details.alertsCorrelated === "number" && (
                            <span>
                              {details.alertsCorrelated} alerts correlated via{" "}
                              {typeof details.method === "string" ? details.method : "unknown"}
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

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 pb-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            aria-label="Previous page"
          >
            <ChevronLeft className="h-4 w-4 mr-1" />
            Previous
          </Button>
          <span className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            aria-label="Next page"
          >
            Next
            <ChevronRight className="h-4 w-4 ml-1" />
          </Button>
        </div>
      )}
    </div>
  );
}
