import { useQuery } from "@tanstack/react-query";
import { FileWarning, Search, Download } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import { SeverityBadge, IncidentStatusBadge, PriorityBadge, formatRelativeTime } from "@/components/security-badges";
import type { Incident } from "@shared/schema";

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

export default function IncidentsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = { all: incidents?.length || 0 };
    STATUSES.forEach((s) => {
      if (s !== "all") counts[s] = 0;
    });
    incidents?.forEach((inc) => {
      if (counts[inc.status] !== undefined) {
        counts[inc.status]++;
      }
    });
    return counts;
  }, [incidents]);

  const filtered = useMemo(() => {
    if (!incidents) return [];
    return incidents
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
  }, [incidents, search, statusFilter]);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Incidents</span></h1>
        <p className="text-sm text-muted-foreground mt-1">AI-correlated security incidents</p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

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
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden md:table-cell">Assignee</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">Alert Count</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">Updated</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-4 py-3"><Skeleton className="h-4 w-48" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-12" /></td>
                      <td className="px-4 py-3 hidden md:table-cell"><Skeleton className="h-4 w-20" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-12" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-16" /></td>
                    </tr>
                  ))
                ) : filtered.length > 0 ? (
                  filtered.map((incident) => (
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
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-sm text-muted-foreground">
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
