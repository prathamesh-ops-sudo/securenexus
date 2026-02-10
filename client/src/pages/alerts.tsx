import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Search, Filter } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useState } from "react";
import type { Alert } from "@shared/schema";

function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-green-500/10 text-green-500 border-green-500/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${variants[severity] || variants.medium}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, string> = {
    new: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    correlated: "bg-purple-500/10 text-purple-500 border-purple-500/20",
    dismissed: "bg-muted text-muted-foreground border-muted",
    investigating: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider border ${variants[status] || variants.new}`}>
      {status}
    </span>
  );
}

export default function AlertsPage() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const { data: alerts, isLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const filtered = alerts?.filter((alert) => {
    const matchesSearch = !search ||
      alert.title.toLowerCase().includes(search.toLowerCase()) ||
      alert.source.toLowerCase().includes(search.toLowerCase()) ||
      alert.description?.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const severities = ["all", "critical", "high", "medium", "low"];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">Alerts</h1>
        <p className="text-sm text-muted-foreground mt-1">All security alerts from integrated tools</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-alerts"
          />
        </div>
        <div className="flex items-center gap-1">
          {severities.map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
                severityFilter === sev
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover-elevate"
              }`}
              data-testid={`filter-${sev}`}
            >
              {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b text-left">
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Alert</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden md:table-cell">Source</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Severity</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground hidden lg:table-cell">MITRE Tactic</th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Status</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-4 py-3"><Skeleton className="h-4 w-48" /></td>
                      <td className="px-4 py-3 hidden md:table-cell"><Skeleton className="h-4 w-24" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                      <td className="px-4 py-3 hidden lg:table-cell"><Skeleton className="h-4 w-28" /></td>
                      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                    </tr>
                  ))
                ) : filtered && filtered.length > 0 ? (
                  filtered.map((alert) => (
                    <tr
                      key={alert.id}
                      className="border-b last:border-0 hover-elevate cursor-pointer"
                      data-testid={`row-alert-${alert.id}`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                          <div>
                            <div className="text-sm font-medium">{alert.title}</div>
                            <div className="text-xs text-muted-foreground truncate max-w-[300px]">{alert.description}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 hidden md:table-cell">
                        <span className="text-xs text-muted-foreground">{alert.source}</span>
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        <span className="text-xs text-muted-foreground">{alert.mitreTactic || "-"}</span>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={alert.status} />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-sm text-muted-foreground">
                      No alerts found
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
