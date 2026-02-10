import { useQuery } from "@tanstack/react-query";
import { FileWarning, Search, AlertTriangle, TrendingDown, Clock, ArrowRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { useState } from "react";
import { Link } from "wouter";
import type { Incident } from "@shared/schema";

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

export default function IncidentsPage() {
  const [search, setSearch] = useState("");

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const filtered = incidents?.filter((inc) => {
    if (!search) return true;
    return (
      inc.title.toLowerCase().includes(search.toLowerCase()) ||
      inc.summary?.toLowerCase().includes(search.toLowerCase())
    );
  });

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">Incidents</h1>
        <p className="text-sm text-muted-foreground mt-1">AI-correlated security incidents</p>
      </div>

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search incidents..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
          data-testid="input-search-incidents"
        />
      </div>

      <div className="space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <Skeleton className="h-10 w-10 rounded-md flex-shrink-0" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-5 w-3/4" />
                    <Skeleton className="h-4 w-full" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : filtered && filtered.length > 0 ? (
          filtered.map((incident) => (
            <Link key={incident.id} href={`/incidents/${incident.id}`}>
              <Card className="hover-elevate cursor-pointer" data-testid={`card-incident-${incident.id}`}>
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div className="flex items-center justify-center w-10 h-10 rounded-md bg-muted/50 flex-shrink-0">
                      <FileWarning className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-sm font-semibold">{incident.title}</span>
                        <SeverityBadge severity={incident.severity} />
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2 mb-2">{incident.summary}</p>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" />
                          {incident.alertCount} alerts
                        </span>
                        {incident.confidence && (
                          <span className="flex items-center gap-1">
                            <TrendingDown className="h-3 w-3" />
                            {Math.round(incident.confidence * 100)}% confidence
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {incident.status}
                        </span>
                        {incident.mitreTactics && incident.mitreTactics.length > 0 && (
                          <div className="flex items-center gap-1 flex-wrap">
                            {incident.mitreTactics.map((tactic, i) => (
                              <span key={i} className="px-1.5 py-0.5 rounded bg-muted text-[10px]">{tactic}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                    <ArrowRight className="h-4 w-4 text-muted-foreground flex-shrink-0 mt-1" />
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))
        ) : (
          <div className="text-center py-16 text-sm text-muted-foreground">
            <FileWarning className="h-8 w-8 mx-auto mb-3 text-muted-foreground/50" />
            <p>No incidents found</p>
          </div>
        )}
      </div>
    </div>
  );
}
