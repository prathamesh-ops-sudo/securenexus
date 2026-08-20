import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest, fetchPaginated } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { EyeOff, RefreshCw, Loader2, AlertTriangle, Eye, Filter, Shield, Clock, User, Search } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Link } from "wouter";
import { useToast } from "@/hooks/use-toast";
import { UntrustedText } from "@/components/untrusted-text";

interface Alert {
  id: string;
  orgId: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  source: string | null;
  category: string | null;
  suppressed: boolean | null;
  suppressedBy: string | null;
  suppressionRuleId: string | null;
  assignedTo: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  resolvedAt: string | null;
}

const SEVERITY_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  critical: { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  high: { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low: { text: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30" },
  informational: { text: "text-muted-foreground", bg: "bg-muted/50", border: "border-muted" },
};

function getSeverityStyle(severity: string) {
  return SEVERITY_COLORS[severity.toLowerCase()] ?? SEVERITY_COLORS.informational;
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "—";
  const now = new Date();
  const date = new Date(dateStr);
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

export default function SuppressedAlertsPage() {
  usePageTitle("Suppressed Alerts");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const {
    data: suppressedAlerts,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<Alert[]>({
    queryKey: ["/api/v1/alerts", "suppressed"],
    queryFn: async () => {
      const { items } = await fetchPaginated<Alert>("/api/v1/alerts", {
        suppressed: "true",
        limit: 200,
        sortOrder: "desc",
      });
      return items;
    },
  });

  const filtered = (suppressedAlerts ?? []).filter((a) => {
    if (severityFilter !== "all" && a.severity?.toLowerCase() !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        a.title?.toLowerCase().includes(q) ||
        a.id?.toLowerCase().includes(q) ||
        a.source?.toLowerCase().includes(q) ||
        a.category?.toLowerCase().includes(q) ||
        a.suppressedBy?.toLowerCase().includes(q) ||
        a.suppressionRuleId?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const unsuppressMutation = useMutation({
    mutationFn: async (alertId: string) => {
      const res = await apiRequest("POST", `/api/alerts/${alertId}/unsuppress`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Alert unsuppressed", description: "The alert is now active again." });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/alerts", "suppressed"] });
      setSelectedAlert(null);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to unsuppress", description: err.message, variant: "destructive" });
    },
  });

  const severityCounts = (suppressedAlerts ?? []).reduce(
    (acc, a) => {
      const sev = a.severity?.toLowerCase() ?? "informational";
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-orange-500/20 to-red-500/10 border border-orange-500/20">
            <EyeOff className="h-5 w-5 text-orange-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Suppressed Alert Audit</h1>
            <p className="text-xs text-muted-foreground">
              Review and manage alerts that have been suppressed by analysts or automation rules
            </p>
          </div>
        </div>
        <Button
          size="sm"
          variant="outline"
          disabled={isFetching}
          className="h-8"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ["/api/v1/alerts", "suppressed"] });
            refetch().then(() => {
              toast({ title: "Refreshed", description: "Suppressed alerts list updated." });
            });
          }}
        >
          {isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          <span className="ml-1.5 hidden sm:inline">Refresh</span>
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-muted/50 border border-muted">
              <EyeOff className="h-4 w-4 text-muted-foreground" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">
                {isLoading ? <Skeleton className="h-7 w-8 inline-block" /> : (suppressedAlerts ?? []).length}
              </p>
              <p className="text-[11px] text-muted-foreground">Total Suppressed</p>
            </div>
          </CardContent>
        </Card>
        {["critical", "high", "medium", "low"].map((sev) => {
          const style = getSeverityStyle(sev);
          return (
            <Card key={sev}>
              <CardContent className="p-4 flex items-center gap-3">
                <div className={`p-2 rounded-lg ${style.bg} border ${style.border}`}>
                  <AlertTriangle className={`h-4 w-4 ${style.text}`} />
                </div>
                <div>
                  <p className={`text-2xl font-bold tabular-nums ${style.text}`}>
                    {isLoading ? <Skeleton className="h-7 w-8 inline-block" /> : (severityCounts[sev] ?? 0)}
                  </p>
                  <p className="text-[11px] text-muted-foreground capitalize">{sev}</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                Suppressed Alerts
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                {filtered.length} alert{filtered.length !== 1 ? "s" : ""} showing
                {severityFilter !== "all" && ` (severity: ${severityFilter})`}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  className="h-7 text-xs pl-7 w-[180px]"
                  placeholder="Search alerts..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[110px] h-7 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="informational">Info</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4 space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : isError ? (
            <div className="p-8 text-center">
              <AlertTriangle className="h-8 w-8 text-destructive mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">Failed to load alerts</p>
              <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
                Retry
              </Button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center">
              <EyeOff className="h-8 w-8 text-muted-foreground/50 mx-auto mb-2" />
              <p className="text-sm font-medium">No suppressed alerts found</p>
              <p className="text-xs text-muted-foreground mt-1">
                {searchQuery || severityFilter !== "all"
                  ? "No alerts match the current filters. Try adjusting your search."
                  : "No alerts are currently suppressed."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Severity</TableHead>
                    <TableHead className="text-xs">Title</TableHead>
                    <TableHead className="text-xs">Source</TableHead>
                    <TableHead className="text-xs">Category</TableHead>
                    <TableHead className="text-xs">Suppressed By</TableHead>
                    <TableHead className="text-xs">Rule ID</TableHead>
                    <TableHead className="text-xs">Created</TableHead>
                    <TableHead className="text-xs w-20">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((alert) => {
                    const sevStyle = getSeverityStyle(alert.severity);
                    return (
                      <TableRow key={alert.id} className="group cursor-pointer" onClick={() => setSelectedAlert(alert)}>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${sevStyle.text} ${sevStyle.bg} ${sevStyle.border}`}
                          >
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs max-w-[250px] truncate">
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <UntrustedText value={alert.title} compact />
                              </TooltipTrigger>
                              <TooltipContent className="text-xs max-w-[400px]">
                                <UntrustedText value={alert.title} compact />
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{alert.source || "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{alert.category || "—"}</TableCell>
                        <TableCell className="text-xs">
                          {alert.suppressedBy ? (
                            <div className="flex items-center gap-1">
                              <User className="h-3 w-3 text-muted-foreground" />
                              <span className="font-mono">{alert.suppressedBy.slice(0, 8)}...</span>
                            </div>
                          ) : (
                            <span className="text-muted-foreground">System</span>
                          )}
                        </TableCell>
                        <TableCell className="text-xs font-mono text-muted-foreground">
                          {alert.suppressionRuleId ? `${alert.suppressionRuleId.slice(0, 8)}...` : "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span>{formatRelativeTime(alert.createdAt)}</span>
                              </TooltipTrigger>
                              <TooltipContent className="text-xs">{formatDate(alert.createdAt)}</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-6 px-2 text-[10px] opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={(e) => {
                              e.stopPropagation();
                              unsuppressMutation.mutate(alert.id);
                            }}
                            disabled={unsuppressMutation.isPending}
                          >
                            <Eye className="h-3 w-3 mr-1" />
                            Restore
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-sm">Suppressed Alert Details</DialogTitle>
          </DialogHeader>
          {selectedAlert && (
            <ScrollArea className="max-h-[60vh]">
              <div className="space-y-4 pr-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${getSeverityStyle(selectedAlert.severity).text} ${getSeverityStyle(selectedAlert.severity).bg} ${getSeverityStyle(selectedAlert.severity).border}`}
                    >
                      {selectedAlert.severity}
                    </Badge>
                    <Badge variant="outline" className="text-[10px]">
                      {selectedAlert.status}
                    </Badge>
                  </div>
                  <h3 className="text-sm font-medium">{selectedAlert.title}</h3>
                  {selectedAlert.description && (
                    <p className="text-xs text-muted-foreground">{selectedAlert.description}</p>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-muted-foreground">Alert ID</span>
                    <p className="font-mono mt-0.5">{selectedAlert.id}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Source</span>
                    <p className="mt-0.5">{selectedAlert.source || "—"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Category</span>
                    <p className="mt-0.5">{selectedAlert.category || "—"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Assigned To</span>
                    <p className="mt-0.5">{selectedAlert.assignedTo || "—"}</p>
                  </div>
                </div>

                <div className="border-t border-border/50 pt-3 space-y-2">
                  <h4 className="text-xs font-medium flex items-center gap-1.5">
                    <EyeOff className="h-3.5 w-3.5 text-muted-foreground" />
                    Suppression Details
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-muted-foreground">Suppressed By</span>
                      <p className="font-mono mt-0.5">{selectedAlert.suppressedBy || "System / Automation"}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Suppression Rule</span>
                      <p className="font-mono mt-0.5">{selectedAlert.suppressionRuleId || "Manual"}</p>
                    </div>
                  </div>
                </div>

                <div className="border-t border-border/50 pt-3 space-y-2">
                  <h4 className="text-xs font-medium flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                    Timeline
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-muted-foreground">Created</span>
                      <p className="mt-0.5">{formatDate(selectedAlert.createdAt)}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Last Updated</span>
                      <p className="mt-0.5">{formatDate(selectedAlert.updatedAt)}</p>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="flex-1 h-8 text-xs"
                    onClick={() => unsuppressMutation.mutate(selectedAlert.id)}
                    disabled={unsuppressMutation.isPending}
                  >
                    {unsuppressMutation.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
                    ) : (
                      <Eye className="h-3.5 w-3.5 mr-1.5" />
                    )}
                    Unsuppress Alert
                  </Button>
                  <Link href={`/alerts/${selectedAlert.id}`}>
                    <Button size="sm" variant="default" className="h-8 text-xs">
                      View Full Alert
                    </Button>
                  </Link>
                </div>
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
