import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  KeyRound,
  RefreshCw,
  AlertTriangle,
  Clock,
  CheckCircle2,
  Loader2,
  Filter,
  Calendar,
  Shield,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Link } from "wouter";

interface SecretRotation {
  id: string;
  connectorId: string;
  orgId: string | null;
  secretField: string;
  lastRotatedAt: string | null;
  nextRotationDue: string | null;
  rotationIntervalDays: number | null;
  status: string;
  rotatedBy: string | null;
  rotatedByName: string | null;
  reminderSentAt: string | null;
  createdAt: string | null;
}

type StatusFilter = "all" | "overdue" | "due_soon" | "ok";

function getDaysUntilDue(nextDue: string | null): number | null {
  if (!nextDue) return null;
  const now = new Date();
  const due = new Date(nextDue);
  return Math.ceil((due.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

function getUrgencyInfo(daysUntil: number | null): {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
  category: "overdue" | "due_soon" | "ok";
} {
  if (daysUntil === null) {
    return {
      label: "Unknown",
      color: "text-muted-foreground",
      bgColor: "bg-muted/50",
      borderColor: "border-muted",
      category: "ok",
    };
  }
  if (daysUntil < 0) {
    return {
      label: "Overdue",
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/30",
      category: "overdue",
    };
  }
  if (daysUntil <= 7) {
    return {
      label: "Critical",
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
      borderColor: "border-orange-500/30",
      category: "due_soon",
    };
  }
  if (daysUntil <= 14) {
    return {
      label: "Warning",
      color: "text-yellow-400",
      bgColor: "bg-yellow-500/10",
      borderColor: "border-yellow-500/30",
      category: "due_soon",
    };
  }
  return {
    label: "OK",
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/30",
    category: "ok",
  };
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function formatRelative(dateStr: string | null): string {
  if (!dateStr) return "—";
  const days = getDaysUntilDue(dateStr);
  if (days === null) return "—";
  if (days < 0) return `${Math.abs(days)}d overdue`;
  if (days === 0) return "Today";
  if (days === 1) return "Tomorrow";
  return `${days}d`;
}

export default function SecretRotationOverviewPage() {
  usePageTitle("Secret Rotation Overview");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [daysAhead, setDaysAhead] = useState(90);

  const {
    data: rotations,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<SecretRotation[]>({
    queryKey: ["/api/secret-rotations/expiring", daysAhead],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/secret-rotations/expiring?days=${daysAhead}`);
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    },
  });

  const filtered = (rotations ?? []).filter((r) => {
    if (statusFilter === "all") return true;
    const days = getDaysUntilDue(r.nextRotationDue);
    const info = getUrgencyInfo(days);
    return info.category === statusFilter;
  });

  const overdueCount = (rotations ?? []).filter((r) => {
    const d = getDaysUntilDue(r.nextRotationDue);
    return d !== null && d < 0;
  }).length;

  const dueSoonCount = (rotations ?? []).filter((r) => {
    const d = getDaysUntilDue(r.nextRotationDue);
    return d !== null && d >= 0 && d <= 14;
  }).length;

  const okCount = (rotations ?? []).filter((r) => {
    const d = getDaysUntilDue(r.nextRotationDue);
    return d !== null && d > 14;
  }).length;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/10 border border-cyan-500/20">
            <KeyRound className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Secret Rotation Scheduling</h1>
            <p className="text-xs text-muted-foreground">Org-wide view of connector secret rotation schedules</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Select value={String(daysAhead)} onValueChange={(v) => setDaysAhead(Number(v))}>
            <SelectTrigger className="w-[130px] h-8 text-xs">
              <Calendar className="h-3.5 w-3.5 mr-1.5" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Next 7 days</SelectItem>
              <SelectItem value="14">Next 14 days</SelectItem>
              <SelectItem value="30">Next 30 days</SelectItem>
              <SelectItem value="60">Next 60 days</SelectItem>
              <SelectItem value="90">Next 90 days</SelectItem>
              <SelectItem value="180">Next 180 days</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching} className="h-8">
            {isFetching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            <span className="ml-1.5 hidden sm:inline">Refresh</span>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Card
          className={`cursor-pointer transition-all hover:border-red-500/40 ${statusFilter === "overdue" ? "border-red-500/50 bg-red-500/5" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "overdue" ? "all" : "overdue")}
        >
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-red-400">
                {isLoading ? <Skeleton className="h-7 w-8 inline-block" /> : overdueCount}
              </p>
              <p className="text-[11px] text-muted-foreground">Overdue</p>
            </div>
          </CardContent>
        </Card>
        <Card
          className={`cursor-pointer transition-all hover:border-orange-500/40 ${statusFilter === "due_soon" ? "border-orange-500/50 bg-orange-500/5" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "due_soon" ? "all" : "due_soon")}
        >
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <Clock className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-orange-400">
                {isLoading ? <Skeleton className="h-7 w-8 inline-block" /> : dueSoonCount}
              </p>
              <p className="text-[11px] text-muted-foreground">Due Soon (≤14d)</p>
            </div>
          </CardContent>
        </Card>
        <Card
          className={`cursor-pointer transition-all hover:border-emerald-500/40 ${statusFilter === "ok" ? "border-emerald-500/50 bg-emerald-500/5" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "ok" ? "all" : "ok")}
        >
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-emerald-400">
                {isLoading ? <Skeleton className="h-7 w-8 inline-block" /> : okCount}
              </p>
              <p className="text-[11px] text-muted-foreground">Healthy</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                Rotation Schedule
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                {filtered.length} rotation{filtered.length !== 1 ? "s" : ""} showing
                {statusFilter !== "all" && ` (filtered: ${statusFilter.replace("_", " ")})`}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
              <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
                <SelectTrigger className="w-[120px] h-7 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="overdue">Overdue</SelectItem>
                  <SelectItem value="due_soon">Due Soon</SelectItem>
                  <SelectItem value="ok">Healthy</SelectItem>
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
              <p className="text-sm text-muted-foreground">Failed to load rotation data</p>
              <Button size="sm" variant="outline" onClick={() => refetch()} className="mt-3">
                Retry
              </Button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
              <p className="text-sm font-medium">No rotations found</p>
              <p className="text-xs text-muted-foreground mt-1">
                {statusFilter !== "all"
                  ? "No rotations match this filter. Try changing the filter."
                  : "No connector secret rotations are scheduled in this time window."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Secret Field</TableHead>
                    <TableHead className="text-xs">Connector</TableHead>
                    <TableHead className="text-xs">Last Rotated</TableHead>
                    <TableHead className="text-xs">Next Due</TableHead>
                    <TableHead className="text-xs text-right">Days Left</TableHead>
                    <TableHead className="text-xs">Interval</TableHead>
                    <TableHead className="text-xs">Rotated By</TableHead>
                    <TableHead className="text-xs w-8" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((rotation) => {
                    const daysUntil = getDaysUntilDue(rotation.nextRotationDue);
                    const urgency = getUrgencyInfo(daysUntil);
                    return (
                      <TableRow key={rotation.id} className="group">
                        <TableCell>
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Badge
                                  variant="outline"
                                  className={`text-[10px] ${urgency.color} ${urgency.bgColor} ${urgency.borderColor}`}
                                >
                                  {urgency.label}
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent className="text-xs">
                                {daysUntil !== null
                                  ? daysUntil < 0
                                    ? `Overdue by ${Math.abs(daysUntil)} days`
                                    : `Due in ${daysUntil} days`
                                  : "No due date set"}
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{rotation.secretField}</TableCell>
                        <TableCell>
                          <Link href={`/connectors`} className="text-xs text-cyan-400 hover:underline">
                            {rotation.connectorId.slice(0, 8)}...
                          </Link>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatDate(rotation.lastRotatedAt)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatDate(rotation.nextRotationDue)}
                        </TableCell>
                        <TableCell className="text-right">
                          <span className={`text-xs font-mono tabular-nums font-medium ${urgency.color}`}>
                            {formatRelative(rotation.nextRotationDue)}
                          </span>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {rotation.rotationIntervalDays != null ? `${rotation.rotationIntervalDays}d` : "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{rotation.rotatedByName || "—"}</TableCell>
                        <TableCell>
                          <Link href="/connectors">
                            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                          </Link>
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
    </div>
  );
}
