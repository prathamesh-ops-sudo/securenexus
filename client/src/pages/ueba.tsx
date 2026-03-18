import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { Progress } from "@/components/ui/progress";
import {
  UserCheck,
  Users,
  AlertTriangle,
  Search,
  Activity,
  Shield,
  TrendingUp,
  Clock,
  Eye,
  XCircle,
  Play,
  BarChart3,
  Plug,
} from "lucide-react";
import { EmptyState } from "@/components/empty-state";
import { useLocation } from "wouter";
import { TablePageSkeleton } from "@/components/page-skeleton";

interface EntityScore {
  id: string;
  entityType: string;
  entityId: string;
  entityName: string | null;
  riskScore: number;
  riskLevel: string;
  anomalyCount: number;
  lastAnomalyAt: string | null;
  updatedAt: string;
}

interface Anomaly {
  id: string;
  entityType: string;
  entityId: string;
  entityName: string | null;
  anomalyType: string;
  severity: string;
  riskScore: number;
  description: string | null;
  details: Record<string, unknown> | null;
  sourceIp: string | null;
  geoLocation: string | null;
  processName: string | null;
  dismissed: boolean;
  createdAt: string;
}

interface Baseline {
  id: string;
  entityType: string;
  entityId: string;
  entityName: string | null;
  normalLoginHoursStart: number | null;
  normalLoginHoursEnd: number | null;
  knownSourceIps: string[];
  processAllowList: string[];
  avgDailyEventVolume: number | null;
  lastUpdated: string;
}

const riskColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  none: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const anomalyTypeLabels: Record<string, string> = {
  off_hours_login: "Off-Hours Login",
  new_geo_location: "New Geo Location",
  suspicious_process: "Suspicious Process",
  traffic_volume_spike: "Traffic Spike",
  new_source_ip: "New Source IP",
  brute_force_attempt: "Brute Force",
  privilege_escalation: "Privilege Escalation",
  data_exfiltration: "Data Exfiltration",
};

function riskScoreColor(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  if (score >= 20) return "text-blue-400";
  return "text-zinc-400";
}

function riskBarColor(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  if (score >= 20) return "bg-blue-500";
  return "bg-zinc-500";
}

async function apiFetch(url: string, options?: RequestInit) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  // Include org context header
  try {
    const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
    if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
  } catch {
    /* SSR / privacy mode */
  }
  // Include CSRF token for mutating requests
  const method = options?.method?.toUpperCase() ?? "GET";
  if (method !== "GET" && method !== "HEAD") {
    const { fetchCsrfToken } = await import("@/lib/queryClient");
    const csrfToken = await fetchCsrfToken();
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(url, {
    ...options,
    headers: { ...headers, ...options?.headers },
    credentials: "include",
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const json = await res.json();
  // Unwrap the standard { data, meta, errors } envelope if present
  if (typeof json === "object" && json !== null && "data" in json && "meta" in json && "errors" in json)
    return json.data;
  return json;
}

export default function UebaPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("leaderboard");
  const [entityTypeFilter, setEntityTypeFilter] = useState("all");
  const [riskLevelFilter, setRiskLevelFilter] = useState("all");
  const [anomalyTypeFilter, setAnomalyTypeFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEntity, setSelectedEntity] = useState<EntityScore | null>(null);

  const { data: entitiesData, isLoading: entitiesLoading } = useQuery<{
    entities: EntityScore[];
    stats: {
      total: number;
      criticalCount: number;
      highCount: number;
      mediumCount: number;
      lowCount: number;
      avgRiskScore: number;
    };
  }>({
    queryKey: ["/api/ueba/entities", entityTypeFilter, riskLevelFilter, searchQuery],
    queryFn: () => {
      const params = new URLSearchParams();
      if (entityTypeFilter !== "all") params.set("entityType", entityTypeFilter);
      if (riskLevelFilter !== "all") params.set("riskLevel", riskLevelFilter);
      if (searchQuery) params.set("q", searchQuery);
      return apiFetch(`/api/ueba/entities?${params}`);
    },
  });

  const { data: anomaliesData, isLoading: anomaliesLoading } = useQuery<{ anomalies: Anomaly[] }>({
    queryKey: ["/api/ueba/anomalies", anomalyTypeFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (anomalyTypeFilter !== "all") params.set("anomalyType", anomalyTypeFilter);
      return apiFetch(`/api/ueba/anomalies?${params}`);
    },
  });

  const { data: entityDetail } = useQuery<{
    score: EntityScore | null;
    baseline: Baseline | null;
    anomalies: Anomaly[];
  }>({
    queryKey: ["/api/ueba/entity-detail", selectedEntity?.entityType, selectedEntity?.entityId],
    queryFn: () => apiFetch(`/api/ueba/entities/${selectedEntity!.entityType}/${selectedEntity!.entityId}`),
    enabled: !!selectedEntity,
  });

  const analyzeMutation = useMutation({
    mutationFn: () => apiFetch("/api/ueba/analyze", { method: "POST", body: JSON.stringify({ windowHours: 24 }) }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ueba"] });
      toast({
        title: "Analysis complete",
        description: `${data.anomaliesCreated} anomalies found, ${data.baselinesUpdated} baselines updated`,
      });
    },
    onError: () => {
      toast({ title: "Analysis failed", variant: "destructive" });
    },
  });

  const dismissMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/ueba/anomalies/${id}/dismiss`, { method: "PATCH" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ueba"] });
      toast({ title: "Anomaly dismissed" });
    },
  });

  const stats = entitiesData?.stats;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <UserCheck className="h-6 w-6 text-teal-400" />
            UEBA Behavioral Analytics
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            User and entity behavior analytics with anomaly detection and risk scoring
          </p>
        </div>
        <Button
          onClick={() => analyzeMutation.mutate()}
          disabled={analyzeMutation.isPending}
          className="bg-teal-600 hover:bg-teal-700"
        >
          <Play className="h-4 w-4 mr-1" />
          {analyzeMutation.isPending ? "Analyzing..." : "Run Analysis"}
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Entities Tracked</div>
            <div className="text-2xl font-semibold mt-1">{stats?.total ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-red-400">Critical Risk</div>
            <div className="text-2xl font-semibold mt-1 text-red-400">{stats?.criticalCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-orange-400">High Risk</div>
            <div className="text-2xl font-semibold mt-1 text-orange-400">{stats?.highCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-yellow-400">Medium Risk</div>
            <div className="text-2xl font-semibold mt-1 text-yellow-400">{stats?.mediumCount ?? 0}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">Avg Risk Score</div>
            <div className={`text-2xl font-semibold mt-1 ${riskScoreColor(stats?.avgRiskScore ?? 0)}`}>
              {stats?.avgRiskScore ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="leaderboard" className="gap-1.5">
            <TrendingUp className="h-3.5 w-3.5" />
            Risk Leaderboard
          </TabsTrigger>
          <TabsTrigger value="anomalies" className="gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            Anomalies ({anomaliesData?.anomalies?.length ?? 0})
          </TabsTrigger>
        </TabsList>

        {/* LEADERBOARD TAB */}
        <TabsContent value="leaderboard" className="mt-4 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search entity name..."
                className="pl-9 bg-zinc-900/50 border-zinc-800"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={entityTypeFilter} onValueChange={setEntityTypeFilter}>
              <SelectTrigger className="w-[130px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Entity Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="user">Users</SelectItem>
                <SelectItem value="host">Hosts</SelectItem>
              </SelectContent>
            </Select>
            <Select value={riskLevelFilter} onValueChange={setRiskLevelFilter}>
              <SelectTrigger className="w-[130px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Levels</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground w-12">#</TableHead>
                    <TableHead className="text-muted-foreground">Entity</TableHead>
                    <TableHead className="text-muted-foreground">Type</TableHead>
                    <TableHead className="text-muted-foreground">Risk Score</TableHead>
                    <TableHead className="text-muted-foreground">Risk Level</TableHead>
                    <TableHead className="text-muted-foreground">Anomalies</TableHead>
                    <TableHead className="text-muted-foreground">Last Anomaly</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entitiesLoading ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                        Loading entities...
                      </TableCell>
                    </TableRow>
                  ) : !entitiesData?.entities?.length ? (
                    <TableRow>
                      <TableCell colSpan={8}>
                        <EmptyState
                          icon={Users}
                          title="No entities tracked yet"
                          description="UEBA requires entity behavior data from connectors like CrowdStrike, Okta, or Microsoft Defender to build behavioral baselines."
                          action={{
                            label: "Connect a Data Source",
                            icon: Plug,
                            onClick: () => navigate("/connectors"),
                          }}
                          secondaryAction={{
                            label: "Run Analysis",
                            icon: Play,
                            onClick: () => analyzeMutation.mutate(),
                            variant: "outline",
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    entitiesData.entities.map((entity, idx) => (
                      <TableRow
                        key={entity.id}
                        className="border-zinc-800 cursor-pointer hover:bg-zinc-800/50"
                        onClick={() => setSelectedEntity(entity)}
                      >
                        <TableCell className="text-muted-foreground font-mono">{idx + 1}</TableCell>
                        <TableCell className="font-medium">{entity.entityName || entity.entityId}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-zinc-800 border-zinc-700">
                            {entity.entityType}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2 w-32">
                            <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${riskBarColor(entity.riskScore)}`}
                                style={{ width: `${entity.riskScore}%` }}
                              />
                            </div>
                            <span className={`text-sm font-semibold ${riskScoreColor(entity.riskScore)}`}>
                              {entity.riskScore}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={riskColors[entity.riskLevel] || ""}>
                            {entity.riskLevel}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium">{entity.anomalyCount}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {entity.lastAnomalyAt ? new Date(entity.lastAnomalyAt).toLocaleString() : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 text-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedEntity(entity);
                            }}
                          >
                            <Eye className="h-3 w-3 mr-1" />
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ANOMALIES TAB */}
        <TabsContent value="anomalies" className="mt-4 space-y-4">
          <div className="flex items-center gap-3">
            <Select value={anomalyTypeFilter} onValueChange={setAnomalyTypeFilter}>
              <SelectTrigger className="w-[180px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Anomaly Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {Object.entries(anomalyTypeLabels).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-muted-foreground">Entity</TableHead>
                    <TableHead className="text-muted-foreground">Type</TableHead>
                    <TableHead className="text-muted-foreground">Anomaly</TableHead>
                    <TableHead className="text-muted-foreground">Risk</TableHead>
                    <TableHead className="text-muted-foreground">Description</TableHead>
                    <TableHead className="text-muted-foreground">Detected</TableHead>
                    <TableHead className="text-muted-foreground text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {anomaliesLoading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                        Loading anomalies...
                      </TableCell>
                    </TableRow>
                  ) : !anomaliesData?.anomalies?.length ? (
                    <TableRow>
                      <TableCell colSpan={7}>
                        <EmptyState
                          icon={Activity}
                          title="No anomalies detected"
                          description="Anomalies appear when UEBA detects behavior that deviates from established baselines. Connect identity or endpoint data sources to start."
                          action={{
                            label: "Connect a Data Source",
                            icon: Plug,
                            onClick: () => navigate("/connectors"),
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    anomaliesData.anomalies.map((a) => (
                      <TableRow key={a.id} className={`border-zinc-800 ${a.dismissed ? "opacity-50" : ""}`}>
                        <TableCell className="font-medium">{a.entityName || a.entityId}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-zinc-800 border-zinc-700">
                            {a.entityType}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              a.severity === "critical" || a.severity === "high"
                                ? "bg-red-500/20 text-red-400 border-red-500/30"
                                : "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                            }
                          >
                            {anomalyTypeLabels[a.anomalyType] || a.anomalyType}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className={`font-semibold ${riskScoreColor(a.riskScore)}`}>{a.riskScore}</span>
                        </TableCell>
                        <TableCell className="max-w-xs truncate text-sm text-muted-foreground">
                          {a.description || "—"}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(a.createdAt).toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right">
                          {!a.dismissed && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-xs"
                              onClick={() => dismissMutation.mutate(a.id)}
                            >
                              <XCircle className="h-3 w-3 mr-1" />
                              Dismiss
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Entity Detail Dialog */}
      <Dialog open={!!selectedEntity} onOpenChange={() => setSelectedEntity(null)}>
        <DialogContent className="bg-zinc-950 border-zinc-800 max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserCheck className="h-5 w-5 text-teal-400" />
              {selectedEntity?.entityName || selectedEntity?.entityId}
              <Badge variant="outline" className="bg-zinc-800 border-zinc-700 ml-2">
                {selectedEntity?.entityType}
              </Badge>
            </DialogTitle>
          </DialogHeader>
          {selectedEntity && (
            <div className="space-y-4">
              {/* Risk Score Bar */}
              <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-muted-foreground">Risk Score</span>
                  <span className={`text-2xl font-bold ${riskScoreColor(selectedEntity.riskScore)}`}>
                    {selectedEntity.riskScore}/100
                  </span>
                </div>
                <div className="h-3 bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${riskBarColor(selectedEntity.riskScore)}`}
                    style={{ width: `${selectedEntity.riskScore}%` }}
                  />
                </div>
                <div className="flex justify-between mt-2 text-xs text-muted-foreground">
                  <span>Low</span>
                  <span>Medium</span>
                  <span>High</span>
                  <span>Critical</span>
                </div>
              </div>

              {/* Baseline */}
              {entityDetail?.baseline && (
                <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
                  <h3 className="text-sm font-medium mb-3">Baseline Profile</h3>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <span className="text-muted-foreground">Login Hours</span>
                      <p className="font-medium">
                        {entityDetail.baseline.normalLoginHoursStart ?? 8}:00 -{" "}
                        {entityDetail.baseline.normalLoginHoursEnd ?? 20}:00 UTC
                      </p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Avg Daily Events</span>
                      <p className="font-medium">{entityDetail.baseline.avgDailyEventVolume?.toFixed(0) ?? 0}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Known IPs</span>
                      <p className="font-medium">{entityDetail.baseline.knownSourceIps?.length ?? 0}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Allowed Processes</span>
                      <p className="font-medium">{entityDetail.baseline.processAllowList?.length ?? 0}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Anomaly History */}
              <div>
                <h3 className="text-sm font-medium mb-3">Anomaly History ({entityDetail?.anomalies?.length ?? 0})</h3>
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {entityDetail?.anomalies?.length ? (
                    entityDetail.anomalies.map((a) => (
                      <div
                        key={a.id}
                        className={`bg-zinc-900 border border-zinc-800 rounded-lg p-3 ${a.dismissed ? "opacity-50" : ""}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={riskColors[a.severity] || ""}>
                              {anomalyTypeLabels[a.anomalyType] || a.anomalyType}
                            </Badge>
                            <span className={`text-sm font-semibold ${riskScoreColor(a.riskScore)}`}>
                              +{a.riskScore}
                            </span>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(a.createdAt).toLocaleString()}
                          </span>
                        </div>
                        {a.description && <p className="text-sm text-muted-foreground mt-1">{a.description}</p>}
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground text-center py-4">
                      No anomalies recorded for this entity
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
