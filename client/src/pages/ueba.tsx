import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  Users,
  Server,
  Activity,
  AlertTriangle,
  TrendingUp,
  Eye,
  RefreshCw,
  Shield,
  Zap,
  Brain,
  Clock,
  MapPin,
  Monitor,
  CheckCircle2,
  BarChart3,
  UserCheck,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface UebaEntity {
  entityType: string;
  entityId: string;
  riskScore: number;
  lastRiskReason?: string;
  eventCount: number;
  anomalyCount?: number;
  lastComputedAt?: string;
  avgDailyEvents: number;
}

interface UebaAnomaly {
  id: string;
  entityType: string;
  entityId: string;
  anomalyType: string;
  severity: string;
  score: number;
  description?: string;
  evidence: Record<string, unknown>;
  status: string;
  detectedAt: string;
}

interface UebaStats {
  totalEntities: number;
  riskyEntities: number;
  openAnomalies: number;
  topRiskyUsers: UebaEntity[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskColor(score: number) {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-emerald-400";
}

function riskBg(score: number) {
  if (score >= 80) return "bg-red-500/20";
  if (score >= 60) return "bg-orange-500/20";
  if (score >= 40) return "bg-yellow-500/20";
  return "bg-emerald-500/10";
}

const ANOMALY_ICONS: Record<string, React.ReactNode> = {
  unusual_login_time: <Clock className="h-4 w-4 text-orange-400" />,
  unusual_login_location: <MapPin className="h-4 w-4 text-red-400" />,
  excessive_auth_failures: <AlertTriangle className="h-4 w-4 text-red-400" />,
  new_process_execution: <Monitor className="h-4 w-4 text-orange-400" />,
  lateral_movement_pattern: <Activity className="h-4 w-4 text-red-500" />,
  data_staging_pattern: <TrendingUp className="h-4 w-4 text-orange-400" />,
  privilege_abuse: <Shield className="h-4 w-4 text-red-400" />,
  off_hours_activity: <Clock className="h-4 w-4 text-yellow-400" />,
  new_network_peer: <Server className="h-4 w-4 text-orange-400" />,
  volume_anomaly: <BarChart3 className="h-4 w-4 text-yellow-400" />,
};

const ANOMALY_LABELS: Record<string, string> = {
  unusual_login_time: "Unusual Login Time",
  unusual_login_location: "Unusual Login Location",
  excessive_auth_failures: "Excessive Auth Failures",
  new_process_execution: "New Suspicious Process",
  lateral_movement_pattern: "Lateral Movement",
  data_staging_pattern: "Data Staging",
  privilege_abuse: "Privilege Abuse",
  off_hours_activity: "Off-Hours Activity",
  new_network_peer: "New Network Peer",
  volume_anomaly: "Volume Anomaly",
};

function formatRelative(ts?: string) {
  if (!ts) return "never";
  const d = Date.now() - new Date(ts).getTime();
  if (d < 60_000) return "just now";
  if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`;
  if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`;
  return `${Math.floor(d / 86_400_000)}d ago`;
}

// ─── Entity Card ──────────────────────────────────────────────────────────────

function EntityCard({ entity }: { entity: UebaEntity }) {
  return (
    <div className="flex items-center gap-4 p-4 rounded-lg bg-slate-800/40 border border-slate-700/50 hover:border-slate-600/70 transition-colors">
      <div className={`h-10 w-10 rounded-full flex items-center justify-center shrink-0 ${riskBg(entity.riskScore)}`}>
        {entity.entityType === "user" ? (
          <Users className={`h-5 w-5 ${riskColor(entity.riskScore)}`} />
        ) : (
          <Server className={`h-5 w-5 ${riskColor(entity.riskScore)}`} />
        )}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-white text-sm">{entity.entityId}</span>
          <Badge variant="outline" className="text-xs px-1.5 py-0 border-slate-600 text-slate-500 capitalize">
            {entity.entityType}
          </Badge>
        </div>
        {entity.lastRiskReason && (
          <p className="text-xs text-slate-500 truncate mt-0.5">{entity.lastRiskReason}</p>
        )}
        <p className="text-xs text-slate-600">
          {entity.eventCount.toLocaleString()} events · updated {formatRelative(entity.lastComputedAt)}
        </p>
      </div>

      {/* Risk score gauge */}
      <div className="text-center shrink-0">
        <div className={`text-2xl font-bold ${riskColor(entity.riskScore)}`}>
          {Math.round(entity.riskScore)}
        </div>
        <div className="text-xs text-slate-500">risk</div>
      </div>

      <div className="w-24">
        <Progress
          value={entity.riskScore}
          className="h-1.5 bg-slate-700"
        />
      </div>
    </div>
  );
}

// ─── Anomaly Row ──────────────────────────────────────────────────────────────

function AnomalyRow({ anomaly, onResolve }: { anomaly: UebaAnomaly; onResolve: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const sev = anomaly.severity;
  const sevColor =
    sev === "critical" ? "text-red-400" : sev === "high" ? "text-orange-400" : "text-yellow-400";
  const sevBg =
    sev === "critical"
      ? "bg-red-500/10 border-red-500/20"
      : sev === "high"
      ? "bg-orange-500/10 border-orange-500/20"
      : "bg-yellow-500/10 border-yellow-500/20";

  return (
    <div className={`rounded-lg border ${anomaly.status === "open" ? "border-slate-700/50 bg-slate-800/40" : "border-slate-700/20 bg-slate-900/30 opacity-60"}`}>
      <div className="flex items-center gap-4 p-4 cursor-pointer" onClick={() => setExpanded((v) => !v)}>
        <div className="shrink-0">
          {ANOMALY_ICONS[anomaly.anomalyType] ?? <Activity className="h-4 w-4 text-slate-400" />}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-white">
              {ANOMALY_LABELS[anomaly.anomalyType] ?? anomaly.anomalyType}
            </span>
            <Badge variant="outline" className={`text-xs px-1.5 py-0 ${sevBg} ${sevColor}`}>
              {sev}
            </Badge>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500 mt-0.5">
            <span className="capitalize">{anomaly.entityType}:</span>
            <span className="text-slate-400">{anomaly.entityId}</span>
            <span>·</span>
            <span>{formatRelative(anomaly.detectedAt)}</span>
          </div>
        </div>

        {/* Anomaly score */}
        <div className="text-center text-xs shrink-0">
          <div className={`text-lg font-bold ${sevColor}`}>{Math.round(anomaly.score)}</div>
          <div className="text-slate-500">score</div>
        </div>

        {anomaly.status === "open" && (
          <Button
            size="sm"
            variant="outline"
            className="h-6 text-xs border-slate-600 text-slate-400 hover:text-white px-2 shrink-0"
            onClick={(e) => { e.stopPropagation(); onResolve(anomaly.id); }}
          >
            Resolve
          </Button>
        )}
      </div>

      {expanded && anomaly.description && (
        <div className="px-4 pb-4 border-t border-slate-700/30 pt-3">
          <p className="text-sm text-slate-400">{anomaly.description}</p>
          {Object.keys(anomaly.evidence ?? {}).length > 0 && (
            <pre className="mt-2 text-xs text-slate-500 bg-slate-900 rounded p-2 overflow-x-auto">
              {JSON.stringify(anomaly.evidence, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function UebaPage() {
  const [tab, setTab] = useState("anomalies");
  const [filterSev, setFilterSev] = useState("all");
  const [filterEntity, setFilterEntity] = useState("all");
  const { toast } = useToast();

  const { data: statsData } = useQuery<{ data: UebaStats }>({
    queryKey: ["/api/ueba/stats"],
  });

  const { data: entitiesData, isLoading: entitiesLoading } = useQuery<{ data: UebaEntity[] }>({
    queryKey: ["/api/ueba/entities"],
  });

  const { data: anomaliesData, isLoading: anomaliesLoading } = useQuery<{ data: UebaAnomaly[] }>({
    queryKey: ["/api/ueba/anomalies", filterSev, filterEntity],
    queryFn: () => {
      const p = new URLSearchParams({ status: "open" });
      if (filterSev !== "all") p.set("severity", filterSev);
      if (filterEntity !== "all") p.set("entityType", filterEntity);
      return apiRequest("GET", `/api/ueba/anomalies?${p}`).then((r) => r.json());
    },
  });

  const computeMutation = useMutation({
    mutationFn: () =>
      apiRequest("POST", "/api/ueba/run-anomaly-detection").then((r) => r.json()),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/ueba/anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ueba/stats"] });
      toast({
        title: "Anomaly detection complete",
        description: `${data.detected ?? 0} anomalies found, ${data.alertsCreated ?? 0} alerts created.`,
      });
    },
    onError: () => toast({ title: "Detection failed", variant: "destructive" }),
  });

  const resolveMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest("PATCH", `/api/ueba/anomalies/${id}`, { status: "resolved" }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ueba/anomalies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ueba/stats"] });
    },
  });

  const stats = statsData?.data;
  const entities = entitiesData?.data ?? [];
  const anomalies = anomaliesData?.data ?? [];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Brain className="h-6 w-6 text-violet-400" />
            UEBA — Behavioral Analytics
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            User & entity risk scoring with anomaly detection. No Exabeam or Darktrace needed.
          </p>
        </div>
        <Button
          className="bg-violet-700 hover:bg-violet-600 text-white gap-2"
          onClick={() => computeMutation.mutate()}
          disabled={computeMutation.isPending}
        >
          {computeMutation.isPending ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <Zap className="h-4 w-4" />
          )}
          Run Detection
        </Button>
      </div>

      {/* USP banner */}
      <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { icon: <Users className="h-5 w-5 text-violet-400" />, title: "Behavioral Baselines", desc: "30-day rolling baseline per user/host: normal hours, IPs, processes, network peers" },
            { icon: <AlertTriangle className="h-5 w-5 text-orange-400" />, title: "Anomaly Detection", desc: "Off-hours logins, new geo locations, suspicious new processes, traffic volume spikes" },
            { icon: <TrendingUp className="h-5 w-5 text-cyan-400" />, title: "Risk Scoring", desc: "0–100 risk score per entity, updated on every anomaly. High-risk entities auto-escalated." },
          ].map((item) => (
            <div key={item.title} className="flex items-start gap-3">
              {item.icon}
              <div>
                <p className="text-sm font-medium text-white">{item.title}</p>
                <p className="text-xs text-slate-400">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Entities Tracked", value: stats?.totalEntities ?? 0, icon: <UserCheck className="h-5 w-5 text-cyan-400" />, color: "bg-cyan-500/10" },
          { label: "High Risk", value: stats?.riskyEntities ?? 0, icon: <AlertTriangle className="h-5 w-5 text-red-400" />, color: "bg-red-500/10" },
          { label: "Open Anomalies", value: stats?.openAnomalies ?? 0, icon: <Activity className="h-5 w-5 text-orange-400" />, color: "bg-orange-500/10" },
          { label: "Users Monitored", value: entities.filter((e) => e.entityType === "user").length, icon: <Users className="h-5 w-5 text-violet-400" />, color: "bg-violet-500/10" },
        ].map((s) => (
          <Card key={s.label} className="bg-slate-900/60 border-slate-700/50">
            <CardContent className="p-4 flex items-center gap-3">
              <div className={`p-2 rounded-lg ${s.color}`}>{s.icon}</div>
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wider">{s.label}</p>
                <p className="text-2xl font-bold text-white">{s.value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-slate-800 border-slate-700">
          <TabsTrigger value="anomalies" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Anomalies ({anomalies.length})
          </TabsTrigger>
          <TabsTrigger value="entities" className="data-[state=active]:bg-slate-700 text-slate-300 data-[state=active]:text-white">
            Entity Risk ({entities.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="anomalies" className="mt-4 space-y-4">
          <div className="flex items-center gap-3">
            <Select value={filterSev} onValueChange={setFilterSev}>
              <SelectTrigger className="w-36 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                <SelectItem value="all" className="text-slate-200">All severities</SelectItem>
                {["critical", "high", "medium"].map((s) => (
                  <SelectItem key={s} value={s} className="text-slate-200 capitalize">{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={filterEntity} onValueChange={setFilterEntity}>
              <SelectTrigger className="w-32 bg-slate-800 border-slate-600 text-slate-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-600">
                <SelectItem value="all" className="text-slate-200">All entities</SelectItem>
                <SelectItem value="user" className="text-slate-200">Users</SelectItem>
                <SelectItem value="host" className="text-slate-200">Hosts</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {anomaliesLoading ? (
            <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-lg" />)}</div>
          ) : anomalies.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <CheckCircle2 className="h-10 w-10 mx-auto mb-3 text-emerald-500 opacity-60" />
              <p>No open anomalies. Run detection to analyse recent activity.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {anomalies.map((a) => (
                <AnomalyRow key={a.id} anomaly={a} onResolve={(id) => resolveMutation.mutate(id)} />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="entities" className="mt-4 space-y-3">
          {entitiesLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-lg" />)}</div>
          ) : entities.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <Users className="h-10 w-10 mx-auto mb-3 opacity-40" />
              <p>No entities profiled yet. Baselines are built from sensor telemetry.</p>
            </div>
          ) : (
            [...entities]
              .sort((a, b) => b.riskScore - a.riskScore)
              .map((e) => <EntityCard key={`${e.entityType}-${e.entityId}`} entity={e} />)
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
