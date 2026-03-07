import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Eye,
  Search,
  FileText,
  GitBranch,
  Power,
  PowerOff,
  Zap,
  Target,
  TrendingUp,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Milestone,
  Layers,
  BarChart3,
  Users,
  Bot,
  Server,
  Settings,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface EvidenceRecord {
  id: string;
  orgId: string;
  traceId: string;
  sourceType: string;
  sourceEngine: string;
  sourceActionId: string;
  severity: string;
  summary: string;
  details: Record<string, unknown>;
  parentEvidenceId: string | null;
  chainDepth: number;
  actorId: string;
  actorType: string;
  timestamp: string;
  tags: string[];
}

interface HumanOverrideRequest {
  id: string;
  orgId: string;
  evidenceId: string;
  featureDomain: string;
  actionDescription: string;
  riskLevel: string;
  requestedBy: string;
  requestedAt: string;
  status: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  rationale: string | null;
  expiresAt: string;
  auditTrail: { action: string; actor: string; timestamp: string; detail: string }[];
}

interface DriftSignal {
  id: string;
  orgId: string;
  category: string;
  severity: string;
  sourceEngine: string;
  entity: string;
  expectedState: string;
  actualState: string;
  detectedAt: string;
  resolvedAt: string | null;
  delta: string[];
  acknowledgedBy: string | null;
}

interface KillSwitch {
  id: string;
  orgId: string;
  featureName: string;
  engineName: string;
  state: string;
  confidenceThreshold: number;
  currentConfidence: number;
  lastTriggeredAt: string | null;
  triggeredBy: string | null;
  triggerReason: string | null;
  rollbackInstructions: string;
  updatedAt: string;
  updatedBy: string;
}

interface TimeToValueMilestone {
  id: string;
  orgId: string;
  kind: string;
  label: string;
  achievedAt: string | null;
  durationFromSignupMs: number | null;
  triggeredByAction: string | null;
  triggeredByActor: string | null;
}

interface CrossCuttingStats {
  evidenceCount: number;
  evidenceBySource: Record<string, number>;
  pendingOverrides: number;
  approvedOverridesLast24h: number;
  rejectedOverridesLast24h: number;
  activeDriftSignals: number;
  driftByCategory: Record<string, number>;
  killSwitchesArmed: number;
  killSwitchesTriggered: number;
  milestonesAchieved: number;
  milestonesRemaining: number;
  avgConfidence: number;
}

function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "text-red-400 bg-red-500/10 border-red-500/30";
    case "high":
      return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "medium":
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "low":
      return "text-blue-400 bg-blue-500/10 border-blue-500/30";
    default:
      return "text-slate-400 bg-slate-500/10 border-slate-500/30";
  }
}

function statusBadge(status: string) {
  switch (status) {
    case "pending":
      return (
        <Badge variant="outline" className="text-yellow-400 border-yellow-500/30 bg-yellow-500/10">
          <Clock className="w-3 h-3 mr-1" />
          Pending
        </Badge>
      );
    case "approved":
      return (
        <Badge variant="outline" className="text-green-400 border-green-500/30 bg-green-500/10">
          <CheckCircle2 className="w-3 h-3 mr-1" />
          Approved
        </Badge>
      );
    case "rejected":
      return (
        <Badge variant="outline" className="text-red-400 border-red-500/30 bg-red-500/10">
          <XCircle className="w-3 h-3 mr-1" />
          Rejected
        </Badge>
      );
    case "expired":
      return (
        <Badge variant="outline" className="text-slate-400 border-slate-500/30 bg-slate-500/10">
          <Clock className="w-3 h-3 mr-1" />
          Expired
        </Badge>
      );
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function killSwitchBadge(state: string) {
  switch (state) {
    case "armed":
      return (
        <Badge variant="outline" className="text-green-400 border-green-500/30 bg-green-500/10">
          <Power className="w-3 h-3 mr-1" />
          Armed
        </Badge>
      );
    case "disarmed":
      return (
        <Badge variant="outline" className="text-slate-400 border-slate-500/30 bg-slate-500/10">
          <PowerOff className="w-3 h-3 mr-1" />
          Disarmed
        </Badge>
      );
    case "triggered":
      return (
        <Badge variant="outline" className="text-red-400 border-red-500/30 bg-red-500/10">
          <Zap className="w-3 h-3 mr-1" />
          Triggered
        </Badge>
      );
    default:
      return <Badge variant="outline">{state}</Badge>;
  }
}

function driftCategoryBadge(category: string) {
  const colors: Record<string, string> = {
    policy: "text-purple-400 border-purple-500/30 bg-purple-500/10",
    integration: "text-blue-400 border-blue-500/30 bg-blue-500/10",
    identity: "text-red-400 border-red-500/30 bg-red-500/10",
    control: "text-orange-400 border-orange-500/30 bg-orange-500/10",
    posture: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
    configuration: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
  };
  return (
    <Badge variant="outline" className={colors[category] ?? "text-slate-400"}>
      {category}
    </Badge>
  );
}

function sourceIcon(actorType: string) {
  switch (actorType) {
    case "user":
      return <Users className="w-4 h-4 text-cyan-400" />;
    case "agent":
      return <Bot className="w-4 h-4 text-purple-400" />;
    case "service":
      return <Server className="w-4 h-4 text-blue-400" />;
    default:
      return <Settings className="w-4 h-4 text-slate-400" />;
  }
}

function formatDuration(ms: number): string {
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  if (ms < 86400000) return `${(ms / 3600000).toFixed(1)}h`;
  return `${(ms / 86400000).toFixed(1)}d`;
}

function formatTimestamp(ts: string): string {
  return new Date(ts).toLocaleString();
}

function StatsOverview({ stats }: { stats: CrossCuttingStats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      <Card className="bg-slate-900/50 border-slate-700/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-1">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span className="text-xs text-slate-400">Evidence Records</span>
          </div>
          <p className="text-2xl font-bold text-white">{stats.evidenceCount}</p>
        </CardContent>
      </Card>
      <Card className="bg-slate-900/50 border-slate-700/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-1">
            <Clock className="w-4 h-4 text-yellow-400" />
            <span className="text-xs text-slate-400">Pending Approvals</span>
          </div>
          <p className="text-2xl font-bold text-yellow-400">{stats.pendingOverrides}</p>
        </CardContent>
      </Card>
      <Card className="bg-slate-900/50 border-slate-700/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <span className="text-xs text-slate-400">Active Drift</span>
          </div>
          <p className="text-2xl font-bold text-orange-400">{stats.activeDriftSignals}</p>
        </CardContent>
      </Card>
      <Card className="bg-slate-900/50 border-slate-700/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-4 h-4 text-green-400" />
            <span className="text-xs text-slate-400">Kill Switches Armed</span>
          </div>
          <p className="text-2xl font-bold text-green-400">{stats.killSwitchesArmed}</p>
        </CardContent>
      </Card>
      <Card className="bg-slate-900/50 border-slate-700/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-1">
            <Zap className="w-4 h-4 text-red-400" />
            <span className="text-xs text-slate-400">Kill Switches Triggered</span>
          </div>
          <p className="text-2xl font-bold text-red-400">{stats.killSwitchesTriggered}</p>
        </CardContent>
      </Card>
      <Card className="bg-slate-900/50 border-slate-700/50">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-1">
            <Target className="w-4 h-4 text-cyan-400" />
            <span className="text-xs text-slate-400">Avg Confidence</span>
          </div>
          <p className="text-2xl font-bold text-white">{(stats.avgConfidence * 100).toFixed(0)}%</p>
        </CardContent>
      </Card>
    </div>
  );
}

function EvidenceTab() {
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: evidence, isLoading } = useQuery<EvidenceRecord[]>({
    queryKey: ["/api/cross-cutting/evidence"],
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full bg-slate-800" />
        ))}
      </div>
    );

  const filtered = (evidence ?? []).filter(
    (e) =>
      !search ||
      e.summary.toLowerCase().includes(search.toLowerCase()) ||
      e.sourceEngine.toLowerCase().includes(search.toLowerCase()) ||
      e.tags.some((t) => t.toLowerCase().includes(search.toLowerCase())),
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <Input
            placeholder="Search evidence by summary, engine, or tag..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10 bg-slate-900/50 border-slate-700"
          />
        </div>
        <Badge variant="outline" className="text-slate-400">
          {filtered.length} records
        </Badge>
      </div>

      <div className="space-y-2">
        {filtered.length === 0 && (
          <Card className="bg-slate-900/50 border-slate-700/50">
            <CardContent className="p-8 text-center text-slate-400">
              <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No evidence records found</p>
            </CardContent>
          </Card>
        )}
        {filtered.map((e) => (
          <Card key={e.id} className="bg-slate-900/50 border-slate-700/50 hover:border-slate-600/50 transition-colors">
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3 flex-1 min-w-0">
                  {sourceIcon(e.actorType)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <Badge variant="outline" className={severityColor(e.severity)}>
                        {e.severity}
                      </Badge>
                      <Badge variant="outline" className="text-slate-400 border-slate-600">
                        {e.sourceEngine}
                      </Badge>
                      {e.chainDepth > 0 && (
                        <Badge variant="outline" className="text-purple-400 border-purple-500/30">
                          <GitBranch className="w-3 h-3 mr-1" />
                          chain depth {e.chainDepth}
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-white truncate">{e.summary}</p>
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                      <span>{formatTimestamp(e.timestamp)}</span>
                      <span>actor: {e.actorId}</span>
                      <span>trace: {e.traceId}</span>
                    </div>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setExpandedId(expandedId === e.id ? null : e.id)}
                  className="text-slate-400 hover:text-white"
                >
                  {expandedId === e.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </Button>
              </div>
              {expandedId === e.id && (
                <div className="mt-3 pt-3 border-t border-slate-700/50">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-slate-400">Source Action:</span>
                      <span className="ml-2 text-white">{e.sourceActionId}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Source Type:</span>
                      <span className="ml-2 text-white">{e.sourceType}</span>
                    </div>
                    {e.parentEvidenceId && (
                      <div className="col-span-2">
                        <span className="text-slate-400">Parent Evidence:</span>
                        <span className="ml-2 text-cyan-400">{e.parentEvidenceId}</span>
                      </div>
                    )}
                    <div className="col-span-2">
                      <span className="text-slate-400">Tags:</span>
                      <span className="ml-2">
                        {e.tags.map((t) => (
                          <Badge key={t} variant="outline" className="text-xs mr-1 text-slate-300">
                            {t}
                          </Badge>
                        ))}
                      </span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-slate-400">Details:</span>
                      <pre className="mt-1 p-2 bg-slate-950 rounded text-xs text-slate-300 overflow-x-auto">
                        {JSON.stringify(e.details, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function OverridesTab() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: overrides, isLoading } = useQuery<HumanOverrideRequest[]>({
    queryKey: ["/api/cross-cutting/overrides"],
  });

  const approveMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/cross-cutting/overrides/${id}/approve`, {
        reviewedBy: "current-user@securenexus.io",
        rationale: "Approved via cross-cutting dashboard",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/overrides"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/stats"] });
      toast({ title: "Override approved" });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/cross-cutting/overrides/${id}/reject`, {
        reviewedBy: "current-user@securenexus.io",
        rationale: "Rejected via cross-cutting dashboard",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/overrides"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/stats"] });
      toast({ title: "Override rejected" });
    },
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full bg-slate-800" />
        ))}
      </div>
    );

  const filtered = (overrides ?? []).filter((o) => statusFilter === "all" || o.status === statusFilter);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        {["all", "pending", "approved", "rejected", "expired"].map((s) => (
          <Button
            key={s}
            variant={statusFilter === s ? "default" : "outline"}
            size="sm"
            onClick={() => setStatusFilter(s)}
            className={statusFilter === s ? "bg-cyan-600 hover:bg-cyan-700" : "border-slate-700 text-slate-400"}
          >
            {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
          </Button>
        ))}
        <Badge variant="outline" className="ml-auto text-slate-400">
          {filtered.length} overrides
        </Badge>
      </div>

      <div className="space-y-2">
        {filtered.length === 0 && (
          <Card className="bg-slate-900/50 border-slate-700/50">
            <CardContent className="p-8 text-center text-slate-400">
              <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No override requests found</p>
            </CardContent>
          </Card>
        )}
        {filtered.map((o) => (
          <Card key={o.id} className="bg-slate-900/50 border-slate-700/50">
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    {statusBadge(o.status)}
                    <Badge variant="outline" className={severityColor(o.riskLevel)}>
                      {o.riskLevel} risk
                    </Badge>
                    <Badge variant="outline" className="text-slate-400 border-slate-600">
                      {o.featureDomain}
                    </Badge>
                  </div>
                  <p className="text-sm text-white">{o.actionDescription}</p>
                  <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                    <span>By: {o.requestedBy}</span>
                    <span>{formatTimestamp(o.requestedAt)}</span>
                    <span>Expires: {formatTimestamp(o.expiresAt)}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {o.status === "pending" && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => approveMutation.mutate(o.id)}
                        disabled={approveMutation.isPending}
                        className="border-green-500/30 text-green-400 hover:bg-green-500/10"
                      >
                        <CheckCircle2 className="w-3 h-3 mr-1" />
                        Approve
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => rejectMutation.mutate(o.id)}
                        disabled={rejectMutation.isPending}
                        className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                      >
                        <XCircle className="w-3 h-3 mr-1" />
                        Reject
                      </Button>
                    </>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setExpandedId(expandedId === o.id ? null : o.id)}
                    className="text-slate-400"
                  >
                    {expandedId === o.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </Button>
                </div>
              </div>
              {expandedId === o.id && (
                <div className="mt-3 pt-3 border-t border-slate-700/50 space-y-3">
                  {o.reviewedBy && (
                    <div className="text-sm">
                      <span className="text-slate-400">Reviewed by:</span>
                      <span className="ml-2 text-white">{o.reviewedBy}</span>
                      {o.reviewedAt && <span className="ml-2 text-slate-500">at {formatTimestamp(o.reviewedAt)}</span>}
                    </div>
                  )}
                  {o.rationale && (
                    <div className="text-sm">
                      <span className="text-slate-400">Rationale:</span>
                      <p className="mt-1 text-white bg-slate-950 rounded p-2">{o.rationale}</p>
                    </div>
                  )}
                  <div>
                    <span className="text-sm text-slate-400">Audit Trail:</span>
                    <div className="mt-1 space-y-1">
                      {o.auditTrail.map((entry, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 text-xs text-slate-400 pl-2 border-l border-slate-700"
                        >
                          <span className="text-slate-500">{formatTimestamp(entry.timestamp)}</span>
                          <Badge variant="outline" className="text-xs">
                            {entry.action}
                          </Badge>
                          <span>{entry.actor}</span>
                          <span className="text-slate-500">— {entry.detail}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function DriftTab() {
  const [activeOnly, setActiveOnly] = useState(true);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: drift, isLoading } = useQuery<DriftSignal[]>({
    queryKey: ["/api/cross-cutting/drift", activeOnly ? "active=true" : ""],
  });

  const scanMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/cross-cutting/drift/scan");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/drift"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/stats"] });
      toast({ title: "Drift scan complete" });
    },
  });

  const acknowledgeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/cross-cutting/drift/${id}/acknowledge`, {
        acknowledgedBy: "current-user@securenexus.io",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/drift"] });
      toast({ title: "Drift acknowledged" });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/cross-cutting/drift/${id}/resolve`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/drift"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/stats"] });
      toast({ title: "Drift resolved" });
    },
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full bg-slate-800" />
        ))}
      </div>
    );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button
          variant={activeOnly ? "default" : "outline"}
          size="sm"
          onClick={() => setActiveOnly(true)}
          className={activeOnly ? "bg-cyan-600 hover:bg-cyan-700" : "border-slate-700 text-slate-400"}
        >
          Active Only
        </Button>
        <Button
          variant={!activeOnly ? "default" : "outline"}
          size="sm"
          onClick={() => setActiveOnly(false)}
          className={!activeOnly ? "bg-cyan-600 hover:bg-cyan-700" : "border-slate-700 text-slate-400"}
        >
          All Signals
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => scanMutation.mutate()}
          disabled={scanMutation.isPending}
          className="ml-auto border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
        >
          <RefreshCw className={`w-3 h-3 mr-1 ${scanMutation.isPending ? "animate-spin" : ""}`} />
          Run Drift Scan
        </Button>
      </div>

      <div className="space-y-2">
        {(drift ?? []).length === 0 && (
          <Card className="bg-slate-900/50 border-slate-700/50">
            <CardContent className="p-8 text-center text-slate-400">
              <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No drift signals detected</p>
            </CardContent>
          </Card>
        )}
        {(drift ?? []).map((d) => (
          <Card key={d.id} className="bg-slate-900/50 border-slate-700/50">
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <Badge variant="outline" className={severityColor(d.severity)}>
                      {d.severity}
                    </Badge>
                    {driftCategoryBadge(d.category)}
                    <Badge variant="outline" className="text-slate-400 border-slate-600">
                      {d.sourceEngine}
                    </Badge>
                    {d.resolvedAt && (
                      <Badge variant="outline" className="text-green-400 border-green-500/30 bg-green-500/10">
                        Resolved
                      </Badge>
                    )}
                    {d.acknowledgedBy && !d.resolvedAt && (
                      <Badge variant="outline" className="text-blue-400 border-blue-500/30 bg-blue-500/10">
                        <Eye className="w-3 h-3 mr-1" />
                        Acknowledged
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-white font-medium">{d.entity}</p>
                  <div className="mt-2 space-y-1">
                    <div className="text-xs">
                      <span className="text-slate-400">Expected:</span>
                      <span className="ml-2 text-green-400">{d.expectedState}</span>
                    </div>
                    <div className="text-xs">
                      <span className="text-slate-400">Actual:</span>
                      <span className="ml-2 text-red-400">{d.actualState}</span>
                    </div>
                    {d.delta.length > 0 && (
                      <div className="text-xs mt-1">
                        <span className="text-slate-400">Delta:</span>
                        {d.delta.map((change, i) => (
                          <Badge
                            key={i}
                            variant="outline"
                            className="ml-1 text-xs text-orange-400 border-orange-500/30"
                          >
                            {change}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-2 text-xs text-slate-500">
                    <span>Detected: {formatTimestamp(d.detectedAt)}</span>
                    {d.resolvedAt && <span>Resolved: {formatTimestamp(d.resolvedAt)}</span>}
                  </div>
                </div>
                {!d.resolvedAt && (
                  <div className="flex items-center gap-2">
                    {!d.acknowledgedBy && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => acknowledgeMutation.mutate(d.id)}
                        disabled={acknowledgeMutation.isPending}
                        className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                      >
                        <Eye className="w-3 h-3 mr-1" />
                        Ack
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => resolveMutation.mutate(d.id)}
                      disabled={resolveMutation.isPending}
                      className="border-green-500/30 text-green-400 hover:bg-green-500/10"
                    >
                      <CheckCircle2 className="w-3 h-3 mr-1" />
                      Resolve
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function ReliabilityTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: killSwitches, isLoading } = useQuery<KillSwitch[]>({
    queryKey: ["/api/cross-cutting/reliability"],
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, state }: { id: string; state: string }) => {
      await apiRequest("PATCH", `/api/cross-cutting/reliability/${id}`, {
        state,
        actor: "current-user@securenexus.io",
        reason: `Manually ${state} via dashboard`,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/reliability"] });
      queryClient.invalidateQueries({ queryKey: ["/api/cross-cutting/stats"] });
      toast({ title: "Kill switch updated" });
    },
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full bg-slate-800" />
        ))}
      </div>
    );

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {(killSwitches ?? []).length === 0 && (
          <Card className="bg-slate-900/50 border-slate-700/50 col-span-2">
            <CardContent className="p-8 text-center text-slate-400">
              <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No kill switches configured</p>
            </CardContent>
          </Card>
        )}
        {(killSwitches ?? []).map((ks) => {
          const confidencePct = Math.round(ks.currentConfidence * 100);
          const thresholdPct = Math.round(ks.confidenceThreshold * 100);
          const belowThreshold = ks.currentConfidence < ks.confidenceThreshold;

          return (
            <Card key={ks.id} className="bg-slate-900/50 border-slate-700/50">
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      {killSwitchBadge(ks.state)}
                      <span className="text-sm font-medium text-white">{ks.featureName}</span>
                    </div>
                    <p className="text-xs text-slate-400">{ks.engineName}</p>
                  </div>
                  <div className="flex gap-1">
                    {ks.state !== "armed" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleMutation.mutate({ id: ks.id, state: "armed" })}
                        disabled={toggleMutation.isPending}
                        className="border-green-500/30 text-green-400 hover:bg-green-500/10 text-xs"
                      >
                        Arm
                      </Button>
                    )}
                    {ks.state === "armed" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleMutation.mutate({ id: ks.id, state: "triggered" })}
                        disabled={toggleMutation.isPending}
                        className="border-red-500/30 text-red-400 hover:bg-red-500/10 text-xs"
                      >
                        Trigger
                      </Button>
                    )}
                    {ks.state !== "disarmed" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleMutation.mutate({ id: ks.id, state: "disarmed" })}
                        disabled={toggleMutation.isPending}
                        className="border-slate-500/30 text-slate-400 hover:bg-slate-500/10 text-xs"
                      >
                        Disarm
                      </Button>
                    )}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Confidence</span>
                    <span className={belowThreshold ? "text-red-400" : "text-green-400"}>
                      {confidencePct}% / {thresholdPct}% threshold
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${belowThreshold ? "bg-red-500" : "bg-green-500"}`}
                      style={{ width: `${confidencePct}%` }}
                    />
                  </div>
                </div>

                {ks.lastTriggeredAt && (
                  <div className="mt-2 text-xs text-slate-500">
                    Last triggered: {formatTimestamp(ks.lastTriggeredAt)}
                    {ks.triggerReason && <span className="ml-1">— {ks.triggerReason}</span>}
                  </div>
                )}

                <div className="mt-2 p-2 bg-slate-950 rounded text-xs text-slate-400">
                  <span className="text-slate-500">Rollback:</span> {ks.rollbackInstructions}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function TimeToValueTab() {
  const { data: milestones, isLoading } = useQuery<TimeToValueMilestone[]>({
    queryKey: ["/api/cross-cutting/time-to-value"],
  });

  if (isLoading)
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full bg-slate-800" />
        ))}
      </div>
    );

  const achieved = (milestones ?? []).filter((m) => m.achievedAt !== null);
  const remaining = (milestones ?? []).filter((m) => m.achievedAt === null);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Milestone className="w-5 h-5 text-cyan-400" />
        <span className="text-white font-medium">Onboarding Milestones</span>
        <Badge variant="outline" className="text-green-400 border-green-500/30 bg-green-500/10">
          {achieved.length} achieved
        </Badge>
        <Badge variant="outline" className="text-slate-400 border-slate-600">
          {remaining.length} remaining
        </Badge>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {(milestones ?? []).map((m) => (
          <Card
            key={m.id}
            className={`border ${m.achievedAt ? "bg-green-950/20 border-green-500/20" : "bg-slate-900/50 border-slate-700/50"}`}
          >
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <div className={`mt-0.5 p-1.5 rounded-full ${m.achievedAt ? "bg-green-500/20" : "bg-slate-700/50"}`}>
                  {m.achievedAt ? (
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                  ) : (
                    <Clock className="w-4 h-4 text-slate-500" />
                  )}
                </div>
                <div className="flex-1">
                  <p className={`text-sm font-medium ${m.achievedAt ? "text-green-400" : "text-slate-300"}`}>
                    {m.label}
                  </p>
                  {m.achievedAt && (
                    <div className="mt-1 space-y-0.5">
                      <div className="flex items-center gap-2 text-xs text-slate-400">
                        <TrendingUp className="w-3 h-3" />
                        {m.durationFromSignupMs !== null && (
                          <span>Achieved in {formatDuration(m.durationFromSignupMs)}</span>
                        )}
                      </div>
                      <div className="text-xs text-slate-500">
                        {formatTimestamp(m.achievedAt)} by {m.triggeredByActor}
                      </div>
                    </div>
                  )}
                  {!m.achievedAt && <p className="mt-1 text-xs text-slate-500">Not yet achieved</p>}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

export default function CrossCuttingPage() {
  const { data: stats, isLoading: statsLoading } = useQuery<CrossCuttingStats>({
    queryKey: ["/api/cross-cutting/stats"],
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Layers className="w-6 h-6 text-cyan-400" />
            Cross-Cutting Controls
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Evidence traceability, human oversight, drift detection, reliability controls, and time-to-value tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-cyan-400 border-cyan-500/30 bg-cyan-500/10">
            <BarChart3 className="w-3 h-3 mr-1" />5 Principles
          </Badge>
        </div>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-20 bg-slate-800" />
          ))}
        </div>
      ) : stats ? (
        <StatsOverview stats={stats} />
      ) : null}

      <Tabs defaultValue="evidence" className="w-full">
        <TabsList className="bg-slate-900/50 border border-slate-700/50 p-1">
          <TabsTrigger
            value="evidence"
            className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white gap-1"
          >
            <FileText className="w-4 h-4" />
            Evidence
          </TabsTrigger>
          <TabsTrigger
            value="overrides"
            className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white gap-1"
          >
            <ShieldAlert className="w-4 h-4" />
            Human Override
          </TabsTrigger>
          <TabsTrigger value="drift" className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white gap-1">
            <Activity className="w-4 h-4" />
            Drift Detection
          </TabsTrigger>
          <TabsTrigger
            value="reliability"
            className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white gap-1"
          >
            <Shield className="w-4 h-4" />
            Reliability
          </TabsTrigger>
          <TabsTrigger value="ttv" className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white gap-1">
            <Target className="w-4 h-4" />
            Time-to-Value
          </TabsTrigger>
        </TabsList>

        <TabsContent value="evidence" className="mt-4">
          <EvidenceTab />
        </TabsContent>
        <TabsContent value="overrides" className="mt-4">
          <OverridesTab />
        </TabsContent>
        <TabsContent value="drift" className="mt-4">
          <DriftTab />
        </TabsContent>
        <TabsContent value="reliability" className="mt-4">
          <ReliabilityTab />
        </TabsContent>
        <TabsContent value="ttv" className="mt-4">
          <TimeToValueTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
