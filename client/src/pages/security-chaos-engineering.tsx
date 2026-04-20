import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  Activity,
  Search,
  Play,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Target,
  BarChart3,
  Calendar,
  Zap,
  Eye,
  ShieldAlert,
  Crosshair,
  Layers,
  Minus,
  Plus,
  ShieldCheck,
  Lock,
  ArrowRight,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
import { DashboardSkeleton } from "@/components/page-skeleton";

// ── API helpers ───────────────────────────────────────────────────────────────

async function apiFetch(url: string, options?: RequestInit) {
  const csrfToken = document.cookie
    .split("; ")
    .find((c) => c.startsWith("XSRF-TOKEN="))
    ?.split("=")[1];

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(csrfToken ? { "x-csrf-token": decodeURIComponent(csrfToken) } : {}),
  };

  const res = await fetch(url, {
    ...options,
    headers: { ...((options?.headers as Record<string, string>) || {}), ...headers },
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(body.message || res.statusText);
  }
  return res.json();
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface MitreTechnique {
  id: string;
  tacticId: string;
  tacticName: string;
  name: string;
  description: string;
  platform: string[];
  severity: string;
  simulationPayload: string;
  expectedDetection: string;
  controlMappings: string[];
}

interface SimulationResult {
  id: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  platform: string;
  severity: string;
  status: string;
  verdict: string;
  durationMs: number;
  output: string;
  controlsTested: string[];
  trigger: string;
  executedBy: string;
  executedAt: string;
}

interface ControlScore {
  controlName: string;
  controlType: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  effectivenessScore: number;
  mitreIds: string[];
  status: string;
  lastTestedAt: string | null;
  trend: string;
}

interface GapEntry {
  techniqueId: string;
  tacticId: string;
  tacticName: string;
  techniqueName: string;
  coverageStatus: string;
  detectionRuleCount: number;
  lastSimulatedAt: string | null;
  recommendation: string;
  priority: string;
}

interface ValidationSchedule {
  id: string;
  name: string;
  description: string;
  frequency: string;
  techniqueIds: string[];
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string;
  totalRuns: number;
  lastScore: number | null;
  previousScore: number | null;
  regressionDetected: boolean;
  createdAt: string;
}

interface PurpleTeamScenario {
  id: string;
  name: string;
  description: string;
  attackScenario: string;
  mitreChain: string[];
  redTeamActions: string;
  blueTeamExpected: string;
}

interface PurpleTeamResult {
  id: string;
  scenarioId: string;
  scenarioName: string;
  attackScenario: string;
  mitreChain: string[];
  status: string;
  overallVerdict: string | null;
  detectionRate: number;
  detectionTimeMs: number | null;
  responseTimeMs: number | null;
  containmentTimeMs: number | null;
  stepsCompleted: number;
  totalSteps: number;
  gapsIdentified: string[];
  improvements: string[];
  executedAt: string | null;
  createdAt: string;
}

interface ChaosStats {
  totalTechniques: number;
  simulatedTechniques: number;
  coveragePercent: number;
  totalSimulations: number;
  passedSimulations: number;
  failedSimulations: number;
  bypassRate: number;
  avgControlEffectiveness: number;
  criticalGaps: number;
  highGaps: number;
  scheduledValidations: number;
  lastValidationAt: string | null;
  regressionsDetected: number;
  purpleTeamExercises: number;
  byTactic: Record<string, { total: number; passed: number; failed: number; coverage: number }>;
  topFailingControls: Array<{ name: string; failRate: number }>;
}

type HeatmapData = Record<string, Record<string, { coverage: string; tested: boolean; passed: boolean }>>;

interface MitreTactic {
  id: string;
  name: string;
  description: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(d: string | null): string {
  if (!d) return "\u2014";
  return new Date(d).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return "\u2014";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function severityBadge(s: string): string {
  switch (s) {
    case "critical":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "high":
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "low":
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    default:
      return "bg-slate-500/20 text-slate-400 border-slate-500/30";
  }
}

function verdictBadge(v: string): string {
  switch (v) {
    case "blocked":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    case "detected":
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "bypassed":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    default:
      return "bg-slate-500/20 text-slate-400 border-slate-500/30";
  }
}

function statusBadge(s: string): string {
  switch (s) {
    case "passed":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    case "failed":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "running":
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    default:
      return "bg-slate-500/20 text-slate-400 border-slate-500/30";
  }
}

function coverageBg(coverage: string): string {
  switch (coverage) {
    case "full":
      return "bg-green-500";
    case "partial":
      return "bg-yellow-500";
    case "none":
      return "bg-red-500/60";
    default:
      return "bg-slate-700";
  }
}

// ── BAS Dashboard Tab ─────────────────────────────────────────────────────────

function BASDashboardTab() {
  const { data: stats, isLoading: statsLoading } = useQuery<ChaosStats>({
    queryKey: ["/api/chaos-engineering/stats"],
    queryFn: () => apiFetch("/api/chaos-engineering/stats"),
  });

  const { data: heatmap, isLoading: heatmapLoading } = useQuery<HeatmapData>({
    queryKey: ["/api/chaos-engineering/heatmap"],
    queryFn: () => apiFetch("/api/chaos-engineering/heatmap"),
  });

  if (statsLoading || heatmapLoading) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading BAS dashboard...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Target className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.coveragePercent ?? 0}%</p>
                <p className="text-xs text-muted-foreground">ATT&CK Coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Shield className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.avgControlEffectiveness ?? 0}%</p>
                <p className="text-xs text-muted-foreground">Avg Control Effectiveness</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <AlertTriangle className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.bypassRate ?? 0}%</p>
                <p className="text-xs text-muted-foreground">Bypass Rate</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <ShieldAlert className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{(stats?.criticalGaps ?? 0) + (stats?.highGaps ?? 0)}</p>
                <p className="text-xs text-muted-foreground">Critical + High Gaps</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Simulation Summary + Regressions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Zap className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.totalSimulations ?? 0}</p>
                <p className="text-xs text-muted-foreground">Total Simulations Run</p>
              </div>
            </div>
            <div className="mt-3 flex gap-4 text-xs">
              <span className="text-green-400">{stats?.passedSimulations ?? 0} passed</span>
              <span className="text-red-400">{stats?.failedSimulations ?? 0} failed</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <Calendar className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.scheduledValidations ?? 0}</p>
                <p className="text-xs text-muted-foreground">Active Schedules</p>
              </div>
            </div>
            <div className="mt-3 text-xs text-muted-foreground">
              Last run: {formatDate(stats?.lastValidationAt ?? null)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div
                className={`p-2 rounded-lg ${(stats?.regressionsDetected ?? 0) > 0 ? "bg-red-500/10" : "bg-green-500/10"}`}
              >
                {(stats?.regressionsDetected ?? 0) > 0 ? (
                  <TrendingDown className="h-5 w-5 text-red-400" />
                ) : (
                  <TrendingUp className="h-5 w-5 text-green-400" />
                )}
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.regressionsDetected ?? 0}</p>
                <p className="text-xs text-muted-foreground">Regressions Detected</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* MITRE ATT&CK Coverage Heatmap */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-5 w-5" />
            MITRE ATT&CK Coverage Heatmap
          </CardTitle>
          <CardDescription>
            Visual coverage of MITRE ATT&CK techniques. Green = detected/blocked, Yellow = partial, Red = no coverage.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {heatmap && Object.keys(heatmap).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(heatmap).map(([tacticName, techniques]) => (
                <div key={tacticName}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-sm font-medium min-w-[180px]">{tacticName}</span>
                    <span className="text-xs text-muted-foreground">
                      ({Object.values(techniques).filter((t) => t.passed).length}/{Object.keys(techniques).length}{" "}
                      covered)
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(techniques).map(([techId, data]) => (
                      <div
                        key={techId}
                        className={`w-7 h-7 rounded ${coverageBg(data.coverage)} flex items-center justify-center cursor-default`}
                        title={`${techId}: ${data.coverage === "full" ? "Covered" : data.coverage === "partial" ? "Partial" : "No coverage"}`}
                      >
                        <span className="text-[9px] text-white/80 font-mono">
                          {techId.split(".")[0].replace("T", "")}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
              <div className="flex items-center gap-4 mt-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-1">
                  <div className="w-3 h-3 rounded bg-green-500" />
                  Full Coverage
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-3 h-3 rounded bg-yellow-500" />
                  Partial Coverage
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-3 h-3 rounded bg-red-500/60" />
                  No Coverage
                </div>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No heatmap data available. Run simulations to populate.</p>
          )}
        </CardContent>
      </Card>

      {/* Tactic-level Breakdown + Top Failing Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Coverage by Tactic</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.byTactic && Object.keys(stats.byTactic).length > 0 ? (
              <div className="space-y-3">
                {Object.entries(stats.byTactic).map(([tactic, data]) => (
                  <div key={tactic}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm">{tactic}</span>
                      <span className="text-xs font-mono">{data.coverage}%</span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${data.coverage >= 80 ? "bg-green-500" : data.coverage >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                        style={{ width: `${data.coverage}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No tactic data</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Top Failing Controls</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.topFailingControls && stats.topFailingControls.length > 0 ? (
              <div className="space-y-3">
                {stats.topFailingControls.map((ctrl) => (
                  <div key={ctrl.name}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm">{ctrl.name}</span>
                      <span className={`text-xs font-mono ${ctrl.failRate > 50 ? "text-red-400" : "text-yellow-400"}`}>
                        {ctrl.failRate}% fail rate
                      </span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full rounded-full bg-red-500" style={{ width: `${ctrl.failRate}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No failing controls</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Attack Library Tab ────────────────────────────────────────────────────────

function AttackLibraryTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tacticFilter, setTacticFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const { data: tactics } = useQuery<MitreTactic[]>({
    queryKey: ["/api/chaos-engineering/tactics"],
    queryFn: () => apiFetch("/api/chaos-engineering/tactics"),
  });

  const queryParams = new URLSearchParams();
  if (tacticFilter !== "all") queryParams.set("tacticId", tacticFilter);
  if (severityFilter !== "all") queryParams.set("severity", severityFilter);

  const { data: techniques, isLoading } = useQuery<MitreTechnique[]>({
    queryKey: ["/api/chaos-engineering/library", tacticFilter, severityFilter],
    queryFn: () => apiFetch(`/api/chaos-engineering/library?${queryParams.toString()}`),
  });

  const simulateMutation = useMutation({
    mutationFn: (techniqueId: string) =>
      apiFetch("/api/chaos-engineering/simulate", {
        method: "POST",
        body: JSON.stringify({ techniqueId }),
      }),
    onSuccess: (data: SimulationResult) => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering"] });
      toast({
        title: data.status === "passed" ? "Simulation Passed" : "Simulation Failed",
        description: `${data.techniqueName}: ${data.verdict}`,
        variant: data.status === "passed" ? "default" : "destructive",
      });
    },
    onError: (err: Error) => {
      toast({ title: "Simulation Error", description: err.message, variant: "destructive" });
    },
  });

  const filtered = (techniques ?? []).filter(
    (t) =>
      !searchQuery ||
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.description.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search techniques..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={tacticFilter} onValueChange={setTacticFilter}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="All Tactics" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tactics</SelectItem>
            {(tactics ?? []).map((t) => (
              <SelectItem key={t.id} value={t.id}>
                {t.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="All Severities" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-muted-foreground">Loading techniques...</div>
      ) : filtered.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No techniques found matching your filters.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">{filtered.length} techniques</p>
          {filtered.map((t) => (
            <Card key={t.id}>
              <CardContent className="py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-sm font-medium text-blue-400">{t.id}</span>
                      <Badge variant="outline" className={severityBadge(t.severity)}>
                        {t.severity}
                      </Badge>
                      <Badge variant="outline" className="bg-slate-500/10">
                        {t.tacticName}
                      </Badge>
                    </div>
                    <h4 className="text-sm font-medium mb-1">{t.name}</h4>
                    <p className="text-xs text-muted-foreground mb-2">{t.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {t.platform.map((p) => (
                        <Badge key={p} variant="outline" className="text-[10px] bg-slate-500/10">
                          {p}
                        </Badge>
                      ))}
                      {t.controlMappings.map((c) => (
                        <Badge key={c} variant="outline" className="text-[10px] bg-purple-500/10 text-purple-400">
                          {c}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => simulateMutation.mutate(t.id)}
                    disabled={simulateMutation.isPending}
                  >
                    <Play className="h-3 w-3 mr-1" />
                    Simulate
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Purple Team Tab ───────────────────────────────────────────────────────────

function PurpleTeamTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: scenarios } = useQuery<PurpleTeamScenario[]>({
    queryKey: ["/api/chaos-engineering/purple-team/scenarios"],
    queryFn: () => apiFetch("/api/chaos-engineering/purple-team/scenarios"),
  });

  const { data: results, isLoading } = useQuery<PurpleTeamResult[]>({
    queryKey: ["/api/chaos-engineering/purple-team/results"],
    queryFn: () => apiFetch("/api/chaos-engineering/purple-team/results"),
  });

  const runMutation = useMutation({
    mutationFn: (scenarioId: string) =>
      apiFetch("/api/chaos-engineering/purple-team/run", {
        method: "POST",
        body: JSON.stringify({ scenarioId }),
      }),
    onSuccess: (data: PurpleTeamResult) => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering"] });
      toast({
        title: "Exercise Completed",
        description: `${data.scenarioName}: ${data.detectionRate}% detection rate`,
      });
    },
    onError: (err: Error) => {
      toast({ title: "Exercise Error", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-6">
      {/* Purple Team Exercise Management */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Crosshair className="h-5 w-5" />
            Attack Scenario Library
          </CardTitle>
          <CardDescription>
            Pre-built kill chain scenarios for purple team exercises. Assign red/blue teams, set objectives, track
            findings, and schedule recurring exercises.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {(scenarios ?? []).map((s) => (
              <div key={s.id} className="border rounded-lg p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <h4 className="font-medium mb-1">{s.name}</h4>
                    <p className="text-sm text-muted-foreground mb-2">{s.description}</p>
                    <div className="flex flex-wrap gap-1 mb-2">
                      {s.mitreChain.map((techId) => (
                        <Badge key={techId} variant="outline" className="text-[10px] font-mono">
                          {techId}
                        </Badge>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      <strong>Kill chain:</strong> {s.attackScenario}
                    </p>
                    {/* Team assignments */}
                    <div className="flex flex-wrap gap-2 mt-2">
                      <div className="flex items-center gap-1 text-[10px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded">
                        <Target className="h-3 w-3" />
                        Red Team: {s.redTeamActions?.slice(0, 50) || "Attack Simulation"}
                      </div>
                      <div className="flex items-center gap-1 text-[10px] bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded">
                        <Shield className="h-3 w-3" />
                        Blue Team: {s.blueTeamExpected?.slice(0, 50) || "Detection & Response"}
                      </div>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => runMutation.mutate(s.id)}
                    disabled={runMutation.isPending}
                  >
                    <Play className="h-3 w-3 mr-1" />
                    Run Exercise
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Exercise Results */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Exercise Results
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">Loading results...</div>
          ) : (results ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">No exercises run yet. Select a scenario above to begin.</p>
          ) : (
            <div className="space-y-4">
              {(results ?? []).map((r) => (
                <div key={r.id} className="border rounded-lg p-4">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <h4 className="font-medium">{r.scenarioName}</h4>
                        <Badge
                          variant="outline"
                          className={
                            r.overallVerdict === "full_detection"
                              ? "bg-green-500/20 text-green-400 border-green-500/30"
                              : r.overallVerdict === "partial_detection"
                                ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                                : r.overallVerdict === "missed"
                                  ? "bg-red-500/20 text-red-400 border-red-500/30"
                                  : "bg-slate-500/20 text-slate-400 border-slate-500/30"
                          }
                        >
                          {r.overallVerdict?.replace(/_/g, " ") ?? r.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{formatDate(r.executedAt)}</p>
                    </div>
                    <div className="text-right">
                      <p
                        className={`text-2xl font-bold ${r.detectionRate >= 80 ? "text-green-400" : r.detectionRate >= 50 ? "text-yellow-400" : "text-red-400"}`}
                      >
                        {r.detectionRate}%
                      </p>
                      <p className="text-xs text-muted-foreground">Detection Rate</p>
                    </div>
                  </div>

                  {/* Metrics */}
                  <div className="grid grid-cols-3 gap-4 mb-3">
                    <div className="text-center p-2 bg-slate-800/50 rounded">
                      <p className="text-sm font-mono">{formatDuration(r.detectionTimeMs)}</p>
                      <p className="text-[10px] text-muted-foreground">Detection Time</p>
                    </div>
                    <div className="text-center p-2 bg-slate-800/50 rounded">
                      <p className="text-sm font-mono">{formatDuration(r.responseTimeMs)}</p>
                      <p className="text-[10px] text-muted-foreground">Response Time</p>
                    </div>
                    <div className="text-center p-2 bg-slate-800/50 rounded">
                      <p className="text-sm font-mono">{formatDuration(r.containmentTimeMs)}</p>
                      <p className="text-[10px] text-muted-foreground">Containment Time</p>
                    </div>
                  </div>

                  {/* Chain Progress */}
                  <div className="flex items-center gap-1 mb-3">
                    {r.mitreChain.map((techId, i) => (
                      <div key={techId} className="flex items-center">
                        <div
                          className={`w-8 h-8 rounded flex items-center justify-center text-[9px] font-mono ${
                            i < r.stepsCompleted
                              ? r.gapsIdentified.some((g) => g.includes(techId))
                                ? "bg-red-500/20 text-red-400 border border-red-500/30"
                                : "bg-green-500/20 text-green-400 border border-green-500/30"
                              : "bg-slate-700 text-slate-400"
                          }`}
                        >
                          {techId.split(".")[0].replace("T", "")}
                        </div>
                        {i < r.mitreChain.length - 1 && <div className="w-4 h-px bg-slate-600 mx-0.5" />}
                      </div>
                    ))}
                  </div>

                  {/* Detection Gap Analysis */}
                  {r.gapsIdentified.length > 0 && (
                    <div className="mt-2">
                      <p className="text-xs font-medium text-red-400 mb-1">Detection Gaps Identified:</p>
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        {r.gapsIdentified.map((g, i) => (
                          <li key={i} className="flex items-center gap-1">
                            <XCircle className="h-3 w-3 text-red-400 shrink-0" />
                            {g}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Improvements suggested */}
                  {r.improvements && r.improvements.length > 0 && (
                    <div className="mt-2">
                      <p className="text-xs font-medium text-green-400 mb-1">Recommended Improvements:</p>
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        {r.improvements.map((imp, i) => (
                          <li key={i} className="flex items-center gap-1">
                            <CheckCircle2 className="h-3 w-3 text-green-500" />
                            {imp}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Effectiveness Tab ─────────────────────────────────────────────────────────

function EffectivenessTab() {
  const [sortBy, setSortBy] = useState("failing");

  const { data: controls, isLoading } = useQuery<ControlScore[]>({
    queryKey: ["/api/chaos-engineering/controls", sortBy],
    queryFn: () => apiFetch(`/api/chaos-engineering/controls?sortBy=${sortBy}`),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">Loading control scores...</div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{(controls ?? []).length} security controls evaluated</p>
        <Select value={sortBy} onValueChange={setSortBy}>
          <SelectTrigger className="w-[180px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="failing">Worst First</SelectItem>
            <SelectItem value="effectiveness">Best First</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {(controls ?? []).length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No controls tested yet. Run simulations to evaluate control effectiveness.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {(controls ?? []).map((ctrl) => (
            <Card key={ctrl.controlName}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold ${
                        ctrl.effectivenessScore >= 80
                          ? "bg-green-500/20 text-green-400"
                          : ctrl.effectivenessScore >= 50
                            ? "bg-yellow-500/20 text-yellow-400"
                            : "bg-red-500/20 text-red-400"
                      }`}
                    >
                      {ctrl.effectivenessScore}
                    </div>
                    <div>
                      <h4 className="font-medium">{ctrl.controlName}</h4>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{ctrl.totalTests} tests</span>
                        <span className="text-green-400">{ctrl.passedTests} passed</span>
                        <span className="text-red-400">{ctrl.failedTests} failed</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant="outline"
                      className={
                        ctrl.status === "effective"
                          ? "bg-green-500/20 text-green-400 border-green-500/30"
                          : ctrl.status === "partial"
                            ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                            : ctrl.status === "failing"
                              ? "bg-red-500/20 text-red-400 border-red-500/30"
                              : "bg-slate-500/20"
                      }
                    >
                      {ctrl.status}
                    </Badge>
                    {ctrl.trend === "improving" && <TrendingUp className="h-4 w-4 text-green-400" />}
                    {ctrl.trend === "declining" && <TrendingDown className="h-4 w-4 text-red-400" />}
                    {ctrl.trend === "stable" && <Minus className="h-4 w-4 text-slate-400" />}
                  </div>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      ctrl.effectivenessScore >= 80
                        ? "bg-green-500"
                        : ctrl.effectivenessScore >= 50
                          ? "bg-yellow-500"
                          : "bg-red-500"
                    }`}
                    style={{ width: `${ctrl.effectivenessScore}%` }}
                  />
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {ctrl.mitreIds.slice(0, 8).map((mid) => (
                    <Badge key={mid} variant="outline" className="text-[10px] font-mono">
                      {mid}
                    </Badge>
                  ))}
                  {ctrl.mitreIds.length > 8 && (
                    <Badge variant="outline" className="text-[10px]">
                      +{ctrl.mitreIds.length - 8} more
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Detection Gaps Tab ────────────────────────────────────────────────────────

function DetectionGapsTab() {
  const [coverageFilter, setCoverageFilter] = useState("all");
  const [priorityFilter, setPriorityFilter] = useState("all");

  const queryParams = new URLSearchParams();
  if (coverageFilter !== "all") queryParams.set("coverageStatus", coverageFilter);
  if (priorityFilter !== "all") queryParams.set("priority", priorityFilter);

  const { data: gaps, isLoading } = useQuery<GapEntry[]>({
    queryKey: ["/api/chaos-engineering/gaps", coverageFilter, priorityFilter],
    queryFn: () => apiFetch(`/api/chaos-engineering/gaps?${queryParams.toString()}`),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-muted-foreground">Loading detection gaps...</div>
    );
  }

  const noCoverage = (gaps ?? []).filter((g) => g.coverageStatus === "no_coverage").length;
  const partial = (gaps ?? []).filter((g) => g.coverageStatus === "partial").length;
  const full = (gaps ?? []).filter((g) => g.coverageStatus === "full").length;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <XCircle className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-red-400">{noCoverage}</p>
                <p className="text-xs text-muted-foreground">No Coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <AlertTriangle className="h-5 w-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-yellow-400">{partial}</p>
                <p className="text-xs text-muted-foreground">Partial Coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-green-400">{full}</p>
                <p className="text-xs text-muted-foreground">Full Coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <Select value={coverageFilter} onValueChange={setCoverageFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All Coverage" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Coverage</SelectItem>
            <SelectItem value="no_coverage">No Coverage</SelectItem>
            <SelectItem value="partial">Partial</SelectItem>
            <SelectItem value="full">Full</SelectItem>
          </SelectContent>
        </Select>
        <Select value={priorityFilter} onValueChange={setPriorityFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="All Priorities" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Priorities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Gap List */}
      {(gaps ?? []).length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No gaps found matching your filters.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">{(gaps ?? []).length} techniques</p>
          <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="text-left p-3 font-medium">Technique</th>
                  <th className="text-left p-3 font-medium">Tactic</th>
                  <th className="text-center p-3 font-medium">Coverage</th>
                  <th className="text-center p-3 font-medium">Priority</th>
                  <th className="text-center p-3 font-medium">Rules</th>
                  <th className="text-left p-3 font-medium">Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {(gaps ?? []).map((g) => (
                  <tr key={g.techniqueId} className="border-b last:border-0 hover:bg-muted/10">
                    <td className="p-3">
                      <div>
                        <span className="font-mono text-xs text-blue-400">{g.techniqueId}</span>
                        <p className="text-xs">{g.techniqueName}</p>
                      </div>
                    </td>
                    <td className="p-3 text-xs text-muted-foreground">{g.tacticName}</td>
                    <td className="p-3 text-center">
                      <Badge
                        variant="outline"
                        className={
                          g.coverageStatus === "full"
                            ? "bg-green-500/20 text-green-400 border-green-500/30"
                            : g.coverageStatus === "partial"
                              ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                              : "bg-red-500/20 text-red-400 border-red-500/30"
                        }
                      >
                        {g.coverageStatus.replace(/_/g, " ")}
                      </Badge>
                    </td>
                    <td className="p-3 text-center">
                      <Badge variant="outline" className={severityBadge(g.priority)}>
                        {g.priority}
                      </Badge>
                    </td>
                    <td className="p-3 text-center font-mono">{g.detectionRuleCount}</td>
                    <td className="p-3 text-xs text-muted-foreground max-w-[250px] truncate">{g.recommendation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Scheduled Validation Tab ──────────────────────────────────────────────────

function ScheduledTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newFreq, setNewFreq] = useState("weekly");

  const { data: schedules, isLoading } = useQuery<ValidationSchedule[]>({
    queryKey: ["/api/chaos-engineering/schedules"],
    queryFn: () => apiFetch("/api/chaos-engineering/schedules"),
  });

  const { data: techniques } = useQuery<MitreTechnique[]>({
    queryKey: ["/api/chaos-engineering/library"],
    queryFn: () => apiFetch("/api/chaos-engineering/library"),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      apiFetch("/api/chaos-engineering/schedules", {
        method: "POST",
        body: JSON.stringify({
          name: newName,
          description: newDesc,
          frequency: newFreq,
          techniqueIds: (techniques ?? []).map((t) => t.id),
          enabled: true,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering/schedules"] });
      toast({ title: "Schedule created" });
      setShowCreate(false);
      setNewName("");
      setNewDesc("");
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/chaos-engineering/schedules/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering/schedules"] });
    },
  });

  const runMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/chaos-engineering/schedules/${id}/run`, { method: "POST" }),
    onSuccess: (data: { count: number }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering"] });
      toast({ title: "Validation Complete", description: `${data.count} simulations executed` });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/chaos-engineering/schedules/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering/schedules"] });
      toast({ title: "Schedule deleted" });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading schedules...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{(schedules ?? []).length} validation schedules</p>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4 mr-1" />
              New Schedule
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Validation Schedule</DialogTitle>
              <DialogDescription>
                Schedule continuous validation of security controls against MITRE ATT&CK techniques.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label>Name</Label>
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Weekly Full ATT&CK Validation"
                />
              </div>
              <div>
                <Label>Description</Label>
                <Input
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Run all technique simulations weekly"
                />
              </div>
              <div>
                <Label>Frequency</Label>
                <Select value={newFreq} onValueChange={setNewFreq}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={() => createMutation.mutate()} disabled={!newName || createMutation.isPending}>
                Create
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {(schedules ?? []).length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No validation schedules created yet. Create one to automate continuous security validation.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {(schedules ?? []).map((s) => (
            <Card key={s.id}>
              <CardContent className="py-4">
                <div className="flex items-start justify-between gap-4 mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-medium">{s.name}</h4>
                      <Badge variant="outline" className="capitalize">
                        {s.frequency}
                      </Badge>
                      {s.regressionDetected && (
                        <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30">
                          Regression
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{s.description}</p>
                    <div className="flex gap-4 text-xs text-muted-foreground">
                      <span>
                        <Clock className="inline h-3 w-3 mr-1" />
                        Last run: {formatDate(s.lastRunAt)}
                      </span>
                      <span>
                        <Calendar className="inline h-3 w-3 mr-1" />
                        Next run: {formatDate(s.nextRunAt)}
                      </span>
                      <span>{s.totalRuns} runs</span>
                      <span>{s.techniqueIds.length} techniques</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {s.lastScore !== null && (
                      <div className="text-right mr-2">
                        <div className="flex items-center gap-1">
                          <span
                            className={`text-lg font-bold ${
                              s.lastScore >= 80
                                ? "text-green-400"
                                : s.lastScore >= 50
                                  ? "text-yellow-400"
                                  : "text-red-400"
                            }`}
                          >
                            {s.lastScore}%
                          </span>
                          {s.previousScore !== null && s.lastScore !== s.previousScore && (
                            <span
                              className={`text-xs ${s.lastScore > s.previousScore ? "text-green-400" : "text-red-400"}`}
                            >
                              {s.lastScore > s.previousScore ? "+" : ""}
                              {s.lastScore - s.previousScore}
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-muted-foreground">Last Score</p>
                      </div>
                    )}
                    <Switch
                      checked={s.enabled}
                      onCheckedChange={(enabled) => toggleMutation.mutate({ id: s.id, enabled })}
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => runMutation.mutate(s.id)}
                      disabled={runMutation.isPending}
                    >
                      <Play className="h-3 w-3 mr-1" />
                      Run Now
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-red-400 hover:text-red-300"
                      onClick={() => deleteMutation.mutate(s.id)}
                    >
                      <XCircle className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Simulations Tab ───────────────────────────────────────────────────────────

function SimulationsTab() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [tacticFilter, setTacticFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const { data: tactics } = useQuery<MitreTactic[]>({
    queryKey: ["/api/chaos-engineering/tactics"],
    queryFn: () => apiFetch("/api/chaos-engineering/tactics"),
  });

  const queryParams = new URLSearchParams();
  if (tacticFilter !== "all") queryParams.set("tacticId", tacticFilter);
  if (statusFilter !== "all") queryParams.set("status", statusFilter);

  const { data: simulations, isLoading } = useQuery<SimulationResult[]>({
    queryKey: ["/api/chaos-engineering/simulations", tacticFilter, statusFilter],
    queryFn: () => apiFetch(`/api/chaos-engineering/simulations?${queryParams.toString()}`),
  });

  const batchMutation = useMutation({
    mutationFn: () => {
      const failedIds = (simulations ?? []).filter((s) => s.status === "failed").map((s) => s.techniqueId);
      return apiFetch("/api/chaos-engineering/simulate-batch", {
        method: "POST",
        body: JSON.stringify({ techniqueIds: failedIds, trigger: "retest" }),
      });
    },
    onSuccess: (data: { count: number }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering"] });
      toast({ title: "Retest Complete", description: `${data.count} simulations re-executed` });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading simulations...</div>;
  }

  const failedCount = (simulations ?? []).filter((s) => s.status === "failed").length;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <Select value={tacticFilter} onValueChange={setTacticFilter}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="All Tactics" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tactics</SelectItem>
            {(tactics ?? []).map((t) => (
              <SelectItem key={t.id} value={t.id}>
                {t.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="All Statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="passed">Passed</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
          </SelectContent>
        </Select>
        {failedCount > 0 && (
          <Button size="sm" variant="outline" onClick={() => batchMutation.mutate()} disabled={batchMutation.isPending}>
            <RefreshCw className="h-3 w-3 mr-1" />
            Retest {failedCount} Failed
          </Button>
        )}
        <span className="text-sm text-muted-foreground ml-auto">{(simulations ?? []).length} results</span>
      </div>

      {(simulations ?? []).length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No simulation results yet. Run simulations from the Attack Library tab.
          </CardContent>
        </Card>
      ) : (
        <div className="border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/30">
                <th className="text-left p-3 font-medium">Technique</th>
                <th className="text-left p-3 font-medium">Tactic</th>
                <th className="text-center p-3 font-medium">Status</th>
                <th className="text-center p-3 font-medium">Verdict</th>
                <th className="text-center p-3 font-medium">Duration</th>
                <th className="text-center p-3 font-medium">Trigger</th>
                <th className="text-left p-3 font-medium">Executed</th>
              </tr>
            </thead>
            <tbody>
              {(simulations ?? []).map((sim) => (
                <tr key={sim.id} className="border-b last:border-0 hover:bg-muted/10">
                  <td className="p-3">
                    <span className="font-mono text-xs text-blue-400">{sim.techniqueId}</span>
                    <p className="text-xs truncate max-w-[200px]">{sim.techniqueName}</p>
                  </td>
                  <td className="p-3 text-xs text-muted-foreground">{sim.tacticName}</td>
                  <td className="p-3 text-center">
                    <Badge variant="outline" className={statusBadge(sim.status)}>
                      {sim.status}
                    </Badge>
                  </td>
                  <td className="p-3 text-center">
                    <Badge variant="outline" className={verdictBadge(sim.verdict)}>
                      {sim.verdict}
                    </Badge>
                  </td>
                  <td className="p-3 text-center font-mono text-xs">{formatDuration(sim.durationMs)}</td>
                  <td className="p-3 text-center">
                    <Badge variant="outline" className="text-[10px]">
                      {sim.trigger}
                    </Badge>
                  </td>
                  <td className="p-3 text-xs text-muted-foreground">{formatDate(sim.executedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Scenario Builder Tab

function ScenarioBuilderTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [scenarioName, setScenarioName] = useState("");
  const [scenarioDesc, setScenarioDesc] = useState("");
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>([]);
  const [targetScope, setTargetScope] = useState("all");
  const [detectionExpectation, setDetectionExpectation] = useState("full_detection");

  const { data: techniques } = useQuery<MitreTechnique[]>({
    queryKey: ["/api/chaos-engineering/library"],
    queryFn: () => apiFetch("/api/chaos-engineering/library"),
  });

  const createScenarioMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      apiFetch("/api/chaos-engineering/scenarios", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/chaos-engineering"] });
      toast({ title: "Scenario Created", description: `"${scenarioName}" saved successfully` });
      setScenarioName("");
      setScenarioDesc("");
      setSelectedTechniques([]);
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const toggleTechnique = (id: string) => {
    setSelectedTechniques((prev) => (prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id]));
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-5 w-5" />
            Simulation Scenario Builder
          </CardTitle>
          <CardDescription>
            Build multi-step attack chains by selecting MITRE ATT&CK techniques, configuring targets, and setting
            detection expectations.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Scenario Name</Label>
              <Input
                value={scenarioName}
                onChange={(e) => setScenarioName(e.target.value)}
                placeholder="e.g. Ransomware Kill Chain"
              />
            </div>
            <div className="space-y-2">
              <Label>Target Scope</Label>
              <Select value={targetScope} onValueChange={setTargetScope}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Endpoints</SelectItem>
                  <SelectItem value="servers">Servers Only</SelectItem>
                  <SelectItem value="workstations">Workstations Only</SelectItem>
                  <SelectItem value="cloud">Cloud Instances</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label>Description</Label>
            <Input
              value={scenarioDesc}
              onChange={(e) => setScenarioDesc(e.target.value)}
              placeholder="Describe the attack scenario and objectives..."
            />
          </div>
          <div className="space-y-2">
            <Label>Detection Expectation</Label>
            <Select value={detectionExpectation} onValueChange={setDetectionExpectation}>
              <SelectTrigger className="w-[250px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="full_detection">Full Detection (all steps)</SelectItem>
                <SelectItem value="partial_detection">Partial Detection (some steps)</SelectItem>
                <SelectItem value="evasion_test">Evasion Test (expect misses)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Attack chain builder */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Attack Chain — Select Techniques</CardTitle>
          <CardDescription>
            Click techniques to add them to your attack chain. They will execute in the order selected.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Selected chain */}
          {selectedTechniques.length > 0 && (
            <div className="mb-4 p-3 rounded border border-blue-500/20 bg-blue-500/5">
              <p className="text-xs font-medium mb-2">Selected Chain ({selectedTechniques.length} steps):</p>
              <div className="flex flex-wrap items-center gap-1">
                {selectedTechniques.map((techId, idx) => (
                  <div key={techId} className="flex items-center">
                    <Badge
                      variant="outline"
                      className="cursor-pointer bg-blue-500/20 text-blue-400 border-blue-500/30"
                      onClick={() => toggleTechnique(techId)}
                    >
                      {techId}
                    </Badge>
                    {idx < selectedTechniques.length - 1 && (
                      <ArrowRight className="h-3 w-3 text-muted-foreground mx-1" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Available techniques */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-[300px] overflow-y-auto">
            {(techniques ?? []).slice(0, 40).map((t) => {
              const isSelected = selectedTechniques.includes(t.id);
              return (
                <div
                  key={t.id}
                  className={`p-2 rounded border cursor-pointer transition-colors text-xs ${
                    isSelected ? "bg-blue-500/20 border-blue-500/30" : "hover:bg-muted/30 border-border"
                  }`}
                  onClick={() => toggleTechnique(t.id)}
                >
                  <span className="font-mono text-blue-400">{t.id}</span>
                  <p className="truncate text-muted-foreground">{t.name}</p>
                  <Badge variant="outline" className={`text-[9px] mt-1 ${severityBadge(t.severity)}`}>
                    {t.severity}
                  </Badge>
                </div>
              );
            })}
          </div>

          {/* Create button */}
          <div className="flex justify-end mt-4">
            <Button
              disabled={!scenarioName || selectedTechniques.length === 0 || createScenarioMutation.isPending}
              onClick={() =>
                createScenarioMutation.mutate({
                  name: scenarioName,
                  description: scenarioDesc,
                  techniqueIds: selectedTechniques,
                  targetScope,
                  detectionExpectation,
                })
              }
            >
              <Plus className="h-4 w-4 mr-1" />
              {createScenarioMutation.isPending ? "Creating..." : "Create Scenario"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Coverage Tracking Tab

function CoverageTrackingTab() {
  const { data: stats } = useQuery<ChaosStats>({
    queryKey: ["/api/chaos-engineering/stats"],
    queryFn: () => apiFetch("/api/chaos-engineering/stats"),
  });

  const { data: gaps } = useQuery<GapEntry[]>({
    queryKey: ["/api/chaos-engineering/gaps"],
    queryFn: () => apiFetch("/api/chaos-engineering/gaps"),
  });

  const closedGaps = (gaps ?? []).filter((g) => g.coverageStatus === "full").length;
  const remainingGaps = (gaps ?? []).filter((g) => g.coverageStatus !== "full").length;
  const totalGaps = (gaps ?? []).length;

  return (
    <div className="space-y-6">
      {/* Coverage summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Target className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.coveragePercent || 0}%</p>
                <p className="text-xs text-muted-foreground">Current Coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-green-400">{closedGaps}</p>
                <p className="text-xs text-muted-foreground">Gaps Closed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <XCircle className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-red-400">{remainingGaps}</p>
                <p className="text-xs text-muted-foreground">Remaining Gaps</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Activity className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.purpleTeamExercises || 0}</p>
                <p className="text-xs text-muted-foreground">Exercises Run</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Coverage by tactic */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Coverage by MITRE ATT&CK Tactic</CardTitle>
          <CardDescription>Before/after coverage changes per validation cycle</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Object.entries(stats?.byTactic || {}).map(([tactic, data]) => (
              <div key={tactic} className="flex items-center gap-4">
                <span className="text-xs w-32 truncate">{tactic}</span>
                <div className="flex-1">
                  <div className="relative h-4 bg-muted rounded-full overflow-hidden">
                    <div
                      className="absolute h-full bg-blue-500/70 rounded-full transition-all"
                      style={{ width: `${data.coverage}%` }}
                    />
                  </div>
                </div>
                <span
                  className={`text-xs font-mono w-12 text-right ${data.coverage >= 80 ? "text-green-400" : data.coverage >= 50 ? "text-yellow-400" : "text-red-400"}`}
                >
                  {data.coverage}%
                </span>
                <span className="text-[10px] text-muted-foreground w-16 text-right">
                  {data.passed}/{data.total}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Safety indicators */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-green-400" />
            Safe Simulation Guardrails
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "No Data Exfiltration", icon: Lock, active: true },
              { label: "No Persistence", icon: ShieldAlert, active: true },
              { label: "Sandbox Isolation", icon: Shield, active: true },
              { label: "Auto-Rollback", icon: RefreshCw, active: true },
            ].map((guard) => (
              <div
                key={guard.label}
                className="flex items-center gap-2 p-3 rounded border border-green-500/20 bg-green-500/5"
              >
                <guard.icon className="h-4 w-4 text-green-400" />
                <span className="text-xs">{guard.label}</span>
                <Badge variant="outline" className="ml-auto text-[9px] text-green-400 border-green-500/30">
                  {guard.active ? "Active" : "Off"}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Gap closure progress */}
      {totalGaps > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Gap Closure Progress</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4 mb-2">
              <div className="flex-1">
                <div className="relative h-4 bg-muted rounded-full overflow-hidden">
                  <div
                    className="absolute h-full bg-green-500/70 rounded-full transition-all"
                    style={{ width: `${(closedGaps / totalGaps) * 100}%` }}
                  />
                </div>
              </div>
              <span className="text-sm font-mono">
                {closedGaps}/{totalGaps}
              </span>
            </div>
            <p className="text-xs text-muted-foreground">
              {Math.round((closedGaps / Math.max(totalGaps, 1)) * 100)}% of detection gaps have been closed through
              simulation exercises.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function SecurityChaosEngineeringPage() {
  const [activeTab, setActiveTab] = useState("dashboard");

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Zap className="h-6 w-6 text-orange-400" />
            Security Chaos Engineering
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Continuous validation of security controls with MITRE ATT&CK coverage mapping. Comparable to AttackIQ /
            SafeBreach.
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-8">
          <TabsTrigger value="dashboard">BAS Dashboard</TabsTrigger>
          <TabsTrigger value="builder">Scenario Builder</TabsTrigger>
          <TabsTrigger value="library">Attack Library</TabsTrigger>
          <TabsTrigger value="purple">Purple Team</TabsTrigger>
          <TabsTrigger value="effectiveness">Effectiveness</TabsTrigger>
          <TabsTrigger value="gaps">Detection Gaps</TabsTrigger>
          <TabsTrigger value="coverage">Coverage</TabsTrigger>
          <TabsTrigger value="scheduled">Scheduled</TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard">
          <BASDashboardTab />
        </TabsContent>
        <TabsContent value="builder">
          <ScenarioBuilderTab />
        </TabsContent>
        <TabsContent value="library">
          <AttackLibraryTab />
        </TabsContent>
        <TabsContent value="purple">
          <PurpleTeamTab />
        </TabsContent>
        <TabsContent value="effectiveness">
          <EffectivenessTab />
        </TabsContent>
        <TabsContent value="gaps">
          <DetectionGapsTab />
        </TabsContent>
        <TabsContent value="coverage">
          <CoverageTrackingTab />
        </TabsContent>
        <TabsContent value="scheduled">
          <ScheduledTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
