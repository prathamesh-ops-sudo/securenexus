import { useQuery, useMutation } from "@tanstack/react-query";
import { useState, useMemo, useCallback } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge, formatTimestamp } from "@/components/security-badges";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Crosshair,
  ArrowRight,
  Target,
  Shield,
  Activity,
  Clock,
  Zap,
  Layers,
  Download,
  Bug,
  HardDrive,
  Wifi,
  Flag,
  AlertTriangle,
  BarChart3,
  GitBranch,
  Play,
  Settings2,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  Timer,
  RadioTower,
  Eye,
  Lock,
  Unplug,
  FileWarning,
  Bell,
  Workflow,
  Camera,
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

// ── Types ────────────────────────────────────────────────────────────

interface PhaseData {
  id: string;
  name: string;
  shortName: string;
  description: string;
  mitreTactics: string[];
  order: number;
  severity: "early" | "mid" | "late";
  alertCount: number;
  incidentCount: number;
  totalCount: number;
  alerts: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    source: string;
    mitreTactic: string;
    mitreTechnique: string;
    detectedAt: string;
    createdAt: string;
    sourceIp: string;
    destinationIp: string;
  }>;
  incidents: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    mitreTactic: string;
    createdAt: string;
  }>;
  highestSeverity: string;
}

interface PhasesResponse {
  data: {
    framework: { id: string; name: string };
    phases: PhaseData[];
    totalAlerts: number;
    totalIncidents: number;
  };
}

interface AnalyticsResponse {
  data: {
    framework: { id: string; name: string };
    phaseStats: Array<{
      phaseId: string;
      phaseName: string;
      order: number;
      totalDetections: number;
      uniqueSources: number;
      firstSeen: string | null;
      lastSeen: string | null;
      dwellTimeMs: number;
      dwellTimeHuman: string;
    }>;
    summary: {
      totalDetections: number;
      activePhases: number;
      totalPhases: number;
      mostTargetedPhase: string;
      breakoutTimeMs: number;
      breakoutTimeHuman: string;
      avgDwellTimeMs: number;
      avgDwellTimeHuman: string;
    };
  };
}

interface CorrelationIncident {
  id: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  phaseCount: number;
  phases: Array<{ phaseId: string; phaseName: string; order: number; severity: string }>;
  furthestPhase: string;
  reachedLateStage: boolean;
  isCritical: boolean;
  riskScore: number;
}

interface CorrelationResponse {
  data: {
    framework: { id: string; name: string };
    incidents: CorrelationIncident[];
    summary: {
      totalIncidents: number;
      criticalIncidents: number;
      multiPhaseIncidents: number;
      lateStageIncidents: number;
    };
  };
}

interface CampaignData {
  incidentId: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string;
  phases: Array<{
    phaseId: string;
    phaseName: string;
    order: number;
    isActive: boolean;
    timeInPhaseMs: number;
    timeInPhaseHuman: string | null;
  }>;
  currentPhase: string;
  progressPercent: number;
  isLateStage: boolean;
}

interface CampaignsResponse {
  data: {
    framework: { id: string; name: string };
    campaigns: CampaignData[];
    activeCampaignCount: number;
    lateStageCount: number;
  };
}

interface TriggerAction {
  id: string;
  name: string;
  description: string;
}

interface TriggerPhase {
  phaseId: string;
  phaseName: string;
  order: number;
  severity: string;
  recommendedActions: string[];
  configuredActions: string[];
}

interface TriggersResponse {
  data: {
    framework: { id: string; name: string };
    triggers: TriggerPhase[];
    availableActions: TriggerAction[];
  };
}

interface FrameworkInfo {
  id: string;
  name: string;
  description: string;
  phaseCount: number;
}

interface FrameworksResponse {
  data: {
    frameworks: FrameworkInfo[];
  };
}

// ── Constants ────────────────────────────────────────────────────────

const PHASE_ICONS: Record<string, any> = {
  Reconnaissance: Crosshair,
  Weaponization: Zap,
  Delivery: Download,
  "Social Engineering": Download,
  Exploitation: Bug,
  Installation: HardDrive,
  Persistence: HardDrive,
  "Defense Evasion": Shield,
  Evasion: Shield,
  Discovery: Eye,
  "Command & Control": Wifi,
  "Lateral Movement": GitBranch,
  Pivoting: GitBranch,
  "Actions on Objectives": Flag,
  Objectives: Flag,
  Impact: Flag,
  Adversary: Target,
  Capability: Zap,
  Infrastructure: RadioTower,
  Victim: AlertTriangle,
  "Initial Access": Download,
  Execution: Bug,
};

const SEVERITY_COLORS: Record<string, string> = {
  early: "text-blue-500 bg-blue-500/10 border-blue-500/30",
  mid: "text-amber-500 bg-amber-500/10 border-amber-500/30",
  late: "text-red-500 bg-red-500/10 border-red-500/30",
};

const PHASE_BG: Record<string, string> = {
  early: "bg-blue-500",
  mid: "bg-amber-500",
  late: "bg-red-500",
};

const ACTION_ICONS: Record<string, any> = {
  isolate_endpoint: Unplug,
  block_ip: Lock,
  disable_account: Lock,
  quarantine_file: FileWarning,
  create_incident: AlertTriangle,
  notify_soc: Bell,
  trigger_playbook: Workflow,
  snapshot_forensics: Camera,
};

// ── Helper Components ────────────────────────────────────────────────

function StatCard({
  title,
  value,
  icon: Icon,
  loading,
  variant,
}: {
  title: string;
  value: string | number;
  icon: any;
  loading?: boolean;
  variant?: "default" | "danger" | "warning";
}) {
  const testId = `stat-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div
          className={`p-1.5 rounded-md ${variant === "danger" ? "bg-red-500/10" : variant === "warning" ? "bg-amber-500/10" : "bg-muted/50"}`}
        >
          <Icon
            className={`h-3.5 w-3.5 ${variant === "danger" ? "text-red-500" : variant === "warning" ? "text-amber-500" : "text-muted-foreground"}`}
          />
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold tabular-nums" data-testid={`value-${testId}`}>
            {value}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// 10.1: Interactive phase card with expand/collapse
function InteractivePhaseCard({
  phase,
  isExpanded,
  onToggle,
  totalMax,
}: {
  phase: PhaseData;
  isExpanded: boolean;
  onToggle: () => void;
  totalMax: number;
}) {
  const Icon = PHASE_ICONS[phase.name] || Target;
  const severityStyle = SEVERITY_COLORS[phase.severity] || SEVERITY_COLORS.early;
  const hasData = phase.totalCount > 0;
  const intensity = totalMax > 0 ? phase.totalCount / totalMax : 0;

  return (
    <div className="flex-1 min-w-[130px]" data-testid={`phase-card-${phase.shortName}`}>
      <button
        className={`w-full rounded-md border p-3 text-left transition-all ${
          hasData
            ? `cursor-pointer hover:border-foreground/20 ${
                intensity >= 0.75
                  ? "bg-red-500/20 border-red-500/40"
                  : intensity >= 0.5
                    ? "bg-red-500/15 border-red-500/30"
                    : intensity >= 0.25
                      ? "bg-red-500/10 border-red-500/20"
                      : "bg-red-500/5 border-red-500/15"
              }`
            : "opacity-50 cursor-default bg-muted/30 border-border"
        } ${isExpanded ? "ring-2 ring-red-500/50" : ""}`}
        onClick={() => hasData && onToggle()}
      >
        <div className="flex items-center gap-2 mb-2">
          <div className={`p-1 rounded-md ${hasData ? "bg-red-500/15" : "bg-muted/50"}`}>
            <Icon className={`h-3.5 w-3.5 ${hasData ? "text-red-500" : "text-muted-foreground"}`} />
          </div>
          <Badge variant="outline" className={`text-[9px] px-1 py-0 ${severityStyle}`}>
            {phase.severity}
          </Badge>
        </div>
        <div className="text-xs font-medium mb-1 leading-tight">{phase.name}</div>
        <div className="text-lg font-bold tabular-nums">{phase.totalCount}</div>
        <div className="text-[10px] text-muted-foreground">
          {phase.alertCount} alerts, {phase.incidentCount} incidents
        </div>
        {hasData && (
          <div className="flex items-center gap-1 mt-2 text-[10px] text-muted-foreground">
            {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            {isExpanded ? "Collapse" : "Expand"}
          </div>
        )}
      </button>

      {/* Expanded detail panel */}
      {isExpanded && hasData && (
        <div
          className="mt-2 rounded-md border bg-card p-3 space-y-2 max-h-[350px] overflow-y-auto"
          data-testid={`phase-detail-${phase.shortName}`}
        >
          <div className="text-xs text-muted-foreground mb-2">{phase.description}</div>
          <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
            MITRE Tactics: {phase.mitreTactics.join(", ")}
          </div>
          {phase.alerts.slice(0, 10).map((alert) => (
            <Link
              key={`alert-${alert.id}`}
              href={`/alerts/${alert.id}`}
              className="flex items-center justify-between gap-2 p-2 rounded-md hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <Badge variant="outline" className="text-[9px] flex-shrink-0">
                  alert
                </Badge>
                <span className="text-xs truncate">{alert.title}</span>
              </div>
              <div className="flex items-center gap-1 flex-shrink-0">
                <SeverityBadge severity={alert.severity} />
              </div>
            </Link>
          ))}
          {phase.incidents.slice(0, 5).map((incident) => (
            <Link
              key={`incident-${incident.id}`}
              href={`/incidents/${incident.id}`}
              className="flex items-center justify-between gap-2 p-2 rounded-md hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <Badge variant="secondary" className="text-[9px] flex-shrink-0">
                  incident
                </Badge>
                <span className="text-xs truncate">{incident.title}</span>
              </div>
              <div className="flex items-center gap-1 flex-shrink-0">
                <SeverityBadge severity={incident.severity} />
              </div>
            </Link>
          ))}
          {phase.totalCount > 15 && (
            <div className="text-[10px] text-muted-foreground text-center pt-1">
              +{phase.totalCount - 15} more items
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 10.2: Progression animation for active campaigns
function CampaignProgression({ campaign, phases }: { campaign: CampaignData; phases: PhaseData[] }) {
  const totalPhases = campaign.phases.length;
  const activeCount = campaign.phases.filter((p) => p.isActive).length;

  return (
    <div
      className="p-3 rounded-md border hover:border-foreground/10 transition-colors"
      data-testid={`campaign-${campaign.incidentId}`}
    >
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <Link href={`/incidents/${campaign.incidentId}`} className="text-sm font-medium truncate hover:underline">
            {campaign.title}
          </Link>
          <SeverityBadge severity={campaign.severity} />
          {campaign.isLateStage && (
            <Badge variant="destructive" className="text-[9px] px-1 py-0 flex-shrink-0">
              Late Stage
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-[10px] text-muted-foreground">{campaign.progressPercent}% progression</span>
          <Badge variant="outline" className="text-[9px]">
            {campaign.status}
          </Badge>
        </div>
      </div>

      {/* Phase progression bar */}
      <div className="flex items-center gap-0.5">
        {campaign.phases.map((phase, idx) => {
          const phaseDef = phases.find((p) => p.id === phase.phaseId);
          const severityType = phaseDef?.severity || "early";
          const bgColor = PHASE_BG[severityType] || "bg-muted";

          return (
            <div key={phase.phaseId} className="flex items-center flex-1">
              <div
                className={`h-2 flex-1 rounded-sm transition-all ${
                  phase.isActive ? `${bgColor} opacity-80` : "bg-muted/40"
                } ${phase.phaseName === campaign.currentPhase ? "ring-1 ring-foreground/20 h-3" : ""}`}
                title={`${phase.phaseName}${phase.isActive ? ` (${phase.timeInPhaseHuman || "active"})` : ""}`}
              />
              {idx < totalPhases - 1 && <div className="w-0.5 h-1 bg-border mx-px flex-shrink-0" />}
            </div>
          );
        })}
      </div>

      <div className="flex items-center justify-between mt-2">
        <span className="text-[10px] text-muted-foreground">
          Current: <span className="font-medium text-foreground">{campaign.currentPhase}</span>
        </span>
        <span className="text-[10px] text-muted-foreground">
          {activeCount}/{totalPhases} phases active
        </span>
      </div>
    </div>
  );
}

// ── Main Page Component ──────────────────────────────────────────────

export default function KillChainPage() {
  const [selectedFramework, setSelectedFramework] = useState("lockheed_martin");
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("timeline");
  const { toast } = useToast();

  // 10.3: Fetch available frameworks
  const { data: frameworksResp } = useQuery<FrameworksResponse>({
    queryKey: ["/api/kill-chain/frameworks"],
    queryFn: () => apiRequest("GET", "/api/kill-chain/frameworks").then((r) => r.json()),
  });
  const frameworks = frameworksResp?.data?.frameworks || [];

  // 10.1 + 10.4: Fetch phases with auto-mapped alerts
  const {
    data: phasesResp,
    isPending: phasesPending,
    isError: phasesError,
    refetch: refetchPhases,
  } = useQuery<PhasesResponse>({
    queryKey: ["/api/kill-chain/phases", selectedFramework],
    queryFn: () => apiRequest("GET", `/api/kill-chain/phases?framework=${selectedFramework}`).then((r) => r.json()),
  });
  const phases = phasesResp?.data?.phases || [];
  const frameworkInfo = phasesResp?.data?.framework;

  // 10.5: Fetch analytics
  const { data: analyticsResp, isPending: analyticsPending } = useQuery<AnalyticsResponse>({
    queryKey: ["/api/kill-chain/analytics", selectedFramework],
    queryFn: () => apiRequest("GET", `/api/kill-chain/analytics?framework=${selectedFramework}`).then((r) => r.json()),
  });
  const analytics = analyticsResp?.data;

  // 10.6: Fetch incident correlation
  const { data: correlationResp, isPending: correlationPending } = useQuery<CorrelationResponse>({
    queryKey: ["/api/kill-chain/incident-correlation", selectedFramework],
    queryFn: () =>
      apiRequest("GET", `/api/kill-chain/incident-correlation?framework=${selectedFramework}`).then((r) => r.json()),
  });
  const correlation = correlationResp?.data;

  // 10.2: Fetch active campaigns
  const { data: campaignsResp, isPending: campaignsPending } = useQuery<CampaignsResponse>({
    queryKey: ["/api/kill-chain/active-campaigns", selectedFramework],
    queryFn: () =>
      apiRequest("GET", `/api/kill-chain/active-campaigns?framework=${selectedFramework}`).then((r) => r.json()),
  });
  const campaigns = campaignsResp?.data;

  // 10.7: Fetch response triggers
  const { data: triggersResp, isPending: triggersPending } = useQuery<TriggersResponse>({
    queryKey: ["/api/kill-chain/response-triggers", selectedFramework],
    queryFn: () =>
      apiRequest("GET", `/api/kill-chain/response-triggers?framework=${selectedFramework}`).then((r) => r.json()),
  });
  const triggers = triggersResp?.data;

  // 10.7: Mutation for configuring triggers
  const triggerMutation = useMutation({
    mutationFn: (body: { phaseId: string; action: string; enabled: boolean; framework: string }) =>
      apiRequest("POST", "/api/kill-chain/response-triggers", body),
    onSuccess: () => {
      toast({ title: "Response trigger updated", description: "Auto-response configuration saved." });
    },
    onError: () => {
      toast({ title: "Failed to update trigger", variant: "destructive" });
    },
  });

  // Computed stats
  const maxPhaseCount = useMemo(() => {
    return Math.max(...phases.map((p) => p.totalCount), 0);
  }, [phases]);

  const summaryStats = useMemo(() => {
    const activePhases = phases.filter((p) => p.totalCount > 0).length;
    const totalItems = phases.reduce((sum, p) => sum + p.totalCount, 0);
    const lateStageCount = phases.filter((p) => p.severity === "late" && p.totalCount > 0).length;
    const mostActive = phases.reduce((max, p) => (p.totalCount > max.totalCount ? p : max), phases[0]);
    return {
      activePhases,
      totalItems,
      lateStageCount,
      mostActiveName: mostActive?.name || "N/A",
    };
  }, [phases]);

  const handleTogglePhase = useCallback((phaseId: string) => {
    setExpandedPhase((prev) => (prev === phaseId ? null : phaseId));
  }, []);

  // Loading state
  if (phasesPending) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto">
        <div>
          <Skeleton className="h-8 w-64 mb-2" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              {Array.from({ length: 7 }).map((_, i) => (
                <Skeleton key={i} className="h-28 flex-1 rounded-md" />
              ))}
            </div>
          </CardContent>
        </Card>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-7 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  // Error state
  if (phasesError) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-kill-chain">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Kill Chain Analysis</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Interactive cyber kill chain timeline and attack progression analysis
          </p>
        </div>
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center justify-center text-center" role="alert">
              <AlertTriangle className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium">Could not load kill chain data</p>
              <p className="text-xs text-muted-foreground mt-1">Check your connection and try again.</p>
              <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchPhases()}>
                Try Again
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const hasData = phases.some((p) => p.totalCount > 0);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-kill-chain">
      {/* Header with framework selector */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            Kill Chain Analysis
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Interactive cyber kill chain timeline and attack progression analysis
          </p>
        </div>

        {/* 10.3: Framework selector */}
        <div className="flex items-center gap-2" data-testid="framework-selector">
          <span className="text-xs text-muted-foreground">Framework:</span>
          <Select value={selectedFramework} onValueChange={setSelectedFramework}>
            <SelectTrigger className="w-[260px] h-8 text-xs">
              <SelectValue placeholder="Select framework" />
            </SelectTrigger>
            <SelectContent>
              {frameworks.length > 0
                ? frameworks.map((fw) => (
                    <SelectItem key={fw.id} value={fw.id} className="text-xs">
                      {fw.name} ({fw.phaseCount} phases)
                    </SelectItem>
                  ))
                : [
                    { id: "lockheed_martin", name: "Lockheed Martin Cyber Kill Chain", phaseCount: 7 },
                    { id: "diamond_model", name: "Diamond Model", phaseCount: 4 },
                    { id: "unified_kill_chain", name: "Unified Kill Chain", phaseCount: 9 },
                    { id: "ics_kill_chain", name: "MITRE ATT&CK for ICS Kill Chain", phaseCount: 9 },
                  ].map((fw) => (
                    <SelectItem key={fw.id} value={fw.id} className="text-xs">
                      {fw.name} ({fw.phaseCount} phases)
                    </SelectItem>
                  ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="summary-stats">
        <StatCard title="Active Phases" value={summaryStats.activePhases} icon={Layers} loading={phasesPending} />
        <StatCard title="Total Items" value={summaryStats.totalItems} icon={Activity} loading={phasesPending} />
        <StatCard
          title="Late Stage Activity"
          value={summaryStats.lateStageCount}
          icon={AlertTriangle}
          loading={phasesPending}
          variant={summaryStats.lateStageCount > 0 ? "danger" : "default"}
        />
        <StatCard title="Most Active" value={summaryStats.mostActiveName} icon={TrendingUp} loading={phasesPending} />
      </div>

      {/* 10.1: Interactive Kill Chain Phases */}
      <Card data-testid="kill-chain-phases">
        <CardHeader className="pb-3 flex flex-row items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Layers className="h-4 w-4 text-muted-foreground" />
            {frameworkInfo?.name || "Kill Chain"} — Phase Overview
          </CardTitle>
          {hasData && (
            <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-blue-500" /> Early
              </span>
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-amber-500" /> Mid
              </span>
              <span className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-red-500" /> Late
              </span>
            </div>
          )}
        </CardHeader>
        <CardContent>
          {!hasData ? (
            <div className="flex flex-col items-center justify-center py-12 text-center" data-testid="empty-state">
              <AlertTriangle className="h-10 w-10 text-muted-foreground mb-3" />
              <p className="text-sm font-medium text-muted-foreground">No kill chain data available</p>
              <p className="text-xs text-muted-foreground mt-1">
                Alerts with MITRE tactic mappings will populate the kill chain
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto -mx-4 px-4 pb-2" data-testid="phases-scroll-container">
              <div className="flex items-start gap-1" style={{ minWidth: `${phases.length * 145}px` }}>
                {phases.map((phase, idx) => (
                  <div key={phase.id} className="flex items-start flex-1 min-w-[130px]">
                    <InteractivePhaseCard
                      phase={phase}
                      isExpanded={expandedPhase === phase.id}
                      onToggle={() => handleTogglePhase(phase.id)}
                      totalMax={maxPhaseCount}
                    />
                    {idx < phases.length - 1 && (
                      <div className="flex items-center px-0.5 flex-shrink-0 pt-10">
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground/40" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Tabbed interface: Timeline | Analytics | Incidents | Auto-Response */}
      <Tabs value={activeTab} onValueChange={setActiveTab} data-testid="kill-chain-tabs">
        <TabsList className="grid grid-cols-4 w-full max-w-[600px]">
          <TabsTrigger value="timeline" className="text-xs">
            <Play className="h-3 w-3 mr-1" /> Progression
          </TabsTrigger>
          <TabsTrigger value="analytics" className="text-xs">
            <BarChart3 className="h-3 w-3 mr-1" /> Analytics
          </TabsTrigger>
          <TabsTrigger value="incidents" className="text-xs">
            <GitBranch className="h-3 w-3 mr-1" /> Correlation
          </TabsTrigger>
          <TabsTrigger value="response" className="text-xs">
            <Settings2 className="h-3 w-3 mr-1" /> Auto-Response
          </TabsTrigger>
        </TabsList>

        {/* 10.2: Kill Chain Progression tab */}
        <TabsContent value="timeline" className="space-y-4" data-testid="tab-timeline">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Play className="h-4 w-4 text-muted-foreground" />
                Active Campaign Progression
              </CardTitle>
            </CardHeader>
            <CardContent>
              {campaignsPending ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={i} className="h-20 w-full rounded-md" />
                  ))}
                </div>
              ) : campaigns && campaigns.campaigns.length > 0 ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-muted-foreground mb-2">
                    <span>{campaigns.activeCampaignCount} active campaigns</span>
                    {campaigns.lateStageCount > 0 && (
                      <Badge variant="destructive" className="text-[9px]">
                        {campaigns.lateStageCount} at late stage
                      </Badge>
                    )}
                  </div>
                  {campaigns.campaigns.map((campaign) => (
                    <CampaignProgression key={campaign.incidentId} campaign={campaign} phases={phases} />
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <Shield className="h-8 w-8 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">No active campaigns detected</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Active incidents with MITRE tactic mappings will appear here
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 10.5: Analytics tab */}
        <TabsContent value="analytics" className="space-y-4" data-testid="tab-analytics">
          {analyticsPending ? (
            <Card>
              <CardContent className="p-6">
                <div className="space-y-3">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full rounded-md" />
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : analytics ? (
            <>
              {/* Summary stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatCard title="Total Detections" value={analytics.summary.totalDetections} icon={Activity} />
                <StatCard
                  title="Breakout Time"
                  value={analytics.summary.breakoutTimeHuman || "N/A"}
                  icon={Timer}
                  variant={analytics.summary.breakoutTimeMs > 0 ? "warning" : "default"}
                />
                <StatCard title="Avg Dwell Time" value={analytics.summary.avgDwellTimeHuman || "N/A"} icon={Clock} />
                <StatCard title="Most Targeted" value={analytics.summary.mostTargetedPhase} icon={Target} />
              </div>

              {/* Phase-by-phase analytics */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-muted-foreground" />
                    Detection Density by Phase
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {analytics.phaseStats.map((ps) => {
                      const maxDetections = Math.max(...analytics.phaseStats.map((s) => s.totalDetections), 1);
                      const barWidth = (ps.totalDetections / maxDetections) * 100;

                      return (
                        <div
                          key={ps.phaseId}
                          className="flex items-center gap-3"
                          data-testid={`analytics-phase-${ps.phaseId}`}
                        >
                          <div className="w-36 text-xs font-medium truncate flex-shrink-0">{ps.phaseName}</div>
                          <div className="flex-1 h-6 bg-muted/30 rounded-sm overflow-hidden relative">
                            <div
                              className="h-full bg-red-500/60 rounded-sm transition-all"
                              style={{ width: `${barWidth}%` }}
                            />
                            <span className="absolute inset-0 flex items-center px-2 text-[10px] font-medium tabular-nums">
                              {ps.totalDetections} detections
                            </span>
                          </div>
                          <div className="w-24 text-[10px] text-muted-foreground text-right flex-shrink-0 tabular-nums">
                            {ps.dwellTimeHuman || "0s"} dwell
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="py-8">
                <div className="flex flex-col items-center justify-center text-center">
                  <BarChart3 className="h-8 w-8 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">No analytics data available</p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* 10.6: Incident Correlation tab */}
        <TabsContent value="incidents" className="space-y-4" data-testid="tab-incidents">
          {correlationPending ? (
            <Card>
              <CardContent className="p-6">
                <div className="space-y-3">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full rounded-md" />
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : correlation ? (
            <>
              {/* Correlation summary */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatCard title="Total Incidents" value={correlation.summary.totalIncidents} icon={GitBranch} />
                <StatCard
                  title="Critical"
                  value={correlation.summary.criticalIncidents}
                  icon={AlertTriangle}
                  variant={correlation.summary.criticalIncidents > 0 ? "danger" : "default"}
                />
                <StatCard
                  title="Multi-Phase"
                  value={correlation.summary.multiPhaseIncidents}
                  icon={Layers}
                  variant={correlation.summary.multiPhaseIncidents > 0 ? "warning" : "default"}
                />
                <StatCard
                  title="Late Stage"
                  value={correlation.summary.lateStageIncidents}
                  icon={Flag}
                  variant={correlation.summary.lateStageIncidents > 0 ? "danger" : "default"}
                />
              </div>

              {/* Incident list */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-muted-foreground" />
                    Incidents by Kill Chain Progression
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {correlation.incidents.length > 0 ? (
                    <div className="space-y-2 max-h-[500px] overflow-y-auto">
                      {correlation.incidents.map((incident) => (
                        <Link
                          key={incident.id}
                          href={`/incidents/${incident.id}`}
                          className="flex items-center justify-between gap-3 p-3 rounded-md hover:bg-muted/50 transition-colors cursor-pointer"
                          data-testid={`correlation-incident-${incident.id}`}
                        >
                          <div className="flex items-center gap-3 min-w-0 flex-1">
                            <div className="flex flex-col items-center gap-0.5 flex-shrink-0">
                              <span className="text-lg font-bold tabular-nums">{incident.riskScore}</span>
                              <span className="text-[9px] text-muted-foreground uppercase">risk</span>
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="text-sm font-medium truncate">{incident.title}</div>
                              <div className="flex items-center gap-1 mt-1 flex-wrap">
                                {incident.phases.map((phase) => (
                                  <Badge
                                    key={phase.phaseId}
                                    variant="outline"
                                    className={`text-[9px] px-1 py-0 ${SEVERITY_COLORS[phase.severity] || ""}`}
                                  >
                                    {phase.phaseName}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <SeverityBadge severity={incident.severity} />
                            {incident.isCritical && (
                              <Badge variant="destructive" className="text-[9px] px-1 py-0">
                                Critical
                              </Badge>
                            )}
                          </div>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                      <Shield className="h-8 w-8 text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No correlated incidents found</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="py-8">
                <div className="flex flex-col items-center justify-center text-center">
                  <GitBranch className="h-8 w-8 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">No correlation data available</p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* 10.7: Auto-Response Triggers tab */}
        <TabsContent value="response" className="space-y-4" data-testid="tab-response">
          {triggersPending ? (
            <Card>
              <CardContent className="p-6">
                <div className="space-y-3">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-20 w-full rounded-md" />
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : triggers ? (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Settings2 className="h-4 w-4 text-muted-foreground" />
                  Autonomous Response Triggers
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground mb-4">
                  Configure automatic response actions triggered when activity is detected at specific kill chain
                  phases.
                </p>
                <div className="space-y-4">
                  {triggers.triggers.map((trigger) => {
                    const severityStyle = SEVERITY_COLORS[trigger.severity] || SEVERITY_COLORS.early;
                    const Icon = PHASE_ICONS[trigger.phaseName] || Target;

                    return (
                      <div
                        key={trigger.phaseId}
                        className="rounded-md border p-3"
                        data-testid={`trigger-phase-${trigger.phaseId}`}
                      >
                        <div className="flex items-center gap-2 mb-3">
                          <div className={`p-1 rounded-md ${severityStyle}`}>
                            <Icon className="h-3.5 w-3.5" />
                          </div>
                          <span className="text-sm font-medium">{trigger.phaseName}</span>
                          <Badge variant="outline" className={`text-[9px] px-1 py-0 ${severityStyle}`}>
                            {trigger.severity}
                          </Badge>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                          {triggers.availableActions.map((action) => {
                            const isRecommended = trigger.recommendedActions.includes(action.id);
                            const isConfigured = trigger.configuredActions.includes(action.id);
                            const ActionIcon = ACTION_ICONS[action.id] || Settings2;

                            return (
                              <Button
                                key={action.id}
                                variant={isConfigured ? "default" : isRecommended ? "outline" : "ghost"}
                                size="sm"
                                className={`text-[10px] h-8 justify-start gap-1.5 ${
                                  isRecommended && !isConfigured ? "border-dashed" : ""
                                }`}
                                onClick={() =>
                                  triggerMutation.mutate({
                                    phaseId: trigger.phaseId,
                                    action: action.id,
                                    enabled: !isConfigured,
                                    framework: selectedFramework,
                                  })
                                }
                                title={action.description}
                                data-testid={`trigger-action-${trigger.phaseId}-${action.id}`}
                              >
                                <ActionIcon className="h-3 w-3 flex-shrink-0" />
                                <span className="truncate">{action.name}</span>
                              </Button>
                            );
                          })}
                        </div>

                        {trigger.recommendedActions.length > 0 && (
                          <div className="text-[10px] text-muted-foreground mt-2">
                            Recommended: {trigger.recommendedActions.join(", ")}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-8">
                <div className="flex flex-col items-center justify-center text-center">
                  <Settings2 className="h-8 w-8 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">No trigger configuration available</p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
