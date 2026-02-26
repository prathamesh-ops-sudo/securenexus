import { useQuery } from "@tanstack/react-query";
import { useState, useMemo } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge, formatTimestamp } from "@/components/security-badges";
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
} from "lucide-react";
import type { Alert, Incident } from "@shared/schema";

const KILL_CHAIN_STAGES = [
  { name: "Reconnaissance", icon: Crosshair, tactics: ["reconnaissance", "resource_development"] as string[] },
  { name: "Weaponization", icon: Zap, tactics: ["credential_access", "discovery"] as string[] },
  { name: "Delivery", icon: Download, tactics: ["initial_access"] as string[] },
  { name: "Exploitation", icon: Bug, tactics: ["execution", "exploitation"] as string[] },
  {
    name: "Installation",
    icon: HardDrive,
    tactics: ["persistence", "privilege_escalation", "defense_evasion"] as string[],
  },
  { name: "Command & Control", icon: Wifi, tactics: ["command_and_control"] as string[] },
  {
    name: "Actions on Objectives",
    icon: Flag,
    tactics: ["collection", "exfiltration", "impact", "lateral_movement"] as string[],
  },
];

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const STAGE_COLORS: Record<string, string> = {
  Reconnaissance: "bg-blue-500",
  Weaponization: "bg-purple-500",
  Delivery: "bg-orange-500",
  Exploitation: "bg-red-500",
  Installation: "bg-rose-500",
  "Command & Control": "bg-pink-500",
  "Actions on Objectives": "bg-red-600",
};

type MappedItem = {
  type: "alert" | "incident";
  id: string;
  title: string;
  severity: string;
  createdAt: string | Date | null;
  source?: string;
  stage: string;
  mitreTactic: string;
};

function mapTacticToStage(tactic: string): string | null {
  const normalized = tactic.toLowerCase().replace(/\s+/g, "_");
  for (const stage of KILL_CHAIN_STAGES) {
    if (stage.tactics.includes(normalized)) {
      return stage.name;
    }
  }
  return null;
}

function getIntensityClass(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return "bg-muted/30 border-border";
  const ratio = count / maxCount;
  if (ratio >= 0.75) return "bg-red-500/25 border-red-500/50";
  if (ratio >= 0.5) return "bg-red-500/18 border-red-500/40";
  if (ratio >= 0.25) return "bg-red-500/12 border-red-500/30";
  return "bg-red-500/8 border-red-500/20";
}

function StatCard({
  title,
  value,
  icon: Icon,
  loading,
}: {
  title: string;
  value: string | number;
  icon: any;
  loading?: boolean;
}) {
  const testId = `stat-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <Card data-testid={testId}>
      <CardHeader className="flex flex-row items-center justify-between gap-1 space-y-0 pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</CardTitle>
        <div className="p-1.5 rounded-md bg-muted/50">
          <Icon className="h-3.5 w-3.5 text-muted-foreground" />
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

export default function KillChainPage() {
  const [selectedStage, setSelectedStage] = useState<string | null>(null);

  const {
    data: alerts,
    isLoading: alertsLoading,
    isError: alertsError,
    refetch: refetchAlerts,
  } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const {
    data: incidents,
    isLoading: incidentsLoading,
    isError: incidentsError,
    refetch: refetchIncidents,
  } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const isLoading = alertsLoading || incidentsLoading;

  const {
    mappedItems,
    stageData,
    maxCount,
    allItems: _allItems,
  } = useMemo(() => {
    const items: MappedItem[] = [];
    const stages = new Map<string, MappedItem[]>();

    KILL_CHAIN_STAGES.forEach((s) => stages.set(s.name, []));

    if (alerts) {
      for (const alert of alerts) {
        if (!alert.mitreTactic) continue;
        const stage = mapTacticToStage(alert.mitreTactic);
        if (!stage) continue;
        const item: MappedItem = {
          type: "alert",
          id: alert.id,
          title: alert.title,
          severity: alert.severity,
          createdAt: alert.createdAt,
          source: alert.source,
          stage,
          mitreTactic: alert.mitreTactic,
        };
        items.push(item);
        stages.get(stage)?.push(item);
      }
    }

    if (incidents) {
      for (const incident of incidents) {
        if (!incident.mitreTactics || incident.mitreTactics.length === 0) continue;
        for (const tactic of incident.mitreTactics) {
          const stage = mapTacticToStage(tactic);
          if (!stage) continue;
          const item: MappedItem = {
            type: "incident",
            id: incident.id,
            title: incident.title,
            severity: incident.severity,
            createdAt: incident.createdAt,
            stage,
            mitreTactic: tactic,
          };
          items.push(item);
          stages.get(stage)?.push(item);
        }
      }
    }

    let max = 0;
    for (const list of Array.from(stages.values())) {
      if (list.length > max) max = list.length;
    }

    const sorted = [...items].sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity] ?? 5;
      const sb = SEVERITY_ORDER[b.severity] ?? 5;
      if (sa !== sb) return sa - sb;
      const da = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const db = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return db - da;
    });

    return { mappedItems: items, stageData: stages, maxCount: max, allItems: sorted };
  }, [alerts, incidents]);

  const stats = useMemo(() => {
    const activatedStages = KILL_CHAIN_STAGES.filter((s) => (stageData.get(s.name)?.length ?? 0) > 0).length;

    let mostActiveName = "N/A";
    let mostActiveCount = 0;
    for (const [name, list] of Array.from(stageData.entries())) {
      if (list.length > mostActiveCount) {
        mostActiveCount = list.length;
        mostActiveName = name;
      }
    }

    let earliest: Date | null = null;
    let latest: Date | null = null;
    for (const item of mappedItems) {
      if (!item.createdAt) continue;
      const d = new Date(item.createdAt);
      if (!earliest || d < earliest) earliest = d;
      if (!latest || d > latest) latest = d;
    }

    let timeSpan = "N/A";
    if (earliest && latest) {
      const diffMs = latest.getTime() - earliest.getTime();
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);
      if (diffDays > 0) {
        timeSpan = `${diffDays}d ${diffHours % 24}h`;
      } else {
        timeSpan = `${diffHours}h`;
      }
    }

    const phaseCounts: Record<string, number> = { early: 0, mid: 0, late: 0 };
    const earlyStages = ["Reconnaissance", "Weaponization", "Delivery"];
    const midStages = ["Exploitation", "Installation"];
    const lateStages = ["Command & Control", "Actions on Objectives"];
    for (const [name, list] of Array.from(stageData.entries())) {
      if (earlyStages.includes(name)) phaseCounts.early += list.length;
      if (midStages.includes(name)) phaseCounts.mid += list.length;
      if (lateStages.includes(name)) phaseCounts.late += list.length;
    }
    let dominantPhase = "N/A";
    if (phaseCounts.early >= phaseCounts.mid && phaseCounts.early >= phaseCounts.late && phaseCounts.early > 0)
      dominantPhase = "Early (Recon)";
    else if (phaseCounts.mid >= phaseCounts.late && phaseCounts.mid > 0) dominantPhase = "Mid (Exploit)";
    else if (phaseCounts.late > 0) dominantPhase = "Late (Actions)";

    return { activatedStages, mostActiveName, timeSpan, dominantPhase };
  }, [stageData, mappedItems]);

  const selectedItems = useMemo(() => {
    if (!selectedStage) return [];
    const list = stageData.get(selectedStage) ?? [];
    return [...list].sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity] ?? 5;
      const sb = SEVERITY_ORDER[b.severity] ?? 5;
      if (sa !== sb) return sa - sb;
      const da = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const db = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return db - da;
    });
  }, [selectedStage, stageData]);

  const chronologicalItems = useMemo(() => {
    return [...mappedItems].sort((a, b) => {
      const da = a.createdAt ? new Date(a.createdAt).getTime() : 0;
      const db = b.createdAt ? new Date(b.createdAt).getTime() : 0;
      return db - da;
    });
  }, [mappedItems]);

  if (isLoading) {
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
                <Skeleton key={i} className="h-24 flex-1 rounded-md" />
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

  if (alertsError || incidentsError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load kill chain data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchAlerts();
            refetchIncidents();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  const hasData = mappedItems.length > 0;

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1400px] mx-auto" data-testid="page-kill-chain">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Kill Chain Analysis</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Interactive cyber kill chain timeline and attack progression analysis
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Card data-testid="kill-chain-timeline">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Layers className="h-4 w-4 text-muted-foreground" />
            Cyber Kill Chain Stages
          </CardTitle>
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
            <div className="overflow-x-auto -mx-4 px-4 pb-2" data-testid="timeline-scroll-container">
              <div className="flex items-stretch gap-1" style={{ minWidth: "900px" }}>
                {KILL_CHAIN_STAGES.map((stage, idx) => {
                  const count = stageData.get(stage.name)?.length ?? 0;
                  const isActive = count > 0;
                  const isSelected = selectedStage === stage.name;
                  const StageIcon = stage.icon;
                  const intensityClass = getIntensityClass(count, maxCount);

                  const stageItems = stageData.get(stage.name) ?? [];
                  const severityCounts: Record<string, number> = {};
                  for (const item of stageItems) {
                    severityCounts[item.severity] = (severityCounts[item.severity] || 0) + 1;
                  }

                  return (
                    <div key={stage.name} className="flex items-stretch flex-1 min-w-[120px]">
                      <button
                        className={`flex-1 rounded-md border p-3 text-left transition-colors ${intensityClass} ${isSelected ? "ring-2 ring-red-500/50" : ""} ${isActive ? "cursor-pointer" : "opacity-50 cursor-default"}`}
                        onClick={() => isActive && setSelectedStage(isSelected ? null : stage.name)}
                        data-testid={`stage-${stage.name.toLowerCase().replace(/\s+/g, "-")}`}
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <div className={`p-1 rounded-md ${isActive ? "bg-red-500/15" : "bg-muted/50"}`}>
                            <StageIcon
                              className={`h-3.5 w-3.5 ${isActive ? "text-red-500" : "text-muted-foreground"}`}
                            />
                          </div>
                          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                            {idx + 1}
                          </span>
                        </div>
                        <div className="text-xs font-medium mb-1 leading-tight">{stage.name}</div>
                        <div
                          className="text-lg font-bold tabular-nums"
                          data-testid={`count-${stage.name.toLowerCase().replace(/\s+/g, "-")}`}
                        >
                          {count}
                        </div>
                        <div className="text-[10px] text-muted-foreground mb-1.5">{count === 1 ? "item" : "items"}</div>
                        {isActive && (
                          <div className="flex flex-wrap gap-0.5 mt-1">
                            {Object.entries(severityCounts)
                              .slice(0, 3)
                              .map(([sev, c]) => (
                                <span
                                  key={sev}
                                  className="text-[9px] px-1 py-0 rounded bg-muted/50 text-muted-foreground"
                                  data-testid={`severity-count-${stage.name.toLowerCase().replace(/\s+/g, "-")}-${sev}`}
                                >
                                  {sev.slice(0, 4)} {c}
                                </span>
                              ))}
                          </div>
                        )}
                      </button>
                      {idx < KILL_CHAIN_STAGES.length - 1 && (
                        <div className="flex items-center px-0.5 flex-shrink-0">
                          <ArrowRight className="h-3.5 w-3.5 text-muted-foreground/40" />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {selectedStage && selectedItems.length > 0 && (
        <Card data-testid="stage-detail-panel">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Target className="h-4 w-4 text-muted-foreground" />
              {selectedStage} — {selectedItems.length} {selectedItems.length === 1 ? "item" : "items"}
            </CardTitle>
            <Button variant="ghost" size="sm" onClick={() => setSelectedStage(null)} data-testid="button-close-detail">
              Close
            </Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {selectedItems.map((item, idx) => (
                <Link
                  key={`${item.type}-${item.id}-${idx}`}
                  href={item.type === "alert" ? `/alerts/${item.id}` : `/incidents/${item.id}`}
                  className="flex items-center justify-between gap-3 p-3 rounded-md hover-elevate cursor-pointer"
                  data-testid={`detail-item-${item.type}-${item.id}`}
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <Badge variant="outline" className="text-[10px] flex-shrink-0">
                      {item.type}
                    </Badge>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium truncate">{item.title}</div>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        {item.source && <span className="text-[10px] text-muted-foreground">{item.source}</span>}
                        <span className="text-[10px] text-muted-foreground">{item.mitreTactic.replace(/_/g, " ")}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
                    <SeverityBadge severity={item.severity} />
                    <span className="text-[10px] text-muted-foreground tabular-nums flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatTimestamp(item.createdAt)}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="summary-stats">
        <StatCard title="Stages Activated" value={stats.activatedStages} icon={Layers} />
        <StatCard title="Most Active Stage" value={stats.mostActiveName} icon={Activity} />
        <StatCard title="Attack Time Span" value={stats.timeSpan} icon={Clock} />
        <StatCard title="Dominant Phase" value={stats.dominantPhase} icon={Shield} />
      </div>

      {hasData && (
        <Card data-testid="attack-timeline">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              Attack Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative pl-6 space-y-0 max-h-[500px] overflow-y-auto">
              <div className="absolute left-[11px] top-0 bottom-0 w-px bg-border" />
              {chronologicalItems.slice(0, 50).map((item, idx) => {
                const stageColor = STAGE_COLORS[item.stage] || "bg-muted";
                return (
                  <div
                    key={`${item.type}-${item.id}-${idx}`}
                    className="relative pb-4"
                    data-testid={`timeline-item-${idx}`}
                  >
                    <div
                      className={`absolute left-[-17px] top-1 w-2.5 h-2.5 rounded-full border-2 border-background ${stageColor}`}
                    />
                    <Link
                      href={item.type === "alert" ? `/alerts/${item.id}` : `/incidents/${item.id}`}
                      className="block p-3 rounded-md hover-elevate cursor-pointer"
                      data-testid={`timeline-link-${item.type}-${item.id}`}
                    >
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <Badge
                              variant="secondary"
                              className="text-[10px]"
                              data-testid={`timeline-stage-badge-${idx}`}
                            >
                              {item.stage}
                            </Badge>
                            <SeverityBadge severity={item.severity} />
                          </div>
                          <div className="text-sm font-medium">{item.title}</div>
                          <div className="flex items-center gap-2 mt-0.5 text-[10px] text-muted-foreground flex-wrap">
                            <span className="capitalize">{item.type}</span>
                            {item.source && (
                              <>
                                <span className="text-border">|</span>
                                <span>{item.source}</span>
                              </>
                            )}
                          </div>
                        </div>
                        <span className="text-[10px] text-muted-foreground tabular-nums flex items-center gap-1 flex-shrink-0">
                          <Clock className="h-3 w-3" />
                          {formatTimestamp(item.createdAt)}
                        </span>
                      </div>
                    </Link>
                  </div>
                );
              })}
              {chronologicalItems.length > 50 && (
                <div className="text-xs text-muted-foreground text-center py-3" data-testid="timeline-truncated">
                  Showing 50 of {chronologicalItems.length} items
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
