import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import { DashboardSkeleton } from "@/components/page-skeleton";
import {
  Shield,
  ShieldAlert,
  Target,
  Download,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Crosshair,
  Zap,
  Play,
  Clock,
  Eye,
  Layers,
  Activity,
  FileCode,
  Info,
} from "lucide-react";

// -- API helpers --------------------------------------------------------------

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

// -- Types --------------------------------------------------------------------

interface SubTechnique {
  id: string;
  name: string;
  description: string;
}

interface Technique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  subtechniques?: SubTechnique[];
  platforms?: string[];
  dataSources?: string[];
  mitigations?: string[];
  url: string;
}

interface Tactic {
  id: string;
  shortName: string;
  name: string;
  description: string;
  techniques: Technique[];
}

interface MatrixResponse {
  version: string;
  lastUpdated: string;
  tactics: Tactic[];
  totalTechniques: number;
  totalSubTechniques: number;
}

interface CoverageEntry {
  level: "high" | "medium" | "low" | "none";
  ruleCount: number;
  alertCount: number;
  detectionAlertCount: number;
}

interface GapEntry {
  id: string;
  name: string;
  tactic: string;
  parentTechnique: string | null;
}

interface CoverageResponse {
  summary: {
    totalTechniques: number;
    coveredTechniques: number;
    coveragePercent: number;
    highCoverage: number;
    mediumCoverage: number;
    lowCoverage: number;
    noCoverage: number;
    totalRules: number;
    totalAlerts: number;
  };
  coverage: Record<string, CoverageEntry>;
  gaps: GapEntry[];
}

interface TechniqueDetailRule {
  id: string;
  name: string;
  description: string | null;
  severity: string;
  status: string;
  match_count: number;
  last_match_at: string | null;
  created_at: string;
}

interface TechniqueDetailAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  detected_at?: string;
  created_at?: string;
  source?: string;
}

interface TechniqueDetailAsset {
  source_ip: string | null;
  destination_ip: string | null;
  alert_count: number;
}

interface TechniqueDetailResponse {
  technique: {
    id: string;
    name: string;
    description: string;
    tactics: string[];
    subtechniques?: SubTechnique[];
    platforms?: string[];
    dataSources?: string[];
    mitigations?: string[];
    url: string;
  };
  rules: TechniqueDetailRule[];
  alerts: TechniqueDetailAlert[];
  detectionAlerts: TechniqueDetailAlert[];
  affectedAssets: TechniqueDetailAsset[];
  coverageLevel: string;
}

interface SyncStatusResponse {
  version: string;
  lastUpdated: string;
  source: string;
  isStale: boolean;
  daysSinceUpdate: number;
  nextExpectedUpdate: string;
}

// -- Coverage color helpers ---------------------------------------------------

function coverageBgColor(level: string): string {
  switch (level) {
    case "high":
      return "bg-green-700";
    case "medium":
      return "bg-green-500";
    case "low":
      return "bg-green-300";
    case "none":
    default:
      return "bg-muted/30";
  }
}

function coverageTextColor(level: string): string {
  switch (level) {
    case "high":
      return "text-white";
    case "medium":
      return "text-white";
    case "low":
      return "text-green-900";
    case "none":
    default:
      return "text-muted-foreground";
  }
}

function coverageBadgeVariant(level: string): "default" | "secondary" | "outline" | "destructive" {
  switch (level) {
    case "high":
      return "default";
    case "medium":
      return "secondary";
    case "low":
      return "outline";
    case "none":
    default:
      return "destructive";
  }
}

function severityBadgeClass(severity: string): string {
  switch (severity) {
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

function formatDate(d: string | null): string {
  if (!d) return "\u2014";
  return new Date(d).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

// -- 9.1: Full ATT&CK Matrix Tab ---------------------------------------------

function MatrixTab({
  matrix,
  coverage,
  onSelectTechnique,
}: {
  matrix: MatrixResponse | undefined;
  coverage: CoverageResponse | undefined;
  onSelectTechnique: (id: string) => void;
}) {
  const [expandedTechniques, setExpandedTechniques] = useState<Set<string>>(new Set());
  const [searchFilter, setSearchFilter] = useState("");
  const [coverageFilter, setCoverageFilter] = useState<string>("all");

  const toggleExpand = useCallback((techId: string) => {
    setExpandedTechniques((prev) => {
      const next = new Set(prev);
      if (next.has(techId)) next.delete(techId);
      else next.add(techId);
      return next;
    });
  }, []);

  if (!matrix) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading matrix...</div>;
  }

  const coverageMap = coverage?.coverage || {};
  const lowerSearch = searchFilter.toLowerCase();

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search techniques by ID or name..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={coverageFilter} onValueChange={setCoverageFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Coverage level" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Coverage</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="none">None (Gaps)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Matrix grid */}
      <div className="overflow-x-auto -mx-4 px-4 pb-2">
        <div className="flex gap-1.5" style={{ minWidth: `${matrix.tactics.length * 160}px` }}>
          {matrix.tactics.map((tactic) => {
            const filteredTechniques = tactic.techniques.filter((tech) => {
              const matchSearch =
                !lowerSearch ||
                tech.id.toLowerCase().includes(lowerSearch) ||
                tech.name.toLowerCase().includes(lowerSearch);
              const techCoverage = coverageMap[tech.id];
              const level = techCoverage?.level || "none";
              const matchCoverage = coverageFilter === "all" || level === coverageFilter;
              return matchSearch && matchCoverage;
            });

            return (
              <div key={tactic.id} className="flex-1 min-w-[150px]">
                {/* Tactic header */}
                <div className="mb-2 px-1">
                  <div className="text-[10px] font-semibold text-center uppercase tracking-wider text-muted-foreground bg-muted/50 rounded py-1.5 px-1 leading-tight">
                    {tactic.name}
                  </div>
                  <div className="text-[9px] text-center text-muted-foreground mt-0.5">
                    {filteredTechniques.length} technique{filteredTechniques.length !== 1 ? "s" : ""}
                  </div>
                </div>

                {/* Techniques */}
                <div className="space-y-0.5">
                  {filteredTechniques.map((tech) => {
                    const techCoverage = coverageMap[tech.id];
                    const level = techCoverage?.level || "none";
                    const hasSubtechniques = tech.subtechniques && tech.subtechniques.length > 0;
                    const isExpanded = expandedTechniques.has(tech.id);

                    return (
                      <div key={tech.id}>
                        <div
                          className={`rounded px-1.5 py-1 cursor-pointer transition-colors hover:ring-1 hover:ring-foreground/20 ${coverageBgColor(level)}`}
                          onClick={() => onSelectTechnique(tech.id)}
                        >
                          <div className="flex items-center gap-1">
                            {hasSubtechniques && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleExpand(tech.id);
                                }}
                                className="p-0 h-3 w-3 flex-shrink-0"
                              >
                                {isExpanded ? (
                                  <ChevronDown className={`h-3 w-3 ${coverageTextColor(level)}`} />
                                ) : (
                                  <ChevronRight className={`h-3 w-3 ${coverageTextColor(level)}`} />
                                )}
                              </button>
                            )}
                            <div className="flex-1 min-w-0">
                              <div className={`text-[9px] font-mono ${coverageTextColor(level)}`}>{tech.id}</div>
                              <div className={`text-[10px] truncate ${coverageTextColor(level)}`}>{tech.name}</div>
                            </div>
                          </div>
                        </div>

                        {hasSubtechniques && isExpanded && (
                          <div className="ml-2 mt-0.5 space-y-0.5 border-l border-border/50 pl-1">
                            {tech.subtechniques!.map((sub) => {
                              const subCoverage = coverageMap[sub.id];
                              const subLevel = subCoverage?.level || "none";
                              if (coverageFilter !== "all" && subLevel !== coverageFilter) return null;
                              if (
                                lowerSearch &&
                                !sub.id.toLowerCase().includes(lowerSearch) &&
                                !sub.name.toLowerCase().includes(lowerSearch)
                              )
                                return null;

                              return (
                                <div
                                  key={sub.id}
                                  className={`rounded px-1.5 py-0.5 cursor-pointer transition-colors hover:ring-1 hover:ring-foreground/20 ${coverageBgColor(subLevel)}`}
                                  onClick={() => onSelectTechnique(sub.id)}
                                >
                                  <div className={`text-[9px] font-mono ${coverageTextColor(subLevel)}`}>{sub.id}</div>
                                  <div className={`text-[9px] truncate ${coverageTextColor(subLevel)}`}>{sub.name}</div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground pt-2 border-t">
        <span className="font-medium">Coverage:</span>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-green-700" />
          High (3+ rules)
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-green-500" />
          Medium (1-2 rules)
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-green-300" />
          Low (alerts only)
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-muted/50 border" />
          None
        </div>
      </div>
    </div>
  );
}

// -- 9.4: Coverage Gaps Tab ---------------------------------------------------

function GapsTab({
  coverage,
  onSelectTechnique,
  onGenerateRule,
  onSimulate,
  isGenerating,
  isSimulating,
}: {
  coverage: CoverageResponse | undefined;
  onSelectTechnique: (id: string) => void;
  onGenerateRule: (id: string, name: string) => void;
  onSimulate: (id: string, name: string) => void;
  isGenerating: boolean;
  isSimulating: boolean;
}) {
  const [gapSearch, setGapSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");

  if (!coverage) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading coverage...</div>;
  }

  const gaps = coverage.gaps || [];
  const filteredGaps = gaps.filter((g) => {
    const matchSearch =
      !gapSearch ||
      g.id.toLowerCase().includes(gapSearch.toLowerCase()) ||
      g.name.toLowerCase().includes(gapSearch.toLowerCase());
    const matchTactic = tacticFilter === "all" || g.tactic === tacticFilter;
    return matchSearch && matchTactic;
  });

  const tacticSet = new Set(gaps.map((g) => g.tactic));
  const uniqueTactics = Array.from(tacticSet).sort();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            Coverage Gaps ({gaps.length} uncovered techniques)
          </h3>
          <p className="text-sm text-muted-foreground">
            Techniques with no detection rules or alert coverage. Prioritize these for rule creation.
          </p>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search gaps..."
            value={gapSearch}
            onChange={(e) => setGapSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={tacticFilter} onValueChange={setTacticFilter}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="Filter by tactic" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tactics</SelectItem>
            {uniqueTactics.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {filteredGaps.length === 0 ? (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center justify-center text-center">
              <CheckCircle2 className="h-10 w-10 text-green-400 mb-3" />
              <p className="text-sm font-medium">No coverage gaps found</p>
              <p className="text-xs text-muted-foreground mt-1">All techniques have some level of detection coverage</p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-1">
          {filteredGaps.map((gap) => (
            <Card key={gap.id} className="hover:bg-muted/20 transition-colors">
              <CardContent className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 cursor-pointer min-w-0" onClick={() => onSelectTechnique(gap.id)}>
                    <div className="flex items-center gap-2">
                      <XCircle className="h-3.5 w-3.5 text-red-400 flex-shrink-0" />
                      <span className="text-sm font-mono font-medium">{gap.id}</span>
                      <span className="text-sm truncate">{gap.name}</span>
                      {gap.parentTechnique && (
                        <Badge variant="outline" className="text-[10px]">
                          Sub of {gap.parentTechnique}
                        </Badge>
                      )}
                    </div>
                    <div className="ml-5 mt-0.5">
                      <span className="text-xs text-muted-foreground">{gap.tactic}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs"
                      onClick={() => onGenerateRule(gap.id, gap.name)}
                      disabled={isGenerating}
                    >
                      <Zap className="h-3 w-3 mr-1" />
                      Generate Rule
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs"
                      onClick={() => onSimulate(gap.id, gap.name)}
                      disabled={isSimulating}
                    >
                      <Play className="h-3 w-3 mr-1" />
                      BAS Test
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

// -- 9.2: Heatmap Tab ---------------------------------------------------------

function HeatmapTab({
  matrix,
  coverage,
  onSelectTechnique,
}: {
  matrix: MatrixResponse | undefined;
  coverage: CoverageResponse | undefined;
  onSelectTechnique: (id: string) => void;
}) {
  if (!matrix || !coverage) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading heatmap...</div>;
  }

  const coverageMap = coverage.coverage || {};

  const tacticStats = matrix.tactics.map((tactic) => {
    let total = 0;
    let covered = 0;
    const techniqueIds: string[] = [];

    for (const tech of tactic.techniques) {
      total++;
      techniqueIds.push(tech.id);
      const c = coverageMap[tech.id];
      if (c && c.level !== "none") covered++;

      if (tech.subtechniques) {
        for (const sub of tech.subtechniques) {
          total++;
          techniqueIds.push(sub.id);
          const sc = coverageMap[sub.id];
          if (sc && sc.level !== "none") covered++;
        }
      }
    }

    return {
      tactic,
      total,
      covered,
      percent: total > 0 ? Math.round((covered / total) * 100) : 0,
      techniqueIds,
    };
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Coverage by Tactic</CardTitle>
          <CardDescription>Detection coverage percentage across MITRE ATT&CK tactics</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {tacticStats.map((ts) => (
              <div key={ts.tactic.id}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium truncate max-w-[200px]">{ts.tactic.name}</span>
                  <span className="text-xs font-mono text-muted-foreground">
                    {ts.covered}/{ts.total} ({ts.percent}%)
                  </span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      ts.percent >= 75
                        ? "bg-green-500"
                        : ts.percent >= 50
                          ? "bg-yellow-500"
                          : ts.percent >= 25
                            ? "bg-orange-500"
                            : "bg-red-500"
                    }`}
                    style={{ width: `${ts.percent}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Technique Heatmap</CardTitle>
          <CardDescription>Each cell represents a technique. Color intensity = coverage level.</CardDescription>
        </CardHeader>
        <CardContent>
          {tacticStats.map((ts) => (
            <div key={ts.tactic.id} className="mb-4">
              <div className="text-xs font-medium mb-1">{ts.tactic.name}</div>
              <div className="flex flex-wrap gap-1">
                {ts.techniqueIds.map((tid) => {
                  const c = coverageMap[tid];
                  const level = c?.level || "none";
                  return (
                    <div
                      key={tid}
                      className={`w-7 h-7 rounded flex items-center justify-center cursor-pointer transition-transform hover:scale-110 ${coverageBgColor(level)}`}
                      title={`${tid}: ${level} coverage (${c?.ruleCount || 0} rules, ${c?.alertCount || 0} alerts)`}
                      onClick={() => onSelectTechnique(tid)}
                    >
                      <span className={`text-[8px] font-mono ${coverageTextColor(level)}`}>
                        {tid.replace("T", "").split(".")[0]}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}

          <div className="flex items-center gap-4 mt-4 pt-3 border-t text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-green-700" />
              High
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-green-500" />
              Medium
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-green-300" />
              Low
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded bg-muted/50 border" />
              None
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// -- 9.7: Rule Mapping Tab ----------------------------------------------------

function RuleMappingTab({
  matrix,
  coverage,
  onSelectTechnique,
}: {
  matrix: MatrixResponse | undefined;
  coverage: CoverageResponse | undefined;
  onSelectTechnique: (id: string) => void;
}) {
  const [ruleSearch, setRuleSearch] = useState("");
  const [sortBy, setSortBy] = useState<"id" | "rules" | "alerts">("rules");

  const allTechniques = useMemo(() => {
    if (!matrix) return [];
    const result: Array<{ id: string; name: string; tactic: string }> = [];
    for (const tactic of matrix.tactics) {
      for (const tech of tactic.techniques) {
        result.push({ id: tech.id, name: tech.name, tactic: tactic.name });
        if (tech.subtechniques) {
          for (const sub of tech.subtechniques) {
            result.push({ id: sub.id, name: sub.name, tactic: tactic.name });
          }
        }
      }
    }
    return result;
  }, [matrix]);

  const coverageMap = coverage?.coverage || {};

  const filtered = useMemo(() => {
    const lowerSearch = ruleSearch.toLowerCase();
    const items = allTechniques
      .filter(
        (t) => !lowerSearch || t.id.toLowerCase().includes(lowerSearch) || t.name.toLowerCase().includes(lowerSearch),
      )
      .map((t) => ({
        ...t,
        coverage: coverageMap[t.id] || {
          level: "none" as const,
          ruleCount: 0,
          alertCount: 0,
          detectionAlertCount: 0,
        },
      }));

    items.sort((a, b) => {
      if (sortBy === "rules") return b.coverage.ruleCount - a.coverage.ruleCount;
      if (sortBy === "alerts") return b.coverage.alertCount - a.coverage.alertCount;
      return a.id.localeCompare(b.id);
    });

    return items;
  }, [allTechniques, coverageMap, ruleSearch, sortBy]);

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search techniques..."
            value={ruleSearch}
            onChange={(e) => setRuleSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={sortBy} onValueChange={(v) => setSortBy(v as "id" | "rules" | "alerts")}>
          <SelectTrigger className="w-[160px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="rules">Sort by Rules</SelectItem>
            <SelectItem value="alerts">Sort by Alerts</SelectItem>
            <SelectItem value="id">Sort by ID</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b">
              <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Technique</th>
              <th className="text-left py-2 px-3 text-xs font-medium text-muted-foreground">Tactic</th>
              <th className="text-center py-2 px-3 text-xs font-medium text-muted-foreground">Rules</th>
              <th className="text-center py-2 px-3 text-xs font-medium text-muted-foreground">Alerts</th>
              <th className="text-center py-2 px-3 text-xs font-medium text-muted-foreground">Coverage</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 100).map((item) => (
              <tr
                key={item.id}
                className="border-b border-border/50 hover:bg-muted/20 cursor-pointer"
                onClick={() => onSelectTechnique(item.id)}
              >
                <td className="py-2 px-3">
                  <span className="font-mono text-xs mr-2">{item.id}</span>
                  <span className="text-sm">{item.name}</span>
                </td>
                <td className="py-2 px-3 text-muted-foreground text-xs">{item.tactic}</td>
                <td className="py-2 px-3 text-center tabular-nums">{item.coverage.ruleCount}</td>
                <td className="py-2 px-3 text-center tabular-nums">
                  {item.coverage.alertCount + item.coverage.detectionAlertCount}
                </td>
                <td className="py-2 px-3 text-center">
                  <Badge variant={coverageBadgeVariant(item.coverage.level)} className="text-[10px] capitalize">
                    {item.coverage.level}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length > 100 && (
          <p className="text-xs text-muted-foreground text-center py-2">
            Showing 100 of {filtered.length} techniques. Use search to narrow results.
          </p>
        )}
      </div>
    </div>
  );
}

// -- 9.3: Technique Detail Dialog ---------------------------------------------

function TechniqueDetailDialog({
  techniqueId,
  open,
  onClose,
  onGenerateRule,
  onSimulate,
  isGenerating,
  isSimulating,
}: {
  techniqueId: string | null;
  open: boolean;
  onClose: () => void;
  onGenerateRule: (id: string, name: string) => void;
  onSimulate: (id: string, name: string) => void;
  isGenerating: boolean;
  isSimulating: boolean;
}) {
  const { data: detail, isLoading } = useQuery<TechniqueDetailResponse>({
    queryKey: ["/api/mitre-attack/technique", techniqueId],
    queryFn: () => apiFetch(`/api/mitre-attack/technique/${techniqueId}`),
    enabled: !!techniqueId && open,
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            {isLoading ? "Loading..." : `${detail?.technique.id} \u2014 ${detail?.technique.name}`}
          </DialogTitle>
          <DialogDescription>
            {detail?.technique.description
              ? detail.technique.description.slice(0, 200) + (detail.technique.description.length > 200 ? "..." : "")
              : ""}
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="py-8 text-center text-muted-foreground">Loading technique details...</div>
        ) : detail ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Coverage Level</div>
                <Badge variant={coverageBadgeVariant(detail.coverageLevel)} className="capitalize">
                  {detail.coverageLevel}
                </Badge>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Tactics</div>
                <div className="flex flex-wrap gap-1">
                  {detail.technique.tactics.map((t) => (
                    <Badge key={t} variant="outline" className="text-[10px]">
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>
              {detail.technique.platforms && detail.technique.platforms.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Platforms</div>
                  <div className="flex flex-wrap gap-1">
                    {detail.technique.platforms.map((pl) => (
                      <Badge key={pl} variant="outline" className="text-[10px]">
                        {pl}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {detail.technique.dataSources && detail.technique.dataSources.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Data Sources</div>
                  <div className="flex flex-wrap gap-1">
                    {detail.technique.dataSources.map((ds) => (
                      <Badge key={ds} variant="outline" className="text-[10px]">
                        {ds}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {detail.technique.subtechniques && detail.technique.subtechniques.length > 0 && (
              <div>
                <div className="text-xs font-medium mb-1">Sub-Techniques ({detail.technique.subtechniques.length})</div>
                <div className="flex flex-wrap gap-1">
                  {detail.technique.subtechniques.map((sub) => (
                    <Badge key={sub.id} variant="secondary" className="text-[10px]">
                      {sub.id}: {sub.name}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            <div>
              <div className="text-xs font-medium mb-2 flex items-center gap-1">
                <FileCode className="h-3 w-3" />
                Detection Rules ({detail.rules.length})
              </div>
              {detail.rules.length === 0 ? (
                <div className="text-xs text-muted-foreground bg-muted/30 rounded p-3 text-center">
                  No detection rules mapped to this technique
                </div>
              ) : (
                <div className="space-y-1">
                  {detail.rules.map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between bg-muted/20 rounded px-3 py-2">
                      <div>
                        <span className="text-sm font-medium">{rule.name}</span>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge className={`text-[10px] ${severityBadgeClass(rule.severity)}`}>{rule.severity}</Badge>
                          <span className="text-[10px] text-muted-foreground">{rule.match_count} matches</span>
                          {rule.last_match_at && (
                            <span className="text-[10px] text-muted-foreground">
                              Last: {formatDate(rule.last_match_at)}
                            </span>
                          )}
                        </div>
                      </div>
                      <Badge variant={rule.status === "enabled" ? "default" : "outline"} className="text-[10px]">
                        {rule.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <div className="text-xs font-medium mb-2 flex items-center gap-1">
                <ShieldAlert className="h-3 w-3" />
                Recent Alerts ({detail.alerts.length + detail.detectionAlerts.length})
              </div>
              {detail.alerts.length === 0 && detail.detectionAlerts.length === 0 ? (
                <div className="text-xs text-muted-foreground bg-muted/30 rounded p-3 text-center">
                  No recent alerts for this technique
                </div>
              ) : (
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {[...detail.alerts, ...detail.detectionAlerts].slice(0, 10).map((alert) => (
                    <div key={alert.id} className="flex items-center justify-between bg-muted/20 rounded px-3 py-1.5">
                      <span className="text-xs truncate max-w-[300px]">{alert.title}</span>
                      <div className="flex items-center gap-2">
                        <Badge className={`text-[10px] ${severityBadgeClass(alert.severity)}`}>{alert.severity}</Badge>
                        <span className="text-[10px] text-muted-foreground">{alert.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {detail.affectedAssets.length > 0 && (
              <div>
                <div className="text-xs font-medium mb-2 flex items-center gap-1">
                  <Layers className="h-3 w-3" />
                  Affected Assets ({detail.affectedAssets.length})
                </div>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {detail.affectedAssets.map((asset, i) => (
                    <div key={i} className="flex items-center justify-between bg-muted/20 rounded px-3 py-1.5">
                      <span className="text-xs font-mono">
                        {asset.source_ip || "?"} {"\u2192"} {asset.destination_ip || "?"}
                      </span>
                      <span className="text-[10px] text-muted-foreground">{asset.alert_count} alerts</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {detail.technique.url && (
              <div className="text-xs">
                <a
                  href={detail.technique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline flex items-center gap-1"
                >
                  <Info className="h-3 w-3" />
                  View on MITRE ATT&CK
                </a>
              </div>
            )}
          </div>
        ) : null}

        <DialogFooter className="flex-row gap-2">
          {detail && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onGenerateRule(detail.technique.id, detail.technique.name)}
                disabled={isGenerating}
              >
                <Zap className="h-3 w-3 mr-1" />
                Generate Rule
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onSimulate(detail.technique.id, detail.technique.name)}
                disabled={isSimulating}
              >
                <Play className="h-3 w-3 mr-1" />
                BAS Test
              </Button>
            </>
          )}
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// -- 9.6: Sync Status Panel ---------------------------------------------------

function SyncStatusPanel({ syncStatus }: { syncStatus: SyncStatusResponse | undefined }) {
  if (!syncStatus) return null;

  return (
    <Card>
      <CardContent className="py-3 px-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <span className="text-xs font-medium">MITRE ATT&CK v{syncStatus.version}</span>
            </div>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Clock className="h-3 w-3" />
              Updated: {formatDate(syncStatus.lastUpdated)}
            </div>
            <div className="text-xs text-muted-foreground">({syncStatus.daysSinceUpdate} days ago)</div>
          </div>
          <div className="flex items-center gap-2">
            {syncStatus.isStale ? (
              <Badge variant="destructive" className="text-[10px]">
                <AlertTriangle className="h-3 w-3 mr-1" />
                Stale Data
              </Badge>
            ) : (
              <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/30">
                <CheckCircle2 className="h-3 w-3 mr-1" />
                Up to Date
              </Badge>
            )}
            <span className="text-[10px] text-muted-foreground">Source: {syncStatus.source}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// -- Main Page Component ------------------------------------------------------

export default function MitreAttackPage() {
  usePageTitle("MITRE ATT&CK Coverage");
  const { toast } = useToast();
  const qc = useQueryClient();

  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const { data: matrixData, isLoading: matrixLoading } = useQuery<MatrixResponse>({
    queryKey: ["/api/mitre-attack/matrix"],
    queryFn: () => apiFetch("/api/mitre-attack/matrix"),
  });

  const { data: coverageData, isLoading: coverageLoading } = useQuery<CoverageResponse>({
    queryKey: ["/api/mitre-attack/coverage"],
    queryFn: () => apiFetch("/api/mitre-attack/coverage"),
  });

  const { data: syncData } = useQuery<SyncStatusResponse>({
    queryKey: ["/api/mitre-attack/sync-status"],
    queryFn: () => apiFetch("/api/mitre-attack/sync-status"),
  });

  const exportNavigator = useCallback(async () => {
    try {
      const data = await apiFetch("/api/mitre-attack/navigator-export");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mitre-attack-navigator-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: "Navigator layer exported" });
    } catch (err) {
      toast({
        title: "Export failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  }, [toast]);

  const generateRuleMutation = useMutation({
    mutationFn: (params: { techniqueId: string; techniqueName: string }) =>
      apiFetch("/api/mitre-attack/generate-rule", {
        method: "POST",
        body: JSON.stringify(params),
      }),
    onSuccess: (data: { rule: { name: string } }) => {
      qc.invalidateQueries({ queryKey: ["/api/mitre-attack/coverage"] });
      toast({ title: "Detection rule created", description: data.rule.name });
    },
    onError: (err: Error) =>
      toast({ title: "Rule generation failed", description: err.message, variant: "destructive" }),
  });

  const simulateMutation = useMutation({
    mutationFn: (params: { techniqueId: string; techniqueName: string }) =>
      apiFetch("/api/mitre-attack/simulate", {
        method: "POST",
        body: JSON.stringify(params),
      }),
    onSuccess: (data: { scenario: { name: string } }) => {
      toast({ title: "BAS scenario created", description: data.scenario.name });
    },
    onError: (err: Error) => toast({ title: "Simulation failed", description: err.message, variant: "destructive" }),
  });

  const handleSelectTechnique = useCallback((id: string) => {
    setSelectedTechnique(id);
    setDetailOpen(true);
  }, []);

  const handleGenerateRule = useCallback(
    (id: string, name: string) => {
      generateRuleMutation.mutate({ techniqueId: id, techniqueName: name });
    },
    [generateRuleMutation],
  );

  const handleSimulate = useCallback(
    (id: string, name: string) => {
      simulateMutation.mutate({ techniqueId: id, techniqueName: name });
    },
    [simulateMutation],
  );

  if (matrixLoading && coverageLoading) {
    return <DashboardSkeleton />;
  }

  const summary = coverageData?.summary;

  return (
    <div className="p-4 md:p-6 space-y-4 max-w-[1600px] mx-auto" data-testid="page-mitre-attack">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
            MITRE ATT&CK Coverage
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Enterprise ATT&CK matrix with detection coverage analysis, gap identification, and rule mapping
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={exportNavigator}>
            <Download className="h-4 w-4 mr-1" />
            Export Navigator
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              qc.invalidateQueries({ queryKey: ["/api/mitre-attack/matrix"] });
              qc.invalidateQueries({ queryKey: ["/api/mitre-attack/coverage"] });
              qc.invalidateQueries({ queryKey: ["/api/mitre-attack/sync-status"] });
            }}
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <SyncStatusPanel syncStatus={syncData} />

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-blue-400" />
                <span className="text-[10px] text-muted-foreground uppercase">Total</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums">{summary.totalTechniques}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <Eye className="h-4 w-4 text-green-400" />
                <span className="text-[10px] text-muted-foreground uppercase">Covered</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums">{summary.coveredTechniques}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-green-600" />
                <span className="text-[10px] text-muted-foreground uppercase">Coverage</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums">{summary.coveragePercent}%</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-green-700" />
                <span className="text-[10px] text-muted-foreground uppercase">High</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums">{summary.highCoverage}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
                <span className="text-[10px] text-muted-foreground uppercase">Medium</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums">{summary.mediumCoverage}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-green-300" />
                <span className="text-[10px] text-muted-foreground uppercase">Low</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums">{summary.lowCoverage}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <span className="text-[10px] text-muted-foreground uppercase">Gaps</span>
              </div>
              <p className="text-xl font-bold mt-1 tabular-nums text-red-400">{summary.noCoverage}</p>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs defaultValue="matrix" className="space-y-4">
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="matrix" className="text-xs">
            <Layers className="h-3.5 w-3.5 mr-1" />
            ATT&CK Matrix
          </TabsTrigger>
          <TabsTrigger value="heatmap" className="text-xs">
            <Activity className="h-3.5 w-3.5 mr-1" />
            Heatmap
          </TabsTrigger>
          <TabsTrigger value="gaps" className="text-xs">
            <AlertTriangle className="h-3.5 w-3.5 mr-1" />
            Coverage Gaps
            {summary && summary.noCoverage > 0 && (
              <Badge variant="destructive" className="ml-1 text-[10px] px-1.5">
                {summary.noCoverage}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="mapping" className="text-xs">
            <FileCode className="h-3.5 w-3.5 mr-1" />
            Rule Mapping
          </TabsTrigger>
        </TabsList>

        <TabsContent value="matrix">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Layers className="h-4 w-4" />
                Enterprise ATT&CK Matrix
              </CardTitle>
              <CardDescription>
                Full MITRE ATT&CK v{matrixData?.version || "15.1"} matrix with {matrixData?.totalTechniques || 0}{" "}
                techniques and {matrixData?.totalSubTechniques || 0} sub-techniques. Click to expand sub-techniques.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <MatrixTab matrix={matrixData} coverage={coverageData} onSelectTechnique={handleSelectTechnique} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="heatmap">
          <HeatmapTab matrix={matrixData} coverage={coverageData} onSelectTechnique={handleSelectTechnique} />
        </TabsContent>

        <TabsContent value="gaps">
          <Card>
            <CardContent className="pt-6">
              <GapsTab
                coverage={coverageData}
                onSelectTechnique={handleSelectTechnique}
                onGenerateRule={handleGenerateRule}
                onSimulate={handleSimulate}
                isGenerating={generateRuleMutation.isPending}
                isSimulating={simulateMutation.isPending}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="mapping">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <FileCode className="h-4 w-4" />
                Technique-to-Rule Mapping
              </CardTitle>
              <CardDescription>
                Bidirectional mapping between detection rules and ATT&CK techniques. Click any row for details.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RuleMappingTab matrix={matrixData} coverage={coverageData} onSelectTechnique={handleSelectTechnique} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <TechniqueDetailDialog
        techniqueId={selectedTechnique}
        open={detailOpen}
        onClose={() => {
          setDetailOpen(false);
          setSelectedTechnique(null);
        }}
        onGenerateRule={handleGenerateRule}
        onSimulate={handleSimulate}
        isGenerating={generateRuleMutation.isPending}
        isSimulating={simulateMutation.isPending}
      />
    </div>
  );
}
