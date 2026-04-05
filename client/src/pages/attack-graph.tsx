import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { ErrorState } from "@/components/empty-state";
import {
  GitBranch,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronRight,
  Loader2,
  Shield,
  Target,
  Zap,
  Network,
  Fingerprint,
  TrendingDown,
  Beaker,
  Wrench,
  ArrowUpDown,
  ShieldAlert,
  Activity,
  BarChart3,
  XCircle,
  Minus,
  CloudCog,
  ListOrdered,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { formatRelativeTime } from "@/components/security-badges";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface AttackPathData {
  id: string;
  orgId: string | null;
  clusterId: string | null;
  campaignId: string | null;
  alertIds: string[] | null;
  entityIds: string[] | null;
  nodes: { id: string; type: "alert" | "entity"; data: Record<string, unknown> }[];
  edges: { source: string; target: string; weight: number; relationship: string }[];
  tacticsSequence: string[] | null;
  techniquesUsed: string[] | null;
  hopCount: number | null;
  confidence: number;
  timeSpanHours: number | null;
  firstAlertAt: string | null;
  lastAlertAt: string | null;
  createdAt: string | null;
}

interface CampaignData {
  id: string;
  orgId: string | null;
  name: string;
  fingerprint: string;
  tacticsSequence: string[] | null;
  entitySignature: string[] | null;
  sourceSignature: string[] | null;
  clusterIds: string[] | null;
  attackPathIds: string[] | null;
  confidence: number;
  alertCount: number | null;
  status: string;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface RiskScoreData {
  pathId: string;
  riskScore: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  factors: {
    hopCountScore: number;
    severityScore: number;
    blastRadiusScore: number;
    controlsScore: number;
    killChainCoverageScore: number;
    temporalScore: number;
  };
  blastRadius: {
    affectedEntityCount: number;
    affectedEntityTypes: string[];
    crownJewelsReached: boolean;
    highValueTargets: string[];
  };
  compensatingControls: { controlName: string; mitigationPercentage: number; applied: boolean }[];
}

interface RiskScoresResponse {
  scores: RiskScoreData[];
  summary: {
    totalPaths: number;
    criticalPaths: number;
    highPaths: number;
    mediumPaths: number;
    lowPaths: number;
    avgRiskScore: number;
    maxRiskScore: number;
  };
}

interface WhatIfDetail {
  pathId: string;
  originalRisk: number;
  modifiedRisk: number | null;
  eliminated: boolean;
  reason: string;
}

interface WhatIfResult {
  scenario: string;
  originalPathCount: number;
  modifiedPathCount: number;
  pathsEliminated: number;
  pathsReduced: string[];
  riskReduction: number;
  originalAvgRisk: number;
  modifiedAvgRisk: number;
  details: WhatIfDetail[];
}

interface GlobalRemediationResponse {
  recommendations: {
    action: string;
    category: string;
    totalImpact: number;
    pathsAffected: number;
    totalRiskReduction: number;
    effort: string;
  }[];
  summary: { totalPaths: number; avgRiskScore: number; criticalPaths: number; highPaths: number };
}

interface CSPMCorrelation {
  findingId: string;
  findingRule: string;
  findingSeverity: string;
  findingResource: string;
  findingDescription: string;
  findingRemediation: string | null;
  attackPathId: string;
  attackPathRisk: number;
  attackPathRiskLevel: string;
  relatedEntities: { type: unknown; value: unknown }[];
  correlationReason: string;
  combinedRiskScore: number;
}

interface VulnPrioritizationEntry {
  alertId: string;
  title: string;
  intrinsicSeverity: string;
  intrinsicSeverityScore: number;
  contextualPriority: number;
  contextualLevel: string;
  pathCount: number;
  maxPathRisk: number;
  avgPathRisk: number;
  onCrownJewelPath: boolean;
  attackPathIds: string[];
  priorityJustification: string;
  upliftReason: string | null;
}

const TACTIC_COLORS: Record<string, string> = {
  reconnaissance: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "resource-development": "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "initial-access": "text-orange-400 bg-orange-500/10 border-orange-500/20",
  execution: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  persistence: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  "privilege-escalation": "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  "defense-evasion": "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  "credential-access": "text-purple-400 bg-purple-500/10 border-purple-500/20",
  discovery: "text-purple-400 bg-purple-500/10 border-purple-500/20",
  "lateral-movement": "text-purple-400 bg-purple-500/10 border-purple-500/20",
  collection: "text-red-400 bg-red-500/10 border-red-500/20",
  "command-and-control": "text-red-400 bg-red-500/10 border-red-500/20",
  exfiltration: "text-red-500 bg-red-500/10 border-red-500/20",
  impact: "text-red-500 bg-red-500/10 border-red-500/20",
};

function getTacticColor(tactic: string): string {
  return TACTIC_COLORS[tactic] || "text-muted-foreground bg-muted/30 border-muted";
}

function formatTimeSpan(hours: number | null): string {
  if (hours === null || hours === undefined) return "N/A";
  if (hours < 24) return `${hours} hours`;
  const days = Math.round(hours / 24);
  return `${days} days`;
}

function getRiskColor(level: string): string {
  switch (level) {
    case "critical":
      return "text-red-500 bg-red-500/10 border-red-500/20";
    case "high":
      return "text-orange-400 bg-orange-500/10 border-orange-500/20";
    case "medium":
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
    case "low":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
    default:
      return "text-muted-foreground bg-muted/10 border-muted/20";
  }
}

function TacticBadge({ tactic }: { tactic: string }) {
  const colorClass = getTacticColor(tactic);
  return (
    <Badge
      variant="outline"
      className={`text-[9px] shrink-0 border ${colorClass}`}
      data-testid={`badge-tactic-${tactic}`}
    >
      {tactic}
    </Badge>
  );
}

function AttackPathNodeChain({ nodes }: { nodes: AttackPathData["nodes"] }) {
  if (!nodes || nodes.length === 0) {
    return <p className="text-xs text-muted-foreground">No nodes in this path</p>;
  }

  return (
    <div className="flex items-center gap-1 flex-wrap py-2">
      {nodes.map((node, idx) => (
        <div key={node.id} className="flex items-center gap-1">
          {node.type === "entity" ? (
            <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-blue-500/10 border border-blue-500/20">
              <Network className="h-3 w-3 text-blue-400" />
              <span className="text-[10px] text-blue-400 font-mono">
                {(node.data?.type as string) || "entity"}: {((node.data?.value as string) || node.id).substring(0, 20)}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-red-500/10 border border-red-500/20">
              <AlertTriangle className="h-3 w-3 text-red-400" />
              <span className="text-[10px] text-red-400 font-mono">
                {((node.data?.title as string) || node.id).substring(0, 25)}
              </span>
              {typeof node.data?.severity === "string" && (
                <Badge
                  variant="outline"
                  className={`text-[8px] ml-1 ${
                    node.data.severity === "critical"
                      ? "text-red-500 border-red-500/20"
                      : node.data.severity === "high"
                        ? "text-orange-400 border-orange-500/20"
                        : node.data.severity === "medium"
                          ? "text-yellow-400 border-yellow-500/20"
                          : "text-emerald-400 border-emerald-500/20"
                  }`}
                >
                  {String(node.data.severity)}
                </Badge>
              )}
            </div>
          )}
          {idx < nodes.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
        </div>
      ))}
    </div>
  );
}

// -----------------------------------------------------------------------
// 12.1: Risk Scoring Tab
// -----------------------------------------------------------------------
function RiskScoringTab() {
  const { data, isLoading } = useQuery<RiskScoresResponse>({
    queryKey: ["/api/attack-paths/risk-scores"],
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-48 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!data || data.scores.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <TrendingDown className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-sm text-muted-foreground">No attack paths to score.</p>
          <p className="text-xs text-muted-foreground mt-1">Run a graph scan to discover attack paths first.</p>
        </CardContent>
      </Card>
    );
  }

  const { scores, summary } = data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-red-500/10 border border-red-500/20">
                <ShieldAlert className="h-4 w-4 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.criticalPaths}</p>
                <p className="text-xs text-muted-foreground">Critical Paths</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-orange-500/10 border border-orange-500/20">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.highPaths}</p>
                <p className="text-xs text-muted-foreground">High Risk Paths</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-blue-500/10 border border-blue-500/20">
                <BarChart3 className="h-4 w-4 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.avgRiskScore}</p>
                <p className="text-xs text-muted-foreground">Avg Risk Score</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-purple-500/10 border border-purple-500/20">
                <Activity className="h-4 w-4 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.maxRiskScore}</p>
                <p className="text-xs text-muted-foreground">Max Risk Score</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Path ID</TableHead>
                <TableHead>
                  <div className="flex items-center gap-1">
                    Risk Score <ArrowUpDown className="h-3 w-3" />
                  </div>
                </TableHead>
                <TableHead>Risk Level</TableHead>
                <TableHead>Blast Radius</TableHead>
                <TableHead>Crown Jewels</TableHead>
                <TableHead>Hop</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Kill Chain</TableHead>
                <TableHead>Controls</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scores.map((score) => (
                <TableRow key={score.pathId}>
                  <TableCell>
                    <span className="font-mono text-xs">{score.pathId.substring(0, 8)}</span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Progress
                        value={score.riskScore}
                        className={`h-2 w-16 ${score.riskScore >= 80 ? "[&>div]:bg-red-500" : score.riskScore >= 60 ? "[&>div]:bg-orange-400" : score.riskScore >= 40 ? "[&>div]:bg-yellow-400" : "[&>div]:bg-emerald-400"}`}
                      />
                      <span className="text-sm font-bold">{score.riskScore}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={`text-[9px] ${getRiskColor(score.riskLevel)}`}>
                      {score.riskLevel}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="text-xs text-muted-foreground cursor-help">
                          {score.blastRadius.affectedEntityCount} entities (
                          {score.blastRadius.affectedEntityTypes.length} types)
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p className="text-xs">Types: {score.blastRadius.affectedEntityTypes.join(", ")}</p>
                        {score.blastRadius.highValueTargets.length > 0 && (
                          <p className="text-xs mt-1">
                            High-value: {score.blastRadius.highValueTargets.slice(0, 3).join(", ")}
                          </p>
                        )}
                      </TooltipContent>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    {score.blastRadius.crownJewelsReached ? (
                      <Badge variant="outline" className="text-[9px] text-red-500 bg-red-500/10 border-red-500/20">
                        Reached
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">No</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="text-xs">{score.factors.hopCountScore}</span>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs">{score.factors.severityScore}</span>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs">{score.factors.killChainCoverageScore}</span>
                  </TableCell>
                  <TableCell>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="text-xs cursor-help">{score.compensatingControls.length} controls</span>
                      </TooltipTrigger>
                      <TooltipContent>
                        {score.compensatingControls.map((c, i) => (
                          <p key={i} className="text-xs">
                            {c.applied ? "Applied" : "Missing"}: {c.controlName} (-{c.mitigationPercentage}%)
                          </p>
                        ))}
                      </TooltipContent>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// -----------------------------------------------------------------------
// 12.2: What-If Simulation Tab
// -----------------------------------------------------------------------
function WhatIfSimulationTab() {
  const [simType, setSimType] = useState<string>("remove_vulnerability");
  const [vulnId, setVulnId] = useState("");
  const [controlName, setControlName] = useState("");
  const [nodeId, setNodeId] = useState("");
  const [targetSeverity, setTargetSeverity] = useState("low");
  const [selectedTactics, setSelectedTactics] = useState<string[]>([]);
  const { toast } = useToast();

  const simMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { type: simType };
      if (simType === "remove_vulnerability") body.vulnerabilityId = vulnId;
      if (simType === "add_control") {
        body.controlName = controlName;
        body.affectedTactics = selectedTactics;
      }
      if (simType === "remove_node") body.nodeId = nodeId;
      if (simType === "patch_severity") body.targetSeverity = targetSeverity;
      const res = await apiRequest("POST", "/api/attack-paths/simulate", body);
      return (await res.json()) as WhatIfResult;
    },
    onError: (error: Error) => {
      toast({ title: "Simulation Failed", description: error.message, variant: "destructive" });
    },
  });

  const result = simMutation.data;

  const tacticOptions = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Beaker className="h-4 w-4 text-purple-400" />
            What-If Scenario Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label className="text-xs">Simulation Type</Label>
              <Select value={simType} onValueChange={setSimType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="remove_vulnerability">Patch a Vulnerability</SelectItem>
                  <SelectItem value="add_control">Add Security Control</SelectItem>
                  <SelectItem value="remove_node">Isolate/Remove Node</SelectItem>
                  <SelectItem value="patch_severity">Downgrade Severity</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {simType === "remove_vulnerability" && (
              <div className="space-y-2">
                <Label className="text-xs">Vulnerability / Alert ID</Label>
                <Input
                  placeholder="e.g. alert-uuid or CVE identifier"
                  value={vulnId}
                  onChange={(e) => setVulnId(e.target.value)}
                />
              </div>
            )}

            {simType === "add_control" && (
              <>
                <div className="space-y-2">
                  <Label className="text-xs">Control Name</Label>
                  <Input
                    placeholder="e.g. MFA, EDR, PAM"
                    value={controlName}
                    onChange={(e) => setControlName(e.target.value)}
                  />
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label className="text-xs">Affected Tactics (click to toggle)</Label>
                  <div className="flex flex-wrap gap-1">
                    {tacticOptions.map((t) => (
                      <Badge
                        key={t}
                        variant="outline"
                        className={`text-[9px] cursor-pointer ${selectedTactics.includes(t) ? "bg-purple-500/20 text-purple-400 border-purple-500/30" : "text-muted-foreground"}`}
                        onClick={() =>
                          setSelectedTactics((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]))
                        }
                      >
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              </>
            )}

            {simType === "remove_node" && (
              <div className="space-y-2">
                <Label className="text-xs">Node / Entity ID</Label>
                <Input
                  placeholder="Entity or node ID to isolate"
                  value={nodeId}
                  onChange={(e) => setNodeId(e.target.value)}
                />
              </div>
            )}

            {simType === "patch_severity" && (
              <div className="space-y-2">
                <Label className="text-xs">Target Severity</Label>
                <Select value={targetSeverity} onValueChange={setTargetSeverity}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="informational">Informational</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          <Button onClick={() => simMutation.mutate()} disabled={simMutation.isPending} className="w-full md:w-auto">
            {simMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Beaker className="h-4 w-4 mr-2" />
            )}
            Run Simulation
          </Button>
        </CardContent>
      </Card>

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{result.originalPathCount}</p>
                <p className="text-xs text-muted-foreground">Original Paths</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold text-emerald-400">{result.pathsEliminated}</p>
                <p className="text-xs text-muted-foreground">Paths Eliminated</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold text-blue-400">{result.riskReduction}</p>
                <p className="text-xs text-muted-foreground">Risk Reduction</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <div className="flex items-center justify-center gap-2">
                  <span className="text-lg text-red-400">{result.originalAvgRisk}</span>
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  <span className="text-lg text-emerald-400">{result.modifiedAvgRisk}</span>
                </div>
                <p className="text-xs text-muted-foreground">Avg Risk Change</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Simulation Details: {result.scenario}</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Path ID</TableHead>
                    <TableHead>Original Risk</TableHead>
                    <TableHead>Modified Risk</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.details.map((d) => (
                    <TableRow key={d.pathId}>
                      <TableCell>
                        <span className="font-mono text-xs">{d.pathId.substring(0, 8)}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm font-medium">{d.originalRisk}</span>
                      </TableCell>
                      <TableCell>
                        {d.eliminated ? (
                          <Badge
                            variant="outline"
                            className="text-[9px] text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                          >
                            Eliminated
                          </Badge>
                        ) : (
                          <span
                            className={`text-sm font-medium ${d.modifiedRisk !== null && d.modifiedRisk < d.originalRisk ? "text-emerald-400" : ""}`}
                          >
                            {d.modifiedRisk}
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        {d.eliminated ? (
                          <XCircle className="h-4 w-4 text-emerald-400" />
                        ) : d.modifiedRisk !== null && d.modifiedRisk < d.originalRisk ? (
                          <TrendingDown className="h-4 w-4 text-blue-400" />
                        ) : (
                          <Minus className="h-4 w-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground">{d.reason}</span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// 12.3: Remediation Recommendations Tab
// -----------------------------------------------------------------------
function RemediationTab() {
  const { data, isLoading } = useQuery<GlobalRemediationResponse>({
    queryKey: ["/api/attack-paths/global-remediation"],
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-48 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!data || data.recommendations.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <Wrench className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-sm text-muted-foreground">No remediation recommendations available.</p>
          <p className="text-xs text-muted-foreground mt-1">
            Discover attack paths first, then recommendations will be generated.
          </p>
        </CardContent>
      </Card>
    );
  }

  const categoryIcon = (cat: string) => {
    switch (cat) {
      case "patch":
        return <Shield className="h-4 w-4 text-red-400" />;
      case "control":
        return <ShieldAlert className="h-4 w-4 text-blue-400" />;
      case "architecture":
        return <Network className="h-4 w-4 text-purple-400" />;
      case "monitoring":
        return <Activity className="h-4 w-4 text-emerald-400" />;
      default:
        return <Wrench className="h-4 w-4 text-muted-foreground" />;
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold">{data.summary.totalPaths}</p>
            <p className="text-xs text-muted-foreground">Total Paths Analyzed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold">{data.summary.avgRiskScore}</p>
            <p className="text-xs text-muted-foreground">Avg Risk Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold text-red-400">{data.summary.criticalPaths}</p>
            <p className="text-xs text-muted-foreground">Critical Paths</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold">{data.recommendations.length}</p>
            <p className="text-xs text-muted-foreground">Recommendations</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Wrench className="h-4 w-4" />
            Global Remediation Recommendations (Ranked by Impact)
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">#</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Impact</TableHead>
                <TableHead>Effort</TableHead>
                <TableHead>Paths Affected</TableHead>
                <TableHead>Risk Reduction</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.recommendations.map((rec, idx) => (
                <TableRow key={idx}>
                  <TableCell>
                    <span className="text-sm font-bold text-muted-foreground">{idx + 1}</span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {categoryIcon(rec.category)}
                      <span className="text-xs font-medium">{rec.action}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-[9px]">
                      {rec.category}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Progress value={rec.totalImpact} className="h-1.5 w-12" />
                      <span className="text-xs">{rec.totalImpact}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-[9px] ${rec.effort === "low" ? "text-emerald-400 border-emerald-500/20" : rec.effort === "medium" ? "text-yellow-400 border-yellow-500/20" : "text-red-400 border-red-500/20"}`}
                    >
                      {rec.effort}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs">{rec.pathsAffected}</span>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs font-medium text-emerald-400">-{rec.totalRiskReduction}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// -----------------------------------------------------------------------
// 12.6: CSPM Correlation Tab
// -----------------------------------------------------------------------
function CSPMCorrelationTab() {
  const { data, isLoading } = useQuery<{ totalCorrelations: number; correlations: CSPMCorrelation[] }>({
    queryKey: ["/api/attack-paths/cspm-correlation"],
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-48 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!data || data.correlations.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <CloudCog className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-sm text-muted-foreground">No CSPM correlations found.</p>
          <p className="text-xs text-muted-foreground mt-1">
            Cloud misconfigurations will be correlated with attack paths when CSPM findings exist.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <CloudCog className="h-4 w-4 text-blue-400" />
          CSPM Finding to Attack Path Correlations ({data.totalCorrelations})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>CSPM Finding</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Attack Path Risk</TableHead>
              <TableHead>Combined Score</TableHead>
              <TableHead>Related Entities</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.correlations.slice(0, 50).map((c, idx) => (
              <TableRow key={idx}>
                <TableCell>
                  <span className="text-xs font-medium">{c.findingRule}</span>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className={`text-[9px] ${getRiskColor(c.findingSeverity)}`}>
                    {c.findingSeverity}
                  </Badge>
                </TableCell>
                <TableCell>
                  <span className="text-xs text-muted-foreground font-mono">
                    {c.findingResource.length > 30 ? `...${c.findingResource.slice(-30)}` : c.findingResource}
                  </span>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className={`text-[9px] ${getRiskColor(c.attackPathRiskLevel)}`}>
                    {c.attackPathRisk} ({c.attackPathRiskLevel})
                  </Badge>
                </TableCell>
                <TableCell>
                  <span className="text-sm font-bold">{c.combinedRiskScore}</span>
                </TableCell>
                <TableCell>
                  <span className="text-xs text-muted-foreground">{c.relatedEntities.length} entities</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// -----------------------------------------------------------------------
// 12.7: Vulnerability Prioritization Tab
// -----------------------------------------------------------------------
function VulnPrioritizationTab() {
  const { data, isLoading } = useQuery<{ totalVulnerabilities: number; prioritization: VulnPrioritizationEntry[] }>({
    queryKey: ["/api/attack-paths/vuln-prioritization"],
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-48 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!data || data.prioritization.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <ListOrdered className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
          <p className="text-sm text-muted-foreground">No vulnerability prioritization data.</p>
          <p className="text-xs text-muted-foreground mt-1">
            Run attack path discovery to enable context-aware vulnerability prioritization.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <ListOrdered className="h-4 w-4 text-orange-400" />
          Context-Aware Vulnerability Prioritization ({data.totalVulnerabilities})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Alert</TableHead>
              <TableHead>Intrinsic Severity</TableHead>
              <TableHead>Contextual Priority</TableHead>
              <TableHead>Crown Jewel Path</TableHead>
              <TableHead># Paths</TableHead>
              <TableHead>Max Path Risk</TableHead>
              <TableHead>Justification</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.prioritization.slice(0, 50).map((v) => (
              <TableRow key={v.alertId}>
                <TableCell>
                  <span className="text-xs font-medium">{v.title.substring(0, 40)}</span>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className={`text-[9px] ${getRiskColor(v.intrinsicSeverity)}`}>
                    {v.intrinsicSeverity}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Progress
                      value={v.contextualPriority}
                      className={`h-2 w-12 ${v.contextualPriority >= 80 ? "[&>div]:bg-red-500" : v.contextualPriority >= 60 ? "[&>div]:bg-orange-400" : "[&>div]:bg-yellow-400"}`}
                    />
                    <Badge variant="outline" className={`text-[9px] ${getRiskColor(v.contextualLevel)}`}>
                      {v.contextualPriority} ({v.contextualLevel})
                    </Badge>
                  </div>
                </TableCell>
                <TableCell>
                  {v.onCrownJewelPath ? (
                    <Badge variant="outline" className="text-[9px] text-red-500 bg-red-500/10 border-red-500/20">
                      Yes
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">No</span>
                  )}
                </TableCell>
                <TableCell>
                  <span className="text-xs">{v.pathCount}</span>
                </TableCell>
                <TableCell>
                  <span className="text-xs font-medium">{v.maxPathRisk}</span>
                </TableCell>
                <TableCell>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="text-xs text-muted-foreground cursor-help">
                        {v.priorityJustification.substring(0, 40)}...
                      </span>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs">
                      <p className="text-xs">{v.priorityJustification}</p>
                      {v.upliftReason && <p className="text-xs mt-1 text-yellow-400">{v.upliftReason}</p>}
                    </TooltipContent>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// -----------------------------------------------------------------------
// Main page component
// -----------------------------------------------------------------------
export default function AttackGraphPage() {
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const { toast } = useToast();

  const {
    data: attackPaths,
    isLoading: pathsLoading,
    isError: pathsError,
    refetch: refetchPaths,
  } = useQuery<AttackPathData[]>({
    queryKey: ["/api/attack-paths"],
  });

  const {
    data: campaigns,
    isLoading: campaignsLoading,
    isError: campaignsError,
    refetch: refetchCampaigns,
  } = useQuery<CampaignData[]>({
    queryKey: ["/api/campaigns"],
  });

  const discoverMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/attack-paths/discover", {});
      return res.json();
    },
    onSuccess: (data: Record<string, unknown>) => {
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths"] });
      queryClient.invalidateQueries({ queryKey: ["/api/campaigns"] });
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths/risk-scores"] });
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths/global-remediation"] });
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths/cspm-correlation"] });
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths/vuln-prioritization"] });
      toast({
        title: "Attack Path Discovery Complete",
        description: `Found ${data?.newAttackPaths ?? 0} attack paths, ${data?.campaignsCreated ?? 0} campaigns`,
      });
    },
    onError: (error: Error) => {
      toast({ title: "Discovery Failed", description: error.message, variant: "destructive" });
    },
  });

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/correlation/graph-scan", {});
      return res.json();
    },
    onSuccess: (data: Record<string, unknown>) => {
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths"] });
      queryClient.invalidateQueries({ queryKey: ["/api/campaigns"] });
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths/risk-scores"] });
      toast({
        title: "Graph Scan Complete",
        description: `Found ${data?.attackPaths ?? 0} attack paths and ${data?.campaigns ?? 0} campaigns`,
      });
    },
    onError: (error: Error) => {
      toast({ title: "Graph Scan Failed", description: error.message, variant: "destructive" });
    },
  });

  const stats = useMemo(() => {
    const paths = attackPaths || [];
    const camps = campaigns || [];
    const totalPaths = paths.length;
    const activeCampaigns = camps.length;
    const avgConfidence = totalPaths > 0 ? paths.reduce((sum, p) => sum + (p.confidence || 0), 0) / totalPaths : 0;
    const maxHops = totalPaths > 0 ? Math.max(...paths.map((p) => p.hopCount || 0)) : 0;
    return { totalPaths, activeCampaigns, avgConfidence, maxHops };
  }, [attackPaths, campaigns]);

  const toggleExpanded = (id: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const isLoading = pathsLoading || campaignsLoading;

  if (isLoading) {
    return (
      <div className="w-full p-4 md:p-6 space-y-6">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="space-y-1">
            <Skeleton className="h-7 w-48" />
            <Skeleton className="h-4 w-96" />
          </div>
          <Skeleton className="h-9 w-36" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <Skeleton className="h-12 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Card>
          <CardContent className="p-4 space-y-3">
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-48 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (pathsError || campaignsError) {
    return (
      <ErrorState
        title="Attack graph unavailable"
        message="We couldn't load attack path data. Your threat detection is still active."
        onRetry={() => {
          refetchPaths();
          refetchCampaigns();
        }}
        compact
      />
    );
  }

  return (
    <div className="w-full p-4 md:p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-md bg-red-500/10 border border-red-500/20">
              <GitBranch className="h-5 w-5 text-red-400" />
            </div>
            <h1 className="text-xl font-bold" data-testid="text-page-title">
              Attack Graph
            </h1>
          </div>
          <p className="text-sm text-muted-foreground" data-testid="text-page-description">
            Graph-based correlation engine — multi-hop attack path detection, risk scoring, and remediation analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => discoverMutation.mutate()}
            disabled={discoverMutation.isPending}
            data-testid="button-discover-paths"
          >
            {discoverMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Target className="h-4 w-4 mr-2" />
            )}
            Discover Paths
          </Button>
          <Button
            className="gradient-btn-red"
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending}
            data-testid="button-run-graph-scan"
          >
            {scanMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Zap className="h-4 w-4 mr-2" />
            )}
            Run Graph Scan
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card data-testid="stat-total-paths">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-red-500/10 border border-red-500/20">
                <GitBranch className="h-4 w-4 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.totalPaths}</p>
                <p className="text-xs text-muted-foreground">Total Attack Paths</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card data-testid="stat-active-campaigns">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-purple-500/10 border border-purple-500/20">
                <Target className="h-4 w-4 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.activeCampaigns}</p>
                <p className="text-xs text-muted-foreground">Active Campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card data-testid="stat-avg-confidence">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-yellow-500/10 border border-yellow-500/20">
                <Shield className="h-4 w-4 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{(stats.avgConfidence * 100).toFixed(0)}%</p>
                <p className="text-xs text-muted-foreground">Avg Confidence</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card data-testid="stat-max-hops">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-orange-500/10 border border-orange-500/20">
                <Zap className="h-4 w-4 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.maxHops}</p>
                <p className="text-xs text-muted-foreground">Max Hop Count</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="attack-paths" className="space-y-4">
        <TabsList data-testid="tabs-attack-graph" className="flex-wrap h-auto gap-1">
          <TabsTrigger value="attack-paths" data-testid="tab-attack-paths">
            Attack Paths
          </TabsTrigger>
          <TabsTrigger value="risk-scoring" data-testid="tab-risk-scoring">
            Risk Scoring
          </TabsTrigger>
          <TabsTrigger value="what-if" data-testid="tab-what-if">
            What-If Simulation
          </TabsTrigger>
          <TabsTrigger value="remediation" data-testid="tab-remediation">
            Remediation
          </TabsTrigger>
          <TabsTrigger value="cspm" data-testid="tab-cspm">
            CSPM Correlation
          </TabsTrigger>
          <TabsTrigger value="vuln-priority" data-testid="tab-vuln-priority">
            Vuln Priority
          </TabsTrigger>
          <TabsTrigger value="campaigns" data-testid="tab-campaigns">
            Campaigns
          </TabsTrigger>
        </TabsList>

        <TabsContent value="attack-paths">
          {!attackPaths || attackPaths.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center">
                <GitBranch className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground" data-testid="text-empty-paths">
                  No attack paths discovered yet.
                </p>
                <p className="text-xs text-muted-foreground mt-1">Run a graph scan to detect multi-hop attack paths.</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table data-testid="table-attack-paths">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8" />
                      <TableHead>Path ID</TableHead>
                      <TableHead>Tactics Sequence</TableHead>
                      <TableHead>Alerts</TableHead>
                      <TableHead>Entities</TableHead>
                      <TableHead>Hops</TableHead>
                      <TableHead>Time Span</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {attackPaths.map((path) => {
                      const isExpanded = expandedPaths.has(path.id);
                      return (
                        <TableRow key={path.id} className="cursor-pointer" data-testid={`row-attack-path-${path.id}`}>
                          <TableCell colSpan={9} className="p-0">
                            <div
                              className="flex items-center gap-0 px-4 py-3 hover-elevate"
                              onClick={() => toggleExpanded(path.id)}
                              data-testid={`button-expand-path-${path.id}`}
                            >
                              <div className="w-8 shrink-0">
                                {isExpanded ? (
                                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                ) : (
                                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                                )}
                              </div>
                              <div className="flex-1 grid grid-cols-8 gap-2 items-center">
                                <span className="font-mono text-xs" data-testid={`text-path-id-${path.id}`}>
                                  {path.id.substring(0, 8)}
                                </span>
                                <div className="col-span-2 flex items-center gap-1 flex-wrap">
                                  {(path.tacticsSequence || []).slice(0, 4).map((tactic, i) => (
                                    <TacticBadge key={`${tactic}-${i}`} tactic={tactic} />
                                  ))}
                                  {(path.tacticsSequence || []).length > 4 && (
                                    <Badge variant="outline" className="text-[9px]">
                                      +{(path.tacticsSequence || []).length - 4}
                                    </Badge>
                                  )}
                                </div>
                                <span
                                  className="text-xs text-muted-foreground"
                                  data-testid={`text-alert-count-${path.id}`}
                                >
                                  {(path.alertIds || []).length}
                                </span>
                                <span
                                  className="text-xs text-muted-foreground"
                                  data-testid={`text-entity-count-${path.id}`}
                                >
                                  {(path.entityIds || []).length}
                                </span>
                                <span
                                  className="text-xs text-muted-foreground"
                                  data-testid={`text-hop-count-${path.id}`}
                                >
                                  {path.hopCount ?? 0}
                                </span>
                                <span className="text-xs text-muted-foreground">
                                  {formatTimeSpan(path.timeSpanHours)}
                                </span>
                                <div className="flex items-center gap-1.5">
                                  <Progress value={path.confidence * 100} className="h-1 w-12" />
                                  <span className="text-xs font-medium" data-testid={`text-confidence-${path.id}`}>
                                    {(path.confidence * 100).toFixed(0)}%
                                  </span>
                                </div>
                              </div>
                              <span className="text-xs text-muted-foreground shrink-0 ml-2">
                                {formatRelativeTime(path.createdAt)}
                              </span>
                            </div>
                            {isExpanded && (
                              <div className="px-12 pb-4 border-t border-border/50">
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-3 mb-2">
                                  Attack Path Chain
                                </p>
                                <AttackPathNodeChain nodes={path.nodes} />
                                {path.techniquesUsed && path.techniquesUsed.length > 0 && (
                                  <div className="mt-3">
                                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                                      Techniques
                                    </p>
                                    <div className="flex gap-1 flex-wrap">
                                      {path.techniquesUsed.map((tech, i) => (
                                        <Badge
                                          key={`${tech}-${i}`}
                                          variant="outline"
                                          className="text-[9px] text-red-400 bg-red-500/10 border-red-500/20"
                                        >
                                          {tech}
                                        </Badge>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="risk-scoring">
          <RiskScoringTab />
        </TabsContent>

        <TabsContent value="what-if">
          <WhatIfSimulationTab />
        </TabsContent>

        <TabsContent value="remediation">
          <RemediationTab />
        </TabsContent>

        <TabsContent value="cspm">
          <CSPMCorrelationTab />
        </TabsContent>

        <TabsContent value="vuln-priority">
          <VulnPrioritizationTab />
        </TabsContent>

        <TabsContent value="campaigns">
          {!campaigns || campaigns.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center">
                <Fingerprint className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
                <p className="text-sm text-muted-foreground" data-testid="text-empty-campaigns">
                  No campaigns identified yet.
                </p>
                <p className="text-xs text-muted-foreground mt-1">Run a graph scan to fingerprint attack campaigns.</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table data-testid="table-campaigns">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Campaign Name</TableHead>
                      <TableHead>Fingerprint</TableHead>
                      <TableHead>Tactics</TableHead>
                      <TableHead>Entity Signature</TableHead>
                      <TableHead>Sources</TableHead>
                      <TableHead>Attack Paths</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>First Seen</TableHead>
                      <TableHead>Last Seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {campaigns.map((campaign) => (
                      <TableRow key={campaign.id} data-testid={`row-campaign-${campaign.id}`}>
                        <TableCell>
                          <span className="text-sm font-medium" data-testid={`text-campaign-name-${campaign.id}`}>
                            {campaign.name}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span
                                className="font-mono text-xs text-muted-foreground cursor-help"
                                data-testid={`text-fingerprint-${campaign.id}`}
                              >
                                {campaign.fingerprint.substring(0, 12)}
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p className="font-mono text-xs">{campaign.fingerprint}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {(campaign.tacticsSequence || []).slice(0, 3).map((tactic, i) => (
                              <TacticBadge key={`${tactic}-${i}`} tactic={tactic} />
                            ))}
                            {(campaign.tacticsSequence || []).length > 3 && (
                              <Badge variant="outline" className="text-[9px]">
                                +{(campaign.tacticsSequence || []).length - 3}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {(campaign.entitySignature || []).slice(0, 3).map((sig, i) => (
                              <Badge
                                key={`${sig}-${i}`}
                                variant="outline"
                                className="text-[9px] text-blue-400 bg-blue-500/10 border-blue-500/20"
                              >
                                {sig}
                              </Badge>
                            ))}
                            {(campaign.entitySignature || []).length > 3 && (
                              <Badge variant="outline" className="text-[9px]">
                                +{(campaign.entitySignature || []).length - 3}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {(campaign.sourceSignature || []).slice(0, 2).map((src, i) => (
                              <Badge
                                key={`${src}-${i}`}
                                variant="outline"
                                className="text-[9px] text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                              >
                                {src}
                              </Badge>
                            ))}
                            {(campaign.sourceSignature || []).length > 2 && (
                              <Badge variant="outline" className="text-[9px]">
                                +{(campaign.sourceSignature || []).length - 2}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <span
                            className="text-xs text-muted-foreground"
                            data-testid={`text-path-count-${campaign.id}`}
                          >
                            {(campaign.attackPathIds || []).length}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <Progress value={campaign.confidence * 100} className="h-1 w-12" />
                            <span
                              className="text-xs font-medium"
                              data-testid={`text-campaign-confidence-${campaign.id}`}
                            >
                              {(campaign.confidence * 100).toFixed(0)}%
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`text-[9px] ${
                              campaign.status === "active"
                                ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                                : "text-blue-400 bg-blue-500/10 border-blue-500/20"
                            }`}
                            data-testid={`badge-status-${campaign.id}`}
                          >
                            {campaign.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">
                            {formatRelativeTime(campaign.firstSeenAt)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">
                            {formatRelativeTime(campaign.lastSeenAt)}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
