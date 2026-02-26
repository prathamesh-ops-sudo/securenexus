import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
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
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
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
  nodes: { id: string; type: "alert" | "entity"; data: any }[];
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
                {node.data?.type || "entity"}: {(node.data?.value || node.id).substring(0, 20)}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-red-500/10 border border-red-500/20">
              <AlertTriangle className="h-3 w-3 text-red-400" />
              <span className="text-[10px] text-red-400 font-mono">
                {(node.data?.title || node.id).substring(0, 25)}
              </span>
              {node.data?.severity && (
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
                  {node.data.severity}
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

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/correlation/graph-scan", {});
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/attack-paths"] });
      queryClient.invalidateQueries({ queryKey: ["/api/campaigns"] });
      toast({
        title: "Graph Scan Complete",
        description: `Found ${data?.attackPaths ?? 0} attack paths and ${data?.campaigns ?? 0} campaigns`,
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Graph Scan Failed",
        description: error.message,
        variant: "destructive",
      });
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
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load attack graph data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchPaths();
            refetchCampaigns();
          }}
        >
          Try Again
        </Button>
      </div>
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
            Graph-based correlation engine — multi-hop attack path detection and campaign fingerprinting
          </p>
        </div>
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
        <TabsList data-testid="tabs-attack-graph">
          <TabsTrigger value="attack-paths" data-testid="tab-attack-paths">
            Attack Paths
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
