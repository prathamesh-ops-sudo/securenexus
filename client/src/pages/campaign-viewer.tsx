import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Target,
  AlertTriangle,
  RefreshCw,
  Search,
  Globe,
  Shield,
  Users,
  Calendar,
  Plus,
  ChevronRight,
  ArrowLeft,
  Network,
  Activity,
  Crosshair,
  Skull,
  Clock,
  Zap,
  Link2,
  Trash2,
  CheckCircle,
  XCircle,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

// ── Types ──

interface CampaignListItem {
  id: string;
  name: string;
  fingerprint: string;
  tacticsSequence: string[] | null;
  entitySignature: string[] | null;
  sourceSignature: string[] | null;
  confidence: number;
  alertCount: number | null;
  status: string;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
}

interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  motivation: string;
  capability: string;
  country: string;
  description: string;
  targetedSectors: string[];
}

interface KillChainPhase {
  phase: string;
  label: string;
  order: number;
  description: string;
  observed: boolean;
  firstObserved: string | null;
  evidenceCount: number;
}

interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  observed: boolean;
}

interface CampaignDetail {
  id: string;
  name: string;
  description: string;
  status: string;
  confidence: number;
  firstSeen: string | null;
  lastSeen: string | null;
  alertCount: number;
  threatActor: ThreatActor;
  targetSectors: string[];
  targetRegions: string[];
  techniques: string[];
  attackTechniques: AttackTechnique[];
  iocRefs: string[];
  killChain: KillChainPhase[];
  killChainProgress: number;
  killChainTotal: number;
  maturity: string;
  predictedNextPhase: string | null;
  relatedAlerts: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    createdAt: string;
    mitreTactic: string | null;
    mitreTechnique: string | null;
    sourceIp: string | null;
    hostname: string | null;
  }>;
  relatedIocs: Array<{
    id: string;
    iocType: string;
    iocValue: string;
    confidence: number;
    severity: string;
    source: string;
    status: string;
    firstSeen: string | null;
  }>;
  iocCount: number;
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: string;
  title: string;
  description: string;
  severity: string;
  killChainPhase: string | null;
}

interface CampaignTimeline {
  campaignId: string;
  campaignName: string;
  firstSeen: string;
  lastSeen: string;
  status: string;
  durationDays: number;
  events: TimelineEvent[];
  activityPeriods: Array<{ month: string; eventCount: number; peakDay: string | null }>;
  peakActivity: string | null;
}

interface RelationshipNode {
  id: string;
  type: "campaign" | "threat_actor" | "technique" | "malware";
  label: string;
  status?: string;
  confidence?: number;
}

interface RelationshipEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  weight: number;
}

interface CampaignRelationships {
  nodes: RelationshipNode[];
  edges: RelationshipEdge[];
  sharedRelationships: Array<{
    campaign1: string;
    campaign2: string;
    sharedTechniques: string[];
    relationshipStrength: number;
  }>;
  summary: {
    totalCampaigns: number;
    totalActors: number;
    totalTechniques: number;
    totalRelationships: number;
    sharedTechniqueLinks: number;
  };
}

interface AttackMatrixTactic {
  tacticId: string;
  tacticName: string;
  techniques: Array<{
    id: string;
    name: string;
    observed?: boolean;
    confidence?: number;
    evidenceCount?: number;
    campaignCount?: number;
    campaigns?: string[];
  }>;
}

interface CampaignAttackMapping {
  campaignId: string;
  campaignName: string;
  matrix: AttackMatrixTactic[];
  summary: {
    totalTactics: number;
    tacticsWithActivity: number;
    totalTechniques: number;
    observedTechniques: number;
    coveragePercent: number;
  };
}

interface KillChainProgression {
  campaignId: string;
  campaignName: string;
  phases: KillChainPhase[];
  progression: {
    completedPhases: number;
    totalPhases: number;
    progressPercent: number;
    currentPhase: string | null;
    nextPredictedPhase: string | null;
    maturity: string;
  };
}

interface ThreatActorProfile {
  id: string;
  name: string;
  aliases: string[];
  motivation: string;
  capability: string;
  country: string;
  description: string;
  targetedSectors: string[];
  techniques: string[];
  campaignCount: number;
  campaigns: Array<{
    id: string;
    name: string;
    status: string;
    confidence: number;
    firstSeen: string | null;
    lastSeen: string | null;
  }>;
  firstSeen: string | null;
  lastSeen: string | null;
  riskLevel: string;
}

interface AlertCorrelation {
  campaignId: string;
  campaignName: string;
  alertId: string;
  alertTitle: string;
  matchType: string;
  confidence: number;
}

interface CorrelationResult {
  correlations: AlertCorrelation[];
  summary: {
    totalAlerts: number;
    totalCampaigns: number;
    correlationsFound: number;
    highConfidence: number;
    mediumConfidence: number;
    lowConfidence: number;
  };
}

// ── Helpers ──

function statusColor(status: string) {
  if (status === "active") return "destructive";
  if (status === "dormant") return "secondary";
  return "outline";
}

function severityColor(severity: string) {
  if (severity === "critical") return "text-red-600 bg-red-50 border-red-200";
  if (severity === "high") return "text-orange-600 bg-orange-50 border-orange-200";
  if (severity === "medium") return "text-yellow-600 bg-yellow-50 border-yellow-200";
  if (severity === "low") return "text-blue-600 bg-blue-50 border-blue-200";
  return "text-muted-foreground bg-muted border-border";
}

function maturityLabel(maturity: string) {
  if (maturity === "late_stage") return "Late Stage";
  if (maturity === "mid_stage") return "Mid Stage";
  return "Early Stage";
}

function maturityColor(maturity: string) {
  if (maturity === "late_stage") return "text-red-600";
  if (maturity === "mid_stage") return "text-yellow-600";
  return "text-blue-600";
}

function capabilityColor(capability: string) {
  if (capability === "advanced") return "text-red-600";
  if (capability === "moderate") return "text-yellow-600";
  return "text-blue-600";
}

function fmtDate(d: string | null) {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function fmtDateTime(d: string | null) {
  if (!d) return "—";
  return new Date(d).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ── Main Component ──

export default function CampaignViewerPage() {
  usePageTitle("Campaign Intelligence");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedCampaignId, setSelectedCampaignId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [createOpen, setCreateOpen] = useState(false);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // ── Queries ──

  const {
    data: campaignsRaw,
    isLoading,
    isError,
    refetch,
  } = useQuery<CampaignListItem[]>({
    queryKey: ["/api/campaigns"],
    queryFn: () => apiRequest("GET", "/api/campaigns").then((r) => r.json()),
  });

  const list = Array.isArray(campaignsRaw) ? campaignsRaw : [];

  const { data: campaignDetail, isLoading: detailLoading } = useQuery<CampaignDetail>({
    queryKey: ["/api/campaigns", selectedCampaignId, "detail"],
    queryFn: () => apiRequest("GET", `/api/campaigns/${selectedCampaignId}/detail`).then((r) => r.json()),
    enabled: !!selectedCampaignId,
  });

  const { data: timelineData } = useQuery<CampaignTimeline>({
    queryKey: ["/api/campaigns", selectedCampaignId, "timeline"],
    queryFn: () => apiRequest("GET", `/api/campaigns/${selectedCampaignId}/timeline`).then((r) => r.json()),
    enabled: !!selectedCampaignId && activeTab === "timeline",
  });

  const { data: relationshipsData } = useQuery<CampaignRelationships>({
    queryKey: ["/api/campaigns/relationships"],
    queryFn: () => apiRequest("GET", "/api/campaigns/relationships").then((r) => r.json()),
    enabled: activeTab === "relationships" && !selectedCampaignId,
  });

  const { data: attackMapping } = useQuery<CampaignAttackMapping>({
    queryKey: ["/api/campaigns", selectedCampaignId, "attack-mapping"],
    queryFn: () => apiRequest("GET", `/api/campaigns/${selectedCampaignId}/attack-mapping`).then((r) => r.json()),
    enabled: !!selectedCampaignId && activeTab === "mitre",
  });

  const { data: killChainData } = useQuery<KillChainProgression>({
    queryKey: ["/api/campaigns", selectedCampaignId, "kill-chain"],
    queryFn: () => apiRequest("GET", `/api/campaigns/${selectedCampaignId}/kill-chain`).then((r) => r.json()),
    enabled: !!selectedCampaignId && activeTab === "killchain",
  });

  const { data: threatActors } = useQuery<ThreatActorProfile[]>({
    queryKey: ["/api/threat-actors"],
    queryFn: () => apiRequest("GET", "/api/threat-actors").then((r) => r.json()),
    enabled: activeTab === "actors" && !selectedCampaignId,
  });

  const { data: correlationData, isLoading: correlating } = useQuery<CorrelationResult>({
    queryKey: ["/api/campaigns/correlate-alerts"],
    queryFn: () => apiRequest("POST", "/api/campaigns/correlate-alerts").then((r) => r.json()),
    enabled: activeTab === "correlation" && !selectedCampaignId,
  });

  const { data: attackMatrix } = useQuery<{
    totalCampaigns: number;
    matrix: AttackMatrixTactic[];
    topTechniques: Array<{ id: string; count: number; campaigns: string[] }>;
  }>({
    queryKey: ["/api/campaigns/attack-matrix"],
    queryFn: () => apiRequest("GET", "/api/campaigns/attack-matrix").then((r) => r.json()),
    enabled: activeTab === "matrix" && !selectedCampaignId,
  });

  // ── Mutations ──

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => apiRequest("POST", "/api/campaigns", data).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/campaigns"] });
      setCreateOpen(false);
      toast({ title: "Campaign created" });
    },
    onError: () => toast({ title: "Failed to create campaign", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/campaigns/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/campaigns"] });
      setSelectedCampaignId(null);
      toast({ title: "Campaign deleted" });
    },
    onError: () => toast({ title: "Failed to delete campaign", variant: "destructive" }),
  });

  // ── Filters ──

  const filtered = list.filter((c) => {
    const matchSearch =
      !search ||
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      (c.tacticsSequence || []).some((t) => t.toLowerCase().includes(search.toLowerCase()));
    const matchStatus = statusFilter === "all" || c.status === statusFilter;
    return matchSearch && matchStatus;
  });

  // ── Detail View ──

  if (selectedCampaignId) {
    return (
      <CampaignDetailView
        campaignId={selectedCampaignId}
        detail={campaignDetail || null}
        detailLoading={detailLoading}
        timelineData={timelineData || null}
        attackMapping={attackMapping || null}
        killChainData={killChainData || null}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onBack={() => {
          setSelectedCampaignId(null);
          setActiveTab("overview");
        }}
        onDelete={(id) => deleteMutation.mutate(id)}
      />
    );
  }

  // ── List View ──

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load campaigns</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Target className="h-6 w-6" /> Campaign Intelligence
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Track threat campaigns, actor groups, TTPs, and kill chain progression
          </p>
        </div>
        <div className="flex gap-2">
          <CreateCampaignDialog
            open={createOpen}
            onOpenChange={setCreateOpen}
            onSubmit={(data) => createMutation.mutate(data)}
            isPending={createMutation.isPending}
          />
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="p-2 rounded-md bg-red-50">
              <Target className="h-5 w-5 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold">{list.filter((c) => c.status === "active").length}</p>
              <p className="text-xs text-muted-foreground">Active Campaigns</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="p-2 rounded-md bg-yellow-50">
              <Shield className="h-5 w-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold">{list.filter((c) => c.status === "dormant").length}</p>
              <p className="text-xs text-muted-foreground">Dormant</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="p-2 rounded-md bg-blue-50">
              <Globe className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total Tracked</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="p-2 rounded-md bg-purple-50">
              <Skull className="h-5 w-5 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold">{new Set(list.map((c) => c.fingerprint.split("-")[0])).size}</p>
              <p className="text-xs text-muted-foreground">Threat Actors</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs for list views */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Campaigns</TabsTrigger>
          <TabsTrigger value="actors">Threat Actors</TabsTrigger>
          <TabsTrigger value="relationships">Relationships</TabsTrigger>
          <TabsTrigger value="correlation">Alert Correlation</TabsTrigger>
          <TabsTrigger value="matrix">ATT&CK Matrix</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {/* Filters */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search campaigns, techniques..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="dormant">Dormant</SelectItem>
                <SelectItem value="historical">Historical</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {filtered.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center py-12 gap-3">
                <Target className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">
                  {search || statusFilter !== "all" ? "No campaigns match your filters" : "No campaigns tracked yet"}
                </p>
                {!search && statusFilter === "all" && (
                  <Button variant="outline" size="sm" onClick={() => setCreateOpen(true)}>
                    <Plus className="mr-2 h-4 w-4" /> Create Campaign
                  </Button>
                )}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {filtered.map((c) => (
                <Card
                  key={c.id}
                  className="transition-all hover:shadow-md cursor-pointer group"
                  onClick={() => setSelectedCampaignId(c.id)}
                >
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 min-w-0">
                        <div
                          className={`p-2 rounded-md ${c.status === "active" ? "bg-red-50" : c.status === "dormant" ? "bg-yellow-50" : "bg-muted"}`}
                        >
                          <Target
                            className={`h-5 w-5 ${c.status === "active" ? "text-red-600" : c.status === "dormant" ? "text-yellow-600" : "text-muted-foreground"}`}
                          />
                        </div>
                        <div className="min-w-0">
                          <p className="font-medium truncate">{c.name}</p>
                          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                            <Calendar className="h-3 w-3" />
                            <span>
                              {fmtDate(c.firstSeenAt)} — {fmtDate(c.lastSeenAt)}
                            </span>
                            {(c.tacticsSequence || []).length > 0 && (
                              <>
                                <span className="text-border">|</span>
                                <Shield className="h-3 w-3" />
                                <span>{(c.tacticsSequence || []).length} techniques</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <Badge variant={statusColor(c.status)}>{c.status}</Badge>
                        <Badge variant="outline">{c.confidence}%</Badge>
                        {(c.alertCount || 0) > 0 && <Badge variant="outline">{c.alertCount} alerts</Badge>}
                        <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="actors">
          <ThreatActorsTab actors={threatActors || []} />
        </TabsContent>

        <TabsContent value="relationships">
          <RelationshipsTab data={relationshipsData || null} />
        </TabsContent>

        <TabsContent value="correlation">
          <CorrelationTab data={correlationData || null} isLoading={correlating} />
        </TabsContent>

        <TabsContent value="matrix">
          <AttackMatrixTab data={attackMatrix || null} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Campaign Detail View (8.1)
// ═══════════════════════════════════════════════════════════════════════════════

function CampaignDetailView({
  campaignId,
  detail,
  detailLoading,
  timelineData,
  attackMapping,
  killChainData,
  activeTab,
  setActiveTab,
  onBack,
  onDelete,
}: {
  campaignId: string;
  detail: CampaignDetail | null;
  detailLoading: boolean;
  timelineData: CampaignTimeline | null;
  attackMapping: CampaignAttackMapping | null;
  killChainData: KillChainProgression | null;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onBack: () => void;
  onDelete: (id: string) => void;
}) {
  if (detailLoading || !detail) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={onBack}>
            <ArrowLeft className="h-4 w-4 mr-1" /> Back
          </Button>
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Target className="h-6 w-6" /> {detail.name}
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">{detail.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={statusColor(detail.status)} className="text-sm">
            {detail.status}
          </Badge>
          <Badge variant="outline" className="text-sm">
            {detail.confidence}% confidence
          </Badge>
          <Button variant="outline" size="sm" className="text-destructive" onClick={() => onDelete(campaignId)}>
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{detail.alertCount}</p>
            <p className="text-xs text-muted-foreground">Related Alerts</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{detail.iocCount}</p>
            <p className="text-xs text-muted-foreground">Associated IOCs</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{detail.attackTechniques.length}</p>
            <p className="text-xs text-muted-foreground">ATT&CK Techniques</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">
              {detail.killChainProgress}/{detail.killChainTotal}
            </p>
            <p className="text-xs text-muted-foreground">Kill Chain Phases</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className={`text-2xl font-bold ${maturityColor(detail.maturity)}`}>{maturityLabel(detail.maturity)}</p>
            <p className="text-xs text-muted-foreground">Campaign Maturity</p>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="mitre">ATT&CK Map</TabsTrigger>
          <TabsTrigger value="killchain">Kill Chain</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="iocs">IOCs</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Threat Actor Attribution */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Skull className="h-4 w-4" /> Threat Actor Attribution
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="font-medium">{detail.threatActor.name}</p>
                  <p className="text-xs text-muted-foreground">{detail.threatActor.aliases.join(", ")}</p>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground">Motivation</p>
                    <Badge variant="outline" className="capitalize mt-0.5">
                      {detail.threatActor.motivation}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Capability</p>
                    <span
                      className={`text-sm font-medium capitalize ${capabilityColor(detail.threatActor.capability)}`}
                    >
                      {detail.threatActor.capability}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">{detail.threatActor.description}</p>
              </CardContent>
            </Card>

            {/* Targeting */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Crosshair className="h-4 w-4" /> Targeting
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Target Sectors</p>
                  <div className="flex flex-wrap gap-1">
                    {detail.targetSectors.map((s) => (
                      <Badge key={s} variant="outline" className="text-xs">
                        <Users className="h-3 w-3 mr-1" />
                        {s}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Target Regions</p>
                  <div className="flex flex-wrap gap-1">
                    {detail.targetRegions.map((r) => (
                      <Badge key={r} variant="outline" className="text-xs">
                        <Globe className="h-3 w-3 mr-1" />
                        {r}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Timeline</p>
                  <p className="text-sm">
                    {fmtDate(detail.firstSeen)} — {fmtDate(detail.lastSeen)}
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Techniques */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="h-4 w-4" /> Techniques ({detail.techniques.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1">
                  {detail.techniques.length > 0 ? (
                    detail.techniques.map((t) => (
                      <Badge key={t} variant="secondary" className="text-xs font-mono">
                        {t}
                      </Badge>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground">No techniques mapped</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Kill Chain Summary */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Layers className="h-4 w-4" /> Kill Chain Progress
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Progress value={(detail.killChainProgress / detail.killChainTotal) * 100} className="h-3" />
                <div className="flex flex-wrap gap-1">
                  {detail.killChain.map((phase) => (
                    <TooltipProvider key={phase.phase}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant={phase.observed ? "default" : "outline"}
                            className={`text-xs ${phase.observed ? "" : "opacity-40"}`}
                          >
                            {phase.observed ? (
                              <CheckCircle className="h-3 w-3 mr-1" />
                            ) : (
                              <XCircle className="h-3 w-3 mr-1" />
                            )}
                            {phase.label}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{phase.description}</p>
                          {phase.observed && phase.firstObserved && (
                            <p className="text-xs mt-1">First observed: {fmtDate(phase.firstObserved)}</p>
                          )}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ))}
                </div>
                {detail.predictedNextPhase && (
                  <p className="text-xs text-muted-foreground">
                    Predicted next phase:{" "}
                    <span className="font-medium text-yellow-600">{detail.predictedNextPhase}</span>
                  </p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Timeline Tab (8.2) */}
        <TabsContent value="timeline">
          <TimelineTab data={timelineData} />
        </TabsContent>

        {/* MITRE ATT&CK Tab (8.7) */}
        <TabsContent value="mitre">
          <MitreAttackTab data={attackMapping} />
        </TabsContent>

        {/* Kill Chain Tab (8.8) */}
        <TabsContent value="killchain">
          <KillChainTab data={killChainData} />
        </TabsContent>

        {/* Alerts Tab */}
        <TabsContent value="alerts">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Related Alerts ({detail.relatedAlerts.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {detail.relatedAlerts.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No correlated alerts</p>
              ) : (
                <ScrollArea className="h-[400px]">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left">
                        <th className="pb-2 font-medium">Alert</th>
                        <th className="pb-2 font-medium">Severity</th>
                        <th className="pb-2 font-medium">Status</th>
                        <th className="pb-2 font-medium">MITRE</th>
                        <th className="pb-2 font-medium">Source</th>
                        <th className="pb-2 font-medium">Date</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.relatedAlerts.map((a) => (
                        <tr key={a.id} className="border-b last:border-0">
                          <td className="py-2 max-w-[200px] truncate">{a.title}</td>
                          <td className="py-2">
                            <Badge variant="outline" className={`text-xs ${severityColor(a.severity)}`}>
                              {a.severity}
                            </Badge>
                          </td>
                          <td className="py-2">
                            <Badge variant="outline" className="text-xs">
                              {a.status}
                            </Badge>
                          </td>
                          <td className="py-2 text-xs font-mono">{a.mitreTechnique || a.mitreTactic || "—"}</td>
                          <td className="py-2 text-xs font-mono">{a.sourceIp || a.hostname || "—"}</td>
                          <td className="py-2 text-xs">{fmtDate(a.createdAt)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* IOCs Tab */}
        <TabsContent value="iocs">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Associated IOCs ({detail.relatedIocs.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {detail.relatedIocs.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">No associated IOCs</p>
              ) : (
                <ScrollArea className="h-[400px]">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left">
                        <th className="pb-2 font-medium">Type</th>
                        <th className="pb-2 font-medium">Value</th>
                        <th className="pb-2 font-medium">Confidence</th>
                        <th className="pb-2 font-medium">Severity</th>
                        <th className="pb-2 font-medium">Source</th>
                        <th className="pb-2 font-medium">First Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.relatedIocs.map((ioc) => (
                        <tr key={ioc.id} className="border-b last:border-0">
                          <td className="py-2">
                            <Badge variant="outline" className="text-xs">
                              {ioc.iocType}
                            </Badge>
                          </td>
                          <td className="py-2 font-mono text-xs max-w-[200px] truncate">{ioc.iocValue}</td>
                          <td className="py-2 text-xs">{ioc.confidence}%</td>
                          <td className="py-2">
                            <Badge variant="outline" className={`text-xs ${severityColor(ioc.severity)}`}>
                              {ioc.severity}
                            </Badge>
                          </td>
                          <td className="py-2 text-xs">{ioc.source}</td>
                          <td className="py-2 text-xs">{fmtDate(ioc.firstSeen)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Timeline Tab (8.2)
// ═══════════════════════════════════════════════════════════════════════════════

function TimelineTab({ data }: { data: CampaignTimeline | null }) {
  const [zoomLevel, setZoomLevel] = useState<"all" | "month" | "week">("all");

  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">Loading timeline...</CardContent>
      </Card>
    );
  }

  const events = data.events;
  const filteredEvents =
    zoomLevel === "all"
      ? events
      : events.filter((e) => {
          const eventDate = new Date(e.timestamp);
          const now = new Date();
          if (zoomLevel === "month") {
            return now.getTime() - eventDate.getTime() < 30 * 24 * 60 * 60 * 1000;
          }
          return now.getTime() - eventDate.getTime() < 7 * 24 * 60 * 60 * 1000;
        });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Clock className="h-4 w-4" />
          <span>Duration: {data.durationDays} days</span>
          <span className="text-border">|</span>
          <span>{data.events.length} events</span>
          <span className="text-border">|</span>
          <Badge variant={statusColor(data.status)}>{data.status}</Badge>
        </div>
        <div className="flex gap-1">
          <Button variant={zoomLevel === "all" ? "default" : "outline"} size="sm" onClick={() => setZoomLevel("all")}>
            All
          </Button>
          <Button
            variant={zoomLevel === "month" ? "default" : "outline"}
            size="sm"
            onClick={() => setZoomLevel("month")}
          >
            30d
          </Button>
          <Button variant={zoomLevel === "week" ? "default" : "outline"} size="sm" onClick={() => setZoomLevel("week")}>
            7d
          </Button>
        </div>
      </div>

      {/* Activity Periods */}
      {data.activityPeriods.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Activity Periods</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-16">
              {data.activityPeriods.map((period) => {
                const maxCount = Math.max(...data.activityPeriods.map((p) => p.eventCount), 1);
                const height = (period.eventCount / maxCount) * 100;
                return (
                  <TooltipProvider key={period.month}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div
                          className="bg-primary/70 rounded-t flex-1 min-w-[20px] transition-all hover:bg-primary"
                          style={{ height: `${Math.max(height, 4)}%` }}
                        />
                      </TooltipTrigger>
                      <TooltipContent>
                        <p className="font-medium">{period.month}</p>
                        <p className="text-xs">{period.eventCount} events</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                );
              })}
            </div>
            <div className="flex gap-1 mt-1">
              {data.activityPeriods.map((period) => (
                <div key={period.month} className="flex-1 text-center text-[10px] text-muted-foreground truncate">
                  {period.month}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Event Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">
            Events ({filteredEvents.length}
            {filteredEvents.length !== events.length ? ` of ${events.length}` : ""})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <div className="relative pl-6">
              <div className="absolute left-2 top-0 bottom-0 w-px bg-border" />
              {filteredEvents.map((event) => (
                <div key={event.id} className="relative pb-4 last:pb-0">
                  <div
                    className={`absolute left-[-14px] w-3 h-3 rounded-full border-2 ${
                      event.severity === "critical"
                        ? "bg-red-500 border-red-300"
                        : event.severity === "high"
                          ? "bg-orange-500 border-orange-300"
                          : event.severity === "medium"
                            ? "bg-yellow-500 border-yellow-300"
                            : "bg-blue-500 border-blue-300"
                    }`}
                  />
                  <div className="ml-4">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">{fmtDateTime(event.timestamp)}</span>
                      <Badge variant="outline" className={`text-xs ${severityColor(event.severity)}`}>
                        {event.severity}
                      </Badge>
                      {event.killChainPhase && (
                        <Badge variant="secondary" className="text-xs">
                          {event.killChainPhase.replace(/_/g, " ")}
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm font-medium mt-1">{event.title}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{event.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MITRE ATT&CK Tab (8.7)
// ═══════════════════════════════════════════════════════════════════════════════

function MitreAttackTab({ data }: { data: CampaignAttackMapping | null }) {
  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">Loading ATT&CK mapping...</CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.coveragePercent}%</p>
            <p className="text-xs text-muted-foreground">Technique Coverage</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.observedTechniques}</p>
            <p className="text-xs text-muted-foreground">Observed Techniques</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.tacticsWithActivity}</p>
            <p className="text-xs text-muted-foreground">Tactics w/ Activity</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalTactics}</p>
            <p className="text-xs text-muted-foreground">Total Tactics</p>
          </CardContent>
        </Card>
      </div>

      {/* ATT&CK Heatmap Matrix */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">ATT&CK Technique Matrix</CardTitle>
          <CardDescription className="text-xs">
            Highlighted cells indicate observed techniques in this campaign
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="w-full">
            <div className="flex gap-1 min-w-[900px]">
              {data.matrix.map((tactic) => (
                <div key={tactic.tacticId} className="flex-1 min-w-[80px]">
                  <div className="text-xs font-medium text-center pb-2 truncate" title={tactic.tacticName}>
                    {tactic.tacticName}
                  </div>
                  <div className="space-y-1">
                    {tactic.techniques.map((tech) => (
                      <TooltipProvider key={tech.id}>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div
                              className={`text-[10px] px-1 py-1 rounded text-center truncate cursor-default ${
                                tech.observed
                                  ? "bg-red-100 text-red-800 border border-red-200 font-medium"
                                  : "bg-muted text-muted-foreground"
                              }`}
                            >
                              {tech.id}
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p className="font-medium">
                              {tech.id}: {tech.name}
                            </p>
                            {tech.observed && (
                              <>
                                <p className="text-xs">Confidence: {tech.confidence}%</p>
                                <p className="text-xs">Evidence: {tech.evidenceCount} items</p>
                              </>
                            )}
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Kill Chain Tab (8.8)
// ═══════════════════════════════════════════════════════════════════════════════

function KillChainTab({ data }: { data: KillChainProgression | null }) {
  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">Loading kill chain...</CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Progression Summary */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Activity className="h-4 w-4" /> Campaign Progression
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <Progress value={data.progression.progressPercent} className="h-4" />
            </div>
            <span className="text-sm font-medium">
              {data.progression.completedPhases}/{data.progression.totalPhases} phases
            </span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Current Phase</p>
              <p className="font-medium">{data.progression.currentPhase || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Next Predicted</p>
              <p className="font-medium text-yellow-600">{data.progression.nextPredictedPhase || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Maturity</p>
              <p className={`font-medium ${maturityColor(data.progression.maturity)}`}>
                {maturityLabel(data.progression.maturity)}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Kill Chain Phases */}
      <div className="grid grid-cols-1 md:grid-cols-7 gap-2">
        {data.phases.map((phase, idx) => (
          <Card key={phase.phase} className={`${phase.observed ? "border-primary/50 bg-primary/5" : "opacity-60"}`}>
            <CardContent className="pt-4 pb-3 text-center space-y-2">
              <div className="flex items-center justify-center gap-1 text-xs text-muted-foreground">
                <span className="font-mono">{phase.order}</span>
                {idx < data.phases.length - 1 && <ChevronRight className="h-3 w-3" />}
              </div>
              <div
                className={`w-8 h-8 rounded-full mx-auto flex items-center justify-center ${
                  phase.observed ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                }`}
              >
                {phase.observed ? <CheckCircle className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
              </div>
              <p className="text-xs font-medium leading-tight">{phase.label}</p>
              {phase.observed && (
                <div className="text-[10px] text-muted-foreground space-y-0.5">
                  {phase.firstObserved && <p>First: {fmtDate(phase.firstObserved)}</p>}
                  <p>{phase.evidenceCount} evidence items</p>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Phase Details */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Phase Details</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left">
                <th className="pb-2 font-medium">Phase</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">First Observed</th>
                <th className="pb-2 font-medium">Evidence</th>
                <th className="pb-2 font-medium">Description</th>
              </tr>
            </thead>
            <tbody>
              {data.phases.map((phase) => (
                <tr key={phase.phase} className="border-b last:border-0">
                  <td className="py-2 font-medium">{phase.label}</td>
                  <td className="py-2">
                    {phase.observed ? (
                      <Badge variant="default" className="text-xs">
                        Observed
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-xs">
                        Not Observed
                      </Badge>
                    )}
                  </td>
                  <td className="py-2 text-xs">{fmtDate(phase.firstObserved)}</td>
                  <td className="py-2 text-xs">{phase.evidenceCount}</td>
                  <td className="py-2 text-xs text-muted-foreground max-w-[300px] truncate">{phase.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Threat Actors Tab (8.6)
// ═══════════════════════════════════════════════════════════════════════════════

function ThreatActorsTab({ actors }: { actors: ThreatActorProfile[] }) {
  if (actors.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center py-12 gap-3">
          <Skull className="h-8 w-8 text-muted-foreground" />
          <p className="text-muted-foreground">No threat actors profiled yet</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {actors.map((actor) => (
        <Card key={actor.id}>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Skull className="h-4 w-4" /> {actor.name}
              </CardTitle>
              <Badge
                variant={
                  actor.riskLevel === "critical" ? "destructive" : actor.riskLevel === "high" ? "default" : "secondary"
                }
              >
                {actor.riskLevel}
              </Badge>
            </div>
            {actor.aliases.length > 0 && (
              <CardDescription className="text-xs">AKA: {actor.aliases.join(", ")}</CardDescription>
            )}
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">{actor.description}</p>

            <div className="grid grid-cols-3 gap-2 text-xs">
              <div>
                <p className="text-muted-foreground">Motivation</p>
                <p className="font-medium capitalize">{actor.motivation}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Capability</p>
                <p className={`font-medium capitalize ${capabilityColor(actor.capability)}`}>{actor.capability}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Campaigns</p>
                <p className="font-medium">{actor.campaignCount}</p>
              </div>
            </div>

            <div>
              <p className="text-xs text-muted-foreground mb-1">Targeted Sectors</p>
              <div className="flex flex-wrap gap-1">
                {actor.targetedSectors.slice(0, 5).map((s) => (
                  <Badge key={s} variant="outline" className="text-xs">
                    {s}
                  </Badge>
                ))}
              </div>
            </div>

            {actor.techniques.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-1">Known Techniques</p>
                <div className="flex flex-wrap gap-1">
                  {actor.techniques.slice(0, 5).map((t) => (
                    <Badge key={t} variant="secondary" className="text-xs font-mono">
                      {t}
                    </Badge>
                  ))}
                  {actor.techniques.length > 5 && (
                    <Badge variant="outline" className="text-xs">
                      +{actor.techniques.length - 5} more
                    </Badge>
                  )}
                </div>
              </div>
            )}

            {actor.campaigns.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-1">Associated Campaigns</p>
                <div className="space-y-1">
                  {actor.campaigns.map((c) => (
                    <div key={c.id} className="flex items-center justify-between text-xs">
                      <span className="font-medium">{c.name}</span>
                      <div className="flex items-center gap-1">
                        <Badge variant={statusColor(c.status)} className="text-[10px]">
                          {c.status}
                        </Badge>
                        <span className="text-muted-foreground">{c.confidence}%</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="text-xs text-muted-foreground pt-1 border-t">
              Active: {fmtDate(actor.firstSeen)} — {fmtDate(actor.lastSeen)}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Relationships Tab (8.3)
// ═══════════════════════════════════════════════════════════════════════════════

function RelationshipsTab({ data }: { data: CampaignRelationships | null }) {
  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">Loading relationships...</CardContent>
      </Card>
    );
  }

  const campaignNodes = data.nodes.filter((n) => n.type === "campaign");
  const actorNodes = data.nodes.filter((n) => n.type === "threat_actor");
  const techniqueNodes = data.nodes.filter((n) => n.type === "technique");

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalCampaigns}</p>
            <p className="text-xs text-muted-foreground">Campaigns</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalActors}</p>
            <p className="text-xs text-muted-foreground">Threat Actors</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalTechniques}</p>
            <p className="text-xs text-muted-foreground">Techniques</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalRelationships}</p>
            <p className="text-xs text-muted-foreground">Relationships</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.sharedTechniqueLinks}</p>
            <p className="text-xs text-muted-foreground">Shared Links</p>
          </CardContent>
        </Card>
      </div>

      {/* Visual Graph (simplified node list) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Campaign Nodes */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4" /> Campaigns ({campaignNodes.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {campaignNodes.map((node) => (
                <div key={node.id} className="flex items-center gap-2 text-sm">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <span className="flex-1 truncate">{node.label}</span>
                  {node.status && (
                    <Badge variant={statusColor(node.status)} className="text-[10px]">
                      {node.status}
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Actor Nodes */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Skull className="h-4 w-4" /> Threat Actors ({actorNodes.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {actorNodes.map((node) => (
                <div key={node.id} className="flex items-center gap-2 text-sm">
                  <div className="w-3 h-3 rounded-full bg-purple-500" />
                  <span className="flex-1 truncate">{node.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Technique Nodes */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4" /> Shared Techniques ({techniqueNodes.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {techniqueNodes.map((node) => (
                <div key={node.id} className="flex items-center gap-2 text-sm">
                  <div className="w-3 h-3 rounded-full bg-blue-500" />
                  <span className="flex-1 truncate font-mono text-xs">{node.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Shared Relationships */}
      {data.sharedRelationships.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Link2 className="h-4 w-4" /> Campaign Overlaps
            </CardTitle>
            <CardDescription className="text-xs">Campaigns sharing techniques or infrastructure</CardDescription>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="pb-2 font-medium">Campaign 1</th>
                  <th className="pb-2 font-medium">Campaign 2</th>
                  <th className="pb-2 font-medium">Shared Techniques</th>
                  <th className="pb-2 font-medium">Strength</th>
                </tr>
              </thead>
              <tbody>
                {data.sharedRelationships.map((rel, idx) => (
                  <tr key={idx} className="border-b last:border-0">
                    <td className="py-2">{rel.campaign1}</td>
                    <td className="py-2">{rel.campaign2}</td>
                    <td className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {rel.sharedTechniques.slice(0, 3).map((t) => (
                          <Badge key={t} variant="secondary" className="text-xs font-mono">
                            {t}
                          </Badge>
                        ))}
                        {rel.sharedTechniques.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{rel.sharedTechniques.length - 3}
                          </Badge>
                        )}
                      </div>
                    </td>
                    <td className="py-2">
                      <div className="flex items-center gap-2">
                        <Progress value={rel.relationshipStrength} className="h-2 w-16" />
                        <span className="text-xs">{rel.relationshipStrength}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {/* Edge List */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Network className="h-4 w-4" /> Relationship Graph ({data.edges.length} edges)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[300px]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="pb-2 font-medium">Source</th>
                  <th className="pb-2 font-medium">Relationship</th>
                  <th className="pb-2 font-medium">Target</th>
                  <th className="pb-2 font-medium">Weight</th>
                </tr>
              </thead>
              <tbody>
                {data.edges.slice(0, 50).map((edge) => {
                  const sourceNode = data.nodes.find((n) => n.id === edge.source);
                  const targetNode = data.nodes.find((n) => n.id === edge.target);
                  return (
                    <tr key={edge.id} className="border-b last:border-0">
                      <td className="py-2 text-xs">{sourceNode?.label || edge.source}</td>
                      <td className="py-2">
                        <Badge variant="outline" className="text-xs">
                          {edge.relationship.replace(/_/g, " ")}
                        </Badge>
                      </td>
                      <td className="py-2 text-xs">{targetNode?.label || edge.target}</td>
                      <td className="py-2 text-xs">{Math.round(edge.weight * 100)}%</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Alert Correlation Tab (8.5)
// ═══════════════════════════════════════════════════════════════════════════════

function CorrelationTab({ data, isLoading }: { data: CorrelationResult | null; isLoading: boolean }) {
  if (isLoading) {
    return (
      <Card>
        <CardContent className="py-8 text-center">
          <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-muted-foreground" />
          <p className="text-muted-foreground">Running alert correlation...</p>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">No correlation data available</CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalAlerts}</p>
            <p className="text-xs text-muted-foreground">Total Alerts</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.totalCampaigns}</p>
            <p className="text-xs text-muted-foreground">Campaigns</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold">{data.summary.correlationsFound}</p>
            <p className="text-xs text-muted-foreground">Correlations</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold text-red-600">{data.summary.highConfidence}</p>
            <p className="text-xs text-muted-foreground">High Conf.</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold text-yellow-600">{data.summary.mediumConfidence}</p>
            <p className="text-xs text-muted-foreground">Medium Conf.</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-2xl font-bold text-blue-600">{data.summary.lowConfidence}</p>
            <p className="text-xs text-muted-foreground">Low Conf.</p>
          </CardContent>
        </Card>
      </div>

      {/* Correlation Results */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="h-4 w-4" /> Alert-Campaign Correlations
          </CardTitle>
          <CardDescription className="text-xs">
            Alerts matched to campaigns by TTP, IOC, and behavioral patterns
          </CardDescription>
        </CardHeader>
        <CardContent>
          {data.correlations.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">
              No correlations found. Run more campaigns or ingest more alerts.
            </p>
          ) : (
            <ScrollArea className="h-[400px]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left">
                    <th className="pb-2 font-medium">Alert</th>
                    <th className="pb-2 font-medium">Campaign</th>
                    <th className="pb-2 font-medium">Match Type</th>
                    <th className="pb-2 font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.correlations.map((c, idx) => (
                    <tr key={idx} className="border-b last:border-0">
                      <td className="py-2 max-w-[200px] truncate">{c.alertTitle}</td>
                      <td className="py-2">
                        <Badge variant="outline" className="text-xs">
                          <Target className="h-3 w-3 mr-1" />
                          {c.campaignName}
                        </Badge>
                      </td>
                      <td className="py-2">
                        <div className="flex flex-wrap gap-1">
                          {c.matchType.split(", ").map((mt) => (
                            <Badge key={mt} variant="secondary" className="text-xs">
                              {mt.replace(/_/g, " ")}
                            </Badge>
                          ))}
                        </div>
                      </td>
                      <td className="py-2">
                        <div className="flex items-center gap-2">
                          <Progress
                            value={c.confidence}
                            className={`h-2 w-16 ${
                              c.confidence >= 70
                                ? "[&>div]:bg-red-500"
                                : c.confidence >= 40
                                  ? "[&>div]:bg-yellow-500"
                                  : "[&>div]:bg-blue-500"
                            }`}
                          />
                          <span className="text-xs">{c.confidence}%</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Aggregate ATT&CK Matrix Tab
// ═══════════════════════════════════════════════════════════════════════════════

function AttackMatrixTab({
  data,
}: {
  data: {
    totalCampaigns: number;
    matrix: AttackMatrixTactic[];
    topTechniques: Array<{ id: string; count: number; campaigns: string[] }>;
  } | null;
}) {
  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">Loading ATT&CK matrix...</CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Aggregate ATT&CK Matrix ({data.totalCampaigns} campaigns)</CardTitle>
          <CardDescription className="text-xs">
            Technique usage across all campaigns — darker = more campaigns
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="w-full">
            <div className="flex gap-1 min-w-[900px]">
              {data.matrix.map((tactic) => (
                <div key={tactic.tacticId} className="flex-1 min-w-[80px]">
                  <div className="text-xs font-medium text-center pb-2 truncate" title={tactic.tacticName}>
                    {tactic.tacticName}
                  </div>
                  <div className="space-y-1">
                    {tactic.techniques.map((tech) => {
                      const count = tech.campaignCount || 0;
                      const maxCount = Math.max(data.totalCampaigns, 1);
                      const intensity = Math.min(count / maxCount, 1);
                      return (
                        <TooltipProvider key={tech.id}>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div
                                className={`text-[10px] px-1 py-1 rounded text-center truncate cursor-default ${
                                  count > 0 ? `border font-medium` : "bg-muted text-muted-foreground"
                                }`}
                                style={
                                  count > 0
                                    ? {
                                        backgroundColor: `rgba(220, 38, 38, ${0.1 + intensity * 0.5})`,
                                        color: intensity > 0.3 ? "white" : "rgb(153, 27, 27)",
                                        borderColor: `rgba(220, 38, 38, ${0.3 + intensity * 0.4})`,
                                      }
                                    : undefined
                                }
                              >
                                {tech.id}
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p className="font-medium">
                                {tech.id}: {tech.name}
                              </p>
                              <p className="text-xs">
                                Used in {count} campaign{count !== 1 ? "s" : ""}
                              </p>
                              {tech.campaigns && tech.campaigns.length > 0 && (
                                <p className="text-xs mt-1">{tech.campaigns.join(", ")}</p>
                              )}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Top Techniques */}
      {data.topTechniques.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Top Techniques Across Campaigns</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.topTechniques.map((tech) => (
                <div key={tech.id} className="flex items-center gap-3">
                  <span className="text-xs font-mono w-16">{tech.id}</span>
                  <Progress value={(tech.count / Math.max(data.totalCampaigns, 1)) * 100} className="h-2 flex-1" />
                  <span className="text-xs text-muted-foreground w-20 text-right">
                    {tech.count} campaign{tech.count !== 1 ? "s" : ""}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Create Campaign Dialog (8.4)
// ═══════════════════════════════════════════════════════════════════════════════

function CreateCampaignDialog({
  open,
  onOpenChange,
  onSubmit,
  isPending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: Record<string, unknown>) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState("active");
  const [techniques, setTechniques] = useState("");
  const [targetSectors, setTargetSectors] = useState("");
  const [targetRegions, setTargetRegions] = useState("");

  const handleSubmit = () => {
    onSubmit({
      name,
      description,
      status,
      techniques: techniques
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      targetSectors: targetSectors
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      targetRegions: targetRegions
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean),
    });
    setName("");
    setDescription("");
    setTechniques("");
    setTargetSectors("");
    setTargetRegions("");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-2 h-4 w-4" /> New Campaign
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Campaign</DialogTitle>
          <DialogDescription>Track a new threat campaign for investigation</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="campaign-name">Campaign Name *</Label>
            <Input
              id="campaign-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Operation ShadowStrike"
            />
          </div>
          <div>
            <Label htmlFor="campaign-desc">Description</Label>
            <Textarea
              id="campaign-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Campaign description..."
              rows={3}
            />
          </div>
          <div>
            <Label htmlFor="campaign-status">Status</Label>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger id="campaign-status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="dormant">Dormant</SelectItem>
                <SelectItem value="historical">Historical</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="campaign-techniques">Techniques (comma-separated)</Label>
            <Input
              id="campaign-techniques"
              value={techniques}
              onChange={(e) => setTechniques(e.target.value)}
              placeholder="T1566, T1059, T1071..."
            />
          </div>
          <div>
            <Label htmlFor="campaign-sectors">Target Sectors (comma-separated)</Label>
            <Input
              id="campaign-sectors"
              value={targetSectors}
              onChange={(e) => setTargetSectors(e.target.value)}
              placeholder="Finance, Healthcare, Government..."
            />
          </div>
          <div>
            <Label htmlFor="campaign-regions">Target Regions (comma-separated)</Label>
            <Input
              id="campaign-regions"
              value={targetRegions}
              onChange={(e) => setTargetRegions(e.target.value)}
              placeholder="North America, Europe, Asia Pacific..."
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!name || isPending}>
            {isPending ? "Creating..." : "Create Campaign"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
