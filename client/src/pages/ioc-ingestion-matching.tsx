import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import { useToast } from "@/hooks/use-toast";
import {
  Upload,
  Database,
  Target,
  AlertTriangle,
  Search,
  Loader2,
  RefreshCw,
  Rss,
  Clock,
  CheckCircle2,
  XCircle,
  Bug,
  Globe,
  Hash,
  Mail,
  Link2,
  Server,
  BarChart3,
  Play,
  TrendingUp,
  Plus,
  Settings2,
  Trash2,
  Power,
  PowerOff,
  Pencil,
  Eye,
  GitCompare,
  Activity,
  Shield,
  Key,
  Lock,
  Download,
  Timer,
  Gauge,
  Network,
  FileText,
  Hourglass,
  ArrowDownToLine,
  Scan,
  Sparkles,
  ThumbsDown,
  Wand2,
  Share2,
  Users,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface IocFeed {
  id: string;
  orgId: string | null;
  name: string;
  feedType: string;
  url: string | null;
  apiKeyRef: string | null;
  schedule: string | null;
  enabled: boolean;
  config: Record<string, unknown> | null;
  lastFetchAt: string | null;
  lastFetchStatus: string | null;
  lastFetchCount: number;
  totalIocCount: number;
  createdAt: string;
  updatedAt: string | null;
}

interface IocEntry {
  id: string;
  orgId: string | null;
  feedId: string | null;
  iocType: string;
  iocValue: string;
  confidence: number;
  severity: string;
  malwareFamily: string | null;
  campaignId: string | null;
  campaignName: string | null;
  tags: string[];
  metadata: Record<string, unknown> | null;
  source: string | null;
  status: string;
  firstSeen: string | null;
  lastSeen: string | null;
  expiresAt: string | null;
  createdAt: string;
}

interface IocMatch {
  id: string;
  orgId: string | null;
  ruleId: string | null;
  iocEntryId: string;
  alertId: string | null;
  incidentId: string | null;
  entityId: string | null;
  matchField: string;
  matchValue: string;
  confidence: number;
  enrichmentData: EnrichmentData | null;
  createdAt: string;
}

interface EnrichmentData {
  malwareFamily?: string;
  campaignName?: string;
  [key: string]: unknown;
}

interface IocMatchRule {
  id: string;
  orgId: string | null;
  feedId: string | null;
  name: string;
  description: string | null;
  iocTypes: string[];
  matchFields: string[];
  minConfidence: number;
  enabled: boolean;
  autoEnrich: boolean;
  action: string;
  actionConfig: Record<string, unknown> | null;
  matchCount: number;
  lastMatchAt: string | null;
  createdAt: string;
  updatedAt: string | null;
}

interface IocStats {
  totalIOCs: number;
  activeIOCs: number;
  totalMatches: number;
  topMalwareFamilies: { name: string; count: number }[];
  typeDistribution: { type: string; count: number }[];
}

interface FeedIngestionStats {
  feedId: string;
  feedName: string;
  total: number;
  last24h: number;
  last7d: number;
  lastFetchAt: string | null;
  lastFetchStatus: string | null;
  lastFetchCount: number;
}

interface FeedPreviewResult {
  success: boolean;
  error?: string;
  sampleIocs: Array<{
    iocType: string;
    iocValue: string;
    confidence: number;
    severity: string;
    source: string;
  }>;
  totalParsed: number;
  feedName?: string;
  feedType?: string;
  contentType?: string;
}

interface FeedComparisonData {
  feeds: Array<{
    feedId: string;
    feedName: string;
    feedType: string;
    enabled: boolean;
    uniqueIocs: number;
    totalIocs: number;
    fpCount: number;
    fpRate: number;
    lastFetchAt: string | null;
    lastFetchStatus: string | null;
  }>;
  overlapMatrix: Array<{
    feedA: string;
    feedB: string;
    overlapCount: number;
    overlapPctA: number;
    overlapPctB: number;
  }>;
}

// 6.1: Confidence distribution types
interface ConfidenceDistribution {
  totalEntries: number;
  activeEntries: number;
  averageConfidence: number;
  distribution: { label: string; min: number; max: number; count: number }[];
  highConfidence: IocEntry[];
  lowConfidence: IocEntry[];
}

// 6.2: Expiration summary types
interface ExpirationSummary {
  expired: IocEntry[];
  expiringSoon: IocEntry[];
  expiringMonth: IocEntry[];
  noExpirationCount: number;
  agingDistribution: { label: string; count: number }[];
  summary: {
    totalExpired: number;
    totalExpiringSoon: number;
    totalExpiringMonth: number;
    totalNoExpiration: number;
  };
}

// 6.3: IOC relationship graph types
interface IocGraphNode {
  id: string;
  label: string;
  type: string;
  confidence: number;
  severity: string;
  malwareFamily: string | null;
  campaignName: string | null;
}

interface IocGraphEdge {
  source: string;
  target: string;
  label: string;
  weight: number;
}

interface IocRelationshipGraph {
  nodes: IocGraphNode[];
  edges: IocGraphEdge[];
  stats: {
    totalNodes: number;
    totalEdges: number;
    malwareFamilies: number;
    campaigns: number;
    connectedComponents: number;
  };
}

// 6.5: Retroactive match summary
interface RetroactiveMatchSummary {
  totalMatches: number;
  retroactiveMatches: number;
  realtimeMatches: number;
  activeIocs: number;
  recentRetroactive: {
    id: string;
    iocEntryId: string | null;
    alertId: string | null;
    matchField: string | null;
    matchValue: string | null;
    confidence: number | null;
    enrichmentData: Record<string, any> | null;
    createdAt: string | null;
  }[];
}

// 6.6: Enrichment status
interface EnrichmentStatus {
  totalActive: number;
  enrichedCount: number;
  notEnrichedCount: number;
  enrichmentRate: number;
  byType: { type: string; enriched: number; total: number; rate: number }[];
  recentlyEnriched: IocEntry[];
}

// 6.7: False positive tracking
interface FpTrackingSummary {
  totalEntries: number;
  trackedCount: number;
  totalFalsePositives: number;
  totalTruePositives: number;
  overallFpRate: number;
  suppressedCount: number;
  highFpIocs: { id: string; iocValue: string; iocType: string; fpRate: number; fpCount: number; tpCount: number }[];
  feedFpRates: { feed: string; fpCount: number; tpCount: number; total: number; fpRate: number }[];
}

// 6.8: Generated rules
interface GeneratedRulesSummary {
  totalRules: number;
  rules: {
    jobId: string;
    name: string;
    description: string | null;
    severity: string | null;
    format: string;
    status: string;
    qualityScore: number | null;
    sourceId: string | null;
    createdAt: string | null;
  }[];
}

// 6.9: Community sharing status
interface CommunitySharingStatus {
  consentActive: boolean;
  consentLevel: string;
  totalActive: number;
  sharedCount: number;
  notSharedCount: number;
  sharingRate: number;
  sharedByType: { type: string; count: number }[];
  contributedIocCount: number;
  lastContributedAt: string | null;
}

const IOC_TYPE_OPTIONS = ["ip", "domain", "url", "hash", "email", "cve"];
const MATCH_FIELD_OPTIONS = ["sourceIp", "destIp", "domain", "url", "fileHash", "sender", "subject"];
const ACTION_OPTIONS = [
  { value: "tag", label: "Tag Alert" },
  { value: "escalate", label: "Escalate to Incident" },
  { value: "notify", label: "Send Notification" },
  { value: "block", label: "Block (Response Action)" },
];

const EMPTY_RULE_FORM = {
  name: "",
  description: "",
  feedId: "",
  iocTypes: [] as string[],
  matchFields: [] as string[],
  minConfidence: 50,
  enabled: true,
  autoEnrich: true,
  action: "tag",
};

function LoadingSkeleton() {
  return (
    <div className="p-6 space-y-6" role="status" aria-label="Loading IOC ingestion">
      <Skeleton className="h-8 w-72" />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-96" />
      <span className="sr-only">Loading IOC ingestion data...</span>
    </div>
  );
}

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="p-6">
      <Card className="glass-card border-red-500/30">
        <CardContent className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-400 mb-4" />
          <p className="text-lg font-semibold mb-2">Failed to Load IOC Data</p>
          <p className="text-sm text-muted-foreground mb-4">Could not retrieve IOC feeds and statistics.</p>
          <Button onClick={onRetry} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-1" /> Retry
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

const IOC_TYPE_ICONS: Record<string, typeof Globe> = {
  ip: Server,
  domain: Globe,
  url: Link2,
  hash: Hash,
  email: Mail,
  cve: Bug,
};

const FEED_TYPE_COLORS: Record<string, string> = {
  misp: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  stix: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  taxii: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  otx: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  virustotal: "bg-red-500/15 text-red-400 border-red-500/30",
  csv: "bg-amber-500/15 text-amber-400 border-amber-500/30",
};

// 4.1: Feed health status indicator — colored dot (green/yellow/red)
function FeedHealthDot({ status, lastFetchAt }: { status: string | null; lastFetchAt: string | null }) {
  let color = "bg-slate-400";
  let label = "Unknown";
  let pulse = false;

  if (!status && !lastFetchAt) {
    color = "bg-slate-400";
    label = "Never synced";
  } else if (status === "success") {
    // Check if stale (> 24h since last fetch)
    const hoursSince = lastFetchAt ? (Date.now() - new Date(lastFetchAt).getTime()) / (1000 * 60 * 60) : Infinity;
    if (hoursSince <= 24) {
      color = "bg-emerald-500";
      label = "Active — syncing";
      pulse = true;
    } else {
      color = "bg-amber-500";
      label = `Stale — last sync ${Math.round(hoursSince)}h ago`;
    }
  } else if (status) {
    color = "bg-red-500";
    label = `Error — ${status}`;
  }

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="relative flex h-2.5 w-2.5">
            {pulse && (
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${color} opacity-75`} />
            )}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${color}`} />
          </span>
        </TooltipTrigger>
        <TooltipContent side="top" className="text-xs">
          {label}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function FeedStatusBadge({ status }: { status: string | null }) {
  if (!status) {
    return (
      <Badge variant="outline" className="bg-slate-500/15 text-slate-400 border-slate-500/30 text-xs">
        <Clock className="h-3 w-3 mr-1" /> Never Run
      </Badge>
    );
  }
  if (status === "success") {
    return (
      <Badge variant="outline" className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-xs">
        <CheckCircle2 className="h-3 w-3 mr-1" /> Success
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 text-xs">
      <XCircle className="h-3 w-3 mr-1" /> {status}
    </Badge>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const color = confidence >= 80 ? "bg-emerald-500" : confidence >= 50 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${confidence}%` }} />
      </div>
      <span className="text-xs font-medium">{confidence}%</span>
    </div>
  );
}

function TypeDistributionChart({ distribution }: { distribution: { type: string; count: number }[] }) {
  const total = distribution.reduce((sum, d) => sum + d.count, 0);
  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
        <Database className="h-8 w-8 mb-2 opacity-40" />
        <p className="text-xs">No IOC type data available</p>
      </div>
    );
  }

  const typeColors: Record<string, string> = {
    ip: "bg-blue-500",
    domain: "bg-emerald-500",
    url: "bg-amber-500",
    hash: "bg-purple-500",
    email: "bg-pink-500",
    cve: "bg-red-500",
  };

  return (
    <div className="space-y-2">
      {distribution
        .sort((a, b) => b.count - a.count)
        .map((d) => {
          const Icon = IOC_TYPE_ICONS[d.type] || Database;
          const pct = total > 0 ? (d.count / total) * 100 : 0;
          return (
            <div key={d.type} className="flex items-center gap-2">
              <Icon className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
              <span className="text-xs text-muted-foreground w-14">{d.type}</span>
              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${typeColors[d.type] || "bg-slate-500"}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="text-xs font-medium w-10 text-right">{d.count}</span>
            </div>
          );
        })}
    </div>
  );
}

export default function IocIngestionMatchingPage() {
  usePageTitle("IOC Ingestion & Matching");
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("feeds");
  const [feedTypeFilter, setFeedTypeFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [showUploadDialog, setShowUploadDialog] = useState(false);
  const [uploadData, setUploadData] = useState("");
  const [selectedFeedId, setSelectedFeedId] = useState<string | null>(null);
  const [entryTypeFilter, setEntryTypeFilter] = useState<string>("all");
  const [ingestingFeedIds, setIngestingFeedIds] = useState<Set<string>>(new Set());
  const [showRuleDialog, setShowRuleDialog] = useState(false);
  const [editingRule, setEditingRule] = useState<IocMatchRule | null>(null);
  const [ruleForm, setRuleForm] = useState(EMPTY_RULE_FORM);
  const [showPreviewDialog, setShowPreviewDialog] = useState(false);
  const [previewFeedId, setPreviewFeedId] = useState<string | null>(null);
  const [showStatsDialog, setShowStatsDialog] = useState(false);
  const [statsFeedId, setStatsFeedId] = useState<string | null>(null);
  const [showAuthDialog, setShowAuthDialog] = useState(false);
  const [authFeedId, setAuthFeedId] = useState<string | null>(null);
  const [authForm, setAuthForm] = useState<{
    authType: string;
    apiKeyHeader: string;
    apiKeyValue: string;
    bearerToken: string;
    basicUsername: string;
    basicPassword: string;
  }>({
    authType: "none",
    apiKeyHeader: "X-API-Key",
    apiKeyValue: "",
    bearerToken: "",
    basicUsername: "",
    basicPassword: "",
  });

  const {
    data: feeds,
    isLoading: isLoadingFeeds,
    isError: isErrorFeeds,
    refetch: refetchFeeds,
  } = useQuery<IocFeed[]>({
    queryKey: ["/api/ioc-feeds"],
  });

  const { data: stats, isLoading: isLoadingStats } = useQuery<IocStats>({
    queryKey: ["/api/ioc-stats"],
  });

  const { data: entries, isLoading: isLoadingEntries } = useQuery<IocEntry[]>({
    queryKey: ["/api/ioc-entries"],
  });

  const { data: matches, isLoading: isLoadingMatches } = useQuery<IocMatch[]>({
    queryKey: ["/api/ioc-matches"],
  });

  const { data: matchRules, isLoading: isLoadingRules } = useQuery<IocMatchRule[]>({
    queryKey: ["/api/ioc-match-rules"],
  });

  // 4.2: Feed ingestion stats query
  const { data: feedStatsData, isLoading: isLoadingFeedStats } = useQuery<FeedIngestionStats>({
    queryKey: ["/api/ioc-feeds", statsFeedId, "stats"],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/ioc-feeds/${statsFeedId}/stats`);
      return res.json();
    },
    enabled: !!statsFeedId && showStatsDialog,
  });

  // 4.3: Feed preview mutation
  const previewMutation = useMutation({
    mutationFn: async (feedId: string) => {
      const res = await apiRequest("POST", `/api/ioc-feeds/${feedId}/preview`);
      return res.json() as Promise<FeedPreviewResult>;
    },
  });

  // 4.4: Feed comparison data
  const { data: comparisonData, isLoading: isLoadingComparison } = useQuery<FeedComparisonData>({
    queryKey: ["/api/ioc-feeds/compare"],
    enabled: activeTab === "comparison",
  });

  // 6.1: Confidence distribution
  const { data: confidenceData, isLoading: isLoadingConfidence } = useQuery<ConfidenceDistribution>({
    queryKey: ["/api/ioc-entries/confidence/distribution"],
    enabled: activeTab === "confidence",
  });

  // 6.2: Expiration summary
  const { data: expirationData, isLoading: isLoadingExpiration } = useQuery<ExpirationSummary>({
    queryKey: ["/api/ioc-entries/expiration/summary"],
    enabled: activeTab === "expiration",
  });

  // 6.3: Relationship graph
  const { data: graphData, isLoading: isLoadingGraph } = useQuery<IocRelationshipGraph>({
    queryKey: ["/api/ioc-entries/relationships"],
    enabled: activeTab === "graph",
  });

  // 6.5: Retroactive match summary
  const { data: retroMatchData, isLoading: isLoadingRetroMatch } = useQuery<RetroactiveMatchSummary>({
    queryKey: ["/api/ioc-entries/retroactive-match/summary"],
    enabled: activeTab === "retroactive",
  });

  // 6.6: Enrichment status
  const { data: enrichmentStatusData, isLoading: isLoadingEnrichmentStatus } = useQuery<EnrichmentStatus>({
    queryKey: ["/api/ioc-entries/enrichment-status"],
    enabled: activeTab === "autoenrich",
  });

  // 6.7: False positive tracking
  const { data: fpTrackingData, isLoading: isLoadingFpTracking } = useQuery<FpTrackingSummary>({
    queryKey: ["/api/ioc-entries/false-positive/summary"],
    enabled: activeTab === "fptracking",
  });

  // 6.8: Generated rules from IOCs
  const { data: generatedRulesData, isLoading: isLoadingGeneratedRules } = useQuery<GeneratedRulesSummary>({
    queryKey: ["/api/ioc-entries/generated-rules"],
    enabled: activeTab === "autorules",
  });

  // 6.9: Community sharing status
  const { data: communitySharingData, isLoading: isLoadingCommunitySharing } = useQuery<CommunitySharingStatus>({
    queryKey: ["/api/ioc-entries/community-sharing/status"],
    enabled: activeTab === "communityshare",
  });

  // Mutations for 6.5-6.9
  const retroMatchMutation = useMutation({
    mutationFn: async (params: { lookbackDays?: number; maxAlerts?: number }) => {
      const res = await apiRequest("POST", "/api/ioc-entries/retroactive-match", params);
      return res.json();
    },
    onSuccess: (data: any) => {
      toast({
        title: "Retroactive Matching Complete",
        description: `Found ${data.matchesFound} matches across ${data.alertsScanned} alerts`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries/retroactive-match/summary"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-matches"] });
    },
    onError: (err: Error) =>
      toast({ title: "Retroactive Match Failed", description: err.message, variant: "destructive" }),
  });

  const autoEnrichMutation = useMutation({
    mutationFn: async (params: { iocEntryIds: string[] }) => {
      const res = await apiRequest("POST", "/api/ioc-entries/auto-enrich", params);
      return res.json();
    },
    onSuccess: (data: any) => {
      toast({
        title: "Auto-Enrichment Complete",
        description: `Enriched ${data.enrichedCount} of ${data.requestedCount} IOC entries`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries/enrichment-status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries"] });
    },
    onError: (err: Error) => toast({ title: "Enrichment Failed", description: err.message, variant: "destructive" }),
  });

  const generateRulesMutation = useMutation({
    mutationFn: async (params: { ruleFormat?: string; minConfidence?: number }) => {
      const res = await apiRequest("POST", "/api/ioc-entries/generate-rules", params);
      return res.json();
    },
    onSuccess: (data: any) => {
      toast({ title: "Rule Generation Complete", description: `Generated ${data.generated} detection rules` });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries/generated-rules"] });
    },
    onError: (err: Error) =>
      toast({ title: "Rule Generation Failed", description: err.message, variant: "destructive" }),
  });

  const shareCommMutation = useMutation({
    mutationFn: async (params: { iocEntryIds: string[]; tlpLevel?: string }) => {
      const res = await apiRequest("POST", "/api/ioc-entries/share-community", params);
      return res.json();
    },
    onSuccess: (data: any) => {
      toast({ title: "Community Sharing Complete", description: `Shared ${data.shared} IOCs to community network` });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries/community-sharing/status"] });
    },
    onError: (err: Error) => toast({ title: "Sharing Failed", description: err.message, variant: "destructive" }),
  });

  const ingestMutation = useMutation({
    mutationFn: async ({ feedId, rawData }: { feedId: string; rawData: unknown }) => {
      const res = await apiRequest("POST", `/api/ioc-feeds/${feedId}/ingest`, { data: rawData });
      return res.json();
    },
    onSuccess: (data: { newEntries?: number; totalParsed?: number }, variables) => {
      toast({
        title: "Ingestion Complete",
        description: `Parsed ${data.totalParsed || 0} entries, ${data.newEntries || 0} new`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-feeds"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-stats"] });
      setIngestingFeedIds((prev) => {
        const next = new Set(prev);
        next.delete(variables.feedId);
        return next;
      });
    },
    onError: (err: Error, variables) => {
      toast({ title: "Ingestion Failed", description: err.message, variant: "destructive" });
      setIngestingFeedIds((prev) => {
        const next = new Set(prev);
        next.delete(variables.feedId);
        return next;
      });
    },
  });

  const createRuleMutation = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await apiRequest("POST", "/api/ioc-match-rules", data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Rule Created", description: "Match rule has been created." });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-match-rules"] });
      setShowRuleDialog(false);
      setRuleForm(EMPTY_RULE_FORM);
      setEditingRule(null);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to Create Rule", description: err.message, variant: "destructive" });
    },
  });

  const updateRuleMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Record<string, unknown> }) => {
      const res = await apiRequest("PATCH", "/api/ioc-match-rules/" + id, data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Rule Updated", description: "Match rule has been updated." });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-match-rules"] });
      setShowRuleDialog(false);
      setRuleForm(EMPTY_RULE_FORM);
      setEditingRule(null);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to Update Rule", description: err.message, variant: "destructive" });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("DELETE", "/api/ioc-match-rules/" + id);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Rule Deleted", description: "Match rule has been removed." });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-match-rules"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to Delete Rule", description: err.message, variant: "destructive" });
    },
  });

  const toggleRuleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const res = await apiRequest("PATCH", "/api/ioc-match-rules/" + id, { enabled });
      return res.json();
    },
    onSuccess: (_data: unknown, variables: { id: string; enabled: boolean }) => {
      toast({
        title: variables.enabled ? "Rule Enabled" : "Rule Disabled",
        description: "Match rule has been " + (variables.enabled ? "enabled" : "disabled") + ".",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-match-rules"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to Toggle Rule", description: err.message, variant: "destructive" });
    },
  });

  const manualUploadMutation = useMutation({
    mutationFn: async (data: { feedId: string; rawData: string }) => {
      const res = await apiRequest("POST", `/api/ioc-feeds/${data.feedId}/ingest`, { data: data.rawData });
      return res.json();
    },
    onSuccess: (data: { newEntries?: number; totalParsed?: number }) => {
      toast({
        title: "Upload Complete",
        description: `Parsed ${data.totalParsed || 0} entries, ${data.newEntries || 0} new`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-feeds"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-entries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-stats"] });
      setShowUploadDialog(false);
      setUploadData("");
    },
    onError: (err: Error) => {
      toast({ title: "Upload Failed", description: err.message, variant: "destructive" });
    },
  });

  // 4.5: Schedule mutation
  const scheduleMutation = useMutation({
    mutationFn: async ({ feedId, schedule }: { feedId: string; schedule: string }) => {
      const res = await apiRequest("PATCH", `/api/ioc-feeds/${feedId}/schedule`, { schedule });
      return res.json();
    },
    onSuccess: (_data: unknown, variables: { feedId: string; schedule: string }) => {
      toast({
        title: "Schedule Updated",
        description: `Feed schedule set to ${variables.schedule === "manual" ? "manual" : "every " + variables.schedule}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-feeds"] });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to Update Schedule", description: err.message, variant: "destructive" });
    },
  });

  // 4.8: Auth config mutation
  const authMutation = useMutation({
    mutationFn: async ({ feedId, authConfig }: { feedId: string; authConfig: Record<string, string> }) => {
      const res = await apiRequest("PATCH", `/api/ioc-feeds/${feedId}/auth`, authConfig);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Authentication Updated", description: "Feed authentication config saved." });
      queryClient.invalidateQueries({ queryKey: ["/api/ioc-feeds"] });
      setShowAuthDialog(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to Update Auth", description: err.message, variant: "destructive" });
    },
  });

  if (isLoadingFeeds || isLoadingStats) return <LoadingSkeleton />;
  if (isErrorFeeds) return <ErrorState onRetry={() => refetchFeeds()} />;

  const allFeeds = Array.isArray(feeds) ? feeds : [];
  const allEntries = Array.isArray(entries) ? entries : [];
  const allMatches = Array.isArray(matches) ? matches : [];
  const iocStats = stats || {
    totalIOCs: 0,
    activeIOCs: 0,
    totalMatches: 0,
    topMalwareFamilies: [],
    typeDistribution: [],
  };

  const filteredFeeds = allFeeds.filter((f) => {
    const matchesSearch = !searchQuery || f.name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = feedTypeFilter === "all" || f.feedType === feedTypeFilter;
    return matchesSearch && matchesType;
  });

  const filteredEntries = allEntries.filter((e) => {
    const matchesSearch =
      !searchQuery ||
      e.iocValue.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.malwareFamily || "").toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = entryTypeFilter === "all" || e.iocType === entryTypeFilter;
    return matchesSearch && matchesType;
  });

  const filteredMatches = allMatches.filter((m) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      m.matchValue.toLowerCase().includes(q) ||
      m.matchField.toLowerCase().includes(q) ||
      (m.enrichmentData?.malwareFamily || "").toLowerCase().includes(q) ||
      (m.enrichmentData?.campaignName || "").toLowerCase().includes(q)
    );
  });

  const feedTypes = Array.from(new Set(allFeeds.map((f) => f.feedType)));
  const entryTypes = Array.from(new Set(allEntries.map((e) => e.iocType)));
  const enabledFeeds = allFeeds.filter((f) => f.enabled).length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">IOC Ingestion &amp; Matching</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage threat feeds, ingest indicators, and review match results
          </p>
        </div>
        <Button size="sm" onClick={() => setShowUploadDialog(true)} className="gap-1">
          <Upload className="h-4 w-4" /> Manual Upload
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Total IOCs</p>
                <p className="text-2xl font-bold">{iocStats.totalIOCs.toLocaleString()}</p>
              </div>
              <Database className="h-8 w-8 text-cyan-400 opacity-60" />
            </div>
            <p className="text-xs text-muted-foreground mt-1">{iocStats.activeIOCs.toLocaleString()} active</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Active Feeds</p>
                <p className="text-2xl font-bold">{enabledFeeds}</p>
              </div>
              <Rss className="h-8 w-8 text-emerald-400 opacity-60" />
            </div>
            <p className="text-xs text-muted-foreground mt-1">of {allFeeds.length} total feeds</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Total Matches</p>
                <p className="text-2xl font-bold">{iocStats.totalMatches.toLocaleString()}</p>
              </div>
              <Target className="h-8 w-8 text-amber-400 opacity-60" />
            </div>
            <p className="text-xs text-muted-foreground mt-1">across alerts &amp; incidents</p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Malware Families</p>
                <p className="text-2xl font-bold">{iocStats.topMalwareFamilies.length}</p>
              </div>
              <Bug className="h-8 w-8 text-red-400 opacity-60" />
            </div>
            <p className="text-xs text-muted-foreground mt-1">tracked families</p>
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={
              activeTab === "feeds"
                ? "Search feeds..."
                : activeTab === "entries"
                  ? "Search IOCs..."
                  : "Search matches..."
            }
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
        {activeTab === "feeds" && (
          <Select value={feedTypeFilter} onValueChange={setFeedTypeFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              {feedTypes.map((t) => (
                <SelectItem key={t} value={t}>
                  {t.toUpperCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {activeTab === "entries" && (
          <Select value={entryTypeFilter} onValueChange={setEntryTypeFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              {entryTypes.map((t) => (
                <SelectItem key={t} value={t}>
                  {t.toUpperCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="feeds" className="gap-1">
            <Rss className="h-4 w-4" /> Feeds ({allFeeds.length})
          </TabsTrigger>
          <TabsTrigger value="entries" className="gap-1">
            <Database className="h-4 w-4" /> IOC Entries ({allEntries.length})
          </TabsTrigger>
          <TabsTrigger value="matches" className="gap-1">
            <Target className="h-4 w-4" /> Matches ({allMatches.length})
          </TabsTrigger>
          <TabsTrigger value="rules" className="gap-1">
            <Settings2 className="h-4 w-4" /> Rules ({(Array.isArray(matchRules) ? matchRules : []).length})
          </TabsTrigger>
          <TabsTrigger value="enrichment" className="gap-1">
            <BarChart3 className="h-4 w-4" /> Enrichment
          </TabsTrigger>
          <TabsTrigger value="comparison" className="gap-1">
            <GitCompare className="h-4 w-4" /> Feed Comparison
          </TabsTrigger>
          <TabsTrigger value="confidence" className="gap-1">
            <Gauge className="h-4 w-4" /> Confidence
          </TabsTrigger>
          <TabsTrigger value="expiration" className="gap-1">
            <Timer className="h-4 w-4" /> Expiration
          </TabsTrigger>
          <TabsTrigger value="graph" className="gap-1">
            <Network className="h-4 w-4" /> Relationships
          </TabsTrigger>
          <TabsTrigger value="export" className="gap-1">
            <Download className="h-4 w-4" /> Export
          </TabsTrigger>
          <TabsTrigger value="retroactive" className="gap-1">
            <Scan className="h-4 w-4" /> Retroactive
          </TabsTrigger>
          <TabsTrigger value="autoenrich" className="gap-1">
            <Sparkles className="h-4 w-4" /> Auto-Enrich
          </TabsTrigger>
          <TabsTrigger value="fptracking" className="gap-1">
            <ThumbsDown className="h-4 w-4" /> FP Tracking
          </TabsTrigger>
          <TabsTrigger value="autorules" className="gap-1">
            <Wand2 className="h-4 w-4" /> Auto-Rules
          </TabsTrigger>
          <TabsTrigger value="communityshare" className="gap-1">
            <Share2 className="h-4 w-4" /> Community
          </TabsTrigger>
        </TabsList>

        <TabsContent value="feeds" className="mt-4">
          {isLoadingFeeds ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-20" />
              ))}
            </div>
          ) : filteredFeeds.length === 0 ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Rss className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No feeds found</p>
                {searchQuery && <p className="text-xs mt-1">Try adjusting your search or filter</p>}
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {filteredFeeds.map((feed) => (
                <Card key={feed.id} className="glass-card border-border/40 hover:border-border/60 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <FeedHealthDot status={feed.lastFetchStatus} lastFetchAt={feed.lastFetchAt} />
                        <Rss className="h-4 w-4 text-cyan-400" />
                        <span className="text-sm font-semibold">{feed.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${FEED_TYPE_COLORS[feed.feedType] || "bg-slate-500/15 text-slate-400 border-slate-500/30"}`}
                        >
                          {feed.feedType.toUpperCase()}
                        </Badge>
                        {feed.enabled ? (
                          <Badge
                            variant="outline"
                            className="text-[10px] bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                          >
                            Active
                          </Badge>
                        ) : (
                          <Badge
                            variant="outline"
                            className="text-[10px] bg-slate-500/15 text-slate-400 border-slate-500/30"
                          >
                            Disabled
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-3 mb-3">
                      <div>
                        <p className="text-[10px] text-muted-foreground">IOC Count</p>
                        <p className="text-sm font-medium">{(feed.totalIocCount || 0).toLocaleString()}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground">Last Fetch</p>
                        <p className="text-sm font-medium">
                          {feed.lastFetchAt ? new Date(feed.lastFetchAt).toLocaleDateString() : "Never"}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground">Schedule</p>
                        <Select
                          value={feed.schedule || "manual"}
                          onValueChange={(val) => scheduleMutation.mutate({ feedId: feed.id, schedule: val })}
                        >
                          <SelectTrigger className="h-6 w-[90px] text-xs border-border/40">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="manual">Manual</SelectItem>
                            <SelectItem value="1h">Every 1h</SelectItem>
                            <SelectItem value="6h">Every 6h</SelectItem>
                            <SelectItem value="12h">Every 12h</SelectItem>
                            <SelectItem value="24h">Every 24h</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <FeedStatusBadge status={feed.lastFetchStatus} />
                        {(() => {
                          const cfg = (feed.config as Record<string, unknown>) || {};
                          const auth = (cfg.auth as Record<string, string>) || {};
                          const at = auth.authType;
                          if (at && at !== "none") {
                            return (
                              <Badge
                                variant="outline"
                                className="text-[10px] bg-green-500/15 text-green-400 border-green-500/30"
                              >
                                <Lock className="h-2.5 w-2.5 mr-0.5" />
                                {at.toUpperCase()}
                              </Badge>
                            );
                          }
                          return null;
                        })()}
                      </div>
                      <div className="flex items-center gap-1">
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0"
                                onClick={() => {
                                  setStatsFeedId(feed.id);
                                  setShowStatsDialog(true);
                                }}
                              >
                                <Activity className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>View ingestion stats</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0"
                                onClick={() => {
                                  setPreviewFeedId(feed.id);
                                  setShowPreviewDialog(true);
                                  previewMutation.mutate(feed.id);
                                }}
                              >
                                <Eye className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Preview sample IOCs</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0"
                                onClick={() => {
                                  setAuthFeedId(feed.id);
                                  const config = (feed.config as Record<string, unknown>) || {};
                                  const auth = (config.auth as Record<string, string>) || {};
                                  setAuthForm({
                                    authType: auth.authType || "none",
                                    apiKeyHeader: auth.apiKeyHeader || "X-API-Key",
                                    apiKeyValue: "",
                                    bearerToken: "",
                                    basicUsername: auth.basicUsername || "",
                                    basicPassword: "",
                                  });
                                  setShowAuthDialog(true);
                                }}
                              >
                                <Key className="h-3.5 w-3.5" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Configure authentication</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="outline"
                                size="sm"
                                className="gap-1 h-7"
                                onClick={() => {
                                  setIngestingFeedIds((prev) => new Set(prev).add(feed.id));
                                  ingestMutation.mutate({ feedId: feed.id, rawData: null });
                                }}
                                disabled={ingestingFeedIds.has(feed.id)}
                              >
                                {ingestingFeedIds.has(feed.id) ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <Play className="h-3 w-3" />
                                )}
                                Ingest
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Trigger manual ingestion for this feed</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="entries" className="mt-4">
          {isLoadingEntries ? (
            <Skeleton className="h-64" />
          ) : filteredEntries.length === 0 ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Database className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No IOC entries found</p>
                {searchQuery && <p className="text-xs mt-1">Try adjusting your search</p>}
              </CardContent>
            </Card>
          ) : (
            <Card className="glass-card">
              <ScrollArea className="h-[500px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-20">Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead className="w-24">Confidence</TableHead>
                      <TableHead className="w-20">Severity</TableHead>
                      <TableHead>Malware</TableHead>
                      <TableHead className="w-20">Status</TableHead>
                      <TableHead className="w-24">First Seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredEntries.slice(0, 100).map((entry) => {
                      const TypeIcon = IOC_TYPE_ICONS[entry.iocType] || Database;
                      return (
                        <TableRow key={entry.id}>
                          <TableCell>
                            <div className="flex items-center gap-1">
                              <TypeIcon className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="text-xs">{entry.iocType}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs font-mono break-all">{entry.iocValue}</span>
                          </TableCell>
                          <TableCell>
                            <ConfidenceBar confidence={entry.confidence} />
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                entry.severity === "critical"
                                  ? "bg-red-500/15 text-red-400 border-red-500/30"
                                  : entry.severity === "high"
                                    ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
                                    : entry.severity === "medium"
                                      ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                      : "bg-slate-500/15 text-slate-400 border-slate-500/30"
                              }`}
                            >
                              {entry.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs">{entry.malwareFamily || "—"}</span>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                entry.status === "active"
                                  ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                  : "bg-slate-500/15 text-slate-400 border-slate-500/30"
                              }`}
                            >
                              {entry.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs text-muted-foreground">
                              {entry.firstSeen ? new Date(entry.firstSeen).toLocaleDateString() : "—"}
                            </span>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </ScrollArea>
              {filteredEntries.length > 100 && (
                <div className="px-4 py-2 border-t border-border/50 text-xs text-muted-foreground">
                  Showing first 100 of {filteredEntries.length} entries
                </div>
              )}
            </Card>
          )}
        </TabsContent>

        <TabsContent value="matches" className="mt-4">
          {isLoadingMatches ? (
            <Skeleton className="h-64" />
          ) : filteredMatches.length === 0 ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Target className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No IOC matches found</p>
                {searchQuery ? (
                  <p className="text-xs mt-1">Try adjusting your search</p>
                ) : (
                  <p className="text-xs mt-1">Matches appear when IOCs are found in alerts or incidents</p>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card className="glass-card">
              <ScrollArea className="h-[500px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Match Value</TableHead>
                      <TableHead className="w-24">Field</TableHead>
                      <TableHead className="w-24">Confidence</TableHead>
                      <TableHead>Alert / Incident</TableHead>
                      <TableHead>Enrichment</TableHead>
                      <TableHead className="w-28">Matched At</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredMatches.slice(0, 100).map((match) => {
                      const enrichment: EnrichmentData = match.enrichmentData || {};
                      return (
                        <TableRow key={match.id}>
                          <TableCell>
                            <span className="text-xs font-mono break-all">{match.matchValue}</span>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-[10px]">
                              {match.matchField}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <ConfidenceBar confidence={match.confidence} />
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-col gap-0.5">
                              {match.alertId && (
                                <span className="text-xs text-muted-foreground">
                                  Alert: {match.alertId.slice(0, 8)}...
                                </span>
                              )}
                              {match.incidentId && (
                                <span className="text-xs text-muted-foreground">
                                  Incident: {match.incidentId.slice(0, 8)}...
                                </span>
                              )}
                              {!match.alertId && !match.incidentId && (
                                <span className="text-xs text-muted-foreground">—</span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {enrichment.malwareFamily && (
                                <Badge
                                  variant="outline"
                                  className="text-[10px] bg-red-500/10 text-red-400 border-red-500/20"
                                >
                                  {enrichment.malwareFamily}
                                </Badge>
                              )}
                              {enrichment.campaignName && (
                                <Badge
                                  variant="outline"
                                  className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/20"
                                >
                                  {enrichment.campaignName}
                                </Badge>
                              )}
                              {!enrichment.malwareFamily && !enrichment.campaignName && (
                                <span className="text-xs text-muted-foreground">—</span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <span className="text-xs text-muted-foreground">
                              {new Date(match.createdAt).toLocaleDateString()}
                            </span>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </ScrollArea>
              {filteredMatches.length > 100 && (
                <div className="px-4 py-2 border-t border-border/50 text-xs text-muted-foreground">
                  Showing first 100 of {filteredMatches.length} matches
                </div>
              )}
            </Card>
          )}
        </TabsContent>

        <TabsContent value="rules" className="mt-4">
          {isLoadingRules ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-20" />
              ))}
            </div>
          ) : (
            (() => {
              const allRules = Array.isArray(matchRules) ? matchRules : [];
              const filteredRules = allRules.filter((r) => {
                if (!searchQuery) return true;
                const q = searchQuery.toLowerCase();
                return r.name.toLowerCase().includes(q) || (r.description || "").toLowerCase().includes(q);
              });
              return (
                <div className="space-y-4">
                  <div className="flex justify-end">
                    <Button
                      size="sm"
                      className="gap-1"
                      onClick={() => {
                        setEditingRule(null);
                        setRuleForm(EMPTY_RULE_FORM);
                        setShowRuleDialog(true);
                      }}
                    >
                      <Plus className="h-4 w-4" /> New Rule
                    </Button>
                  </div>
                  {filteredRules.length === 0 ? (
                    <Card className="glass-card">
                      <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                        <Settings2 className="h-10 w-10 mb-3 opacity-40" />
                        <p className="text-sm">No match rules configured</p>
                        <p className="text-xs mt-1">Create a rule to automatically match IOCs against alerts</p>
                      </CardContent>
                    </Card>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {filteredRules.map((rule) => {
                        const targetFeed = allFeeds.find((f) => f.id === rule.feedId);
                        return (
                          <Card
                            key={rule.id}
                            className="glass-card border-border/40 hover:border-border/60 transition-colors"
                          >
                            <CardContent className="p-4">
                              <div className="flex items-start justify-between mb-3">
                                <div className="flex items-center gap-2">
                                  <Settings2 className="h-4 w-4 text-cyan-400" />
                                  <span className="text-sm font-semibold">{rule.name}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  {rule.enabled ? (
                                    <Badge
                                      variant="outline"
                                      className="text-[10px] bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                    >
                                      Active
                                    </Badge>
                                  ) : (
                                    <Badge
                                      variant="outline"
                                      className="text-[10px] bg-slate-500/15 text-slate-400 border-slate-500/30"
                                    >
                                      Disabled
                                    </Badge>
                                  )}
                                  <Badge variant="outline" className="text-[10px]">
                                    {ACTION_OPTIONS.find((a) => a.value === rule.action)?.label || rule.action}
                                  </Badge>
                                </div>
                              </div>

                              {rule.description && (
                                <p className="text-xs text-muted-foreground mb-3">{rule.description}</p>
                              )}

                              <div className="grid grid-cols-3 gap-3 mb-3">
                                <div>
                                  <p className="text-[10px] text-muted-foreground">Target Feed</p>
                                  <p className="text-sm font-medium">
                                    {targetFeed ? targetFeed.name : rule.feedId ? "Unknown" : "All Feeds"}
                                  </p>
                                </div>
                                <div>
                                  <p className="text-[10px] text-muted-foreground">Min Confidence</p>
                                  <p className="text-sm font-medium">{rule.minConfidence}%</p>
                                </div>
                                <div>
                                  <p className="text-[10px] text-muted-foreground">Matches</p>
                                  <p className="text-sm font-medium">{rule.matchCount}</p>
                                </div>
                              </div>

                              <div className="flex flex-wrap gap-1 mb-3">
                                {(rule.iocTypes || []).map((t) => (
                                  <Badge
                                    key={t}
                                    variant="outline"
                                    className="text-[10px] bg-blue-500/10 text-blue-400 border-blue-500/20"
                                  >
                                    {t}
                                  </Badge>
                                ))}
                                {(rule.matchFields || []).map((f) => (
                                  <Badge
                                    key={f}
                                    variant="outline"
                                    className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/20"
                                  >
                                    {f}
                                  </Badge>
                                ))}
                              </div>

                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-muted-foreground">
                                  {rule.lastMatchAt
                                    ? "Last match: " + new Date(rule.lastMatchAt).toLocaleDateString()
                                    : "No matches yet"}
                                </span>
                                <div className="flex items-center gap-1">
                                  <TooltipProvider>
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <Button
                                          variant="ghost"
                                          size="sm"
                                          className="h-7 w-7 p-0"
                                          onClick={() =>
                                            toggleRuleMutation.mutate({ id: rule.id, enabled: !rule.enabled })
                                          }
                                        >
                                          {rule.enabled ? (
                                            <PowerOff className="h-3.5 w-3.5" />
                                          ) : (
                                            <Power className="h-3.5 w-3.5" />
                                          )}
                                        </Button>
                                      </TooltipTrigger>
                                      <TooltipContent>{rule.enabled ? "Disable rule" : "Enable rule"}</TooltipContent>
                                    </Tooltip>
                                  </TooltipProvider>
                                  <TooltipProvider>
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <Button
                                          variant="ghost"
                                          size="sm"
                                          className="h-7 w-7 p-0"
                                          onClick={() => {
                                            setEditingRule(rule);
                                            setRuleForm({
                                              name: rule.name,
                                              description: rule.description || "",
                                              feedId: rule.feedId || "",
                                              iocTypes: rule.iocTypes || [],
                                              matchFields: rule.matchFields || [],
                                              minConfidence: rule.minConfidence,
                                              enabled: rule.enabled,
                                              autoEnrich: rule.autoEnrich,
                                              action: rule.action,
                                            });
                                            setShowRuleDialog(true);
                                          }}
                                        >
                                          <Pencil className="h-3.5 w-3.5" />
                                        </Button>
                                      </TooltipTrigger>
                                      <TooltipContent>Edit rule</TooltipContent>
                                    </Tooltip>
                                  </TooltipProvider>
                                  <TooltipProvider>
                                    <Tooltip>
                                      <TooltipTrigger asChild>
                                        <Button
                                          variant="ghost"
                                          size="sm"
                                          className="h-7 w-7 p-0 text-red-400 hover:text-red-300"
                                          onClick={() => deleteRuleMutation.mutate(rule.id)}
                                        >
                                          <Trash2 className="h-3.5 w-3.5" />
                                        </Button>
                                      </TooltipTrigger>
                                      <TooltipContent>Delete rule</TooltipContent>
                                    </Tooltip>
                                  </TooltipProvider>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })()
          )}
        </TabsContent>

        <TabsContent value="enrichment" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">IOC Type Distribution</CardTitle>
                <CardDescription className="text-xs">Breakdown of indicator types in your database</CardDescription>
              </CardHeader>
              <CardContent>
                <TypeDistributionChart distribution={iocStats.typeDistribution} />
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Top Malware Families</CardTitle>
                <CardDescription className="text-xs">
                  Most prevalent malware families from ingested IOCs
                </CardDescription>
              </CardHeader>
              <CardContent>
                {iocStats.topMalwareFamilies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                    <Bug className="h-8 w-8 mb-2 opacity-40" />
                    <p className="text-xs">No malware family data available</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {iocStats.topMalwareFamilies.map((fam, idx) => (
                      <div key={fam.name} className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground w-4">{idx + 1}</span>
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">{fam.name}</span>
                            <span className="text-xs text-muted-foreground">{fam.count} IOCs</span>
                          </div>
                          <Progress
                            value={(fam.count / Math.max(iocStats.topMalwareFamilies[0].count, 1)) * 100}
                            className="h-1 mt-1"
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Confidence Distribution</CardTitle>
                <CardDescription className="text-xs">IOC confidence score spread across entries</CardDescription>
              </CardHeader>
              <CardContent>
                {allEntries.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                    <TrendingUp className="h-8 w-8 mb-2 opacity-40" />
                    <p className="text-xs">No entries to analyze</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {[
                      { label: "High (80-100)", min: 80, max: 100, color: "bg-emerald-500" },
                      { label: "Medium (50-79)", min: 50, max: 79, color: "bg-amber-500" },
                      { label: "Low (0-49)", min: 0, max: 49, color: "bg-red-500" },
                    ].map((bucket) => {
                      const count = allEntries.filter(
                        (e) => e.confidence >= bucket.min && e.confidence <= bucket.max,
                      ).length;
                      const pct = allEntries.length > 0 ? (count / allEntries.length) * 100 : 0;
                      return (
                        <div key={bucket.label} className="flex items-center gap-3">
                          <span className="text-xs text-muted-foreground w-28">{bucket.label}</span>
                          <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                            <div className={`h-full ${bucket.color} rounded-full`} style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs font-medium w-12 text-right">
                            {count} ({Math.round(pct)}%)
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Feed Health Summary</CardTitle>
                <CardDescription className="text-xs">Ingestion status across all configured feeds</CardDescription>
              </CardHeader>
              <CardContent>
                {allFeeds.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                    <Rss className="h-8 w-8 mb-2 opacity-40" />
                    <p className="text-xs">No feeds configured</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {allFeeds.slice(0, 8).map((feed) => (
                      <div key={feed.id} className="flex items-center justify-between py-1">
                        <div className="flex items-center gap-2">
                          <FeedHealthDot status={feed.lastFetchStatus} lastFetchAt={feed.lastFetchAt} />
                          <span className="text-xs truncate max-w-[140px]">{feed.name}</span>
                        </div>
                        <span className="text-[10px] text-muted-foreground">
                          {feed.lastFetchAt ? new Date(feed.lastFetchAt).toLocaleDateString() : "Never"}
                        </span>
                      </div>
                    ))}
                    {allFeeds.length > 8 && (
                      <p className="text-[10px] text-muted-foreground text-center pt-1">
                        +{allFeeds.length - 8} more feeds
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 4.4: Feed Comparison Tab */}
        <TabsContent value="comparison" className="mt-4">
          {isLoadingComparison ? (
            <div className="space-y-4">
              <Skeleton className="h-64" />
              <Skeleton className="h-48" />
            </div>
          ) : !comparisonData || comparisonData.feeds.length === 0 ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <GitCompare className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No feeds to compare</p>
                <p className="text-xs mt-1">Add at least two feeds to see comparison data</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Per-feed coverage table */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Feed Coverage Comparison</CardTitle>
                  <CardDescription className="text-xs">
                    Side-by-side comparison of unique IOCs, false positive rates, and feed quality
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="max-h-[400px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Feed</TableHead>
                          <TableHead className="w-20">Type</TableHead>
                          <TableHead className="w-20 text-right">Total IOCs</TableHead>
                          <TableHead className="w-24 text-right">Unique IOCs</TableHead>
                          <TableHead className="w-20 text-right">FP Count</TableHead>
                          <TableHead className="w-20 text-right">FP Rate</TableHead>
                          <TableHead className="w-20">Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {comparisonData.feeds.map((f) => (
                          <TableRow key={f.feedId}>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <FeedHealthDot status={f.lastFetchStatus} lastFetchAt={f.lastFetchAt} />
                                <span className="text-xs font-medium">{f.feedName}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={`text-[10px] ${FEED_TYPE_COLORS[f.feedType] || "bg-slate-500/15 text-slate-400 border-slate-500/30"}`}
                              >
                                {f.feedType.toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-right text-xs font-medium">
                              {f.totalIocs.toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right text-xs font-medium">
                              {f.uniqueIocs.toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right text-xs">{f.fpCount}</TableCell>
                            <TableCell className="text-right">
                              <Badge
                                variant="outline"
                                className={`text-[10px] ${
                                  f.fpRate > 10
                                    ? "bg-red-500/15 text-red-400 border-red-500/30"
                                    : f.fpRate > 5
                                      ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                      : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                }`}
                              >
                                {f.fpRate}%
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={`text-[10px] ${
                                  f.enabled
                                    ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                    : "bg-slate-500/15 text-slate-400 border-slate-500/30"
                                }`}
                              >
                                {f.enabled ? "Active" : "Disabled"}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>

              {/* Overlap matrix */}
              {comparisonData.overlapMatrix.length > 0 && (
                <Card className="glass-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Feed Overlap Matrix</CardTitle>
                    <CardDescription className="text-xs">
                      Percentage of shared IOCs between feeds. High overlap may indicate redundant feeds.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {comparisonData.overlapMatrix.map((overlap) => {
                        const feedAName =
                          comparisonData.feeds.find((f) => f.feedId === overlap.feedA)?.feedName || "Unknown";
                        const feedBName =
                          comparisonData.feeds.find((f) => f.feedId === overlap.feedB)?.feedName || "Unknown";
                        const maxPct = Math.max(overlap.overlapPctA, overlap.overlapPctB);
                        return (
                          <div key={`${overlap.feedA}-${overlap.feedB}`} className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-xs">
                                {feedAName} <span className="text-muted-foreground">↔</span> {feedBName}
                              </span>
                              <span className="text-xs font-medium">{overlap.overlapCount} shared IOCs</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    maxPct > 50 ? "bg-amber-500" : maxPct > 20 ? "bg-cyan-500" : "bg-emerald-500"
                                  }`}
                                  style={{ width: `${Math.min(maxPct, 100)}%` }}
                                />
                              </div>
                              <span className="text-[10px] text-muted-foreground w-16 text-right">
                                {overlap.overlapPctA}% / {overlap.overlapPctB}%
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* ── 6.1: Confidence Scoring Tab ── */}
        <TabsContent value="confidence" className="mt-4">
          {isLoadingConfidence ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
          ) : !confidenceData ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Gauge className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No confidence data available</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Average Confidence</p>
                    <div className="flex items-center gap-3 mt-1">
                      <p className="text-3xl font-bold">{confidenceData.averageConfidence}%</p>
                      <Badge
                        variant="outline"
                        className={
                          confidenceData.averageConfidence >= 80
                            ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                            : confidenceData.averageConfidence >= 50
                              ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                              : "bg-red-500/15 text-red-400 border-red-500/30"
                        }
                      >
                        {confidenceData.averageConfidence >= 80
                          ? "High"
                          : confidenceData.averageConfidence >= 50
                            ? "Medium"
                            : "Low"}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Total IOC Entries</p>
                    <p className="text-3xl font-bold mt-1">{confidenceData.totalEntries.toLocaleString()}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {confidenceData.activeEntries.toLocaleString()} active
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">High Confidence (≥80)</p>
                    <p className="text-3xl font-bold mt-1 text-emerald-400">
                      {confidenceData.distribution.find((d) => d.min === 80)?.count ?? 0}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {confidenceData.totalEntries > 0
                        ? Math.round(
                            ((confidenceData.distribution.find((d) => d.min === 80)?.count ?? 0) /
                              confidenceData.totalEntries) *
                              100,
                          )
                        : 0}
                      % of total
                    </p>
                  </CardContent>
                </Card>
              </div>

              {/* Distribution Chart */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Confidence Distribution</CardTitle>
                  <CardDescription>IOC entries grouped by confidence score buckets</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {confidenceData.distribution.map((bucket) => {
                      const pct =
                        confidenceData.totalEntries > 0 ? (bucket.count / confidenceData.totalEntries) * 100 : 0;
                      const color =
                        bucket.min >= 80
                          ? "bg-emerald-500"
                          : bucket.min >= 60
                            ? "bg-cyan-500"
                            : bucket.min >= 40
                              ? "bg-amber-500"
                              : bucket.min >= 20
                                ? "bg-orange-500"
                                : "bg-red-500";
                      return (
                        <div key={bucket.label} className="flex items-center gap-3">
                          <span className="text-xs text-muted-foreground w-32">{bucket.label}</span>
                          <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
                            <div
                              className={`h-full ${color} rounded-full transition-all`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-xs font-medium w-16 text-right">
                            {bucket.count} ({Math.round(pct)}%)
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              {/* High & Low Confidence Tables */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card className="glass-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-emerald-400" /> High-Confidence IOCs
                    </CardTitle>
                    <CardDescription>Most reliable indicators — prioritize for active blocking</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[300px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Type</TableHead>
                            <TableHead className="text-xs">Value</TableHead>
                            <TableHead className="text-xs text-right">Score</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {confidenceData.highConfidence.map((entry) => {
                            const Icon = IOC_TYPE_ICONS[entry.iocType] || Database;
                            return (
                              <TableRow key={entry.id}>
                                <TableCell className="py-1.5">
                                  <div className="flex items-center gap-1.5">
                                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                                    <span className="text-xs">{entry.iocType}</span>
                                  </div>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <span className="text-xs font-mono truncate max-w-[200px] block">
                                    {entry.iocValue}
                                  </span>
                                </TableCell>
                                <TableCell className="py-1.5 text-right">
                                  <Badge
                                    variant="outline"
                                    className={
                                      (entry.confidence ?? 0) >= 80
                                        ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                        : (entry.confidence ?? 0) >= 50
                                          ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                          : "bg-red-500/15 text-red-400 border-red-500/30"
                                    }
                                  >
                                    {entry.confidence ?? 0}%
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>

                <Card className="glass-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-400" /> Low-Confidence IOCs
                    </CardTitle>
                    <CardDescription>Review these indicators — may need verification or removal</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[300px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Type</TableHead>
                            <TableHead className="text-xs">Value</TableHead>
                            <TableHead className="text-xs text-right">Score</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {confidenceData.lowConfidence.map((entry) => {
                            const Icon = IOC_TYPE_ICONS[entry.iocType] || Database;
                            return (
                              <TableRow key={entry.id}>
                                <TableCell className="py-1.5">
                                  <div className="flex items-center gap-1.5">
                                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                                    <span className="text-xs">{entry.iocType}</span>
                                  </div>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <span className="text-xs font-mono truncate max-w-[200px] block">
                                    {entry.iocValue}
                                  </span>
                                </TableCell>
                                <TableCell className="py-1.5 text-right">
                                  <Badge
                                    variant="outline"
                                    className={
                                      (entry.confidence ?? 0) >= 80
                                        ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                        : (entry.confidence ?? 0) >= 50
                                          ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                          : "bg-red-500/15 text-red-400 border-red-500/30"
                                    }
                                  >
                                    {entry.confidence ?? 0}%
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </TabsContent>

        {/* ── 6.2: Expiration & Aging Tab ── */}
        <TabsContent value="expiration" className="mt-4">
          {isLoadingExpiration ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
          ) : !expirationData ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Timer className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No expiration data available</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <Card className="glass-card border-red-500/20">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Expired</p>
                    <p className="text-2xl font-bold text-red-400 mt-1">{expirationData.summary.totalExpired}</p>
                    <p className="text-xs text-muted-foreground mt-1">should be purged</p>
                  </CardContent>
                </Card>
                <Card className="glass-card border-amber-500/20">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Expiring Soon</p>
                    <p className="text-2xl font-bold text-amber-400 mt-1">{expirationData.summary.totalExpiringSoon}</p>
                    <p className="text-xs text-muted-foreground mt-1">within 7 days</p>
                  </CardContent>
                </Card>
                <Card className="glass-card border-cyan-500/20">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Expiring This Month</p>
                    <p className="text-2xl font-bold text-cyan-400 mt-1">{expirationData.summary.totalExpiringMonth}</p>
                    <p className="text-xs text-muted-foreground mt-1">within 30 days</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">No Expiration</p>
                    <p className="text-2xl font-bold mt-1">{expirationData.summary.totalNoExpiration}</p>
                    <p className="text-xs text-muted-foreground mt-1">consider setting TTL</p>
                  </CardContent>
                </Card>
              </div>

              {/* Aging Distribution */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">IOC Age Distribution</CardTitle>
                  <CardDescription>How old are your active IOC entries?</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {expirationData.agingDistribution.map((bucket, idx) => {
                      const total = expirationData.agingDistribution.reduce((s, b) => s + b.count, 0);
                      const pct = total > 0 ? (bucket.count / total) * 100 : 0;
                      const colors = ["bg-emerald-500", "bg-cyan-500", "bg-amber-500", "bg-orange-500", "bg-red-500"];
                      return (
                        <div key={bucket.label} className="flex items-center gap-3">
                          <span className="text-xs text-muted-foreground w-24">{bucket.label}</span>
                          <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
                            <div
                              className={`h-full ${colors[idx] || "bg-slate-500"} rounded-full transition-all`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-xs font-medium w-16 text-right">
                            {bucket.count} ({Math.round(pct)}%)
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              {/* Expired IOCs List */}
              {expirationData.expired.length > 0 && (
                <Card className="glass-card border-red-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <XCircle className="h-4 w-4 text-red-400" /> Expired IOCs
                    </CardTitle>
                    <CardDescription>
                      These IOCs have passed their expiration date and should be excluded from active matching
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[250px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Type</TableHead>
                            <TableHead className="text-xs">Value</TableHead>
                            <TableHead className="text-xs">Expired</TableHead>
                            <TableHead className="text-xs text-right">Confidence</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {expirationData.expired.slice(0, 30).map((entry) => {
                            const Icon = IOC_TYPE_ICONS[entry.iocType] || Database;
                            return (
                              <TableRow key={entry.id} className="opacity-60">
                                <TableCell className="py-1.5">
                                  <div className="flex items-center gap-1.5">
                                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                                    <span className="text-xs">{entry.iocType}</span>
                                  </div>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <span className="text-xs font-mono truncate max-w-[200px] block line-through text-muted-foreground">
                                    {entry.iocValue}
                                  </span>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <Badge
                                    variant="outline"
                                    className="text-[10px] bg-red-500/15 text-red-400 border-red-500/30"
                                  >
                                    {entry.expiresAt ? new Date(entry.expiresAt).toLocaleDateString() : "N/A"}
                                  </Badge>
                                </TableCell>
                                <TableCell className="py-1.5 text-right">
                                  <span className="text-xs text-muted-foreground">{entry.confidence ?? 0}%</span>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}

              {/* Expiring Soon IOCs */}
              {expirationData.expiringSoon.length > 0 && (
                <Card className="glass-card border-amber-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Hourglass className="h-4 w-4 text-amber-400" /> Expiring Within 7 Days
                    </CardTitle>
                    <CardDescription>These IOCs will expire soon — review or extend their TTL</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[250px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Type</TableHead>
                            <TableHead className="text-xs">Value</TableHead>
                            <TableHead className="text-xs">Expires In</TableHead>
                            <TableHead className="text-xs text-right">Confidence</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {expirationData.expiringSoon.map((entry) => {
                            const Icon = IOC_TYPE_ICONS[entry.iocType] || Database;
                            const daysLeft = entry.expiresAt
                              ? Math.ceil((new Date(entry.expiresAt).getTime() - Date.now()) / (24 * 60 * 60 * 1000))
                              : 0;
                            return (
                              <TableRow key={entry.id}>
                                <TableCell className="py-1.5">
                                  <div className="flex items-center gap-1.5">
                                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                                    <span className="text-xs">{entry.iocType}</span>
                                  </div>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <span className="text-xs font-mono truncate max-w-[200px] block">
                                    {entry.iocValue}
                                  </span>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <Badge
                                    variant="outline"
                                    className="text-[10px] bg-amber-500/15 text-amber-400 border-amber-500/30"
                                  >
                                    {daysLeft} day{daysLeft !== 1 ? "s" : ""}
                                  </Badge>
                                </TableCell>
                                <TableCell className="py-1.5 text-right">
                                  <ConfidenceBar confidence={entry.confidence ?? 0} />
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* ── 6.3: IOC Relationship Graph Tab ── */}
        <TabsContent value="graph" className="mt-4">
          {isLoadingGraph ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
          ) : !graphData || graphData.nodes.length === 0 ? (
            <Card className="glass-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Network className="h-10 w-10 mb-3 opacity-40" />
                <p className="text-sm">No IOC relationships found</p>
                <p className="text-xs mt-1">
                  IOC entries need shared malware families, campaigns, or metadata to build relationships
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Graph Stats */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Nodes (IOCs)</p>
                    <p className="text-2xl font-bold mt-1">{graphData.stats.totalNodes}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Relationships</p>
                    <p className="text-2xl font-bold text-cyan-400 mt-1">{graphData.stats.totalEdges}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Malware Families</p>
                    <p className="text-2xl font-bold text-red-400 mt-1">{graphData.stats.malwareFamilies}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <p className="text-xs text-muted-foreground">Campaigns</p>
                    <p className="text-2xl font-bold text-amber-400 mt-1">{graphData.stats.campaigns}</p>
                  </CardContent>
                </Card>
              </div>

              {/* Relationship List */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">IOC Relationships</CardTitle>
                  <CardDescription>
                    Connections between IOCs based on shared malware families, campaigns, feeds, and metadata
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {graphData.edges.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                      <Network className="h-8 w-8 mb-2 opacity-40" />
                      <p className="text-xs">No relationships detected between IOCs</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[400px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Source IOC</TableHead>
                            <TableHead className="text-xs text-center">Relationship</TableHead>
                            <TableHead className="text-xs">Target IOC</TableHead>
                            <TableHead className="text-xs text-right">Weight</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {graphData.edges.slice(0, 50).map((edge, idx) => {
                            const sourceNode = graphData.nodes.find((n) => n.id === edge.source);
                            const targetNode = graphData.nodes.find((n) => n.id === edge.target);
                            return (
                              <TableRow key={idx}>
                                <TableCell className="py-1.5">
                                  <div className="flex items-center gap-1.5">
                                    {sourceNode && (
                                      <>
                                        {(() => {
                                          const Icon = IOC_TYPE_ICONS[sourceNode.type] || Database;
                                          return <Icon className="h-3.5 w-3.5 text-muted-foreground" />;
                                        })()}
                                        <span className="text-xs font-mono truncate max-w-[150px] block">
                                          {sourceNode.label}
                                        </span>
                                      </>
                                    )}
                                  </div>
                                </TableCell>
                                <TableCell className="py-1.5 text-center">
                                  <Badge
                                    variant="outline"
                                    className={
                                      edge.label.startsWith("malware")
                                        ? "text-[10px] bg-red-500/15 text-red-400 border-red-500/30"
                                        : edge.label.startsWith("campaign")
                                          ? "text-[10px] bg-amber-500/15 text-amber-400 border-amber-500/30"
                                          : edge.label.includes("resolves") || edge.label.includes("communicates")
                                            ? "text-[10px] bg-purple-500/15 text-purple-400 border-purple-500/30"
                                            : "text-[10px] bg-slate-500/15 text-slate-400 border-slate-500/30"
                                    }
                                  >
                                    {edge.label}
                                  </Badge>
                                </TableCell>
                                <TableCell className="py-1.5">
                                  <div className="flex items-center gap-1.5">
                                    {targetNode && (
                                      <>
                                        {(() => {
                                          const Icon = IOC_TYPE_ICONS[targetNode.type] || Database;
                                          return <Icon className="h-3.5 w-3.5 text-muted-foreground" />;
                                        })()}
                                        <span className="text-xs font-mono truncate max-w-[150px] block">
                                          {targetNode.label}
                                        </span>
                                      </>
                                    )}
                                  </div>
                                </TableCell>
                                <TableCell className="py-1.5 text-right">
                                  <div className="flex items-center justify-end gap-1">
                                    {Array.from({ length: Math.min(edge.weight, 5) }).map((_, i) => (
                                      <div
                                        key={i}
                                        className={`w-1.5 h-1.5 rounded-full ${
                                          edge.weight >= 4
                                            ? "bg-red-400"
                                            : edge.weight >= 3
                                              ? "bg-amber-400"
                                              : "bg-slate-400"
                                        }`}
                                      />
                                    ))}
                                  </div>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>

              {/* Nodes by Type */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">IOC Nodes by Type</CardTitle>
                  <CardDescription>Active IOCs in the relationship graph</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                    {["ip", "domain", "url", "hash", "email", "cve"].map((type) => {
                      const count = graphData.nodes.filter((n) => n.type === type).length;
                      const Icon = IOC_TYPE_ICONS[type] || Database;
                      return (
                        <div
                          key={type}
                          className="flex items-center gap-2 p-2 rounded-lg bg-muted/30 border border-border/30"
                        >
                          <Icon className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <p className="text-xs font-medium">{type.toUpperCase()}</p>
                            <p className="text-lg font-bold">{count}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── 6.4: Export Tab ── */}
        <TabsContent value="export" className="mt-4">
          <div className="space-y-6">
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Download className="h-4 w-4" /> Export IOC Entries
                </CardTitle>
                <CardDescription>
                  Download IOC entries in multiple formats for sharing with partners and other security tools
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {/* CSV Export */}
                  <Card className="border-border/40 hover:border-border/60 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 rounded-lg bg-emerald-500/10">
                          <FileText className="h-5 w-5 text-emerald-400" />
                        </div>
                        <div>
                          <p className="text-sm font-semibold">CSV</p>
                          <p className="text-[10px] text-muted-foreground">Comma-separated values</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        Compatible with Excel, Google Sheets, SIEM imports, and custom scripting
                      </p>
                      <Button
                        size="sm"
                        variant="outline"
                        className="w-full gap-1"
                        onClick={() => {
                          window.open("/api/ioc-entries/export/csv", "_blank");
                        }}
                      >
                        <ArrowDownToLine className="h-3.5 w-3.5" /> Download CSV
                      </Button>
                    </CardContent>
                  </Card>

                  {/* STIX Export */}
                  <Card className="border-border/40 hover:border-border/60 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 rounded-lg bg-cyan-500/10">
                          <Shield className="h-5 w-5 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-sm font-semibold">STIX 2.1</p>
                          <p className="text-[10px] text-muted-foreground">Structured Threat Information</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        OASIS standard for sharing cyber threat intelligence with TAXII-compatible platforms
                      </p>
                      <Button
                        size="sm"
                        variant="outline"
                        className="w-full gap-1"
                        onClick={() => {
                          window.open("/api/ioc-entries/export/stix", "_blank");
                        }}
                      >
                        <ArrowDownToLine className="h-3.5 w-3.5" /> Download STIX
                      </Button>
                    </CardContent>
                  </Card>

                  {/* OpenIOC Export */}
                  <Card className="border-border/40 hover:border-border/60 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 rounded-lg bg-amber-500/10">
                          <Target className="h-5 w-5 text-amber-400" />
                        </div>
                        <div>
                          <p className="text-sm font-semibold">OpenIOC</p>
                          <p className="text-[10px] text-muted-foreground">Mandiant format</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        XML-based format used by Mandiant and compatible with FireEye/Trellix endpoint tools
                      </p>
                      <Button
                        size="sm"
                        variant="outline"
                        className="w-full gap-1"
                        onClick={() => {
                          window.open("/api/ioc-entries/export/openioc", "_blank");
                        }}
                      >
                        <ArrowDownToLine className="h-3.5 w-3.5" /> Download OpenIOC
                      </Button>
                    </CardContent>
                  </Card>

                  {/* JSON Export */}
                  <Card className="border-border/40 hover:border-border/60 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="p-2 rounded-lg bg-purple-500/10">
                          <Database className="h-5 w-5 text-purple-400" />
                        </div>
                        <div>
                          <p className="text-sm font-semibold">JSON</p>
                          <p className="text-[10px] text-muted-foreground">Raw data export</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        Full IOC data with all metadata fields for custom integrations and analysis pipelines
                      </p>
                      <Button
                        size="sm"
                        variant="outline"
                        className="w-full gap-1"
                        onClick={() => {
                          window.open("/api/ioc-entries/export/json", "_blank");
                        }}
                      >
                        <ArrowDownToLine className="h-3.5 w-3.5" /> Download JSON
                      </Button>
                    </CardContent>
                  </Card>
                </div>
              </CardContent>
            </Card>

            {/* Export Info */}
            <Card className="glass-card">
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium">Export Details</p>
                    <ul className="text-xs text-muted-foreground mt-1 space-y-1 list-disc list-inside">
                      <li>Exports include up to 5,000 IOC entries per download</li>
                      <li>
                        Use URL query parameters to filter:{" "}
                        <code className="text-[10px] bg-muted px-1 rounded">
                          ?iocType=ip&amp;status=active&amp;minConfidence=70
                        </code>
                      </li>
                      <li>STIX 2.1 bundles include proper indicator patterns and validity dates</li>
                      <li>OpenIOC format is compatible with Mandiant/FireEye/Trellix tools</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── 6.5: Retroactive Matching Tab ── */}
        <TabsContent value="retroactive" className="mt-4">
          {isLoadingRetroMatch ? (
            <LoadingSkeleton />
          ) : (
            <div className="space-y-4">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Matches</p>
                    <p className="text-2xl font-bold mt-1">{retroMatchData?.totalMatches || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Retroactive</p>
                    <p className="text-2xl font-bold mt-1 text-cyan-400">{retroMatchData?.retroactiveMatches || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Real-time</p>
                    <p className="text-2xl font-bold mt-1 text-emerald-400">{retroMatchData?.realtimeMatches || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Active IOCs</p>
                    <p className="text-2xl font-bold mt-1">{retroMatchData?.activeIocs || 0}</p>
                  </CardContent>
                </Card>
              </div>

              {/* Run Retroactive Match */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Scan className="h-4 w-4 text-cyan-400" /> Run Retroactive Scan
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Scan historical alerts for matches against all active IOC entries
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="flex items-center gap-3">
                    <Button
                      size="sm"
                      onClick={() => retroMatchMutation.mutate({ lookbackDays: 7, maxAlerts: 500 })}
                      disabled={retroMatchMutation.isPending}
                    >
                      {retroMatchMutation.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                      ) : (
                        <Scan className="h-3.5 w-3.5 mr-1" />
                      )}
                      Last 7 Days
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => retroMatchMutation.mutate({ lookbackDays: 30, maxAlerts: 1000 })}
                      disabled={retroMatchMutation.isPending}
                    >
                      Last 30 Days
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => retroMatchMutation.mutate({ lookbackDays: 90, maxAlerts: 2000 })}
                      disabled={retroMatchMutation.isPending}
                    >
                      Last 90 Days
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Recent Retroactive Matches */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Recent Retroactive Matches</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[300px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Match Field</TableHead>
                          <TableHead className="text-xs">Value</TableHead>
                          <TableHead className="text-xs">Confidence</TableHead>
                          <TableHead className="text-xs">Matched At</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(retroMatchData?.recentRetroactive || []).length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={4} className="text-center text-xs text-muted-foreground py-8">
                              No retroactive matches yet. Run a scan above.
                            </TableCell>
                          </TableRow>
                        ) : (
                          (retroMatchData?.recentRetroactive || []).map((m) => (
                            <TableRow key={m.id}>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="text-[10px]">
                                  {m.matchField}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs font-mono truncate max-w-[200px]">{m.matchValue}</TableCell>
                              <TableCell className="text-xs">
                                <Badge
                                  className={`text-[10px] ${(m.confidence || 0) >= 80 ? "bg-emerald-500/20 text-emerald-400" : (m.confidence || 0) >= 50 ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"}`}
                                >
                                  {m.confidence || 0}%
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {m.createdAt ? new Date(m.createdAt).toLocaleDateString() : "—"}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── 6.6: Auto-Enrichment Tab ── */}
        <TabsContent value="autoenrich" className="mt-4">
          {isLoadingEnrichmentStatus ? (
            <LoadingSkeleton />
          ) : (
            <div className="space-y-4">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Enrichment Rate</p>
                    <p className="text-2xl font-bold mt-1 text-emerald-400">
                      {enrichmentStatusData?.enrichmentRate || 0}%
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Enriched</p>
                    <p className="text-2xl font-bold mt-1 text-cyan-400">{enrichmentStatusData?.enrichedCount || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Not Enriched</p>
                    <p className="text-2xl font-bold mt-1 text-amber-400">
                      {enrichmentStatusData?.notEnrichedCount || 0}
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Active</p>
                    <p className="text-2xl font-bold mt-1">{enrichmentStatusData?.totalActive || 0}</p>
                  </CardContent>
                </Card>
              </div>

              {/* Enrichment by Type */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-amber-400" /> Enrichment Coverage by IOC Type
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="space-y-3">
                    {(enrichmentStatusData?.byType || []).map((t) => (
                      <div key={t.type} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-medium uppercase">{t.type}</span>
                          <span className="text-muted-foreground">
                            {t.enriched}/{t.total} ({t.rate}%)
                          </span>
                        </div>
                        <Progress value={t.rate} className="h-2" />
                      </div>
                    ))}
                    {(enrichmentStatusData?.byType || []).length === 0 && (
                      <p className="text-xs text-muted-foreground text-center py-4">No IOC entries to display</p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Enrich All Button */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-cyan-400" /> Auto-Enrich IOCs
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Enrich un-enriched IOCs with VirusTotal, WHOIS, passive DNS, and geo-IP data
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="flex items-center gap-3">
                    <Button
                      size="sm"
                      onClick={() => {
                        const unenriched = (enrichmentStatusData?.recentlyEnriched || [])
                          .filter((e) => {
                            const meta = e.metadata as Record<string, any> | null;
                            return !meta?.enrichment;
                          })
                          .slice(0, 20)
                          .map((e) => e.id);
                        if (unenriched.length > 0) {
                          autoEnrichMutation.mutate({ iocEntryIds: unenriched });
                        } else {
                          // Enrich the first 20 entries
                          const allIds = (Array.isArray(entries) ? entries : []).slice(0, 20).map((e: any) => e.id);
                          if (allIds.length > 0) autoEnrichMutation.mutate({ iocEntryIds: allIds });
                        }
                      }}
                      disabled={autoEnrichMutation.isPending}
                    >
                      {autoEnrichMutation.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                      ) : (
                        <Sparkles className="h-3.5 w-3.5 mr-1" />
                      )}
                      Enrich Up to 20 IOCs
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Recently Enriched */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Recently Enriched IOCs</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[250px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Type</TableHead>
                          <TableHead className="text-xs">Value</TableHead>
                          <TableHead className="text-xs">Confidence</TableHead>
                          <TableHead className="text-xs">Sources</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(enrichmentStatusData?.recentlyEnriched || []).length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={4} className="text-center text-xs text-muted-foreground py-8">
                              No enriched IOCs yet
                            </TableCell>
                          </TableRow>
                        ) : (
                          (enrichmentStatusData?.recentlyEnriched || []).slice(0, 15).map((e) => (
                            <TableRow key={e.id}>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="text-[10px]">
                                  {e.iocType?.toUpperCase()}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs font-mono truncate max-w-[200px]">{e.iocValue}</TableCell>
                              <TableCell className="text-xs">
                                <Badge
                                  className={`text-[10px] ${(e.confidence || 0) >= 80 ? "bg-emerald-500/20 text-emerald-400" : (e.confidence || 0) >= 50 ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"}`}
                                >
                                  {e.confidence || 0}%
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {(() => {
                                  const meta = e.metadata as Record<string, any> | null;
                                  const enrichment = meta?.enrichment;
                                  if (!enrichment) return "—";
                                  const sources = [];
                                  if (enrichment.virusTotal) sources.push("VT");
                                  if (enrichment.whois) sources.push("WHOIS");
                                  if (enrichment.passiveDns) sources.push("DNS");
                                  if (enrichment.geoIp) sources.push("GeoIP");
                                  return sources.join(", ") || "—";
                                })()}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── 6.7: False Positive Tracking Tab ── */}
        <TabsContent value="fptracking" className="mt-4">
          {isLoadingFpTracking ? (
            <LoadingSkeleton />
          ) : (
            <div className="space-y-4">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Overall FP Rate</p>
                    <p
                      className={`text-2xl font-bold mt-1 ${(fpTrackingData?.overallFpRate || 0) > 50 ? "text-red-400" : (fpTrackingData?.overallFpRate || 0) > 20 ? "text-amber-400" : "text-emerald-400"}`}
                    >
                      {fpTrackingData?.overallFpRate || 0}%
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">False Positives</p>
                    <p className="text-2xl font-bold mt-1 text-red-400">{fpTrackingData?.totalFalsePositives || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">True Positives</p>
                    <p className="text-2xl font-bold mt-1 text-emerald-400">
                      {fpTrackingData?.totalTruePositives || 0}
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Auto-Suppressed</p>
                    <p className="text-2xl font-bold mt-1 text-amber-400">{fpTrackingData?.suppressedCount || 0}</p>
                  </CardContent>
                </Card>
              </div>

              {/* High FP IOCs */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ThumbsDown className="h-4 w-4 text-red-400" /> High False Positive IOCs
                  </CardTitle>
                  <CardDescription className="text-xs">
                    IOCs with FP rate &gt; 50% and at least 3 reports. Auto-suppressed at &gt;80% with 5+ reports.
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[250px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Type</TableHead>
                          <TableHead className="text-xs">Value</TableHead>
                          <TableHead className="text-xs">FP Rate</TableHead>
                          <TableHead className="text-xs">FP / TP</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(fpTrackingData?.highFpIocs || []).length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={4} className="text-center text-xs text-muted-foreground py-8">
                              No high-FP IOCs detected
                            </TableCell>
                          </TableRow>
                        ) : (
                          (fpTrackingData?.highFpIocs || []).map((ioc) => (
                            <TableRow key={ioc.id}>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="text-[10px]">
                                  {ioc.iocType.toUpperCase()}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs font-mono truncate max-w-[200px]">{ioc.iocValue}</TableCell>
                              <TableCell className="text-xs">
                                <Badge
                                  className={`text-[10px] ${ioc.fpRate > 80 ? "bg-red-500/20 text-red-400" : "bg-amber-500/20 text-amber-400"}`}
                                >
                                  {ioc.fpRate}%
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {ioc.fpCount} / {ioc.tpCount}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>

              {/* Feed FP Rates */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Rss className="h-4 w-4 text-amber-400" /> False Positive Rates by Feed
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="space-y-3">
                    {(fpTrackingData?.feedFpRates || []).map((f) => (
                      <div key={f.feed} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-medium truncate max-w-[200px]">{f.feed}</span>
                          <span
                            className={`${f.fpRate > 50 ? "text-red-400" : f.fpRate > 20 ? "text-amber-400" : "text-emerald-400"}`}
                          >
                            {f.fpRate}% FP ({f.fpCount} FP / {f.tpCount} TP)
                          </span>
                        </div>
                        <div className="h-2 rounded-full bg-muted overflow-hidden">
                          <div
                            className={`h-full rounded-full ${f.fpRate > 50 ? "bg-red-500" : f.fpRate > 20 ? "bg-amber-500" : "bg-emerald-500"}`}
                            style={{ width: `${Math.min(100, f.fpRate)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                    {(fpTrackingData?.feedFpRates || []).length === 0 && (
                      <p className="text-xs text-muted-foreground text-center py-4">No FP tracking data available</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── 6.8: Auto-Rules Tab ── */}
        <TabsContent value="autorules" className="mt-4">
          {isLoadingGeneratedRules ? (
            <LoadingSkeleton />
          ) : (
            <div className="space-y-4">
              {/* Summary */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Generated Rules</p>
                    <p className="text-2xl font-bold mt-1">{generatedRulesData?.totalRules || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Avg Quality</p>
                    <p className="text-2xl font-bold mt-1 text-emerald-400">
                      {generatedRulesData?.rules && generatedRulesData.rules.length > 0
                        ? Math.round(
                            generatedRulesData.rules.reduce((sum, r) => sum + (r.qualityScore || 0), 0) /
                              generatedRulesData.rules.length,
                          )
                        : 0}
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Format</p>
                    <p className="text-2xl font-bold mt-1 text-cyan-400">
                      {generatedRulesData?.rules?.[0]?.format?.toUpperCase() || "SIGMA"}
                    </p>
                  </CardContent>
                </Card>
              </div>

              {/* Generate Rules Action */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Wand2 className="h-4 w-4 text-cyan-400" /> Generate Detection Rules from IOCs
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Auto-generate Sigma/YARA detection rules from high-confidence IOC entries
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="flex items-center gap-3">
                    <Button
                      size="sm"
                      onClick={() => generateRulesMutation.mutate({ ruleFormat: "sigma", minConfidence: 70 })}
                      disabled={generateRulesMutation.isPending}
                    >
                      {generateRulesMutation.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                      ) : (
                        <Wand2 className="h-3.5 w-3.5 mr-1" />
                      )}
                      Generate Sigma Rules
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => generateRulesMutation.mutate({ ruleFormat: "yara", minConfidence: 70 })}
                      disabled={generateRulesMutation.isPending}
                    >
                      Generate YARA Rules
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Generated Rules List */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">IOC-Generated Detection Rules</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[300px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Rule Name</TableHead>
                          <TableHead className="text-xs">Format</TableHead>
                          <TableHead className="text-xs">Severity</TableHead>
                          <TableHead className="text-xs">Quality</TableHead>
                          <TableHead className="text-xs">Status</TableHead>
                          <TableHead className="text-xs">Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(generatedRulesData?.rules || []).length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={6} className="text-center text-xs text-muted-foreground py-8">
                              No auto-generated rules yet. Click above to generate.
                            </TableCell>
                          </TableRow>
                        ) : (
                          (generatedRulesData?.rules || []).map((r) => (
                            <TableRow key={r.jobId}>
                              <TableCell className="text-xs font-medium truncate max-w-[200px]">{r.name}</TableCell>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="text-[10px]">
                                  {r.format?.toUpperCase()}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs">
                                <Badge
                                  className={`text-[10px] ${r.severity === "critical" ? "bg-red-500/20 text-red-400" : r.severity === "high" ? "bg-orange-500/20 text-orange-400" : r.severity === "medium" ? "bg-amber-500/20 text-amber-400" : "bg-emerald-500/20 text-emerald-400"}`}
                                >
                                  {r.severity}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs">
                                <Badge
                                  className={`text-[10px] ${(r.qualityScore || 0) >= 80 ? "bg-emerald-500/20 text-emerald-400" : (r.qualityScore || 0) >= 50 ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"}`}
                                >
                                  {r.qualityScore || 0}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="text-[10px]">
                                  {r.status}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {r.createdAt ? new Date(r.createdAt).toLocaleDateString() : "—"}
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── 6.9: Community Sharing Tab ── */}
        <TabsContent value="communityshare" className="mt-4">
          {isLoadingCommunitySharing ? (
            <LoadingSkeleton />
          ) : (
            <div className="space-y-4">
              {/* Consent Status */}
              <Card
                className={`glass-card border-l-4 ${communitySharingData?.consentActive ? "border-l-emerald-500" : "border-l-amber-500"}`}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Users className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <p className="text-sm font-medium">Community Intel Sharing</p>
                        <p className="text-xs text-muted-foreground">
                          {communitySharingData?.consentActive
                            ? `Active — consent level: ${communitySharingData.consentLevel}`
                            : "Not active — enable sharing consent in Community Intel settings"}
                        </p>
                      </div>
                    </div>
                    <Badge
                      className={`text-[10px] ${communitySharingData?.consentActive ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/20 text-amber-400"}`}
                    >
                      {communitySharingData?.consentActive ? "ACTIVE" : "INACTIVE"}
                    </Badge>
                  </div>
                </CardContent>
              </Card>

              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Sharing Rate</p>
                    <p className="text-2xl font-bold mt-1 text-cyan-400">{communitySharingData?.sharingRate || 0}%</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Shared IOCs</p>
                    <p className="text-2xl font-bold mt-1 text-emerald-400">{communitySharingData?.sharedCount || 0}</p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Not Shared</p>
                    <p className="text-2xl font-bold mt-1 text-amber-400">
                      {communitySharingData?.notSharedCount || 0}
                    </p>
                  </CardContent>
                </Card>
                <Card className="glass-card">
                  <CardContent className="p-4 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Contributions</p>
                    <p className="text-2xl font-bold mt-1">{communitySharingData?.contributedIocCount || 0}</p>
                  </CardContent>
                </Card>
              </div>

              {/* Share Action */}
              {communitySharingData?.consentActive && (
                <Card className="glass-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Share2 className="h-4 w-4 text-cyan-400" /> Share IOCs to Community Network
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Anonymously share high-confidence IOCs with industry peers
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="p-4 pt-0">
                    <div className="flex items-center gap-3">
                      <Button
                        size="sm"
                        onClick={() => {
                          const activeIds = (Array.isArray(entries) ? entries : [])
                            .filter((e: any) => e.status === "active" && (e.confidence || 0) >= 70)
                            .slice(0, 50)
                            .map((e: any) => e.id);
                          if (activeIds.length > 0) {
                            shareCommMutation.mutate({ iocEntryIds: activeIds, tlpLevel: "amber" });
                          }
                        }}
                        disabled={shareCommMutation.isPending}
                      >
                        {shareCommMutation.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                        ) : (
                          <Share2 className="h-3.5 w-3.5 mr-1" />
                        )}
                        Share High-Confidence IOCs (TLP:AMBER)
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          const activeIds = (Array.isArray(entries) ? entries : [])
                            .filter((e: any) => e.status === "active" && (e.confidence || 0) >= 70)
                            .slice(0, 50)
                            .map((e: any) => e.id);
                          if (activeIds.length > 0) {
                            shareCommMutation.mutate({ iocEntryIds: activeIds, tlpLevel: "green" });
                          }
                        }}
                        disabled={shareCommMutation.isPending}
                      >
                        Share (TLP:GREEN)
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Shared by Type */}
              <Card className="glass-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Network className="h-4 w-4 text-emerald-400" /> Shared IOCs by Type
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {(communitySharingData?.sharedByType || []).map((t) => (
                      <div key={t.type} className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                        <span className="text-xs font-medium uppercase">{t.type}</span>
                        <Badge variant="outline" className="text-[10px]">
                          {t.count}
                        </Badge>
                      </div>
                    ))}
                    {(communitySharingData?.sharedByType || []).length === 0 && (
                      <div className="col-span-full text-center py-4">
                        <p className="text-xs text-muted-foreground">No IOCs shared yet</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Last Contribution */}
              {communitySharingData?.lastContributedAt && (
                <Card className="glass-card">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Clock className="h-3.5 w-3.5" />
                      Last contribution: {new Date(communitySharingData.lastContributedAt).toLocaleString()}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* 4.2: Feed Ingestion Stats Dialog */}
      <Dialog
        open={showStatsDialog}
        onOpenChange={(open) => {
          setShowStatsDialog(open);
          if (!open) setStatsFeedId(null);
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Activity className="h-4 w-4" /> Feed Ingestion Statistics
            </DialogTitle>
            <DialogDescription>{feedStatsData ? feedStatsData.feedName : "Loading..."}</DialogDescription>
          </DialogHeader>
          {isLoadingFeedStats ? (
            <div className="space-y-3 py-4">
              <Skeleton className="h-16" />
              <Skeleton className="h-16" />
            </div>
          ) : feedStatsData ? (
            <div className="space-y-4 py-2">
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-3 rounded-lg bg-muted/50">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total IOCs</p>
                  <p className="text-xl font-bold mt-1">{feedStatsData.total.toLocaleString()}</p>
                </div>
                <div className="text-center p-3 rounded-lg bg-muted/50">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Last 24h</p>
                  <p className="text-xl font-bold mt-1 text-cyan-400">{feedStatsData.last24h.toLocaleString()}</p>
                </div>
                <div className="text-center p-3 rounded-lg bg-muted/50">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Last 7d</p>
                  <p className="text-xl font-bold mt-1 text-emerald-400">{feedStatsData.last7d.toLocaleString()}</p>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Last Fetch Status</span>
                  <FeedStatusBadge status={feedStatsData.lastFetchStatus} />
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Last Fetch Count</span>
                  <span className="font-medium">{feedStatsData.lastFetchCount} entries</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Last Sync</span>
                  <span className="font-medium">
                    {feedStatsData.lastFetchAt ? new Date(feedStatsData.lastFetchAt).toLocaleString() : "Never"}
                  </span>
                </div>
              </div>
              {feedStatsData.total > 0 && (
                <div>
                  <p className="text-[10px] text-muted-foreground mb-1">Ingestion Velocity</p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-500 rounded-full"
                        style={{
                          width: `${Math.min((feedStatsData.last7d / Math.max(feedStatsData.total, 1)) * 100, 100)}%`,
                        }}
                      />
                    </div>
                    <span className="text-[10px] text-muted-foreground">
                      {feedStatsData.total > 0 ? Math.round((feedStatsData.last7d / feedStatsData.total) * 100) : 0}% in
                      last 7d
                    </span>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground py-4 text-center">No data available</p>
          )}
        </DialogContent>
      </Dialog>

      {/* 4.3: Feed Preview Dialog */}
      <Dialog
        open={showPreviewDialog}
        onOpenChange={(open) => {
          setShowPreviewDialog(open);
          if (!open) {
            setPreviewFeedId(null);
            previewMutation.reset();
          }
        }}
      >
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="h-4 w-4" /> Feed Preview — Sample IOCs
            </DialogTitle>
            <DialogDescription>
              Preview of the first 10 IOCs this feed would ingest. Use this to evaluate feed quality before enabling.
            </DialogDescription>
          </DialogHeader>
          {previewMutation.isPending ? (
            <div className="flex flex-col items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-cyan-400 mb-2" />
              <p className="text-xs text-muted-foreground">Fetching preview from feed source...</p>
            </div>
          ) : previewMutation.isError ? (
            <div className="flex flex-col items-center justify-center py-8 text-red-400">
              <AlertTriangle className="h-6 w-6 mb-2" />
              <p className="text-xs">Failed to fetch preview: {previewMutation.error?.message}</p>
            </div>
          ) : previewMutation.data ? (
            <div className="space-y-4 py-2">
              {!previewMutation.data.success ? (
                <div className="flex flex-col items-center justify-center py-6 text-amber-400">
                  <AlertTriangle className="h-6 w-6 mb-2" />
                  <p className="text-sm font-medium">Preview Failed</p>
                  <p className="text-xs text-muted-foreground mt-1">{previewMutation.data.error}</p>
                </div>
              ) : previewMutation.data.sampleIocs.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
                  <Database className="h-6 w-6 mb-2 opacity-40" />
                  <p className="text-sm">No IOCs found in feed</p>
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    {previewMutation.data.feedName && (
                      <span>
                        Feed: <strong className="text-foreground">{previewMutation.data.feedName}</strong>
                      </span>
                    )}
                    {previewMutation.data.feedType && (
                      <Badge variant="outline" className="text-[10px]">
                        {previewMutation.data.feedType.toUpperCase()}
                      </Badge>
                    )}
                    <span>{previewMutation.data.totalParsed} IOCs parsed</span>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">Type</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead className="w-24">Confidence</TableHead>
                        <TableHead className="w-20">Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {previewMutation.data.sampleIocs.map((ioc, idx) => {
                        const TypeIcon = IOC_TYPE_ICONS[ioc.iocType] || Database;
                        return (
                          <TableRow key={idx}>
                            <TableCell>
                              <div className="flex items-center gap-1">
                                <TypeIcon className="h-3.5 w-3.5 text-muted-foreground" />
                                <span className="text-xs">{ioc.iocType}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className="text-xs font-mono break-all">{ioc.iocValue}</span>
                            </TableCell>
                            <TableCell>
                              <ConfidenceBar confidence={ioc.confidence} />
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant="outline"
                                className={`text-[10px] ${
                                  ioc.severity === "critical"
                                    ? "bg-red-500/15 text-red-400 border-red-500/30"
                                    : ioc.severity === "high"
                                      ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
                                      : ioc.severity === "medium"
                                        ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                        : "bg-slate-500/15 text-slate-400 border-slate-500/30"
                                }`}
                              >
                                {ioc.severity}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </>
              )}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      <Dialog open={showUploadDialog} onOpenChange={setShowUploadDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Manual IOC Upload</DialogTitle>
            <DialogDescription>
              Paste IOC data for ingestion. Select a CSV feed to process it through.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label htmlFor="upload-feed">Target Feed</Label>
              <Select value={selectedFeedId || ""} onValueChange={setSelectedFeedId}>
                <SelectTrigger id="upload-feed" className="mt-1">
                  <SelectValue placeholder="Select a feed..." />
                </SelectTrigger>
                <SelectContent>
                  {allFeeds.length > 0 ? (
                    allFeeds.map((f) => (
                      <SelectItem key={f.id} value={f.id}>
                        {f.name} ({f.feedType.toUpperCase()})
                      </SelectItem>
                    ))
                  ) : (
                    <div className="px-3 py-2 text-xs text-muted-foreground">
                      No feeds configured. Create a feed in the Feed Sources tab first.
                    </div>
                  )}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="upload-data">IOC Data</Label>
              <Textarea
                id="upload-data"
                placeholder={"type,value,confidence\nip,192.168.1.1,80\ndomain,evil.com,90\nhash,abc123def456,75"}
                value={uploadData}
                onChange={(e) => setUploadData(e.target.value)}
                className="mt-1 font-mono text-xs"
                rows={8}
              />
              <p className="text-[10px] text-muted-foreground mt-1">
                For CSV feeds: use type,value,confidence format. For JSON feeds: paste a valid JSON object.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowUploadDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!selectedFeedId) {
                  toast({
                    title: "Validation Error",
                    description: "Please select a target feed",
                    variant: "destructive",
                  });
                  return;
                }
                if (!uploadData.trim()) {
                  toast({
                    title: "Validation Error",
                    description: "Please provide IOC data to upload",
                    variant: "destructive",
                  });
                  return;
                }
                manualUploadMutation.mutate({ feedId: selectedFeedId, rawData: uploadData.trim() });
              }}
              disabled={manualUploadMutation.isPending}
            >
              {manualUploadMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Upload className="h-4 w-4 mr-1" />
              )}
              Upload &amp; Ingest
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={showRuleDialog}
        onOpenChange={(open) => {
          if (!open) {
            setShowRuleDialog(false);
            setEditingRule(null);
            setRuleForm(EMPTY_RULE_FORM);
          } else {
            setShowRuleDialog(true);
          }
        }}
      >
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingRule ? "Edit Match Rule" : "Create Match Rule"}</DialogTitle>
            <DialogDescription>
              {editingRule
                ? "Update the match rule configuration."
                : "Define a rule to automatically match IOCs against alerts and incidents."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label htmlFor="rule-name">Rule Name</Label>
              <Input
                id="rule-name"
                placeholder="e.g. Block Known C2 IPs"
                value={ruleForm.name}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, name: e.target.value }))}
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="rule-desc">Description</Label>
              <Textarea
                id="rule-desc"
                placeholder="What this rule does..."
                value={ruleForm.description}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, description: e.target.value }))}
                className="mt-1"
                rows={2}
              />
            </div>
            <div>
              <Label htmlFor="rule-feed">Target Feed</Label>
              <Select value={ruleForm.feedId} onValueChange={(v) => setRuleForm((prev) => ({ ...prev, feedId: v }))}>
                <SelectTrigger id="rule-feed" className="mt-1">
                  <SelectValue placeholder="All feeds (no filter)" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Feeds</SelectItem>
                  {allFeeds.map((f) => (
                    <SelectItem key={f.id} value={f.id}>
                      {f.name} ({f.feedType.toUpperCase()})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[10px] text-muted-foreground mt-1">
                Restrict this rule to IOCs from a specific feed, or leave as "All Feeds" to match across all sources.
              </p>
            </div>
            <div>
              <Label>IOC Types</Label>
              <div className="flex flex-wrap gap-2 mt-1">
                {IOC_TYPE_OPTIONS.map((t) => {
                  const selected = ruleForm.iocTypes.includes(t);
                  return (
                    <Button
                      key={t}
                      type="button"
                      variant={selected ? "default" : "outline"}
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => {
                        setRuleForm((prev) => ({
                          ...prev,
                          iocTypes: selected ? prev.iocTypes.filter((x) => x !== t) : [...prev.iocTypes, t],
                        }));
                      }}
                    >
                      {t}
                    </Button>
                  );
                })}
              </div>
              <p className="text-[10px] text-muted-foreground mt-1">
                Select which IOC types this rule should match. Leave empty to match all types.
              </p>
            </div>
            <div>
              <Label>Match Fields</Label>
              <div className="flex flex-wrap gap-2 mt-1">
                {MATCH_FIELD_OPTIONS.map((f) => {
                  const selected = ruleForm.matchFields.includes(f);
                  return (
                    <Button
                      key={f}
                      type="button"
                      variant={selected ? "default" : "outline"}
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => {
                        setRuleForm((prev) => ({
                          ...prev,
                          matchFields: selected ? prev.matchFields.filter((x) => x !== f) : [...prev.matchFields, f],
                        }));
                      }}
                    >
                      {f}
                    </Button>
                  );
                })}
              </div>
              <p className="text-[10px] text-muted-foreground mt-1">Alert fields to check for IOC matches.</p>
            </div>
            <div>
              <Label htmlFor="rule-confidence">Minimum Confidence ({ruleForm.minConfidence}%)</Label>
              <input
                id="rule-confidence"
                type="range"
                min={0}
                max={100}
                step={5}
                value={ruleForm.minConfidence}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, minConfidence: parseInt(e.target.value, 10) }))}
                className="w-full mt-1 accent-cyan-500"
              />
              <div className="flex justify-between text-[10px] text-muted-foreground">
                <span>0%</span>
                <span>50%</span>
                <span>100%</span>
              </div>
            </div>
            <div>
              <Label htmlFor="rule-action">Action on Match</Label>
              <Select value={ruleForm.action} onValueChange={(v) => setRuleForm((prev) => ({ ...prev, action: v }))}>
                <SelectTrigger id="rule-action" className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTION_OPTIONS.map((a) => (
                    <SelectItem key={a.value} value={a.value}>
                      {a.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={ruleForm.autoEnrich}
                  onChange={(e) => setRuleForm((prev) => ({ ...prev, autoEnrich: e.target.checked }))}
                  className="rounded accent-cyan-500"
                />
                Auto-enrich matches
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={ruleForm.enabled}
                  onChange={(e) => setRuleForm((prev) => ({ ...prev, enabled: e.target.checked }))}
                  className="rounded accent-cyan-500"
                />
                Enabled
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowRuleDialog(false);
                setEditingRule(null);
                setRuleForm(EMPTY_RULE_FORM);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!ruleForm.name.trim()) {
                  toast({ title: "Validation Error", description: "Rule name is required", variant: "destructive" });
                  return;
                }
                const payload: Record<string, unknown> = {
                  name: ruleForm.name.trim(),
                  description: ruleForm.description.trim() || null,
                  feedId: ruleForm.feedId && ruleForm.feedId !== "all" ? ruleForm.feedId : null,
                  iocTypes: ruleForm.iocTypes,
                  matchFields: ruleForm.matchFields,
                  minConfidence: ruleForm.minConfidence,
                  enabled: ruleForm.enabled,
                  autoEnrich: ruleForm.autoEnrich,
                  action: ruleForm.action,
                };
                if (editingRule) {
                  updateRuleMutation.mutate({ id: editingRule.id, data: payload });
                } else {
                  createRuleMutation.mutate(payload);
                }
              }}
              disabled={createRuleMutation.isPending || updateRuleMutation.isPending}
            >
              {createRuleMutation.isPending || updateRuleMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Settings2 className="h-4 w-4 mr-1" />
              )}
              {editingRule ? "Update Rule" : "Create Rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 4.8: Feed Authentication Config Dialog */}
      <Dialog open={showAuthDialog} onOpenChange={setShowAuthDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" /> Feed Authentication
            </DialogTitle>
            <DialogDescription>Configure how this feed authenticates with its source.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label className="text-xs">Auth Type</Label>
              <Select
                value={authForm.authType}
                onValueChange={(val) => setAuthForm((prev) => ({ ...prev, authType: val }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  <SelectItem value="api_key">API Key (Custom Header)</SelectItem>
                  <SelectItem value="bearer">Bearer Token</SelectItem>
                  <SelectItem value="basic">Basic Auth</SelectItem>
                  <SelectItem value="mtls">mTLS Certificate</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {authForm.authType === "api_key" && (
              <>
                <div>
                  <Label className="text-xs">Header Name</Label>
                  <Input
                    value={authForm.apiKeyHeader}
                    onChange={(e) => setAuthForm((prev) => ({ ...prev, apiKeyHeader: e.target.value }))}
                    placeholder="X-API-Key"
                  />
                </div>
                <div>
                  <Label className="text-xs">API Key Value</Label>
                  <Input
                    type="password"
                    value={authForm.apiKeyValue}
                    onChange={(e) => setAuthForm((prev) => ({ ...prev, apiKeyValue: e.target.value }))}
                    placeholder="Enter API key"
                  />
                </div>
              </>
            )}

            {authForm.authType === "bearer" && (
              <div>
                <Label className="text-xs">Bearer Token</Label>
                <Input
                  type="password"
                  value={authForm.bearerToken}
                  onChange={(e) => setAuthForm((prev) => ({ ...prev, bearerToken: e.target.value }))}
                  placeholder="Enter bearer token"
                />
              </div>
            )}

            {authForm.authType === "basic" && (
              <>
                <div>
                  <Label className="text-xs">Username</Label>
                  <Input
                    value={authForm.basicUsername}
                    onChange={(e) => setAuthForm((prev) => ({ ...prev, basicUsername: e.target.value }))}
                    placeholder="Username"
                  />
                </div>
                <div>
                  <Label className="text-xs">Password</Label>
                  <Input
                    type="password"
                    value={authForm.basicPassword}
                    onChange={(e) => setAuthForm((prev) => ({ ...prev, basicPassword: e.target.value }))}
                    placeholder="Password"
                  />
                </div>
              </>
            )}

            {authForm.authType === "mtls" && (
              <div className="text-xs text-muted-foreground p-3 bg-muted/50 rounded-md">
                <Shield className="h-4 w-4 inline mr-1" />
                mTLS certificate upload requires admin CLI access. Use the API endpoint directly:
                <code className="block mt-1 text-[10px] font-mono break-all">
                  PATCH /api/ioc-feeds/:id/auth with clientCertPem and clientKeyPem
                </code>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAuthDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!authFeedId) return;
                authMutation.mutate({
                  feedId: authFeedId,
                  authConfig: {
                    authType: authForm.authType,
                    ...(authForm.authType === "api_key"
                      ? { apiKeyHeader: authForm.apiKeyHeader, apiKeyValue: authForm.apiKeyValue }
                      : {}),
                    ...(authForm.authType === "bearer" ? { bearerToken: authForm.bearerToken } : {}),
                    ...(authForm.authType === "basic"
                      ? { basicUsername: authForm.basicUsername, basicPassword: authForm.basicPassword }
                      : {}),
                  },
                });
              }}
              disabled={authMutation.isPending}
            >
              {authMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Key className="h-4 w-4 mr-1" />
              )}
              Save Auth Config
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
