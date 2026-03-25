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
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";
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
        <SuccessIcon size={12} color="#22c55e" /> Success
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
                        <p className="text-sm font-medium">{feed.schedule || "Manual"}</p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <FeedStatusBadge status={feed.lastFetchStatus} />
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
                          <div
                            className={`w-2 h-2 rounded-full ${
                              feed.lastFetchStatus === "success"
                                ? "bg-emerald-500"
                                : feed.lastFetchStatus
                                  ? "bg-red-500"
                                  : "bg-slate-500"
                            }`}
                          />
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
      </Tabs>

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
    </div>
  );
}
