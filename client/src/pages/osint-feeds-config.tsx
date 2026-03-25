import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Rss,
  RefreshCw,
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  AlertTriangle,
  Search,
  Zap,
  Timer,
  BarChart3,
  ChevronRight,
} from "lucide-react";
import { SuccessIcon } from "@/components/ui/animated-state-icons";

interface FeedStatus {
  name: string;
  slug: string;
  url: string;
  description: string;
  category: string;
  indicatorTypes: string[];
  lastFetched: string | null;
  lastSuccess: string | null;
  lastError: string | null;
  lastErrorMessage: string | null;
  totalIndicators: number;
  status: "success" | "error" | "never_fetched";
  enabled: boolean;
  refreshIntervalMinutes: number;
  successRate: number;
  avgResponseTimeMs: number;
  totalFetches: number;
  consecutiveErrors: number;
  requiresApiKey: false;
}

interface FeedSubscription {
  slug: string;
  enabled: boolean;
  refreshIntervalMinutes: number;
}

interface HealthEntry {
  timestamp: string;
  status: "success" | "error";
  indicatorCount: number;
  responseTimeMs: number;
  errorMessage?: string;
}

interface BulkRefreshResult {
  total: number;
  completed: number;
  results: Array<{
    slug: string;
    status: string;
    indicatorCount: number;
    errorMessage?: string;
  }>;
}

const REFRESH_INTERVALS = [
  { value: "5", label: "5 min" },
  { value: "15", label: "15 min" },
  { value: "30", label: "30 min" },
  { value: "60", label: "1 hour" },
  { value: "120", label: "2 hours" },
  { value: "240", label: "4 hours" },
  { value: "1440", label: "24 hours" },
];

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return minutes + "m ago";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + "h ago";
  const days = Math.floor(hours / 24);
  return days + "d ago";
}

function StatusDot({ status }: { status: string }) {
  const color = status === "success" ? "bg-emerald-500" : status === "error" ? "bg-red-500" : "bg-zinc-400";
  return (
    <span className="relative flex h-2.5 w-2.5">
      {status === "success" && (
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
      )}
      <span className={"relative inline-flex rounded-full h-2.5 w-2.5 " + color} />
    </span>
  );
}

function HealthTimeline({ entries }: { entries: HealthEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center py-4 text-xs text-muted-foreground">
        No health data yet. Refresh the feed to start tracking.
      </div>
    );
  }
  return (
    <div className="space-y-1.5 max-h-48 overflow-y-auto">
      {entries.slice(0, 15).map((entry, idx) => (
        <div
          key={entry.timestamp + "-" + idx}
          className="flex items-center gap-2 text-xs px-2 py-1 rounded-md glass-subtle"
        >
          {entry.status === "success" ? (
            <SuccessIcon size={12} color="#22c55e" />
          ) : (
            <XCircle className="h-3 w-3 text-red-500 shrink-0" />
          )}
          <span className="text-muted-foreground">{timeAgo(entry.timestamp)}</span>
          <span className="text-muted-foreground">|</span>
          <span>{entry.indicatorCount} IOCs</span>
          <span className="text-muted-foreground">|</span>
          <span>{entry.responseTimeMs}ms</span>
          {entry.errorMessage && (
            <span className="text-red-400 truncate ml-auto max-w-[200px]" title={entry.errorMessage}>
              {entry.errorMessage}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function FeedCard({
  feed,
  onToggle,
  onRefresh,
  onIntervalChange,
  isRefreshing,
  isToggling,
}: {
  feed: FeedStatus;
  onToggle: (slug: string, enabled: boolean) => void;
  onRefresh: (slug: string) => void;
  onIntervalChange: (slug: string, minutes: number) => void;
  isRefreshing: boolean;
  isToggling: boolean;
}) {
  const [showHealth, setShowHealth] = useState(false);
  const healthQueryKey = "/api/osint-feeds/" + feed.slug + "/health";
  const { data: healthData, isLoading: healthLoading } = useQuery<HealthEntry[]>({
    queryKey: [healthQueryKey],
    queryFn: async () => {
      const res = await apiRequest("GET", healthQueryKey);
      return res.json();
    },
    enabled: showHealth,
  });

  return (
    <Card className="glass-card border-border/50 hover:border-cyan-500/30 transition-all duration-200">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <StatusDot status={feed.status} />
            <div className="min-w-0">
              <CardTitle className="text-sm font-semibold truncate">{feed.name}</CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{feed.description}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Tooltip>
              <TooltipTrigger asChild>
                <div>
                  <Switch
                    checked={feed.enabled}
                    onCheckedChange={(checked) => onToggle(feed.slug, checked)}
                    disabled={isToggling}
                    aria-label={"Toggle " + feed.name}
                  />
                </div>
              </TooltipTrigger>
              <TooltipContent>{feed.enabled ? "Disable feed" : "Enable feed"}</TooltipContent>
            </Tooltip>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 mt-2">
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4">
            {feed.category}
          </Badge>
          {feed.indicatorTypes.map((t) => (
            <Badge key={t} variant="secondary" className="text-[10px] px-1.5 py-0 h-4 uppercase">
              {t}
            </Badge>
          ))}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-2">
          <div className="flex items-center gap-1.5 text-xs">
            <Clock className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Last sync:</span>
            <span className="font-medium">{timeAgo(feed.lastFetched)}</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <Activity className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">IOCs:</span>
            <span className="font-medium">{feed.totalIndicators.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <BarChart3 className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Success:</span>
            <span
              className={
                "font-medium " +
                (feed.successRate >= 80
                  ? "text-emerald-500"
                  : feed.successRate >= 50
                    ? "text-yellow-500"
                    : "text-red-500")
              }
            >
              {feed.totalFetches > 0 ? feed.successRate + "%" : "N/A"}
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <Timer className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">Avg:</span>
            <span className="font-medium">{feed.totalFetches > 0 ? feed.avgResponseTimeMs + "ms" : "N/A"}</span>
          </div>
        </div>

        {feed.consecutiveErrors > 0 && (
          <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-md bg-red-500/10 border border-red-500/20">
            <AlertTriangle className="h-3 w-3 text-red-500 shrink-0" />
            <span className="text-xs text-red-400">
              {feed.consecutiveErrors} consecutive error
              {feed.consecutiveErrors > 1 ? "s" : ""}
              {feed.lastErrorMessage ? ": " + feed.lastErrorMessage : ""}
            </span>
          </div>
        )}

        <div className="flex items-center gap-2">
          <Select
            value={String(feed.refreshIntervalMinutes)}
            onValueChange={(val) => onIntervalChange(feed.slug, parseInt(val, 10))}
          >
            <SelectTrigger className="h-7 text-xs flex-1">
              <SelectValue placeholder="Interval" />
            </SelectTrigger>
            <SelectContent>
              {REFRESH_INTERVALS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value} className="text-xs">
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs hover:bg-cyan-500/10 hover:border-cyan-500/30 active:scale-95 transition-all"
            onClick={() => onRefresh(feed.slug)}
            disabled={isRefreshing || !feed.enabled}
          >
            {isRefreshing ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <RefreshCw className="h-3 w-3 mr-1" />}
            Refresh
          </Button>
        </div>

        <button
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors w-full"
          onClick={() => setShowHealth(!showHealth)}
          type="button"
        >
          <ChevronRight className={"h-3 w-3 transition-transform " + (showHealth ? "rotate-90" : "")} />
          Health History ({feed.totalFetches} fetches)
        </button>

        {showHealth && (
          <div className="border-t border-border/50 pt-2">
            {healthLoading ? (
              <div className="space-y-1">
                <Skeleton className="h-6 w-full" />
                <Skeleton className="h-6 w-full" />
                <Skeleton className="h-6 w-3/4" />
              </div>
            ) : (
              <HealthTimeline entries={healthData || []} />
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FeedCardSkeleton() {
  return (
    <Card className="glass-card border-border/50">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="space-y-2 flex-1">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-3 w-64" />
          </div>
          <Skeleton className="h-5 w-9 rounded-full" />
        </div>
        <div className="flex gap-1.5 mt-2">
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-4 w-10" />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-4 w-20" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-7 flex-1" />
          <Skeleton className="h-7 w-20" />
        </div>
      </CardContent>
    </Card>
  );
}

export default function OsintFeedsConfigPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshingSlug, setRefreshingSlug] = useState<string | null>(null);
  const [togglingSlug, setTogglingSlug] = useState<string | null>(null);

  useEffect(() => {
    document.title = "OSINT Feeds Configuration | SecureNexus";
  }, []);

  const { data, isLoading, error } = useQuery<{
    subscriptions: FeedSubscription[];
    statuses: FeedStatus[];
  }>({
    queryKey: ["/api/osint-feeds/subscriptions"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/osint-feeds/subscriptions");
      return res.json();
    },
    refetchInterval: 30000,
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ slug, enabled }: { slug: string; enabled: boolean }) => {
      setTogglingSlug(slug);
      const endpoint = enabled
        ? "/api/osint-feeds/" + slug + "/subscribe"
        : "/api/osint-feeds/" + slug + "/unsubscribe";
      await apiRequest("POST", endpoint);
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ["/api/osint-feeds/subscriptions"],
      });
      toast({
        title: variables.enabled ? "Feed Enabled" : "Feed Disabled",
        description: "Subscription updated successfully.",
      });
      setTogglingSlug(null);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update subscription.",
        variant: "destructive",
      });
      setTogglingSlug(null);
    },
  });

  const refreshMutation = useMutation({
    mutationFn: async (slug: string) => {
      setRefreshingSlug(slug);
      const res = await apiRequest("POST", "/api/osint-feeds/" + slug + "/refresh");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["/api/osint-feeds/subscriptions"],
      });
      toast({
        title: "Feed Refreshed",
        description: "Feed data updated successfully.",
      });
      setRefreshingSlug(null);
    },
    onError: () => {
      toast({
        title: "Refresh Failed",
        description: "Could not refresh feed.",
        variant: "destructive",
      });
      setRefreshingSlug(null);
    },
  });

  const refreshAllMutation = useMutation<BulkRefreshResult>({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/osint-feeds/refresh-all");
      return res.json();
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({
        queryKey: ["/api/osint-feeds/subscriptions"],
      });
      const failed = result.results.filter((r) => r.status === "error").length;
      toast({
        title: "Bulk Refresh Complete",
        description:
          result.completed + "/" + result.total + " feeds refreshed" + (failed > 0 ? " (" + failed + " failed)" : ""),
        variant: failed > 0 ? "destructive" : "default",
      });
    },
    onError: () => {
      toast({
        title: "Bulk Refresh Failed",
        description: "Could not refresh feeds.",
        variant: "destructive",
      });
    },
  });

  const intervalMutation = useMutation({
    mutationFn: async ({ slug, minutes }: { slug: string; minutes: number }) => {
      await apiRequest("PATCH", "/api/osint-feeds/" + slug + "/config", {
        refreshIntervalMinutes: minutes,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["/api/osint-feeds/subscriptions"],
      });
      toast({
        title: "Interval Updated",
        description: "Refresh interval changed.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update interval.",
        variant: "destructive",
      });
    },
  });

  const feeds = data?.statuses || [];
  const filteredFeeds = feeds.filter(
    (f) =>
      f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const enabledCount = feeds.filter((f) => f.enabled).length;
  const totalIndicators = feeds.reduce((sum, f) => sum + f.totalIndicators, 0);
  const feedsWithFetches = feeds.filter((f) => f.totalFetches > 0);
  const avgSuccessRate =
    feedsWithFetches.length > 0
      ? Math.round(feedsWithFetches.reduce((sum, f) => sum + f.successRate, 0) / feedsWithFetches.length)
      : 0;

  if (error) {
    return (
      <div className="p-6">
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <XCircle className="h-10 w-10 text-red-500 mb-3" />
          <h2 className="text-lg font-semibold">Failed to load feed configuration</h2>
          <p className="text-sm text-muted-foreground mt-1">Please try refreshing the page.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Rss className="h-5 w-5 text-cyan-500" />
            <h1 className="text-xl font-bold">OSINT Feeds Configuration</h1>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Manage threat intelligence feed subscriptions, health monitoring, and refresh schedules.
          </p>
        </div>
        <Button
          variant="outline"
          className="shrink-0 hover:bg-cyan-500/10 hover:border-cyan-500/30 active:scale-95 transition-all"
          onClick={() => refreshAllMutation.mutate()}
          disabled={refreshAllMutation.isPending}
        >
          {refreshAllMutation.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Zap className="h-4 w-4 mr-2" />
          )}
          Refresh All Feeds
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2">
              <Rss className="h-4 w-4 text-cyan-500" />
              <span className="text-xs text-muted-foreground">Active Feeds</span>
            </div>
            <p className="text-2xl font-bold mt-1">
              {isLoading ? <Skeleton className="h-8 w-12 inline-block" /> : enabledCount + "/" + feeds.length}
            </p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-500" />
              <span className="text-xs text-muted-foreground">Total Indicators</span>
            </div>
            <p className="text-2xl font-bold mt-1">
              {isLoading ? <Skeleton className="h-8 w-16 inline-block" /> : totalIndicators.toLocaleString()}
            </p>
          </CardContent>
        </Card>
        <Card className="glass-card">
          <CardContent className="pt-4 pb-3 px-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-cyan-500" />
              <span className="text-xs text-muted-foreground">Avg Success Rate</span>
            </div>
            <p className="text-2xl font-bold mt-1">
              {isLoading ? (
                <Skeleton className="h-8 w-12 inline-block" />
              ) : avgSuccessRate > 0 ? (
                avgSuccessRate + "%"
              ) : (
                "N/A"
              )}
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search feeds by name, category, or description..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-9 h-9"
        />
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <FeedCardSkeleton />
          <FeedCardSkeleton />
          <FeedCardSkeleton />
          <FeedCardSkeleton />
        </div>
      ) : filteredFeeds.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Search className="h-10 w-10 text-muted-foreground mb-3" />
          <h2 className="text-lg font-semibold">No feeds found</h2>
          <p className="text-sm text-muted-foreground mt-1">
            {searchQuery
              ? 'No feeds match "' + searchQuery + '". Try a different search.'
              : "No OSINT feeds configured."}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredFeeds.map((feed) => (
            <FeedCard
              key={feed.slug}
              feed={feed}
              onToggle={(slug, enabled) => toggleMutation.mutate({ slug, enabled })}
              onRefresh={(slug) => refreshMutation.mutate(slug)}
              onIntervalChange={(slug, minutes) => intervalMutation.mutate({ slug, minutes })}
              isRefreshing={refreshingSlug === feed.slug}
              isToggling={togglingSlug === feed.slug}
            />
          ))}
        </div>
      )}
    </div>
  );
}
