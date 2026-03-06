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
  ExternalLink,
  Newspaper,
  Filter,
  BarChart3,
  Timer,
  ChevronRight,
  Globe,
  Tag,
} from "lucide-react";

interface ThreatIntelArticle {
  id: string;
  source: string;
  feedUrl: string;
  feedTitle: string | null;
  title: string;
  link: string;
  canonicalLink: string;
  guid: string | null;
  publishedAt: string | null;
  updatedAt: string | null;
  authors: string[];
  categories: string[];
  summaryText: string;
  contentText: string;
  fetchedAt: string;
}

interface FeedStatus {
  name: string;
  slug: string;
  url: string;
  category: string;
  type: "rss" | "blog";
  enabled: boolean;
  lastFetched: string | null;
  lastSuccess: string | null;
  lastError: string | null;
  lastErrorMessage: string | null;
  articleCount: number;
  status: "success" | "error" | "never_fetched";
  successRate: number;
  avgResponseTimeMs: number;
  totalFetches: number;
  consecutiveErrors: number;
}

interface FeedCategory {
  name: string;
  feedCount: number;
}

interface HealthEntry {
  timestamp: string;
  status: "success" | "error";
  articleCount: number;
  responseTimeMs: number;
  errorMessage?: string;
}

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

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function formatTime(dateStr: string | null): string {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
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

function ArticleCard({ article }: { article: ThreatIntelArticle }) {
  return (
    <div className="group flex flex-col gap-2 p-4 rounded-lg glass-subtle border border-border/30 hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all duration-200">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <a
            href={article.link}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-semibold leading-tight hover:text-cyan-400 transition-colors line-clamp-2"
          >
            {article.title}
            <ExternalLink className="inline-block h-3 w-3 ml-1 opacity-0 group-hover:opacity-100 transition-opacity" />
          </a>
          <div className="flex items-center gap-2 mt-1.5 text-xs text-muted-foreground">
            <Globe className="h-3 w-3 shrink-0" />
            <span className="truncate">{article.source}</span>
            {article.publishedAt && (
              <>
                <span className="text-border">|</span>
                <Clock className="h-3 w-3 shrink-0" />
                <span>{formatDate(article.publishedAt)}</span>
                <span className="hidden sm:inline">{formatTime(article.publishedAt)}</span>
              </>
            )}
            {article.authors.length > 0 && (
              <>
                <span className="text-border hidden sm:inline">|</span>
                <span className="hidden sm:inline truncate max-w-[150px]">{article.authors.join(", ")}</span>
              </>
            )}
          </div>
        </div>
      </div>
      {article.summaryText && (
        <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">{article.summaryText}</p>
      )}
      {article.categories.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {article.categories.slice(0, 5).map((cat) => (
            <Badge key={cat} variant="outline" className="text-[9px] px-1.5 py-0 h-4">
              {cat}
            </Badge>
          ))}
          {article.categories.length > 5 && (
            <Badge variant="outline" className="text-[9px] px-1.5 py-0 h-4">
              +{article.categories.length - 5}
            </Badge>
          )}
        </div>
      )}
    </div>
  );
}

function ArticleSkeleton() {
  return (
    <div className="p-4 rounded-lg glass-subtle border border-border/30">
      <Skeleton className="h-4 w-3/4 mb-2" />
      <Skeleton className="h-3 w-1/3 mb-2" />
      <Skeleton className="h-3 w-full mb-1" />
      <Skeleton className="h-3 w-2/3" />
    </div>
  );
}

function FeedStatusCard({
  feed,
  onToggle,
  onRefresh,
  isRefreshing,
}: {
  feed: FeedStatus;
  onToggle: (slug: string, enabled: boolean) => void;
  onRefresh: (slug: string) => void;
  isRefreshing: boolean;
}) {
  const [showHealth, setShowHealth] = useState(false);
  const { data: healthData, isLoading: healthLoading } = useQuery<HealthEntry[]>({
    queryKey: ["/api/threat-intel-feeds/" + feed.slug + "/health"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/threat-intel-feeds/" + feed.slug + "/health");
      return res.json();
    },
    enabled: showHealth,
  });

  return (
    <div className="flex flex-col gap-2 p-3 rounded-lg glass-subtle border border-border/30 hover:border-cyan-500/20 transition-all">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <StatusDot status={feed.status} />
          <span className="text-xs font-medium truncate">{feed.name}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                variant="ghost"
                className="h-6 w-6 p-0 hover:bg-cyan-500/10"
                onClick={() => onRefresh(feed.slug)}
                disabled={isRefreshing || !feed.enabled}
                aria-label={"Refresh " + feed.name}
              >
                {isRefreshing ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>Refresh feed</TooltipContent>
          </Tooltip>
          <Switch
            checked={feed.enabled}
            onCheckedChange={(checked) => onToggle(feed.slug, checked)}
            className="scale-75"
            aria-label={"Toggle " + feed.name}
          />
        </div>
      </div>
      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
        <Badge variant="outline" className="text-[9px] px-1 py-0 h-3.5">
          {feed.category}
        </Badge>
        <span>{feed.articleCount} articles</span>
        <span>{timeAgo(feed.lastFetched)}</span>
        {feed.totalFetches > 0 && (
          <span
            className={
              feed.successRate >= 80 ? "text-emerald-500" : feed.successRate >= 50 ? "text-yellow-500" : "text-red-500"
            }
          >
            {feed.successRate}%
          </span>
        )}
      </div>
      {feed.consecutiveErrors > 0 && (
        <div className="flex items-center gap-1 text-[10px] text-red-400">
          <AlertTriangle className="h-2.5 w-2.5" />
          <span className="truncate">
            {feed.consecutiveErrors} error{feed.consecutiveErrors > 1 ? "s" : ""}
            {feed.lastErrorMessage ? ": " + feed.lastErrorMessage.slice(0, 60) : ""}
          </span>
        </div>
      )}
      <button
        className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
        onClick={() => setShowHealth(!showHealth)}
        type="button"
      >
        <ChevronRight className={"h-2.5 w-2.5 transition-transform " + (showHealth ? "rotate-90" : "")} />
        Health ({feed.totalFetches} fetches)
      </button>
      {showHealth && (
        <div className="border-t border-border/30 pt-1.5">
          {healthLoading ? (
            <Skeleton className="h-12 w-full" />
          ) : !healthData || healthData.length === 0 ? (
            <div className="text-[10px] text-muted-foreground text-center py-2">No health data yet</div>
          ) : (
            <div className="space-y-0.5 max-h-32 overflow-y-auto">
              {healthData.slice(0, 10).map((entry, idx) => (
                <div key={entry.timestamp + "-" + idx} className="flex items-center gap-1.5 text-[10px]">
                  {entry.status === "success" ? (
                    <CheckCircle2 className="h-2.5 w-2.5 text-emerald-500 shrink-0" />
                  ) : (
                    <XCircle className="h-2.5 w-2.5 text-red-500 shrink-0" />
                  )}
                  <span className="text-muted-foreground">{timeAgo(entry.timestamp)}</span>
                  <span>{entry.articleCount} items</span>
                  <span className="text-muted-foreground">{entry.responseTimeMs}ms</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ThreatIntelFeedsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [refreshingSlug, setRefreshingSlug] = useState<string | null>(null);
  const [view, setView] = useState<"articles" | "feeds">("articles");
  const [articleLimit, setArticleLimit] = useState(100);

  useEffect(() => {
    document.title = "Threat Intel Feeds | SecureNexus";
  }, []);

  const { data: categories } = useQuery<FeedCategory[]>({
    queryKey: ["/api/threat-intel-feeds/categories"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/threat-intel-feeds/categories");
      return res.json();
    },
  });

  const { data: feedStatuses, isLoading: statusesLoading } = useQuery<FeedStatus[]>({
    queryKey: ["/api/threat-intel-feeds/statuses"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/threat-intel-feeds/statuses");
      return res.json();
    },
    refetchInterval: 30000,
  });

  const articleQueryParams = new URLSearchParams();
  articleQueryParams.set("limit", String(articleLimit));
  if (selectedCategory !== "all") articleQueryParams.set("category", selectedCategory);
  if (searchQuery.trim()) articleQueryParams.set("search", searchQuery.trim());

  const { data: articlesData, isLoading: articlesLoading } = useQuery<{
    articles: ThreatIntelArticle[];
    total: number;
  }>({
    queryKey: ["/api/threat-intel-feeds/articles", articleQueryParams.toString()],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/threat-intel-feeds/articles?" + articleQueryParams.toString());
      return res.json();
    },
    refetchInterval: 60000,
  });

  const refreshAllMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/threat-intel-feeds/refresh-all");
      return res.json();
    },
    onSuccess: (result: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-feeds/statuses"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-feeds/articles"] });
      toast({
        title: "Feeds Refreshed",
        description: result.meta
          ? result.meta.okFeedCount + "/" + result.feedCount + " feeds fetched (" + result.itemCount + " articles)"
          : "All feeds refreshed",
      });
    },
    onError: () => {
      toast({ title: "Refresh Failed", description: "Could not refresh feeds.", variant: "destructive" });
    },
  });

  const refreshFeedMutation = useMutation({
    mutationFn: async (slug: string) => {
      setRefreshingSlug(slug);
      const res = await apiRequest("POST", "/api/threat-intel-feeds/" + slug + "/refresh");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-feeds/statuses"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-feeds/articles"] });
      toast({ title: "Feed Refreshed", description: "Feed data updated." });
      setRefreshingSlug(null);
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to refresh feed.", variant: "destructive" });
      setRefreshingSlug(null);
    },
  });

  const toggleFeedMutation = useMutation({
    mutationFn: async ({ slug, enabled }: { slug: string; enabled: boolean }) => {
      const endpoint = "/api/threat-intel-feeds/" + slug + (enabled ? "/enable" : "/disable");
      await apiRequest("POST", endpoint);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-feeds/statuses"] });
      toast({ title: "Feed Updated" });
    },
    onError: () => {
      toast({ title: "Error", description: "Failed to toggle feed.", variant: "destructive" });
    },
  });

  const feeds = feedStatuses || [];
  const articles = articlesData?.articles || [];
  const enabledCount = feeds.filter((f) => f.enabled).length;
  const totalArticles = feeds.reduce((sum, f) => sum + f.articleCount, 0);
  const activeFeedsWithData = feeds.filter((f) => f.totalFetches > 0);
  const avgSuccessRate =
    activeFeedsWithData.length > 0
      ? Math.round(activeFeedsWithData.reduce((sum, f) => sum + f.successRate, 0) / activeFeedsWithData.length)
      : 0;
  const errorFeeds = feeds.filter((f) => f.consecutiveErrors > 0).length;

  const filteredFeeds = feeds.filter((f) => {
    const matchesSearch =
      !searchQuery ||
      f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = selectedCategory === "all" || f.category.toLowerCase() === selectedCategory.toLowerCase();
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Newspaper className="h-6 w-6 text-cyan-500" />
            Threat Intel Feeds
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time aggregation from {feeds.length} cybersecurity RSS feeds across {categories?.length || 0}{" "}
            categories
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            className={"h-8 text-xs " + (view === "articles" ? "bg-cyan-500/10 border-cyan-500/30" : "")}
            onClick={() => setView("articles")}
          >
            <Newspaper className="h-3.5 w-3.5 mr-1" />
            Articles
          </Button>
          <Button
            size="sm"
            variant="outline"
            className={"h-8 text-xs " + (view === "feeds" ? "bg-cyan-500/10 border-cyan-500/30" : "")}
            onClick={() => setView("feeds")}
          >
            <Rss className="h-3.5 w-3.5 mr-1" />
            Feed Sources
          </Button>
          <Button
            size="sm"
            className="h-8 text-xs hover:bg-cyan-500/10 hover:border-cyan-500/30 active:scale-95 transition-all"
            variant="outline"
            onClick={() => refreshAllMutation.mutate()}
            disabled={refreshAllMutation.isPending}
          >
            {refreshAllMutation.isPending ? (
              <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5 mr-1" />
            )}
            Refresh All
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="glass-card border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-md bg-cyan-500/10">
                <Rss className="h-4 w-4 text-cyan-500" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Active Feeds</p>
                <p className="text-lg font-bold">
                  {enabledCount}
                  <span className="text-xs text-muted-foreground font-normal">/{feeds.length}</span>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-md bg-emerald-500/10">
                <Newspaper className="h-4 w-4 text-emerald-500" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Cached Articles</p>
                <p className="text-lg font-bold">{totalArticles.toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-md bg-blue-500/10">
                <BarChart3 className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Avg Success</p>
                <p
                  className={
                    "text-lg font-bold " +
                    (avgSuccessRate >= 80
                      ? "text-emerald-500"
                      : avgSuccessRate >= 50
                        ? "text-yellow-500"
                        : "text-red-500")
                  }
                >
                  {activeFeedsWithData.length > 0 ? avgSuccessRate + "%" : "N/A"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="glass-card border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-md bg-red-500/10">
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Error Feeds</p>
                <p className={"text-lg font-bold " + (errorFeeds > 0 ? "text-red-500" : "text-emerald-500")}>
                  {errorFeeds}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder={view === "articles" ? "Search articles..." : "Search feeds..."}
            className="h-8 pl-8 text-xs"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && articles.length === 0 && !articlesLoading && view === "articles" && (
            <div className="absolute top-full mt-1 left-0 right-0 bg-background border border-border rounded-md p-2 text-xs text-muted-foreground shadow-lg z-10">
              No results found for "{searchQuery}"
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <Select value={selectedCategory} onValueChange={setSelectedCategory}>
            <SelectTrigger className="h-8 text-xs w-[160px]">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="text-xs">
                All Categories
              </SelectItem>
              {(categories || []).map((cat) => (
                <SelectItem key={cat.name} value={cat.name.toLowerCase()} className="text-xs">
                  {cat.name} ({cat.feedCount})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {view === "articles" && (
            <Select value={String(articleLimit)} onValueChange={(v) => setArticleLimit(parseInt(v, 10))}>
              <SelectTrigger className="h-8 text-xs w-[100px]">
                <SelectValue placeholder="Limit" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="50" className="text-xs">
                  50
                </SelectItem>
                <SelectItem value="100" className="text-xs">
                  100
                </SelectItem>
                <SelectItem value="250" className="text-xs">
                  250
                </SelectItem>
                <SelectItem value="500" className="text-xs">
                  500
                </SelectItem>
                <SelectItem value="1000" className="text-xs">
                  1000
                </SelectItem>
              </SelectContent>
            </Select>
          )}
        </div>
      </div>

      {view === "articles" ? (
        <div className="space-y-2">
          {articlesLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 8 }).map((_, i) => (
                <ArticleSkeleton key={i} />
              ))}
            </div>
          ) : articles.length === 0 ? (
            <Card className="glass-card border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Newspaper className="h-12 w-12 text-muted-foreground/30 mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No articles available</p>
                <p className="text-xs text-muted-foreground/70 mt-1">
                  Click "Refresh All" to fetch articles from enabled feeds
                </p>
                <Button
                  size="sm"
                  variant="outline"
                  className="mt-4 h-8 text-xs"
                  onClick={() => refreshAllMutation.mutate()}
                  disabled={refreshAllMutation.isPending}
                >
                  {refreshAllMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                  ) : (
                    <RefreshCw className="h-3.5 w-3.5 mr-1" />
                  )}
                  Fetch Articles
                </Button>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="text-xs text-muted-foreground">
                Showing {articles.length} article{articles.length !== 1 ? "s" : ""}
                {selectedCategory !== "all" ? " in " + selectedCategory : ""}
                {searchQuery ? ' matching "' + searchQuery + '"' : ""}
              </div>
              {articles.map((article) => (
                <ArticleCard key={article.id} article={article} />
              ))}
              {articles.length >= articleLimit && (
                <div className="text-center py-4">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-8 text-xs"
                    onClick={() => setArticleLimit((prev) => prev + 100)}
                  >
                    Load More
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {statusesLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {Array.from({ length: 12 }).map((_, i) => (
                <Card key={i} className="glass-card border-border/50">
                  <CardContent className="p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <Skeleton className="h-2.5 w-2.5 rounded-full" />
                      <Skeleton className="h-3.5 w-32" />
                    </div>
                    <div className="flex gap-2">
                      <Skeleton className="h-3 w-16" />
                      <Skeleton className="h-3 w-20" />
                      <Skeleton className="h-3 w-12" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : filteredFeeds.length === 0 ? (
            <Card className="glass-card border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Rss className="h-12 w-12 text-muted-foreground/30 mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No feeds match your filter</p>
                <p className="text-xs text-muted-foreground/70 mt-1">Try adjusting your search or category filter</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="text-xs text-muted-foreground">
                {filteredFeeds.length} feed{filteredFeeds.length !== 1 ? "s" : ""}
                {selectedCategory !== "all" ? " in " + selectedCategory : ""}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {filteredFeeds.map((feed) => (
                  <FeedStatusCard
                    key={feed.slug}
                    feed={feed}
                    onToggle={(slug, enabled) => toggleFeedMutation.mutate({ slug, enabled })}
                    onRefresh={(slug) => refreshFeedMutation.mutate(slug)}
                    isRefreshing={refreshingSlug === feed.slug}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
