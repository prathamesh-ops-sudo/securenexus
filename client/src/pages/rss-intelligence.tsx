import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Rss,
  Brain,
  TrendingUp,
  BarChart3,
  Activity,
  Zap,
  RefreshCw,
  Database,
  Shield,
  AlertTriangle,
  Search,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Clock,
  Star,
  Filter,
  Download,
  Play,
  BookOpen,
  Eye,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Progress } from "@/components/ui/progress";

// ── API helpers ─────────────────────────────────────────────────────

async function apiFetch(url: string, options?: RequestInit) {
  const csrfRes = await fetch("/api/csrf-token", { credentials: "include" });
  const csrfData = await csrfRes.json();
  const token = csrfData?.data?.token || csrfData?.token || "";
  const res = await fetch(url, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": token,
      ...(options?.headers || {}),
    },
    ...options,
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  const json = await res.json();
  return json.data ?? json;
}

// ── Severity colors ─────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

const TIER_LABELS: Record<string, string> = {
  tier1: "Premium",
  tier2: "Research",
  tier3: "Infrastructure",
  tier4: "Blogs",
  tier5: "General",
};

const TIER_COLORS: Record<string, string> = {
  tier1: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  tier2: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  tier3: "bg-violet-500/15 text-violet-400 border-violet-500/30",
  tier4: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  tier5: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

// ── Stat Card ───────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  subtitle,
  trend,
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  subtitle?: string;
  trend?: string;
}) {
  return (
    <Card className="border-border/50">
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold tabular-nums">
              {typeof value === "number" ? value.toLocaleString() : value}
            </p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
            {trend && <p className="text-xs text-emerald-400">{trend}</p>}
          </div>
          <div className="rounded-md bg-muted/50 p-2">
            <Icon className="h-4 w-4 text-muted-foreground" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Page ───────────────────────────────────────────────────────

export default function RSSIntelligencePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState("overview");
  const [articleFilter, setArticleFilter] = useState({ severity: "", tier: "", search: "" });
  const [feedFilter, setFeedFilter] = useState({ tier: "", sortBy: "quality" });

  // ── Queries ─────────────────────────────────────────────────────────

  const { data: dashboard, isLoading: dashLoading } = useQuery({
    queryKey: ["/api/rss-intelligence/dashboard"],
    queryFn: () => apiFetch("/api/rss-intelligence/dashboard"),
    refetchInterval: 60_000,
  });

  const { data: registry } = useQuery({
    queryKey: ["/api/rss-intelligence/registry"],
    queryFn: () => apiFetch("/api/rss-intelligence/registry"),
  });

  const { data: articles, isLoading: articlesLoading } = useQuery({
    queryKey: ["/api/rss-intelligence/articles", articleFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (articleFilter.severity) params.set("severity", articleFilter.severity);
      if (articleFilter.tier) params.set("feedTier", articleFilter.tier);
      params.set("limit", "50");
      return apiFetch(`/api/rss-intelligence/articles?${params}`);
    },
    enabled: activeTab === "articles",
  });

  const { data: feeds, isLoading: feedsLoading } = useQuery({
    queryKey: ["/api/rss-intelligence/feeds", feedFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (feedFilter.tier) params.set("tier", feedFilter.tier);
      params.set("sortBy", feedFilter.sortBy);
      params.set("limit", "100");
      return apiFetch(`/api/rss-intelligence/feeds?${params}`);
    },
    enabled: activeTab === "feeds",
  });

  const { data: trends } = useQuery({
    queryKey: ["/api/rss-intelligence/trends"],
    queryFn: () => apiFetch("/api/rss-intelligence/trends?days=7"),
    enabled: activeTab === "trends",
  });

  const { data: learning } = useQuery({
    queryKey: ["/api/rss-intelligence/learning"],
    queryFn: () => apiFetch("/api/rss-intelligence/learning?days=30"),
    enabled: activeTab === "learning",
  });

  // ── Mutations ─────────────────────────────────────────────────────

  const pollMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch("/api/rss-intelligence/poll", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (data) => {
      toast({ title: "Poll Complete", description: `${data?.summary?.newArticles || 0} new articles ingested` });
      queryClient.invalidateQueries({ queryKey: ["/api/rss-intelligence"] });
    },
    onError: () => toast({ title: "Poll Failed", variant: "destructive" }),
  });

  const indexMutation = useMutation({
    mutationFn: () =>
      apiFetch("/api/rss-intelligence/index-rag", { method: "POST", body: JSON.stringify({ limit: 100 }) }),
    onSuccess: (data) => {
      toast({ title: "RAG Indexing Complete", description: `${data?.indexed || 0} articles indexed` });
      queryClient.invalidateQueries({ queryKey: ["/api/rss-intelligence"] });
    },
    onError: () => toast({ title: "Indexing Failed", variant: "destructive" }),
  });

  const dailyLearnMutation = useMutation({
    mutationFn: () => apiFetch("/api/rss-intelligence/daily-learn", { method: "POST", body: JSON.stringify({}) }),
    onSuccess: () => {
      toast({ title: "Daily Learning Complete", description: "All feeds polled, indexed, and quality updated" });
      queryClient.invalidateQueries({ queryKey: ["/api/rss-intelligence"] });
    },
    onError: () => toast({ title: "Learning Cycle Failed", variant: "destructive" }),
  });

  // ── Overview Tab ────────────────────────────────────────────────────

  const reg = dashboard?.registry;
  const lrn = dashboard?.learning;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-6 w-6 text-cyan-400" />
            RSS Intelligence Engine
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {reg?.total?.toLocaleString() || "3,640"} feeds &middot; Self-learning threat intelligence from the codex
            repository
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => pollMutation.mutate({ tier: "tier1" })}
            disabled={pollMutation.isPending}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${pollMutation.isPending ? "animate-spin" : ""}`} />
            Poll Tier 1
          </Button>
          <Button variant="outline" size="sm" onClick={() => indexMutation.mutate()} disabled={indexMutation.isPending}>
            <Database className={`h-4 w-4 mr-1 ${indexMutation.isPending ? "animate-spin" : ""}`} />
            Index RAG
          </Button>
          <Button size="sm" onClick={() => dailyLearnMutation.mutate()} disabled={dailyLearnMutation.isPending}>
            <Zap className={`h-4 w-4 mr-1 ${dailyLearnMutation.isPending ? "animate-spin" : ""}`} />
            Daily Learn
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">
            <BarChart3 className="h-4 w-4 mr-1" /> Overview
          </TabsTrigger>
          <TabsTrigger value="articles">
            <BookOpen className="h-4 w-4 mr-1" /> Articles
          </TabsTrigger>
          <TabsTrigger value="feeds">
            <Rss className="h-4 w-4 mr-1" /> Feed Manager
          </TabsTrigger>
          <TabsTrigger value="trends">
            <TrendingUp className="h-4 w-4 mr-1" /> Trends
          </TabsTrigger>
          <TabsTrigger value="learning">
            <Brain className="h-4 w-4 mr-1" /> Learning
          </TabsTrigger>
        </TabsList>

        {/* ── Overview Tab ───────────────────────────────────────────── */}
        <TabsContent value="overview" className="space-y-6 mt-4">
          {/* Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <StatCard
              label="Total Feeds"
              value={reg?.total || 0}
              icon={Rss}
              subtitle={`${Object.keys(reg?.byTier || {}).length} tiers`}
            />
            <StatCard label="Tier 1 (Premium)" value={reg?.byTier?.tier1 || 0} icon={Star} subtitle="30 min polling" />
            <StatCard
              label="Tier 2 (Research)"
              value={reg?.byTier?.tier2 || 0}
              icon={Search}
              subtitle="1 hour polling"
            />
            <StatCard label="Articles Today" value={lrn?.totalKnowledge?.totalArticles || 0} icon={BookOpen} />
            <StatCard label="IOCs Extracted" value={lrn?.totalKnowledge?.totalIocs || 0} icon={Shield} />
            <StatCard label="RAG Indexed" value={lrn?.totalKnowledge?.ragIndexed || 0} icon={Brain} />
          </div>

          {/* Tier Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Feed Tier Distribution</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {Object.entries(reg?.byTier || {}).map(([tier, count]) => (
                  <div key={tier} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <Badge variant="outline" className={TIER_COLORS[tier] || ""}>
                          {TIER_LABELS[tier] || tier}
                        </Badge>
                      </span>
                      <span className="text-muted-foreground tabular-nums">
                        {(count as number).toLocaleString()} feeds
                      </span>
                    </div>
                    <Progress value={((count as number) / (reg?.total || 1)) * 100} className="h-1.5" />
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Category Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(reg?.byCategory || {})
                    .sort(([, a], [, b]) => (b as number) - (a as number))
                    .slice(0, 12)
                    .map(([cat, count]) => (
                      <div
                        key={cat}
                        className="flex items-center justify-between text-sm py-1 px-2 rounded bg-muted/30"
                      >
                        <span className="truncate">{cat.replace(/_/g, " ")}</span>
                        <span className="text-muted-foreground tabular-nums ml-2">
                          {(count as number).toLocaleString()}
                        </span>
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Critical Articles */}
          {dashboard?.recentCritical && dashboard.recentCritical.length > 0 && (
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  Recent Critical Articles
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {dashboard.recentCritical.map((article: any) => (
                    <div key={article.id} className="flex items-start gap-3 p-2 rounded bg-muted/30">
                      <Badge variant="outline" className={SEV_COLORS[article.severity] || ""}>
                        {article.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{article.title}</p>
                        <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                          <Badge variant="outline" className={TIER_COLORS[article.feed_tier] || ""}>
                            {TIER_LABELS[article.feed_tier] || article.feed_tier}
                          </Badge>
                          <span>{article.ioc_count} IOCs</span>
                          {article.cve_refs?.length > 0 && <span>{article.cve_refs.length} CVEs</span>}
                          <span>{new Date(article.published_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                      {article.article_url && (
                        <a
                          href={article.article_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-foreground"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Knowledge Growth */}
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Brain className="h-4 w-4 text-cyan-400" />
                Knowledge Growth (7 days)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-3 rounded bg-muted/30">
                  <p className="text-2xl font-bold tabular-nums">
                    {lrn?.totalKnowledge?.totalArticles?.toLocaleString() || 0}
                  </p>
                  <p className="text-xs text-muted-foreground">Total Articles</p>
                </div>
                <div className="text-center p-3 rounded bg-muted/30">
                  <p className="text-2xl font-bold tabular-nums">
                    {lrn?.totalKnowledge?.totalIocs?.toLocaleString() || 0}
                  </p>
                  <p className="text-xs text-muted-foreground">IOCs Extracted</p>
                </div>
                <div className="text-center p-3 rounded bg-muted/30">
                  <p className="text-2xl font-bold tabular-nums">
                    {lrn?.totalKnowledge?.totalCves?.toLocaleString() || 0}
                  </p>
                  <p className="text-xs text-muted-foreground">CVE Articles</p>
                </div>
                <div className="text-center p-3 rounded bg-muted/30">
                  <p className="text-2xl font-bold tabular-nums">
                    {lrn?.totalKnowledge?.ragIndexed?.toLocaleString() || 0}
                  </p>
                  <p className="text-xs text-muted-foreground">RAG Indexed</p>
                </div>
              </div>
              {lrn?.growthRate && (
                <div className="mt-3 text-xs text-muted-foreground text-center">
                  Daily average: ~{Math.round(lrn.growthRate.articlesPerDay)} articles, ~
                  {Math.round(lrn.growthRate.iocsPerDay)} IOCs, ~{Math.round(lrn.growthRate.cvesPerDay)} CVEs
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Articles Tab ───────────────────────────────────────────── */}
        <TabsContent value="articles" className="space-y-4 mt-4">
          <div className="flex items-center gap-3">
            <Select
              value={articleFilter.severity}
              onValueChange={(v) => setArticleFilter((p) => ({ ...p, severity: v === "all" ? "" : v }))}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="info">Info</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={articleFilter.tier}
              onValueChange={(v) => setArticleFilter((p) => ({ ...p, tier: v === "all" ? "" : v }))}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Tier" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tiers</SelectItem>
                <SelectItem value="tier1">Tier 1 — Premium</SelectItem>
                <SelectItem value="tier2">Tier 2 — Research</SelectItem>
                <SelectItem value="tier3">Tier 3 — Infra</SelectItem>
                <SelectItem value="tier4">Tier 4 — Blogs</SelectItem>
                <SelectItem value="tier5">Tier 5 — General</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-sm text-muted-foreground ml-auto">
              {articles?.total?.toLocaleString() || 0} articles
            </span>
          </div>

          {articlesLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading articles...</div>
          ) : (
            <div className="space-y-2">
              {(articles?.articles || []).map((article: any) => (
                <Card key={article.id} className="border-border/50">
                  <CardContent className="p-3">
                    <div className="flex items-start gap-3">
                      <Badge variant="outline" className={SEV_COLORS[article.severity] || ""}>
                        {article.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">{article.title}</p>
                        {article.summary && (
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{article.summary}</p>
                        )}
                        <div className="flex items-center flex-wrap gap-2 mt-2">
                          <Badge variant="outline" className={TIER_COLORS[article.feed_tier] || ""}>
                            {TIER_LABELS[article.feed_tier] || article.feed_tier}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{article.feed_category}</span>
                          {article.ioc_count > 0 && (
                            <Badge variant="outline" className="text-xs">
                              {article.ioc_count} IOCs
                            </Badge>
                          )}
                          {article.cve_refs?.length > 0 && (
                            <Badge variant="outline" className="text-xs">
                              {article.cve_refs.length} CVEs
                            </Badge>
                          )}
                          {article.mitre_techniques?.length > 0 && (
                            <Badge variant="outline" className="text-xs">
                              {article.mitre_techniques.length} TTPs
                            </Badge>
                          )}
                          {article.threat_actors?.length > 0 &&
                            article.threat_actors.map((a: string) => (
                              <Badge
                                key={a}
                                variant="outline"
                                className="text-xs bg-red-500/10 text-red-400 border-red-500/30"
                              >
                                {a}
                              </Badge>
                            ))}
                          {article.malware_families?.length > 0 &&
                            article.malware_families.map((m: string) => (
                              <Badge
                                key={m}
                                variant="outline"
                                className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/30"
                              >
                                {m}
                              </Badge>
                            ))}
                          <span className="text-xs text-muted-foreground ml-auto">
                            {article.confidence_score?.toFixed(0)}% confidence &middot;{" "}
                            {new Date(article.published_at).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      {article.article_url && (
                        <a
                          href={article.article_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-foreground shrink-0"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
              {(articles?.articles || []).length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  <BookOpen className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No articles found. Run a poll to start ingesting feeds.</p>
                </div>
              )}
            </div>
          )}
        </TabsContent>

        {/* ── Feed Manager Tab ───────────────────────────────────────── */}
        <TabsContent value="feeds" className="space-y-4 mt-4">
          <div className="flex items-center gap-3">
            <Select
              value={feedFilter.tier}
              onValueChange={(v) => setFeedFilter((p) => ({ ...p, tier: v === "all" ? "" : v }))}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Tier" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tiers</SelectItem>
                <SelectItem value="tier1">Tier 1</SelectItem>
                <SelectItem value="tier2">Tier 2</SelectItem>
                <SelectItem value="tier3">Tier 3</SelectItem>
                <SelectItem value="tier4">Tier 4</SelectItem>
                <SelectItem value="tier5">Tier 5</SelectItem>
              </SelectContent>
            </Select>
            <Select value={feedFilter.sortBy} onValueChange={(v) => setFeedFilter((p) => ({ ...p, sortBy: v }))}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="quality">Quality Score</SelectItem>
                <SelectItem value="relevance">Relevance</SelectItem>
                <SelectItem value="articles">Articles Count</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-sm text-muted-foreground ml-auto">
              {feeds?.total?.toLocaleString() || 0} tracked feeds
            </span>
          </div>

          {feedsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading feeds...</div>
          ) : (
            <div className="space-y-2">
              {(feeds?.feeds || []).map((feed: any) => (
                <Card key={feed.id} className="border-border/50">
                  <CardContent className="p-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${feed.enabled ? "bg-emerald-400" : "bg-slate-500"}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate">{feed.feed_domain}</span>
                          <Badge variant="outline" className={TIER_COLORS[feed.tier] || ""}>
                            {TIER_LABELS[feed.tier] || feed.tier}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {feed.category}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                          <span>{feed.total_articles_ingested || 0} articles</span>
                          <span>{feed.total_iocs_extracted || 0} IOCs</span>
                          <span>Quality: {feed.quality_score?.toFixed(1) || "—"}</span>
                          <span>Errors: {feed.consecutive_errors || 0}</span>
                          {feed.last_success_at && (
                            <span>Last: {new Date(feed.last_success_at).toLocaleDateString()}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        <Progress value={feed.quality_score || 0} className="w-16 h-1.5" />
                        <span className="text-xs text-muted-foreground w-8 text-right">
                          {feed.quality_score?.toFixed(0) || 0}
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {(feeds?.feeds || []).length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  <Rss className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No feeds tracked yet. Run a poll to start tracking.</p>
                </div>
              )}
            </div>
          )}
        </TabsContent>

        {/* ── Trends Tab ─────────────────────────────────────────────── */}
        <TabsContent value="trends" className="space-y-6 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Trending CVEs */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="h-4 w-4 text-red-400" />
                  Trending CVEs (7 days)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(trends?.trendingCves || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">No CVE trends yet</p>
                ) : (
                  <div className="space-y-2">
                    {(trends?.trendingCves || []).slice(0, 10).map((cve: any) => (
                      <div key={cve.cve} className="flex items-center justify-between text-sm py-1">
                        <span className="font-mono text-xs">{cve.cve}</span>
                        <Badge variant="outline">{cve.mentions} mentions</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Trending Threat Actors */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Eye className="h-4 w-4 text-orange-400" />
                  Active Threat Actors
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(trends?.trendingActors || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">No threat actor activity yet</p>
                ) : (
                  <div className="space-y-2">
                    {(trends?.trendingActors || []).map((actor: any) => (
                      <div key={actor.actor} className="flex items-center justify-between text-sm py-1">
                        <span className="font-medium">{actor.actor}</span>
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30">
                          {actor.mentions} mentions
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Trending Malware */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  Malware Families
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(trends?.trendingMalware || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">No malware trends yet</p>
                ) : (
                  <div className="space-y-2">
                    {(trends?.trendingMalware || []).map((m: any) => (
                      <div key={m.malware} className="flex items-center justify-between text-sm py-1">
                        <span className="font-medium">{m.malware}</span>
                        <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30">
                          {m.mentions}
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* MITRE Techniques */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Layers className="h-4 w-4 text-violet-400" />
                  MITRE ATT&CK Techniques
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(trends?.trendingTechniques || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">No technique trends yet</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {(trends?.trendingTechniques || []).map((t: any) => (
                      <Badge
                        key={t.technique}
                        variant="outline"
                        className="bg-violet-500/10 text-violet-400 border-violet-500/30"
                      >
                        {t.technique} ({t.mentions})
                      </Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top Sources */}
            <Card className="border-border/50 lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Star className="h-4 w-4 text-yellow-400" />
                  Top Contributing Sources
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(trends?.topSources || []).length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">No source data yet</p>
                ) : (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {(trends?.topSources || []).map((s: any) => (
                      <div
                        key={s.domain}
                        className="flex items-center justify-between text-sm py-1 px-2 rounded bg-muted/30"
                      >
                        <span className="truncate">{s.domain}</span>
                        <span className="text-muted-foreground tabular-nums ml-2">{s.articles}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Learning Tab ───────────────────────────────────────────── */}
        <TabsContent value="learning" className="space-y-6 mt-4">
          {/* Total Knowledge */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            <StatCard label="Total Articles" value={learning?.totalKnowledge?.totalArticles || 0} icon={BookOpen} />
            <StatCard label="Total IOCs" value={learning?.totalKnowledge?.totalIocs || 0} icon={Shield} />
            <StatCard label="CVE Articles" value={learning?.totalKnowledge?.totalCves || 0} icon={AlertTriangle} />
            <StatCard label="TTP Articles" value={learning?.totalKnowledge?.totalTechniques || 0} icon={Layers} />
            <StatCard label="Actor Articles" value={learning?.totalKnowledge?.totalActors || 0} icon={Eye} />
            <StatCard label="Malware Articles" value={learning?.totalKnowledge?.totalMalware || 0} icon={Activity} />
            <StatCard label="RAG Indexed" value={learning?.totalKnowledge?.ragIndexed || 0} icon={Brain} />
          </div>

          {/* Daily Growth Rate */}
          {learning?.growthRate && (
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Daily Growth Rate (7-day avg)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-3 rounded bg-muted/30">
                    <p className="text-xl font-bold tabular-nums">~{Math.round(learning.growthRate.articlesPerDay)}</p>
                    <p className="text-xs text-muted-foreground">Articles/day</p>
                  </div>
                  <div className="text-center p-3 rounded bg-muted/30">
                    <p className="text-xl font-bold tabular-nums">~{Math.round(learning.growthRate.iocsPerDay)}</p>
                    <p className="text-xs text-muted-foreground">IOCs/day</p>
                  </div>
                  <div className="text-center p-3 rounded bg-muted/30">
                    <p className="text-xl font-bold tabular-nums">~{Math.round(learning.growthRate.cvesPerDay)}</p>
                    <p className="text-xs text-muted-foreground">CVEs/day</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Learning History */}
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Learning History (30 days)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {(learning?.history || []).length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No learning history yet. Run a daily learning cycle to start.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {(learning?.history || []).map((entry: any) => (
                    <div key={entry.date} className="flex items-center gap-4 p-2 rounded bg-muted/30 text-sm">
                      <span className="text-muted-foreground w-24 shrink-0">
                        {new Date(entry.date).toLocaleDateString()}
                      </span>
                      <span className="tabular-nums">{entry.feedsPolled} feeds</span>
                      <span className="tabular-nums">{entry.articlesIngested} articles</span>
                      <span className="tabular-nums">{entry.newIocs} IOCs</span>
                      <span className="tabular-nums">{entry.newCves} CVEs</span>
                      <span className="tabular-nums">{entry.newTechniques} TTPs</span>
                      {entry.summary && (
                        <span className="text-xs text-muted-foreground truncate flex-1">{entry.summary}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
