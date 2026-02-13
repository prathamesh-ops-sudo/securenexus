import { useState, useMemo, Fragment } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Link } from "wouter";
import { Shield, Search, Globe, Server, ExternalLink, Database, RefreshCw, CheckCircle2, XCircle, Zap, Network, Rss, Loader2, Clock, ChevronDown } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Tooltip as ShadTooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, formatTimestamp } from "@/components/security-badges";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from "recharts";
import type { Alert, Incident } from "@shared/schema";

interface ProviderStatus {
  name: string;
  enabled: boolean;
  configured: boolean;
  supportedTypes: string[];
}

interface FeedStatus {
  name: string;
  slug: string;
  url: string;
  lastFetched: string | null;
  totalIndicators: number;
  status: "success" | "error" | "never_fetched";
  requiresApiKey: false;
}

interface OsintIndicator {
  type: string;
  value: string;
  threat: string;
  source: string;
  firstSeen?: string;
  tags: string[];
  confidence: number;
}

interface OsintFeedResult {
  feedName: string;
  feedUrl: string;
  lastFetched: string;
  totalIndicators: number;
  indicators: OsintIndicator[];
  status: "success" | "error" | "stale";
  errorMessage?: string;
}

interface IOCEntry {
  value: string;
  type: string;
  source: string;
  alertTitle: string;
  severity: string;
  firstSeen: string | Date | null | undefined;
  alertId: string;
}

const IOC_TYPE_BADGE_VARIANT: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
  ip: "destructive",
  domain: "default",
  hash: "secondary",
  url: "outline",
  hostname: "secondary",
  email: "outline",
};

const CHART_COLORS = [
  "hsl(var(--chart-1))",
  "hsl(var(--chart-2))",
  "hsl(var(--chart-3))",
  "hsl(var(--chart-4))",
  "hsl(var(--chart-5))",
  "hsl(var(--destructive))",
];

function extractIOCsFromAlerts(alerts: Alert[]): IOCEntry[] {
  const iocs: IOCEntry[] = [];
  for (const alert of alerts) {
    const fields: { field: string | null | undefined; type: string }[] = [
      { field: alert.sourceIp, type: "ip" },
      { field: alert.destIp, type: "ip" },
      { field: alert.domain, type: "domain" },
      { field: alert.url, type: "url" },
      { field: alert.fileHash, type: "hash" },
      { field: alert.hostname, type: "hostname" },
    ];
    for (const { field, type } of fields) {
      if (field && field.trim()) {
        iocs.push({
          value: field.trim(),
          type,
          source: alert.source,
          alertTitle: alert.title,
          severity: alert.severity,
          firstSeen: alert.detectedAt || alert.createdAt,
          alertId: alert.id,
        });
      }
    }
  }
  return iocs;
}

function extractIOCsFromIncidents(incidents: Incident[]): IOCEntry[] {
  const iocs: IOCEntry[] = [];
  for (const incident of incidents) {
    if (!incident.iocs || !Array.isArray(incident.iocs)) continue;
    for (const iocStr of incident.iocs as string[]) {
      const match = iocStr.match(/^(.+?)\s*\((\w+):\s*(.+?)\)$/);
      if (match) {
        iocs.push({
          value: match[1].trim(),
          type: match[2].trim().toLowerCase(),
          source: "Incident Analysis",
          alertTitle: incident.title,
          severity: incident.severity,
          firstSeen: incident.createdAt,
          alertId: "",
        });
      } else {
        iocs.push({
          value: iocStr.trim(),
          type: "unknown",
          source: "Incident Analysis",
          alertTitle: incident.title,
          severity: incident.severity,
          firstSeen: incident.createdAt,
          alertId: "",
        });
      }
    }
  }
  return iocs;
}

function formatRelativeTimestamp(date: string | null): string {
  if (!date) return "Never";
  const d = new Date(date);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

const FEED_STATUS_DOT: Record<string, string> = {
  success: "bg-green-500",
  never_fetched: "bg-yellow-500",
  error: "bg-red-500",
};

export default function ThreatIntelPage() {
  const [search, setSearch] = useState("");
  const [selectedIOCIdx, setSelectedIOCIdx] = useState<number | null>(null);
  const [expandedFeed, setExpandedFeed] = useState<string | null>(null);
  const [feedDataMap, setFeedDataMap] = useState<Record<string, OsintFeedResult>>({});
  const { toast } = useToast();

  const { data: alerts, isLoading: alertsLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts"],
  });

  const { data: incidents, isLoading: incidentsLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: providers, isLoading: providersLoading } = useQuery<ProviderStatus[]>({
    queryKey: ["/api/enrichment/providers"],
  });

  const { data: feedStatuses, isLoading: feedStatusesLoading } = useQuery<FeedStatus[]>({
    queryKey: ["/api/osint-feeds/status"],
  });

  const refreshFeedMutation = useMutation({
    mutationFn: async (feedSlug: string) => {
      const res = await apiRequest("POST", `/api/osint-feeds/${encodeURIComponent(feedSlug)}/refresh`);
      return res.json() as Promise<OsintFeedResult>;
    },
    onSuccess: (data, feedSlug) => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint-feeds/status"] });
      setFeedDataMap((prev) => ({ ...prev, [feedSlug]: data }));
      setExpandedFeed(feedSlug);
      toast({
        title: "Feed refreshed",
        description: `${data.feedName}: ${data.totalIndicators} indicators fetched`,
      });
    },
    onError: (error: Error, feedSlug) => {
      toast({
        title: "Feed refresh failed",
        description: `${feedSlug}: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  const refreshAllMutation = useMutation({
    mutationFn: async () => {
      const statuses = feedStatuses || [];
      const results = await Promise.all(
        statuses.map(async (feed) => {
          const res = await apiRequest("POST", `/api/osint-feeds/${encodeURIComponent(feed.slug)}/refresh`);
          return res.json() as Promise<OsintFeedResult>;
        })
      );
      return results;
    },
    onSuccess: (results) => {
      queryClient.invalidateQueries({ queryKey: ["/api/osint-feeds/status"] });
      const newMap: Record<string, OsintFeedResult> = {};
      const statuses = feedStatuses || [];
      for (let i = 0; i < results.length; i++) {
        const slug = statuses[i]?.slug || results[i].feedName;
        newMap[slug] = results[i];
      }
      setFeedDataMap((prev) => ({ ...prev, ...newMap }));
      toast({
        title: "All feeds refreshed",
        description: `${results.length} feeds updated`,
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Refresh all failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const isLoading = alertsLoading || incidentsLoading;
  const anyProviderConfigured = providers?.some((p) => p.configured) ?? false;

  const allIOCs = useMemo(() => {
    const alertIOCs = alerts ? extractIOCsFromAlerts(alerts) : [];
    const incidentIOCs = incidents ? extractIOCsFromIncidents(incidents) : [];
    return [...alertIOCs, ...incidentIOCs];
  }, [alerts, incidents]);

  const filteredIOCs = useMemo(() => {
    if (!search.trim()) return allIOCs;
    const q = search.toLowerCase();
    return allIOCs.filter(
      (ioc) =>
        ioc.value.toLowerCase().includes(q) ||
        ioc.type.toLowerCase().includes(q) ||
        ioc.source.toLowerCase().includes(q)
    );
  }, [allIOCs, search]);

  const stats = useMemo(() => {
    const uniqueDomains = new Set(
      allIOCs.filter((i) => i.type === "domain").map((i) => i.value.toLowerCase())
    ).size;
    const uniqueIPs = new Set(
      allIOCs.filter((i) => i.type === "ip").map((i) => i.value)
    ).size;
    return { total: allIOCs.length, uniqueDomains, uniqueIPs };
  }, [allIOCs]);

  const typeDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const ioc of allIOCs) {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1;
    }
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [allIOCs]);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto" data-testid="page-threat-intel">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Threat Intelligence</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
          Indicators of Compromise (IOCs) extracted from alerts and incidents
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4" data-testid="section-enrichment-providers">
        {providersLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Skeleton className="h-8 w-8 rounded-full" />
                  <div className="space-y-2 flex-1">
                    <Skeleton className="h-4 w-24" />
                    <Skeleton className="h-3 w-32" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : providers && providers.length > 0 ? (
          providers.map((provider) => (
            <Card key={provider.name} data-testid={`card-provider-${provider.name}`}>
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0 mt-0.5">
                    <Zap className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium" data-testid={`text-provider-name-${provider.name}`}>
                        {provider.name}
                      </span>
                      <span
                        className={`h-2 w-2 rounded-full flex-shrink-0 ${provider.configured ? "bg-green-500" : "bg-red-500"}`}
                        data-testid={`status-provider-${provider.name}`}
                      />
                    </div>
                    <p
                      className={`text-xs ${provider.configured ? "text-green-600 dark:text-green-400" : "text-muted-foreground"}`}
                      data-testid={`text-provider-status-${provider.name}`}
                    >
                      {provider.configured ? "Configured" : "API Key Required"}
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {provider.supportedTypes.map((type) => (
                        <Badge
                          key={type}
                          variant="outline"
                          className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                          data-testid={`badge-provider-type-${provider.name}-${type}`}
                        >
                          {type}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          <Card className="sm:col-span-3">
            <CardContent className="p-4 text-center">
              <p className="text-sm text-muted-foreground" data-testid="text-no-providers">
                No enrichment providers available
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      <Card data-testid="section-osint-feeds">
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Rss className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">Public OSINT Feeds</CardTitle>
          </div>
          <Button
            size="sm"
            variant="outline"
            disabled={refreshAllMutation.isPending}
            onClick={() => refreshAllMutation.mutate()}
            data-testid="button-fetch-all-feeds"
          >
            {refreshAllMutation.isPending ? (
              <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            )}
            Fetch All
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {feedStatusesLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="border rounded-md p-4 space-y-3">
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-3 w-20" />
                  <Skeleton className="h-3 w-16" />
                </div>
              ))}
            </div>
          ) : feedStatuses && feedStatuses.length > 0 ? (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" data-testid="grid-osint-feeds">
                {feedStatuses.map((feed) => {
                  const isFetching = refreshFeedMutation.isPending && refreshFeedMutation.variables === feed.name;
                  return (
                    <div key={feed.name} className="border rounded-md p-4 space-y-3" data-testid={`card-feed-${feed.name}`}>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`h-2 w-2 rounded-full flex-shrink-0 ${FEED_STATUS_DOT[feed.status] || "bg-gray-400"}`}
                            data-testid={`status-feed-${feed.name}`}
                          />
                          <span className="text-sm font-medium truncate" data-testid={`text-feed-name-${feed.name}`}>
                            {feed.name}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Database className="h-3 w-3 flex-shrink-0" />
                          <span data-testid={`text-feed-count-${feed.name}`}>
                            {feed.totalIndicators.toLocaleString()} indicators
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Clock className="h-3 w-3 flex-shrink-0" />
                          <span data-testid={`text-feed-last-fetched-${feed.name}`}>
                            {formatRelativeTimestamp(feed.lastFetched)}
                          </span>
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          className="w-full"
                          disabled={isFetching}
                          onClick={() => refreshFeedMutation.mutate(feed.slug)}
                          data-testid={`button-fetch-feed-${feed.name}`}
                        >
                          {isFetching ? (
                            <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                          ) : (
                            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
                          )}
                          Fetch
                        </Button>
                      </div>
                  );
                })}
              </div>

              {expandedFeed && feedDataMap[expandedFeed] && (
                <Collapsible open={true} onOpenChange={(open) => { if (!open) setExpandedFeed(null); }}>
                  <CollapsibleTrigger asChild>
                    <Button
                      variant="ghost"
                      className="w-full flex items-center justify-between gap-2"
                      data-testid="button-toggle-feed-data"
                    >
                      <span className="text-sm font-medium">
                        {feedDataMap[expandedFeed].feedName} - {feedDataMap[expandedFeed].indicators.length} indicators
                      </span>
                      <ChevronDown className="h-4 w-4" />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="overflow-x-auto mt-2 border rounded-md">
                      <Table data-testid="table-feed-indicators">
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Type</TableHead>
                            <TableHead className="text-xs">Value</TableHead>
                            <TableHead className="text-xs hidden md:table-cell">Threat</TableHead>
                            <TableHead className="text-xs hidden lg:table-cell">Source</TableHead>
                            <TableHead className="text-xs hidden md:table-cell">First Seen</TableHead>
                            <TableHead className="text-xs">Tags</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {feedDataMap[expandedFeed].indicators.length > 0 ? (
                            feedDataMap[expandedFeed].indicators.map((indicator, idx) => (
                              <TableRow key={`${indicator.value}-${idx}`} data-testid={`row-feed-indicator-${idx}`}>
                                <TableCell>
                                  <Badge
                                    variant={IOC_TYPE_BADGE_VARIANT[indicator.type] || "secondary"}
                                    className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                                    data-testid={`badge-feed-indicator-type-${idx}`}
                                  >
                                    {indicator.type}
                                  </Badge>
                                </TableCell>
                                <TableCell>
                                  <span className="text-xs font-mono truncate max-w-[250px] block" data-testid={`text-feed-indicator-value-${idx}`}>
                                    {indicator.value}
                                  </span>
                                </TableCell>
                                <TableCell className="hidden md:table-cell">
                                  <span className="text-xs text-muted-foreground truncate max-w-[200px] block" data-testid={`text-feed-indicator-threat-${idx}`}>
                                    {indicator.threat}
                                  </span>
                                </TableCell>
                                <TableCell className="hidden lg:table-cell">
                                  <span className="text-xs text-muted-foreground" data-testid={`text-feed-indicator-source-${idx}`}>
                                    {indicator.source}
                                  </span>
                                </TableCell>
                                <TableCell className="hidden md:table-cell">
                                  <span className="text-xs text-muted-foreground" data-testid={`text-feed-indicator-firstseen-${idx}`}>
                                    {indicator.firstSeen ? formatTimestamp(indicator.firstSeen) : "N/A"}
                                  </span>
                                </TableCell>
                                <TableCell>
                                  <div className="flex flex-wrap gap-1">
                                    {indicator.tags.slice(0, 3).map((tag, tIdx) => (
                                      <Badge
                                        key={`${tag}-${tIdx}`}
                                        variant="outline"
                                        className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                                        data-testid={`badge-feed-indicator-tag-${idx}-${tIdx}`}
                                      >
                                        {tag}
                                      </Badge>
                                    ))}
                                    {indicator.tags.length > 3 && (
                                      <Badge
                                        variant="outline"
                                        className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                                      >
                                        +{indicator.tags.length - 3}
                                      </Badge>
                                    )}
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))
                          ) : (
                            <TableRow>
                              <TableCell colSpan={6} className="text-center py-8">
                                <p className="text-sm text-muted-foreground" data-testid="text-no-feed-indicators">
                                  No indicators available for this feed
                                </p>
                              </TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              )}
            </>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4" data-testid="text-no-feeds">
              No OSINT feeds available
            </p>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card data-testid="card-total-iocs">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total IOCs</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="stat-total-iocs">
                {stats.total}
              </div>
            )}
          </CardContent>
        </Card>
        <Card data-testid="card-unique-domains">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Unique Domains</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="stat-unique-domains">
                {stats.uniqueDomains}
              </div>
            )}
          </CardContent>
        </Card>
        <Card data-testid="card-unique-ips">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Unique IPs</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <div className="text-2xl font-bold" data-testid="stat-unique-ips">
                {stats.uniqueIPs}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search IOCs by value, type, or source..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
          data-testid="input-search-iocs"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3">
          <Card data-testid="card-ioc-table">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Indicator</TableHead>
                      <TableHead className="text-xs">Type</TableHead>
                      <TableHead className="text-xs hidden md:table-cell">Source</TableHead>
                      <TableHead className="text-xs hidden lg:table-cell">Alert Title</TableHead>
                      <TableHead className="text-xs">Severity</TableHead>
                      <TableHead className="text-xs hidden md:table-cell">First Seen</TableHead>
                      <TableHead className="text-xs w-10">Enrich</TableHead>
                      <TableHead className="text-xs w-10"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {isLoading ? (
                      Array.from({ length: 6 }).map((_, i) => (
                        <TableRow key={i}>
                          <TableCell><Skeleton className="h-4 w-40" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                          <TableCell className="hidden md:table-cell"><Skeleton className="h-4 w-24" /></TableCell>
                          <TableCell className="hidden lg:table-cell"><Skeleton className="h-4 w-32" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                          <TableCell className="hidden md:table-cell"><Skeleton className="h-4 w-24" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-6" /></TableCell>
                          <TableCell><Skeleton className="h-4 w-6" /></TableCell>
                        </TableRow>
                      ))
                    ) : filteredIOCs.length > 0 ? (
                      filteredIOCs.map((ioc, idx) => (
                        <Fragment key={`${ioc.value}-${ioc.alertId}-${idx}`}>
                        <TableRow
                          data-testid={`row-ioc-${idx}`}
                          className="cursor-pointer"
                          onClick={() => setSelectedIOCIdx(selectedIOCIdx === idx ? null : idx)}
                        >
                          <TableCell>
                            <span className="text-sm font-mono truncate max-w-[200px] block" data-testid={`text-ioc-value-${idx}`}>
                              {ioc.value}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={IOC_TYPE_BADGE_VARIANT[ioc.type] || "secondary"}
                              className="no-default-hover-elevate no-default-active-elevate text-[10px] uppercase"
                              data-testid={`badge-ioc-type-${idx}`}
                            >
                              {ioc.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            <span className="text-xs text-muted-foreground" data-testid={`text-ioc-source-${idx}`}>
                              {ioc.source}
                            </span>
                          </TableCell>
                          <TableCell className="hidden lg:table-cell">
                            <span className="text-xs text-muted-foreground truncate max-w-[200px] block" data-testid={`text-ioc-alert-${idx}`}>
                              {ioc.alertTitle}
                            </span>
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={ioc.severity} />
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            <span className="text-xs text-muted-foreground" data-testid={`text-ioc-firstseen-${idx}`}>
                              {formatTimestamp(ioc.firstSeen)}
                            </span>
                          </TableCell>
                          <TableCell>
                            <ShadTooltip>
                              <TooltipTrigger asChild>
                                <span>
                                  <Button
                                    size="icon"
                                    variant="ghost"
                                    disabled={!anyProviderConfigured}
                                    data-testid={`button-enrich-${idx}`}
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    <RefreshCw className="h-3.5 w-3.5" />
                                  </Button>
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p className="text-xs">
                                  {anyProviderConfigured
                                    ? "Enrich this IOC"
                                    : "Configure API keys to enable enrichment"}
                                </p>
                              </TooltipContent>
                            </ShadTooltip>
                          </TableCell>
                          <TableCell>
                            {ioc.alertId ? (
                              <Link href={`/alerts/${ioc.alertId}`} data-testid={`link-ioc-alert-${idx}`}>
                                <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
                              </Link>
                            ) : null}
                          </TableCell>
                        </TableRow>
                        {selectedIOCIdx === idx && (
                          <TableRow key={`${ioc.value}-${ioc.alertId}-${idx}-detail`} data-testid={`row-ioc-detail-${idx}`}>
                            <TableCell colSpan={8} className="bg-muted/30 p-4">
                              <div className="flex items-center gap-4 flex-wrap">
                                <div className="flex items-center gap-2 text-sm">
                                  <Network className="h-4 w-4 text-muted-foreground" />
                                  <span className="text-muted-foreground">View in Entity Graph:</span>
                                  <Link
                                    href={`/entity-graph?search=${encodeURIComponent(ioc.value)}`}
                                    data-testid={`link-entity-graph-${idx}`}
                                  >
                                    <Badge variant="outline" className="text-xs font-mono">
                                      {ioc.value}
                                      <ExternalLink className="h-3 w-3 ml-1" />
                                    </Badge>
                                  </Link>
                                </div>
                                {!anyProviderConfigured && (
                                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                    <XCircle className="h-3.5 w-3.5" />
                                    <span>No enrichment providers configured</span>
                                  </div>
                                )}
                                {anyProviderConfigured && (
                                  <div className="flex items-center gap-1.5 text-xs text-green-600 dark:text-green-400">
                                    <CheckCircle2 className="h-3.5 w-3.5" />
                                    <span>Enrichment available</span>
                                  </div>
                                )}
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                        </Fragment>
                      ))
                    ) : (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-12">
                          <div className="flex flex-col items-center gap-2" data-testid="empty-state-iocs">
                            <Shield className="h-8 w-8 text-muted-foreground/50" />
                            <p className="text-sm text-muted-foreground">No IOCs found</p>
                            {search && (
                              <p className="text-xs text-muted-foreground">
                                Try adjusting your search query
                              </p>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-1">
          <Card data-testid="card-ioc-distribution">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">IOC Type Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Skeleton className="h-32 w-32 rounded-full" />
                </div>
              ) : typeDistribution.length > 0 ? (
                <div>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie
                        data={typeDistribution}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {typeDistribution.map((_, i) => (
                          <Cell
                            key={i}
                            fill={CHART_COLORS[i % CHART_COLORS.length]}
                          />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: "hsl(var(--card))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: "6px",
                          fontSize: "12px",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="space-y-1.5 mt-2">
                    {typeDistribution.map((entry, i) => (
                      <div
                        key={entry.name}
                        className="flex items-center justify-between text-xs"
                        data-testid={`legend-ioc-type-${entry.name}`}
                      >
                        <div className="flex items-center gap-2">
                          <span
                            className="h-2.5 w-2.5 rounded-sm flex-shrink-0"
                            style={{ backgroundColor: CHART_COLORS[i % CHART_COLORS.length] }}
                          />
                          <span className="text-muted-foreground uppercase">{entry.name}</span>
                        </div>
                        <span className="font-medium">{entry.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground text-center py-8" data-testid="empty-distribution">
                  No data available
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
