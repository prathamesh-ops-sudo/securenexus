import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import {
  Globe,
  Shield,
  Share2,
  AlertTriangle,
  Eye,
  Network,
  Activity,
  Search,
  Plus,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  TrendingUp,
  Users,
  FileWarning,
  Crosshair,
  Rss,
} from "lucide-react";

// ── API helpers ───────────────────────────────────────────────────────────────

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

// ── Types ─────────────────────────────────────────────────────────────────────

interface SharingConsent {
  id: string;
  orgId: string;
  consentLevel: string;
  industrySector: string;
  companySize: string;
  shareIocs: boolean;
  shareDetectionPatterns: boolean;
  shareTelemetry: boolean;
  receiveGlobalFeed: boolean;
  receiveIndustryFeed: boolean;
  autoContribute: boolean;
  contributedIocCount: number;
  receivedIocCount: number;
  lastContributedAt: string | null;
  lastReceivedAt: string | null;
  consentGrantedAt: string | null;
}

interface SharedIoc {
  id: string;
  iocType: string;
  iocValue: string;
  severity: string;
  confidence: number;
  tlpLevel: string;
  tags: string[];
  threatActorRef: string | null;
  campaignRef: string | null;
  context: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  sightingCount: number;
  industrySectors: string[];
  isActive: boolean;
  createdAt: string;
}

interface CommunityFeed {
  id: string;
  feedName: string;
  feedType: string;
  industrySector: string | null;
  description: string | null;
  iocCount: number;
  memberCount: number;
  isSubscribed: boolean;
  autoIngest: boolean;
  filterSeverity: string | null;
  filterConfidence: number | null;
}

interface Campaign {
  id: string;
  campaignName: string;
  threatActorName: string | null;
  description: string | null;
  mitreAttackIds: string[];
  targetSectors: string[];
  iocCount: number;
  affectedOrgCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  status: string;
  severity: string;
  tlpLevel: string;
}

interface NetworkStats {
  totalSharedIocs: number;
  activeIocs: number;
  participatingOrgs: number;
  campaignsTracked: number;
  iocsByType: Record<string, number>;
  iocsBySeverity: Record<string, number>;
  topIndustrySectors: Array<{ sector: string; count: number }>;
  avgConfidence: number;
  last24hContributions: number;
  last7dContributions: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function severityColor(s: string): string {
  switch (s) {
    case "critical":
      return "text-red-400";
    case "high":
      return "text-orange-400";
    case "medium":
      return "text-yellow-400";
    case "low":
      return "text-blue-400";
    default:
      return "text-slate-400";
  }
}

function severityBadge(s: string): string {
  switch (s) {
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

function tlpBadge(tlp: string): string {
  switch (tlp) {
    case "white":
      return "bg-white/20 text-white border-white/30";
    case "green":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    case "amber":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "red":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    default:
      return "bg-slate-500/20 text-slate-400 border-slate-500/30";
  }
}

function iocTypeLabel(t: string): string {
  const labels: Record<string, string> = {
    ip: "IP Address",
    domain: "Domain",
    url: "URL",
    hash_md5: "MD5 Hash",
    hash_sha1: "SHA-1 Hash",
    hash_sha256: "SHA-256 Hash",
    email: "Email",
    file_name: "File Name",
    cidr: "CIDR Range",
    certificate: "Certificate",
  };
  return labels[t] || t;
}

// ── Dashboard Tab ─────────────────────────────────────────────────────────────

function DashboardTab() {
  const { data, isLoading } = useQuery<{
    network: NetworkStats;
    orgContribution: {
      consentLevel: string;
      contributedIocCount: number;
      receivedIocCount: number;
      lastContributedAt: string | null;
      lastReceivedAt: string | null;
    } | null;
  }>({
    queryKey: ["/api/community-intel/stats"],
    queryFn: () => apiFetch("/api/community-intel/stats"),
  });

  if (isLoading) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading network stats...</div>;
  }

  const stats = data?.network;
  const org = data?.orgContribution;

  return (
    <div className="space-y-6">
      {/* Network Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Globe className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.totalSharedIocs ?? 0}</p>
                <p className="text-xs text-muted-foreground">Total Shared IOCs</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Users className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.participatingOrgs ?? 0}</p>
                <p className="text-xs text-muted-foreground">Participating Orgs</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <Crosshair className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.campaignsTracked ?? 0}</p>
                <p className="text-xs text-muted-foreground">Campaigns Tracked</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <TrendingUp className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.last24hContributions ?? 0}</p>
                <p className="text-xs text-muted-foreground">IOCs (Last 24h)</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* IOC Breakdown + Org Contribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">IOCs by Type</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.iocsByType && Object.keys(stats.iocsByType).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(stats.iocsByType)
                  .sort((a, b) => b[1] - a[1])
                  .map(([type, cnt]) => (
                    <div key={type} className="flex items-center justify-between">
                      <span className="text-sm">{iocTypeLabel(type)}</span>
                      <Badge variant="outline">{cnt}</Badge>
                    </div>
                  ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No IOCs shared yet</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Your Contribution</CardTitle>
          </CardHeader>
          <CardContent>
            {org ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Consent Level</span>
                  <Badge variant="outline" className="capitalize">
                    {org.consentLevel}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">IOCs Contributed</span>
                  <span className="font-mono">{org.contributedIocCount}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">IOCs Received</span>
                  <span className="font-mono">{org.receivedIocCount}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Last Contributed</span>
                  <span className="text-xs">{formatDate(org.lastContributedAt)}</span>
                </div>
              </div>
            ) : (
              <div className="text-center py-4">
                <p className="text-sm text-muted-foreground">
                  Not yet participating. Enable sharing in the Preferences tab.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Severity Breakdown + Top Sectors */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">IOCs by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.iocsBySeverity && Object.keys(stats.iocsBySeverity).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(stats.iocsBySeverity)
                  .sort(
                    (a, b) =>
                      ["critical", "high", "medium", "low", "informational"].indexOf(a[0]) -
                      ["critical", "high", "medium", "low", "informational"].indexOf(b[0]),
                  )
                  .map(([sev, cnt]) => (
                    <div key={sev} className="flex items-center justify-between">
                      <span className={`text-sm capitalize ${severityColor(sev)}`}>{sev}</span>
                      <Badge variant="outline">{cnt}</Badge>
                    </div>
                  ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No data</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Top Industry Sectors</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.topIndustrySectors && stats.topIndustrySectors.length > 0 ? (
              <div className="space-y-2">
                {stats.topIndustrySectors.map((s) => (
                  <div key={s.sector} className="flex items-center justify-between">
                    <span className="text-sm capitalize">{s.sector}</span>
                    <Badge variant="outline">{s.count}</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No sector data</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Sharing Preferences Tab ───────────────────────────────────────────────────

function SharingPreferencesTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<{
    consent: SharingConsent | null;
    defaults: { consentLevels: string[]; industrySectors: string[] };
  }>({
    queryKey: ["/api/community-intel/consent"],
    queryFn: () => apiFetch("/api/community-intel/consent"),
  });

  const [consentLevel, setConsentLevel] = useState("");
  const [industrySector, setIndustrySector] = useState("");
  const [companySize, setCompanySize] = useState("medium");
  const [shareIocs, setShareIocs] = useState(false);
  const [shareDetectionPatterns, setShareDetectionPatterns] = useState(false);
  const [shareTelemetry, setShareTelemetry] = useState(false);
  const [receiveGlobal, setReceiveGlobal] = useState(true);
  const [receiveIndustry, setReceiveIndustry] = useState(true);
  const [autoContribute, setAutoContribute] = useState(false);
  const [initialized, setInitialized] = useState(false);

  // Initialize form from existing consent
  if (data?.consent && !initialized) {
    setConsentLevel(data.consent.consentLevel);
    setIndustrySector(data.consent.industrySector);
    setCompanySize(data.consent.companySize);
    setShareIocs(data.consent.shareIocs);
    setShareDetectionPatterns(data.consent.shareDetectionPatterns);
    setShareTelemetry(data.consent.shareTelemetry);
    setReceiveGlobal(data.consent.receiveGlobalFeed);
    setReceiveIndustry(data.consent.receiveIndustryFeed);
    setAutoContribute(data.consent.autoContribute);
    setInitialized(true);
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch("/api/community-intel/consent", {
        method: "POST",
        body: JSON.stringify({
          consentLevel,
          industrySector,
          companySize,
          shareIocs,
          shareDetectionPatterns,
          shareTelemetry,
          receiveGlobalFeed: receiveGlobal,
          receiveIndustryFeed: receiveIndustry,
          autoContribute,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/consent"] });
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/stats"] });
      toast({ title: "Sharing preferences saved" });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading preferences...</div>;
  }

  return (
    <div className="max-w-2xl space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Share2 className="h-5 w-5" />
            Sharing Consent
          </CardTitle>
          <CardDescription>
            Control what threat intelligence your organization shares with the community network. All shared data is
            anonymized — your organization identity is never revealed.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Consent Level */}
          <div className="space-y-2">
            <Label>Consent Level</Label>
            <Select value={consentLevel} onValueChange={setConsentLevel}>
              <SelectTrigger>
                <SelectValue placeholder="Select consent level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None — Do not share</SelectItem>
                <SelectItem value="ioc_only">IOC Only — Share indicators of compromise</SelectItem>
                <SelectItem value="detection_patterns">Detection Patterns — IOCs + detection rules</SelectItem>
                <SelectItem value="full_telemetry">Full Telemetry — IOCs + patterns + anonymized telemetry</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Industry & Size */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Industry Sector</Label>
              <Select value={industrySector} onValueChange={setIndustrySector}>
                <SelectTrigger>
                  <SelectValue placeholder="Select industry" />
                </SelectTrigger>
                <SelectContent>
                  {(data?.defaults.industrySectors || []).map((s) => (
                    <SelectItem key={s} value={s}>
                      {s.charAt(0).toUpperCase() + s.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Company Size</Label>
              <Select value={companySize} onValueChange={setCompanySize}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="small">Small (1-50)</SelectItem>
                  <SelectItem value="medium">Medium (51-500)</SelectItem>
                  <SelectItem value="large">Large (501-5000)</SelectItem>
                  <SelectItem value="enterprise">Enterprise (5000+)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Sharing Toggles */}
          <div className="space-y-4 pt-2">
            <div className="flex items-center justify-between">
              <div>
                <Label>Share IOCs</Label>
                <p className="text-xs text-muted-foreground">
                  Contribute malicious IPs, domains, and hashes to the network
                </p>
              </div>
              <Switch checked={shareIocs} onCheckedChange={setShareIocs} />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label>Share Detection Patterns</Label>
                <p className="text-xs text-muted-foreground">Share detection rules and signatures with the community</p>
              </div>
              <Switch checked={shareDetectionPatterns} onCheckedChange={setShareDetectionPatterns} />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label>Share Telemetry</Label>
                <p className="text-xs text-muted-foreground">
                  Contribute anonymized event telemetry for network-wide analysis
                </p>
              </div>
              <Switch checked={shareTelemetry} onCheckedChange={setShareTelemetry} />
            </div>
          </div>

          {/* Receiving Toggles */}
          <div className="space-y-4 pt-2 border-t">
            <p className="text-sm font-medium pt-2">Receiving Preferences</p>
            <div className="flex items-center justify-between">
              <div>
                <Label>Receive Global Feed</Label>
                <p className="text-xs text-muted-foreground">Get IOCs from all industries</p>
              </div>
              <Switch checked={receiveGlobal} onCheckedChange={setReceiveGlobal} />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label>Receive Industry Feed</Label>
                <p className="text-xs text-muted-foreground">Get sector-specific threat intelligence</p>
              </div>
              <Switch checked={receiveIndustry} onCheckedChange={setReceiveIndustry} />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label>Auto-Contribute New IOCs</Label>
                <p className="text-xs text-muted-foreground">Automatically share newly detected IOCs</p>
              </div>
              <Switch checked={autoContribute} onCheckedChange={setAutoContribute} />
            </div>
          </div>

          <Button className="w-full" onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
            {saveMutation.isPending ? "Saving..." : "Save Preferences"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Community Feeds Tab ───────────────────────────────────────────────────────

function CommunityFeedsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<{ feeds: CommunityFeed[] }>({
    queryKey: ["/api/community-intel/feeds"],
    queryFn: () => apiFetch("/api/community-intel/feeds"),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ feedId, isSubscribed }: { feedId: string; isSubscribed: boolean }) =>
      apiFetch(`/api/community-intel/feeds/${feedId}`, {
        method: "PATCH",
        body: JSON.stringify({ isSubscribed }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/feeds"] });
      toast({ title: "Feed subscription updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center py-12 text-muted-foreground">Loading feeds...</div>;
  }

  const feeds = data?.feeds || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Community Feeds</h3>
          <p className="text-sm text-muted-foreground">
            Subscribe to industry-specific and global threat intelligence feeds
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {feeds.map((feed) => (
          <Card key={feed.id}>
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <Rss className="h-4 w-4 text-muted-foreground" />
                  <CardTitle className="text-sm">{feed.feedName}</CardTitle>
                </div>
                <Badge variant="outline" className="capitalize text-xs">
                  {feed.feedType}
                </Badge>
              </div>
              {feed.description && <CardDescription className="text-xs mt-1">{feed.description}</CardDescription>}
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span>{feed.iocCount} IOCs</span>
                  <span>{feed.memberCount} members</span>
                  {feed.industrySector && (
                    <Badge variant="secondary" className="text-xs capitalize">
                      {feed.industrySector}
                    </Badge>
                  )}
                </div>
                <Button
                  size="sm"
                  variant={feed.isSubscribed ? "destructive" : "default"}
                  onClick={() =>
                    toggleMutation.mutate({
                      feedId: feed.id,
                      isSubscribed: !feed.isSubscribed,
                    })
                  }
                  disabled={toggleMutation.isPending}
                >
                  {feed.isSubscribed ? "Unsubscribe" : "Subscribe"}
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {feeds.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Rss className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No community feeds available yet.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── IOC Browser Tab ───────────────────────────────────────────────────────────

function IocBrowserTab() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  const { data, isLoading, error } = useQuery<{ iocs: SharedIoc[]; total: number }>({
    queryKey: ["/api/community-intel/iocs", search, typeFilter, severityFilter],
    queryFn: () =>
      apiFetch(
        `/api/community-intel/iocs?q=${encodeURIComponent(search)}&type=${typeFilter}&severity=${severityFilter}&limit=100`,
      ),
  });

  const notOptedIn = error instanceof Error && error.message.includes("not opted in");

  if (notOptedIn) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <Shield className="h-10 w-10 mx-auto mb-3 text-muted-foreground opacity-50" />
          <h3 className="text-lg font-medium mb-1">Not Participating</h3>
          <p className="text-sm text-muted-foreground">
            Your organization has not opted in to community intelligence. Go to the <strong>Preferences</strong> tab to
            enable sharing.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search IOCs by value, context, or threat actor..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="IOC Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="ip">IP Address</SelectItem>
            <SelectItem value="domain">Domain</SelectItem>
            <SelectItem value="url">URL</SelectItem>
            <SelectItem value="hash_sha256">SHA-256</SelectItem>
            <SelectItem value="hash_md5">MD5</SelectItem>
            <SelectItem value="email">Email</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* IOC List */}
      {isLoading ? (
        <div className="py-8 text-center text-muted-foreground">Loading IOCs...</div>
      ) : (
        <>
          <div className="text-xs text-muted-foreground">{data?.total ?? 0} IOCs found</div>
          <div className="space-y-2">
            {(data?.iocs || []).map((ioc) => (
              <Card key={ioc.id}>
                <CardContent className="py-3 px-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className="text-xs">
                          {iocTypeLabel(ioc.iocType)}
                        </Badge>
                        <Badge className={`text-xs ${severityBadge(ioc.severity)}`}>{ioc.severity}</Badge>
                        <Badge className={`text-xs ${tlpBadge(ioc.tlpLevel)}`}>TLP:{ioc.tlpLevel.toUpperCase()}</Badge>
                      </div>
                      <p className="font-mono text-sm truncate">{ioc.iocValue}</p>
                      {ioc.context && <p className="text-xs text-muted-foreground mt-1 truncate">{ioc.context}</p>}
                      <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Eye className="h-3 w-3" />
                          {ioc.sightingCount} sightings
                        </span>
                        <span>Confidence: {ioc.confidence}%</span>
                        <span>First: {formatDate(ioc.firstSeenAt)}</span>
                        <span>Last: {formatDate(ioc.lastSeenAt)}</span>
                      </div>
                      {ioc.tags && (ioc.tags as string[]).length > 0 && (
                        <div className="flex gap-1 mt-1">
                          {(ioc.tags as string[]).map((tag) => (
                            <Badge key={tag} variant="secondary" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    {ioc.threatActorRef && (
                      <Badge variant="outline" className="text-xs shrink-0">
                        {ioc.threatActorRef}
                      </Badge>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
          {(data?.iocs || []).length === 0 && (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <FileWarning className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No IOCs match your filters</p>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

// ── Campaigns Tab ─────────────────────────────────────────────────────────────

function CampaignsTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<{ campaigns: Campaign[]; total: number }>({
    queryKey: ["/api/community-intel/campaigns"],
    queryFn: () => apiFetch("/api/community-intel/campaigns"),
  });

  const correlateMutation = useMutation({
    mutationFn: () => apiFetch("/api/community-intel/correlate", { method: "POST" }),
    onSuccess: (res: { message: string }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/campaigns"] });
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/stats"] });
      toast({ title: "Correlation complete", description: res.message });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Threat Campaigns</h3>
          <p className="text-sm text-muted-foreground">
            Correlated attack campaigns detected across the community network
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => correlateMutation.mutate()}
          disabled={correlateMutation.isPending}
        >
          <RefreshCw className={`h-4 w-4 mr-1 ${correlateMutation.isPending ? "animate-spin" : ""}`} />
          Run Correlation
        </Button>
      </div>

      {isLoading ? (
        <div className="py-8 text-center text-muted-foreground">Loading campaigns...</div>
      ) : (
        <div className="space-y-3">
          {(data?.campaigns || []).map((c) => (
            <Card key={c.id}>
              <CardContent className="py-4 px-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Crosshair className="h-4 w-4 text-orange-400" />
                      <span className="font-medium text-sm">{c.campaignName}</span>
                      <Badge className={`text-xs ${severityBadge(c.severity)}`}>{c.severity}</Badge>
                      <Badge
                        variant="outline"
                        className={`text-xs ${
                          c.status === "active"
                            ? "text-green-400 border-green-500/30"
                            : c.status === "dormant"
                              ? "text-yellow-400 border-yellow-500/30"
                              : "text-slate-400"
                        }`}
                      >
                        {c.status}
                      </Badge>
                    </div>
                    {c.description && <p className="text-xs text-muted-foreground mt-1">{c.description}</p>}
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      {c.threatActorName && (
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" />
                          {c.threatActorName}
                        </span>
                      )}
                      <span>{c.iocCount} IOCs</span>
                      <span>{c.affectedOrgCount} affected orgs</span>
                      <span>First: {formatDate(c.firstSeenAt)}</span>
                    </div>
                    {c.targetSectors && (c.targetSectors as string[]).length > 0 && (
                      <div className="flex gap-1 mt-2">
                        {(c.targetSectors as string[]).map((s) => (
                          <Badge key={s} variant="secondary" className="text-xs capitalize">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}

          {(data?.campaigns || []).length === 0 && (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <Network className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No campaigns correlated yet. Click "Run Correlation" to analyze shared IOCs.</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ── Report IOC Tab ────────────────────────────────────────────────────────────

function ReportIocTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [iocType, setIocType] = useState("ip");
  const [iocValue, setIocValue] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [confidence, setConfidence] = useState("70");
  const [tlpLevel, setTlpLevel] = useState("amber");
  const [tags, setTags] = useState("");
  const [threatActorRef, setThreatActorRef] = useState("");
  const [context, setContext] = useState("");

  const reportMutation = useMutation({
    mutationFn: () =>
      apiFetch("/api/community-intel/iocs", {
        method: "POST",
        body: JSON.stringify({
          iocType,
          iocValue: iocValue.trim(),
          severity,
          confidence: parseInt(confidence) || 70,
          tlpLevel,
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          threatActorRef: threatActorRef || null,
          context: context || null,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/iocs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/community-intel/stats"] });
      queryClient.invalidateQueries({
        queryKey: ["/api/community-intel/my-contributions"],
      });
      toast({ title: "IOC shared with community" });
      setIocValue("");
      setTags("");
      setThreatActorRef("");
      setContext("");
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="max-w-2xl space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Plus className="h-5 w-5" />
            Report IOC
          </CardTitle>
          <CardDescription>
            Share a new indicator of compromise with the community network. Your organization identity will be
            anonymized.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>IOC Type</Label>
              <Select value={iocType} onValueChange={setIocType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP Address</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="hash_md5">MD5 Hash</SelectItem>
                  <SelectItem value="hash_sha1">SHA-1 Hash</SelectItem>
                  <SelectItem value="hash_sha256">SHA-256 Hash</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                  <SelectItem value="file_name">File Name</SelectItem>
                  <SelectItem value="cidr">CIDR Range</SelectItem>
                  <SelectItem value="certificate">Certificate</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="informational">Informational</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label>IOC Value</Label>
            <Input
              placeholder="e.g. 203.0.113.42, evil.example.com, d41d8cd98f..."
              value={iocValue}
              onChange={(e) => setIocValue(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Confidence (0-100)</Label>
              <Input
                type="number"
                min="0"
                max="100"
                value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>TLP Level</Label>
              <Select value={tlpLevel} onValueChange={setTlpLevel}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="white">TLP:WHITE — Unlimited sharing</SelectItem>
                  <SelectItem value="green">TLP:GREEN — Community sharing</SelectItem>
                  <SelectItem value="amber">TLP:AMBER — Limited sharing</SelectItem>
                  <SelectItem value="red">TLP:RED — Restricted</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Tags (comma-separated)</Label>
            <Input
              placeholder="ransomware, c2, phishing, apt, trojan"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label>Threat Actor Reference (optional)</Label>
            <Input
              placeholder="e.g. APT29, Lazarus Group, FIN7"
              value={threatActorRef}
              onChange={(e) => setThreatActorRef(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label>Context (optional)</Label>
            <Textarea
              placeholder="Describe where/how this IOC was observed (will be anonymized)..."
              value={context}
              onChange={(e) => setContext(e.target.value)}
              rows={3}
            />
          </div>

          <Button
            className="w-full"
            onClick={() => reportMutation.mutate()}
            disabled={reportMutation.isPending || !iocValue.trim()}
          >
            {reportMutation.isPending ? "Sharing..." : "Share IOC with Community"}
          </Button>
        </CardContent>
      </Card>

      {/* Recent Contributions */}
      <MyContributions />
    </div>
  );
}

function MyContributions() {
  const { data, isLoading } = useQuery<{
    contributions: SharedIoc[];
    total: number;
  }>({
    queryKey: ["/api/community-intel/my-contributions"],
    queryFn: () => apiFetch("/api/community-intel/my-contributions?limit=10"),
  });

  if (isLoading) return null;
  if (!data?.contributions?.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Your Recent Contributions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {data.contributions.map((ioc) => (
            <div key={ioc.id} className="flex items-center justify-between py-2 border-b last:border-0">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-xs">
                  {iocTypeLabel(ioc.iocType)}
                </Badge>
                <span className="font-mono text-xs truncate max-w-[300px]">{ioc.iocValue}</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>{ioc.sightingCount} sightings</span>
                <Badge className={`text-xs ${severityBadge(ioc.severity)}`}>{ioc.severity}</Badge>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CommunityIntelPage() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Network className="h-6 w-6" />
            Community Threat Intelligence
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Anonymous IOC sharing, industry-sector feeds, and threat campaign correlation across the SecureNexus network
          </p>
        </div>
      </div>

      <Tabs defaultValue="dashboard" className="space-y-4">
        <TabsList>
          <TabsTrigger value="dashboard" className="flex items-center gap-1">
            <Activity className="h-4 w-4" />
            Dashboard
          </TabsTrigger>
          <TabsTrigger value="preferences" className="flex items-center gap-1">
            <Share2 className="h-4 w-4" />
            Preferences
          </TabsTrigger>
          <TabsTrigger value="feeds" className="flex items-center gap-1">
            <Rss className="h-4 w-4" />
            Feeds
          </TabsTrigger>
          <TabsTrigger value="iocs" className="flex items-center gap-1">
            <Eye className="h-4 w-4" />
            IOC Browser
          </TabsTrigger>
          <TabsTrigger value="campaigns" className="flex items-center gap-1">
            <Crosshair className="h-4 w-4" />
            Campaigns
          </TabsTrigger>
          <TabsTrigger value="report" className="flex items-center gap-1">
            <Plus className="h-4 w-4" />
            Report IOC
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard">
          <DashboardTab />
        </TabsContent>
        <TabsContent value="preferences">
          <SharingPreferencesTab />
        </TabsContent>
        <TabsContent value="feeds">
          <CommunityFeedsTab />
        </TabsContent>
        <TabsContent value="iocs">
          <IocBrowserTab />
        </TabsContent>
        <TabsContent value="campaigns">
          <CampaignsTab />
        </TabsContent>
        <TabsContent value="report">
          <ReportIocTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
