import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchCsrfToken } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  Key,
  Server,
  AlertTriangle,
  Plus,
  Trash2,
  Power,
  PowerOff,
  Eye,
  Target,
  Wand2,
  Activity,
  Globe,
  Database,
  FileText,
  Mail,
  Link,
  Terminal,
  HardDrive,
  Network,
  MonitorSpeaker,
  Copy,
  Plug,
  MapPin,
  Gauge,
  Star,
  Clock,
  UserX,
  Usb,
  Bug,
  Crosshair,
  BarChart3,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { EmptyState } from "@/components/empty-state";
import { DetailPageSkeleton } from "@/components/page-skeleton";

const TOKEN_TYPE_LABELS: Record<string, { label: string; icon: typeof Key; description: string }> = {
  aws_key: { label: "AWS Credentials", icon: Key, description: "Fake AWS access key + secret" },
  database_credential: { label: "Database Credential", icon: Database, description: "Fake DB connection string" },
  api_key: { label: "API Key", icon: Key, description: "Fake API key (sk-...)" },
  document: { label: "Document Tracker", icon: FileText, description: "Tracking pixel in documents" },
  email_pixel: { label: "Email Pixel", icon: Mail, description: "1x1 tracking pixel for emails" },
  dns_token: { label: "DNS Token", icon: Globe, description: "Canary DNS subdomain" },
  url_token: { label: "URL Token", icon: Link, description: "Canary URL endpoint" },
  kubeconfig: { label: "Kubeconfig", icon: Terminal, description: "Fake Kubernetes config" },
  ssh_key: { label: "SSH Key", icon: Key, description: "Fake SSH private key" },
  slack_webhook: { label: "Slack Webhook", icon: Link, description: "Fake Slack webhook URL" },
  // 54.4 — New canary token types
  usb_canary: { label: "USB Canary", icon: Usb, description: "Triggers on USB mount/autorun" },
  web_bug: { label: "Web Bug", icon: Bug, description: "Invisible tracking in web pages" },
  document_canary: { label: "Document Canary", icon: FileText, description: "Macro-based phone-home in Office/PDF" },
  email_canary: { label: "Email Canary", icon: Mail, description: "Full email with open/click/reply tracking" },
};

const ASSET_TYPE_LABELS: Record<string, { label: string; icon: typeof Server; description: string }> = {
  honey_account: { label: "Honey Account", icon: Shield, description: "Fake AD/LDAP user account" },
  honeypot_endpoint: { label: "Honeypot Endpoint", icon: Server, description: "Fake internal service" },
  deception_fileshare: { label: "Deception Fileshare", icon: HardDrive, description: "Fake sensitive directory" },
  network_decoy: { label: "Network Decoy", icon: Network, description: "Fake host on network" },
  fake_rdp: { label: "Fake RDP", icon: MonitorSpeaker, description: "Fake Remote Desktop" },
  fake_ssh: { label: "Fake SSH", icon: Terminal, description: "Fake SSH server" },
  fake_admin_panel: { label: "Fake Admin Panel", icon: Shield, description: "Fake admin dashboard" },
  fake_database: { label: "Fake Database", icon: Database, description: "Fake database service" },
};

const DEPLOY_TARGET_LABELS: Record<string, string> = {
  s3_bucket: "S3 Bucket",
  github_repo: "GitHub Repository",
  email: "Email",
  shared_drive: "Shared Drive",
  active_directory: "Active Directory",
  kubernetes: "Kubernetes",
  ci_cd_pipeline: "CI/CD Pipeline",
  internal_wiki: "Internal Wiki",
};

async function apiRequest(url: string, options?: RequestInit) {
  const method = options?.method?.toUpperCase() ?? "GET";
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (method !== "GET" && method !== "HEAD") {
    const csrfToken = await fetchCsrfToken();
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const msg = body?.errors?.[0]?.message || body.message || `Request failed: ${res.status}`;
    throw new Error(msg);
  }
  const json = await res.json();
  // Unwrap envelope middleware { data, meta, errors } shape
  if (json && typeof json === "object" && "data" in json && "meta" in json) {
    return json.data;
  }
  return json;
}

export default function DeceptionPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState("overview");

  // Queries
  const { data: stats, isLoading } = useQuery({
    queryKey: ["/api/deception/stats"],
    queryFn: () => apiRequest("/api/deception/stats"),
  });

  const { data: tokensData } = useQuery({
    queryKey: ["/api/deception/canary-tokens"],
    queryFn: () => apiRequest("/api/deception/canary-tokens"),
  });

  const { data: assetsData } = useQuery({
    queryKey: ["/api/deception/honeypot-assets"],
    queryFn: () => apiRequest("/api/deception/honeypot-assets"),
  });

  const { data: hitsData } = useQuery({
    queryKey: ["/api/deception/hits"],
    queryFn: () => apiRequest("/api/deception/hits"),
  });

  const tokens = tokensData?.tokens || [];
  const assets = assetsData?.assets || [];
  const hits = hitsData?.hits || [];

  if (isLoading) return <DetailPageSkeleton />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Deception Technology</h1>
          <p className="text-muted-foreground">
            Zero false positive detection — canary tokens, honeypots, and network decoys
          </p>
        </div>
        <div className="flex gap-2">
          <DeployWizardDialog />
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="canary-tokens">
            Canary Tokens
            {tokens.length > 0 && (
              <Badge variant="secondary" className="ml-2 text-xs">
                {tokens.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="honeypots">
            Honeypots
            {assets.length > 0 && (
              <Badge variant="secondary" className="ml-2 text-xs">
                {assets.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="hits">
            Hits
            {hits.length > 0 && (
              <Badge variant="destructive" className="ml-2 text-xs">
                {hits.length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <StatsCards stats={stats} />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <RecentHitsCard hits={hits.slice(0, 5)} />
            <DeceptionCoverageCard tokens={tokens} assets={assets} />
          </div>
        </TabsContent>

        <TabsContent value="canary-tokens" className="space-y-4">
          <CanaryTokensSection tokens={tokens} />
        </TabsContent>

        <TabsContent value="honeypots" className="space-y-4">
          <HoneypotAssetsSection assets={assets} />
        </TabsContent>

        <TabsContent value="hits" className="space-y-4">
          <DeceptionHitsSection hits={hits} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// =========================================================================
// STATS CARDS
// =========================================================================

function StatsCards({ stats }: { stats: Record<string, number | unknown[]> | undefined }) {
  const cards = [
    {
      title: "Active Tokens",
      value: stats?.activeTokens ?? 0,
      subtitle: `${stats?.totalTokens ?? 0} total deployed`,
      icon: Key,
      color: "text-blue-500",
    },
    {
      title: "Active Honeypots",
      value: stats?.activeAssets ?? 0,
      subtitle: `${stats?.totalAssets ?? 0} total deployed`,
      icon: Server,
      color: "text-purple-500",
    },
    {
      title: "Total Hits",
      value: stats?.totalHits ?? 0,
      subtitle: `${stats?.recentHits24h ?? 0} in last 24h`,
      icon: AlertTriangle,
      color: "text-red-500",
    },
    {
      title: "False Positive Rate",
      value: "0%",
      subtitle: "Every deception hit is real",
      icon: Target,
      color: "text-emerald-500",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <Card key={card.title}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">{card.title}</p>
                <p className="text-2xl font-bold">{String(card.value)}</p>
                <p className="text-xs text-muted-foreground mt-1">{card.subtitle}</p>
              </div>
              <card.icon className={`h-8 w-8 ${card.color} opacity-80`} />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// =========================================================================
// RECENT HITS CARD
// =========================================================================

function RecentHitsCard({ hits }: { hits: Array<Record<string, unknown>> }) {
  if (hits.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recent Hits</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={Shield}
            title="No deception hits detected yet"
            description="Deploy canary tokens and honeypots across your environment. When an attacker interacts with them, hits will appear here with full attribution."
            compact
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Recent Hits</CardTitle>
        <CardDescription>Latest deception triggers — all confirmed true positives</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {hits.map((hit) => (
            <div key={String(hit.id)} className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <AlertTriangle
                  className={`h-4 w-4 ${hit.severity === "critical" ? "text-red-500" : "text-orange-500"}`}
                />
                <div>
                  <p className="text-sm font-medium">{String(hit.sourceName || "Unknown")}</p>
                  <p className="text-xs text-muted-foreground">
                    {String(hit.sourceIp || "Unknown IP")} — {String(hit.sourceType || "")}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <SeverityBadge severity={String(hit.severity)} />
                <p className="text-xs text-muted-foreground mt-1">
                  {hit.hitAt ? new Date(String(hit.hitAt)).toLocaleString() : ""}
                </p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// =========================================================================
// DECEPTION COVERAGE CARD
// =========================================================================

// 54.1 — Network segment constants for coverage gap analysis
const NETWORK_SEGMENTS = [
  { id: "corporate_lan", label: "Corporate LAN", icon: Network },
  { id: "dmz", label: "DMZ", icon: Shield },
  { id: "cloud_aws", label: "AWS Cloud", icon: Globe },
  { id: "cloud_azure", label: "Azure Cloud", icon: Globe },
  { id: "ci_cd", label: "CI/CD Pipeline", icon: Activity },
  { id: "active_directory", label: "Active Directory", icon: Key },
  { id: "developer_env", label: "Developer Env", icon: Terminal },
  { id: "database_tier", label: "Database Tier", icon: Database },
  { id: "file_servers", label: "File Servers", icon: HardDrive },
  { id: "email_system", label: "Email System", icon: Mail },
];

function DeceptionCoverageCard({
  tokens,
  assets,
}: {
  tokens: Array<Record<string, unknown>>;
  assets: Array<Record<string, unknown>>;
}) {
  const tokenTypes = new Set(tokens.map((t) => String(t.tokenType)));
  const assetTypes = new Set(assets.map((a) => String(a.assetType)));

  // 54.1 — Build segment coverage from deployment targets
  const deployedSegments = new Set<string>();
  tokens.forEach((t) => {
    if (t.deployedTo) deployedSegments.add(String(t.deployedTo));
  });
  assets.forEach((a) => {
    if (a.decoyHostname) deployedSegments.add("corporate_lan");
    if (a.listenAddress) deployedSegments.add("corporate_lan");
  });
  // Map deployment targets to segments
  const targetToSegment: Record<string, string> = {
    s3_bucket: "cloud_aws",
    github_repo: "developer_env",
    email: "email_system",
    shared_drive: "file_servers",
    active_directory: "active_directory",
    kubernetes: "ci_cd",
    ci_cd_pipeline: "ci_cd",
    internal_wiki: "corporate_lan",
  };
  tokens.forEach((t) => {
    const seg = targetToSegment[String(t.deployedTo || "")];
    if (seg) deployedSegments.add(seg);
  });

  const coveredCount = NETWORK_SEGMENTS.filter((s) => deployedSegments.has(s.id)).length;
  const gapCount = NETWORK_SEGMENTS.length - coveredCount;
  const coveragePct = NETWORK_SEGMENTS.length > 0 ? Math.round((coveredCount / NETWORK_SEGMENTS.length) * 100) : 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <MapPin className="h-4 w-4" />
          Deception Coverage Map
        </CardTitle>
        <CardDescription>
          {coveragePct}% network coverage — {coveredCount} segments covered, {gapCount} gaps
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Network Segment Coverage Grid */}
          <div>
            <p className="text-sm font-medium mb-2">Network Segment Coverage</p>
            <div className="grid grid-cols-2 gap-2">
              {NETWORK_SEGMENTS.map((seg) => {
                const covered = deployedSegments.has(seg.id);
                const SegIcon = seg.icon;
                return (
                  <div
                    key={seg.id}
                    className={`flex items-center gap-2 rounded border p-2 text-xs ${
                      covered ? "bg-emerald-500/10 border-emerald-500/30" : "bg-red-500/5 border-red-500/20 opacity-70"
                    }`}
                  >
                    <SegIcon className={`h-3.5 w-3.5 ${covered ? "text-emerald-500" : "text-red-400"}`} />
                    <span className={covered ? "" : "text-muted-foreground"}>{seg.label}</span>
                    {covered ? (
                      <Badge variant="secondary" className="ml-auto text-[10px]">
                        Covered
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="ml-auto text-[10px] border-red-500/30 text-red-400">
                        Gap
                      </Badge>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Coverage progress bar */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="text-muted-foreground">Overall Coverage</span>
              <span className="font-medium">{coveragePct}%</span>
            </div>
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className={`h-full rounded-full ${coveragePct >= 80 ? "bg-emerald-500" : coveragePct >= 50 ? "bg-amber-500" : "bg-red-500"}`}
                style={{ width: `${coveragePct}%` }}
              />
            </div>
          </div>

          {/* Token & Asset type coverage (original) */}
          <div>
            <p className="text-sm font-medium mb-2">Canary Token Types</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(TOKEN_TYPE_LABELS).map(([type, { label }]) => (
                <Badge
                  key={type}
                  variant={tokenTypes.has(type) ? "default" : "outline"}
                  className={tokenTypes.has(type) ? "" : "opacity-40"}
                >
                  {label}
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <p className="text-sm font-medium mb-2">Honeypot Types</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(ASSET_TYPE_LABELS).map(([type, { label }]) => (
                <Badge
                  key={type}
                  variant={assetTypes.has(type) ? "default" : "outline"}
                  className={assetTypes.has(type) ? "" : "opacity-40"}
                >
                  {label}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// =========================================================================
// CANARY TOKENS SECTION
// =========================================================================

function CanaryTokensSection({ tokens }: { tokens: Array<Record<string, unknown>> }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/deception/canary-tokens/${id}/toggle`, { method: "PATCH" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/canary-tokens"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/deception/canary-tokens/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/canary-tokens"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      toast({ title: "Token deleted" });
    },
  });

  const simulateMutation = useMutation({
    mutationFn: (canaryTokenId: string) =>
      apiRequest("/api/deception/simulate-hit", {
        method: "POST",
        body: JSON.stringify({ canaryTokenId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/hits"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/canary-tokens"] });
      toast({ title: "Hit simulated — check Hits tab" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Canary Tokens</h3>
        <CreateTokenDialog />
      </div>

      {tokens.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState
              icon={Key}
              title="No canary tokens deployed"
              description="Canary tokens are fake credentials (AWS keys, API tokens, DB strings) that trigger an alert the moment an attacker uses them. Deploy them across your environment for zero-noise intrusion detection."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {tokens.map((token) => {
            const typeInfo = TOKEN_TYPE_LABELS[String(token.tokenType)] || {
              label: String(token.tokenType),
              icon: Key,
              description: "",
            };
            const Icon = typeInfo.icon;
            const isActive = token.isActive === true;

            return (
              <Card key={String(token.id)} className={!isActive ? "opacity-60" : ""}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <Icon className="h-5 w-5 text-blue-500 mt-0.5" />
                      <div>
                        <p className="font-medium">{String(token.name)}</p>
                        <p className="text-xs text-muted-foreground">{typeInfo.label}</p>
                        {token.description ? (
                          <p className="text-xs text-muted-foreground mt-1">{String(token.description)}</p>
                        ) : null}
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <Badge variant={isActive ? "default" : "secondary"}>{isActive ? "Active" : "Disabled"}</Badge>
                    </div>
                  </div>

                  {/* 54.3 — Decoy authenticity scoring */}
                  <div className="mt-3 grid grid-cols-4 gap-2 text-center">
                    <div>
                      <p className="text-lg font-bold">{String(token.hitCount || 0)}</p>
                      <p className="text-xs text-muted-foreground">Hits</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium truncate">
                        {token.deployedTo ? String(token.deployedTo).replace(/_/g, " ") : "Not deployed"}
                      </p>
                      <p className="text-xs text-muted-foreground">Target</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium">
                        {token.createdAt ? new Date(String(token.createdAt)).toLocaleDateString() : "—"}
                      </p>
                      <p className="text-xs text-muted-foreground">Created</p>
                    </div>
                    <div>
                      {(() => {
                        const hits = Number(token.hitCount || 0);
                        const deployed = token.deployedTo ? 1 : 0;
                        const hasDesc = token.description ? 1 : 0;
                        // Authenticity score: 0-100 based on completeness + interaction
                        const baseScore = deployed * 30 + (hasDesc ? 20 : 0) + Math.min(hits * 10, 50);
                        const score = Math.min(baseScore, 100);
                        const color =
                          score >= 70 ? "text-emerald-500" : score >= 40 ? "text-amber-500" : "text-red-400";
                        return (
                          <>
                            <p className={`text-lg font-bold ${color}`}>{score}</p>
                            <p className="text-xs text-muted-foreground">Authenticity</p>
                          </>
                        );
                      })()}
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => toggleMutation.mutate(String(token.id))}
                      disabled={toggleMutation.isPending}
                    >
                      {isActive ? <PowerOff className="h-3 w-3 mr-1" /> : <Power className="h-3 w-3 mr-1" />}
                      {isActive ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => simulateMutation.mutate(String(token.id))}
                      disabled={simulateMutation.isPending}
                    >
                      <Activity className="h-3 w-3 mr-1" />
                      Test
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => deleteMutation.mutate(String(token.id))}
                      disabled={deleteMutation.isPending}
                      className="ml-auto"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// =========================================================================
// HONEYPOT ASSETS SECTION
// =========================================================================

function HoneypotAssetsSection({ assets }: { assets: Array<Record<string, unknown>> }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/deception/honeypot-assets/${id}/toggle`, { method: "PATCH" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/honeypot-assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest(`/api/deception/honeypot-assets/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/honeypot-assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      toast({ title: "Asset deleted" });
    },
  });

  const simulateMutation = useMutation({
    mutationFn: (honeypotAssetId: string) =>
      apiRequest("/api/deception/simulate-hit", {
        method: "POST",
        body: JSON.stringify({ honeypotAssetId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/hits"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/honeypot-assets"] });
      toast({ title: "Hit simulated — check Hits tab" });
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Honeypot Assets</h3>
        <CreateHoneypotDialog />
      </div>

      {assets.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState
              icon={Server}
              title="No honeypot assets deployed"
              description="Honeypots are decoy services (SSH, RDP, databases, file shares) that look real to attackers. Any interaction is a confirmed true positive — no false alarms."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {assets.map((asset) => {
            const typeInfo = ASSET_TYPE_LABELS[String(asset.assetType)] || {
              label: String(asset.assetType),
              icon: Server,
              description: "",
            };
            const Icon = typeInfo.icon;
            const isActive = asset.isActive === true;

            return (
              <Card key={String(asset.id)} className={!isActive ? "opacity-60" : ""}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <Icon className="h-5 w-5 text-purple-500 mt-0.5" />
                      <div>
                        <p className="font-medium">{String(asset.name)}</p>
                        <p className="text-xs text-muted-foreground">{typeInfo.label}</p>
                        {asset.description ? (
                          <p className="text-xs text-muted-foreground mt-1">{String(asset.description)}</p>
                        ) : null}
                      </div>
                    </div>
                    <Badge variant={isActive ? "default" : "secondary"}>{isActive ? "Active" : "Disabled"}</Badge>
                  </div>

                  <div className="mt-3 space-y-1 text-xs text-muted-foreground">
                    {asset.fakeUsername ? <p>Username: {String(asset.fakeUsername)}</p> : null}
                    {asset.listenAddress ? <p>Address: {String(asset.listenAddress)}</p> : null}
                    {asset.sharePath ? <p>Path: {String(asset.sharePath)}</p> : null}
                    {asset.decoyHostname ? <p>Hostname: {String(asset.decoyHostname)}</p> : null}
                    {asset.protocol ? <p>Protocol: {String(asset.protocol).toUpperCase()}</p> : null}
                  </div>

                  {/* 54.3 — Decoy authenticity scoring for honeypots */}
                  <div className="mt-3 pt-2 border-t">
                    <div className="flex items-center gap-4 mb-2">
                      <span className="text-sm">
                        <span className="font-bold">{String(asset.hitCount || 0)}</span>{" "}
                        <span className="text-muted-foreground">hits</span>
                      </span>
                      {(() => {
                        const hits = Number(asset.hitCount || 0);
                        const hasAddr = asset.listenAddress || asset.decoyHostname ? 1 : 0;
                        const hasProto = asset.protocol ? 1 : 0;
                        const hasDesc = asset.description ? 1 : 0;
                        const baseScore =
                          hasAddr * 25 + (hasProto ? 15 : 0) + (hasDesc ? 10 : 0) + Math.min(hits * 10, 50);
                        const score = Math.min(baseScore, 100);
                        const color =
                          score >= 70 ? "text-emerald-500" : score >= 40 ? "text-amber-500" : "text-red-400";
                        const tip =
                          score < 40
                            ? "Low authenticity — not attractive enough to attackers"
                            : score < 70
                              ? "Moderate authenticity — consider adding more detail"
                              : "High authenticity — convincing decoy";
                        return (
                          <span className="text-xs flex items-center gap-1" title={tip}>
                            <Star className={`h-3 w-3 ${color}`} />
                            <span className={color}>{score}/100</span>
                            <span className="text-muted-foreground">authenticity</span>
                          </span>
                        );
                      })()}
                    </div>
                  </div>
                  <div className="mt-1 flex items-center justify-between">
                    <span />
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="outline" onClick={() => toggleMutation.mutate(String(asset.id))}>
                        {isActive ? <PowerOff className="h-3 w-3 mr-1" /> : <Power className="h-3 w-3 mr-1" />}
                        {isActive ? "Disable" : "Enable"}
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => simulateMutation.mutate(String(asset.id))}>
                        <Activity className="h-3 w-3 mr-1" />
                        Test
                      </Button>
                      <Button size="sm" variant="destructive" onClick={() => deleteMutation.mutate(String(asset.id))}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
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
}

// =========================================================================
// DECEPTION HITS SECTION
// =========================================================================

// 54.2 — Alert drill-down for deception triggers
function DeceptionHitsSection({ hits }: { hits: Array<Record<string, unknown>> }) {
  const [expandedHit, setExpandedHit] = useState<string | null>(null);

  if (hits.length === 0) {
    return (
      <Card>
        <CardContent>
          <EmptyState
            icon={Target}
            title="No deception hits recorded"
            description="Hits appear when attackers interact with your canary tokens or honeypots. Deploy deception assets from the Canary Tokens or Honeypots tabs to start detecting intrusions."
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">
        Deception Hits
        <span className="text-sm text-muted-foreground font-normal ml-2">
          100% true positive rate — every hit is confirmed malicious activity
        </span>
      </h3>

      <div className="space-y-3">
        {hits.map((hit) => {
          const hitId = String(hit.id);
          const isExpanded = expandedHit === hitId;
          const hitTime = hit.hitAt ? new Date(String(hit.hitAt)) : null;

          return (
            <Card
              key={hitId}
              className={`cursor-pointer transition-all ${isExpanded ? "ring-1 ring-primary/30" : ""}`}
              onClick={() => setExpandedHit(isExpanded ? null : hitId)}
            >
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <AlertTriangle
                      className={`h-5 w-5 mt-0.5 ${hit.severity === "critical" ? "text-red-500" : "text-orange-500"}`}
                    />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{String(hit.sourceName || "Unknown Source")}</p>
                        <SeverityBadge severity={String(hit.severity)} />
                        {hit.isInternal === true && (
                          <Badge variant="destructive" className="text-xs">
                            INTERNAL
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {String(hit.sourceType || "")
                          .replace(":", " — ")
                          .replace(/_/g, " ")}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="text-right text-sm text-muted-foreground">
                      {hitTime ? hitTime.toLocaleString() : ""}
                    </div>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>
                </div>

                <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground">Source IP</p>
                    <p className="font-mono">{String(hit.sourceIp || "—")}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Hostname</p>
                    <p className="truncate">{String(hit.sourceHostname || "—")}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Method</p>
                    <p className="font-mono">{String(hit.httpMethod || "—")}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">User Agent</p>
                    <p className="truncate text-xs">{String(hit.sourceUserAgent || "—")}</p>
                  </div>
                </div>

                {/* 54.2 — Expanded drill-down panel */}
                {isExpanded && (
                  <div className="mt-4 pt-4 border-t space-y-4">
                    {/* Who / What triggered */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <p className="text-xs font-semibold uppercase text-muted-foreground">Who / What Triggered</p>
                        <div className="rounded border p-3 space-y-1 text-sm">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Source Name</span>
                            <span className="font-mono">{String(hit.sourceName || "Unknown")}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">IP Address</span>
                            <span className="font-mono">{String(hit.sourceIp || "—")}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Hostname</span>
                            <span className="font-mono">{String(hit.sourceHostname || "—")}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Internal Actor</span>
                            <span>{hit.isInternal === true ? "Yes (insider threat)" : "External"}</span>
                          </div>
                        </div>
                      </div>

                      {/* Action Taken */}
                      <div className="space-y-2">
                        <p className="text-xs font-semibold uppercase text-muted-foreground">Action Details</p>
                        <div className="rounded border p-3 space-y-1 text-sm">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">HTTP Method</span>
                            <span className="font-mono">{String(hit.httpMethod || "N/A")}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Request Path</span>
                            <span className="font-mono truncate max-w-[200px]">
                              {String(hit.httpPath || hit.requestUrl || "—")}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">User Agent</span>
                            <span className="truncate max-w-[200px] text-xs">{String(hit.sourceUserAgent || "—")}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Source Type</span>
                            <span>{String(hit.sourceType || "—").replace(/_/g, " ")}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Timeline */}
                    <div className="space-y-2">
                      <p className="text-xs font-semibold uppercase text-muted-foreground">Activity Timeline</p>
                      <div className="rounded border p-3">
                        <div className="flex items-center gap-3 text-xs">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3 text-muted-foreground" />
                            <span className="text-muted-foreground">Hit detected:</span>
                            <span className="font-medium">{hitTime ? hitTime.toLocaleString() : "Unknown"}</span>
                          </div>
                          {hit.alertId ? (
                            <div className="flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3 text-amber-500" />
                              <span className="text-muted-foreground">Alert created:</span>
                              <span className="font-mono">{String(hit.alertId).slice(0, 8)}</span>
                            </div>
                          ) : null}
                        </div>
                      </div>
                    </div>

                    {/* Recommended Response */}
                    <div className="space-y-2">
                      <p className="text-xs font-semibold uppercase text-muted-foreground">Recommended Response</p>
                      <div className="rounded bg-amber-500/10 border border-amber-500/20 p-3 text-sm space-y-1">
                        {hit.severity === "critical" ? (
                          <>
                            <p>1. Immediately isolate source IP {String(hit.sourceIp || "")} from the network</p>
                            <p>2. Check if the source host is compromised — run endpoint forensics</p>
                            <p>3. Rotate any real credentials near the triggered canary</p>
                            <p>4. Escalate to incident response team</p>
                          </>
                        ) : (
                          <>
                            <p>1. Investigate source {String(hit.sourceIp || "")} for suspicious activity</p>
                            <p>2. Check if this is an authorized security scan or pentest</p>
                            <p>3. Review adjacent logs for lateral movement indicators</p>
                            <p>4. Update canary placement if repeatedly triggered by scans</p>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {hit.alertId && !isExpanded ? (
                  <div className="mt-2 text-xs text-muted-foreground">
                    Alert created: <span className="font-mono">{String(hit.alertId)}</span>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// =========================================================================
// CREATE TOKEN DIALOG
// =========================================================================

function CreateTokenDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tokenType, setTokenType] = useState("");
  const [deploymentTarget, setDeploymentTarget] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      apiRequest("/api/deception/canary-tokens", {
        method: "POST",
        body: JSON.stringify({ name, description, tokenType, deploymentTarget: deploymentTarget || undefined }),
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/canary-tokens"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      toast({ title: "Canary token created" });
      setOpen(false);
      setName("");
      setDescription("");
      setTokenType("");
      setDeploymentTarget("");
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="h-4 w-4 mr-1" />
          Create Token
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Canary Token</DialogTitle>
          <DialogDescription>Generate a fake credential that alerts you when accessed</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Production DB Canary" />
          </div>
          <div>
            <Label>Description</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Where this token will be planted..."
              rows={2}
            />
          </div>
          <div>
            <Label>Token Type</Label>
            <Select value={tokenType} onValueChange={setTokenType}>
              <SelectTrigger>
                <SelectValue placeholder="Select type..." />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(TOKEN_TYPE_LABELS).map(([value, { label, description }]) => (
                  <SelectItem key={value} value={value}>
                    <div>
                      <span>{label}</span>
                      <span className="text-xs text-muted-foreground ml-2">— {description}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Deployment Target (optional)</Label>
            <Select value={deploymentTarget} onValueChange={setDeploymentTarget}>
              <SelectTrigger>
                <SelectValue placeholder="Select target..." />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(DEPLOY_TARGET_LABELS).map(([value, label]) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button
            onClick={() => mutation.mutate()}
            disabled={!name || !tokenType || mutation.isPending}
            className="w-full"
          >
            {mutation.isPending ? "Creating..." : "Create Canary Token"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// =========================================================================
// CREATE HONEYPOT DIALOG
// =========================================================================

function CreateHoneypotDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [assetType, setAssetType] = useState("");
  const [fakeUsername, setFakeUsername] = useState("");
  const [fakeEmail, setFakeEmail] = useState("");
  const [listenAddress, setListenAddress] = useState("");
  const [protocol, setProtocol] = useState("");
  const [sharePath, setSharePath] = useState("");
  const [decoyHostname, setDecoyHostname] = useState("");
  const [decoyIp, setDecoyIp] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      apiRequest("/api/deception/honeypot-assets", {
        method: "POST",
        body: JSON.stringify({
          name,
          description,
          assetType,
          fakeUsername: fakeUsername || undefined,
          fakeEmail: fakeEmail || undefined,
          listenAddress: listenAddress || undefined,
          protocol: protocol || undefined,
          sharePath: sharePath || undefined,
          decoyHostname: decoyHostname || undefined,
          decoyIp: decoyIp || undefined,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/honeypot-assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      toast({ title: "Honeypot asset created" });
      setOpen(false);
      setName("");
      setDescription("");
      setAssetType("");
      setFakeUsername("");
      setFakeEmail("");
      setListenAddress("");
      setProtocol("");
      setSharePath("");
      setDecoyHostname("");
      setDecoyIp("");
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const showAccountFields = assetType === "honey_account";
  const showEndpointFields = [
    "honeypot_endpoint",
    "fake_rdp",
    "fake_ssh",
    "fake_admin_panel",
    "fake_database",
  ].includes(assetType);
  const showShareFields = assetType === "deception_fileshare";
  const showDecoyFields = assetType === "network_decoy";

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="h-4 w-4 mr-1" />
          Create Honeypot
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create Honeypot Asset</DialogTitle>
          <DialogDescription>Deploy a fake service or account that alerts on any interaction</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Fake Domain Admin" />
          </div>
          <div>
            <Label>Description</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Purpose of this honeypot..."
              rows={2}
            />
          </div>
          <div>
            <Label>Asset Type</Label>
            <Select value={assetType} onValueChange={setAssetType}>
              <SelectTrigger>
                <SelectValue placeholder="Select type..." />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(ASSET_TYPE_LABELS).map(([value, { label, description }]) => (
                  <SelectItem key={value} value={value}>
                    <div>
                      <span>{label}</span>
                      <span className="text-xs text-muted-foreground ml-2">— {description}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {showAccountFields && (
            <>
              <div>
                <Label>Fake Username</Label>
                <Input
                  value={fakeUsername}
                  onChange={(e) => setFakeUsername(e.target.value)}
                  placeholder="e.g., svc_backup_admin"
                />
              </div>
              <div>
                <Label>Fake Email</Label>
                <Input
                  value={fakeEmail}
                  onChange={(e) => setFakeEmail(e.target.value)}
                  placeholder="e.g., backup.admin@corp.local"
                />
              </div>
            </>
          )}

          {showEndpointFields && (
            <>
              <div>
                <Label>Listen Address</Label>
                <Input
                  value={listenAddress}
                  onChange={(e) => setListenAddress(e.target.value)}
                  placeholder="e.g., 10.0.0.50:3389"
                />
              </div>
              <div>
                <Label>Protocol</Label>
                <Select value={protocol} onValueChange={setProtocol}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select protocol..." />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="rdp">RDP</SelectItem>
                    <SelectItem value="ssh">SSH</SelectItem>
                    <SelectItem value="http">HTTP</SelectItem>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="smb">SMB</SelectItem>
                    <SelectItem value="mysql">MySQL</SelectItem>
                    <SelectItem value="postgres">PostgreSQL</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </>
          )}

          {showShareFields && (
            <div>
              <Label>Share Path</Label>
              <Input
                value={sharePath}
                onChange={(e) => setSharePath(e.target.value)}
                placeholder="e.g., \\\\fileserver\\executive-salaries"
              />
            </div>
          )}

          {showDecoyFields && (
            <>
              <div>
                <Label>Decoy Hostname</Label>
                <Input
                  value={decoyHostname}
                  onChange={(e) => setDecoyHostname(e.target.value)}
                  placeholder="e.g., dc03.corp.local"
                />
              </div>
              <div>
                <Label>Decoy IP</Label>
                <Input value={decoyIp} onChange={(e) => setDecoyIp(e.target.value)} placeholder="e.g., 10.0.0.100" />
              </div>
            </>
          )}

          <Button
            onClick={() => mutation.mutate()}
            disabled={!name || !assetType || mutation.isPending}
            className="w-full"
          >
            {mutation.isPending ? "Creating..." : "Create Honeypot Asset"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// =========================================================================
// DEPLOY WIZARD DIALOG
// =========================================================================

function DeployWizardDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tokenType, setTokenType] = useState("");
  const [deploymentTarget, setDeploymentTarget] = useState("");
  const [result, setResult] = useState<{
    token: Record<string, unknown>;
    deploymentInstructions: string;
    steps: string[];
  } | null>(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      apiRequest("/api/deception/deploy-wizard", {
        method: "POST",
        body: JSON.stringify({ name, description, tokenType, deploymentTarget }),
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/deception/canary-tokens"] });
      queryClient.invalidateQueries({ queryKey: ["/api/deception/stats"] });
      setResult(data);
      toast({ title: "Token generated — follow deployment steps" });
    },
    onError: (err: Error) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const handleClose = () => {
    setOpen(false);
    setResult(null);
    setName("");
    setDescription("");
    setTokenType("");
    setDeploymentTarget("");
  };

  return (
    <Dialog open={open} onOpenChange={(v) => (v ? setOpen(true) : handleClose())}>
      <DialogTrigger asChild>
        <Button>
          <Wand2 className="h-4 w-4 mr-2" />
          Deploy Wizard
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Token Deployment Wizard</DialogTitle>
          <DialogDescription>
            One-click deploy canary tokens into S3 buckets, GitHub repos, email, and more
          </DialogDescription>
        </DialogHeader>

        {!result ? (
          <div className="space-y-4">
            <div>
              <Label>Token Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., S3 AWS Key Canary" />
            </div>
            <div>
              <Label>Description</Label>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Purpose and location..."
                rows={2}
              />
            </div>
            <div>
              <Label>Token Type</Label>
              <Select value={tokenType} onValueChange={setTokenType}>
                <SelectTrigger>
                  <SelectValue placeholder="What kind of bait?" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(TOKEN_TYPE_LABELS).map(([value, { label, description }]) => (
                    <SelectItem key={value} value={value}>
                      {label} — {description}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Deployment Target</Label>
              <Select value={deploymentTarget} onValueChange={setDeploymentTarget}>
                <SelectTrigger>
                  <SelectValue placeholder="Where to plant it?" />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(DEPLOY_TARGET_LABELS).map(([value, label]) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={() => mutation.mutate()}
              disabled={!name || !tokenType || !deploymentTarget || mutation.isPending}
              className="w-full"
            >
              <Wand2 className="h-4 w-4 mr-2" />
              {mutation.isPending ? "Generating..." : "Generate & Deploy"}
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4">
              <p className="text-sm font-medium text-emerald-600">Token generated successfully</p>
              <p className="text-xs text-muted-foreground mt-1">
                Follow the deployment steps below to plant the canary
              </p>
            </div>

            <div>
              <p className="text-sm font-medium mb-2">Deployment Steps</p>
              <div className="space-y-2">
                {result.steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <span className="bg-primary text-primary-foreground rounded-full w-5 h-5 flex items-center justify-center text-xs flex-shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <p className="text-sm font-medium mb-2">Deployment Instructions</p>
              <pre className="bg-muted p-3 rounded-lg text-xs overflow-x-auto whitespace-pre-wrap">
                {result.deploymentInstructions}
              </pre>
              <Button
                size="sm"
                variant="outline"
                className="mt-2"
                onClick={() => {
                  navigator.clipboard.writeText(result.deploymentInstructions);
                  toast({ title: "Copied to clipboard" });
                }}
              >
                <Copy className="h-3 w-3 mr-1" />
                Copy Instructions
              </Button>
            </div>

            <Button onClick={handleClose} variant="outline" className="w-full">
              Done
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// =========================================================================
// SEVERITY BADGE
// =========================================================================

function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  };

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${variants[severity] || variants.high}`}>
      {severity.toUpperCase()}
    </span>
  );
}
