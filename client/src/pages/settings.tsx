import { useState } from "react";
import {
  Brain,
  Activity,
  Key,
  Globe,
  ArrowUpRight,
  Crown,
  Users,
  Shield,
  Zap,
  RefreshCw,
  Trash2,
  Loader2,
  Check,
  X,
  Webhook,
  ExternalLink,
  Send,
  ChevronDown,
  ChevronRight,
  Plus,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTime } from "@/lib/i18n";
import { useAuth } from "@/hooks/use-auth";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Link } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

const ROLES = [
  { name: "Admin", description: "Full access to all features, settings, and user management", color: "text-red-400" },
  {
    name: "Analyst",
    description: "Can view/edit alerts, incidents, run AI analysis, manage connectors",
    color: "text-yellow-400",
  },
  { name: "Viewer", description: "Read-only access to dashboards, alerts, and incidents", color: "text-blue-400" },
];

const PLANS = [
  {
    name: "Free",
    price: "$0",
    period: "/month",
    alerts: "100",
    connectors: "2",
    users: "1",
    ai: false,
    soar: false,
    current: false,
  },
  {
    name: "Pro",
    price: "$49",
    period: "/month",
    alerts: "10,000",
    connectors: "10",
    users: "5",
    ai: true,
    soar: false,
    current: true,
  },
  {
    name: "Enterprise",
    price: "$199",
    period: "/month",
    alerts: "Unlimited",
    connectors: "Unlimited",
    users: "Unlimited",
    ai: true,
    soar: true,
    current: false,
  },
];

const THREAT_INTEL_PROVIDERS = [
  { key: "abuseipdb", name: "AbuseIPDB", types: "IP reputation" },
  { key: "virustotal", name: "VirusTotal", types: "IP, domain, file hash, URL" },
  { key: "otx", name: "OTX AlienVault", types: "IP, domain, file hash, URL" },
];

const WEBHOOK_EVENTS = [
  "incident.created",
  "incident.updated",
  "incident.closed",
  "incident.escalated",
  "alert.created",
  "alert.correlated",
  "alert.closed",
  "scan.completed",
  "policy.violation",
];

interface OutboundWebhook {
  id: string;
  orgId: string;
  name: string;
  url: string;
  secret: string | null;
  events: string[];
  isActive: boolean;
  retryCount: number;
  timeoutMs: number;
  headers: any;
  createdAt: string;
}

interface OutboundWebhookLog {
  id: string;
  webhookId: string;
  event: string;
  payload: any;
  responseStatus: number | null;
  responseBody: string | null;
  attempt: number;
  success: boolean;
  errorMessage: string | null;
  deliveredAt: string;
}

export default function SettingsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [apiKeyInputs, setApiKeyInputs] = useState<Record<string, string>>({});
  const [addWebhookOpen, setAddWebhookOpen] = useState(false);
  const [webhookForm, setWebhookForm] = useState({ name: "", url: "", secret: "", events: [] as string[] });
  const [expandedWebhookId, setExpandedWebhookId] = useState<string | null>(null);

  const {
    data: stats,
    isError: statsError,
    refetch: refetchStats,
  } = useQuery<any>({
    queryKey: ["/api/dashboard/stats"],
  });

  const {
    data: apiKeys,
    isError: apiKeysError,
    refetch: refetchApiKeys,
  } = useQuery<any[]>({
    queryKey: ["/api/api-keys"],
  });

  const { data: connectorsData } = useQuery<any[]>({
    queryKey: ["/api/connectors"],
  });

  const { data: threatIntelConfigs } = useQuery<any[]>({
    queryKey: ["/api/threat-intel-configs"],
  });

  const saveThreatIntelKey = useMutation({
    mutationFn: async ({ provider, apiKey }: { provider: string; apiKey: string }) => {
      await apiRequest("POST", "/api/threat-intel-configs", { provider, apiKey, enabled: true });
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-configs"] });
      setApiKeyInputs((prev) => ({ ...prev, [variables.provider]: "" }));
      toast({ title: "API key saved", description: `${variables.provider} key configured successfully.` });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to save key",
        description: error.message || "An error occurred.",
        variant: "destructive",
      });
    },
  });

  const testThreatIntelKey = useMutation({
    mutationFn: async (provider: string) => {
      await apiRequest("POST", `/api/threat-intel-configs/${provider}/test`);
    },
    onSuccess: (_data, provider) => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-configs"] });
      toast({ title: "Test successful", description: `${provider} API key is valid.` });
    },
    onError: (error: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-configs"] });
      toast({ title: "Test failed", description: error.message || "API key test failed.", variant: "destructive" });
    },
  });

  const deleteThreatIntelKey = useMutation({
    mutationFn: async (provider: string) => {
      await apiRequest("DELETE", `/api/threat-intel-configs/${provider}`);
    },
    onSuccess: (_data, provider) => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel-configs"] });
      toast({ title: "API key removed", description: `${provider} key deleted successfully.` });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to delete key",
        description: error.message || "An error occurred.",
        variant: "destructive",
      });
    },
  });

  const {
    data: webhooks,
    isLoading: webhooksLoading,
    isError: webhooksError,
    refetch: refetchWebhooks,
  } = useQuery<OutboundWebhook[]>({
    queryKey: ["/api/outbound-webhooks"],
  });

  const { data: webhookLogs } = useQuery<OutboundWebhookLog[]>({
    queryKey: ["/api/outbound-webhooks", expandedWebhookId, "logs"],
    queryFn: async () => {
      const res = await fetch(`/api/outbound-webhooks/${expandedWebhookId}/logs`);
      if (!res.ok) throw new Error("Failed to fetch logs");
      return res.json();
    },
    enabled: !!expandedWebhookId,
  });

  const createWebhook = useMutation({
    mutationFn: async (data: { name: string; url: string; secret?: string; events: string[] }) => {
      await apiRequest("POST", "/api/outbound-webhooks", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/outbound-webhooks"] });
      setAddWebhookOpen(false);
      setWebhookForm({ name: "", url: "", secret: "", events: [] });
      toast({ title: "Webhook created", description: "Outbound webhook configured successfully." });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to create webhook",
        description: error.message || "An error occurred.",
        variant: "destructive",
      });
    },
  });

  const testWebhook = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/outbound-webhooks/${id}/test`);
    },
    onSuccess: () => {
      toast({ title: "Test sent", description: "Webhook test payload delivered." });
    },
    onError: (error: any) => {
      toast({ title: "Test failed", description: error.message || "Webhook test failed.", variant: "destructive" });
    },
  });

  const deleteWebhook = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/outbound-webhooks/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/outbound-webhooks"] });
      toast({ title: "Webhook deleted", description: "Outbound webhook removed." });
    },
    onError: (error: any) => {
      toast({
        title: "Failed to delete webhook",
        description: error.message || "An error occurred.",
        variant: "destructive",
      });
    },
  });

  const toggleWebhookEvent = (event: string) => {
    setWebhookForm((prev) => ({
      ...prev,
      events: prev.events.includes(event) ? prev.events.filter((e) => e !== event) : [...prev.events, event],
    }));
  };

  const truncateUrl = (url: string, maxLen = 40) => (url.length > maxLen ? url.substring(0, maxLen) + "..." : url);

  const getConfigForProvider = (provider: string) => threatIntelConfigs?.find((c: any) => c.provider === provider);

  const initials = user ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U" : "U";

  if (statsError || apiKeysError || webhooksError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load settings</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchStats();
            refetchApiKeys();
            refetchWebhooks();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Settings</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1">Manage your account, roles, and subscription</p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Profile</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <Avatar className="h-14 w-14">
              <AvatarImage src={user?.profileImageUrl || ""} />
              <AvatarFallback>{initials}</AvatarFallback>
            </Avatar>
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-semibold" data-testid="text-user-name">
                  {user?.firstName} {user?.lastName}
                </span>
                <Badge
                  variant="outline"
                  className="text-[10px] border-red-500/30 text-red-400"
                  data-testid="badge-user-role"
                >
                  <Crown className="h-2.5 w-2.5 mr-0.5" />
                  Admin
                </Badge>
              </div>
              <div className="text-sm text-muted-foreground" data-testid="text-user-email">
                {user?.email || "No email"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
          <CardTitle className="text-sm font-semibold">Roles & Permissions</CardTitle>
          <Badge variant="secondary" className="text-[10px]">
            <Users className="h-2.5 w-2.5 mr-0.5" />
            RBAC
          </Badge>
        </CardHeader>
        <CardContent className="space-y-3">
          {ROLES.map((role) => (
            <div
              key={role.name}
              className="flex items-start gap-3 p-2 rounded-md bg-muted/30"
              data-testid={`role-${role.name.toLowerCase()}`}
            >
              <Shield className={`h-4 w-4 mt-0.5 flex-shrink-0 ${role.color}`} />
              <div>
                <div className="text-sm font-medium">{role.name}</div>
                <div className="text-xs text-muted-foreground">{role.description}</div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
          <CardTitle className="text-sm font-semibold">Plan & Usage</CardTitle>
          <Badge className="text-[10px] bg-red-500/10 text-red-400 border-red-500/20" data-testid="badge-current-plan">
            <Zap className="h-2.5 w-2.5 mr-0.5" />
            Pro Plan
          </Badge>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-1 text-xs text-muted-foreground">
                <span>Alerts</span>
                <span className="tabular-nums">{stats?.totalAlerts || 0} / 10,000</span>
              </div>
              <Progress
                value={Math.min(((stats?.totalAlerts || 0) / 10000) * 100, 100)}
                className="h-1.5"
                data-testid="progress-alerts"
              />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-1 text-xs text-muted-foreground">
                <span>Connectors</span>
                <span className="tabular-nums">{connectorsData?.length || 0} / 10</span>
              </div>
              <Progress
                value={Math.min(((connectorsData?.length || 0) / 10) * 100, 100)}
                className="h-1.5"
                data-testid="progress-connectors"
              />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-1 text-xs text-muted-foreground">
                <span>API Keys</span>
                <span className="tabular-nums">{apiKeys?.length || 0} / 20</span>
              </div>
              <Progress
                value={Math.min(((apiKeys?.length || 0) / 20) * 100, 100)}
                className="h-1.5"
                data-testid="progress-api-keys"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
            {PLANS.map((plan) => (
              <div
                key={plan.name}
                className={`p-3 rounded-md border text-center space-y-2 ${plan.current ? "border-red-500/40 bg-red-500/5" : "border-border"}`}
                data-testid={`plan-${plan.name.toLowerCase()}`}
              >
                <div className="text-xs font-medium">{plan.name}</div>
                <div className="text-lg font-bold">
                  {plan.price}
                  <span className="text-xs font-normal text-muted-foreground">{plan.period}</span>
                </div>
                <div className="space-y-1 text-[10px] text-muted-foreground">
                  <div>{plan.alerts} alerts</div>
                  <div>{plan.connectors} connectors</div>
                  <div>{plan.users} users</div>
                  <div>{plan.ai ? "AI Engine" : "—"}</div>
                  <div>{plan.soar ? "SOAR Automation" : "—"}</div>
                </div>
                {plan.current ? (
                  <Badge variant="outline" className="text-[9px]">
                    Current
                  </Badge>
                ) : plan.name === "Enterprise" ? (
                  <Button size="sm" className="text-[10px] h-6" data-testid="button-upgrade-enterprise">
                    Upgrade
                  </Button>
                ) : null}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
          <CardTitle className="text-sm font-semibold">Threat Intelligence API Keys</CardTitle>
          <Badge className="text-[10px] bg-red-500/10 text-red-400 border-red-500/20" data-testid="badge-threat-intel">
            <Zap className="h-2.5 w-2.5 mr-0.5" />
            Enrichment
          </Badge>
        </CardHeader>
        <CardContent className="space-y-3">
          {THREAT_INTEL_PROVIDERS.map((provider) => {
            const config = getConfigForProvider(provider.key);
            const inputValue = apiKeyInputs[provider.key] || "";
            return (
              <div
                key={provider.key}
                className="p-3 rounded-md bg-muted/30 space-y-2"
                data-testid={`threat-intel-row-${provider.key}`}
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div>
                    <div className="text-sm font-medium flex items-center gap-1.5 flex-wrap">
                      <Shield className="h-3.5 w-3.5 text-red-400 flex-shrink-0" />
                      {provider.name}
                    </div>
                    <div className="text-[10px] text-muted-foreground ml-5">{provider.types}</div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {config ? (
                      <>
                        <span
                          className="text-xs text-muted-foreground font-mono"
                          data-testid={`masked-key-${provider.key}`}
                        >
                          {config.maskedKey}
                        </span>
                        {config.lastTestStatus === "success" ? (
                          <Badge
                            variant="outline"
                            className="text-[10px] border-green-500/30 text-green-400"
                            data-testid={`status-badge-${provider.key}`}
                          >
                            <Check className="h-2.5 w-2.5 mr-0.5" />
                            Verified
                          </Badge>
                        ) : config.lastTestStatus === "failed" ? (
                          <Badge
                            variant="outline"
                            className="text-[10px] border-red-500/30 text-red-400"
                            data-testid={`status-badge-${provider.key}`}
                          >
                            <X className="h-2.5 w-2.5 mr-0.5" />
                            Failed
                          </Badge>
                        ) : (
                          <Badge
                            variant="outline"
                            className="text-[10px] border-yellow-500/30 text-yellow-400"
                            data-testid={`status-badge-${provider.key}`}
                          >
                            <Key className="h-2.5 w-2.5 mr-0.5" />
                            Configured
                          </Badge>
                        )}
                      </>
                    ) : (
                      <Badge
                        variant="outline"
                        className="text-[10px] text-muted-foreground"
                        data-testid={`status-badge-${provider.key}`}
                      >
                        Not configured
                      </Badge>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <Input
                    type="password"
                    placeholder={`Enter ${provider.name} API key`}
                    value={inputValue}
                    onChange={(e) => setApiKeyInputs((prev) => ({ ...prev, [provider.key]: e.target.value }))}
                    className="flex-1 text-xs"
                    data-testid={`input-api-key-${provider.key}`}
                  />
                  <Button
                    size="sm"
                    disabled={!inputValue || saveThreatIntelKey.isPending}
                    onClick={() => saveThreatIntelKey.mutate({ provider: provider.key, apiKey: inputValue })}
                    data-testid={`button-save-key-${provider.key}`}
                  >
                    {saveThreatIntelKey.isPending && saveThreatIntelKey.variables?.provider === provider.key ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      "Save"
                    )}
                  </Button>
                  {config && (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={testThreatIntelKey.isPending}
                        onClick={() => testThreatIntelKey.mutate(provider.key)}
                        data-testid={`button-test-key-${provider.key}`}
                      >
                        {testThreatIntelKey.isPending && testThreatIntelKey.variables === provider.key ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3 w-3" />
                        )}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={deleteThreatIntelKey.isPending}
                        onClick={() => deleteThreatIntelKey.mutate(provider.key)}
                        data-testid={`button-delete-key-${provider.key}`}
                      >
                        {deleteThreatIntelKey.isPending && deleteThreatIntelKey.variables === provider.key ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Trash2 className="h-3 w-3" />
                        )}
                      </Button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          { icon: Key, title: "API Keys", description: "Manage API keys for alert ingestion", href: "/ingestion" },
          {
            icon: Globe,
            title: "Integrations",
            description: "Configure pull-based security tool connectors",
            href: "/connectors",
          },
          {
            icon: Brain,
            title: "AI Engine",
            description: "Configure AI correlation and triage settings",
            href: "/ai-engine",
          },
          {
            icon: Activity,
            title: "Audit Log",
            description: "View all platform activities and changes",
            href: "/audit-log",
          },
        ].map((item) => (
          <Link
            key={item.href}
            href={item.href}
            data-testid={`link-setting-${item.title.toLowerCase().replace(/\s+/g, "-")}`}
          >
            <Card
              className="hover-elevate cursor-pointer h-full"
              data-testid={`card-setting-${item.title.toLowerCase().replace(/\s+/g, "-")}`}
            >
              <CardContent className="p-4">
                <div className="flex items-start gap-3 relative">
                  <div className="flex items-center justify-center w-9 h-9 rounded-md bg-muted flex-shrink-0">
                    <item.icon className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">{item.title}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">{item.description}</div>
                  </div>
                  <ArrowUpRight className="h-4 w-4 text-muted-foreground flex-shrink-0 ml-2" />
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      <Card data-testid="card-api-surface">
        <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
          <CardTitle className="text-sm font-semibold">API Surface</CardTitle>
          <Badge variant="secondary" className="text-[10px]">
            <Globe className="h-2.5 w-2.5 mr-0.5" />
            v1
          </Badge>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div>
              <div className="text-sm font-medium">Current API Version</div>
              <div className="text-xs text-muted-foreground">v1</div>
            </div>
            <a href="/api/v1/openapi" target="_blank" rel="noopener noreferrer">
              <Button size="sm" variant="outline" data-testid="link-openapi-spec">
                <ExternalLink className="h-3 w-3 mr-1" />
                OpenAPI Spec
              </Button>
            </a>
          </div>
          <div className="p-2 rounded-md bg-muted/30">
            <div className="text-xs text-muted-foreground">
              All ingestion endpoints support <span className="font-mono text-foreground">X-Idempotency-Key</span>{" "}
              header for at-most-once delivery
            </div>
          </div>
        </CardContent>
      </Card>

      <Card data-testid="card-outbound-webhooks">
        <CardHeader className="flex flex-row items-center justify-between gap-1 pb-3">
          <div>
            <CardTitle className="text-sm font-semibold">Outbound Webhooks</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Configure webhooks to receive notifications for incident lifecycle events
            </p>
          </div>
          <Dialog open={addWebhookOpen} onOpenChange={setAddWebhookOpen}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="button-add-webhook">
                <Plus className="h-3 w-3 mr-1" />
                Add Webhook
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Outbound Webhook</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 pt-2">
                <div className="space-y-1.5">
                  <Label className="text-xs">Name</Label>
                  <Input
                    placeholder="My webhook"
                    value={webhookForm.name}
                    onChange={(e) => setWebhookForm((prev) => ({ ...prev, name: e.target.value }))}
                    data-testid="input-webhook-name"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">URL</Label>
                  <Input
                    placeholder="https://example.com/webhook"
                    value={webhookForm.url}
                    onChange={(e) => setWebhookForm((prev) => ({ ...prev, url: e.target.value }))}
                    data-testid="input-webhook-url"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Secret (optional)</Label>
                  <Input
                    type="password"
                    placeholder="Signing secret"
                    value={webhookForm.secret}
                    onChange={(e) => setWebhookForm((prev) => ({ ...prev, secret: e.target.value }))}
                    data-testid="input-webhook-secret"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Events</Label>
                  <div className="grid grid-cols-2 gap-2">
                    {WEBHOOK_EVENTS.map((event) => (
                      <div key={event} className="flex items-center gap-2">
                        <Checkbox
                          id={`event-${event}`}
                          checked={webhookForm.events.includes(event)}
                          onCheckedChange={() => toggleWebhookEvent(event)}
                          data-testid={`checkbox-event-${event}`}
                        />
                        <label htmlFor={`event-${event}`} className="text-xs cursor-pointer">
                          {event}
                        </label>
                      </div>
                    ))}
                  </div>
                </div>
                <Button
                  className="w-full"
                  disabled={
                    !webhookForm.name || !webhookForm.url || webhookForm.events.length === 0 || createWebhook.isPending
                  }
                  onClick={() =>
                    createWebhook.mutate({
                      name: webhookForm.name,
                      url: webhookForm.url,
                      secret: webhookForm.secret || undefined,
                      events: webhookForm.events,
                    })
                  }
                  data-testid="button-submit-webhook"
                >
                  {createWebhook.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Create Webhook"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent className="space-y-3">
          {webhooksLoading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : !webhooks || webhooks.length === 0 ? (
            <div className="text-center py-6">
              <Webhook className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
              <div className="text-sm text-muted-foreground">No webhooks configured</div>
            </div>
          ) : (
            webhooks.map((wh) => (
              <div key={wh.id} className="rounded-md bg-muted/30">
                <div
                  className="p-3 cursor-pointer"
                  onClick={() => setExpandedWebhookId(expandedWebhookId === wh.id ? null : wh.id)}
                  data-testid={`webhook-row-${wh.id}`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-1 min-w-0 flex-wrap">
                      {expandedWebhookId === wh.id ? (
                        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                      )}
                      <Webhook className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                      <span className="text-sm font-medium">{wh.name}</span>
                      <span className="text-xs text-muted-foreground font-mono truncate">{truncateUrl(wh.url)}</span>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      {wh.isActive ? (
                        <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">
                          Active
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px] text-muted-foreground">
                          Inactive
                        </Badge>
                      )}
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={testWebhook.isPending}
                        onClick={(e) => {
                          e.stopPropagation();
                          testWebhook.mutate(wh.id);
                        }}
                        data-testid={`button-test-webhook-${wh.id}`}
                      >
                        {testWebhook.isPending && testWebhook.variables === wh.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Send className="h-3 w-3" />
                        )}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={deleteWebhook.isPending}
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteWebhook.mutate(wh.id);
                        }}
                        data-testid={`button-delete-webhook-${wh.id}`}
                      >
                        {deleteWebhook.isPending && deleteWebhook.variables === wh.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Trash2 className="h-3 w-3" />
                        )}
                      </Button>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 mt-2 flex-wrap ml-7">
                    {wh.events.map((ev) => (
                      <Badge key={ev} variant="secondary" className="text-[10px]">
                        {ev}
                      </Badge>
                    ))}
                  </div>
                </div>
                {expandedWebhookId === wh.id && (
                  <div className="border-t border-border px-3 pb-3 pt-2 space-y-2">
                    <div className="text-xs font-medium text-muted-foreground">Recent Delivery Logs</div>
                    {!webhookLogs || webhookLogs.length === 0 ? (
                      <div className="text-xs text-muted-foreground py-2">No delivery logs yet</div>
                    ) : (
                      webhookLogs.map((log) => (
                        <div
                          key={log.id}
                          className="flex items-center justify-between gap-2 p-2 rounded-md bg-background text-xs flex-wrap"
                          data-testid={`webhook-log-${log.id}`}
                        >
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono">{log.event}</span>
                            {log.success ? (
                              <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">
                                <Check className="h-2.5 w-2.5 mr-0.5" />
                                Success
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400">
                                <X className="h-2.5 w-2.5 mr-0.5" />
                                Failed
                              </Badge>
                            )}
                            {log.responseStatus !== null && (
                              <span className="text-muted-foreground">HTTP {log.responseStatus}</span>
                            )}
                            <span className="text-muted-foreground">Attempt {log.attempt}</span>
                          </div>
                          <div className="flex items-center gap-2 flex-wrap">
                            {log.errorMessage && (
                              <span className="text-red-400 truncate max-w-[200px]">{log.errorMessage}</span>
                            )}
                            <span className="text-muted-foreground">{formatDateTime(log.deliveredAt)}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <div className="pt-2 pb-4">
        <p className="text-muted-foreground text-xs">
          Tip: Press Cmd+K to open the command palette for quick navigation
        </p>
      </div>
    </div>
  );
}
