import { useState } from "react";
import { Brain, Activity, Key, Globe, ArrowUpRight, Crown, Users, Shield, Zap, BarChart3, RefreshCw, Trash2, Loader2, Check, X } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/hooks/use-auth";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Link } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

const ROLES = [
  { name: "Admin", description: "Full access to all features, settings, and user management", color: "text-red-400" },
  { name: "Analyst", description: "Can view/edit alerts, incidents, run AI analysis, manage connectors", color: "text-yellow-400" },
  { name: "Viewer", description: "Read-only access to dashboards, alerts, and incidents", color: "text-blue-400" },
];

const PLANS = [
  { name: "Free", price: "$0", period: "/month", alerts: "100", connectors: "2", users: "1", ai: false, soar: false, current: false },
  { name: "Pro", price: "$49", period: "/month", alerts: "10,000", connectors: "10", users: "5", ai: true, soar: false, current: true },
  { name: "Enterprise", price: "$199", period: "/month", alerts: "Unlimited", connectors: "Unlimited", users: "Unlimited", ai: true, soar: true, current: false },
];

const THREAT_INTEL_PROVIDERS = [
  { key: "abuseipdb", name: "AbuseIPDB", types: "IP reputation" },
  { key: "virustotal", name: "VirusTotal", types: "IP, domain, file hash, URL" },
  { key: "otx", name: "OTX AlienVault", types: "IP, domain, file hash, URL" },
];

export default function SettingsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [apiKeyInputs, setApiKeyInputs] = useState<Record<string, string>>({});

  const { data: stats } = useQuery<any>({
    queryKey: ["/api/dashboard/stats"],
  });

  const { data: apiKeys } = useQuery<any[]>({
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
      toast({ title: "Failed to save key", description: error.message || "An error occurred.", variant: "destructive" });
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
      toast({ title: "Failed to delete key", description: error.message || "An error occurred.", variant: "destructive" });
    },
  });

  const getConfigForProvider = (provider: string) =>
    threatIntelConfigs?.find((c: any) => c.provider === provider);

  const initials = user
    ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U"
    : "U";

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title"><span className="gradient-text-red">Settings</span></h1>
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
                <span className="font-semibold" data-testid="text-user-name">{user?.firstName} {user?.lastName}</span>
                <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400" data-testid="badge-user-role">
                  <Crown className="h-2.5 w-2.5 mr-0.5" />
                  Admin
                </Badge>
              </div>
              <div className="text-sm text-muted-foreground" data-testid="text-user-email">{user?.email || "No email"}</div>
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
            <div key={role.name} className="flex items-start gap-3 p-2 rounded-md bg-muted/30" data-testid={`role-${role.name.toLowerCase()}`}>
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
              <Progress value={Math.min(((stats?.totalAlerts || 0) / 10000) * 100, 100)} className="h-1.5" data-testid="progress-alerts" />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-1 text-xs text-muted-foreground">
                <span>Connectors</span>
                <span className="tabular-nums">{connectorsData?.length || 0} / 10</span>
              </div>
              <Progress value={Math.min(((connectorsData?.length || 0) / 10) * 100, 100)} className="h-1.5" data-testid="progress-connectors" />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-1 text-xs text-muted-foreground">
                <span>API Keys</span>
                <span className="tabular-nums">{apiKeys?.length || 0} / 20</span>
              </div>
              <Progress value={Math.min(((apiKeys?.length || 0) / 20) * 100, 100)} className="h-1.5" data-testid="progress-api-keys" />
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
                <div className="text-lg font-bold">{plan.price}<span className="text-xs font-normal text-muted-foreground">{plan.period}</span></div>
                <div className="space-y-1 text-[10px] text-muted-foreground">
                  <div>{plan.alerts} alerts</div>
                  <div>{plan.connectors} connectors</div>
                  <div>{plan.users} users</div>
                  <div>{plan.ai ? "AI Engine" : "—"}</div>
                  <div>{plan.soar ? "SOAR Automation" : "—"}</div>
                </div>
                {plan.current ? (
                  <Badge variant="outline" className="text-[9px]">Current</Badge>
                ) : plan.name === "Enterprise" ? (
                  <Button size="sm" className="text-[10px] h-6" data-testid="button-upgrade-enterprise">Upgrade</Button>
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
              <div key={provider.key} className="p-3 rounded-md bg-muted/30 space-y-2" data-testid={`threat-intel-row-${provider.key}`}>
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
                        <span className="text-xs text-muted-foreground font-mono" data-testid={`masked-key-${provider.key}`}>{config.maskedKey}</span>
                        {config.lastTestStatus === "success" ? (
                          <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400" data-testid={`status-badge-${provider.key}`}>
                            <Check className="h-2.5 w-2.5 mr-0.5" />
                            Verified
                          </Badge>
                        ) : config.lastTestStatus === "failed" ? (
                          <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400" data-testid={`status-badge-${provider.key}`}>
                            <X className="h-2.5 w-2.5 mr-0.5" />
                            Failed
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-400" data-testid={`status-badge-${provider.key}`}>
                            <Key className="h-2.5 w-2.5 mr-0.5" />
                            Configured
                          </Badge>
                        )}
                      </>
                    ) : (
                      <Badge variant="outline" className="text-[10px] text-muted-foreground" data-testid={`status-badge-${provider.key}`}>
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
          { icon: Globe, title: "Integrations", description: "Configure pull-based security tool connectors", href: "/connectors" },
          { icon: Brain, title: "AI Engine", description: "Configure AI correlation and triage settings", href: "/ai-engine" },
          { icon: Activity, title: "Audit Log", description: "View all platform activities and changes", href: "/audit-log" },
        ].map((item) => (
          <Link key={item.href} href={item.href} data-testid={`link-setting-${item.title.toLowerCase().replace(/\s+/g, '-')}`}>
            <Card className="hover-elevate cursor-pointer h-full" data-testid={`card-setting-${item.title.toLowerCase().replace(/\s+/g, '-')}`}>
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

      <div className="pt-2 pb-4">
        <p className="text-muted-foreground text-xs">Tip: Press Cmd+K to open the command palette for quick navigation</p>
      </div>
    </div>
  );
}