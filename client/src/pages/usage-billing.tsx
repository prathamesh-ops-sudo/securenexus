import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { formatDateShort, formatDateFull, formatNumber as formatI18nNumber } from "@/lib/i18n";
import {
  BarChart3,
  Zap,
  Brain,
  Plug,
  Activity,
  AlertTriangle,
  Shield,
  Cloud,
  Building,
  Loader2,
  ArrowRight,
  Layers,
  CreditCard,
  Package,
} from "lucide-react";

function statusColor(status: string) {
  if (status === "critical") return "text-red-500";
  if (status === "warning") return "text-yellow-500";
  return "text-green-500";
}

function statusBg(status: string) {
  if (status === "critical") return "bg-red-500/10 border-red-500/30";
  if (status === "warning") return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-emerald-500/10 border-emerald-500/30";
}

function progressColor(pct: number, soft: number, hard: number) {
  if (pct >= hard) return "bg-red-500";
  if (pct >= soft) return "bg-yellow-500";
  return "bg-emerald-500";
}

function metricIcon(type: string) {
  switch (type) {
    case "events_ingested":
      return <Activity className="h-5 w-5" />;
    case "connectors_active":
      return <Plug className="h-5 w-5" />;
    case "ai_tokens_used":
      return <Brain className="h-5 w-5" />;
    case "automation_runs":
      return <Zap className="h-5 w-5" />;
    default:
      return <BarChart3 className="h-5 w-5" />;
  }
}

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return formatI18nNumber(n);
}

interface UsageMetric {
  type: string;
  label: string;
  current: number;
  limit: number;
  unit: string;
  pctUsed: number;
  softThreshold: number;
  hardThreshold: number;
  status: string;
}

interface UsageData {
  planTier: string;
  billingCycleStart: string;
  billingCycleEnd: string;
  metrics: UsageMetric[];
  warnings: UsageMetric[];
}

interface PlanData {
  planTier: string;
  eventsPerMonth: number;
  maxConnectors: number;
  aiTokensPerMonth: number;
  automationRunsPerMonth: number;
  apiCallsPerMonth: number;
  storageGb: number;
  softThresholdPct: number;
  hardThresholdPct: number;
  overageAllowed: boolean;
}

interface WorkspaceTemplate {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  category: string;
  icon: string | null;
  config: any;
  connectorsConfig: any[];
  playbooksConfig: any[];
  notificationConfig: any[];
  complianceConfig: any;
  createdAt: string;
}

function tierBadge(tier: string) {
  const styles: Record<string, string> = {
    free: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    starter: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    professional: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    enterprise: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  };
  return styles[tier] || styles.free;
}

function templateIcon(icon: string | null) {
  switch (icon) {
    case "Building":
      return <Building className="h-8 w-8" />;
    case "Cloud":
      return <Cloud className="h-8 w-8" />;
    default:
      return <Shield className="h-8 w-8" />;
  }
}

function UsageMeteringTab() {
  const {
    data: usage,
    isLoading,
    isError: usageError,
    refetch: refetchUsage,
  } = useQuery<UsageData>({
    queryKey: ["/api/usage-metering"],
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-32 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (usageError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load usage data</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button
          variant="outline"
          size="sm"
          className="mt-3"
          onClick={() => {
            refetchUsage();
          }}
        >
          Try Again
        </Button>
      </div>
    );
  }

  if (!usage) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Activity className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground">No usage data available yet</p>
        </CardContent>
      </Card>
    );
  }

  const cycleStart = formatDateShort(usage.billingCycleStart);
  const cycleEnd = formatDateFull(usage.billingCycleEnd);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold">Current Billing Cycle</h3>
            <Badge variant="outline" className={tierBadge(usage.planTier)}>
              {usage.planTier.charAt(0).toUpperCase() + usage.planTier.slice(1)} Plan
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            {cycleStart} — {cycleEnd}
          </p>
        </div>
        {usage.warnings.length > 0 && (
          <Badge variant="outline" className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 gap-1">
            <AlertTriangle className="h-3 w-3" />
            {usage.warnings.length} limit{usage.warnings.length > 1 ? "s" : ""} approaching
          </Badge>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {usage.metrics.map((metric) => (
          <Card key={metric.type} className={`glass border ${statusBg(metric.status)}`}>
            <CardContent className="pt-5 pb-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-lg ${statusBg(metric.status)}`}>{metricIcon(metric.type)}</div>
                  <div>
                    <p className="font-medium text-sm">{metric.label}</p>
                    <p className="text-xs text-muted-foreground">{metric.unit}</p>
                  </div>
                </div>
                <Badge variant="outline" className={`text-xs ${statusBg(metric.status)} ${statusColor(metric.status)}`}>
                  {metric.status === "critical" ? "Over limit" : metric.status === "warning" ? "Approaching" : "OK"}
                </Badge>
              </div>

              <div className="space-y-2">
                <div className="flex items-end justify-between">
                  <span className="text-2xl font-bold">{formatNumber(metric.current)}</span>
                  <span className="text-sm text-muted-foreground">/ {formatNumber(metric.limit)}</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted overflow-hidden">
                  <div
                    className={`absolute inset-y-0 left-0 rounded-full transition-all ${progressColor(metric.pctUsed, metric.softThreshold, metric.hardThreshold)}`}
                    style={{ width: `${Math.min(metric.pctUsed, 100)}%` }}
                  />
                  <div
                    className="absolute inset-y-0 w-px bg-yellow-500/50"
                    style={{ left: `${metric.softThreshold}%` }}
                  />
                  <div className="absolute inset-y-0 w-px bg-red-500/50" style={{ left: `${metric.hardThreshold}%` }} />
                </div>
                <p className="text-xs text-muted-foreground text-right">{metric.pctUsed}% used</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {usage.warnings.length > 0 && (
        <Card className="glass border border-yellow-500/30 bg-yellow-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-yellow-400">
              <AlertTriangle className="h-4 w-4" />
              Usage Warnings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {usage.warnings.map((w) => (
                <li key={w.type} className="flex items-center justify-between text-sm">
                  <span>
                    {w.label}: {formatNumber(w.current)} / {formatNumber(w.limit)}
                  </span>
                  <span className={`font-medium ${statusColor(w.status)}`}>{w.pctUsed}%</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function PlanLimitsTab() {
  const { toast } = useToast();
  const [_selectedTier, _setSelectedTier] = useState<string>("");

  const {
    data: plan,
    isLoading,
    isError: _planError,
    refetch: _refetchPlan,
  } = useQuery<PlanData>({
    queryKey: ["/api/plan-limits"],
  });

  const upgradeMutation = useMutation({
    mutationFn: async (tier: string) => {
      const tierLimits: Record<string, any> = {
        free: {
          planTier: "free",
          eventsPerMonth: 10000,
          maxConnectors: 3,
          aiTokensPerMonth: 5000,
          automationRunsPerMonth: 100,
        },
        starter: {
          planTier: "starter",
          eventsPerMonth: 50000,
          maxConnectors: 10,
          aiTokensPerMonth: 25000,
          automationRunsPerMonth: 500,
        },
        professional: {
          planTier: "professional",
          eventsPerMonth: 500000,
          maxConnectors: 50,
          aiTokensPerMonth: 100000,
          automationRunsPerMonth: 5000,
        },
        enterprise: {
          planTier: "enterprise",
          eventsPerMonth: 5000000,
          maxConnectors: 500,
          aiTokensPerMonth: 1000000,
          automationRunsPerMonth: 50000,
        },
      };
      const res = await apiRequest("PUT", "/api/plan-limits", tierLimits[tier]);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/plan-limits"] });
      queryClient.invalidateQueries({ queryKey: ["/api/usage-metering"] });
      toast({ title: "Plan updated successfully" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-48 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  const plans = [
    {
      tier: "free",
      name: "Free",
      price: "$0",
      desc: "For evaluation and small teams",
      events: "10K",
      connectors: "3",
      ai: "5K",
      automation: "100",
      color: "border-zinc-500/30",
    },
    {
      tier: "starter",
      name: "Starter",
      price: "$299/mo",
      desc: "For growing security teams",
      events: "50K",
      connectors: "10",
      ai: "25K",
      automation: "500",
      color: "border-blue-500/30",
    },
    {
      tier: "professional",
      name: "Professional",
      price: "$999/mo",
      desc: "For mature SOC operations",
      events: "500K",
      connectors: "50",
      ai: "100K",
      automation: "5K",
      color: "border-purple-500/30",
      popular: true,
    },
    {
      tier: "enterprise",
      name: "Enterprise",
      price: "Custom",
      desc: "Unlimited scale with SLA",
      events: "5M+",
      connectors: "500+",
      ai: "1M+",
      automation: "50K+",
      color: "border-amber-500/30",
    },
  ];

  const currentTier = plan?.planTier || "free";

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">Plan & Pricing</h3>
        <p className="text-sm text-muted-foreground">Choose the right plan for your organization's needs</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {plans.map((p) => (
          <Card
            key={p.tier}
            className={`glass border relative ${p.color} ${currentTier === p.tier ? "ring-2 ring-primary" : ""}`}
          >
            {(p as any).popular && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <Badge className="bg-purple-600 text-white text-xs">Most Popular</Badge>
              </div>
            )}
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <Badge variant="outline" className={tierBadge(p.tier)}>
                  {p.name}
                </Badge>
                {currentTier === p.tier && <Badge className="bg-primary/20 text-primary text-xs">Current</Badge>}
              </div>
              <CardTitle className="text-2xl mt-2">{p.price}</CardTitle>
              <CardDescription>{p.desc}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Events/mo</span>
                  <span className="font-medium">{p.events}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Connectors</span>
                  <span className="font-medium">{p.connectors}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">AI Tokens</span>
                  <span className="font-medium">{p.ai}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Automation</span>
                  <span className="font-medium">{p.automation}</span>
                </div>
              </div>
              {currentTier !== p.tier && (
                <Button
                  size="sm"
                  className="w-full mt-3"
                  variant={currentTier === p.tier ? "outline" : "default"}
                  disabled={upgradeMutation.isPending}
                  onClick={() => upgradeMutation.mutate(p.tier)}
                >
                  {upgradeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  {plans.findIndex((x) => x.tier === p.tier) > plans.findIndex((x) => x.tier === currentTier)
                    ? "Upgrade"
                    : "Downgrade"}
                </Button>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="glass">
        <CardHeader>
          <CardTitle className="text-sm">Current Limits</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <p className="text-muted-foreground">Events/month</p>
              <p className="font-semibold text-lg">{formatNumber(plan?.eventsPerMonth || 10000)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Max Connectors</p>
              <p className="font-semibold text-lg">{plan?.maxConnectors || 3}</p>
            </div>
            <div>
              <p className="text-muted-foreground">AI Tokens/month</p>
              <p className="font-semibold text-lg">{formatNumber(plan?.aiTokensPerMonth || 5000)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Automation Runs/month</p>
              <p className="font-semibold text-lg">{formatNumber(plan?.automationRunsPerMonth || 100)}</p>
            </div>
          </div>
          <div className="mt-4 flex items-center gap-4 text-sm text-muted-foreground">
            <span>Soft threshold: {plan?.softThresholdPct || 80}%</span>
            <span>Hard threshold: {plan?.hardThresholdPct || 95}%</span>
            <span>Overage: {plan?.overageAllowed ? "Allowed" : "Blocked"}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function WorkspaceTemplatesTab() {
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: templates, isLoading } = useQuery<WorkspaceTemplate[]>({
    queryKey: ["/api/workspace-templates"],
  });

  const applyMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest("POST", `/api/workspace-templates/${id}/apply`);
      return res.json();
    },
    onSuccess: (data) => {
      toast({
        title: `Template "${data.templateName}" applied`,
        description: `${data.applied.length} items configured`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/connectors"] });
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
    },
    onError: () => {
      toast({ title: "Failed to apply template", variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-64 rounded-lg" />
        ))}
      </div>
    );
  }

  if (!templates || templates.length === 0) {
    return (
      <Card className="glass">
        <CardContent className="py-12 text-center">
          <Layers className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
          <p className="text-muted-foreground">No workspace templates available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">Workspace Templates</h3>
        <p className="text-sm text-muted-foreground">
          Quick-start your SOC with pre-built configurations tailored to your organization type
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {templates.map((t) => {
          const connectors = (t.connectorsConfig || []) as any[];
          const playbooks = (t.playbooksConfig || []) as any[];
          const notifications = (t.notificationConfig || []) as any[];
          const isExpanded = expandedId === t.id;

          return (
            <Card key={t.id} className="glass border hover:border-primary/30 transition-colors">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-primary/10 text-primary">{templateIcon(t.icon)}</div>
                  <div>
                    <CardTitle className="text-base">{t.name}</CardTitle>
                    <Badge variant="outline" className="text-xs mt-1">
                      {t.category.replace("_", " ")}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground leading-relaxed">{t.description}</p>

                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <Plug className="h-3.5 w-3.5 text-muted-foreground" />
                    <span>
                      {connectors.length} connector{connectors.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Zap className="h-3.5 w-3.5 text-muted-foreground" />
                    <span>
                      {playbooks.length} playbook{playbooks.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Activity className="h-3.5 w-3.5 text-muted-foreground" />
                    <span>
                      {notifications.length} notification channel{notifications.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                </div>

                {isExpanded && (
                  <div className="space-y-3 pt-2 border-t border-border/50">
                    {connectors.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Connectors</p>
                        {connectors.map((c: any, i: number) => (
                          <p key={i} className="text-xs ml-2">
                            • {c.name} ({c.type})
                          </p>
                        ))}
                      </div>
                    )}
                    {playbooks.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1">Playbooks</p>
                        {playbooks.map((p: any, i: number) => (
                          <p key={i} className="text-xs ml-2">
                            • {p.name}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div className="flex gap-2 pt-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="flex-1"
                    onClick={() => setExpandedId(isExpanded ? null : t.id)}
                  >
                    {isExpanded ? "Less" : "Details"}
                  </Button>
                  <Button
                    size="sm"
                    className="flex-1 gap-1"
                    disabled={applyMutation.isPending}
                    onClick={() => applyMutation.mutate(t.id)}
                  >
                    {applyMutation.isPending ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <ArrowRight className="h-3 w-3" />
                    )}
                    Apply
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

export default function UsageBillingPage() {
  return (
    <div className="p-4 md:p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Usage & Billing</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Monitor resource consumption, manage plan limits, and configure workspace templates
        </p>
      </div>

      <Tabs defaultValue="usage" className="space-y-4">
        <TabsList className="glass">
          <TabsTrigger value="usage" className="gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" />
            Usage
          </TabsTrigger>
          <TabsTrigger value="plans" className="gap-1.5">
            <CreditCard className="h-3.5 w-3.5" />
            Plans
          </TabsTrigger>
          <TabsTrigger value="templates" className="gap-1.5">
            <Package className="h-3.5 w-3.5" />
            Templates
          </TabsTrigger>
        </TabsList>

        <TabsContent value="usage">
          <UsageMeteringTab />
        </TabsContent>
        <TabsContent value="plans">
          <PlanLimitsTab />
        </TabsContent>
        <TabsContent value="templates">
          <WorkspaceTemplatesTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
